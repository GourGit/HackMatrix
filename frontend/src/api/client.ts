import { AssessmentDetail, CreateAssessmentPayload, AnonymousSessionResponse } from '../types';

const API_BASE = '/v1';

interface VisitorSession {
  accessToken: string;
  tokenType: string;
  expiresAt: number; // millisecond timestamp
  tenantId: string;
  subjectId: string;
}

let activeSession: VisitorSession | null = null;
let sessionPromise: Promise<string> | null = null;

/**
 * Initializes or retrieves a cached visitor session JWT in-memory.
 * Refreshes automatically if within 60 seconds of expiration.
 */
export async function getOrInitVisitorSession(forceRefresh = false): Promise<string> {
  const now = Date.now();
  if (!forceRefresh && activeSession && now < activeSession.expiresAt - 60000) {
    return activeSession.accessToken;
  }

  if (sessionPromise && !forceRefresh) {
    return sessionPromise;
  }

  sessionPromise = (async () => {
    try {
      const res = await fetch(`${API_BASE}/auth/anonymous`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err?.error?.message || `Failed to create visitor session: ${res.statusText}`);
      }
      const data: AnonymousSessionResponse = await res.json();
      activeSession = {
        accessToken: data.accessToken,
        tokenType: data.tokenType || 'Bearer',
        expiresAt: Date.now() + data.expiresIn * 1000,
        tenantId: data.tenantId,
        subjectId: data.subjectId,
      };
      return data.accessToken;
    } finally {
      sessionPromise = null;
    }
  })();

  return sessionPromise;
}

/**
 * Executes a fetch request with an attached visitor Bearer token.
 * Retries once on 401 Unauthorized with a freshly acquired session.
 */
export async function authenticatedFetch(input: string, init: RequestInit = {}): Promise<Response> {
  let token = await getOrInitVisitorSession();
  const headers = new Headers(init.headers || {});
  headers.set('Authorization', `Bearer ${token}`);

  let res = await fetch(input, { ...init, headers });

  if (res.status === 401) {
    // Retry once with forced refresh
    token = await getOrInitVisitorSession(true);
    headers.set('Authorization', `Bearer ${token}`);
    res = await fetch(input, { ...init, headers });
  }

  return res;
}

export async function createAssessment(
  payload: CreateAssessmentPayload
): Promise<{ assessmentId: string; status: string; scopeId?: string | null }> {
  const res = await authenticatedFetch(`${API_BASE}/assessments`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err?.error?.message || `Failed to submit assessment: ${res.statusText}`);
  }
  return res.json();
}

export async function getAssessment(assessmentId: string): Promise<AssessmentDetail> {
  const res = await authenticatedFetch(`${API_BASE}/assessments/${encodeURIComponent(assessmentId)}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err?.error?.message || `Failed to fetch assessment: ${res.statusText}`);
  }
  return res.json();
}

import { AssessmentDetail, CreateAssessmentPayload } from '../types';

const API_BASE = '/v1';

export async function createAssessment(payload: CreateAssessmentPayload): Promise<{ assessmentId: string; status: string; scopeId: string }> {
  const res = await fetch(`${API_BASE}/assessments`, {
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
  const res = await fetch(`${API_BASE}/assessments/${assessmentId}`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err?.error?.message || `Failed to fetch assessment: ${res.statusText}`);
  }
  return res.json();
}


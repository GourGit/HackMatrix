export type Severity = 'informational' | 'low' | 'medium' | 'high' | 'critical';
export type ScoreBand = 'low' | 'guarded' | 'high' | 'critical';
export type AssessmentStatus = 'queued' | 'running' | 'completed' | 'partial' | 'failed' | 'cancelled';

export interface Finding {
  findingId: string;
  agent: string;
  type: string;
  severity: Severity;
  confidence: number;
  title: string;
  evidenceIds: string[];
}

export interface RiskDetail {
  score: number;
  band: ScoreBand;
  version: string;
  contributions: Array<{ findingId: string; points: number }>;
}

export type CheckStatus = 'passed' | 'failed' | 'unknown' | 'not_requested' | 'unavailable' | 'good' | 'revoked' | 'completed';

export interface ChecksDetail {
  ct: CheckStatus;
  revocation: CheckStatus;
  safeScan: CheckStatus;
  hostnameMatch?: CheckStatus;
  validityDates?: CheckStatus;
  caChain?: CheckStatus;
  tlsConfiguration?: CheckStatus;
  cryptoStrength?: CheckStatus;
}

export interface AgentRunDetail {
  agentName: string;
  status: 'queued' | 'running' | 'completed' | 'partial' | 'failed' | 'unavailable' | 'timeout';
  startedAt?: string | null;
  endedAt?: string | null;
  errorCode?: string | null;
}

export interface AssessmentDetail {
  assessmentId: string;
  status: AssessmentStatus;
  target: string;
  normalizedUrl?: string;
  risk: RiskDetail;
  findings: Finding[];
  checks: ChecksDetail;
  agentRuns?: AgentRunDetail[];
  createdAt?: string;
  completedAt?: string;
}

export interface CreateAssessmentPayload {
  url: string;
  authorization: {
    attested: boolean;
    scopeId?: string;
  };
  safeScan?: {
    enabled: boolean;
    ports?: number[];
  };
  options?: {
    cryptoScamAnalysis?: boolean;
  };
}

export interface AnonymousSessionResponse {
  accessToken: string;
  tokenType: string;
  expiresIn: number;
  tenantId: string;
  subjectId: string;
}


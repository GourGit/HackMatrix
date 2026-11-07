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

export interface ChecksDetail {
  ct: 'passed' | 'failed' | 'unknown' | 'not_requested';
  revocation: 'good' | 'revoked' | 'unknown' | 'not_requested';
  safeScan: 'completed' | 'failed' | 'unknown' | 'not_requested';
}

export interface AssessmentDetail {
  assessmentId: string;
  status: AssessmentStatus;
  target: string;
  normalizedUrl?: string;
  risk: RiskDetail;
  findings: Finding[];
  checks: ChecksDetail;
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


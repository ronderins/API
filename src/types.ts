export interface VerifyRequest {
  user_id: string;
  doc_hash: string;
  age_threshold: number;
}

export interface VerifyResponse {
  verified: boolean;
  criteria_met: string;
  proof_signature: string;
  // Optional extended attributes for backward compatibility
  proof_id?: string;
  status?: "accepted";
  commitment?: string;
  age_threshold?: number;
  age_verified?: boolean;
  signed_token?: string;
  verification_timestamp?: string;
  created_at?: string;
}

export interface AuditEvent {
  event_id: number;
  event_type: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface ProofResponse {
  proof_id: string;
  status: string;
  user_id_digest: string;
  document_hash: string;
  age_threshold: number;
  verified: boolean;
  criteria_met: string;
  commitment: string;
  proof_signature: string;
  created_at: string;
  audit_trail: AuditEvent[];
  // Compatibility fields
  age_verified?: boolean;
  signed_token?: string;
  verification_timestamp?: string;
}

export interface ErrorBody {
  code: string;
  message: string;
  request_id: string;
  details?: Record<string, string>;
}

export interface ErrorResponse {
  error: ErrorBody;
}

export interface HealthResponse {
  status: string;
  service: string;
  uptime_seconds?: number;
  timestamp?: string;
}

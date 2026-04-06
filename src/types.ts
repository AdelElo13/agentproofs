// ── Event Types ──

export const EVENT_TYPES = [
  'session_started',
  'session_ended',
  'tool_started',
  'tool_completed',
  'tool_failed',
  'tool_denied',
  'decision',
  'delegation_started',
  'delegation_completed',
  'approval_requested',
  'approval_granted',
  'approval_denied',
  'policy_violation',
  'checkpoint_created',
  'key_rotated',
  'daemon_started',
  'daemon_stopped',
  'error',
] as const;

export type EventType = (typeof EVENT_TYPES)[number];

// ── Origin Types ──

export const ORIGINS = ['hook', 'sdk', 'mcp', 'manual', 'daemon'] as const;
export type Origin = (typeof ORIGINS)[number];

// ── Redaction Levels ──

export type RedactionLevel = 0 | 1 | 2 | 3;

// ── EU AI Act Categories ──

export const AI_ACT_CATEGORIES = ['minimal', 'limited', 'high', 'unacceptable'] as const;
export type AiActCategory = (typeof AI_ACT_CATEGORIES)[number];

// ── Proof Action ──

export interface ProofAction {
  readonly tool?: string;
  readonly input_hash: string;
  readonly output_hash: string;
  readonly input_summary?: string;
  readonly output_summary?: string;
  readonly input_encrypted?: string;
  readonly output_encrypted?: string;
  readonly duration_ms?: number;
  readonly success: boolean;
  readonly error_message?: string;
}

// ── Proof Context ──

export interface ProofContext {
  readonly working_dir?: string;
  readonly namespace?: string;
  readonly reason?: string;
  readonly parent_event_id?: string;
  readonly tags?: readonly string[];
  readonly origin: Origin;
  readonly git_commit?: string;
  readonly repo_dirty?: boolean;
  readonly model_id?: string;
  readonly model_version?: string;
}

// ── Compliance ──

export interface ProofCompliance {
  readonly eu_ai_act_category?: AiActCategory;
  readonly data_categories?: readonly string[];
  readonly retention_days?: number;
  readonly redaction_level: RedactionLevel;
}

// ── Proof Entry ──

export interface ProofEntry {
  // Chain metadata
  readonly schema_version: 1;
  readonly chain_id: string;
  readonly id: string;
  readonly sequence: number;
  readonly prev_hash: string;
  readonly hash: string;
  readonly signature: string;

  // Crypto metadata
  readonly hash_algorithm: 'sha256';
  readonly signature_algorithm: 'ed25519';
  readonly key_id: string;

  // Timing
  readonly timestamp: string;
  readonly monotonic_time_ns?: number;

  // Who
  readonly agent_id: string;
  readonly session_id: string;
  readonly user_id?: string;
  readonly host_id?: string;
  readonly process_id?: number;

  // What
  readonly event_type: EventType;
  readonly tool_invocation_id?: string;
  readonly trace_id?: string;
  readonly span_id?: string;
  readonly action: ProofAction;

  // Why
  readonly context: ProofContext;

  // Compliance
  readonly compliance?: ProofCompliance;
}

// ── Hashable Entry (without hash + signature) ──

export type HashableEntry = Omit<ProofEntry, 'hash' | 'signature'>;

// ── Segment Manifest ──

export interface SegmentManifest {
  readonly segment_id: string;
  readonly chain_id: string;
  readonly first_sequence: number;
  readonly last_sequence: number;
  readonly first_hash: string;
  readonly last_hash: string;
  readonly segment_hash: string;
  readonly proof_count: number;
  readonly created_at: string;
  readonly sealed_at: string;
  readonly key_id: string;
  readonly signature: string;
  readonly retention_applied?: boolean;
}

// ── Verification Result ──

export interface VerificationResult {
  readonly valid: boolean;
  readonly total_proofs: number;
  readonly verified: number;
  readonly first_invalid_sequence?: number;
  readonly first_invalid_reason?: string;
  readonly last_valid_hash?: string;
  readonly chain_hash?: string;
  readonly segments_verified: number;
  readonly checkpoint_status: 'none' | 'valid' | 'invalid';
  readonly key_transitions: number;
}

// ── Query Parameters ──

export interface QueryParams {
  readonly proof_id?: string;
  readonly agent_id?: string;
  readonly session_id?: string;
  readonly trace_id?: string;
  readonly event_type?: EventType;
  readonly tool?: string;
  readonly namespace?: string;
  readonly tags?: readonly string[];
  readonly from_date?: string;
  readonly to_date?: string;
  readonly success?: boolean;
  readonly redaction_level?: RedactionLevel;
  readonly sort?: 'asc' | 'desc';
  readonly limit?: number;
  readonly offset?: number;
}

// ── Query Result ──

export interface QueryResult {
  readonly results: readonly ProofEntry[];
  readonly total: number;
  readonly has_more: boolean;
}

// ── Export Parameters ──

export interface ExportParams {
  readonly format: 'jsonl' | 'json' | 'csv';
  readonly from_date?: string;
  readonly to_date?: string;
  readonly namespace?: string;
  readonly export_scope?: 'full' | 'filtered' | 'trace' | 'session';
  readonly trace_id?: string;
  readonly session_id?: string;
  readonly include_verification?: boolean;
  readonly include_hash_material?: boolean;
  readonly include_signatures?: boolean;
  readonly include_redacted_summaries?: boolean;
  readonly sign_export?: boolean;
  readonly checkpoint_bundle?: boolean;
}

// ── Export Result ──

export interface ExportResult {
  readonly file_path: string;
  readonly total_proofs: number;
  readonly chain_valid: boolean;
  readonly export_hash: string;
  readonly export_signature?: string;
}

// ── Config ──

export interface AgentproofsConfig {
  readonly dataDir: string;
  readonly agentId: string;
  readonly userId: string;
  readonly namespace: string;
  readonly logLevel: 'debug' | 'info' | 'warn' | 'error';
  readonly retentionDays: number;
  readonly segmentSize: number;
  readonly segmentMaxAge: number;
  readonly redactionLevel: RedactionLevel;
  readonly socketPath: string;
  readonly httpPort: number;
  readonly keyStore: 'file' | 'keychain' | 'hsm';
  readonly checkpointInterval: number;
}

// ── Key Pair ──

export interface KeyPair {
  readonly privateKey: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly keyId: string;
}

// ── Log Input (what callers provide) ──

export interface ProofLogInput {
  readonly event_type: EventType;
  readonly tool?: string;
  readonly tool_invocation_id?: string;
  readonly trace_id?: string;
  readonly span_id?: string;
  readonly input_hash?: string;
  readonly output_hash?: string;
  readonly input_summary?: string;
  readonly output_summary?: string;
  readonly success: boolean;
  readonly error_message?: string;
  readonly reason?: string;
  readonly namespace?: string;
  readonly tags?: readonly string[];
  readonly duration_ms?: number;
  readonly origin?: Origin;
  readonly parent_event_id?: string;
  readonly redaction_level?: RedactionLevel;
  readonly working_dir?: string;
  readonly git_commit?: string;
  readonly repo_dirty?: boolean;
  readonly model_id?: string;
  readonly model_version?: string;
}

// ── Log Result ──

export interface ProofLogResult {
  readonly proof_id: string;
  readonly sequence: number;
  readonly hash: string;
  readonly signature: string;
  readonly key_id: string;
}

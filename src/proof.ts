import { hostname } from 'node:os';
import { sha256, generateProofId, signHash } from './crypto.ts';
import { canonicalize } from './canonical.ts';
import type {
  ProofEntry,
  ProofLogInput,
  ProofLogResult,
  HashableEntry,
  KeyPair,
  AgentproofsConfig,
} from './types.ts';

// ── Timestamp ──

export function nowTimestamp(): string {
  return new Date().toISOString();
}

let monotonicBase: bigint | null = null;

export function monotonicTimeNs(): number {
  if (monotonicBase === null) {
    monotonicBase = process.hrtime.bigint();
  }
  return Number(process.hrtime.bigint() - monotonicBase);
}

// ── Create Proof Entry ──

export function createProofEntry(
  input: ProofLogInput,
  config: AgentproofsConfig,
  chainId: string,
  sequence: number,
  prevHash: string,
  keyPair: KeyPair,
  sessionId: string,
): ProofEntry {
  const hashable: HashableEntry = {
    schema_version: 1,
    chain_id: chainId,
    id: generateProofId(),
    sequence,
    prev_hash: prevHash,
    hash_algorithm: 'sha256',
    signature_algorithm: 'ed25519',
    key_id: keyPair.keyId,
    timestamp: nowTimestamp(),
    monotonic_time_ns: monotonicTimeNs(),
    agent_id: config.agentId,
    session_id: sessionId,
    ...(config.userId ? { user_id: config.userId } : {}),
    host_id: hostname(),
    process_id: process.pid,
    event_type: input.event_type,
    ...(input.tool_invocation_id ? { tool_invocation_id: input.tool_invocation_id } : {}),
    ...(input.trace_id ? { trace_id: input.trace_id } : {}),
    ...(input.span_id ? { span_id: input.span_id } : {}),
    action: {
      ...(input.tool ? { tool: input.tool } : {}),
      input_hash: input.input_hash ?? sha256(input.input_summary ?? ''),
      output_hash: input.output_hash ?? sha256(input.output_summary ?? ''),
      ...(input.input_summary ? { input_summary: input.input_summary } : {}),
      ...(input.output_summary ? { output_summary: input.output_summary } : {}),
      ...(input.duration_ms !== undefined ? { duration_ms: input.duration_ms } : {}),
      success: input.success,
      ...(input.error_message ? { error_message: input.error_message } : {}),
    },
    context: {
      ...(input.working_dir ? { working_dir: input.working_dir } : {}),
      namespace: input.namespace ?? config.namespace,
      ...(input.reason ? { reason: input.reason } : {}),
      ...(input.parent_event_id ? { parent_event_id: input.parent_event_id } : {}),
      ...(input.tags && input.tags.length > 0 ? { tags: input.tags } : {}),
      origin: input.origin ?? 'mcp',
      ...(input.git_commit ? { git_commit: input.git_commit } : {}),
      ...(input.repo_dirty !== undefined ? { repo_dirty: input.repo_dirty } : {}),
      ...(input.model_id ? { model_id: input.model_id } : {}),
      ...(input.model_version ? { model_version: input.model_version } : {}),
    },
    compliance: {
      redaction_level: input.redaction_level ?? config.redactionLevel,
    },
  };

  const canonical = canonicalize(hashable);
  const hash = sha256(canonical);
  const signature = signHash(hash, keyPair.privateKey);

  return {
    ...hashable,
    hash,
    signature,
  };
}

// ── Extract Log Result ──

export function toLogResult(entry: ProofEntry): ProofLogResult {
  return {
    proof_id: entry.id,
    sequence: entry.sequence,
    hash: entry.hash,
    signature: entry.signature,
    key_id: entry.key_id,
  };
}

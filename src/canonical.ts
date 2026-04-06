import type { HashableEntry } from './types.ts';

/**
 * Canonical field order for deterministic hash computation.
 * Based on RFC 8785 (JCS) principles with explicit field ordering.
 *
 * Rules:
 * - Fixed field order (not alphabetical)
 * - UTF-8 encoding, no BOM
 * - Omitted fields are excluded (not set to null)
 * - Numbers: no leading/trailing zeros, -0 → 0
 * - Timestamps: always UTC, millisecond precision, Z suffix
 * - Arrays: preserved order
 * - Fields 'hash' and 'signature' are never included
 */

// Flat field order for canonical serialization
const TOP_LEVEL_FIELDS: ReadonlyArray<keyof HashableEntry> = [
  'schema_version',
  'chain_id',
  'id',
  'sequence',
  'prev_hash',
  'hash_algorithm',
  'signature_algorithm',
  'key_id',
  'timestamp',
  'monotonic_time_ns',
  'agent_id',
  'session_id',
  'user_id',
  'host_id',
  'process_id',
  'event_type',
  'tool_invocation_id',
  'trace_id',
  'span_id',
  'action',
  'context',
  'compliance',
];

const ACTION_FIELDS = [
  'tool',
  'input_hash',
  'output_hash',
  'input_summary',
  'output_summary',
  'input_encrypted',
  'output_encrypted',
  'duration_ms',
  'success',
  'error_message',
] as const;

const CONTEXT_FIELDS = [
  'working_dir',
  'namespace',
  'reason',
  'parent_event_id',
  'tags',
  'origin',
  'git_commit',
  'repo_dirty',
  'model_id',
  'model_version',
] as const;

const COMPLIANCE_FIELDS = [
  'eu_ai_act_category',
  'data_categories',
  'retention_days',
  'redaction_level',
] as const;

function canonicalValue(value: unknown): string | undefined {
  if (value === undefined || value === null) return undefined;

  if (typeof value === 'string') return JSON.stringify(value);

  if (typeof value === 'number') {
    // Normalize -0 to 0
    const n = Object.is(value, -0) ? 0 : value;
    return JSON.stringify(n);
  }

  if (typeof value === 'boolean') return value ? 'true' : 'false';

  if (Array.isArray(value)) {
    const items = value.map((v) => canonicalValue(v)).filter((v) => v !== undefined);
    return `[${items.join(',')}]`;
  }

  return undefined;
}

function canonicalObject(
  obj: Record<string, unknown>,
  fieldOrder: readonly string[],
): string {
  const pairs: string[] = [];
  for (const field of fieldOrder) {
    const val = canonicalValue(obj[field]);
    if (val !== undefined) {
      pairs.push(`${JSON.stringify(field)}:${val}`);
    }
  }
  return `{${pairs.join(',')}}`;
}

/**
 * Produce canonical JSON bytes for a proof entry (excluding hash and signature).
 * This is the input to SHA-256 for hash computation.
 */
export function canonicalize(entry: HashableEntry): string {
  const pairs: string[] = [];

  for (const field of TOP_LEVEL_FIELDS) {
    const value = entry[field];
    if (value === undefined || value === null) continue;

    if (field === 'action') {
      pairs.push(
        `${JSON.stringify(field)}:${canonicalObject(value as unknown as Record<string, unknown>, ACTION_FIELDS)}`,
      );
    } else if (field === 'context') {
      pairs.push(
        `${JSON.stringify(field)}:${canonicalObject(value as unknown as Record<string, unknown>, CONTEXT_FIELDS)}`,
      );
    } else if (field === 'compliance') {
      pairs.push(
        `${JSON.stringify(field)}:${canonicalObject(value as unknown as Record<string, unknown>, COMPLIANCE_FIELDS)}`,
      );
    } else {
      const val = canonicalValue(value);
      if (val !== undefined) {
        pairs.push(`${JSON.stringify(field)}:${val}`);
      }
    }
  }

  return `{${pairs.join(',')}}`;
}

import { readAllEntries } from './chain.ts';
import type { ProofEntry, QueryParams, QueryResult } from './types.ts';

// ── In-Memory Query (v1 — no SQLite yet) ──

function matchesEntry(entry: ProofEntry, params: QueryParams): boolean {
  if (params.proof_id !== undefined && entry.id !== params.proof_id) return false;
  if (params.agent_id !== undefined && entry.agent_id !== params.agent_id) return false;
  if (params.session_id !== undefined && entry.session_id !== params.session_id) return false;
  if (params.trace_id !== undefined && entry.trace_id !== params.trace_id) return false;
  if (params.event_type !== undefined && entry.event_type !== params.event_type) return false;
  if (params.tool !== undefined && entry.action.tool !== params.tool) return false;
  if (params.namespace !== undefined && entry.context.namespace !== params.namespace) return false;
  if (params.success !== undefined && entry.action.success !== params.success) return false;

  if (params.from_date !== undefined && entry.timestamp < params.from_date) return false;
  if (params.to_date !== undefined && entry.timestamp > params.to_date) return false;

  if (params.redaction_level !== undefined) {
    const entryLevel = entry.compliance?.redaction_level ?? 0;
    if (entryLevel < params.redaction_level) return false;
  }

  if (params.tags !== undefined && params.tags.length > 0) {
    const entryTags = entry.context.tags ?? [];
    for (const tag of params.tags) {
      if (!entryTags.includes(tag)) return false;
    }
  }

  return true;
}

export async function queryProofs(
  dataDir: string,
  params: QueryParams,
): Promise<QueryResult> {
  const allEntries = await readAllEntries(dataDir);

  const filtered = allEntries.filter((entry) => matchesEntry(entry, params));

  // Sort
  const sorted = params.sort === 'asc'
    ? filtered
    : [...filtered].reverse();

  // Pagination
  const limit = params.limit ?? 50;
  const offset = params.offset ?? 0;
  const total = sorted.length;
  const results = sorted.slice(offset, offset + limit);

  return {
    results,
    total,
    has_more: offset + limit < total,
  };
}

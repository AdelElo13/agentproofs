import { readAllEntries } from './chain.ts';
import type { ProofEntry, ProofLogInput } from './types.ts';

/**
 * Detect orphaned tool_started events (no matching completion).
 * Returns recovery inputs to log tool_failed for each orphan.
 */
export async function detectOrphans(
  dataDir: string,
): Promise<readonly ProofLogInput[]> {
  const entries = await readAllEntries(dataDir);
  return findOrphanedStarts(entries);
}

export function findOrphanedStarts(
  entries: readonly ProofEntry[],
): readonly ProofLogInput[] {
  // Track tool_started events by tool_invocation_id
  const pendingStarts = new Map<string, ProofEntry>();

  for (const entry of entries) {
    if (entry.event_type === 'tool_started' && entry.tool_invocation_id) {
      pendingStarts.set(entry.tool_invocation_id, entry);
    } else if (
      (entry.event_type === 'tool_completed' ||
       entry.event_type === 'tool_failed' ||
       entry.event_type === 'tool_denied') &&
      entry.tool_invocation_id
    ) {
      pendingStarts.delete(entry.tool_invocation_id);
    }
  }

  // Remaining entries are orphaned starts
  return Array.from(pendingStarts.values()).map((start) => ({
    event_type: 'tool_failed' as const,
    tool: start.action.tool,
    tool_invocation_id: start.tool_invocation_id,
    input_hash: start.action.input_hash,
    output_hash: start.action.output_hash,
    success: false,
    error_message: 'orphaned_start_detected',
    origin: 'daemon' as const,
    reason: `Orphaned tool_started at sequence ${start.sequence} — no matching completion found`,
  }));
}

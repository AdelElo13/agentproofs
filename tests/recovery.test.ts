import { describe, it, expect } from 'vitest';
import { findOrphanedStarts } from '../src/recovery.ts';
import type { ProofEntry } from '../src/types.ts';

function makeProof(eventType: string, invocationId?: string): ProofEntry {
  return {
    schema_version: 1,
    chain_id: 'ch_test',
    id: `ap_${Math.random().toString(36).slice(2)}`,
    sequence: 1,
    prev_hash: 'genesis',
    hash: 'abc',
    signature: 'sig',
    hash_algorithm: 'sha256',
    signature_algorithm: 'ed25519',
    key_id: 'key1',
    timestamp: new Date().toISOString(),
    agent_id: 'test',
    session_id: 'sess',
    event_type: eventType as any,
    tool_invocation_id: invocationId,
    action: { tool: 'Bash', input_hash: 'abc', output_hash: 'def', success: true },
    context: { origin: 'hook' },
  } as ProofEntry;
}

describe('Orphan Detection', () => {
  it('finds no orphans in complete chain', () => {
    const entries = [
      makeProof('tool_started', 'inv_1'),
      makeProof('tool_completed', 'inv_1'),
      makeProof('tool_started', 'inv_2'),
      makeProof('tool_completed', 'inv_2'),
    ];
    expect(findOrphanedStarts(entries)).toHaveLength(0);
  });

  it('detects orphaned tool_started', () => {
    const entries = [
      makeProof('tool_started', 'inv_1'),
      makeProof('tool_completed', 'inv_1'),
      makeProof('tool_started', 'inv_2'), // orphan — no completion
    ];
    const orphans = findOrphanedStarts(entries);
    expect(orphans).toHaveLength(1);
    expect(orphans[0].tool_invocation_id).toBe('inv_2');
    expect(orphans[0].error_message).toBe('orphaned_start_detected');
  });

  it('handles tool_failed as valid completion', () => {
    const entries = [
      makeProof('tool_started', 'inv_1'),
      makeProof('tool_failed', 'inv_1'),
    ];
    expect(findOrphanedStarts(entries)).toHaveLength(0);
  });

  it('handles tool_denied as valid completion', () => {
    const entries = [
      makeProof('tool_started', 'inv_1'),
      makeProof('tool_denied', 'inv_1'),
    ];
    expect(findOrphanedStarts(entries)).toHaveLength(0);
  });

  it('handles empty chain', () => {
    expect(findOrphanedStarts([])).toHaveLength(0);
  });

  it('handles multiple orphans', () => {
    const entries = [
      makeProof('tool_started', 'inv_1'),
      makeProof('tool_started', 'inv_2'),
      makeProof('tool_started', 'inv_3'),
      makeProof('tool_completed', 'inv_1'),
    ];
    const orphans = findOrphanedStarts(entries);
    expect(orphans).toHaveLength(2);
  });
});

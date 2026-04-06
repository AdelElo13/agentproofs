import { describe, it, expect } from 'vitest';
import { canonicalize } from '../src/canonical.ts';
import type { HashableEntry } from '../src/types.ts';

function makeEntry(overrides: Partial<HashableEntry> = {}): HashableEntry {
  return {
    schema_version: 1,
    chain_id: 'ch_test',
    id: 'ap_test',
    sequence: 1,
    prev_hash: 'genesis',
    hash_algorithm: 'sha256',
    signature_algorithm: 'ed25519',
    key_id: 'testkey123456789',
    timestamp: '2026-04-06T10:00:00.000Z',
    agent_id: 'claude-code',
    session_id: 'sess_test',
    event_type: 'tool_completed',
    action: {
      tool: 'Bash',
      input_hash: 'abc123',
      output_hash: 'def456',
      success: true,
    },
    context: {
      namespace: 'default',
      origin: 'hook',
    },
    ...overrides,
  };
}

describe('Canonicalization', () => {
  it('produces deterministic output', () => {
    const entry = makeEntry();
    const c1 = canonicalize(entry);
    const c2 = canonicalize(entry);
    expect(c1).toBe(c2);
  });

  it('maintains fixed field order', () => {
    const entry = makeEntry();
    const canonical = canonicalize(entry);

    // schema_version should come before chain_id
    const svIdx = canonical.indexOf('"schema_version"');
    const ciIdx = canonical.indexOf('"chain_id"');
    expect(svIdx).toBeLessThan(ciIdx);

    // action should come before context
    const actIdx = canonical.indexOf('"action"');
    const ctxIdx = canonical.indexOf('"context"');
    expect(actIdx).toBeLessThan(ctxIdx);
  });

  it('omits undefined/null fields', () => {
    const entry = makeEntry();
    // No user_id, trace_id, etc. set
    const canonical = canonicalize(entry);
    expect(canonical).not.toContain('"user_id"');
    expect(canonical).not.toContain('"trace_id"');
    expect(canonical).not.toContain('"span_id"');
  });

  it('includes optional fields when present', () => {
    const entry = makeEntry({
      user_id: 'adel',
      trace_id: 'trace_123',
    });
    const canonical = canonicalize(entry);
    expect(canonical).toContain('"user_id":"adel"');
    expect(canonical).toContain('"trace_id":"trace_123"');
  });

  it('handles boolean values correctly', () => {
    const entry = makeEntry();
    const canonical = canonicalize(entry);
    expect(canonical).toContain('"success":true');
  });

  it('handles number values correctly', () => {
    const entry = makeEntry({
      action: {
        tool: 'Bash',
        input_hash: 'abc',
        output_hash: 'def',
        success: true,
        duration_ms: 150,
      },
    });
    const canonical = canonicalize(entry);
    expect(canonical).toContain('"duration_ms":150');
  });

  it('handles arrays in tags', () => {
    const entry = makeEntry({
      context: {
        namespace: 'default',
        origin: 'hook',
        tags: ['security', 'auth'],
      },
    });
    const canonical = canonicalize(entry);
    expect(canonical).toContain('"tags":["security","auth"]');
  });

  it('different entries produce different canonical forms', () => {
    const entry1 = makeEntry({ sequence: 1 });
    const entry2 = makeEntry({ sequence: 2 });
    expect(canonicalize(entry1)).not.toBe(canonicalize(entry2));
  });

  it('handles compliance fields', () => {
    const entry = makeEntry({
      compliance: {
        eu_ai_act_category: 'high',
        data_categories: ['personal_data'],
        retention_days: 180,
        redaction_level: 1,
      },
    });
    const canonical = canonicalize(entry);
    expect(canonical).toContain('"compliance"');
    expect(canonical).toContain('"eu_ai_act_category":"high"');
    expect(canonical).toContain('"redaction_level":1');
  });

  it('action fields maintain fixed order', () => {
    const entry = makeEntry({
      action: {
        tool: 'Bash',
        input_hash: 'abc',
        output_hash: 'def',
        input_summary: 'npm install',
        success: true,
        duration_ms: 100,
      },
    });
    const canonical = canonicalize(entry);

    // tool before input_hash before output_hash
    const toolIdx = canonical.indexOf('"tool"');
    const ihIdx = canonical.indexOf('"input_hash"');
    const ohIdx = canonical.indexOf('"output_hash"');
    expect(toolIdx).toBeLessThan(ihIdx);
    expect(ihIdx).toBeLessThan(ohIdx);
  });
});

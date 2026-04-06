import { describe, it, expect } from 'vitest';
import { createProofEntry, toLogResult } from '../src/proof.ts';
import { generateKeyPair, sha256 } from '../src/crypto.ts';
import { canonicalize } from '../src/canonical.ts';
import type { ProofLogInput, AgentproofsConfig } from '../src/types.ts';

const testConfig: AgentproofsConfig = {
  dataDir: '/tmp/agentproofs-test',
  agentId: 'test-agent',
  userId: '',
  namespace: 'test',
  logLevel: 'error',
  retentionDays: 365,
  segmentSize: 10000,
  segmentMaxAge: 86400,
  redactionLevel: 0,
  socketPath: '/tmp/test.sock',
  httpPort: 0,
  keyStore: 'file',
  checkpointInterval: 0,
};

const testInput: ProofLogInput = {
  event_type: 'tool_completed',
  tool: 'Bash',
  input_hash: sha256('ls -la'),
  output_hash: sha256('file1.txt\nfile2.txt'),
  success: true,
  duration_ms: 42,
  origin: 'hook',
};

describe('Proof Entry Creation', () => {
  it('creates a valid proof entry', () => {
    const kp = generateKeyPair();
    const entry = createProofEntry(
      testInput, testConfig, 'ch_test', 1, 'genesis', kp, 'sess_test',
    );

    expect(entry.schema_version).toBe(1);
    expect(entry.chain_id).toBe('ch_test');
    expect(entry.sequence).toBe(1);
    expect(entry.prev_hash).toBe('genesis');
    expect(entry.hash_algorithm).toBe('sha256');
    expect(entry.signature_algorithm).toBe('ed25519');
    expect(entry.key_id).toBe(kp.keyId);
    expect(entry.agent_id).toBe('test-agent');
    expect(entry.session_id).toBe('sess_test');
    expect(entry.event_type).toBe('tool_completed');
    expect(entry.action.tool).toBe('Bash');
    expect(entry.action.success).toBe(true);
    expect(entry.action.duration_ms).toBe(42);
    expect(entry.context.namespace).toBe('test');
    expect(entry.context.origin).toBe('hook');
  });

  it('computes a valid hash', () => {
    const kp = generateKeyPair();
    const entry = createProofEntry(
      testInput, testConfig, 'ch_test', 1, 'genesis', kp, 'sess_test',
    );

    // Recompute hash manually
    const { hash: _h, signature: _s, ...hashable } = entry;
    const computed = sha256(canonicalize(hashable));
    expect(computed).toBe(entry.hash);
  });

  it('hash changes when any field changes', () => {
    const kp = generateKeyPair();
    const entry1 = createProofEntry(
      testInput, testConfig, 'ch_test', 1, 'genesis', kp, 'sess_test',
    );
    const entry2 = createProofEntry(
      { ...testInput, success: false }, testConfig, 'ch_test', 2, entry1.hash, kp, 'sess_test',
    );

    expect(entry1.hash).not.toBe(entry2.hash);
  });

  it('auto-computes input/output hash from summary when not provided', () => {
    const kp = generateKeyPair();
    const input: ProofLogInput = {
      event_type: 'decision',
      input_summary: 'Use JWT for auth',
      output_summary: 'Decision recorded',
      success: true,
      origin: 'manual',
    };

    const entry = createProofEntry(input, testConfig, 'ch_test', 1, 'genesis', kp, 'sess_test');
    expect(entry.action.input_hash).toBe(sha256('Use JWT for auth'));
    expect(entry.action.output_hash).toBe(sha256('Decision recorded'));
  });

  it('includes optional fields when provided', () => {
    const kp = generateKeyPair();
    const input: ProofLogInput = {
      ...testInput,
      trace_id: 'trace_abc',
      span_id: 'span_123',
      tool_invocation_id: 'inv_456',
      reason: 'Installing dependencies',
      tags: ['setup', 'npm'],
      git_commit: 'abc123',
      repo_dirty: true,
    };

    const entry = createProofEntry(input, testConfig, 'ch_test', 1, 'genesis', kp, 'sess_test');
    expect(entry.trace_id).toBe('trace_abc');
    expect(entry.span_id).toBe('span_123');
    expect(entry.tool_invocation_id).toBe('inv_456');
    expect(entry.context.reason).toBe('Installing dependencies');
    expect(entry.context.tags).toEqual(['setup', 'npm']);
    expect(entry.context.git_commit).toBe('abc123');
    expect(entry.context.repo_dirty).toBe(true);
  });

  it('uses config namespace when not provided in input', () => {
    const kp = generateKeyPair();
    const input: ProofLogInput = {
      event_type: 'tool_completed',
      success: true,
      origin: 'hook',
    };

    const entry = createProofEntry(input, testConfig, 'ch_test', 1, 'genesis', kp, 'sess_test');
    expect(entry.context.namespace).toBe('test');
  });

  it('uses input namespace over config namespace', () => {
    const kp = generateKeyPair();
    const input: ProofLogInput = {
      event_type: 'tool_completed',
      success: true,
      origin: 'hook',
      namespace: 'custom',
    };

    const entry = createProofEntry(input, testConfig, 'ch_test', 1, 'genesis', kp, 'sess_test');
    expect(entry.context.namespace).toBe('custom');
  });
});

describe('Log Result', () => {
  it('extracts correct fields', () => {
    const kp = generateKeyPair();
    const entry = createProofEntry(
      testInput, testConfig, 'ch_test', 1, 'genesis', kp, 'sess_test',
    );
    const result = toLogResult(entry);

    expect(result.proof_id).toBe(entry.id);
    expect(result.sequence).toBe(1);
    expect(result.hash).toBe(entry.hash);
    expect(result.signature).toBe(entry.signature);
    expect(result.key_id).toBe(kp.keyId);
  });
});

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { tmpdir } from 'node:os';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { initChain, appendProof } from '../src/chain.ts';
import { createProofEntry } from '../src/proof.ts';
import { exportProofs } from '../src/export.ts';
import { generateKeyPair, generateChainId, sha256, verifySignature } from '../src/crypto.ts';
import type { ProofLogInput, AgentproofsConfig, KeyPair } from '../src/types.ts';

let tmpDir: string;
let kp: KeyPair;
let chainId: string;
let config: AgentproofsConfig;

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), 'agentproofs-export-'));
  kp = generateKeyPair();
  chainId = generateChainId();
  config = {
    dataDir: tmpDir,
    agentId: 'test-agent',
    userId: '',
    namespace: 'default',
    logLevel: 'error',
    retentionDays: 365,
    segmentSize: 10000,
    segmentMaxAge: 86400,
    redactionLevel: 0,
    socketPath: '',
    httpPort: 0,
    keyStore: 'file',
    checkpointInterval: 0,
  };
  await initChain(tmpDir);

  // Seed 3 entries
  let prevHash = 'genesis';
  for (let i = 1; i <= 3; i++) {
    const entry = createProofEntry(
      {
        event_type: 'tool_completed',
        tool: 'Bash',
        input_hash: sha256(`input-${i}`),
        output_hash: sha256(`output-${i}`),
        success: true,
        origin: 'hook',
      },
      config, chainId, i, prevHash, kp, 'sess_test',
    );
    await appendProof(tmpDir, '000001', entry);
    prevHash = entry.hash;
  }
});

afterEach(async () => {
  await rm(tmpDir, { recursive: true });
});

describe('Export', () => {
  it('exports as JSONL', async () => {
    const result = await exportProofs(tmpDir, { format: 'jsonl' });
    expect(result.total_proofs).toBe(3);
    expect(result.file_path).toContain('.jsonl');
    expect(result.export_hash).toMatch(/^[0-9a-f]{64}$/);

    const content = await readFile(result.file_path, 'utf-8');
    const lines = content.trim().split('\n');
    expect(lines).toHaveLength(3);

    // Each line is valid JSON
    for (const line of lines) {
      const entry = JSON.parse(line);
      expect(entry.id).toMatch(/^ap_/);
    }
  });

  it('exports as JSON', async () => {
    const result = await exportProofs(tmpDir, { format: 'json' });
    expect(result.file_path).toContain('.json');

    const content = await readFile(result.file_path, 'utf-8');
    const entries = JSON.parse(content);
    expect(entries).toHaveLength(3);
  });

  it('exports as CSV', async () => {
    const result = await exportProofs(tmpDir, { format: 'csv' });
    expect(result.file_path).toContain('.csv');

    const content = await readFile(result.file_path, 'utf-8');
    const lines = content.trim().split('\n');
    expect(lines).toHaveLength(4); // header + 3 rows

    // Check header
    expect(lines[0]).toContain('id');
    expect(lines[0]).toContain('sequence');
    expect(lines[0]).toContain('timestamp');
  });

  it('signs the export', async () => {
    const result = await exportProofs(tmpDir, { format: 'jsonl', sign_export: true }, kp);
    expect(result.export_signature).toBeDefined();

    // Verify signature
    const isValid = verifySignature(result.export_hash, result.export_signature!, kp.publicKey);
    expect(isValid).toBe(true);
  });

  it('filters by namespace', async () => {
    // Add an entry with a different namespace
    const entry = createProofEntry(
      {
        event_type: 'tool_completed',
        tool: 'Edit',
        input_hash: sha256('special'),
        output_hash: sha256('result'),
        success: true,
        origin: 'hook',
        namespace: 'special-ns',
      },
      config, chainId, 4, sha256('prev'), kp, 'sess_test',
    );
    await appendProof(tmpDir, '000001', entry);

    const result = await exportProofs(tmpDir, { format: 'jsonl', namespace: 'special-ns' });
    expect(result.total_proofs).toBe(1);
  });

  it('exports empty chain without error', async () => {
    const emptyDir = await mkdtemp(join(tmpdir(), 'agentproofs-empty-'));
    await initChain(emptyDir);

    const result = await exportProofs(emptyDir, { format: 'jsonl' });
    expect(result.total_proofs).toBe(0);

    await rm(emptyDir, { recursive: true });
  });
});

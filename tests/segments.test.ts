import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { tmpdir } from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { initChain, appendProof } from '../src/chain.ts';
import { createProofEntry } from '../src/proof.ts';
import { sealSegment, loadManifest, listSegments, shouldSealSegment } from '../src/segments.ts';
import { generateKeyPair, generateChainId, sha256 } from '../src/crypto.ts';
import type { AgentproofsConfig, KeyPair } from '../src/types.ts';

let tmpDir: string;
let kp: KeyPair;
let chainId: string;

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), 'agentproofs-seg-'));
  kp = generateKeyPair();
  chainId = generateChainId();
  await initChain(tmpDir);
});

afterEach(async () => {
  await rm(tmpDir, { recursive: true });
});

async function seedSegment(n: number): Promise<void> {
  let prevHash = 'genesis';
  for (let i = 1; i <= n; i++) {
    const entry = createProofEntry({
      event_type: 'tool_completed', tool: 'Bash',
      input_hash: sha256(`in-${i}`), output_hash: sha256(`out-${i}`),
      success: true, origin: 'hook',
    }, {
      dataDir: tmpDir, agentId: 'test', userId: '', namespace: 'test',
      logLevel: 'error', retentionDays: 365, segmentSize: 10000,
      segmentMaxAge: 86400, redactionLevel: 0, socketPath: '', httpPort: 0,
      keyStore: 'file', checkpointInterval: 0,
    }, chainId, i, prevHash, kp, 'sess');
    await appendProof(tmpDir, '000001', entry);
    prevHash = entry.hash;
  }
}

describe('Segments', () => {
  it('seals a segment and creates manifest', async () => {
    await seedSegment(5);
    const manifest = await sealSegment(tmpDir, '000001', kp);

    expect(manifest.segment_id).toBe('000001');
    expect(manifest.proof_count).toBe(5);
    expect(manifest.first_sequence).toBe(1);
    expect(manifest.last_sequence).toBe(5);
    expect(manifest.signature).toBeTruthy();
    expect(manifest.segment_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('loads manifest from disk', async () => {
    await seedSegment(3);
    await sealSegment(tmpDir, '000001', kp);

    const loaded = await loadManifest(tmpDir, '000001');
    expect(loaded).not.toBeNull();
    expect(loaded!.proof_count).toBe(3);
  });

  it('returns null for missing manifest', async () => {
    const loaded = await loadManifest(tmpDir, '999999');
    expect(loaded).toBeNull();
  });

  it('lists segments with manifest status', async () => {
    await seedSegment(3);
    const beforeSeal = await listSegments(tmpDir);
    expect(beforeSeal).toHaveLength(1);
    expect(beforeSeal[0].hasManifest).toBe(false);

    await sealSegment(tmpDir, '000001', kp);
    const afterSeal = await listSegments(tmpDir);
    expect(afterSeal[0].hasManifest).toBe(true);
  });

  it('throws on empty segment', async () => {
    await expect(sealSegment(tmpDir, '000001', kp)).rejects.toThrow('empty');
  });
});

describe('shouldSealSegment', () => {
  it('seals when size exceeds threshold', () => {
    expect(shouldSealSegment(10001, new Date().toISOString(), 10000, 86400)).toBe(true);
  });

  it('seals when age exceeds threshold', () => {
    const old = new Date(Date.now() - 100000 * 1000).toISOString();
    expect(shouldSealSegment(5, old, 10000, 86400)).toBe(true);
  });

  it('does not seal when below both thresholds', () => {
    expect(shouldSealSegment(100, new Date().toISOString(), 10000, 86400)).toBe(false);
  });
});

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { tmpdir } from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { initChain, appendProof, readSegmentEntries } from '../src/chain.ts';
import { createProofEntry } from '../src/proof.ts';
import { sealSegment, loadManifest } from '../src/segments.ts';
import { applyRetention } from '../src/retention.ts';
import { generateKeyPair, generateChainId, sha256 } from '../src/crypto.ts';
import type { KeyPair } from '../src/types.ts';

let tmpDir: string;
let kp: KeyPair;

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), 'agentproofs-ret-'));
  kp = generateKeyPair();
  await initChain(tmpDir);
});

afterEach(async () => {
  await rm(tmpDir, { recursive: true });
});

async function seedAndSeal(): Promise<void> {
  let prevHash = 'genesis';
  for (let i = 1; i <= 3; i++) {
    const entry = createProofEntry({
      event_type: 'tool_completed', tool: 'Bash',
      input_hash: sha256(`in-${i}`), output_hash: sha256(`out-${i}`),
      input_summary: `command ${i}`, output_summary: `result ${i}`,
      success: true, origin: 'hook',
    }, {
      dataDir: tmpDir, agentId: 'test', userId: '', namespace: 'test',
      logLevel: 'error', retentionDays: 365, segmentSize: 10000,
      segmentMaxAge: 86400, redactionLevel: 0, socketPath: '', httpPort: 0,
      keyStore: 'file', checkpointInterval: 0,
    }, generateChainId(), i, prevHash, kp, 'sess');
    await appendProof(tmpDir, '000001', entry);
    prevHash = entry.hash;
  }

  // Seal with very old date to trigger retention
  const manifest = await sealSegment(tmpDir, '000001', kp);

  // Backdate the manifest
  const { writeFile, readFile } = await import('node:fs/promises');
  const mPath = join(tmpDir, 'manifests', '000001.manifest.json');
  const m = JSON.parse(await readFile(mPath, 'utf-8'));
  m.sealed_at = new Date(Date.now() - 400 * 24 * 60 * 60 * 1000).toISOString();
  await writeFile(mPath, JSON.stringify(m, null, 2));
}

describe('Retention', () => {
  it('zeroes payloads after retention period', async () => {
    await seedAndSeal();

    const result = await applyRetention(tmpDir, '000001', 365);
    expect(result).not.toBeNull();
    expect(result!.payloadsZeroed).toBe(3);

    // Verify payloads are gone
    const entries = await readSegmentEntries(tmpDir, '000001');
    for (const e of entries) {
      expect(e.action.input_summary).toBeUndefined();
      expect(e.action.output_summary).toBeUndefined();
    }
  });

  it('preserves proof skeleton', async () => {
    await seedAndSeal();
    const beforeEntries = await readSegmentEntries(tmpDir, '000001');

    await applyRetention(tmpDir, '000001', 365);
    const afterEntries = await readSegmentEntries(tmpDir, '000001');

    // Skeleton fields preserved
    for (let i = 0; i < beforeEntries.length; i++) {
      expect(afterEntries[i].id).toBe(beforeEntries[i].id);
      expect(afterEntries[i].hash).toBe(beforeEntries[i].hash);
      expect(afterEntries[i].prev_hash).toBe(beforeEntries[i].prev_hash);
      expect(afterEntries[i].signature).toBe(beforeEntries[i].signature);
      expect(afterEntries[i].sequence).toBe(beforeEntries[i].sequence);
    }
  });

  it('updates manifest with retention_applied', async () => {
    await seedAndSeal();
    await applyRetention(tmpDir, '000001', 365);

    const manifest = await loadManifest(tmpDir, '000001');
    expect(manifest!.retention_applied).toBe(true);
  });

  it('skips retention if not sealed', async () => {
    // No manifest
    const result = await applyRetention(tmpDir, '000001', 365);
    expect(result).toBeNull();
  });

  it('skips if already retained', async () => {
    await seedAndSeal();
    await applyRetention(tmpDir, '000001', 365);

    // Second apply should be no-op
    const result = await applyRetention(tmpDir, '000001', 365);
    expect(result).toBeNull();
  });

  it('skips if not old enough', async () => {
    // Seed and seal with current date
    let prevHash = 'genesis';
    for (let i = 1; i <= 2; i++) {
      const entry = createProofEntry({
        event_type: 'tool_completed', tool: 'Bash',
        input_hash: sha256(`in-${i}`), output_hash: sha256(`out-${i}`),
        success: true, origin: 'hook',
      }, {
        dataDir: tmpDir, agentId: 'test', userId: '', namespace: 'test',
        logLevel: 'error', retentionDays: 365, segmentSize: 10000,
        segmentMaxAge: 86400, redactionLevel: 0, socketPath: '', httpPort: 0,
        keyStore: 'file', checkpointInterval: 0,
      }, generateChainId(), i, prevHash, kp, 'sess');
      await appendProof(tmpDir, '000001', entry);
      prevHash = entry.hash;
    }
    await sealSegment(tmpDir, '000001', kp);

    const result = await applyRetention(tmpDir, '000001', 365);
    expect(result).toBeNull();
  });
});

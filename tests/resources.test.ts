import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { tmpdir } from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { initChain, appendProof } from '../src/chain.ts';
import { createProofEntry } from '../src/proof.ts';
import { generateKeyPair, generateChainId, sha256, formatPublicKey } from '../src/crypto.ts';
import { getChainStatus, getStats, getLatest, getByAgent, getBySession } from '../src/resources.ts';
import type { AgentproofsConfig, KeyPair } from '../src/types.ts';

let tmpDir: string;
let kp: KeyPair;
let chainId: string;
let config: AgentproofsConfig;

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), 'agentproofs-resources-'));
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
});

afterEach(async () => {
  await rm(tmpDir, { recursive: true });
});

async function seed(count: number, overrides: Record<string, any> = {}): Promise<void> {
  let prevHash = 'genesis';
  for (let i = 1; i <= count; i++) {
    const entry = createProofEntry(
      {
        event_type: 'tool_completed',
        tool: i % 2 === 0 ? 'Edit' : 'Bash',
        input_hash: sha256(`in-${i}`),
        output_hash: sha256(`out-${i}`),
        success: true,
        origin: 'hook',
        ...overrides,
      },
      config, chainId, i, prevHash, kp, overrides.session_id ?? 'sess_test',
    );
    await appendProof(tmpDir, '000001', entry);
    prevHash = entry.hash;
  }
}

describe('Chain Status Resource', () => {
  it('returns empty status for new chain', async () => {
    const status = await getChainStatus(config, chainId);
    expect(status.length).toBe(0);
    expect(status.health).toBe('empty');
  });

  it('returns healthy status with proofs', async () => {
    await seed(5);
    const pubKeyFormatted = formatPublicKey(kp.publicKey);
    const status = await getChainStatus(config, chainId, pubKeyFormatted);
    expect(status.length).toBe(5);
    expect(status.health).toBe('healthy');
    expect(status.public_key).toMatch(/^ed25519:/);
    expect(status.chain_id).toBe(chainId);
  });
});

describe('Stats Resource', () => {
  it('computes statistics', async () => {
    await seed(6);
    const stats = await getStats(config);
    expect(stats.total_proofs).toBe(6);
    expect(stats.by_agent['test-agent']).toBe(6);
    expect(stats.by_tool['Bash']).toBe(3);
    expect(stats.by_tool['Edit']).toBe(3);
    expect(stats.by_event_type['tool_completed']).toBe(6);
  });

  it('returns empty stats for empty chain', async () => {
    const stats = await getStats(config);
    expect(stats.total_proofs).toBe(0);
    expect(Object.keys(stats.by_agent)).toHaveLength(0);
  });
});

describe('Latest Resource', () => {
  it('returns last N entries', async () => {
    await seed(25);
    const latest = await getLatest(config, 10);
    expect(latest).toHaveLength(10);
    // Should be the last 10 (sequences 16-25)
    expect(latest[0].sequence).toBe(16);
    expect(latest[9].sequence).toBe(25);
  });

  it('returns all if fewer than N', async () => {
    await seed(3);
    const latest = await getLatest(config, 20);
    expect(latest).toHaveLength(3);
  });
});

describe('By Agent Resource', () => {
  it('filters by agent', async () => {
    await seed(5);
    const entries = await getByAgent(config, 'test-agent');
    expect(entries).toHaveLength(5);

    const none = await getByAgent(config, 'nonexistent');
    expect(none).toHaveLength(0);
  });
});

describe('By Session Resource', () => {
  it('filters by session', async () => {
    await seed(3);
    const entries = await getBySession(config, 'sess_test');
    expect(entries).toHaveLength(3);

    const none = await getBySession(config, 'sess_other');
    expect(none).toHaveLength(0);
  });
});

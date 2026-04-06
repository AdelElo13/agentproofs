import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { tmpdir } from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { initChain, appendProof } from '../src/chain.ts';
import { createProofEntry } from '../src/proof.ts';
import { queryProofs } from '../src/query.ts';
import { generateKeyPair, generateChainId, sha256 } from '../src/crypto.ts';
import type { ProofLogInput, AgentproofsConfig, KeyPair } from '../src/types.ts';

let tmpDir: string;
let kp: KeyPair;
let chainId: string;
let config: AgentproofsConfig;

function makeInput(overrides: Partial<ProofLogInput> = {}): ProofLogInput {
  return {
    event_type: 'tool_completed',
    tool: 'Bash',
    input_hash: sha256('test'),
    output_hash: sha256('output'),
    success: true,
    origin: 'hook',
    ...overrides,
  };
}

async function seedChain(): Promise<void> {
  let prevHash = 'genesis';
  const inputs: ProofLogInput[] = [
    makeInput({ tool: 'Bash', namespace: 'project-a', tags: ['setup'] }),
    makeInput({ tool: 'Edit', namespace: 'project-a', tags: ['code'] }),
    makeInput({ tool: 'Bash', namespace: 'project-b', success: false, tags: ['deploy'] }),
    { event_type: 'decision' as const, namespace: 'project-a', tags: ['architecture'], success: true, origin: 'hook' as const },
    makeInput({ tool: 'Write', namespace: 'project-b', tags: ['code', 'setup'] }),
  ];

  for (let i = 0; i < inputs.length; i++) {
    const entry = createProofEntry(
      inputs[i], config, chainId, i + 1, prevHash, kp, 'sess_test',
    );
    await appendProof(tmpDir, '000001', entry);
    prevHash = entry.hash;
  }
}

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), 'agentproofs-query-'));
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
  await seedChain();
});

afterEach(async () => {
  await rm(tmpDir, { recursive: true });
});

describe('Query', () => {
  it('returns all proofs with no filters', async () => {
    const result = await queryProofs(tmpDir, {});
    expect(result.total).toBe(5);
    expect(result.results).toHaveLength(5);
  });

  it('filters by tool', async () => {
    const result = await queryProofs(tmpDir, { tool: 'Bash' });
    expect(result.total).toBe(2);
    expect(result.results.every((r) => r.action.tool === 'Bash')).toBe(true);
  });

  it('filters by namespace', async () => {
    const result = await queryProofs(tmpDir, { namespace: 'project-a' });
    expect(result.total).toBe(3);
  });

  it('filters by event_type', async () => {
    const result = await queryProofs(tmpDir, { event_type: 'decision' });
    expect(result.total).toBe(1);
    expect(result.results[0].event_type).toBe('decision');
  });

  it('filters by success', async () => {
    const result = await queryProofs(tmpDir, { success: false });
    expect(result.total).toBe(1);
    expect(result.results[0].action.success).toBe(false);
  });

  it('filters by tags (AND)', async () => {
    const result = await queryProofs(tmpDir, { tags: ['code', 'setup'] });
    expect(result.total).toBe(1); // only the last entry has both tags
  });

  it('paginates results', async () => {
    const page1 = await queryProofs(tmpDir, { limit: 2, offset: 0, sort: 'asc' });
    expect(page1.results).toHaveLength(2);
    expect(page1.has_more).toBe(true);

    const page2 = await queryProofs(tmpDir, { limit: 2, offset: 2, sort: 'asc' });
    expect(page2.results).toHaveLength(2);
    expect(page2.has_more).toBe(true);

    const page3 = await queryProofs(tmpDir, { limit: 2, offset: 4, sort: 'asc' });
    expect(page3.results).toHaveLength(1);
    expect(page3.has_more).toBe(false);
  });

  it('returns empty for no matches', async () => {
    const result = await queryProofs(tmpDir, { tool: 'Nonexistent' });
    expect(result.total).toBe(0);
    expect(result.results).toHaveLength(0);
    expect(result.has_more).toBe(false);
  });

  it('sorts descending by default', async () => {
    const result = await queryProofs(tmpDir, {});
    // Default is desc — last entry first
    expect(result.results[0].sequence).toBe(5);
    expect(result.results[4].sequence).toBe(1);
  });

  it('sorts ascending when specified', async () => {
    const result = await queryProofs(tmpDir, { sort: 'asc' });
    expect(result.results[0].sequence).toBe(1);
    expect(result.results[4].sequence).toBe(5);
  });
});

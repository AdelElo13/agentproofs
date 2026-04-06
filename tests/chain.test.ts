import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { tmpdir } from 'node:os';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  initChain,
  readChainState,
  appendProof,
  readSegmentEntries,
  readAllEntries,
  verifyChain,
  formatSegmentId,
} from '../src/chain.ts';
import { createProofEntry } from '../src/proof.ts';
import { generateKeyPair, generateChainId, sha256 } from '../src/crypto.ts';
import { canonicalize } from '../src/canonical.ts';
import type { ProofLogInput, AgentproofsConfig, ProofEntry, KeyPair } from '../src/types.ts';

let tmpDir: string;
let kp: KeyPair;
let chainId: string;

let testConfig: AgentproofsConfig = {
  dataDir: '', // set in beforeEach
  agentId: 'test-agent',
  userId: '',
  namespace: 'test',
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

function makeInput(overrides: Partial<ProofLogInput> = {}): ProofLogInput {
  return {
    event_type: 'tool_completed',
    tool: 'Bash',
    input_hash: sha256('test-input'),
    output_hash: sha256('test-output'),
    success: true,
    origin: 'hook',
    ...overrides,
  };
}

async function appendN(
  n: number,
  dataDir: string,
  config: AgentproofsConfig,
): Promise<ProofEntry[]> {
  const entries: ProofEntry[] = [];
  let prevHash = 'genesis';

  for (let i = 1; i <= n; i++) {
    const entry = createProofEntry(
      makeInput(), config, chainId, i, prevHash, kp, 'sess_test',
    );
    await appendProof(dataDir, '000001', entry);
    entries.push(entry);
    prevHash = entry.hash;
  }

  return entries;
}

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), 'agentproofs-chain-'));
  kp = generateKeyPair();
  chainId = generateChainId();
  testConfig = { ...testConfig, dataDir: tmpDir } as any;
  await initChain(tmpDir);
});

afterEach(async () => {
  await rm(tmpDir, { recursive: true });
});

describe('Chain Initialization', () => {
  it('creates directory structure', async () => {
    // initChain already called in beforeEach
    const state = await readChainState(tmpDir, chainId);
    expect(state.sequence).toBe(0);
    expect(state.lastHash).toBe('genesis');
    expect(state.proofCount).toBe(0);
  });
});

describe('Append and Read', () => {
  it('appends a genesis proof', async () => {
    const entry = createProofEntry(
      makeInput(), testConfig, chainId, 1, 'genesis', kp, 'sess_test',
    );
    await appendProof(tmpDir, '000001', entry);

    const entries = await readSegmentEntries(tmpDir, '000001');
    expect(entries).toHaveLength(1);
    expect(entries[0].prev_hash).toBe('genesis');
    expect(entries[0].sequence).toBe(1);
  });

  it('appends multiple proofs with correct linkage', async () => {
    const entries = await appendN(3, tmpDir, testConfig);

    expect(entries[0].prev_hash).toBe('genesis');
    expect(entries[1].prev_hash).toBe(entries[0].hash);
    expect(entries[2].prev_hash).toBe(entries[1].hash);
  });

  it('reads chain state after appends', async () => {
    const entries = await appendN(5, tmpDir, testConfig);
    const state = await readChainState(tmpDir, chainId);

    expect(state.sequence).toBe(5);
    expect(state.lastHash).toBe(entries[4].hash);
  });

  it('reads all entries across read', async () => {
    await appendN(3, tmpDir, testConfig);
    const all = await readAllEntries(tmpDir);
    expect(all).toHaveLength(3);
  });
});

describe('Chain Verification', () => {
  it('verifies an empty chain', async () => {
    const keys = new Map([[kp.keyId, kp.publicKey]]);
    const result = await verifyChain(tmpDir, keys);
    expect(result.valid).toBe(true);
    expect(result.verified).toBe(0);
  });

  it('verifies a valid chain', async () => {
    await appendN(5, tmpDir, testConfig);
    const keys = new Map([[kp.keyId, kp.publicKey]]);
    const result = await verifyChain(tmpDir, keys);

    expect(result.valid).toBe(true);
    expect(result.verified).toBe(5);
    expect(result.key_transitions).toBe(0);
  });

  it('detects tampered hash', async () => {
    await appendN(3, tmpDir, testConfig);

    // Tamper with the middle entry
    const segPath = join(tmpDir, 'segments', '000001.jsonl');
    const content = await readFile(segPath, 'utf-8');
    const lines = content.trim().split('\n');
    const entry = JSON.parse(lines[1]) as ProofEntry;
    const tampered = { ...entry, hash: sha256('tampered') };
    lines[1] = JSON.stringify(tampered);
    await writeFile(segPath, lines.join('\n') + '\n');

    const keys = new Map([[kp.keyId, kp.publicKey]]);
    const result = await verifyChain(tmpDir, keys);
    expect(result.valid).toBe(false);
    expect(result.first_invalid_sequence).toBe(2);
  });

  it('detects deleted entry', async () => {
    await appendN(3, tmpDir, testConfig);

    // Delete the middle entry
    const segPath = join(tmpDir, 'segments', '000001.jsonl');
    const content = await readFile(segPath, 'utf-8');
    const lines = content.trim().split('\n');
    lines.splice(1, 1); // Remove middle
    await writeFile(segPath, lines.join('\n') + '\n');

    const keys = new Map([[kp.keyId, kp.publicKey]]);
    const result = await verifyChain(tmpDir, keys);
    expect(result.valid).toBe(false);
  });

  it('detects inserted entry', async () => {
    const entries = await appendN(3, tmpDir, testConfig);

    // Insert a fake entry between 1 and 2
    const fake = { ...entries[0], sequence: 99, id: 'ap_fake' };
    const segPath = join(tmpDir, 'segments', '000001.jsonl');
    const content = await readFile(segPath, 'utf-8');
    const lines = content.trim().split('\n');
    lines.splice(1, 0, JSON.stringify(fake));
    await writeFile(segPath, lines.join('\n') + '\n');

    const keys = new Map([[kp.keyId, kp.publicKey]]);
    const result = await verifyChain(tmpDir, keys);
    expect(result.valid).toBe(false);
  });

  it('detects invalid signature', async () => {
    await appendN(2, tmpDir, testConfig);

    // Tamper with signature
    const segPath = join(tmpDir, 'segments', '000001.jsonl');
    const content = await readFile(segPath, 'utf-8');
    const lines = content.trim().split('\n');
    const entry = JSON.parse(lines[0]);
    entry.signature = 'AAAA' + entry.signature.slice(4); // corrupt sig
    lines[0] = JSON.stringify(entry);
    await writeFile(segPath, lines.join('\n') + '\n');

    const keys = new Map([[kp.keyId, kp.publicKey]]);
    const result = await verifyChain(tmpDir, keys);
    expect(result.valid).toBe(false);
    expect(result.first_invalid_reason).toContain('Signature');
  });

  it('detects unknown key_id', async () => {
    await appendN(2, tmpDir, testConfig);

    // Use empty key map
    const keys = new Map<string, Uint8Array>();
    const result = await verifyChain(tmpDir, keys);
    expect(result.valid).toBe(false);
    expect(result.first_invalid_reason).toContain('Unknown key_id');
  });

  it('verifies a range of entries', async () => {
    await appendN(10, tmpDir, testConfig);
    const keys = new Map([[kp.keyId, kp.publicKey]]);
    const result = await verifyChain(tmpDir, keys, {
      fromSequence: 5,
      toSequence: 8,
    });
    expect(result.valid).toBe(true);
  });
});

describe('Segment ID Formatting', () => {
  it('pads to 6 digits', () => {
    expect(formatSegmentId(1)).toBe('000001');
    expect(formatSegmentId(42)).toBe('000042');
    expect(formatSegmentId(999999)).toBe('999999');
  });
});

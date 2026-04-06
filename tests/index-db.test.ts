import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { tmpdir } from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { ProofIndex } from '../src/index-db.ts';
import { createProofEntry } from '../src/proof.ts';
import { generateKeyPair, generateChainId, sha256 } from '../src/crypto.ts';
import type { ProofLogInput, AgentproofsConfig, KeyPair } from '../src/types.ts';

let tmpDir: string;
let index: ProofIndex;
let kp: KeyPair;

const config: AgentproofsConfig = {
  dataDir: '',
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

function makeEntry(seq: number, overrides: Partial<ProofLogInput> = {}) {
  return createProofEntry({
    event_type: 'tool_completed',
    tool: 'Bash',
    input_hash: sha256(`input-${seq}`),
    output_hash: sha256(`output-${seq}`),
    success: true,
    origin: 'hook',
    ...overrides,
  }, { ...config, dataDir: tmpDir }, 'ch_test', seq, 'genesis', kp, 'sess_test');
}

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), 'agentproofs-idx-'));
  index = new ProofIndex(tmpDir);
  kp = generateKeyPair();
});

afterEach(() => {
  index.close();
});

describe('ProofIndex', () => {
  it('indexes and queries a proof', () => {
    const entry = makeEntry(1);
    index.indexProof(entry);

    const result = index.query({ tool: 'Bash' });
    expect(result.total).toBe(1);
    expect(result.ids).toHaveLength(1);
  });

  it('bulk indexes entries', () => {
    const entries = Array.from({ length: 100 }, (_, i) => makeEntry(i + 1));
    index.bulkIndex(entries);

    const stats = index.getStats();
    expect(stats.total).toBe(100);
  });

  it('queries by event_type', () => {
    index.indexProof(makeEntry(1, { event_type: 'tool_completed' }));
    index.indexProof(makeEntry(2, { event_type: 'session_started' }));

    expect(index.query({ event_type: 'tool_completed' }).total).toBe(1);
    expect(index.query({ event_type: 'session_started' }).total).toBe(1);
  });

  it('queries by success/failure', () => {
    index.indexProof(makeEntry(1, { success: true }));
    index.indexProof(makeEntry(2, { success: false }));

    expect(index.query({ success: true }).total).toBe(1);
    expect(index.query({ success: false }).total).toBe(1);
  });

  it('queries by namespace', () => {
    index.indexProof(makeEntry(1, { namespace: 'project-a' }));
    index.indexProof(makeEntry(2, { namespace: 'project-b' }));

    expect(index.query({ namespace: 'project-a' }).total).toBe(1);
  });

  it('queries by tags (AND)', () => {
    index.indexProof(makeEntry(1, { tags: ['setup', 'npm'] }));
    index.indexProof(makeEntry(2, { tags: ['deploy'] }));

    expect(index.query({ tags: ['setup'] }).total).toBe(1);
    expect(index.query({ tags: ['setup', 'npm'] }).total).toBe(1);
    expect(index.query({ tags: ['setup', 'deploy'] }).total).toBe(0);
  });

  it('paginates results', () => {
    const entries = Array.from({ length: 10 }, (_, i) => makeEntry(i + 1));
    index.bulkIndex(entries);

    const page1 = index.query({ limit: 3, offset: 0 });
    expect(page1.ids).toHaveLength(3);
    expect(page1.total).toBe(10);

    const page2 = index.query({ limit: 3, offset: 3 });
    expect(page2.ids).toHaveLength(3);
  });

  it('sorts ascending and descending', () => {
    const entries = Array.from({ length: 5 }, (_, i) => makeEntry(i + 1));
    index.bulkIndex(entries);

    const asc = index.query({ sort: 'asc', limit: 5 });
    const desc = index.query({ sort: 'desc', limit: 5 });
    expect(asc.ids[0]).not.toBe(desc.ids[0]);
  });

  it('gets stats', () => {
    index.indexProof(makeEntry(1, { tool: 'Bash' }));
    index.indexProof(makeEntry(2, { tool: 'Edit' }));
    index.indexProof(makeEntry(3, { tool: 'Bash' }));

    const stats = index.getStats();
    expect(stats.total).toBe(3);
    expect(stats.byTool['Bash']).toBe(2);
    expect(stats.byTool['Edit']).toBe(1);
  });

  it('gets latest sequence', () => {
    expect(index.getLatestSequence()).toBe(0);

    index.indexProof(makeEntry(1));
    index.indexProof(makeEntry(2));
    expect(index.getLatestSequence()).toBe(2);
  });

  it('clears index', () => {
    index.indexProof(makeEntry(1));
    expect(index.getStats().total).toBe(1);

    index.clear();
    expect(index.getStats().total).toBe(0);
  });
});

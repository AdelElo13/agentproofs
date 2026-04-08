import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, writeFile, readFile, readdir, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  computeMerkleRoot,
  createCheckpoint,
  createCheckpointFromChain,
  submitToRekor,
  verifyRekorEntry,
  saveAnchor,
  listAnchors,
  loadAnchor,
  _buildRekorPayload,
} from '../src/anchor.ts';
import type { AnchorRecord, Checkpoint } from '../src/anchor.ts';
import { generateKeyPair, sha256, signHash } from '../src/crypto.ts';
import { initChain, appendProof } from '../src/chain.ts';
import { createProofEntry } from '../src/proof.ts';
import type { KeyPair, ProofEntry, AgentproofsConfig } from '../src/types.ts';

// ── Helpers ──

function makeConfig(dataDir: string): AgentproofsConfig {
  return {
    dataDir,
    agentId: 'test-agent',
    userId: 'test-user',
    namespace: 'test',
    logLevel: 'error',
    retentionDays: 365,
    segmentSize: 10000,
    segmentMaxAge: 86400,
    redactionLevel: 0,
    socketPath: join(dataDir, 'daemon.sock'),
    httpPort: 0,
    keyStore: 'file',
    checkpointInterval: 0,
  };
}

function createTestEntry(
  config: AgentproofsConfig,
  chainId: string,
  sequence: number,
  prevHash: string,
  keyPair: KeyPair,
): ProofEntry {
  return createProofEntry(
    {
      event_type: 'tool_completed',
      tool: 'Bash',
      success: true,
      input_summary: `test action ${sequence}`,
      output_summary: `result ${sequence}`,
      origin: 'manual',
    },
    config,
    chainId,
    sequence,
    prevHash,
    keyPair,
    'sess_test',
  );
}

async function seedChain(
  dataDir: string,
  config: AgentproofsConfig,
  keyPair: KeyPair,
  count: number,
): Promise<ProofEntry[]> {
  await initChain(dataDir);
  await writeFile(join(dataDir, 'chain_id'), 'ch_test123', 'utf-8');

  const entries: ProofEntry[] = [];
  let prevHash = 'genesis';

  for (let i = 1; i <= count; i++) {
    const entry = createTestEntry(config, 'ch_test123', i, prevHash, keyPair);
    await appendProof(dataDir, '000001', entry);
    entries.push(entry);
    prevHash = entry.hash;
  }

  return entries;
}

// ── Mocks ──

function createMockFetch(responseData: Record<string, unknown>, status = 201) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 201 ? 'Created' : 'Error',
    json: () => Promise.resolve(responseData),
    text: () => Promise.resolve(JSON.stringify(responseData)),
  });
}

// ── Tests ──

describe('anchor', () => {
  let tmpDir: string;
  let keyPair: KeyPair;
  let config: AgentproofsConfig;

  beforeEach(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), 'agentproofs-test-'));
    keyPair = generateKeyPair();
    config = makeConfig(tmpDir);
  });

  afterEach(async () => {
    await rm(tmpDir, { recursive: true, force: true });
  });

  describe('computeMerkleRoot', () => {
    it('should compute SHA-256 of concatenated hashes', () => {
      const hashes = ['abc123', 'def456', 'ghi789'];
      const expected = sha256('abc123def456ghi789');
      expect(computeMerkleRoot(hashes)).toBe(expected);
    });

    it('should throw on empty input', () => {
      expect(() => computeMerkleRoot([])).toThrow('Cannot compute Merkle root from empty proof list');
    });

    it('should produce different roots for different orderings', () => {
      const root1 = computeMerkleRoot(['aaa', 'bbb']);
      const root2 = computeMerkleRoot(['bbb', 'aaa']);
      expect(root1).not.toBe(root2);
    });

    it('should produce a 64-char hex string', () => {
      const root = computeMerkleRoot(['test']);
      expect(root).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('createCheckpoint', () => {
    it('should create a signed checkpoint from entries', async () => {
      const entries = await seedChain(tmpDir, config, keyPair, 3);
      const checkpoint = createCheckpoint(entries, 'ch_test123', keyPair);

      expect(checkpoint.checkpoint_id).toMatch(/^ckpt_[0-9a-f]{16}$/);
      expect(checkpoint.chain_id).toBe('ch_test123');
      expect(checkpoint.proof_count).toBe(3);
      expect(checkpoint.first_sequence).toBe(1);
      expect(checkpoint.last_sequence).toBe(3);
      expect(checkpoint.first_hash).toBe(entries[0].hash);
      expect(checkpoint.last_hash).toBe(entries[2].hash);
      expect(checkpoint.merkle_root).toMatch(/^[0-9a-f]{64}$/);
      expect(checkpoint.key_id).toBe(keyPair.keyId);
      expect(checkpoint.signature).toBeTruthy();
      expect(checkpoint.created_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    });

    it('should throw on empty entries', () => {
      expect(() => createCheckpoint([], 'ch_test', keyPair))
        .toThrow('Cannot create checkpoint from empty entry list');
    });

    it('should produce consistent merkle root for same entries', async () => {
      const entries = await seedChain(tmpDir, config, keyPair, 5);
      const cp1 = createCheckpoint(entries, 'ch_test123', keyPair);
      const cp2 = createCheckpoint(entries, 'ch_test123', keyPair);

      expect(cp1.merkle_root).toBe(cp2.merkle_root);
    });
  });

  describe('createCheckpointFromChain', () => {
    it('should create checkpoint from all chain entries', async () => {
      await seedChain(tmpDir, config, keyPair, 5);
      const checkpoint = await createCheckpointFromChain(tmpDir, 'ch_test123', keyPair);

      expect(checkpoint.proof_count).toBe(5);
      expect(checkpoint.first_sequence).toBe(1);
      expect(checkpoint.last_sequence).toBe(5);
    });

    it('should create checkpoint from last N entries', async () => {
      await seedChain(tmpDir, config, keyPair, 10);
      const checkpoint = await createCheckpointFromChain(tmpDir, 'ch_test123', keyPair, 3);

      expect(checkpoint.proof_count).toBe(3);
      expect(checkpoint.first_sequence).toBe(8);
      expect(checkpoint.last_sequence).toBe(10);
    });

    it('should throw on empty chain', async () => {
      await initChain(tmpDir);
      await expect(createCheckpointFromChain(tmpDir, 'ch_test', keyPair))
        .rejects.toThrow('No proofs in chain to checkpoint');
    });
  });

  describe('buildRekorPayload', () => {
    it('should produce valid hashedrekord format', async () => {
      const entries = await seedChain(tmpDir, config, keyPair, 2);
      const checkpoint = createCheckpoint(entries, 'ch_test123', keyPair);
      const payload = _buildRekorPayload(checkpoint, keyPair);

      expect(payload.apiVersion).toBe('0.0.1');
      expect(payload.kind).toBe('hashedrekord');
      expect(payload.spec.data.hash.algorithm).toBe('sha256');
      expect(payload.spec.data.hash.value).toBe(checkpoint.merkle_root);
      expect(payload.spec.signature.content).toBeTruthy();
      expect(payload.spec.signature.publicKey.content).toBeTruthy();

      // Verify the public key is base64-encoded DER
      const pubKeyBuf = Buffer.from(payload.spec.signature.publicKey.content, 'base64');
      expect(pubKeyBuf.length).toBeGreaterThan(0);
    });
  });

  describe('submitToRekor', () => {
    it('should submit checkpoint and return anchor record', async () => {
      const entries = await seedChain(tmpDir, config, keyPair, 3);
      const checkpoint = createCheckpoint(entries, 'ch_test123', keyPair);

      const mockUUID = '24296fb24b8ad77a' + 'f' .repeat(48);
      const mockResponse = {
        [mockUUID]: {
          logIndex: 42,
          integratedTime: 1712500000,
          logID: 'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d',
        },
      };

      const mockFetch = createMockFetch(mockResponse);
      const anchor = await submitToRekor(checkpoint, keyPair, mockFetch);

      // Verify fetch was called correctly
      expect(mockFetch).toHaveBeenCalledOnce();
      const [url, opts] = mockFetch.mock.calls[0];
      expect(url).toBe('https://rekor.sigstore.dev/api/v1/log/entries');
      expect(opts.method).toBe('POST');
      expect(opts.headers['Content-Type']).toBe('application/json');

      const body = JSON.parse(opts.body);
      expect(body.kind).toBe('hashedrekord');
      expect(body.spec.data.hash.value).toBe(checkpoint.merkle_root);

      // Verify anchor record
      expect(anchor.checkpoint).toEqual(checkpoint);
      expect(anchor.rekor_entry_uuid).toBe(mockUUID);
      expect(anchor.rekor_log_index).toBe(42);
      expect(anchor.rekor_integrated_time).toBe(1712500000);
      expect(anchor.trust_level).toBe('L1');
      expect(anchor.anchored_at).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    });

    it('should throw on non-200 response', async () => {
      const entries = await seedChain(tmpDir, config, keyPair, 1);
      const checkpoint = createCheckpoint(entries, 'ch_test123', keyPair);

      const mockFetch = createMockFetch({ error: 'bad request' }, 400);
      await expect(submitToRekor(checkpoint, keyPair, mockFetch))
        .rejects.toThrow('Rekor submission failed (400)');
    });

    it('should throw on empty Rekor response', async () => {
      const entries = await seedChain(tmpDir, config, keyPair, 1);
      const checkpoint = createCheckpoint(entries, 'ch_test123', keyPair);

      const mockFetch = createMockFetch({});
      await expect(submitToRekor(checkpoint, keyPair, mockFetch))
        .rejects.toThrow('Rekor returned empty response');
    });
  });

  describe('verifyRekorEntry', () => {
    it('should verify a valid entry', async () => {
      const merkleRoot = sha256('test-data');
      const entryUUID = 'abc123def456';

      // Build a mock body that Rekor would return (base64-encoded JSON)
      const body = Buffer.from(JSON.stringify({
        apiVersion: '0.0.1',
        kind: 'hashedrekord',
        spec: {
          data: { hash: { algorithm: 'sha256', value: merkleRoot } },
        },
      })).toString('base64');

      const mockResponse = {
        [entryUUID]: {
          body,
          logIndex: 100,
          integratedTime: 1712500000,
          verification: {
            inclusionProof: {
              checkpoint: 'test',
              hashes: ['a', 'b'],
              logIndex: 100,
              rootHash: 'abc',
              treeSize: 1000,
            },
          },
        },
      };

      const mockFetch = createMockFetch(mockResponse, 200);
      const result = await verifyRekorEntry(entryUUID, merkleRoot, mockFetch);

      expect(result.valid).toBe(true);
      expect(result.entry_uuid).toBe(entryUUID);
      expect(result.log_index).toBe(100);
      expect(result.integrated_time).toBe(1712500000);
      expect(result.body_hash_matches).toBe(true);
      expect(result.inclusion_proof_present).toBe(true);
    });

    it('should detect hash mismatch', async () => {
      const entryUUID = 'abc123def456';

      const body = Buffer.from(JSON.stringify({
        spec: {
          data: { hash: { algorithm: 'sha256', value: 'different_hash' } },
        },
      })).toString('base64');

      const mockResponse = {
        [entryUUID]: {
          body,
          logIndex: 100,
          integratedTime: 1712500000,
        },
      };

      const mockFetch = createMockFetch(mockResponse, 200);
      const result = await verifyRekorEntry(entryUUID, 'expected_hash', mockFetch);

      expect(result.valid).toBe(false);
      expect(result.body_hash_matches).toBe(false);
    });

    it('should report missing inclusion proof', async () => {
      const merkleRoot = sha256('test');
      const entryUUID = 'abc123';

      const body = Buffer.from(JSON.stringify({
        spec: { data: { hash: { algorithm: 'sha256', value: merkleRoot } } },
      })).toString('base64');

      const mockResponse = {
        [entryUUID]: {
          body,
          logIndex: 50,
          integratedTime: 1712500000,
          // no verification field
        },
      };

      const mockFetch = createMockFetch(mockResponse, 200);
      const result = await verifyRekorEntry(entryUUID, merkleRoot, mockFetch);

      expect(result.valid).toBe(true);
      expect(result.inclusion_proof_present).toBe(false);
    });

    it('should throw on 404', async () => {
      const mockFetch = createMockFetch({}, 404);
      await expect(verifyRekorEntry('nonexistent', 'hash', mockFetch))
        .rejects.toThrow('Rekor lookup failed (404)');
    });
  });

  describe('anchor persistence', () => {
    function makeAnchor(checkpointId: string): AnchorRecord {
      return {
        checkpoint: {
          checkpoint_id: checkpointId,
          chain_id: 'ch_test',
          merkle_root: sha256(checkpointId),
          proof_count: 10,
          first_sequence: 1,
          last_sequence: 10,
          first_hash: 'aaa',
          last_hash: 'bbb',
          created_at: '2026-04-07T10:00:00.000Z',
          key_id: 'testkey',
          signature: 'sig123',
        },
        rekor_entry_uuid: `uuid_${checkpointId}`,
        rekor_log_index: 42,
        rekor_integrated_time: 1712500000,
        rekor_log_id: 'logid123',
        anchored_at: '2026-04-07T10:00:01.000Z',
        trust_level: 'L1',
      };
    }

    it('should save and load an anchor', async () => {
      const anchor = makeAnchor('ckpt_aaa');
      const filePath = await saveAnchor(tmpDir, anchor);

      expect(filePath).toContain('ckpt_aaa.json');

      const loaded = await loadAnchor(tmpDir, 'ckpt_aaa');
      expect(loaded).toEqual(anchor);
    });

    it('should list all anchors sorted by filename', async () => {
      await saveAnchor(tmpDir, makeAnchor('ckpt_001'));
      await saveAnchor(tmpDir, makeAnchor('ckpt_002'));
      await saveAnchor(tmpDir, makeAnchor('ckpt_003'));

      const anchors = await listAnchors(tmpDir);
      expect(anchors).toHaveLength(3);
      expect(anchors[0].checkpoint.checkpoint_id).toBe('ckpt_001');
      expect(anchors[2].checkpoint.checkpoint_id).toBe('ckpt_003');
    });

    it('should return empty array when no anchors exist', async () => {
      const anchors = await listAnchors(tmpDir);
      expect(anchors).toHaveLength(0);
    });

    it('should return null for nonexistent anchor', async () => {
      const loaded = await loadAnchor(tmpDir, 'nonexistent');
      expect(loaded).toBeNull();
    });
  });

  describe('end-to-end flow (mocked Rekor)', () => {
    it('should create checkpoint, submit, save, and list', async () => {
      const entries = await seedChain(tmpDir, config, keyPair, 5);

      // Create checkpoint
      const checkpoint = await createCheckpointFromChain(tmpDir, 'ch_test123', keyPair);
      expect(checkpoint.proof_count).toBe(5);

      // Mock Rekor submission
      const mockUUID = 'e2e_test_uuid_' + '0'.repeat(50);
      const mockFetch = createMockFetch({
        [mockUUID]: {
          logIndex: 999,
          integratedTime: 1712600000,
          logID: 'test-log-id',
        },
      });

      const anchor = await submitToRekor(checkpoint, keyPair, mockFetch);
      expect(anchor.rekor_entry_uuid).toBe(mockUUID);

      // Save
      await saveAnchor(tmpDir, anchor);

      // List
      const anchors = await listAnchors(tmpDir);
      expect(anchors).toHaveLength(1);
      expect(anchors[0].rekor_entry_uuid).toBe(mockUUID);
      expect(anchors[0].checkpoint.merkle_root).toBe(checkpoint.merkle_root);
      expect(anchors[0].trust_level).toBe('L1');
    });
  });
});

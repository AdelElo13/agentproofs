import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { tmpdir } from 'node:os';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { auditChain, type AuditReport } from '../src/verifier.ts';
import { createProofEntry } from '../src/proof.ts';
import { generateKeyPair, generateChainId, sha256, signHash } from '../src/crypto.ts';
import type { ProofLogInput, AgentproofsConfig, ProofEntry, KeyPair } from '../src/types.ts';

let tmpDir: string;
let kp: KeyPair;
let chainId: string;

const testConfig: AgentproofsConfig = {
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

function buildChain(count: number): readonly ProofEntry[] {
  const entries: ProofEntry[] = [];
  let prevHash = 'genesis';

  for (let i = 1; i <= count; i++) {
    const entry = createProofEntry(
      makeInput(), testConfig, chainId, i, prevHash, kp, 'sess_test',
    );
    entries.push(entry);
    prevHash = entry.hash;
  }

  return entries;
}

function toJsonl(entries: readonly ProofEntry[]): string {
  return entries.map((e) => JSON.stringify(e)).join('\n') + '\n';
}

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), 'agentproofs-verifier-'));
  kp = generateKeyPair();
  chainId = generateChainId();
});

afterEach(async () => {
  await rm(tmpDir, { recursive: true });
});

describe('auditChain', () => {
  it('passes audit for a valid chain', async () => {
    const entries = buildChain(5);
    const jsonl = toJsonl(entries);
    const keys = new Map([[kp.keyId, kp.publicKey]]);

    const report = await auditChain(jsonl, keys, kp);

    expect(report.total_proofs).toBe(5);
    expect(report.chain_valid).toBe(true);
    expect(report.signatures_valid).toBe(true);
    expect(report.timestamps_monotonic).toBe(true);
    expect(report.sequences_monotonic).toBe(true);
    expect(report.errors).toHaveLength(0);
    expect(report.first_proof_time).toBe(entries[0].timestamp);
    expect(report.last_proof_time).toBe(entries[4].timestamp);
    expect(report.verified_at).toBeTruthy();
    expect(report.verifier_signature).toBeTruthy();
  });

  it('detects tampered hash', async () => {
    const entries = buildChain(3);
    // Tamper with the hash of the second entry
    const tampered = entries.map((e, i) => {
      if (i === 1) {
        return { ...e, hash: sha256('tampered-data') };
      }
      return e;
    });
    const jsonl = toJsonl(tampered);
    const keys = new Map([[kp.keyId, kp.publicKey]]);

    const report = await auditChain(jsonl, keys, kp);

    expect(report.chain_valid).toBe(false);
    const hashErrors = report.errors.filter((e) => e.type === 'hash_mismatch');
    expect(hashErrors.length).toBeGreaterThanOrEqual(1);
    expect(hashErrors[0].sequence).toBe(2);
  });

  it('detects tampered signature', async () => {
    const entries = buildChain(3);
    // Corrupt the signature of the first entry
    const tampered = entries.map((e, i) => {
      if (i === 0) {
        return { ...e, signature: 'AAAA' + e.signature.slice(4) };
      }
      return e;
    });
    const jsonl = toJsonl(tampered);
    const keys = new Map([[kp.keyId, kp.publicKey]]);

    const report = await auditChain(jsonl, keys, kp);

    expect(report.chain_valid).toBe(false);
    expect(report.signatures_valid).toBe(false);
    const sigErrors = report.errors.filter((e) => e.type === 'signature_invalid');
    expect(sigErrors.length).toBeGreaterThanOrEqual(1);
    expect(sigErrors[0].sequence).toBe(1);
  });

  it('detects sequence gap (missing proof)', async () => {
    const entries = buildChain(5);
    // Remove the third entry (index 2), creating a gap from seq 2 -> seq 4
    const gapped = [entries[0], entries[1], entries[3], entries[4]];
    const jsonl = toJsonl(gapped);
    const keys = new Map([[kp.keyId, kp.publicKey]]);

    const report = await auditChain(jsonl, keys, kp);

    expect(report.chain_valid).toBe(false);
    expect(report.sequences_monotonic).toBe(false);
    const seqErrors = report.errors.filter((e) => e.type === 'sequence_gap');
    expect(seqErrors.length).toBeGreaterThanOrEqual(1);
    expect(seqErrors[0].message).toContain('expected 3');
  });

  it('detects non-monotonic timestamp', async () => {
    const entries = buildChain(3);
    // Swap timestamps so the second entry has an earlier timestamp
    const tampered = entries.map((e, i) => {
      if (i === 1) {
        return { ...e, timestamp: '2000-01-01T00:00:00.000Z' };
      }
      return e;
    });
    // Rewrite: we need to keep hash correct but timestamp wrong.
    // Since we changed the timestamp, the hash will also be wrong.
    // For this test we want to specifically test timestamp regression detection.
    // We need to rebuild the entry with the wrong timestamp but valid hash/sig.
    // Simplest: build entries manually with controlled timestamps.

    // Build 3 entries, the second with a timestamp in the past
    const manualEntries: ProofEntry[] = [];
    let prevHash = 'genesis';
    const timestamps = [
      '2026-04-07T10:00:00.000Z',
      '2026-04-07T09:00:00.000Z', // regression!
      '2026-04-07T11:00:00.000Z',
    ];

    for (let i = 0; i < 3; i++) {
      const input = makeInput();
      // Create entry manually to control timestamp
      const entry = createProofEntry(input, testConfig, chainId, i + 1, prevHash, kp, 'sess_test');
      // Override timestamp - need to rehash
      const { hash: _h, signature: _s, ...hashable } = entry;
      const modified = { ...hashable, timestamp: timestamps[i] };
      const { canonicalize } = await import('../src/canonical.ts');
      const canonical = canonicalize(modified);
      const { sha256: hash256, signHash: sign } = await import('../src/crypto.ts');
      const newHash = hash256(canonical);
      const newSig = sign(newHash, kp.privateKey);
      const finalEntry: ProofEntry = { ...modified, hash: newHash, signature: newSig };
      manualEntries.push(finalEntry);
      prevHash = newHash;
    }

    const jsonl = toJsonl(manualEntries);
    const keys = new Map([[kp.keyId, kp.publicKey]]);

    const report = await auditChain(jsonl, keys, kp);

    expect(report.chain_valid).toBe(false);
    expect(report.timestamps_monotonic).toBe(false);
    const tsErrors = report.errors.filter((e) => e.type === 'timestamp_regression');
    expect(tsErrors.length).toBeGreaterThanOrEqual(1);
    expect(tsErrors[0].sequence).toBe(2);
  });

  it('reads from file path', async () => {
    const entries = buildChain(3);
    const jsonl = toJsonl(entries);
    const filePath = join(tmpDir, 'chain.jsonl');
    await writeFile(filePath, jsonl, 'utf-8');

    const keys = new Map([[kp.keyId, kp.publicKey]]);
    const report = await auditChain(filePath, keys, kp);

    expect(report.total_proofs).toBe(3);
    expect(report.chain_valid).toBe(true);
  });

  it('handles empty chain', async () => {
    const keys = new Map([[kp.keyId, kp.publicKey]]);
    const report = await auditChain('', keys, kp);

    expect(report.total_proofs).toBe(0);
    expect(report.chain_valid).toBe(true);
    expect(report.signatures_valid).toBe(true);
    expect(report.first_proof_time).toBe('');
    expect(report.last_proof_time).toBe('');
  });

  it('report signature is verifiable', async () => {
    const entries = buildChain(2);
    const jsonl = toJsonl(entries);
    const keys = new Map([[kp.keyId, kp.publicKey]]);

    const report = await auditChain(jsonl, keys, kp);

    // Reconstruct the report data that was signed
    const { verifier_signature, ...reportData } = report;
    const reportHash = sha256(JSON.stringify(reportData));

    const { verifySignature } = await import('../src/crypto.ts');
    expect(verifySignature(reportHash, verifier_signature, kp.publicKey)).toBe(true);
  });
});

import { readFile } from 'node:fs/promises';
import { sha256, signHash, verifySignature } from './crypto.ts';
import { canonicalize } from './canonical.ts';
import type { ProofEntry, HashableEntry, KeyPair } from './types.ts';

// ── Verification Report ──

export interface AuditReport {
  readonly total_proofs: number;
  readonly chain_valid: boolean;
  readonly signatures_valid: boolean;
  readonly timestamps_monotonic: boolean;
  readonly sequences_monotonic: boolean;
  readonly first_proof_time: string;
  readonly last_proof_time: string;
  readonly errors: readonly AuditError[];
  readonly verified_at: string;
  readonly verifier_signature: string;
}

export interface AuditError {
  readonly sequence: number;
  readonly type: 'hash_mismatch' | 'signature_invalid' | 'prev_hash_broken' | 'sequence_gap' | 'timestamp_regression';
  readonly message: string;
}

// ── Parse JSONL ──

function parseJsonlChain(jsonl: string): readonly ProofEntry[] {
  const lines = jsonl.trim().split('\n').filter(Boolean);
  return lines.map((line, i) => {
    try {
      return JSON.parse(line) as ProofEntry;
    } catch {
      throw new Error(`Failed to parse JSONL at line ${i + 1}`);
    }
  });
}

// ── Stateless Audit ──

export async function auditChain(
  input: string,
  publicKeys: ReadonlyMap<string, Uint8Array>,
  signingKeyPair: KeyPair,
): Promise<AuditReport> {
  // Determine if input is a file path or raw JSONL
  let jsonl: string;
  if (!input || input.includes('\n') || input.startsWith('{')) {
    jsonl = input;
  } else {
    jsonl = await readFile(input, 'utf-8');
  }

  const entries = parseJsonlChain(jsonl);
  const errors: AuditError[] = [];

  let signaturesValid = true;
  let timestampsMonotonic = true;
  let sequencesMonotonic = true;
  let chainValid = true;

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const prev = i > 0 ? entries[i - 1] : null;

    // 1. Validate hash link (prev_hash matches)
    if (prev === null) {
      if (entry.sequence === 1 && entry.prev_hash !== 'genesis') {
        errors.push({
          sequence: entry.sequence,
          type: 'prev_hash_broken',
          message: `First entry prev_hash is not genesis: ${entry.prev_hash}`,
        });
        chainValid = false;
      }
    } else {
      if (entry.prev_hash !== prev.hash) {
        errors.push({
          sequence: entry.sequence,
          type: 'prev_hash_broken',
          message: `prev_hash mismatch: expected ${prev.hash}, got ${entry.prev_hash}`,
        });
        chainValid = false;
      }
    }

    // 2. Recompute and validate hash
    const { hash: _hash, signature: _sig, ...hashable } = entry;
    const canonical = canonicalize(hashable as HashableEntry);
    const computedHash = sha256(canonical);

    if (computedHash !== entry.hash) {
      errors.push({
        sequence: entry.sequence,
        type: 'hash_mismatch',
        message: `Hash mismatch: computed ${computedHash}, stored ${entry.hash}`,
      });
      chainValid = false;
    }

    // 3. Validate Ed25519 signature
    const publicKey = publicKeys.get(entry.key_id);
    if (!publicKey) {
      errors.push({
        sequence: entry.sequence,
        type: 'signature_invalid',
        message: `Unknown key_id: ${entry.key_id}`,
      });
      signaturesValid = false;
      chainValid = false;
    } else if (!verifySignature(entry.hash, entry.signature, publicKey)) {
      errors.push({
        sequence: entry.sequence,
        type: 'signature_invalid',
        message: `Signature verification failed`,
      });
      signaturesValid = false;
      chainValid = false;
    }

    // 4. Check sequence monotonicity
    if (prev !== null && entry.sequence !== prev.sequence + 1) {
      errors.push({
        sequence: entry.sequence,
        type: 'sequence_gap',
        message: `Sequence gap: expected ${prev.sequence + 1}, got ${entry.sequence}`,
      });
      sequencesMonotonic = false;
      chainValid = false;
    }

    // 5. Check timestamp monotonicity
    if (prev !== null && entry.timestamp < prev.timestamp) {
      errors.push({
        sequence: entry.sequence,
        type: 'timestamp_regression',
        message: `Timestamp regression: ${entry.timestamp} < ${prev.timestamp}`,
      });
      timestampsMonotonic = false;
      chainValid = false;
    }
  }

  const firstProofTime = entries.length > 0 ? entries[0].timestamp : '';
  const lastProofTime = entries.length > 0 ? entries[entries.length - 1].timestamp : '';
  const verifiedAt = new Date().toISOString();

  // Build the unsigned report for hashing
  const reportData = {
    total_proofs: entries.length,
    chain_valid: chainValid,
    signatures_valid: signaturesValid,
    timestamps_monotonic: timestampsMonotonic,
    sequences_monotonic: sequencesMonotonic,
    first_proof_time: firstProofTime,
    last_proof_time: lastProofTime,
    errors,
    verified_at: verifiedAt,
  };

  const reportHash = sha256(JSON.stringify(reportData));
  const verifierSignature = signHash(reportHash, signingKeyPair.privateKey);

  return {
    ...reportData,
    verifier_signature: verifierSignature,
  };
}

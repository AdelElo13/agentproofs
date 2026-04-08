import { readFile, writeFile, readdir, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { sha256, signHash, verifySignature } from './crypto.ts';
import { readAllEntries } from './chain.ts';
import type { KeyPair, ProofEntry } from './types.ts';

// ── Types ──

export interface Checkpoint {
  readonly checkpoint_id: string;
  readonly chain_id: string;
  readonly merkle_root: string;
  readonly proof_count: number;
  readonly first_sequence: number;
  readonly last_sequence: number;
  readonly first_hash: string;
  readonly last_hash: string;
  readonly created_at: string;
  readonly key_id: string;
  readonly signature: string;
}

export interface AnchorRecord {
  readonly checkpoint: Checkpoint;
  readonly rekor_entry_uuid: string;
  readonly rekor_log_index: number;
  readonly rekor_integrated_time: number;
  readonly rekor_log_id: string;
  readonly anchored_at: string;
  readonly trust_level: 'L1';
}

export interface RekorEntryVerification {
  readonly valid: boolean;
  readonly entry_uuid: string;
  readonly log_index: number;
  readonly integrated_time: number;
  readonly body_hash_matches: boolean;
  readonly inclusion_proof_present: boolean;
}

// ── Checkpoint Creation ──

export function computeMerkleRoot(proofHashes: readonly string[]): string {
  if (proofHashes.length === 0) {
    throw new Error('Cannot compute Merkle root from empty proof list');
  }
  // Concatenate all proof hashes and SHA-256 the result
  const concatenated = proofHashes.join('');
  return sha256(concatenated);
}

export function createCheckpoint(
  entries: readonly ProofEntry[],
  chainId: string,
  keyPair: KeyPair,
): Checkpoint {
  if (entries.length === 0) {
    throw new Error('Cannot create checkpoint from empty entry list');
  }

  const proofHashes = entries.map((e) => e.hash);
  const merkleRoot = computeMerkleRoot(proofHashes);
  const first = entries[0];
  const last = entries[entries.length - 1];

  const checkpointId = `ckpt_${randomBytes(8).toString('hex')}`;
  const createdAt = new Date().toISOString();

  const signable = {
    checkpoint_id: checkpointId,
    chain_id: chainId,
    merkle_root: merkleRoot,
    proof_count: entries.length,
    first_sequence: first.sequence,
    last_sequence: last.sequence,
    first_hash: first.hash,
    last_hash: last.hash,
    created_at: createdAt,
    key_id: keyPair.keyId,
  };

  const signableHash = sha256(JSON.stringify(signable));
  const signature = signHash(signableHash, keyPair.privateKey);

  return { ...signable, signature };
}

export async function createCheckpointFromChain(
  dataDir: string,
  chainId: string,
  keyPair: KeyPair,
  lastN?: number,
): Promise<Checkpoint> {
  const allEntries = await readAllEntries(dataDir);
  if (allEntries.length === 0) {
    throw new Error('No proofs in chain to checkpoint');
  }

  const entries = lastN !== undefined && lastN > 0
    ? allEntries.slice(-lastN)
    : allEntries;

  return createCheckpoint(entries, chainId, keyPair);
}

// ── Rekor Submission ──

interface RekorRequestBody {
  readonly apiVersion: '0.0.1';
  readonly kind: 'hashedrekord';
  readonly spec: {
    readonly data: {
      readonly hash: {
        readonly algorithm: 'sha256';
        readonly value: string;
      };
    };
    readonly signature: {
      readonly content: string;
      readonly publicKey: {
        readonly content: string;
      };
    };
  };
}

function buildRekorPayload(checkpoint: Checkpoint, keyPair: KeyPair): RekorRequestBody {
  // Sign the merkle_root hash bytes directly for Rekor
  const merkleRootSignature = signHash(checkpoint.merkle_root, keyPair.privateKey);
  const publicKeyBase64 = Buffer.from(keyPair.publicKey).toString('base64');

  return {
    apiVersion: '0.0.1',
    kind: 'hashedrekord',
    spec: {
      data: {
        hash: {
          algorithm: 'sha256',
          value: checkpoint.merkle_root,
        },
      },
      signature: {
        content: merkleRootSignature,
        publicKey: {
          content: publicKeyBase64,
        },
      },
    },
  };
}

export { buildRekorPayload as _buildRekorPayload };

const REKOR_API = 'https://rekor.sigstore.dev/api/v1';

export async function submitToRekor(
  checkpoint: Checkpoint,
  keyPair: KeyPair,
  fetchFn: typeof globalThis.fetch = globalThis.fetch,
): Promise<AnchorRecord> {
  const payload = buildRekorPayload(checkpoint, keyPair);

  const response = await fetchFn(`${REKOR_API}/log/entries`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const errorBody = await response.text().catch(() => response.statusText);
    throw new Error(`Rekor submission failed (${response.status}): ${errorBody}`);
  }

  const result = await response.json() as Record<string, unknown>;

  // Rekor returns { "<uuid>": { ... } }
  const entries = Object.entries(result);
  if (entries.length === 0) {
    throw new Error('Rekor returned empty response');
  }

  const [entryUUID, entryData] = entries[0];
  const data = entryData as {
    logIndex: number;
    integratedTime: number;
    logID: string;
  };

  return {
    checkpoint,
    rekor_entry_uuid: entryUUID,
    rekor_log_index: data.logIndex,
    rekor_integrated_time: data.integratedTime,
    rekor_log_id: data.logID,
    anchored_at: new Date().toISOString(),
    trust_level: 'L1',
  };
}

// ── Rekor Verification ──

export async function verifyRekorEntry(
  entryUUID: string,
  expectedMerkleRoot: string,
  fetchFn: typeof globalThis.fetch = globalThis.fetch,
): Promise<RekorEntryVerification> {
  const response = await fetchFn(`${REKOR_API}/log/entries/${entryUUID}`, {
    method: 'GET',
    headers: { 'Accept': 'application/json' },
  });

  if (!response.ok) {
    throw new Error(`Rekor lookup failed (${response.status}): ${response.statusText}`);
  }

  const result = await response.json() as Record<string, unknown>;
  const entries = Object.entries(result);
  if (entries.length === 0) {
    throw new Error('Rekor returned empty response for entry lookup');
  }

  const [, entryData] = entries[0];
  const data = entryData as {
    body: string;
    logIndex: number;
    integratedTime: number;
    verification?: {
      inclusionProof?: unknown;
    };
  };

  // Decode the base64 body and check the hash matches
  let bodyHashMatches = false;
  try {
    const bodyJson = JSON.parse(Buffer.from(data.body, 'base64').toString('utf-8'));
    const storedHash = bodyJson?.spec?.data?.hash?.value;
    bodyHashMatches = storedHash === expectedMerkleRoot;
  } catch {
    bodyHashMatches = false;
  }

  const inclusionProofPresent = data.verification?.inclusionProof !== undefined
    && data.verification.inclusionProof !== null;

  return {
    valid: bodyHashMatches,
    entry_uuid: entryUUID,
    log_index: data.logIndex,
    integrated_time: data.integratedTime,
    body_hash_matches: bodyHashMatches,
    inclusion_proof_present: inclusionProofPresent,
  };
}

// ── Anchor Persistence ──

function anchorsDir(dataDir: string): string {
  return join(dataDir, 'anchors');
}

export async function saveAnchor(dataDir: string, anchor: AnchorRecord): Promise<string> {
  const dir = anchorsDir(dataDir);
  await mkdir(dir, { recursive: true });

  const filename = `${anchor.checkpoint.checkpoint_id}.json`;
  const filePath = join(dir, filename);
  await writeFile(filePath, JSON.stringify(anchor, null, 2), 'utf-8');
  return filePath;
}

export async function listAnchors(dataDir: string): Promise<readonly AnchorRecord[]> {
  const dir = anchorsDir(dataDir);
  const records: AnchorRecord[] = [];

  try {
    const files = await readdir(dir);
    const jsonFiles = files.filter((f) => f.endsWith('.json')).sort();

    for (const file of jsonFiles) {
      try {
        const content = await readFile(join(dir, file), 'utf-8');
        records.push(JSON.parse(content) as AnchorRecord);
      } catch {
        // Skip malformed files
      }
    }
  } catch {
    // No anchors dir yet
  }

  return records;
}

export async function loadAnchor(
  dataDir: string,
  checkpointId: string,
): Promise<AnchorRecord | null> {
  try {
    const content = await readFile(
      join(anchorsDir(dataDir), `${checkpointId}.json`),
      'utf-8',
    );
    return JSON.parse(content) as AnchorRecord;
  } catch {
    return null;
  }
}

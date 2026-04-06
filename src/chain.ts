import { appendFile, readFile, mkdir, stat } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { join } from 'node:path';
import { sha256, verifySignature } from './crypto.ts';
import { canonicalize } from './canonical.ts';
import type {
  ProofEntry,
  HashableEntry,
  KeyPair,
  VerificationResult,
  AgentproofsConfig,
} from './types.ts';

const GENESIS = 'genesis';

// ── Chain State ──

export interface ChainState {
  readonly chainId: string;
  readonly segmentId: string;
  readonly sequence: number;
  readonly lastHash: string;
  readonly lastTimestamp: string;
  readonly proofCount: number;
}

// ── Segment Path ──

function segmentDir(dataDir: string): string {
  return join(dataDir, 'segments');
}

function segmentPath(dataDir: string, segmentId: string): string {
  return join(segmentDir(dataDir), `${segmentId}.jsonl`);
}

export function formatSegmentId(n: number): string {
  return String(n).padStart(6, '0');
}

// ── Initialize Chain ──

export async function initChain(dataDir: string): Promise<void> {
  await mkdir(segmentDir(dataDir), { recursive: true });
  await mkdir(join(dataDir, 'manifests'), { recursive: true });
  await mkdir(join(dataDir, 'checkpoints'), { recursive: true });
  await mkdir(join(dataDir, 'keys'), { recursive: true });
  await mkdir(join(dataDir, 'keys', 'rotated'), { recursive: true });
}

// ── Read Chain State ──

export async function readChainState(
  dataDir: string,
  chainId: string,
): Promise<ChainState> {
  // Find the latest segment
  const dir = segmentDir(dataDir);
  let segmentNum = 1;
  let lastEntry: ProofEntry | null = null;

  // Scan for the latest segment file
  while (true) {
    const path = segmentPath(dataDir, formatSegmentId(segmentNum));
    try {
      await stat(path);
      segmentNum++;
    } catch {
      segmentNum--;
      break;
    }
  }

  if (segmentNum < 1) segmentNum = 1;

  const currentSegmentId = formatSegmentId(segmentNum);
  const path = segmentPath(dataDir, currentSegmentId);

  try {
    lastEntry = await readLastEntry(path);
  } catch {
    // No entries yet
  }

  if (lastEntry) {
    return {
      chainId,
      segmentId: currentSegmentId,
      sequence: lastEntry.sequence,
      lastHash: lastEntry.hash,
      lastTimestamp: lastEntry.timestamp,
      proofCount: lastEntry.sequence,
    };
  }

  return {
    chainId,
    segmentId: currentSegmentId,
    sequence: 0,
    lastHash: GENESIS,
    lastTimestamp: '',
    proofCount: 0,
  };
}

// ── Read Last Entry ──

async function readLastEntry(filePath: string): Promise<ProofEntry | null> {
  const content = await readFile(filePath, 'utf-8');
  const lines = content.trim().split('\n').filter(Boolean);
  if (lines.length === 0) return null;
  return JSON.parse(lines[lines.length - 1]) as ProofEntry;
}

// ── Append Proof ──

export async function appendProof(
  dataDir: string,
  segmentId: string,
  entry: ProofEntry,
): Promise<void> {
  const path = segmentPath(dataDir, segmentId);
  const line = JSON.stringify(entry) + '\n';
  await appendFile(path, line, 'utf-8');
}

// ── Read All Entries from Segment ──

export async function readSegmentEntries(
  dataDir: string,
  segmentId: string,
): Promise<readonly ProofEntry[]> {
  const path = segmentPath(dataDir, segmentId);
  const entries: ProofEntry[] = [];

  try {
    const rl = createInterface({
      input: createReadStream(path, 'utf-8'),
      crlfDelay: Infinity,
    });

    for await (const line of rl) {
      if (line.trim()) {
        entries.push(JSON.parse(line) as ProofEntry);
      }
    }
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
  }

  return entries;
}

// ── Read All Entries (all segments) ──

export async function readAllEntries(dataDir: string): Promise<readonly ProofEntry[]> {
  const allEntries: ProofEntry[] = [];
  let segmentNum = 1;

  while (true) {
    const segId = formatSegmentId(segmentNum);
    const entries = await readSegmentEntries(dataDir, segId);
    if (entries.length === 0 && segmentNum > 1) break;
    if (entries.length === 0 && segmentNum === 1) break;
    allEntries.push(...entries);
    segmentNum++;
  }

  return allEntries;
}

// ── Verify Chain ──

export async function verifyChain(
  dataDir: string,
  publicKeys: ReadonlyMap<string, Uint8Array>,
  options?: {
    readonly fromSequence?: number;
    readonly toSequence?: number;
    readonly verifySignatures?: boolean;
  },
): Promise<VerificationResult> {
  const entries = await readAllEntries(dataDir);
  const verifySignatures = options?.verifySignatures ?? true;

  if (entries.length === 0) {
    return {
      valid: true,
      total_proofs: 0,
      verified: 0,
      segments_verified: 0,
      checkpoint_status: 'none',
      key_transitions: 0,
    };
  }

  let keyTransitions = 0;
  let prevEntry: ProofEntry | null = null;

  for (const entry of entries) {
    // Skip entries outside range
    if (options?.fromSequence !== undefined && entry.sequence < options.fromSequence) {
      prevEntry = entry;
      continue;
    }
    if (options?.toSequence !== undefined && entry.sequence > options.toSequence) {
      break;
    }

    // 1. Check prev_hash linkage
    if (prevEntry === null) {
      if (entry.sequence === 1 && entry.prev_hash !== GENESIS) {
        return invalidResult(entries.length, entry.sequence, 'First entry prev_hash is not genesis');
      }
    } else {
      if (entry.prev_hash !== prevEntry.hash) {
        return invalidResult(
          entries.length,
          entry.sequence,
          `prev_hash mismatch: expected ${prevEntry.hash}, got ${entry.prev_hash}`,
        );
      }
    }

    // 2. Recompute hash
    const { hash: _hash, signature: _sig, ...hashable } = entry;
    const canonical = canonicalize(hashable as HashableEntry);
    const computedHash = sha256(canonical);

    if (computedHash !== entry.hash) {
      return invalidResult(
        entries.length,
        entry.sequence,
        `Hash mismatch: computed ${computedHash}, stored ${entry.hash}`,
      );
    }

    // 3. Verify signature
    if (verifySignatures) {
      const publicKey = publicKeys.get(entry.key_id);
      if (!publicKey) {
        return invalidResult(
          entries.length,
          entry.sequence,
          `Unknown key_id: ${entry.key_id}`,
        );
      }

      if (!verifySignature(entry.hash, entry.signature, publicKey)) {
        return invalidResult(
          entries.length,
          entry.sequence,
          'Signature verification failed',
        );
      }
    }

    // 4. Check monotonic sequence
    if (prevEntry !== null && entry.sequence !== prevEntry.sequence + 1) {
      return invalidResult(
        entries.length,
        entry.sequence,
        `Sequence gap: expected ${prevEntry.sequence + 1}, got ${entry.sequence}`,
      );
    }

    // 5. Check monotonic timestamp
    if (prevEntry !== null && entry.timestamp < prevEntry.timestamp) {
      return invalidResult(
        entries.length,
        entry.sequence,
        `Timestamp regression: ${entry.timestamp} < ${prevEntry.timestamp}`,
      );
    }

    // 6. Track key transitions
    if (entry.event_type === 'key_rotated') {
      keyTransitions++;
    }

    prevEntry = entry;
  }

  return {
    valid: true,
    total_proofs: entries.length,
    verified: entries.length,
    last_valid_hash: prevEntry?.hash,
    chain_hash: prevEntry?.hash,
    segments_verified: 1, // TODO: multi-segment support
    checkpoint_status: 'none',
    key_transitions: keyTransitions,
  };
}

function invalidResult(
  total: number,
  invalidSeq: number,
  reason: string,
): VerificationResult {
  return {
    valid: false,
    total_proofs: total,
    verified: invalidSeq - 1,
    first_invalid_sequence: invalidSeq,
    first_invalid_reason: reason,
    segments_verified: 0,
    checkpoint_status: 'none',
    key_transitions: 0,
  };
}

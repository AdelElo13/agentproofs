import { writeFile, readFile, readdir, mkdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { sha256, signHash } from './crypto.ts';
import { readSegmentEntries, formatSegmentId } from './chain.ts';
import type { SegmentManifest, KeyPair, ProofEntry } from './types.ts';

/**
 * Seal a segment — compute digest, sign, write manifest.
 */
export async function sealSegment(
  dataDir: string,
  segmentId: string,
  keyPair: KeyPair,
): Promise<SegmentManifest> {
  const entries = await readSegmentEntries(dataDir, segmentId);
  if (entries.length === 0) {
    throw new Error(`Segment ${segmentId} is empty, cannot seal`);
  }

  const first = entries[0];
  const last = entries[entries.length - 1];

  // Compute segment hash: SHA-256 of concatenated proof hashes
  const concatenatedHashes = entries.map((e) => e.hash).join('');
  const segmentHash = sha256(concatenatedHashes);

  const manifest: Omit<SegmentManifest, 'signature'> = {
    segment_id: segmentId,
    chain_id: first.chain_id,
    first_sequence: first.sequence,
    last_sequence: last.sequence,
    first_hash: first.hash,
    last_hash: last.hash,
    segment_hash: segmentHash,
    proof_count: entries.length,
    created_at: first.timestamp,
    sealed_at: new Date().toISOString(),
    key_id: keyPair.keyId,
  };

  const signature = signHash(sha256(JSON.stringify(manifest)), keyPair.privateKey);

  const signed: SegmentManifest = { ...manifest, signature };

  // Write manifest
  const manifestDir = join(dataDir, 'manifests');
  await mkdir(manifestDir, { recursive: true });
  await writeFile(
    join(manifestDir, `${segmentId}.manifest.json`),
    JSON.stringify(signed, null, 2),
    'utf-8',
  );

  return signed;
}

/**
 * Load a segment manifest.
 */
export async function loadManifest(
  dataDir: string,
  segmentId: string,
): Promise<SegmentManifest | null> {
  try {
    const content = await readFile(
      join(dataDir, 'manifests', `${segmentId}.manifest.json`),
      'utf-8',
    );
    return JSON.parse(content) as SegmentManifest;
  } catch {
    return null;
  }
}

/**
 * List all segments.
 */
export async function listSegments(
  dataDir: string,
): Promise<ReadonlyArray<{ segmentId: string; proofCount: number; hasManifest: boolean }>> {
  const segDir = join(dataDir, 'segments');
  const results: Array<{ segmentId: string; proofCount: number; hasManifest: boolean }> = [];

  try {
    const files = await readdir(segDir);
    const jsonlFiles = files.filter((f) => f.endsWith('.jsonl')).sort();

    for (const f of jsonlFiles) {
      const segmentId = f.replace('.jsonl', '');
      const entries = await readSegmentEntries(dataDir, segmentId);
      const manifest = await loadManifest(dataDir, segmentId);
      results.push({
        segmentId,
        proofCount: entries.length,
        hasManifest: manifest !== null,
      });
    }
  } catch {
    // No segments dir
  }

  return results;
}

/**
 * Check if current segment should be sealed (size or age threshold).
 */
export function shouldSealSegment(
  proofCount: number,
  segmentCreatedAt: string,
  maxSize: number,
  maxAgeSeconds: number,
): boolean {
  if (proofCount >= maxSize) return true;

  const ageMs = Date.now() - new Date(segmentCreatedAt).getTime();
  if (ageMs >= maxAgeSeconds * 1000) return true;

  return false;
}

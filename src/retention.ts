import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { readSegmentEntries } from './chain.ts';
import { loadManifest } from './segments.ts';
import type { ProofEntry, SegmentManifest } from './types.ts';

/**
 * Apply retention to a sealed segment.
 *
 * Retention does NOT delete proofs or break the chain.
 * It preserves the proof skeleton (id, sequence, hash, prev_hash, signature,
 * event_type, timestamp) and zeros out payload data (summaries, encrypted blobs).
 *
 * Chain integrity remains verifiable because hashes were computed from the
 * original data and stored in the manifest.
 */

export interface RetentionResult {
  readonly segmentId: string;
  readonly proofsRetained: number;
  readonly payloadsZeroed: number;
}

export async function applyRetention(
  dataDir: string,
  segmentId: string,
  retentionDays: number,
): Promise<RetentionResult | null> {
  const manifest = await loadManifest(dataDir, segmentId);
  if (!manifest) return null;
  if (manifest.retention_applied) return null;

  // Check if segment is old enough
  const sealedAt = new Date(manifest.sealed_at).getTime();
  const ageMs = Date.now() - sealedAt;
  const retentionMs = retentionDays * 24 * 60 * 60 * 1000;

  if (ageMs < retentionMs) return null;

  // Read entries
  const entries = await readSegmentEntries(dataDir, segmentId);

  // Zero out payloads but keep skeleton
  let payloadsZeroed = 0;
  const retained: ProofEntry[] = entries.map((entry) => {
    const hasPayload = entry.action.input_summary ||
      entry.action.output_summary ||
      entry.action.input_encrypted ||
      entry.action.output_encrypted;

    if (hasPayload) {
      payloadsZeroed++;
      return {
        ...entry,
        action: {
          ...entry.action,
          input_summary: undefined,
          output_summary: undefined,
          input_encrypted: undefined,
          output_encrypted: undefined,
        },
      } as ProofEntry;
    }
    return entry;
  });

  // Write back the segment with zeroed payloads
  const segPath = join(dataDir, 'segments', `${segmentId}.jsonl`);
  const content = retained.map((e) => JSON.stringify(e)).join('\n') + '\n';
  await writeFile(segPath, content, 'utf-8');

  // Update manifest
  const updatedManifest: SegmentManifest = {
    ...manifest,
    retention_applied: true,
  };
  await writeFile(
    join(dataDir, 'manifests', `${segmentId}.manifest.json`),
    JSON.stringify(updatedManifest, null, 2),
    'utf-8',
  );

  return {
    segmentId,
    proofsRetained: entries.length,
    payloadsZeroed,
  };
}

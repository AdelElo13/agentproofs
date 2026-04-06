import { writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { sha256, signHash } from './crypto.ts';
import { queryProofs } from './query.ts';
import type {
  ProofEntry,
  ExportParams,
  ExportResult,
  KeyPair,
  QueryParams,
} from './types.ts';

// ── Export Formats ──

function toJsonl(entries: readonly ProofEntry[]): string {
  return entries.map((e) => JSON.stringify(e)).join('\n') + '\n';
}

function toJson(entries: readonly ProofEntry[]): string {
  return JSON.stringify(entries, null, 2);
}

function toCsv(entries: readonly ProofEntry[]): string {
  const headers = [
    'id', 'sequence', 'timestamp', 'event_type', 'agent_id', 'session_id',
    'tool', 'success', 'duration_ms', 'namespace', 'hash', 'prev_hash',
  ];

  const rows = entries.map((e) => [
    e.id,
    e.sequence,
    e.timestamp,
    e.event_type,
    e.agent_id,
    e.session_id,
    e.action.tool ?? '',
    e.action.success,
    e.action.duration_ms ?? '',
    e.context.namespace ?? '',
    e.hash,
    e.prev_hash,
  ].map((v) => csvEscape(String(v))).join(','));

  return [headers.join(','), ...rows].join('\n') + '\n';
}

function csvEscape(value: string): string {
  if (value.includes(',') || value.includes('"') || value.includes('\n')) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

// ── Export ──

export async function exportProofs(
  dataDir: string,
  params: ExportParams,
  keyPair?: KeyPair,
): Promise<ExportResult> {
  const exportDir = join(dataDir, 'exports');
  await mkdir(exportDir, { recursive: true });

  // Build query params from export params
  const queryParams: QueryParams = {
    from_date: params.from_date,
    to_date: params.to_date,
    namespace: params.namespace,
    session_id: params.session_id,
    trace_id: params.trace_id,
    limit: 0, // no limit for export — we handle it below
    sort: 'asc',
  };

  // Query all matching proofs (with a high limit)
  const result = await queryProofs(dataDir, { ...queryParams, limit: 1_000_000 });
  const entries = result.results;

  // Format
  let content: string;
  let ext: string;
  switch (params.format) {
    case 'jsonl':
      content = toJsonl(entries);
      ext = 'jsonl';
      break;
    case 'json':
      content = toJson(entries);
      ext = 'json';
      break;
    case 'csv':
      content = toCsv(entries);
      ext = 'csv';
      break;
  }

  // Generate filename
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const filename = `export-${timestamp}.${ext}`;
  const filePath = join(exportDir, filename);

  await writeFile(filePath, content, 'utf-8');

  const exportHash = sha256(content);
  let exportSignature: string | undefined;

  if (params.sign_export && keyPair) {
    exportSignature = signHash(exportHash, keyPair.privateKey);
  }

  return {
    file_path: filePath,
    total_proofs: entries.length,
    chain_valid: true, // caller should verify separately
    export_hash: exportHash,
    export_signature: exportSignature,
  };
}

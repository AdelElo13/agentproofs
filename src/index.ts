import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { loadConfig } from './config.ts';
import { createMcpServer } from './server.ts';
import { writePidFile } from './daemon.ts';

export async function main(): Promise<void> {
  const config = loadConfig();
  const { server, daemon } = await createMcpServer(config);

  await writePidFile(config.dataDir);

  // Log daemon start
  const { daemonAppend } = await import('./daemon.ts');
  await daemonAppend(daemon, {
    event_type: 'daemon_started',
    success: true,
    origin: 'daemon',
    input_summary: `Daemon started with agent_id=${config.agentId}`,
    output_summary: `Chain ${daemon.chainId}, session ${daemon.sessionId}`,
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

// Re-exports for library usage
export { createMcpServer } from './server.ts';
export { createDaemon, daemonAppend, stopDaemon } from './daemon.ts';
export { loadConfig } from './config.ts';
export { verifyChain, readAllEntries, readChainState } from './chain.ts';
export { queryProofs } from './query.ts';
export { exportProofs } from './export.ts';
export { generateKeyPair, sha256, formatPublicKey } from './crypto.ts';
export { canonicalize } from './canonical.ts';
export { ProofIndex } from './index-db.ts';
export { rotateKey, listKeys, loadKeyById, loadAllPublicKeys } from './keys.ts';
export { sealSegment, loadManifest, listSegments, shouldSealSegment } from './segments.ts';
export { applyRetention } from './retention.ts';
export { detectOrphans, findOrphanedStarts } from './recovery.ts';
export { generateComplianceReport, formatReportAsMarkdown } from './compliance.ts';
export type { ComplianceReport } from './compliance.ts';
export { auditChain } from './verifier.ts';
export type { AuditReport, AuditError } from './verifier.ts';
export {
  createCheckpoint,
  createCheckpointFromChain,
  computeMerkleRoot,
  submitToRekor,
  verifyRekorEntry,
  saveAnchor,
  listAnchors,
  loadAnchor,
} from './anchor.ts';
export type { Checkpoint, AnchorRecord, RekorEntryVerification } from './anchor.ts';
export { createDashboardServer, startDashboardServer } from './dashboard-server.ts';
export type * from './types.ts';

// ── AgentTrace Module (observability + cost attribution) ──
export * from './trace/index.ts';

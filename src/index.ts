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
export type * from './types.ts';

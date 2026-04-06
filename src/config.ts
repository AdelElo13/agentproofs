import { join } from 'node:path';
import { homedir } from 'node:os';
import type { AgentproofsConfig, RedactionLevel } from './types.ts';

function envStr(key: string, fallback: string): string {
  return process.env[key] ?? fallback;
}

function envInt(key: string, fallback: number): number {
  const val = process.env[key];
  if (val === undefined) return fallback;
  const parsed = parseInt(val, 10);
  return Number.isNaN(parsed) ? fallback : parsed;
}

export function loadConfig(): AgentproofsConfig {
  const dataDir = envStr('AGENTPROOFS_DATA_DIR', join(homedir(), '.agentproofs'));

  return {
    dataDir,
    agentId: envStr('AGENTPROOFS_AGENT_ID', 'claude-code'),
    userId: envStr('AGENTPROOFS_USER_ID', ''),
    namespace: envStr('AGENTPROOFS_NAMESPACE', 'default'),
    logLevel: envStr('AGENTPROOFS_LOG_LEVEL', 'info') as AgentproofsConfig['logLevel'],
    retentionDays: envInt('AGENTPROOFS_RETENTION_DAYS', 365),
    segmentSize: envInt('AGENTPROOFS_SEGMENT_SIZE', 10000),
    segmentMaxAge: envInt('AGENTPROOFS_SEGMENT_MAX_AGE', 86400),
    redactionLevel: envInt('AGENTPROOFS_REDACTION_LEVEL', 0) as RedactionLevel,
    socketPath: envStr('AGENTPROOFS_SOCKET_PATH', join(dataDir, 'daemon.sock')),
    httpPort: envInt('AGENTPROOFS_HTTP_PORT', 0),
    keyStore: envStr('AGENTPROOFS_KEY_STORE', 'file') as AgentproofsConfig['keyStore'],
    checkpointInterval: envInt('AGENTPROOFS_CHECKPOINT_INTERVAL', 0),
  };
}

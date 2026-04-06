import { readChainState, readAllEntries } from './chain.ts';
import type { ProofEntry, AgentproofsConfig } from './types.ts';

// ── Chain Status Resource ──

export interface ChainStatusResource {
  readonly chain_id: string;
  readonly length: number;
  readonly last_hash: string;
  readonly last_sequence: number;
  readonly last_timestamp: string;
  readonly segment_id: string;
  readonly health: 'healthy' | 'empty' | 'unknown';
  readonly public_key?: string;
}

export async function getChainStatus(
  config: AgentproofsConfig,
  chainId: string,
  publicKeyFormatted?: string,
): Promise<ChainStatusResource> {
  const state = await readChainState(config.dataDir, chainId);

  return {
    chain_id: chainId,
    length: state.proofCount,
    last_hash: state.lastHash,
    last_sequence: state.sequence,
    last_timestamp: state.lastTimestamp,
    segment_id: state.segmentId,
    health: state.proofCount > 0 ? 'healthy' : 'empty',
    public_key: publicKeyFormatted,
  };
}

// ── Stats Resource ──

export interface StatsResource {
  readonly total_proofs: number;
  readonly by_agent: Record<string, number>;
  readonly by_tool: Record<string, number>;
  readonly by_event_type: Record<string, number>;
  readonly by_namespace: Record<string, number>;
  readonly by_day: Record<string, number>;
}

export async function getStats(config: AgentproofsConfig): Promise<StatsResource> {
  const entries = await readAllEntries(config.dataDir);

  const byAgent: Record<string, number> = {};
  const byTool: Record<string, number> = {};
  const byEventType: Record<string, number> = {};
  const byNamespace: Record<string, number> = {};
  const byDay: Record<string, number> = {};

  for (const entry of entries) {
    byAgent[entry.agent_id] = (byAgent[entry.agent_id] ?? 0) + 1;

    if (entry.action.tool) {
      byTool[entry.action.tool] = (byTool[entry.action.tool] ?? 0) + 1;
    }

    byEventType[entry.event_type] = (byEventType[entry.event_type] ?? 0) + 1;

    const ns = entry.context.namespace ?? 'default';
    byNamespace[ns] = (byNamespace[ns] ?? 0) + 1;

    const day = entry.timestamp.slice(0, 10);
    byDay[day] = (byDay[day] ?? 0) + 1;
  }

  return {
    total_proofs: entries.length,
    by_agent: byAgent,
    by_tool: byTool,
    by_event_type: byEventType,
    by_namespace: byNamespace,
    by_day: byDay,
  };
}

// ── Latest Resource ──

export async function getLatest(
  config: AgentproofsConfig,
  count = 20,
): Promise<readonly ProofEntry[]> {
  const entries = await readAllEntries(config.dataDir);
  return entries.slice(-count);
}

// ── By Agent Resource ──

export async function getByAgent(
  config: AgentproofsConfig,
  agentId: string,
): Promise<readonly ProofEntry[]> {
  const entries = await readAllEntries(config.dataDir);
  return entries.filter((e) => e.agent_id === agentId);
}

// ── By Session Resource ──

export async function getBySession(
  config: AgentproofsConfig,
  sessionId: string,
): Promise<readonly ProofEntry[]> {
  const entries = await readAllEntries(config.dataDir);
  return entries.filter((e) => e.session_id === sessionId);
}

// ── By Trace Resource ──

export async function getByTrace(
  config: AgentproofsConfig,
  traceId: string,
): Promise<readonly ProofEntry[]> {
  const entries = await readAllEntries(config.dataDir);
  return entries.filter((e) => e.trace_id === traceId);
}

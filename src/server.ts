import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { createDaemon, daemonAppend, type DaemonState } from './daemon.ts';
import { verifyChain } from './chain.ts';
import { queryProofs } from './query.ts';
import { exportProofs } from './export.ts';
import { formatPublicKey } from './crypto.ts';
import {
  getChainStatus,
  getStats,
  getLatest,
  getByAgent,
  getBySession,
  getByTrace,
} from './resources.ts';
import type { AgentproofsConfig, EventType } from './types.ts';
import { EVENT_TYPES } from './types.ts';

export async function createMcpServer(config: AgentproofsConfig): Promise<{
  server: McpServer;
  daemon: DaemonState;
}> {
  const daemon = await createDaemon(config);
  const server = new McpServer({
    name: 'agentproofs',
    version: '0.1.0',
  });

  // ── Tools ──

  server.tool(
    'proof_log',
    'Log an agent event to the proof chain',
    {
      event_type: z.enum(EVENT_TYPES as unknown as [string, ...string[]]).describe('Event type'),
      tool: z.string().optional().describe('Tool name'),
      tool_invocation_id: z.string().optional().describe('Links started/completed pair'),
      trace_id: z.string().optional().describe('Distributed trace ID'),
      input_summary: z.string().optional().describe('Human-readable input description'),
      output_summary: z.string().optional().describe('Human-readable output description'),
      input_hash: z.string().optional().describe('Pre-computed input hash'),
      output_hash: z.string().optional().describe('Pre-computed output hash'),
      success: z.boolean().describe('Did the action succeed?'),
      reason: z.string().optional().describe('Why this action was taken'),
      namespace: z.string().optional().describe('Project namespace'),
      tags: z.array(z.string()).optional().describe('Searchable tags'),
      duration_ms: z.number().optional().describe('Execution time in ms'),
      origin: z.enum(['hook', 'sdk', 'mcp', 'manual', 'daemon']).optional().describe('Event origin'),
      parent_event_id: z.string().optional().describe('Parent event for delegation'),
      redaction_level: z.number().min(0).max(3).optional().describe('Privacy level (0-3)'),
    },
    async (params) => {
      const result = await daemonAppend(daemon, {
        event_type: params.event_type as EventType,
        tool: params.tool,
        tool_invocation_id: params.tool_invocation_id,
        trace_id: params.trace_id,
        input_summary: params.input_summary,
        output_summary: params.output_summary,
        input_hash: params.input_hash,
        output_hash: params.output_hash,
        success: params.success,
        reason: params.reason,
        namespace: params.namespace,
        tags: params.tags,
        duration_ms: params.duration_ms,
        origin: params.origin as any,
        parent_event_id: params.parent_event_id,
        redaction_level: params.redaction_level as any,
      });

      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }],
      };
    },
  );

  server.tool(
    'proof_verify',
    'Verify the integrity of the proof chain',
    {
      from_sequence: z.number().optional().describe('Start from sequence'),
      to_sequence: z.number().optional().describe('End at sequence'),
      verify_signatures: z.boolean().optional().describe('Verify Ed25519 signatures (default: true)'),
    },
    async (params) => {
      const keys = new Map([[daemon.keyPair.keyId, daemon.keyPair.publicKey]]);
      const result = await verifyChain(config.dataDir, keys, {
        fromSequence: params.from_sequence,
        toSequence: params.to_sequence,
        verifySignatures: params.verify_signatures,
      });

      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }],
      };
    },
  );

  server.tool(
    'proof_query',
    'Search the proof chain',
    {
      proof_id: z.string().optional().describe('Specific proof by ID'),
      agent_id: z.string().optional().describe('Filter by agent'),
      session_id: z.string().optional().describe('Filter by session'),
      trace_id: z.string().optional().describe('Filter by trace'),
      event_type: z.string().optional().describe('Filter by event type'),
      tool: z.string().optional().describe('Filter by tool'),
      namespace: z.string().optional().describe('Filter by namespace'),
      tags: z.array(z.string()).optional().describe('Filter by tags (AND)'),
      from_date: z.string().optional().describe('ISO start date'),
      to_date: z.string().optional().describe('ISO end date'),
      success: z.boolean().optional().describe('Filter by success/failure'),
      sort: z.enum(['asc', 'desc']).optional().describe('Sort order'),
      limit: z.number().optional().describe('Max results (default 50)'),
      offset: z.number().optional().describe('Pagination offset'),
    },
    async (params) => {
      const result = await queryProofs(config.dataDir, {
        proof_id: params.proof_id,
        agent_id: params.agent_id,
        session_id: params.session_id,
        trace_id: params.trace_id,
        event_type: params.event_type as EventType | undefined,
        tool: params.tool,
        namespace: params.namespace,
        tags: params.tags,
        from_date: params.from_date,
        to_date: params.to_date,
        success: params.success,
        sort: params.sort,
        limit: params.limit,
        offset: params.offset,
      });

      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }],
      };
    },
  );

  server.tool(
    'proof_export',
    'Export proofs for external audit',
    {
      format: z.enum(['jsonl', 'json', 'csv']).describe('Export format'),
      from_date: z.string().optional().describe('Start date'),
      to_date: z.string().optional().describe('End date'),
      namespace: z.string().optional().describe('Filter by namespace'),
      export_scope: z.enum(['full', 'filtered', 'trace', 'session']).optional(),
      trace_id: z.string().optional(),
      session_id: z.string().optional(),
      include_verification: z.boolean().optional(),
      sign_export: z.boolean().optional().describe('Sign the export file'),
    },
    async (params) => {
      const result = await exportProofs(config.dataDir, {
        format: params.format,
        from_date: params.from_date,
        to_date: params.to_date,
        namespace: params.namespace,
        export_scope: params.export_scope,
        trace_id: params.trace_id,
        session_id: params.session_id,
        include_verification: params.include_verification,
        sign_export: params.sign_export,
      }, params.sign_export ? daemon.keyPair : undefined);

      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }],
      };
    },
  );

  // ── Resources ──

  server.resource(
    'chain',
    'proofs://chain',
    { description: 'Chain status, health, and public key' },
    async () => {
      const status = await getChainStatus(
        config,
        daemon.chainId,
        formatPublicKey(daemon.keyPair.publicKey),
      );
      return {
        contents: [{
          uri: 'proofs://chain',
          mimeType: 'application/json',
          text: JSON.stringify(status, null, 2),
        }],
      };
    },
  );

  server.resource(
    'stats',
    'proofs://stats',
    { description: 'Per-agent, per-tool, per-namespace statistics' },
    async () => {
      const stats = await getStats(config);
      return {
        contents: [{
          uri: 'proofs://stats',
          mimeType: 'application/json',
          text: JSON.stringify(stats, null, 2),
        }],
      };
    },
  );

  server.resource(
    'latest',
    'proofs://latest',
    { description: 'Last 20 proof entries' },
    async () => {
      const latest = await getLatest(config);
      return {
        contents: [{
          uri: 'proofs://latest',
          mimeType: 'application/json',
          text: JSON.stringify(latest, null, 2),
        }],
      };
    },
  );

  return { server, daemon };
}

/**
 * Claude Code Session Parser
 *
 * Parses Claude Code JSONL session logs into AgentTrace decision trees.
 * First integration target — zero-code instrumentation of existing sessions.
 *
 * Fixes applied (Codex rounds 4+5):
 * - Proper delegation tree with consistent agentIds
 * - Two-pass token attribution: collect usage per turn, then attribute
 * - Delegation stack uses Map for out-of-order result handling
 * - Remainder tokens distributed correctly (no Math.floor loss)
 */

import type { DecisionType } from './trace-types.js';
import { findPricing, calculateCost } from './pricing.js';
import { Tracer, Span, type TracerConfig } from './tracer.js';

// ── Claude Code JSONL Types ───────────────────────────────────

interface ClaudeCodeMessage {
  type: string;
  role?: string;
  content?: ClaudeCodeContent[];
  model?: string;
  usage?: {
    input_tokens?: number;
    output_tokens?: number;
    cache_creation_input_tokens?: number;
    cache_read_input_tokens?: number;
  };
  stop_reason?: string;
}

interface ClaudeCodeContent {
  type: string;
  name?: string;
  id?: string;
  input?: unknown;
  text?: string;
  content?: string;
  is_error?: boolean;
}

// ── Token Accumulator ─────────────────────────────────────────

interface TokenBucket {
  input: number;
  output: number;
  cacheRead: number;
  cacheWrite: number;
}

function emptyBucket(): TokenBucket {
  return { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 };
}

function addBuckets(a: TokenBucket, b: TokenBucket): TokenBucket {
  return {
    input: a.input + b.input,
    output: a.output + b.output,
    cacheRead: a.cacheRead + b.cacheRead,
    cacheWrite: a.cacheWrite + b.cacheWrite,
  };
}

/** Distribute tokens across N spans, with remainder going to the first span */
function distributeBucket(total: TokenBucket, count: number): TokenBucket[] {
  if (count <= 0) return [];
  if (count === 1) return [{ ...total }];

  const base: TokenBucket = {
    input: Math.floor(total.input / count),
    output: Math.floor(total.output / count),
    cacheRead: Math.floor(total.cacheRead / count),
    cacheWrite: Math.floor(total.cacheWrite / count),
  };

  const result: TokenBucket[] = [];
  // First span gets the remainder
  result.push({
    input: total.input - base.input * (count - 1),
    output: total.output - base.output * (count - 1),
    cacheRead: total.cacheRead - base.cacheRead * (count - 1),
    cacheWrite: total.cacheWrite - base.cacheWrite * (count - 1),
  });
  for (let i = 1; i < count; i++) {
    result.push({ ...base });
  }
  return result;
}

// ── Parser ────────────────────────────────────────────────────

export interface ParseOptions {
  readonly project?: string;
  readonly sessionId?: string;
  readonly model?: string;
}

interface ActiveTool {
  span: Span;
  delegationAgentId: string; // the agentId of the delegation context this tool runs in
  isDelegation: boolean;
  tokens: TokenBucket;
}

export function parseClaudeCodeSession(
  jsonlLines: readonly string[],
  opts: ParseOptions = {},
): ReturnType<Tracer['finish']> {
  const messages = jsonlLines
    .filter(line => line.trim().length > 0)
    .map(line => {
      try { return JSON.parse(line) as ClaudeCodeMessage; }
      catch { return null; }
    })
    .filter((m): m is ClaudeCodeMessage => m !== null);

  const model = opts.model ?? detectModel(messages) ?? 'claude-sonnet-4-6';

  const config: TracerConfig = {
    project: opts.project ?? 'unknown',
    sessionId: opts.sessionId,
    model,
    agentName: 'main',
  };

  const tracer = new Tracer(config);
  const rootSpan = tracer.startSpan('Claude Code Session', { type: 'reasoning' });

  // Active tool spans keyed by tool_use id
  const activeTools = new Map<string, ActiveTool>();

  // Delegation context: maps tool_use id -> { span, agentId }
  // When an Agent tool_use is active, subsequent tool_uses within the same
  // turn or before the Agent result are children of that delegation
  const activeDelegations = new Map<string, { span: Span; agentId: string }>();

  // Tokens accumulated for root reasoning (non-tool-attributed)
  const rootTokens = emptyBucket();

  // Per-turn: collect tool_use ids, then attribute the turn's usage to them
  let turnToolIds: string[] = [];

  for (const msg of messages) {
    // ── Assistant turn: extract tool_uses ────────────────────
    if (msg.role === 'assistant' && msg.content) {
      // Reset turn tracking
      turnToolIds = [];

      for (const block of msg.content) {
        if (block.type === 'tool_use' && block.name && block.id) {
          const type = classifyTool(block.name);
          const description = describeToolUse(block.name, block.input);

          // Determine parent span and agentId from delegation context
          let parentSpan = rootSpan;
          let currentAgentId = 'main';

          // Find the innermost active delegation to nest under
          for (const deleg of activeDelegations.values()) {
            parentSpan = deleg.span;
            currentAgentId = deleg.agentId;
          }

          // For delegation tool_uses (Agent/Task), create a unique agentId
          const isDelegation = type === 'delegation';
          const thisAgentId = isDelegation
            ? `agent-${block.id}`
            : currentAgentId;
          const thisAgentName = isDelegation
            ? extractAgentName(block.input)
            : currentAgentId === 'main' ? 'main' : 'sub-agent';

          const span = parentSpan.startChild(description, {
            type,
            tool: block.name,
            agentId: thisAgentId,
            agentName: thisAgentName,
            metadata: { toolInput: summarizeInput(block.input) },
          });

          const entry: ActiveTool = {
            span,
            delegationAgentId: currentAgentId,
            isDelegation,
            tokens: emptyBucket(),
          };
          activeTools.set(block.id, entry);
          turnToolIds.push(block.id);

          // If this is a delegation, register it so future tool_uses nest under it
          if (isDelegation) {
            activeDelegations.set(block.id, { span, agentId: thisAgentId });
          }
        }
      }

      // ── Attribute usage from this response to the turn's tool_uses ──
      if (msg.usage) {
        const turnTokens: TokenBucket = {
          input: msg.usage.input_tokens ?? 0,
          output: msg.usage.output_tokens ?? 0,
          cacheRead: msg.usage.cache_read_input_tokens ?? 0,
          cacheWrite: msg.usage.cache_creation_input_tokens ?? 0,
        };

        if (turnToolIds.length > 0) {
          const distributed = distributeBucket(turnTokens, turnToolIds.length);
          for (let i = 0; i < turnToolIds.length; i++) {
            const entry = activeTools.get(turnToolIds[i]!);
            if (entry) {
              entry.tokens = addBuckets(entry.tokens, distributed[i]!);
            }
          }
        } else {
          // No tool_uses in this turn — attribute to root reasoning
          Object.assign(rootTokens, addBuckets(rootTokens, turnTokens));
        }
      }
    }

    // ── User turn: process tool_results ──────────────────────
    if (msg.role === 'user' && msg.content) {
      // Usage on user messages goes to root reasoning
      if (msg.usage) {
        const userTokens: TokenBucket = {
          input: msg.usage.input_tokens ?? 0,
          output: msg.usage.output_tokens ?? 0,
          cacheRead: msg.usage.cache_read_input_tokens ?? 0,
          cacheWrite: msg.usage.cache_creation_input_tokens ?? 0,
        };
        Object.assign(rootTokens, addBuckets(rootTokens, userTokens));
      }

      for (const block of msg.content) {
        if (block.type === 'tool_result' && block.id) {
          const entry = activeTools.get(block.id);
          if (entry) {
            const isError = block.is_error === true;

            entry.span.end({
              outcome: isError ? 'failure' : 'success',
              tokens: entry.tokens,
              wasteReason: isError ? extractErrorReason(block.content) : undefined,
            });

            // Clean up delegation context
            if (entry.isDelegation) {
              activeDelegations.delete(block.id);
            }
            activeTools.delete(block.id);
          }
        }
      }
    }
  }

  // End any unclosed spans
  for (const [id, entry] of activeTools) {
    entry.span.end({ outcome: 'partial', tokens: entry.tokens, wasteReason: 'Tool call never completed' });
    if (entry.isDelegation) activeDelegations.delete(id);
  }
  activeTools.clear();

  // End root span with reasoning tokens
  rootSpan.end({ outcome: 'success', tokens: rootTokens });

  return tracer.finish();
}

// ── Classification Helpers ────────────────────────────────────

function classifyTool(name: string): DecisionType {
  if (name === 'Agent' || name === 'Task') return 'delegation';
  if (['Read', 'Glob', 'Grep', 'WebSearch', 'WebFetch', 'ToolSearch'].includes(name)) return 'exploration';
  if (['Write', 'Edit', 'NotebookEdit'].includes(name)) return 'generation';
  return 'tool_call';
}

function describeToolUse(name: string, input: unknown): string {
  if (!input || typeof input !== 'object') return name;
  const inp = input as Record<string, unknown>;

  if (name === 'Read' && inp.file_path) return `Read ${basename(String(inp.file_path))}`;
  if (name === 'Write' && inp.file_path) return `Write ${basename(String(inp.file_path))}`;
  if (name === 'Edit' && inp.file_path) return `Edit ${basename(String(inp.file_path))}`;
  if (name === 'Bash' && inp.command) return `Bash: ${truncate(String(inp.command), 60)}`;
  if (name === 'Grep' && inp.pattern) return `Grep "${truncate(String(inp.pattern), 40)}"`;
  if (name === 'Glob' && inp.pattern) return `Glob "${truncate(String(inp.pattern), 40)}"`;
  if (name === 'Agent' && inp.description) return `Agent: ${truncate(String(inp.description), 50)}`;

  return name;
}

function detectModel(messages: readonly ClaudeCodeMessage[]): string | null {
  for (const msg of messages) {
    if (msg.model) return msg.model;
  }
  return null;
}

function extractAgentName(input: unknown): string {
  if (!input || typeof input !== 'object') return 'sub-agent';
  const inp = input as Record<string, unknown>;
  return truncate(String(inp.description ?? inp.subagent_type ?? 'sub-agent'), 40);
}

function extractErrorReason(content: string | undefined): string {
  if (!content) return 'Tool call failed';
  return truncate(content, 100);
}

function summarizeInput(input: unknown): string {
  if (!input) return '';
  const str = JSON.stringify(input);
  return str.length > 200 ? str.slice(0, 200) + '...' : str;
}

function basename(path: string): string {
  return path.split('/').pop() ?? path;
}

function truncate(str: string, max: number): string {
  return str.length > max ? str.slice(0, max) + '...' : str;
}

/**
 * AgentTrace Module
 *
 * Decision-level observability and cost attribution for AI agents.
 * Integrated into AgentProofs as the observability layer.
 */

export type {
  TokenUsage,
  CostBreakdown,
  ModelPricing,
  DecisionType,
  DecisionOutcome,
  Decision,
  Trace,
  AgentSummary,
  DecisionRef,
  InsightSeverity,
  InsightCategory,
  Insight,
  Recommendation,
} from './trace-types.js';

export { findPricing, calculateCost, sumTokens } from './pricing.js';
export { scoreWaste, detectInsights, buildAgentSummaries, flattenDecisions } from './analyzer.js';
export { Tracer, Span } from './tracer.js';
export type { TracerConfig, SpanOptions, SpanEndOptions } from './tracer.js';
export { parseClaudeCodeSession } from './claude-code-parser.js';
export type { ParseOptions } from './claude-code-parser.js';

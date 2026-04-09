/**
 * AgentTrace SDK — Tracer
 *
 * The main instrumentation API. Wrap agent functions to automatically
 * capture decision trees with cost attribution.
 *
 * Usage:
 *   const tracer = new Tracer({ project: 'my-app', model: 'claude-sonnet-4-6' });
 *   const span = tracer.startSpan('research', { type: 'exploration' });
 *   // ... do work ...
 *   span.end({ outcome: 'success' });
 *   const trace = tracer.finish();
 */

import type {
  Decision,
  DecisionType,
  DecisionOutcome,
  Trace,
  TokenUsage,
  CostBreakdown,
} from './trace-types.js';
import { findPricing, calculateCost, sumTokens } from './pricing.js';
import { scoreWaste, detectInsights, buildAgentSummaries, flattenDecisions } from './analyzer.js';

// ── Config ────────────────────────────────────────────────────

export interface TracerConfig {
  readonly project: string;
  readonly sessionId?: string;
  readonly model: string;
  readonly agentId?: string;
  readonly agentName?: string;
}

// ── Span (mutable during recording) ──────────────────────────

export interface SpanOptions {
  readonly type: DecisionType;
  readonly tool?: string;
  readonly agentId?: string;
  readonly agentName?: string;
  readonly metadata?: Record<string, unknown>;
}

export interface SpanEndOptions {
  readonly outcome: DecisionOutcome;
  readonly tokens?: Partial<TokenUsage>;
  readonly wasteReason?: string;
  readonly metadata?: Record<string, unknown>;
}

interface MutableSpan {
  id: string;
  parentId: string | null;
  agentId: string;
  agentName: string;
  type: DecisionType;
  tool: string | null;
  description: string;
  startedAt: number;
  endedAt: number;
  tokens: TokenUsage;
  cost: CostBreakdown;
  outcome: DecisionOutcome;
  wasteScore: number;
  wasteReason: string | null;
  children: MutableSpan[];
  metadata: Record<string, unknown>;
}

export class Span {
  private readonly _span: MutableSpan;
  private readonly _tracer: Tracer;
  private _ended = false;

  constructor(span: MutableSpan, tracer: Tracer) {
    this._span = span;
    this._tracer = tracer;
  }

  startChild(description: string, opts: SpanOptions): Span {
    if (this._ended) throw new Error('Cannot start child on ended span');
    return this._tracer._createSpan(description, opts, this._span);
  }

  end(opts: SpanEndOptions): void {
    if (this._ended) return;
    this._ended = true;

    const now = Date.now();
    this._span.endedAt = now;
    this._span.outcome = opts.outcome;
    this._span.wasteReason = opts.wasteReason ?? null;

    if (opts.tokens) {
      this._span.tokens = {
        input: opts.tokens.input ?? 0,
        output: opts.tokens.output ?? 0,
        cacheRead: opts.tokens.cacheRead ?? 0,
        cacheWrite: opts.tokens.cacheWrite ?? 0,
      };
    }

    if (opts.metadata) {
      Object.assign(this._span.metadata, opts.metadata);
    }

    // Calculate cost
    const pricing = findPricing(this._tracer.model);
    if (pricing) {
      this._span.cost = calculateCost(this._span.tokens, pricing);
    }

    // Score waste
    this._span.wasteScore = scoreWaste(this._span as Decision);
  }

  get id(): string { return this._span.id; }
}

// ── Tracer ────────────────────────────────────────────────────

let spanCounter = 0;

export class Tracer {
  readonly project: string;
  readonly sessionId: string;
  readonly model: string;
  private readonly _agentId: string;
  private readonly _agentName: string;
  private _root: MutableSpan | null = null;
  private _startedAt: number;
  private _finished = false;

  constructor(config: TracerConfig) {
    this.project = config.project;
    this.sessionId = config.sessionId ?? crypto.randomUUID();
    this.model = config.model;
    this._agentId = config.agentId ?? 'root';
    this._agentName = config.agentName ?? 'root';
    this._startedAt = Date.now();
  }

  startSpan(description: string, opts: SpanOptions): Span {
    return this._createSpan(description, opts, null);
  }

  /** @internal */
  _createSpan(description: string, opts: SpanOptions, parent: MutableSpan | null): Span {
    const span: MutableSpan = {
      id: `span-${++spanCounter}`,
      parentId: parent?.id ?? null,
      agentId: opts.agentId ?? this._agentId,
      agentName: opts.agentName ?? this._agentName,
      type: opts.type,
      tool: opts.tool ?? null,
      description,
      startedAt: Date.now(),
      endedAt: 0,
      tokens: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      cost: { tokens: 0, tools: 0, total: 0 },
      outcome: 'success',
      wasteScore: 0,
      wasteReason: null,
      children: [],
      metadata: opts.metadata ? { ...opts.metadata } : {},
    };

    if (parent) {
      parent.children.push(span);
    } else if (!this._root) {
      this._root = span;
    } else {
      this._root.children.push(span);
    }

    return new Span(span, this);
  }

  finish(): Trace {
    if (this._finished) throw new Error('Tracer already finished');
    this._finished = true;

    if (!this._root) {
      throw new Error('No spans recorded');
    }

    const rootDecision = freezeSpan(this._root);
    const allDecisions = flattenDecisions(rootDecision);
    const allTokens = allDecisions.map(d => d.tokens);
    const totalTokens = sumTokens(allTokens);
    const totalCost = allDecisions.reduce((s, d) => s + d.cost.total, 0);
    const wasteCost = allDecisions.reduce((s, d) => s + d.cost.total * d.wasteScore, 0);
    const agents = buildAgentSummaries(rootDecision);
    const insights = detectInsights(rootDecision);
    const uniqueAgents = new Set(allDecisions.map(d => d.agentId));

    return {
      id: crypto.randomUUID(),
      sessionId: this.sessionId,
      project: this.project,
      startedAt: this._startedAt,
      endedAt: Date.now(),
      model: this.model,
      provider: findPricing(this.model)?.provider ?? 'unknown',
      tokens: totalTokens,
      cost: {
        tokens: Math.round(totalCost * 1_000_000) / 1_000_000,
        tools: 0,
        total: Math.round(totalCost * 1_000_000) / 1_000_000,
      },
      wasteTotal: Math.round(wasteCost * 100) / 100,
      wastePercentage: totalCost > 0 ? wasteCost / totalCost : 0,
      decisionCount: allDecisions.length,
      agentCount: uniqueAgents.size,
      rootDecision,
      agents,
      insights,
    };
  }
}

// ── Helpers ───────────────────────────────────────────────────

function freezeSpan(span: MutableSpan): Decision {
  return {
    id: span.id,
    parentId: span.parentId,
    agentId: span.agentId,
    agentName: span.agentName,
    type: span.type,
    tool: span.tool,
    description: span.description,
    startedAt: span.startedAt,
    endedAt: span.endedAt,
    tokens: { ...span.tokens },
    cost: { ...span.cost },
    outcome: span.outcome,
    wasteScore: span.wasteScore,
    wasteReason: span.wasteReason,
    children: span.children.map(freezeSpan),
    metadata: { ...span.metadata },
  };
}

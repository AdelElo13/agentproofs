/**
 * Waste Analyzer
 *
 * Analyzes a decision tree and scores each node for waste.
 * Uses heuristics based on outcome, cost, and patterns.
 *
 * This is the core differentiator: not "what LLM calls happened"
 * but "which agent decisions were worth the money."
 */

import type { Decision, Trace, Insight, InsightCategory, InsightSeverity, AgentSummary, DecisionRef, Recommendation } from './trace-types.js';

// ── Waste Scoring ─────────────────────────────────────────────

const OUTCOME_WASTE: Record<string, number> = {
  success: 0.0,
  partial: 0.2,
  failure: 0.7,
  redundant: 0.9,
  dead_end: 1.0,
};

export function scoreWaste(decision: Decision): number {
  const baseScore = OUTCOME_WASTE[decision.outcome] ?? 0;

  // Boost waste score for expensive dead ends
  const costWeight = decision.cost.total > 1.0 ? 0.1 : 0;

  // Boost waste for exploration that read many files but produced nothing
  const explorationPenalty =
    decision.type === 'exploration' &&
    decision.outcome === 'dead_end' &&
    decision.children.length > 5
      ? 0.15
      : 0;

  return Math.min(1.0, baseScore + costWeight + explorationPenalty);
}

// ── Pattern Detection ─────────────────────────────────────────

export function detectInsights(root: Decision): readonly Insight[] {
  const insights: Insight[] = [];
  let insightId = 0;

  const allDecisions = flattenDecisions(root);

  // 1. Retry loops: same tool called 3+ times by same agent
  const toolCounts = new Map<string, Decision[]>();
  for (const d of allDecisions) {
    if (d.type === 'tool_call' && d.tool) {
      const key = `${d.agentId}:${d.tool}`;
      const list = toolCounts.get(key) ?? [];
      list.push(d);
      toolCounts.set(key, list);
    }
  }
  for (const [key, decisions] of toolCounts) {
    const failures = decisions.filter(d => d.outcome === 'failure');
    if (failures.length >= 3) {
      const cost = failures.reduce((s, d) => s + d.cost.total, 0);
      const toolName = key.split(':')[1]!;
      insights.push(
        makeInsight(++insightId, 'warning', 'retry_loop',
          `Retry loop: ${toolName}`,
          `Agent retried ${toolName} ${failures.length} times before succeeding. Consider adding validation before the call.`,
          cost,
          failures.map(d => d.id),
          'Add pre-validation or error handling to avoid repeated failures.',
          {
            confidence: 0.9,
            evidence: [`${failures.length} consecutive failures of the same tool by the same agent`, `Total cost of failed attempts: $${cost.toFixed(2)}`],
            recommendation: {
              action: `Add a validation step before calling ${toolName}. Check prerequisites (env vars, file existence, permissions) before each attempt.`,
              type: 'workflow',
              effort: 'easy',
            },
          },
        ),
      );
    }
  }

  // 2. Dead-end exploration: agent explored many files/URLs with no useful outcome
  const deadEnds = allDecisions.filter(
    d => d.type === 'exploration' && d.outcome === 'dead_end' && d.cost.total > 0.10,
  );
  if (deadEnds.length > 0) {
    const cost = deadEnds.reduce((s, d) => s + d.cost.total, 0);
    insights.push(
      makeInsight(++insightId, 'warning', 'dead_end_exploration',
        `Dead-end exploration: $${cost.toFixed(2)} wasted`,
        `${deadEnds.length} exploration paths led nowhere. The agent searched broadly but the answers weren't in those locations.`,
        cost,
        deadEnds.map(d => d.id),
        'Narrow the search scope or provide better context to guide the agent.',
        {
          confidence: Math.min(0.95, 0.6 + deadEnds.length * 0.05),
          evidence: [`${deadEnds.length} explorations marked as dead_end`, `Each cost >$0.10 with no useful outcome`],
          recommendation: {
            action: 'Add specific file patterns or directory scopes to agent instructions. Use Glob/Grep before Read to narrow candidates.',
            type: 'prompt',
            effort: 'trivial',
          },
        },
      ),
    );
  }

  // 3. Redundant work: multiple agents doing similar tool calls
  const crossAgentTools = new Map<string, Decision[]>();
  for (const d of allDecisions) {
    if (d.tool) {
      const existing = crossAgentTools.get(d.tool) ?? [];
      existing.push(d);
      crossAgentTools.set(d.tool, existing);
    }
  }
  for (const [tool, decisions] of crossAgentTools) {
    const agents = new Set(decisions.map(d => d.agentId));
    if (agents.size >= 2 && decisions.length >= 4) {
      const cost = decisions.reduce((s, d) => s + d.cost.total, 0);
      insights.push(
        makeInsight(++insightId, 'info', 'redundant_work',
          `Overlapping work: ${tool} used by ${agents.size} agents`,
          `${agents.size} different agents called ${tool} a total of ${decisions.length} times. Some of this work may be redundant.`,
          cost * 0.3,
          decisions.map(d => d.id),
          'Consider sharing results between agents or narrowing each agent\'s scope.',
          {
            confidence: 0.5,
            evidence: [`${agents.size} agents used ${tool} independently`, `Cross-agent overlap detected (low confidence — may be intentional)`],
            recommendation: {
              action: `Share ${tool} results between agents via shared context, or assign ${tool} usage to a single dedicated agent.`,
              type: 'workflow',
              effort: 'moderate',
            },
          },
        ),
      );
    }
  }

  // 4. Delegation overhead: sub-agent cost vs parent context
  const delegations = allDecisions.filter(d => d.type === 'delegation');
  for (const d of delegations) {
    const childCost = sumTreeCost(d);
    if (childCost > 2.0 && d.outcome !== 'success') {
      insights.push(
        makeInsight(++insightId, 'critical', 'delegation_overhead',
          `Expensive delegation: ${d.agentName} cost $${childCost.toFixed(2)}`,
          `Sub-agent "${d.agentName}" was delegated a task costing $${childCost.toFixed(2)} but outcome was "${d.outcome}".`,
          childCost,
          [d.id],
          'Review whether this delegation was necessary or if the parent agent could have handled it directly.',
          {
            confidence: 0.85,
            evidence: [`Delegation cost $${childCost.toFixed(2)} with outcome "${d.outcome}"`, `Non-success outcome on expensive sub-agent is strong waste signal`],
            recommendation: {
              action: `Consider handling "${d.description}" in the parent agent instead of delegating, or add better scoping to reduce sub-agent cost.`,
              type: 'workflow',
              effort: 'moderate',
            },
          },
        ),
      );
    }
  }

  return insights;
}

// ── Agent Summaries ───────────────────────────────────────────

export function buildAgentSummaries(root: Decision): readonly AgentSummary[] {
  const agentMap = new Map<string, Decision[]>();

  for (const d of flattenDecisions(root)) {
    const list = agentMap.get(d.agentId) ?? [];
    list.push(d);
    agentMap.set(d.agentId, list);
  }

  return Array.from(agentMap.entries()).map(([agentId, decisions]) => {
    const first = decisions[0]!;
    const totalCost = decisions.reduce((s, d) => s + d.cost.total, 0);
    const wasteCost = decisions.reduce((s, d) => s + d.cost.total * d.wasteScore, 0);

    const topWaste: DecisionRef[] = decisions
      .filter(d => d.wasteScore > 0.3)
      .sort((a, b) => (b.cost.total * b.wasteScore) - (a.cost.total * a.wasteScore))
      .slice(0, 5)
      .map(d => ({
        decisionId: d.id,
        description: d.description,
        cost: d.cost.total,
        wasteScore: d.wasteScore,
        wasteReason: d.wasteReason,
      }));

    return {
      id: agentId,
      name: first.agentName,
      parentId: first.parentId,
      model: '',
      decisionCount: decisions.length,
      tokens: {
        input: decisions.reduce((s, d) => s + d.tokens.input, 0),
        output: decisions.reduce((s, d) => s + d.tokens.output, 0),
        cacheRead: decisions.reduce((s, d) => s + d.tokens.cacheRead, 0),
        cacheWrite: decisions.reduce((s, d) => s + d.tokens.cacheWrite, 0),
      },
      cost: {
        tokens: totalCost,
        tools: 0,
        total: totalCost,
      },
      wasteTotal: Math.round(wasteCost * 100) / 100,
      wastePercentage: totalCost > 0 ? wasteCost / totalCost : 0,
      topWasteDecisions: topWaste,
    };
  });
}

// ── Helpers ───────────────────────────────────────────────────

export function flattenDecisions(root: Decision): readonly Decision[] {
  const result: Decision[] = [root];
  for (const child of root.children) {
    result.push(...flattenDecisions(child));
  }
  return result;
}

function sumTreeCost(node: Decision): number {
  return node.cost.total + node.children.reduce((s, c) => s + sumTreeCost(c), 0);
}

interface InsightOpts {
  confidence?: number;
  evidence?: readonly string[];
  recommendation?: Partial<Recommendation>;
}

function makeInsight(
  id: number,
  severity: InsightSeverity,
  category: InsightCategory,
  title: string,
  description: string,
  cost: number,
  affectedDecisions: readonly string[],
  suggestion: string,
  opts: InsightOpts = {},
): Insight {
  const weeklySavings = Math.round(cost * 5 * 100) / 100; // assume ~5 similar sessions/week
  return {
    id: `insight-${id}`,
    severity,
    category,
    title,
    description,
    cost: Math.round(cost * 100) / 100,
    confidence: opts.confidence ?? 0.7,
    evidence: opts.evidence ?? [],
    affectedDecisions,
    suggestion,
    recommendation: {
      action: opts.recommendation?.action ?? suggestion,
      type: opts.recommendation?.type ?? 'workflow',
      projectedWeeklySavings: opts.recommendation?.projectedWeeklySavings ?? weeklySavings,
      effort: opts.recommendation?.effort ?? 'easy',
      applied: false,
    },
  };
}

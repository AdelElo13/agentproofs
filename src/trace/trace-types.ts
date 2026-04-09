/**
 * AgentTrace Core Types
 *
 * The data model centers on Decision nodes forming a tree.
 * Each decision tracks what an agent chose to do, what it cost,
 * and whether it contributed to the outcome.
 */

// ── Token & Cost ──────────────────────────────────────────────

export interface TokenUsage {
  readonly input: number;
  readonly output: number;
  readonly cacheRead: number;
  readonly cacheWrite: number;
}

export interface CostBreakdown {
  readonly tokens: number;
  readonly tools: number;
  readonly total: number;
}

// ── Model Pricing ─────────────────────────────────────────────

export interface ModelPricing {
  readonly model: string;
  readonly provider: string;
  readonly inputPerMillion: number;
  readonly outputPerMillion: number;
  readonly cacheReadPerMillion: number;
  readonly cacheWritePerMillion: number;
}

// ── Decision Tree ─────────────────────────────────────────────

export type DecisionType =
  | 'tool_call'      // Agent used a tool (Read, Write, Bash, etc.)
  | 'delegation'     // Agent spawned a sub-agent
  | 'reasoning'      // Internal reasoning / thinking
  | 'exploration'    // Reading files, searching — gathering info
  | 'generation';    // Producing output (code, text)

export type DecisionOutcome =
  | 'success'        // Contributed directly to the goal
  | 'failure'        // Failed and was not retried
  | 'partial'        // Partially useful
  | 'redundant'      // Duplicated work done elsewhere
  | 'dead_end';      // Explored but produced nothing useful

export interface Decision {
  readonly id: string;
  readonly parentId: string | null;
  readonly agentId: string;
  readonly agentName: string;
  readonly type: DecisionType;
  readonly tool: string | null;
  readonly description: string;
  readonly startedAt: number;       // epoch ms
  readonly endedAt: number;
  readonly tokens: TokenUsage;
  readonly cost: CostBreakdown;
  readonly outcome: DecisionOutcome;
  readonly wasteScore: number;      // 0.0 – 1.0
  readonly wasteReason: string | null;
  readonly children: readonly Decision[];
  readonly metadata: Readonly<Record<string, unknown>>;
}

// ── Trace (root container) ────────────────────────────────────

export interface Trace {
  readonly id: string;
  readonly sessionId: string;
  readonly project: string;
  readonly startedAt: number;
  readonly endedAt: number;
  readonly model: string;
  readonly provider: string;
  readonly tokens: TokenUsage;
  readonly cost: CostBreakdown;
  readonly wasteTotal: number;        // total $ identified as waste
  readonly wastePercentage: number;   // 0.0 – 1.0
  readonly decisionCount: number;
  readonly agentCount: number;
  readonly rootDecision: Decision;
  readonly agents: readonly AgentSummary[];
  readonly insights: readonly Insight[];
}

// ── Agent Summary ─────────────────────────────────────────────

export interface AgentSummary {
  readonly id: string;
  readonly name: string;
  readonly parentId: string | null;
  readonly model: string;
  readonly decisionCount: number;
  readonly tokens: TokenUsage;
  readonly cost: CostBreakdown;
  readonly wasteTotal: number;
  readonly wastePercentage: number;
  readonly topWasteDecisions: readonly DecisionRef[];
}

export interface DecisionRef {
  readonly decisionId: string;
  readonly description: string;
  readonly cost: number;
  readonly wasteScore: number;
  readonly wasteReason: string | null;
}

// ── Insights (actionable findings) ────────────────────────────

export type InsightSeverity = 'critical' | 'warning' | 'info';

export type InsightCategory =
  | 'cost_waste'
  | 'redundant_work'
  | 'scope_drift'
  | 'retry_loop'
  | 'dead_end_exploration'
  | 'delegation_overhead';

export interface Insight {
  readonly id: string;
  readonly severity: InsightSeverity;
  readonly category: InsightCategory;
  readonly title: string;
  readonly description: string;
  readonly cost: number;
  readonly confidence: number;           // 0.0 – 1.0, how confident we are this is real waste
  readonly evidence: readonly string[];  // specific observations backing the claim
  readonly affectedDecisions: readonly string[];
  readonly suggestion: string;
  readonly recommendation: Recommendation;
}

export interface Recommendation {
  readonly action: string;               // specific thing to change
  readonly type: 'config' | 'prompt' | 'workflow' | 'tool_choice';
  readonly projectedWeeklySavings: number;  // estimated $/week if applied
  readonly effort: 'trivial' | 'easy' | 'moderate';
  readonly applied: boolean;             // track if user marked as applied
}

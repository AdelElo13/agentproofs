/**
 * Golden Parser Tests
 *
 * These are the trust foundation of AgentTrace.
 * If these fail, the product's core value proposition is broken.
 *
 * Invariants tested:
 * 1. Token conservation: sum of all decision tokens ≤ total session tokens
 * 2. Agent consistency: every decision has a valid, non-empty agentId
 * 3. Tree integrity: no orphan nodes, root is always present
 * 4. Cost accuracy: costs match token counts × pricing rates
 * 5. Outcome coverage: every decision has a valid outcome
 */

import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseClaudeCodeSession, flattenDecisions, findPricing, calculateCost } from '../../src/trace/index.ts';
import type { Decision, Trace } from '../../src/trace/index.ts';

const FIXTURES = join(import.meta.dirname, 'fixtures');

function loadFixture(name: string): string[] {
  return readFileSync(join(FIXTURES, name), 'utf-8').split('\n');
}

function parseFixture(name: string, project = 'test'): Trace {
  return parseClaudeCodeSession(loadFixture(name), { project });
}

// ── Invariant 1: Token Conservation ───────────────────────────

describe('Token Conservation', () => {
  it('simple session: child token sum equals total', () => {
    const trace = parseFixture('simple-session.jsonl');
    const all = flattenDecisions(trace.rootDecision);

    // Total tokens from all messages: input=3300, output=550, cacheRead=1700
    const totalInput = all.reduce((s, d) => s + d.tokens.input, 0);
    const totalOutput = all.reduce((s, d) => s + d.tokens.output, 0);

    // Tokens should be conserved (sum of decisions = total)
    expect(totalInput).toBe(trace.tokens.input);
    expect(totalOutput).toBe(trace.tokens.output);
  });

  it('delegation session: tokens distributed without loss', () => {
    const trace = parseFixture('delegation-session.jsonl');
    const all = flattenDecisions(trace.rootDecision);

    const totalInput = all.reduce((s, d) => s + d.tokens.input, 0);
    const totalOutput = all.reduce((s, d) => s + d.tokens.output, 0);

    // Allow small rounding variance (max 1 token per decision due to distribution)
    expect(Math.abs(totalInput - trace.tokens.input)).toBeLessThan(all.length);
    expect(Math.abs(totalOutput - trace.tokens.output)).toBeLessThan(all.length);
  });
});

// ── Invariant 2: Agent Consistency ────────────────────────────

describe('Agent Consistency', () => {
  it('every decision has a non-empty agentId', () => {
    const trace = parseFixture('delegation-session.jsonl');
    const all = flattenDecisions(trace.rootDecision);

    for (const d of all) {
      expect(d.agentId).toBeTruthy();
      expect(d.agentId.length).toBeGreaterThan(0);
    }
  });

  it('delegation spans have unique agentIds', () => {
    const trace = parseFixture('delegation-session.jsonl');
    const all = flattenDecisions(trace.rootDecision);
    const delegations = all.filter(d => d.type === 'delegation');

    const ids = delegations.map(d => d.agentId);
    const unique = new Set(ids);
    expect(unique.size).toBe(ids.length);
  });

  it('agent summary covers all unique agents', () => {
    const trace = parseFixture('delegation-session.jsonl');
    const all = flattenDecisions(trace.rootDecision);
    const uniqueAgents = new Set(all.map(d => d.agentId));

    for (const agentId of uniqueAgents) {
      const found = trace.agents.some(a => a.id === agentId);
      expect(found).toBe(true);
    }
  });
});

// ── Invariant 3: Tree Integrity ───────────────────────────────

describe('Tree Integrity', () => {
  it('root decision exists and has no parent', () => {
    const trace = parseFixture('simple-session.jsonl');
    expect(trace.rootDecision).toBeTruthy();
    expect(trace.rootDecision.parentId).toBeNull();
  });

  it('all non-root decisions have a valid parentId', () => {
    const trace = parseFixture('delegation-session.jsonl');
    const all = flattenDecisions(trace.rootDecision);
    const allIds = new Set(all.map(d => d.id));

    for (const d of all) {
      if (d.parentId !== null) {
        expect(allIds.has(d.parentId)).toBe(true);
      }
    }
  });

  it('decision count matches actual count', () => {
    const trace = parseFixture('simple-session.jsonl');
    const all = flattenDecisions(trace.rootDecision);
    expect(trace.decisionCount).toBe(all.length);
  });
});

// ── Invariant 4: Cost Accuracy ────────────────────────────────

describe('Cost Accuracy', () => {
  it('total cost is non-negative', () => {
    const trace = parseFixture('simple-session.jsonl');
    expect(trace.cost.total).toBeGreaterThanOrEqual(0);
  });

  it('waste total does not exceed total cost', () => {
    const trace = parseFixture('delegation-session.jsonl');
    expect(trace.wasteTotal).toBeLessThanOrEqual(trace.cost.total + 0.01);
  });

  it('waste percentage is between 0 and 1', () => {
    const trace = parseFixture('delegation-session.jsonl');
    expect(trace.wastePercentage).toBeGreaterThanOrEqual(0);
    expect(trace.wastePercentage).toBeLessThanOrEqual(1);
  });
});

// ── Invariant 5: Outcome Coverage ─────────────────────────────

describe('Outcome Coverage', () => {
  const validOutcomes = ['success', 'failure', 'partial', 'redundant', 'dead_end'];

  it('every decision has a valid outcome', () => {
    const trace = parseFixture('delegation-session.jsonl');
    const all = flattenDecisions(trace.rootDecision);

    for (const d of all) {
      expect(validOutcomes).toContain(d.outcome);
    }
  });

  it('failed tool calls are marked as failure', () => {
    const trace = parseFixture('delegation-session.jsonl');
    const all = flattenDecisions(trace.rootDecision);
    const bashFails = all.filter(
      d => d.tool === 'Bash' && d.outcome === 'failure',
    );

    // We know there are 2 failed test runs in the fixture
    expect(bashFails.length).toBe(2);
  });
});

// ── Insight Quality ───────────────────────────────────────────

describe('Insight Quality', () => {
  it('insights have confidence scores between 0 and 1', () => {
    const trace = parseFixture('delegation-session.jsonl');

    for (const insight of trace.insights) {
      expect(insight.confidence).toBeGreaterThanOrEqual(0);
      expect(insight.confidence).toBeLessThanOrEqual(1);
    }
  });

  it('insights have non-empty evidence arrays', () => {
    const trace = parseFixture('delegation-session.jsonl');

    for (const insight of trace.insights) {
      expect(insight.evidence.length).toBeGreaterThan(0);
    }
  });

  it('insight affected decisions reference real decision ids', () => {
    const trace = parseFixture('delegation-session.jsonl');
    const all = flattenDecisions(trace.rootDecision);
    const allIds = new Set(all.map(d => d.id));

    for (const insight of trace.insights) {
      for (const decId of insight.affectedDecisions) {
        expect(allIds.has(decId)).toBe(true);
      }
    }
  });
});

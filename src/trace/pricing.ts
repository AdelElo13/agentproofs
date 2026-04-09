/**
 * Model pricing database.
 * Prices in USD per million tokens.
 */

import type { ModelPricing, TokenUsage, CostBreakdown } from './trace-types.js';

const PRICING_DB: readonly ModelPricing[] = [
  // Anthropic
  { model: 'claude-opus-4-6', provider: 'anthropic', inputPerMillion: 15, outputPerMillion: 75, cacheReadPerMillion: 1.5, cacheWritePerMillion: 18.75 },
  { model: 'claude-sonnet-4-6', provider: 'anthropic', inputPerMillion: 3, outputPerMillion: 15, cacheReadPerMillion: 0.3, cacheWritePerMillion: 3.75 },
  { model: 'claude-haiku-4-5', provider: 'anthropic', inputPerMillion: 0.8, outputPerMillion: 4, cacheReadPerMillion: 0.08, cacheWritePerMillion: 1 },
  // OpenAI
  { model: 'gpt-5.3', provider: 'openai', inputPerMillion: 2.5, outputPerMillion: 10, cacheReadPerMillion: 1.25, cacheWritePerMillion: 2.5 },
  { model: 'gpt-5.3-codex', provider: 'openai', inputPerMillion: 2.5, outputPerMillion: 10, cacheReadPerMillion: 1.25, cacheWritePerMillion: 2.5 },
  { model: 'o3', provider: 'openai', inputPerMillion: 10, outputPerMillion: 40, cacheReadPerMillion: 2.5, cacheWritePerMillion: 10 },
  // Google
  { model: 'gemini-2.5-pro', provider: 'google', inputPerMillion: 1.25, outputPerMillion: 10, cacheReadPerMillion: 0.315, cacheWritePerMillion: 4.5 },
  { model: 'gemini-2.5-flash', provider: 'google', inputPerMillion: 0.15, outputPerMillion: 0.6, cacheReadPerMillion: 0.0375, cacheWritePerMillion: 1 },
];

export function findPricing(model: string): ModelPricing | null {
  return PRICING_DB.find(p => model.startsWith(p.model)) ?? null;
}

export function calculateCost(tokens: TokenUsage, pricing: ModelPricing): CostBreakdown {
  const tokenCost =
    (tokens.input * pricing.inputPerMillion / 1_000_000) +
    (tokens.output * pricing.outputPerMillion / 1_000_000) +
    (tokens.cacheRead * pricing.cacheReadPerMillion / 1_000_000) +
    (tokens.cacheWrite * pricing.cacheWritePerMillion / 1_000_000);

  return {
    tokens: round(tokenCost),
    tools: 0,
    total: round(tokenCost),
  };
}

export function sumTokens(usages: readonly TokenUsage[]): TokenUsage {
  return usages.reduce(
    (acc, u) => ({
      input: acc.input + u.input,
      output: acc.output + u.output,
      cacheRead: acc.cacheRead + u.cacheRead,
      cacheWrite: acc.cacheWrite + u.cacheWrite,
    }),
    { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
  );
}

function round(n: number): number {
  return Math.round(n * 1_000_000) / 1_000_000;
}

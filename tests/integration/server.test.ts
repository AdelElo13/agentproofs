import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { tmpdir } from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { createMcpServer } from '../../src/server.ts';
import { daemonAppend, stopDaemon, type DaemonState } from '../../src/daemon.ts';
import { readAllEntries, verifyChain } from '../../src/chain.ts';
import { sha256 } from '../../src/crypto.ts';
import type { AgentproofsConfig } from '../../src/types.ts';

let tmpDir: string;
let config: AgentproofsConfig;
let daemon: DaemonState;

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), 'agentproofs-integration-'));
  config = {
    dataDir: tmpDir,
    agentId: 'integration-agent',
    userId: 'test-user',
    namespace: 'integration',
    logLevel: 'error',
    retentionDays: 365,
    segmentSize: 10000,
    segmentMaxAge: 86400,
    redactionLevel: 0,
    socketPath: join(tmpDir, 'test.sock'),
    httpPort: 0,
    keyStore: 'file',
    checkpointInterval: 0,
  };

  const result = await createMcpServer(config);
  daemon = result.daemon;
});

afterEach(async () => {
  await stopDaemon(daemon);
  await rm(tmpDir, { recursive: true });
});

describe('Integration: MCP Server', () => {
  it('creates server with valid daemon', () => {
    expect(daemon.chainId).toMatch(/^ch_/);
    expect(daemon.sessionId).toMatch(/^sess_/);
    expect(daemon.keyPair.keyId).toMatch(/^[0-9a-f]{16}$/);
  });

  it('logs proofs through daemon', async () => {
    const r1 = await daemonAppend(daemon, {
      event_type: 'tool_started',
      tool: 'Bash',
      input_hash: sha256('npm test'),
      output_hash: sha256(''),
      success: true,
      origin: 'hook',
      tool_invocation_id: 'inv_001',
    });

    const r2 = await daemonAppend(daemon, {
      event_type: 'tool_completed',
      tool: 'Bash',
      input_hash: sha256('npm test'),
      output_hash: sha256('all tests passed'),
      success: true,
      origin: 'hook',
      tool_invocation_id: 'inv_001',
      duration_ms: 1500,
    });

    expect(r1.sequence).toBe(1);
    expect(r2.sequence).toBe(2);

    const entries = await readAllEntries(tmpDir);
    expect(entries).toHaveLength(2);
    expect(entries[0].event_type).toBe('tool_started');
    expect(entries[1].event_type).toBe('tool_completed');
    expect(entries[1].tool_invocation_id).toBe('inv_001');
  });

  it('maintains valid chain through multiple operations', async () => {
    // Log a variety of events
    await daemonAppend(daemon, {
      event_type: 'session_started',
      success: true,
      origin: 'daemon',
      input_summary: 'Session started',
    });

    for (let i = 0; i < 5; i++) {
      await daemonAppend(daemon, {
        event_type: 'tool_completed',
        tool: `Tool${i}`,
        input_hash: sha256(`input-${i}`),
        output_hash: sha256(`output-${i}`),
        success: i !== 3, // one failure
        error_message: i === 3 ? 'Command failed' : undefined,
        origin: 'hook',
      });
    }

    await daemonAppend(daemon, {
      event_type: 'decision',
      input_summary: 'Chose REST over GraphQL',
      output_summary: 'Decision recorded',
      success: true,
      origin: 'manual',
      reason: 'Simpler for MVP',
      tags: ['architecture'],
    });

    await daemonAppend(daemon, {
      event_type: 'session_ended',
      success: true,
      origin: 'daemon',
    });

    // Verify the chain
    const keys = new Map([[daemon.keyPair.keyId, daemon.keyPair.publicKey]]);
    const result = await verifyChain(tmpDir, keys);
    expect(result.valid).toBe(true);
    expect(result.verified).toBe(8);

    // Verify all entries
    const entries = await readAllEntries(tmpDir);
    expect(entries).toHaveLength(8);
    expect(entries[0].event_type).toBe('session_started');
    expect(entries[7].event_type).toBe('session_ended');

    // Check the failed tool
    const failed = entries.find((e) => !e.action.success);
    expect(failed).toBeDefined();
    expect(failed!.action.error_message).toBe('Command failed');

    // Check the decision
    const decision = entries.find((e) => e.event_type === 'decision');
    expect(decision).toBeDefined();
    expect(decision!.action.input_summary).toBe('Chose REST over GraphQL');
    expect(decision!.context.reason).toBe('Simpler for MVP');
  });

  it('handles concurrent logging correctly', async () => {
    const promises = Array.from({ length: 20 }, (_, i) =>
      daemonAppend(daemon, {
        event_type: 'tool_completed',
        tool: `Concurrent${i}`,
        input_hash: sha256(`concurrent-${i}`),
        output_hash: sha256(`result-${i}`),
        success: true,
        origin: 'hook',
      }),
    );

    const results = await Promise.all(promises);
    const sequences = results.map((r) => r.sequence).sort((a, b) => a - b);

    // All 20 should have unique sequential numbers
    expect(sequences).toEqual(Array.from({ length: 20 }, (_, i) => i + 1));

    // Chain should be valid
    const keys = new Map([[daemon.keyPair.keyId, daemon.keyPair.publicKey]]);
    const verification = await verifyChain(tmpDir, keys);
    expect(verification.valid).toBe(true);
    expect(verification.verified).toBe(20);
  });
});

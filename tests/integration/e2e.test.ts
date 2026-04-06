/**
 * Full end-to-end test: simulates a real user session.
 *
 * 1. Init → keys + chain created
 * 2. Start daemon + socket server
 * 3. Log session_started
 * 4. Log tool_started + tool_completed pairs (via socket, like hooks would)
 * 5. Log a failed tool
 * 6. Log a decision
 * 7. Log session_ended
 * 8. Verify chain — must be valid
 * 9. Query by tool, by session, by event type, by success/failure
 * 10. Export as JSONL, JSON, CSV — all must produce correct output
 * 11. Export signed — signature must verify
 * 12. Stats must reflect what was logged
 * 13. Tamper with one entry — verify must fail
 * 14. Stop daemon cleanly
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { tmpdir } from 'node:os';
import { mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createConnection } from 'node:net';
import {
  createDaemon,
  daemonAppend,
  startSocketServer,
  stopDaemon,
  type DaemonState,
} from '../../src/daemon.ts';
import {
  readAllEntries,
  verifyChain,
} from '../../src/chain.ts';
import { queryProofs } from '../../src/query.ts';
import { exportProofs } from '../../src/export.ts';
import { sha256, verifySignature } from '../../src/crypto.ts';
import { getStats, getLatest, getChainStatus, getBySession } from '../../src/resources.ts';
import type { AgentproofsConfig, ProofEntry } from '../../src/types.ts';

let tmpDir: string;
let config: AgentproofsConfig;
let daemon: DaemonState;

beforeAll(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), 'agentproofs-e2e-'));
  config = {
    dataDir: tmpDir,
    agentId: 'claude-code',
    userId: 'adel',
    namespace: 'agentproofs',
    logLevel: 'error',
    retentionDays: 365,
    segmentSize: 10000,
    segmentMaxAge: 86400,
    redactionLevel: 0,
    socketPath: join(tmpDir, 'daemon.sock'),
    httpPort: 0,
    keyStore: 'file',
    checkpointInterval: 0,
  };

  daemon = await createDaemon(config);
  await startSocketServer(daemon);
});

afterAll(async () => {
  await stopDaemon(daemon);
  await rm(tmpDir, { recursive: true });
});

// Helper: send event via Unix socket (like a hook would)
function sendViaSocket(event: Record<string, unknown>): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(config.socketPath, () => {
      socket.write(JSON.stringify({ type: 'log', input: event }) + '\n');
      socket.on('data', (data) => {
        socket.end();
        resolve(JSON.parse(data.toString().trim()));
      });
    });
    socket.on('error', reject);
    setTimeout(() => { socket.end(); reject(new Error('socket timeout')); }, 5000);
  });
}

describe('End-to-End: Full Session Simulation', () => {

  // ── Phase 1: Log a realistic session ──

  it('step 1: daemon initialized with keys and chain', () => {
    expect(daemon.chainId).toMatch(/^ch_/);
    expect(daemon.sessionId).toMatch(/^sess_/);
    expect(daemon.keyPair.keyId).toMatch(/^[0-9a-f]{16}$/);
    expect(daemon.chainState.sequence).toBe(0);
  });

  it('step 2: log session_started', async () => {
    const result = await daemonAppend(daemon, {
      event_type: 'session_started',
      success: true,
      origin: 'daemon',
      input_summary: 'Session started by adel',
      output_summary: `Chain ${daemon.chainId}`,
    });
    expect(result.sequence).toBe(1);
    expect(result.proof_id).toMatch(/^ap_/);
  });

  it('step 3: log tool_started + tool_completed pair via daemon', async () => {
    const invocationId = 'inv_bash_001';

    const started = await daemonAppend(daemon, {
      event_type: 'tool_started',
      tool: 'Bash',
      tool_invocation_id: invocationId,
      input_hash: sha256('npm install'),
      output_hash: sha256(''),
      success: true,
      origin: 'hook',
      working_dir: '/Users/adel/agentproofs',
    });

    const completed = await daemonAppend(daemon, {
      event_type: 'tool_completed',
      tool: 'Bash',
      tool_invocation_id: invocationId,
      input_hash: sha256('npm install'),
      output_hash: sha256('added 47 packages'),
      success: true,
      duration_ms: 3200,
      origin: 'hook',
      working_dir: '/Users/adel/agentproofs',
    });

    expect(started.sequence).toBe(2);
    expect(completed.sequence).toBe(3);
  });

  it('step 4: log tool pair via socket (like a real hook)', async () => {
    const result = await sendViaSocket({
      event_type: 'tool_completed',
      tool: 'Edit',
      input_hash: sha256('edit src/index.ts'),
      output_hash: sha256('file updated'),
      success: true,
      duration_ms: 50,
      origin: 'hook',
      working_dir: '/Users/adel/agentproofs',
    });

    expect(result.proof_id).toMatch(/^ap_/);
    expect(result.sequence).toBe(4);
  });

  it('step 5: log a failed tool', async () => {
    const result = await daemonAppend(daemon, {
      event_type: 'tool_failed',
      tool: 'Bash',
      tool_invocation_id: 'inv_bash_fail',
      input_hash: sha256('rm -rf /'),
      output_hash: sha256('Permission denied'),
      success: false,
      error_message: 'Permission denied',
      duration_ms: 10,
      origin: 'hook',
    });
    expect(result.sequence).toBe(5);
  });

  it('step 6: log a decision', async () => {
    const result = await daemonAppend(daemon, {
      event_type: 'decision',
      input_summary: 'Chose Ed25519 over RSA for signing',
      output_summary: 'Decision recorded: Ed25519 is faster and produces smaller signatures',
      success: true,
      origin: 'manual',
      reason: 'Performance and key size advantages',
      tags: ['architecture', 'crypto'],
    });
    expect(result.sequence).toBe(6);
  });

  it('step 7: log more tool calls to build up the chain', async () => {
    const tools = ['Write', 'Read', 'Grep', 'Glob', 'Write'];
    for (let i = 0; i < tools.length; i++) {
      await daemonAppend(daemon, {
        event_type: 'tool_completed',
        tool: tools[i],
        input_hash: sha256(`input-${tools[i]}-${i}`),
        output_hash: sha256(`output-${tools[i]}-${i}`),
        success: true,
        duration_ms: 10 + i * 5,
        origin: 'hook',
        namespace: i < 3 ? 'agentproofs' : 'other-project',
      });
    }
    expect(daemon.chainState.sequence).toBe(11);
  });

  it('step 8: log session_ended', async () => {
    const result = await daemonAppend(daemon, {
      event_type: 'session_ended',
      success: true,
      origin: 'daemon',
      input_summary: 'Session ended normally',
    });
    expect(result.sequence).toBe(12);
  });

  // ── Phase 2: Verify everything ──

  it('step 9: verify chain — must be valid', async () => {
    const keys = new Map([[daemon.keyPair.keyId, daemon.keyPair.publicKey]]);
    const result = await verifyChain(tmpDir, keys);

    expect(result.valid).toBe(true);
    expect(result.verified).toBe(12);
    expect(result.total_proofs).toBe(12);
  });

  it('step 10: all entries have correct hash linkage', async () => {
    const entries = await readAllEntries(tmpDir);
    expect(entries).toHaveLength(12);

    // First entry links to genesis
    expect(entries[0].prev_hash).toBe('genesis');
    expect(entries[0].event_type).toBe('session_started');

    // Every subsequent entry links to previous
    for (let i = 1; i < entries.length; i++) {
      expect(entries[i].prev_hash).toBe(entries[i - 1].hash);
      expect(entries[i].sequence).toBe(i + 1);
    }

    // Last entry is session_ended
    expect(entries[11].event_type).toBe('session_ended');
  });

  it('step 11: all entries have valid signatures', async () => {
    const entries = await readAllEntries(tmpDir);
    for (const entry of entries) {
      const valid = verifySignature(entry.hash, entry.signature, daemon.keyPair.publicKey);
      expect(valid).toBe(true);
    }
  });

  // ── Phase 3: Query ──

  it('step 12: query by tool', async () => {
    const bashResult = await queryProofs(tmpDir, { tool: 'Bash' });
    expect(bashResult.total).toBe(3); // started + completed + failed

    const editResult = await queryProofs(tmpDir, { tool: 'Edit' });
    expect(editResult.total).toBe(1);

    const writeResult = await queryProofs(tmpDir, { tool: 'Write' });
    expect(writeResult.total).toBe(2);
  });

  it('step 13: query by event type', async () => {
    const decisions = await queryProofs(tmpDir, { event_type: 'decision' });
    expect(decisions.total).toBe(1);
    expect(decisions.results[0].action.input_summary).toBe('Chose Ed25519 over RSA for signing');

    const failed = await queryProofs(tmpDir, { event_type: 'tool_failed' });
    expect(failed.total).toBe(1);
    expect(failed.results[0].action.error_message).toBe('Permission denied');

    const sessions = await queryProofs(tmpDir, { event_type: 'session_started' });
    expect(sessions.total).toBe(1);
  });

  it('step 14: query by success/failure', async () => {
    const failures = await queryProofs(tmpDir, { success: false });
    expect(failures.total).toBe(1);
    expect(failures.results[0].action.tool).toBe('Bash');

    const successes = await queryProofs(tmpDir, { success: true });
    expect(successes.total).toBe(11);
  });

  it('step 15: query by namespace', async () => {
    const agentproofs = await queryProofs(tmpDir, { namespace: 'agentproofs' });
    expect(agentproofs.total).toBeGreaterThan(0);

    const other = await queryProofs(tmpDir, { namespace: 'other-project' });
    expect(other.total).toBe(2);
  });

  it('step 16: query by tags', async () => {
    const crypto = await queryProofs(tmpDir, { tags: ['crypto'] });
    expect(crypto.total).toBe(1);

    const arch = await queryProofs(tmpDir, { tags: ['architecture'] });
    expect(arch.total).toBe(1);

    const both = await queryProofs(tmpDir, { tags: ['architecture', 'crypto'] });
    expect(both.total).toBe(1);

    const none = await queryProofs(tmpDir, { tags: ['nonexistent'] });
    expect(none.total).toBe(0);
  });

  it('step 17: query pagination', async () => {
    const page1 = await queryProofs(tmpDir, { limit: 3, offset: 0, sort: 'asc' });
    expect(page1.results).toHaveLength(3);
    expect(page1.has_more).toBe(true);
    expect(page1.results[0].sequence).toBe(1);

    const page2 = await queryProofs(tmpDir, { limit: 3, offset: 3, sort: 'asc' });
    expect(page2.results).toHaveLength(3);
    expect(page2.results[0].sequence).toBe(4);
  });

  it('step 18: query by session', async () => {
    const bySession = await getBySession(config, daemon.sessionId);
    expect(bySession).toHaveLength(12); // all proofs from this session
  });

  // ── Phase 4: Resources ──

  it('step 19: chain status is correct', async () => {
    const status = await getChainStatus(config, daemon.chainId);
    expect(status.length).toBe(12);
    expect(status.health).toBe('healthy');
    expect(status.chain_id).toBe(daemon.chainId);
  });

  it('step 20: stats are correct', async () => {
    const stats = await getStats(config);
    expect(stats.total_proofs).toBe(12);
    expect(stats.by_event_type['tool_completed']).toBe(7);
    expect(stats.by_event_type['tool_started']).toBe(1);
    expect(stats.by_event_type['tool_failed']).toBe(1);
    expect(stats.by_event_type['decision']).toBe(1);
    expect(stats.by_event_type['session_started']).toBe(1);
    expect(stats.by_event_type['session_ended']).toBe(1);
    expect(stats.by_agent['claude-code']).toBe(12);
  });

  it('step 21: latest returns last N', async () => {
    const latest5 = await getLatest(config, 5);
    expect(latest5).toHaveLength(5);
    expect(latest5[4].sequence).toBe(12);
    expect(latest5[0].sequence).toBe(8);
  });

  // ── Phase 5: Export ──

  it('step 22: export as JSONL', async () => {
    const result = await exportProofs(tmpDir, { format: 'jsonl' });
    expect(result.total_proofs).toBe(12);

    const content = await readFile(result.file_path, 'utf-8');
    const lines = content.trim().split('\n');
    expect(lines).toHaveLength(12);

    // Each line is a valid proof entry
    for (const line of lines) {
      const entry = JSON.parse(line) as ProofEntry;
      expect(entry.id).toMatch(/^ap_/);
      expect(entry.hash).toMatch(/^[0-9a-f]{64}$/);
      expect(entry.signature).toBeTruthy();
    }
  });

  it('step 23: export as JSON', async () => {
    const result = await exportProofs(tmpDir, { format: 'json' });
    const content = await readFile(result.file_path, 'utf-8');
    const entries = JSON.parse(content) as ProofEntry[];
    expect(entries).toHaveLength(12);
  });

  it('step 24: export as CSV', async () => {
    const result = await exportProofs(tmpDir, { format: 'csv' });
    const content = await readFile(result.file_path, 'utf-8');
    const lines = content.trim().split('\n');
    expect(lines).toHaveLength(13); // header + 12 rows

    // Header has expected columns
    const header = lines[0];
    expect(header).toContain('id');
    expect(header).toContain('sequence');
    expect(header).toContain('timestamp');
    expect(header).toContain('event_type');
    expect(header).toContain('hash');
  });

  it('step 25: signed export has verifiable signature', async () => {
    const result = await exportProofs(tmpDir, {
      format: 'jsonl',
      sign_export: true,
    }, daemon.keyPair);

    expect(result.export_signature).toBeTruthy();

    // Verify the signature
    const isValid = verifySignature(
      result.export_hash,
      result.export_signature!,
      daemon.keyPair.publicKey,
    );
    expect(isValid).toBe(true);

    // Verify hash matches content
    const content = await readFile(result.file_path, 'utf-8');
    const computedHash = sha256(content);
    expect(computedHash).toBe(result.export_hash);
  });

  it('step 26: filtered export by namespace', async () => {
    const result = await exportProofs(tmpDir, {
      format: 'jsonl',
      namespace: 'other-project',
    });
    expect(result.total_proofs).toBe(2);
  });

  // ── Phase 6: Tamper Detection ──

  it('step 27: tampering with an entry breaks verification', async () => {
    const entries = await readAllEntries(tmpDir);

    // Tamper with entry 6 (the decision) — change the summary
    const segPath = join(tmpDir, 'segments', '000001.jsonl');
    const content = await readFile(segPath, 'utf-8');
    const lines = content.trim().split('\n');

    const original = JSON.parse(lines[5]) as ProofEntry;
    expect(original.event_type).toBe('decision');

    // Modify the action summary (without recomputing hash)
    const tampered = {
      ...original,
      action: {
        ...original.action,
        input_summary: 'TAMPERED: Chose RSA over Ed25519',
      },
    };
    lines[5] = JSON.stringify(tampered);
    await writeFile(segPath, lines.join('\n') + '\n');

    // Verify should now fail
    const keys = new Map([[daemon.keyPair.keyId, daemon.keyPair.publicKey]]);
    const result = await verifyChain(tmpDir, keys);

    expect(result.valid).toBe(false);
    expect(result.first_invalid_sequence).toBe(6);
    expect(result.first_invalid_reason).toContain('Hash mismatch');

    // Restore the original
    lines[5] = JSON.stringify(original);
    await writeFile(segPath, lines.join('\n') + '\n');

    // Verify should pass again
    const restored = await verifyChain(tmpDir, keys);
    expect(restored.valid).toBe(true);
  });

  it('step 28: deleting an entry breaks verification', async () => {
    const segPath = join(tmpDir, 'segments', '000001.jsonl');
    const content = await readFile(segPath, 'utf-8');
    const lines = content.trim().split('\n');

    // Delete entry 4
    const deleted = [...lines];
    deleted.splice(3, 1);
    await writeFile(segPath, deleted.join('\n') + '\n');

    const keys = new Map([[daemon.keyPair.keyId, daemon.keyPair.publicKey]]);
    const result = await verifyChain(tmpDir, keys);
    expect(result.valid).toBe(false);

    // Restore
    await writeFile(segPath, lines.join('\n') + '\n');
    const restored = await verifyChain(tmpDir, keys);
    expect(restored.valid).toBe(true);
  });

  it('step 29: inserting an entry breaks verification', async () => {
    const segPath = join(tmpDir, 'segments', '000001.jsonl');
    const content = await readFile(segPath, 'utf-8');
    const lines = content.trim().split('\n');

    // Insert a copy of entry 2 between entries 4 and 5
    const fake = JSON.parse(lines[1]);
    const inserted = [...lines];
    inserted.splice(4, 0, JSON.stringify(fake));
    await writeFile(segPath, inserted.join('\n') + '\n');

    const keys = new Map([[daemon.keyPair.keyId, daemon.keyPair.publicKey]]);
    const result = await verifyChain(tmpDir, keys);
    expect(result.valid).toBe(false);

    // Restore
    await writeFile(segPath, lines.join('\n') + '\n');
    const restored = await verifyChain(tmpDir, keys);
    expect(restored.valid).toBe(true);
  });

  it('step 30: reordering entries breaks verification', async () => {
    const segPath = join(tmpDir, 'segments', '000001.jsonl');
    const content = await readFile(segPath, 'utf-8');
    const lines = content.trim().split('\n');

    // Swap entries 3 and 4
    const reordered = [...lines];
    [reordered[2], reordered[3]] = [reordered[3], reordered[2]];
    await writeFile(segPath, reordered.join('\n') + '\n');

    const keys = new Map([[daemon.keyPair.keyId, daemon.keyPair.publicKey]]);
    const result = await verifyChain(tmpDir, keys);
    expect(result.valid).toBe(false);

    // Restore
    await writeFile(segPath, lines.join('\n') + '\n');
  });

  // ── Phase 7: Socket server status ──

  it('step 31: socket server returns correct status', async () => {
    const response = await new Promise<Record<string, unknown>>((resolve, reject) => {
      const socket = createConnection(config.socketPath, () => {
        socket.write(JSON.stringify({ type: 'status' }) + '\n');
        socket.on('data', (data) => {
          socket.end();
          resolve(JSON.parse(data.toString().trim()));
        });
      });
      socket.on('error', reject);
      setTimeout(() => { socket.end(); reject(new Error('timeout')); }, 5000);
    });

    expect(response.chain_id).toBe(daemon.chainId);
    expect(response.session_id).toBe(daemon.sessionId);
    expect(response.sequence).toBe(12);
    expect(response.running).toBe(true);
    expect(response.public_key).toMatch(/^ed25519:/);
  });

  // ── Phase 8: Final integrity check ──

  it('step 32: final chain verification after all operations', async () => {
    const keys = new Map([[daemon.keyPair.keyId, daemon.keyPair.publicKey]]);
    const result = await verifyChain(tmpDir, keys);

    expect(result.valid).toBe(true);
    expect(result.verified).toBe(12);
    expect(result.total_proofs).toBe(12);
    expect(result.key_transitions).toBe(0);
  });
});

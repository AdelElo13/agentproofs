import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { tmpdir } from 'node:os';
import { mkdtemp, rm, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { createConnection } from 'node:net';
import {
  createDaemon,
  daemonAppend,
  startSocketServer,
  stopDaemon,
  writePidFile,
  readPidFile,
} from '../src/daemon.ts';
import { readAllEntries } from '../src/chain.ts';
import { sha256 } from '../src/crypto.ts';
import type { AgentproofsConfig } from '../src/types.ts';

let tmpDir: string;
let config: AgentproofsConfig;

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), 'agentproofs-daemon-'));
  config = {
    dataDir: tmpDir,
    agentId: 'test-agent',
    userId: '',
    namespace: 'test',
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
});

afterEach(async () => {
  await rm(tmpDir, { recursive: true });
});

describe('Daemon', () => {
  it('creates daemon with chain state', async () => {
    const daemon = await createDaemon(config);
    expect(daemon.chainId).toMatch(/^ch_/);
    expect(daemon.sessionId).toMatch(/^sess_/);
    expect(daemon.chainState.sequence).toBe(0);
    expect(daemon.keyPair.keyId).toMatch(/^[0-9a-f]{16}$/);
  });

  it('persists chain_id across restarts', async () => {
    const daemon1 = await createDaemon(config);
    const daemon2 = await createDaemon(config);
    expect(daemon2.chainId).toBe(daemon1.chainId);
  });

  it('generates new session_id on restart', async () => {
    const daemon1 = await createDaemon(config);
    const daemon2 = await createDaemon(config);
    expect(daemon2.sessionId).not.toBe(daemon1.sessionId);
  });

  it('appends proofs sequentially', async () => {
    const daemon = await createDaemon(config);

    const r1 = await daemonAppend(daemon, {
      event_type: 'tool_completed',
      tool: 'Bash',
      input_hash: sha256('ls'),
      output_hash: sha256('files'),
      success: true,
      origin: 'hook',
    });

    const r2 = await daemonAppend(daemon, {
      event_type: 'tool_completed',
      tool: 'Edit',
      input_hash: sha256('edit'),
      output_hash: sha256('done'),
      success: true,
      origin: 'hook',
    });

    expect(r1.sequence).toBe(1);
    expect(r2.sequence).toBe(2);

    // Verify chain state updated
    expect(daemon.chainState.sequence).toBe(2);
    expect(daemon.chainState.lastHash).toBe(r2.hash);
  });

  it('handles concurrent appends safely', async () => {
    const daemon = await createDaemon(config);

    // Fire 10 appends concurrently
    const promises = Array.from({ length: 10 }, (_, i) =>
      daemonAppend(daemon, {
        event_type: 'tool_completed',
        tool: `Tool${i}`,
        input_hash: sha256(`input-${i}`),
        output_hash: sha256(`output-${i}`),
        success: true,
        origin: 'hook',
      }),
    );

    const results = await Promise.all(promises);

    // All should have unique sequences 1-10
    const sequences = results.map((r) => r.sequence).sort((a, b) => a - b);
    expect(sequences).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    // Verify chain integrity
    const entries = await readAllEntries(tmpDir);
    expect(entries).toHaveLength(10);

    // Hash chain should be valid
    for (let i = 1; i < entries.length; i++) {
      expect(entries[i].prev_hash).toBe(entries[i - 1].hash);
    }
  });

  it('updates chain state after append', async () => {
    const daemon = await createDaemon(config);
    expect(daemon.chainState.proofCount).toBe(0);

    await daemonAppend(daemon, {
      event_type: 'session_started',
      success: true,
      origin: 'daemon',
    });

    expect(daemon.chainState.proofCount).toBe(1);
    expect(daemon.chainState.sequence).toBe(1);
  });
});

describe('Socket Server', () => {
  it('starts and accepts connections', async () => {
    const daemon = await createDaemon(config);
    const server = await startSocketServer(daemon);

    // Connect and send ping
    const response = await new Promise<string>((resolve, reject) => {
      const socket = createConnection(config.socketPath, () => {
        socket.write(JSON.stringify({ type: 'ping' }) + '\n');
        socket.on('data', (data) => {
          socket.end();
          resolve(data.toString().trim());
        });
      });
      socket.on('error', reject);
      setTimeout(() => reject(new Error('timeout')), 3000);
    });

    const parsed = JSON.parse(response);
    expect(parsed.pong).toBe(true);

    await stopDaemon(daemon);
  });

  it('handles log messages via socket', async () => {
    const daemon = await createDaemon(config);
    await startSocketServer(daemon);

    const response = await new Promise<string>((resolve, reject) => {
      const socket = createConnection(config.socketPath, () => {
        socket.write(JSON.stringify({
          type: 'log',
          input: {
            event_type: 'tool_completed',
            tool: 'Bash',
            input_hash: sha256('socket-test'),
            output_hash: sha256('socket-result'),
            success: true,
            origin: 'hook',
          },
        }) + '\n');
        socket.on('data', (data) => {
          socket.end();
          resolve(data.toString().trim());
        });
      });
      socket.on('error', reject);
      setTimeout(() => reject(new Error('timeout')), 3000);
    });

    const parsed = JSON.parse(response);
    expect(parsed.proof_id).toMatch(/^ap_/);
    expect(parsed.sequence).toBe(1);

    // Verify entry was written
    const entries = await readAllEntries(tmpDir);
    expect(entries).toHaveLength(1);

    await stopDaemon(daemon);
  });

  it('returns status via socket', async () => {
    const daemon = await createDaemon(config);
    await startSocketServer(daemon);

    const response = await new Promise<string>((resolve, reject) => {
      const socket = createConnection(config.socketPath, () => {
        socket.write(JSON.stringify({ type: 'status' }) + '\n');
        socket.on('data', (data) => {
          socket.end();
          resolve(data.toString().trim());
        });
      });
      socket.on('error', reject);
      setTimeout(() => reject(new Error('timeout')), 3000);
    });

    const parsed = JSON.parse(response);
    expect(parsed.chain_id).toMatch(/^ch_/);
    expect(parsed.running).toBe(true);
    expect(parsed.public_key).toMatch(/^ed25519:/);

    await stopDaemon(daemon);
  });
});

describe('PID File', () => {
  it('writes and reads PID file', async () => {
    await writePidFile(tmpDir);
    const pid = await readPidFile(tmpDir);
    expect(pid).toBe(process.pid);
  });

  it('returns null for missing PID file', async () => {
    const pid = await readPidFile(join(tmpDir, 'nonexistent'));
    expect(pid).toBeNull();
  });
});

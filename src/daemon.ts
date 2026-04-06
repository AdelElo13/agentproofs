import { createServer, type Server } from 'node:net';
import { writeFile, unlink, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  initChain,
  readChainState,
  appendProof,
  type ChainState,
} from './chain.ts';
import { createProofEntry, toLogResult } from './proof.ts';
import {
  loadOrCreateKeyPair,
  generateChainId,
  generateSessionId,
  formatPublicKey,
} from './crypto.ts';
import type {
  AgentproofsConfig,
  KeyPair,
  ProofLogInput,
  ProofLogResult,
  ProofEntry,
} from './types.ts';

// ── Daemon State ──

export interface DaemonState {
  readonly config: AgentproofsConfig;
  readonly keyPair: KeyPair;
  readonly chainId: string;
  readonly sessionId: string;
  chainState: ChainState;
  readonly server: Server | null;
  running: boolean;
}

// ── Create Daemon ──

export async function createDaemon(config: AgentproofsConfig): Promise<DaemonState> {
  await initChain(config.dataDir);

  const keyDir = join(config.dataDir, 'keys');
  const keyPair = await loadOrCreateKeyPair(keyDir);

  // Load or create chain ID
  const chainIdPath = join(config.dataDir, 'chain_id');
  let chainId: string;
  try {
    chainId = (await readFile(chainIdPath, 'utf-8')).trim();
  } catch {
    chainId = generateChainId();
    await writeFile(chainIdPath, chainId, 'utf-8');
  }

  const sessionId = generateSessionId();
  const chainState = await readChainState(config.dataDir, chainId);

  return {
    config,
    keyPair,
    chainId,
    sessionId,
    chainState,
    server: null,
    running: false,
  };
}

// ── Append (Single Writer — serialized) ──

// Write lock: serializes all appends through a single promise chain
let writeLock: Promise<unknown> = Promise.resolve();

export function daemonAppend(
  daemon: DaemonState,
  input: ProofLogInput,
): Promise<ProofLogResult> {
  const resultPromise = writeLock.then(async (): Promise<ProofLogResult> => {
    const sequence = daemon.chainState.sequence + 1;
    const prevHash = daemon.chainState.lastHash;

    const entry = createProofEntry(
      input,
      daemon.config,
      daemon.chainId,
      sequence,
      prevHash,
      daemon.keyPair,
      daemon.sessionId,
    );

    await appendProof(daemon.config.dataDir, daemon.chainState.segmentId, entry);

    // Update in-memory state (controlled mutation of daemon state)
    (daemon.chainState as any) = {
      ...daemon.chainState,
      sequence: entry.sequence,
      lastHash: entry.hash,
      lastTimestamp: entry.timestamp,
      proofCount: daemon.chainState.proofCount + 1,
    };

    return toLogResult(entry);
  });

  // Chain the lock but swallow errors so next write isn't blocked by previous failure
  writeLock = resultPromise.catch(() => {});

  return resultPromise;
}

// ── Socket Server ──

export async function startSocketServer(daemon: DaemonState): Promise<Server> {
  const socketPath = daemon.config.socketPath;

  // Clean up stale socket
  try {
    await unlink(socketPath);
  } catch {
    // doesn't exist, fine
  }

  const server = createServer((socket) => {
    let buffer = '';

    socket.on('data', (data) => {
      buffer += data.toString();

      // Process complete messages (newline-delimited JSON)
      const lines = buffer.split('\n');
      buffer = lines.pop() ?? '';

      for (const line of lines) {
        if (!line.trim()) continue;
        handleMessage(daemon, line.trim())
          .then((response) => {
            socket.write(JSON.stringify(response) + '\n');
          })
          .catch((err) => {
            socket.write(JSON.stringify({ error: String(err) }) + '\n');
          });
      }
    });

    socket.on('error', () => {
      // Client disconnected, ignore
    });
  });

  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(socketPath, () => {
      (daemon as any).server = server;
      (daemon as any).running = true;
      resolve(server);
    });
  });
}

async function handleMessage(
  daemon: DaemonState,
  message: string,
): Promise<unknown> {
  const parsed = JSON.parse(message);

  switch (parsed.type) {
    case 'log':
      return daemonAppend(daemon, parsed.input as ProofLogInput);
    case 'status':
      return {
        chain_id: daemon.chainId,
        session_id: daemon.sessionId,
        sequence: daemon.chainState.sequence,
        last_hash: daemon.chainState.lastHash,
        public_key: formatPublicKey(daemon.keyPair.publicKey),
        running: daemon.running,
      };
    case 'ping':
      return { pong: true };
    default:
      return { error: `Unknown message type: ${parsed.type}` };
  }
}

// ── Stop Daemon ──

export async function stopDaemon(daemon: DaemonState): Promise<void> {
  daemon.running = false;

  if (daemon.server) {
    await new Promise<void>((resolve) => {
      daemon.server!.close(() => resolve());
    });
  }

  // Clean up socket
  try {
    await unlink(daemon.config.socketPath);
  } catch {
    // ignore
  }

  // Write PID file cleanup
  try {
    await unlink(join(daemon.config.dataDir, 'daemon.pid'));
  } catch {
    // ignore
  }
}

// ── PID File ──

export async function writePidFile(dataDir: string): Promise<void> {
  await writeFile(join(dataDir, 'daemon.pid'), String(process.pid), 'utf-8');
}

export async function readPidFile(dataDir: string): Promise<number | null> {
  try {
    const content = await readFile(join(dataDir, 'daemon.pid'), 'utf-8');
    return parseInt(content.trim(), 10);
  } catch {
    return null;
  }
}

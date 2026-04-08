import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { loadConfig } from './config.ts';
import { readAllEntries, verifyChain, initChain } from './chain.ts';
import { queryProofs } from './query.ts';
import { loadOrCreateKeyPair } from './crypto.ts';
import { listKeys, loadAllPublicKeys } from './keys.ts';
import { generateComplianceReport } from './compliance.ts';
import {
  listAnchors,
  createCheckpointFromChain,
  submitToRekor,
  saveAnchor,
} from './anchor.ts';
import type { AgentproofsConfig, QueryParams, EventType } from './types.ts';
import { EVENT_TYPES } from './types.ts';

// ── Response Helpers ──

function jsonResponse(res: ServerResponse, data: unknown, status = 200): void {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-cache',
  });
  res.end(body);
}

function errorResponse(res: ServerResponse, message: string, status = 500): void {
  jsonResponse(res, { error: message }, status);
}

// ── Dashboard HTML path ──

function getDashboardPath(): string {
  // Works both from source (src/) and dist (dist/)
  const srcDir = import.meta.dirname ?? resolve('.');
  // Try dashboard/ relative to project root
  const candidates = [
    resolve(srcDir, '..', 'dashboard', 'dashboard.html'),
    resolve(srcDir, '..', '..', 'dashboard', 'dashboard.html'),
    resolve('dashboard', 'dashboard.html'),
  ];
  return candidates[0];
}

// ── URL Parser ──

function parseUrl(url: string): { pathname: string; params: URLSearchParams } {
  const questionIdx = url.indexOf('?');
  if (questionIdx === -1) {
    return { pathname: url, params: new URLSearchParams() };
  }
  return {
    pathname: url.slice(0, questionIdx),
    params: new URLSearchParams(url.slice(questionIdx + 1)),
  };
}

// ── Route Handlers ──

async function handleGetDashboard(
  _req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  const dashboardPath = getDashboardPath();
  try {
    const html = await readFile(dashboardPath, 'utf-8');
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache',
    });
    res.end(html);
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Dashboard HTML not found. Expected at: ' + dashboardPath);
  }
}

async function handleGetProofs(
  config: AgentproofsConfig,
  params: URLSearchParams,
  res: ServerResponse,
): Promise<void> {
  const queryParams: QueryParams = {
    limit: parseInt(params.get('limit') ?? '50', 10),
    offset: parseInt(params.get('offset') ?? '0', 10),
    sort: 'desc',
  };

  const eventType = params.get('type');
  if (eventType && EVENT_TYPES.includes(eventType as EventType)) {
    (queryParams as Record<string, unknown>).event_type = eventType;
  }

  const agent = params.get('agent');
  if (agent) {
    (queryParams as Record<string, unknown>).agent_id = agent;
  }

  const fromDate = params.get('from_date');
  if (fromDate) {
    (queryParams as Record<string, unknown>).from_date = fromDate;
  }

  const toDate = params.get('to_date');
  if (toDate) {
    (queryParams as Record<string, unknown>).to_date = toDate;
  }

  const tool = params.get('tool');
  if (tool) {
    (queryParams as Record<string, unknown>).tool = tool;
  }

  const result = await queryProofs(config.dataDir, queryParams);
  jsonResponse(res, result);
}

async function handleVerify(
  config: AgentproofsConfig,
  res: ServerResponse,
): Promise<void> {
  const keyDir = join(config.dataDir, 'keys');
  const allPublicKeys = await loadAllPublicKeys(keyDir);

  const result = await verifyChain(config.dataDir, allPublicKeys, {
    verifySignatures: true,
  });

  jsonResponse(res, result);
}

async function handleCompliance(
  config: AgentproofsConfig,
  res: ServerResponse,
): Promise<void> {
  const report = await generateComplianceReport(config);
  jsonResponse(res, report);
}

async function handleGetAnchors(
  config: AgentproofsConfig,
  res: ServerResponse,
): Promise<void> {
  const anchors = await listAnchors(config.dataDir);
  jsonResponse(res, { anchors });
}

async function handleCreateAnchor(
  config: AgentproofsConfig,
  res: ServerResponse,
): Promise<void> {
  const keyDir = join(config.dataDir, 'keys');
  const keyPair = await loadOrCreateKeyPair(keyDir);

  // Load chain ID
  let chainId: string;
  try {
    chainId = (await readFile(join(config.dataDir, 'chain_id'), 'utf-8')).trim();
  } catch {
    errorResponse(res, 'No chain found. Run "npx agentproofs init" first.', 400);
    return;
  }

  const checkpoint = await createCheckpointFromChain(config.dataDir, chainId, keyPair);
  const anchor = await submitToRekor(checkpoint, keyPair);
  await saveAnchor(config.dataDir, anchor);

  jsonResponse(res, anchor);
}

async function handleGetKeys(
  config: AgentproofsConfig,
  res: ServerResponse,
): Promise<void> {
  const keyDir = join(config.dataDir, 'keys');
  const keyPair = await loadOrCreateKeyPair(keyDir);
  const keys = await listKeys(keyDir);

  jsonResponse(res, {
    current_key_id: keyPair.keyId,
    total_keys: keys.length,
    keys,
  });
}

// ── Server ──

export function createDashboardServer(
  config: AgentproofsConfig,
): ReturnType<typeof createServer> {
  const server = createServer(async (req, res) => {
    const method = req.method ?? 'GET';
    const { pathname, params } = parseUrl(req.url ?? '/');

    // CORS preflight
    if (method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      });
      res.end();
      return;
    }

    try {
      if (method === 'GET' && (pathname === '/' || pathname === '/dashboard')) {
        await handleGetDashboard(req, res);
      } else if (method === 'GET' && pathname === '/api/proofs') {
        await handleGetProofs(config, params, res);
      } else if (method === 'GET' && pathname === '/api/verify') {
        await handleVerify(config, res);
      } else if (method === 'GET' && pathname === '/api/compliance') {
        await handleCompliance(config, res);
      } else if (method === 'GET' && pathname === '/api/anchors') {
        await handleGetAnchors(config, res);
      } else if (method === 'POST' && pathname === '/api/anchor') {
        await handleCreateAnchor(config, res);
      } else if (method === 'GET' && pathname === '/api/keys') {
        await handleGetKeys(config, res);
      } else {
        errorResponse(res, 'Not found', 404);
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : String(err);
      errorResponse(res, message, 500);
    }
  });

  return server;
}

export async function startDashboardServer(port = 3300): Promise<void> {
  const config = loadConfig();

  // Ensure data dir exists
  await initChain(config.dataDir);

  const server = createDashboardServer(config);

  server.listen(port, '127.0.0.1', () => {
    const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
    const cyan = (s: string) => `\x1b[36m${s}\x1b[0m`;
    const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;

    console.log('');
    console.log(bold('AgentProofs Dashboard'));
    console.log('');
    console.log(`  ${cyan('Local:')}   http://127.0.0.1:${port}/`);
    console.log(`  ${dim('Data:')}    ${config.dataDir}`);
    console.log('');
    console.log(dim('Press Ctrl+C to stop'));
    console.log('');
  });
}

// ── Direct execution ──

const isDirectRun = process.argv[1] &&
  (process.argv[1].endsWith('dashboard-server.ts') ||
   process.argv[1].endsWith('dashboard-server.js'));

if (isDirectRun) {
  const port = parseInt(process.env.AGENTPROOFS_DASHBOARD_PORT ?? '3300', 10);
  startDashboardServer(port).catch((err) => {
    console.error('Failed to start dashboard:', err.message);
    process.exit(1);
  });
}

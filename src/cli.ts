import { resolve, join } from 'node:path';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { loadConfig } from './config.ts';
import {
  readAllEntries,
  readChainState,
  verifyChain,
  initChain,
} from './chain.ts';
import { queryProofs } from './query.ts';
import { exportProofs } from './export.ts';
import { auditChain } from './verifier.ts';
import {
  loadOrCreateKeyPair,
  formatPublicKey,
  generateChainId,
} from './crypto.ts';
import { getStats } from './resources.ts';
import { generateComplianceReport, formatReportAsMarkdown } from './compliance.ts';
import type { AgentproofsConfig, EventType, QueryParams } from './types.ts';
import { EVENT_TYPES } from './types.ts';

// ── Helpers ──

function bold(s: string): string { return `\x1b[1m${s}\x1b[0m`; }
function green(s: string): string { return `\x1b[32m${s}\x1b[0m`; }
function red(s: string): string { return `\x1b[31m${s}\x1b[0m`; }
function yellow(s: string): string { return `\x1b[33m${s}\x1b[0m`; }
function dim(s: string): string { return `\x1b[2m${s}\x1b[0m`; }

function formatTimestamp(ts: string): string {
  return ts.replace('T', ' ').replace(/\.\d+Z$/, '');
}

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max - 1) + '\u2026' : s;
}

// ── Commands ──

async function cmdServe(config: AgentproofsConfig): Promise<void> {
  const { main } = await import('./index.ts');
  await main();
}

async function cmdVerify(config: AgentproofsConfig, args: string[]): Promise<void> {
  const keyDir = join(config.dataDir, 'keys');
  const keyPair = await loadOrCreateKeyPair(keyDir);
  const keys = new Map([[keyPair.keyId, keyPair.publicKey]]);

  let fromSequence: number | undefined;
  let toSequence: number | undefined;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--from' && args[i + 1]) fromSequence = parseInt(args[++i], 10);
    if (args[i] === '--to' && args[i + 1]) toSequence = parseInt(args[++i], 10);
  }

  const result = await verifyChain(config.dataDir, keys, {
    fromSequence,
    toSequence,
    verifySignatures: true,
  });

  if (result.valid) {
    console.log(green('\u2713') + ` Chain valid: ${bold(String(result.verified))} proofs verified`);
    console.log(`  Trust level: L0 (local, key integrity assumed)`);
    if (result.key_transitions > 0) {
      console.log(`  Key transitions: ${result.key_transitions}`);
    }
    console.log(`  No tampering detected.`);
  } else {
    console.log(red('\u2717') + ` Chain INVALID`);
    console.log(`  First invalid at sequence: ${result.first_invalid_sequence}`);
    console.log(`  Reason: ${result.first_invalid_reason}`);
    console.log(`  Verified before failure: ${result.verified}`);
    process.exitCode = 1;
  }
}

async function cmdStats(config: AgentproofsConfig): Promise<void> {
  const stats = await getStats(config);

  if (stats.total_proofs === 0) {
    console.log(dim('No proofs recorded yet.'));
    return;
  }

  console.log(bold(`Chain Statistics`));
  console.log(`  Total proofs: ${bold(String(stats.total_proofs))}`);
  console.log('');

  if (Object.keys(stats.by_event_type).length > 0) {
    console.log(bold('  By event type:'));
    for (const [type, count] of Object.entries(stats.by_event_type).sort((a, b) => b[1] - a[1])) {
      console.log(`    ${type.padEnd(24)} ${count}`);
    }
    console.log('');
  }

  if (Object.keys(stats.by_tool).length > 0) {
    console.log(bold('  By tool:'));
    for (const [tool, count] of Object.entries(stats.by_tool).sort((a, b) => b[1] - a[1])) {
      console.log(`    ${tool.padEnd(24)} ${count}`);
    }
    console.log('');
  }

  if (Object.keys(stats.by_agent).length > 0) {
    console.log(bold('  By agent:'));
    for (const [agent, count] of Object.entries(stats.by_agent).sort((a, b) => b[1] - a[1])) {
      console.log(`    ${agent.padEnd(24)} ${count}`);
    }
    console.log('');
  }

  if (Object.keys(stats.by_namespace).length > 0) {
    console.log(bold('  By namespace:'));
    for (const [ns, count] of Object.entries(stats.by_namespace).sort((a, b) => b[1] - a[1])) {
      console.log(`    ${ns.padEnd(24)} ${count}`);
    }
  }
}

async function cmdTail(config: AgentproofsConfig, args: string[]): Promise<void> {
  let count = 20;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '-n' && args[i + 1]) count = parseInt(args[++i], 10);
  }

  const entries = await readAllEntries(config.dataDir);
  const tail = entries.slice(-count);

  if (tail.length === 0) {
    console.log(dim('No proofs recorded yet.'));
    return;
  }

  for (const entry of tail) {
    const status = entry.action.success ? green('\u2713') : red('\u2717');
    const tool = entry.action.tool ? ` ${entry.action.tool}` : '';
    const summary = entry.action.input_summary ? dim(` "${truncate(entry.action.input_summary, 40)}"`) : '';
    const dur = entry.action.duration_ms ? dim(` ${entry.action.duration_ms}ms`) : '';

    console.log(
      `${dim(String(entry.sequence).padStart(6))} ${status} ${formatTimestamp(entry.timestamp)} ` +
      `${yellow(entry.event_type)}${tool}${summary}${dur}`
    );
  }
}

async function cmdQuery(config: AgentproofsConfig, args: string[]): Promise<void> {
  const params: Record<string, any> = { sort: 'desc', limit: 50 };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const next = args[i + 1];
    if (arg === '--tool' && next) { params.tool = next; i++; }
    else if (arg === '--agent' && next) { params.agent_id = next; i++; }
    else if (arg === '--session' && next) { params.session_id = next; i++; }
    else if (arg === '--trace' && next) { params.trace_id = next; i++; }
    else if (arg === '--type' && next) { params.event_type = next; i++; }
    else if (arg === '--namespace' && next) { params.namespace = next; i++; }
    else if (arg === '--from' && next) { params.from_date = next; i++; }
    else if (arg === '--to' && next) { params.to_date = next; i++; }
    else if (arg === '--success') { params.success = true; }
    else if (arg === '--failed') { params.success = false; }
    else if (arg === '--limit' && next) { params.limit = parseInt(next, 10); i++; }
    else if (arg === '--asc') { params.sort = 'asc'; }
  }

  const result = await queryProofs(config.dataDir, params as QueryParams);

  if (result.total === 0) {
    console.log(dim('No matching proofs found.'));
    return;
  }

  console.log(dim(`Showing ${result.results.length} of ${result.total} proofs\n`));

  for (const entry of result.results) {
    const status = entry.action.success ? green('\u2713') : red('\u2717');
    const tool = entry.action.tool ? ` ${entry.action.tool}` : '';
    const summary = entry.action.input_summary ? dim(` "${truncate(entry.action.input_summary, 40)}"`) : '';

    console.log(
      `${dim(String(entry.sequence).padStart(6))} ${status} ${formatTimestamp(entry.timestamp)} ` +
      `${yellow(entry.event_type)}${tool}${summary}`
    );
  }

  if (result.has_more) {
    console.log(dim(`\n... ${result.total - result.results.length} more proofs (use --limit to see more)`));
  }
}

async function cmdExport(config: AgentproofsConfig, args: string[]): Promise<void> {
  let format: 'jsonl' | 'json' | 'csv' = 'jsonl';
  let signExport = false;
  let namespace: string | undefined;
  let fromDate: string | undefined;
  let toDate: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const next = args[i + 1];
    if (arg === '--format' && next) { format = next as any; i++; }
    else if (arg === '--sign') { signExport = true; }
    else if (arg === '--namespace' && next) { namespace = next; i++; }
    else if (arg === '--from' && next) { fromDate = next; i++; }
    else if (arg === '--to' && next) { toDate = next; i++; }
  }

  const keyDir = join(config.dataDir, 'keys');
  const keyPair = signExport ? await loadOrCreateKeyPair(keyDir) : undefined;

  const result = await exportProofs(config.dataDir, {
    format,
    from_date: fromDate,
    to_date: toDate,
    namespace,
    sign_export: signExport,
  }, keyPair);

  console.log(green('\u2713') + ` Exported ${bold(String(result.total_proofs))} proofs`);
  console.log(`  Format: ${format}`);
  console.log(`  File: ${result.file_path}`);
  console.log(`  Hash: ${dim(result.export_hash)}`);
  if (result.export_signature) {
    console.log(`  Signed: ${green('yes')}`);
  }
}

async function cmdPubkey(config: AgentproofsConfig): Promise<void> {
  const keyDir = join(config.dataDir, 'keys');
  const keyPair = await loadOrCreateKeyPair(keyDir);
  console.log(formatPublicKey(keyPair.publicKey));
}

async function cmdKeys(config: AgentproofsConfig): Promise<void> {
  const keyDir = join(config.dataDir, 'keys');
  const keyPair = await loadOrCreateKeyPair(keyDir);
  console.log(bold('Current key:'));
  console.log(`  Key ID:     ${keyPair.keyId}`);
  console.log(`  Public key: ${formatPublicKey(keyPair.publicKey)}`);
}

async function cmdShow(config: AgentproofsConfig, args: string[]): Promise<void> {
  const proofId = args[0];
  if (!proofId) {
    console.error('Usage: agentproofs show <proof_id>');
    process.exitCode = 1;
    return;
  }

  const result = await queryProofs(config.dataDir, { proof_id: proofId, limit: 1 });
  if (result.total === 0) {
    console.log(dim(`No proof found with ID: ${proofId}`));
    return;
  }

  console.log(JSON.stringify(result.results[0], null, 2));
}

async function cmdInit(config: AgentproofsConfig): Promise<void> {
  await initChain(config.dataDir);
  const keyDir = join(config.dataDir, 'keys');
  const keyPair = await loadOrCreateKeyPair(keyDir);

  // Generate chain_id if not exists
  const chainIdPath = join(config.dataDir, 'chain_id');
  try {
    await readFile(chainIdPath, 'utf-8');
  } catch {
    await writeFile(chainIdPath, generateChainId(), 'utf-8');
  }

  console.log(green('\u2713') + ' agentproofs initialized');
  console.log(`  Data dir:   ${config.dataDir}`);
  console.log(`  Key ID:     ${keyPair.keyId}`);
  console.log(`  Public key: ${formatPublicKey(keyPair.publicKey)}`);
  console.log('');

  // Offer to install hooks
  console.log(bold('To install Claude Code hooks:'));
  console.log(`  npx agentproofs install-hooks`);
}

async function cmdInstallHooks(config: AgentproofsConfig): Promise<void> {
  const claudeDir = join(process.env.HOME ?? '~', '.claude');
  const settingsPath = join(claudeDir, 'settings.json');

  let settings: any = {};
  try {
    settings = JSON.parse(await readFile(settingsPath, 'utf-8'));
  } catch {
    // No settings file yet
  }

  if (!settings.hooks) settings.hooks = {};

  // Resolve hook template paths
  const templateDir = resolve(import.meta.dirname ?? '.', '..', 'templates', 'hooks');

  const preHook = {
    type: 'command' as const,
    command: `node ${join(templateDir, 'agentproofs-pre.js')}`,
  };
  const postHook = {
    type: 'command' as const,
    command: `node ${join(templateDir, 'agentproofs-post.js')}`,
  };
  const stopHook = {
    type: 'command' as const,
    command: `node ${join(templateDir, 'agentproofs-stop.js')}`,
  };

  // Add hooks if not already present
  if (!settings.hooks.PreToolUse) settings.hooks.PreToolUse = [];
  if (!settings.hooks.PostToolUse) settings.hooks.PostToolUse = [];
  if (!settings.hooks.Stop) settings.hooks.Stop = [];

  const hasPreHook = settings.hooks.PreToolUse.some(
    (h: any) => h.command?.includes('agentproofs-pre'),
  );
  const hasPostHook = settings.hooks.PostToolUse.some(
    (h: any) => h.command?.includes('agentproofs-post'),
  );
  const hasStopHook = settings.hooks.Stop.some(
    (h: any) => h.command?.includes('agentproofs-stop'),
  );

  let installed = 0;

  if (!hasPreHook) {
    settings.hooks.PreToolUse.push(preHook);
    installed++;
  }
  if (!hasPostHook) {
    settings.hooks.PostToolUse.push(postHook);
    installed++;
  }
  if (!hasStopHook) {
    settings.hooks.Stop.push(stopHook);
    installed++;
  }

  if (installed === 0) {
    console.log(dim('Hooks already installed.'));
    return;
  }

  await mkdir(claudeDir, { recursive: true });
  await writeFile(settingsPath, JSON.stringify(settings, null, 2), 'utf-8');

  console.log(green('\u2713') + ` Installed ${installed} hook(s) in ${settingsPath}`);
  console.log('  - PreToolUse: tool_started capture');
  console.log('  - PostToolUse: tool_completed/failed capture');
  console.log('  - Stop: session_ended capture');
  console.log('');
  console.log(dim('Restart Claude Code for hooks to take effect.'));
}

async function cmdSegments(config: AgentproofsConfig): Promise<void> {
  const state = await readChainState(config.dataDir, '');

  console.log(bold('Segments:'));
  console.log(`  Current segment: ${state.segmentId}`);
  console.log(`  Total proofs:    ${state.proofCount}`);
  console.log(`  Last sequence:   ${state.sequence}`);
  console.log(`  Last hash:       ${dim(state.lastHash)}`);
}

async function cmdSync(config: AgentproofsConfig, args: string[]): Promise<void> {
  let target = '';
  let token = '';

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--to' && args[i + 1]) target = args[++i];
    if (args[i] === '--token' && args[i + 1]) token = args[++i];
  }

  if (!target) {
    console.error('Usage: npx agentproofs sync --to <url> --token <api-token>');
    console.error('Example: npx agentproofs sync --to https://agentproofs.io --token ap_abc123...');
    process.exitCode = 1;
    return;
  }

  if (!token) {
    console.error('Missing --token. Create one at your dashboard settings.');
    process.exitCode = 1;
    return;
  }

  // Read all entries
  const entries = await readAllEntries(config.dataDir);
  if (entries.length === 0) {
    console.log(dim('No proofs to sync.'));
    return;
  }

  console.log(dim(`Syncing ${entries.length} proofs to ${target}...`));

  // Send as JSONL
  const body = entries.map((e) => JSON.stringify(e)).join('\n');
  const syncUrl = target.replace(/\/$/, '') + '/api/chain/sync';

  try {
    const response = await fetch(syncUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/jsonl',
      },
      body,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: response.statusText }));
      console.error(red('\u2717') + ` Sync failed: ${(error as any).error ?? response.statusText}`);
      process.exitCode = 1;
      return;
    }

    const result = await response.json() as { proofs: number; agent_id: string };
    console.log(green('\u2713') + ` Synced ${bold(String(result.proofs))} proofs`);
    console.log(`  Agent: ${result.agent_id}`);
    console.log(`  Target: ${target}`);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(red('\u2717') + ` Sync failed: ${msg}`);
    process.exitCode = 1;
  }
}

async function cmdAudit(config: AgentproofsConfig, args: string[]): Promise<void> {
  const filePath = args[0];
  if (!filePath) {
    console.error('Usage: agentproofs audit <export.jsonl>');
    process.exitCode = 1;
    return;
  }

  const keyDir = join(config.dataDir, 'keys');
  const keyPair = await loadOrCreateKeyPair(keyDir);
  const keys = new Map([[keyPair.keyId, keyPair.publicKey]]);

  const resolved = resolve(filePath);
  const report = await auditChain(resolved, keys, keyPair);

  if (report.chain_valid) {
    console.log(green('\u2713') + ` Audit PASSED: ${bold(String(report.total_proofs))} proofs verified`);
  } else {
    console.log(red('\u2717') + ` Audit FAILED`);
  }

  console.log(`  Chain valid:       ${report.chain_valid ? green('yes') : red('no')}`);
  console.log(`  Signatures valid:  ${report.signatures_valid ? green('yes') : red('no')}`);
  console.log(`  Timestamps mono:   ${report.timestamps_monotonic ? green('yes') : red('no')}`);
  console.log(`  Sequences mono:    ${report.sequences_monotonic ? green('yes') : red('no')}`);
  console.log(`  First proof:       ${report.first_proof_time}`);
  console.log(`  Last proof:        ${report.last_proof_time}`);
  console.log(`  Verified at:       ${report.verified_at}`);

  if (report.errors.length > 0) {
    console.log('');
    console.log(bold(`  Errors (${report.errors.length}):`));
    for (const err of report.errors) {
      console.log(`    ${red('seq ' + String(err.sequence))} [${err.type}] ${err.message}`);
    }
  }

  console.log(`  Verifier sig:      ${dim(report.verifier_signature.slice(0, 32))}...`);

  if (!report.chain_valid) {
    process.exitCode = 1;
  }
}

async function cmdComplianceReport(config: AgentproofsConfig, args: string[]): Promise<void> {
  let format: 'json' | 'markdown' = 'json';
  let outputPath: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const next = args[i + 1];
    if (arg === '--format' && next) {
      format = next as 'json' | 'markdown';
      i++;
    } else if (arg === '--output' && next) {
      outputPath = next;
      i++;
    }
  }

  const report = await generateComplianceReport(config);

  const output = format === 'markdown'
    ? formatReportAsMarkdown(report)
    : JSON.stringify(report, null, 2);

  if (outputPath) {
    await writeFile(resolve(outputPath), output, 'utf-8');
    console.log(green('\u2713') + ` Compliance report written to ${outputPath}`);
    console.log(`  Format: ${format}`);
    console.log(`  Proofs analyzed: ${report.system_overview.total_proofs}`);
    console.log(`  Chain valid: ${report.verification_status.chain_integrity_valid ? green('yes') : red('no')}`);
  } else {
    console.log(output);
  }
}

function printHelp(): void {
  console.log(`
${bold('agentproofs')} — Signed, hash-chained proof logs for AI agent actions

${bold('USAGE')}
  npx agentproofs [command] [options]

${bold('COMMANDS')}
  ${bold('(default)')}          Start MCP server (stdio transport)
  ${bold('init')}               Initialize data directory and keys
  ${bold('install-hooks')}      Install Claude Code auto-capture hooks
  ${bold('verify')}             Verify chain integrity
  ${bold('audit')} <file>        Audit a JSONL chain export (stateless)
  ${bold('stats')}              Show chain statistics
  ${bold('tail')}               Show latest proofs
  ${bold('query')}              Search proofs
  ${bold('show')} <id>          Show single proof detail
  ${bold('export')}             Export proofs for audit
  ${bold('pubkey')}             Print public key
  ${bold('keys')}               List all keys
  ${bold('segments')}           List chain segments
  ${bold('sync')}               Sync chain to agentproofs.io
  ${bold('compliance-report')}  Generate EU AI Act Article 12 compliance report

${bold('COMPLIANCE REPORT OPTIONS')}
  --format <fmt>       json or markdown (default: json)
  --output <file>      Write to file instead of stdout

${bold('VERIFY OPTIONS')}
  --from <seq>         Start verification from sequence
  --to <seq>           End verification at sequence

${bold('TAIL OPTIONS')}
  -n <count>           Number of entries (default: 20)

${bold('QUERY OPTIONS')}
  --tool <name>        Filter by tool name
  --agent <id>         Filter by agent
  --session <id>       Filter by session
  --trace <id>         Filter by trace
  --type <event_type>  Filter by event type
  --namespace <ns>     Filter by namespace
  --from <date>        Start date (ISO)
  --to <date>          End date (ISO)
  --success            Only successful
  --failed             Only failed
  --limit <n>          Max results (default: 50)
  --asc                Sort ascending

${bold('EXPORT OPTIONS')}
  --format <fmt>       jsonl, json, or csv (default: jsonl)
  --sign               Sign the export file
  --namespace <ns>     Filter by namespace
  --from <date>        Start date
  --to <date>          End date

${bold('EXAMPLES')}
  npx agentproofs init
  npx agentproofs install-hooks
  npx agentproofs verify
  npx agentproofs tail -n 10
  npx agentproofs query --tool Bash --from 2026-04-01
  npx agentproofs export --sign --format csv
  npx agentproofs pubkey
`);
}

// ── Main CLI Entry ──

export async function cli(argv: string[]): Promise<void> {
  const command = argv[0];
  const args = argv.slice(1);
  const config = loadConfig();

  if (command === '--help' || command === '-h' || command === 'help') {
    printHelp();
    return;
  }

  // Ensure data dir exists for all commands
  if (command !== 'init') {
    await initChain(config.dataDir);
  }

  switch (command) {
    case undefined:
    case 'serve':
      await cmdServe(config);
      break;
    case 'init':
      await cmdInit(config);
      break;
    case 'install-hooks':
      await cmdInstallHooks(config);
      break;
    case 'verify':
      await cmdVerify(config, args);
      break;
    case 'audit':
      await cmdAudit(config, args);
      break;
    case 'stats':
      await cmdStats(config);
      break;
    case 'tail':
      await cmdTail(config, args);
      break;
    case 'query':
      await cmdQuery(config, args);
      break;
    case 'show':
      await cmdShow(config, args);
      break;
    case 'export':
      await cmdExport(config, args);
      break;
    case 'pubkey':
      await cmdPubkey(config);
      break;
    case 'keys':
      await cmdKeys(config);
      break;
    case 'segments':
      await cmdSegments(config);
      break;
    case 'sync':
      await cmdSync(config, args);
      break;
    case 'compliance-report':
      await cmdComplianceReport(config, args);
      break;
    default:
      console.error(`Unknown command: ${command}`);
      console.error('Run "npx agentproofs --help" for usage.');
      process.exitCode = 1;
  }
}

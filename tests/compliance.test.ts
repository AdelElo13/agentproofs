import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { tmpdir } from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { initChain, appendProof } from '../src/chain.ts';
import { createProofEntry } from '../src/proof.ts';
import { generateKeyPair, generateChainId, sha256, saveKeyPair } from '../src/crypto.ts';
import {
  generateComplianceReport,
  formatReportAsMarkdown,
} from '../src/compliance.ts';
import type { AgentproofsConfig, KeyPair, EventType } from '../src/types.ts';

let tmpDir: string;
let kp: KeyPair;
let chainId: string;
let config: AgentproofsConfig;

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), 'agentproofs-compliance-'));
  kp = generateKeyPair();
  chainId = generateChainId();
  config = {
    dataDir: tmpDir,
    agentId: 'test-agent',
    userId: '',
    namespace: 'default',
    logLevel: 'error',
    retentionDays: 365,
    segmentSize: 10000,
    segmentMaxAge: 86400,
    redactionLevel: 0,
    socketPath: '',
    httpPort: 0,
    keyStore: 'file',
    checkpointInterval: 0,
  };
  await initChain(tmpDir);
  await saveKeyPair(join(tmpDir, 'keys'), kp);
});

afterEach(async () => {
  await rm(tmpDir, { recursive: true });
});

async function seed(
  count: number,
  overrides: Record<string, unknown> = {},
): Promise<void> {
  let prevHash = 'genesis';
  for (let i = 1; i <= count; i++) {
    const entry = createProofEntry(
      {
        event_type: (overrides.event_type as EventType) ?? 'tool_completed',
        tool: (overrides.tool as string) ?? (i % 2 === 0 ? 'Edit' : 'Bash'),
        tool_invocation_id: overrides.tool_invocation_id as string | undefined,
        input_hash: sha256(`in-${i}`),
        output_hash: sha256(`out-${i}`),
        success: (overrides.success as boolean) ?? true,
        origin: 'hook',
      },
      config,
      chainId,
      i,
      prevHash,
      kp,
      'sess_test',
    );
    await appendProof(tmpDir, '000001', entry);
    prevHash = entry.hash;
  }
}

async function seedMixed(): Promise<void> {
  const events: Array<{ event_type: EventType; tool?: string; success: boolean; tool_invocation_id?: string }> = [
    { event_type: 'session_started', success: true },
    { event_type: 'tool_started', tool: 'Bash', success: true, tool_invocation_id: 'inv_1' },
    { event_type: 'tool_completed', tool: 'Bash', success: true, tool_invocation_id: 'inv_1' },
    { event_type: 'tool_started', tool: 'Edit', success: true, tool_invocation_id: 'inv_2' },
    { event_type: 'tool_failed', tool: 'Edit', success: false, tool_invocation_id: 'inv_2' },
    { event_type: 'tool_started', tool: 'Read', success: true, tool_invocation_id: 'inv_3' },
    { event_type: 'tool_denied', tool: 'Read', success: false, tool_invocation_id: 'inv_3' },
    { event_type: 'policy_violation', success: false },
    { event_type: 'error', success: false },
    { event_type: 'session_ended', success: true },
  ];

  let prevHash = 'genesis';
  for (let i = 0; i < events.length; i++) {
    const ev = events[i];
    const entry = createProofEntry(
      {
        event_type: ev.event_type,
        tool: ev.tool,
        tool_invocation_id: ev.tool_invocation_id,
        input_hash: sha256(`in-${i}`),
        output_hash: sha256(`out-${i}`),
        success: ev.success,
        origin: 'hook',
      },
      config,
      chainId,
      i + 1,
      prevHash,
      kp,
      'sess_test',
    );
    await appendProof(tmpDir, '000001', entry);
    prevHash = entry.hash;
  }
}

describe('Compliance Report Generation', () => {
  it('generates report for empty chain', async () => {
    const report = await generateComplianceReport(config);

    expect(report.report_version).toBe('1.0');
    expect(report.framework).toBe('EU AI Act Article 12');
    expect(report.system_overview.total_proofs).toBe(0);
    expect(report.system_overview.agent_id).toBe('test-agent');
    expect(report.system_overview.chain_creation_date).toBeNull();
    expect(report.verification_status.chain_integrity_valid).toBe(true);
    expect(report.audit_trail_coverage.coverage_percentage).toBe(100);
    expect(report.risk_indicators.policy_violations).toBe(0);
  });

  it('generates report with proofs', async () => {
    await seed(10);
    const report = await generateComplianceReport(config);

    expect(report.system_overview.total_proofs).toBe(10);
    expect(report.system_overview.chain_creation_date).toBeTruthy();
    expect(report.system_overview.public_key_fingerprint).toBe(kp.keyId);
    expect(report.event_summary.total_events).toBe(10);
    expect(report.event_summary.by_event_type['tool_completed']).toBe(10);
    expect(report.verification_status.chain_integrity_valid).toBe(true);
    expect(report.verification_status.total_verified).toBe(10);
  });

  it('computes data retention fields', async () => {
    await seed(5);
    const report = await generateComplianceReport(config);

    expect(report.data_retention.configured_retention_days).toBe(365);
    expect(report.data_retention.oldest_proof_date).toBeTruthy();
    expect(report.data_retention.newest_proof_date).toBeTruthy();
    expect(report.data_retention.article_19_compliant).toBe(true);
    expect(report.data_retention.article_19_notes).toContain('365 days');
  });

  it('flags non-compliant retention', async () => {
    const shortRetentionConfig = { ...config, retentionDays: 30 };
    await seed(3);
    const report = await generateComplianceReport(shortRetentionConfig);

    expect(report.data_retention.article_19_compliant).toBe(false);
    expect(report.data_retention.article_19_notes).toContain('Consider increasing');
  });

  it('reports privacy controls at redaction level 0', async () => {
    const report = await generateComplianceReport(config);

    expect(report.privacy_controls.configured_redaction_level).toBe(0);
    expect(report.privacy_controls.redaction_level_description).toContain('No redaction');
    expect(report.privacy_controls.data_hashed.length).toBeGreaterThan(0);
    expect(report.privacy_controls.data_stored_plaintext.length).toBeGreaterThan(0);
  });

  it('reports privacy controls at higher redaction levels', async () => {
    const r2Config = { ...config, redactionLevel: 2 as const };
    const report = await generateComplianceReport(r2Config);

    expect(report.privacy_controls.configured_redaction_level).toBe(2);
    expect(report.privacy_controls.data_stored_plaintext.length).toBeLessThan(4);
  });

  it('reports key management', async () => {
    const report = await generateComplianceReport(config);

    expect(report.key_management.current_key_fingerprint).toBe(kp.keyId);
    expect(report.key_management.key_algorithm).toBe('Ed25519 (EdDSA)');
    expect(report.key_management.total_keys).toBeGreaterThanOrEqual(1);
    expect(report.key_management.rotation_history.length).toBeGreaterThanOrEqual(1);
    expect(
      report.key_management.rotation_history.some((k) => k.is_current),
    ).toBe(true);
  });

  it('computes audit trail coverage with complete pairs', async () => {
    await seedMixed();
    const report = await generateComplianceReport(config);

    // 3 tool_started, all have matching completions
    expect(report.audit_trail_coverage.total_tool_starts).toBe(3);
    expect(report.audit_trail_coverage.orphaned_starts).toBe(0);
    expect(report.audit_trail_coverage.coverage_percentage).toBe(100);
  });

  it('detects orphaned starts', async () => {
    // Seed a tool_started without a matching completion
    let prevHash = 'genesis';
    const startEntry = createProofEntry(
      {
        event_type: 'tool_started',
        tool: 'Bash',
        tool_invocation_id: 'inv_orphan',
        input_hash: sha256('in'),
        output_hash: sha256('out'),
        success: true,
        origin: 'hook',
      },
      config,
      chainId,
      1,
      prevHash,
      kp,
      'sess_test',
    );
    await appendProof(tmpDir, '000001', startEntry);

    const report = await generateComplianceReport(config);

    expect(report.audit_trail_coverage.total_tool_starts).toBe(1);
    expect(report.audit_trail_coverage.orphaned_starts).toBe(1);
    expect(report.audit_trail_coverage.coverage_percentage).toBe(0);
  });

  it('detects risk indicators', async () => {
    await seedMixed();
    const report = await generateComplianceReport(config);

    expect(report.risk_indicators.policy_violations).toBe(1);
    expect(report.risk_indicators.errors).toBe(1);
    expect(report.risk_indicators.tool_denials).toBe(1);
    expect(report.risk_indicators.failed_actions).toBeGreaterThan(0);
    expect(report.risk_indicators.unusual_patterns).toContainEqual(
      expect.stringContaining('policy violation'),
    );
  });

  it('flags high failure rate', async () => {
    // All failures
    await seed(4, { success: false });
    const report = await generateComplianceReport(config);

    expect(report.risk_indicators.failed_actions).toBe(4);
    expect(report.risk_indicators.unusual_patterns).toContainEqual(
      expect.stringContaining('High failure rate'),
    );
  });

  it('reports no unusual patterns for healthy chain', async () => {
    await seed(10);
    const report = await generateComplianceReport(config);

    expect(report.risk_indicators.unusual_patterns).toHaveLength(0);
    expect(report.risk_indicators.failed_verifications).toBe(0);
  });
});

describe('Markdown Formatting', () => {
  it('formats empty report as markdown', async () => {
    const report = await generateComplianceReport(config);
    const md = formatReportAsMarkdown(report);

    expect(md).toContain('# EU AI Act Article 12');
    expect(md).toContain('## 1. System Overview');
    expect(md).toContain('## 2. Event Summary');
    expect(md).toContain('## 3. Verification Status');
    expect(md).toContain('## 4. Data Retention');
    expect(md).toContain('## 5. Privacy Controls');
    expect(md).toContain('## 6. Key Management');
    expect(md).toContain('## 7. Audit Trail Coverage');
    expect(md).toContain('## 8. Risk Indicators');
    expect(md).toContain('test-agent');
  });

  it('formats report with data as markdown', async () => {
    await seedMixed();
    const report = await generateComplianceReport(config);
    const md = formatReportAsMarkdown(report);

    // Should contain event type breakdown
    expect(md).toContain('tool_started');
    expect(md).toContain('tool_completed');
    expect(md).toContain('policy_violation');

    // Should contain anomalies section if present
    expect(md).toContain('Policy Violations');
    expect(md).toContain('PASS');
  });

  it('includes anomalies in markdown when chain has issues', async () => {
    await seedMixed();
    const report = await generateComplianceReport(config);
    const md = formatReportAsMarkdown(report);

    // Risk indicators with unusual patterns
    expect(md).toContain('Unusual Patterns');
    expect(md).toContain('policy violation');
  });
});

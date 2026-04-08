import { join } from 'node:path';
import { readAllEntries, verifyChain } from './chain.ts';
import { loadOrCreateKeyPair, formatPublicKey, computeKeyId } from './crypto.ts';
import { listKeys, loadAllPublicKeys } from './keys.ts';
import { findOrphanedStarts } from './recovery.ts';
import type {
  ProofEntry,
  AgentproofsConfig,
  VerificationResult,
  RedactionLevel,
} from './types.ts';

// ── Report Types ──

export interface ComplianceReportSystemOverview {
  readonly agent_id: string;
  readonly public_key_fingerprint: string;
  readonly chain_creation_date: string | null;
  readonly total_proofs: number;
  readonly report_generated_at: string;
}

export interface ComplianceReportEventSummary {
  readonly by_event_type: Readonly<Record<string, number>>;
  readonly total_events: number;
}

export interface ComplianceReportVerificationStatus {
  readonly chain_integrity_valid: boolean;
  readonly total_verified: number;
  readonly signature_validity: boolean;
  readonly anomalies: readonly string[];
  readonly key_transitions: number;
  readonly checkpoint_status: string;
}

export interface ComplianceReportDataRetention {
  readonly configured_retention_days: number;
  readonly oldest_proof_date: string | null;
  readonly newest_proof_date: string | null;
  readonly chain_span_days: number;
  readonly article_19_compliant: boolean;
  readonly article_19_notes: string;
}

export interface ComplianceReportPrivacyControls {
  readonly configured_redaction_level: RedactionLevel;
  readonly redaction_level_description: string;
  readonly data_hashed: readonly string[];
  readonly data_stored_plaintext: readonly string[];
  readonly data_redactable: readonly string[];
}

export interface ComplianceReportKeyManagement {
  readonly current_key_fingerprint: string;
  readonly key_algorithm: string;
  readonly total_keys: number;
  readonly rotation_history: readonly { readonly key_id: string; readonly is_current: boolean }[];
}

export interface ComplianceReportAuditTrailCoverage {
  readonly total_tool_starts: number;
  readonly total_tool_completions: number;
  readonly orphaned_starts: number;
  readonly coverage_percentage: number;
}

export interface ComplianceReportRiskIndicators {
  readonly policy_violations: number;
  readonly failed_verifications: number;
  readonly failed_actions: number;
  readonly tool_denials: number;
  readonly errors: number;
  readonly unusual_patterns: readonly string[];
}

export interface ComplianceReport {
  readonly report_version: '1.0';
  readonly framework: 'EU AI Act Article 12';
  readonly system_overview: ComplianceReportSystemOverview;
  readonly event_summary: ComplianceReportEventSummary;
  readonly verification_status: ComplianceReportVerificationStatus;
  readonly data_retention: ComplianceReportDataRetention;
  readonly privacy_controls: ComplianceReportPrivacyControls;
  readonly key_management: ComplianceReportKeyManagement;
  readonly audit_trail_coverage: ComplianceReportAuditTrailCoverage;
  readonly risk_indicators: ComplianceReportRiskIndicators;
}

// ── Redaction Level Descriptions ──

const REDACTION_DESCRIPTIONS: Record<RedactionLevel, string> = {
  0: 'No redaction — full input/output summaries stored',
  1: 'Light redaction — sensitive fields masked',
  2: 'Medium redaction — only hashes and metadata retained',
  3: 'Maximum redaction — only cryptographic proofs, no content',
};

// ── Report Generation ──

export async function generateComplianceReport(
  config: AgentproofsConfig,
): Promise<ComplianceReport> {
  const keyDir = join(config.dataDir, 'keys');
  const keyPair = await loadOrCreateKeyPair(keyDir);
  const allPublicKeys = await loadAllPublicKeys(keyDir);
  const entries = await readAllEntries(config.dataDir);

  // Verification
  const verification = await verifyChain(config.dataDir, allPublicKeys, {
    verifySignatures: true,
  });

  // Key management
  const keyList = await listKeys(keyDir);

  // Build report sections
  const systemOverview = buildSystemOverview(config, keyPair.keyId, entries);
  const eventSummary = buildEventSummary(entries);
  const verificationStatus = buildVerificationStatus(verification, entries);
  const dataRetention = buildDataRetention(config, entries);
  const privacyControls = buildPrivacyControls(config);
  const keyManagement = buildKeyManagement(keyPair.keyId, keyList);
  const auditTrailCoverage = buildAuditTrailCoverage(entries);
  const riskIndicators = buildRiskIndicators(entries, verification);

  return {
    report_version: '1.0',
    framework: 'EU AI Act Article 12',
    system_overview: systemOverview,
    event_summary: eventSummary,
    verification_status: verificationStatus,
    data_retention: dataRetention,
    privacy_controls: privacyControls,
    key_management: keyManagement,
    audit_trail_coverage: auditTrailCoverage,
    risk_indicators: riskIndicators,
  };
}

// ── Section Builders ──

function buildSystemOverview(
  config: AgentproofsConfig,
  keyId: string,
  entries: readonly ProofEntry[],
): ComplianceReportSystemOverview {
  const creationDate = entries.length > 0 ? entries[0].timestamp : null;

  return {
    agent_id: config.agentId,
    public_key_fingerprint: keyId,
    chain_creation_date: creationDate,
    total_proofs: entries.length,
    report_generated_at: new Date().toISOString(),
  };
}

function buildEventSummary(
  entries: readonly ProofEntry[],
): ComplianceReportEventSummary {
  const byEventType: Record<string, number> = {};

  for (const entry of entries) {
    byEventType[entry.event_type] = (byEventType[entry.event_type] ?? 0) + 1;
  }

  return {
    by_event_type: byEventType,
    total_events: entries.length,
  };
}

function buildVerificationStatus(
  verification: VerificationResult,
  entries: readonly ProofEntry[],
): ComplianceReportVerificationStatus {
  const anomalies: string[] = [];

  // Check for timestamp regressions
  for (let i = 1; i < entries.length; i++) {
    if (entries[i].timestamp < entries[i - 1].timestamp) {
      anomalies.push(`Timestamp regression at sequence ${entries[i].sequence}`);
    }
  }

  // Check for sequence gaps
  for (let i = 1; i < entries.length; i++) {
    if (entries[i].sequence !== entries[i - 1].sequence + 1) {
      anomalies.push(
        `Sequence gap: ${entries[i - 1].sequence} -> ${entries[i].sequence}`,
      );
    }
  }

  if (!verification.valid && verification.first_invalid_reason) {
    anomalies.push(`Chain integrity failure: ${verification.first_invalid_reason}`);
  }

  return {
    chain_integrity_valid: verification.valid,
    total_verified: verification.verified,
    signature_validity: verification.valid,
    anomalies,
    key_transitions: verification.key_transitions,
    checkpoint_status: verification.checkpoint_status,
  };
}

function buildDataRetention(
  config: AgentproofsConfig,
  entries: readonly ProofEntry[],
): ComplianceReportDataRetention {
  const oldestDate = entries.length > 0 ? entries[0].timestamp : null;
  const newestDate = entries.length > 0 ? entries[entries.length - 1].timestamp : null;

  let chainSpanDays = 0;
  if (oldestDate && newestDate) {
    const diffMs = new Date(newestDate).getTime() - new Date(oldestDate).getTime();
    chainSpanDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24));
  }

  // Article 19 requires logs to be kept for at least the duration the AI system is on the market
  // plus 10 years for high-risk systems. A configured retention policy satisfying this is compliant.
  const article19Compliant = config.retentionDays >= 365;
  const article19Notes = article19Compliant
    ? `Retention configured for ${config.retentionDays} days. Meets minimum logging duration requirements.`
    : `Retention configured for ${config.retentionDays} days. Consider increasing to at least 365 days for Article 19 compliance.`;

  return {
    configured_retention_days: config.retentionDays,
    oldest_proof_date: oldestDate,
    newest_proof_date: newestDate,
    chain_span_days: chainSpanDays,
    article_19_compliant: article19Compliant,
    article_19_notes: article19Notes,
  };
}

function buildPrivacyControls(
  config: AgentproofsConfig,
): ComplianceReportPrivacyControls {
  return {
    configured_redaction_level: config.redactionLevel,
    redaction_level_description: REDACTION_DESCRIPTIONS[config.redactionLevel],
    data_hashed: [
      'action.input_hash (SHA-256 of tool input)',
      'action.output_hash (SHA-256 of tool output)',
      'proof.hash (SHA-256 of canonical entry)',
    ],
    data_stored_plaintext: config.redactionLevel === 0
      ? [
          'action.input_summary (human-readable description)',
          'action.output_summary (human-readable description)',
          'context.reason (action rationale)',
          'context.working_dir (file system path)',
        ]
      : config.redactionLevel === 1
        ? [
            'context.reason (action rationale)',
            'event_type and tool name',
          ]
        : [
            'event_type and tool name',
          ],
    data_redactable: [
      'action.input_summary',
      'action.output_summary',
      'context.working_dir',
      'context.reason',
    ],
  };
}

function buildKeyManagement(
  currentKeyId: string,
  keyList: ReadonlyArray<{ keyId: string; isCurrent: boolean }>,
): ComplianceReportKeyManagement {
  return {
    current_key_fingerprint: currentKeyId,
    key_algorithm: 'Ed25519 (EdDSA)',
    total_keys: keyList.length,
    rotation_history: keyList.map((k) => ({
      key_id: k.keyId,
      is_current: k.isCurrent,
    })),
  };
}

function buildAuditTrailCoverage(
  entries: readonly ProofEntry[],
): ComplianceReportAuditTrailCoverage {
  const orphans = findOrphanedStarts(entries);

  const totalStarts = entries.filter(
    (e) => e.event_type === 'tool_started',
  ).length;
  const totalCompletions = entries.filter(
    (e) =>
      e.event_type === 'tool_completed' ||
      e.event_type === 'tool_failed' ||
      e.event_type === 'tool_denied',
  ).length;

  const coveragePercentage =
    totalStarts === 0
      ? 100
      : Math.round(((totalStarts - orphans.length) / totalStarts) * 10000) / 100;

  return {
    total_tool_starts: totalStarts,
    total_tool_completions: totalCompletions,
    orphaned_starts: orphans.length,
    coverage_percentage: coveragePercentage,
  };
}

function buildRiskIndicators(
  entries: readonly ProofEntry[],
  verification: VerificationResult,
): ComplianceReportRiskIndicators {
  const policyViolations = entries.filter(
    (e) => e.event_type === 'policy_violation',
  ).length;
  const failedActions = entries.filter(
    (e) => !e.action.success,
  ).length;
  const toolDenials = entries.filter(
    (e) => e.event_type === 'tool_denied',
  ).length;
  const errors = entries.filter(
    (e) => e.event_type === 'error',
  ).length;

  const unusualPatterns: string[] = [];

  // High failure rate
  if (entries.length > 0) {
    const failureRate = failedActions / entries.length;
    if (failureRate > 0.5) {
      unusualPatterns.push(
        `High failure rate: ${(failureRate * 100).toFixed(1)}% of actions failed`,
      );
    }
  }

  // High denial rate
  if (entries.length > 0 && toolDenials / entries.length > 0.2) {
    unusualPatterns.push(
      `High tool denial rate: ${toolDenials} denials out of ${entries.length} events`,
    );
  }

  // Policy violations present
  if (policyViolations > 0) {
    unusualPatterns.push(
      `${policyViolations} policy violation(s) recorded`,
    );
  }

  // Chain integrity failure
  if (!verification.valid) {
    unusualPatterns.push(
      `Chain integrity compromised at sequence ${verification.first_invalid_sequence}`,
    );
  }

  return {
    policy_violations: policyViolations,
    failed_verifications: verification.valid ? 0 : 1,
    failed_actions: failedActions,
    tool_denials: toolDenials,
    errors,
    unusual_patterns: unusualPatterns,
  };
}

// ── Markdown Formatting ──

export function formatReportAsMarkdown(report: ComplianceReport): string {
  const lines: string[] = [];

  lines.push('# EU AI Act Article 12 — Compliance Report');
  lines.push('');
  lines.push(`**Framework:** ${report.framework}`);
  lines.push(`**Report Version:** ${report.report_version}`);
  lines.push(`**Generated:** ${report.system_overview.report_generated_at}`);
  lines.push('');

  // System Overview
  lines.push('## 1. System Overview');
  lines.push('');
  lines.push(`| Field | Value |`);
  lines.push(`|-------|-------|`);
  lines.push(`| Agent ID | \`${report.system_overview.agent_id}\` |`);
  lines.push(`| Public Key Fingerprint | \`${report.system_overview.public_key_fingerprint}\` |`);
  lines.push(`| Chain Created | ${report.system_overview.chain_creation_date ?? 'N/A'} |`);
  lines.push(`| Total Proofs | ${report.system_overview.total_proofs} |`);
  lines.push('');

  // Event Summary
  lines.push('## 2. Event Summary');
  lines.push('');
  lines.push(`Total events: **${report.event_summary.total_events}**`);
  lines.push('');
  if (Object.keys(report.event_summary.by_event_type).length > 0) {
    lines.push('| Event Type | Count |');
    lines.push('|------------|-------|');
    const sorted = Object.entries(report.event_summary.by_event_type)
      .sort(([, a], [, b]) => b - a);
    for (const [type, count] of sorted) {
      lines.push(`| ${type} | ${count} |`);
    }
    lines.push('');
  }

  // Verification Status
  lines.push('## 3. Verification Status');
  lines.push('');
  const integrityIcon = report.verification_status.chain_integrity_valid ? 'PASS' : 'FAIL';
  lines.push(`- **Chain Integrity:** ${integrityIcon}`);
  lines.push(`- **Proofs Verified:** ${report.verification_status.total_verified}`);
  lines.push(`- **Signature Validity:** ${report.verification_status.signature_validity ? 'Valid' : 'Invalid'}`);
  lines.push(`- **Key Transitions:** ${report.verification_status.key_transitions}`);
  lines.push(`- **Checkpoint Status:** ${report.verification_status.checkpoint_status}`);
  if (report.verification_status.anomalies.length > 0) {
    lines.push('');
    lines.push('**Anomalies:**');
    for (const anomaly of report.verification_status.anomalies) {
      lines.push(`- ${anomaly}`);
    }
  }
  lines.push('');

  // Data Retention
  lines.push('## 4. Data Retention');
  lines.push('');
  lines.push(`| Field | Value |`);
  lines.push(`|-------|-------|`);
  lines.push(`| Configured Retention | ${report.data_retention.configured_retention_days} days |`);
  lines.push(`| Oldest Proof | ${report.data_retention.oldest_proof_date ?? 'N/A'} |`);
  lines.push(`| Newest Proof | ${report.data_retention.newest_proof_date ?? 'N/A'} |`);
  lines.push(`| Chain Span | ${report.data_retention.chain_span_days} days |`);
  lines.push(`| Article 19 Compliant | ${report.data_retention.article_19_compliant ? 'Yes' : 'No'} |`);
  lines.push('');
  lines.push(`> ${report.data_retention.article_19_notes}`);
  lines.push('');

  // Privacy Controls
  lines.push('## 5. Privacy Controls');
  lines.push('');
  lines.push(`**Redaction Level:** ${report.privacy_controls.configured_redaction_level} — ${report.privacy_controls.redaction_level_description}`);
  lines.push('');
  lines.push('**Data hashed (not stored in plaintext):**');
  for (const item of report.privacy_controls.data_hashed) {
    lines.push(`- ${item}`);
  }
  lines.push('');
  lines.push('**Data stored in plaintext (at current redaction level):**');
  for (const item of report.privacy_controls.data_stored_plaintext) {
    lines.push(`- ${item}`);
  }
  lines.push('');

  // Key Management
  lines.push('## 6. Key Management');
  lines.push('');
  lines.push(`| Field | Value |`);
  lines.push(`|-------|-------|`);
  lines.push(`| Algorithm | ${report.key_management.key_algorithm} |`);
  lines.push(`| Current Key | \`${report.key_management.current_key_fingerprint}\` |`);
  lines.push(`| Total Keys | ${report.key_management.total_keys} |`);
  lines.push('');
  if (report.key_management.rotation_history.length > 1) {
    lines.push('**Rotation History:**');
    for (const key of report.key_management.rotation_history) {
      const status = key.is_current ? '(current)' : '(rotated)';
      lines.push(`- \`${key.key_id}\` ${status}`);
    }
    lines.push('');
  }

  // Audit Trail Coverage
  lines.push('## 7. Audit Trail Coverage');
  lines.push('');
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Tool Starts | ${report.audit_trail_coverage.total_tool_starts} |`);
  lines.push(`| Tool Completions | ${report.audit_trail_coverage.total_tool_completions} |`);
  lines.push(`| Orphaned Starts | ${report.audit_trail_coverage.orphaned_starts} |`);
  lines.push(`| Coverage | ${report.audit_trail_coverage.coverage_percentage}% |`);
  lines.push('');

  // Risk Indicators
  lines.push('## 8. Risk Indicators');
  lines.push('');
  lines.push(`| Indicator | Count |`);
  lines.push(`|-----------|-------|`);
  lines.push(`| Policy Violations | ${report.risk_indicators.policy_violations} |`);
  lines.push(`| Failed Verifications | ${report.risk_indicators.failed_verifications} |`);
  lines.push(`| Failed Actions | ${report.risk_indicators.failed_actions} |`);
  lines.push(`| Tool Denials | ${report.risk_indicators.tool_denials} |`);
  lines.push(`| Errors | ${report.risk_indicators.errors} |`);
  if (report.risk_indicators.unusual_patterns.length > 0) {
    lines.push('');
    lines.push('**Unusual Patterns:**');
    for (const pattern of report.risk_indicators.unusual_patterns) {
      lines.push(`- ${pattern}`);
    }
  }
  lines.push('');

  return lines.join('\n');
}

# agentproofs — Architecture Plan v3

## One-liner

Signed, hash-chained proof logs for AI agent tool executions and auditable events. MCP-native. Local-first.

## Problem

AI agents perform autonomous actions — writing code, deploying services, accessing data, making decisions — but there is no verifiable record of what happened, when, by whom, and why. 93% of AI agent projects use unscoped API keys with no audit trail linking action to agent to user to authorization (source: Grantex State of Agent Security 2026).

The EU AI Act (fully applicable August 2, 2026) introduces logging and traceability obligations under Articles 12 and 19 for high-risk AI systems. No mainstream MCP-compatible solution exists for local-first, cryptographically verifiable event logging.

## What agentproofs does

Every **captured agent event** gets a **cryptographically signed proof** appended to a **hash-chained log**. The chain is append-only — any modification, insertion, or deletion breaks the chain and is immediately detectable.

```
Proof 1: { event: "tool_started: Bash", hash: abc, sig: ... }
    | prev_hash: abc
Proof 2: { event: "tool_completed: Bash", hash: def, sig: ... }
    | prev_hash: def
Proof 3: { event: "decision: use JWT over sessions", hash: ghi, sig: ... }
```

If someone alters Proof 2, its hash changes, Proof 3's prev_hash no longer matches, chain is broken, verification fails.

**Scope of capture:** agentproofs logs tool executions, lifecycle events, and explicitly recorded agent decisions. It does not capture pure model reasoning, internal chain-of-thought, or memory retrievals that occur outside tool boundaries. The proof chain records what was *observed*, not what was *thought*.

## Why this and not existing solutions

| Existing | Gap |
|----------|-----|
| AgentSign SDK | Signing only, no chain, no MCP, no auto-capture |
| AEGIS/AgentGuard | Pre-execution firewall, not audit trail |
| Agent Passport | Identity-focused, not action-focused |
| Sigstore A2A | A2A protocol only, not MCP ecosystem |
| Blockchain solutions | Too heavy, external dependencies, overkill |
| LangWatch/Agenta | Observability SaaS, not verifiable proofs, not local-first |

**Our position:** First MCP-native, local-first, auto-capturing proof chain for AI agent tool executions and auditable events. No cloud required, no blockchain, minimal config.

## Threat Model (Explicit)

agentproofs is designed against specific threat scenarios. Users must understand what it does and does not protect against.

### What it protects against

| Threat | Protection |
|--------|-----------|
| Post-hoc tampering without key access | Hash chain breaks on any modification |
| Log entry deletion | Missing sequence numbers detected |
| Log entry insertion | Hash linkage and sequence monotonicity break |
| Log reordering | Timestamp monotonicity + sequence check |
| Forged proofs from external party | Ed25519 signature verification fails |
| Selective log omission (after capture) | Chain gaps are detectable |

### What it does NOT protect against (without hardened mode)

| Threat | Why | Mitigation |
|--------|-----|------------|
| Host compromise with key access | Attacker can rewrite chain + re-sign | External anchoring (v2), hardware-backed keys (v3) |
| Root/same-user shell access | Can read private key and rewrite | OS keychain storage (v2), HSM (v3) |
| Events that never reach the daemon | Hook not installed, process killed before emit | PreToolUse capture, crash recovery (v2) |
| Model reasoning / internal decisions | Not observable via tool hooks | Explicit `decision` events only |
| Compromised daemon process | Daemon itself is the trust anchor | Process integrity checks (v3) |

### Trust levels

| Level | Name | What you get |
|-------|------|-------------|
| **L0** | Local-only (v1 default) | Tamper-evident on host. Detects post-hoc modification without key compromise. Suitable for personal audit trails and team accountability. |
| **L1** | External anchoring (v2) | Periodic chain head checkpoints to external witness (remote storage, Rekor, S3 with object lock). Detects full chain rewrite even with key compromise, within checkpoint interval. |
| **L2** | Hardware-backed (v3) | Private key in HSM/Secure Enclave/TPM. Chain rewrite requires physical hardware access. |
| **L3** | Federated witnesses (v3) | Multiple independent witnesses cross-sign checkpoints. Byzantine fault tolerant verification. |

**Marketing rule:** Always state the trust level. Never say "tamper-proof" without qualification. The correct claim for v1 is: *"tamper-evident on host, assuming key integrity."*

## EU AI Act Positioning

### What we say

> agentproofs is designed to support the logging and traceability obligations under EU AI Act Articles 12 and 19, where applicable to the deployer's use case.

### What we do NOT say

- ~~"Article 13 compliant out of the box"~~ (Article 12 covers logging; Article 13 covers transparency; Article 19 covers log retention)
- ~~"EU AI Act compliant"~~ (compliance depends on risk classification, which depends on the use case, not the tool)
- ~~"Required for all AI agents"~~ (high-risk classification is bounded by Article 6, with exceptions for narrow procedural tasks)

### How agentproofs supports compliance

| AI Act Requirement | How agentproofs helps | Article |
|-------------------|----------------------|---------|
| Automatic recording of events | Auto-capture daemon logs tool executions | Art. 12(1) |
| Lifecycle tracing | Hash chain with timestamps, agent IDs, session IDs | Art. 12(1) |
| Traceability of outputs to inputs | input_hash + output_hash per proof | Art. 12(1) |
| Log retention by deployers | Configurable retention with segment archival | Art. 19(1) |
| Tamper evidence | Hash chain + Ed25519 signatures | Art. 12(1) |
| Source data linkage | parent_event_id for delegation chains | Art. 12(1) |

**Important:** Not every AI agent is automatically high-risk. The high-risk categories are bounded (Annex III), and Article 6(3) contains exceptions for systems performing only narrow procedural or preparatory tasks without material impact on decisions. agentproofs provides the *mechanism* for compliance; the *obligation* depends on classification.

## Design Principles

1. **Signed, not just hashed** — Ed25519 keypair generated on first run. Every proof is signed. Public key = agent identity.
2. **Hash-chained** — each proof contains the hash of the previous. Tamper-evident without distributed ledger overhead.
3. **Single global chain** — one chain per daemon instance. Namespace is a field for filtering. Cross-namespace ordering is provable.
4. **Single writer** — only the daemon process appends to the chain. Hooks and SDK clients send events to the daemon, never write directly.
5. **Auto-capture** — hooks emit events to the daemon for every tool call. No manual intervention needed.
6. **MCP-native** — runs as MCP server. Tools for logging, verification, querying, exporting.
7. **Zero-config local start** — `npx agentproofs` starts the daemon with auto-generated keys. Optional hardened mode for production.
8. **Privacy by design** — input/output are hashed (SHA-256), not stored by default. Privacy ladder for configurable disclosure.
9. **Honest claims** — documentation states exactly what is and isn't protected, at which trust level.

## Architecture

```
+------------------------------------------------------+
|              AI Agent (Claude Code, etc.)             |
|                                                      |
|  PreToolUse hook ---> event: tool_started            |
|  PostToolUse hook --> event: tool_completed/failed    |
|  Stop hook ---------> event: session_ended           |
+---------------+--------------------------------------+
                |
                | Unix domain socket / localhost HTTP
                | (events, never direct file writes)
                v
+------------------------------------------------------+
|              agentproofs daemon (single writer)       |
|                                                      |
|  Event Queue:                                        |
|  +-- receive event from hook/SDK/MCP                 |
|  +-- read chain head (latest hash + sequence)        |
|  +-- assign sequence number                          |
|  +-- compute canonical hash                          |
|  +-- sign with Ed25519 private key                   |
|  +-- append to current segment                       |
|  +-- fsync                                           |
|  +-- update in-memory index                          |
|  +-- ack to caller                                   |
|                                                      |
|  MCP Server (exposed to agents):                     |
|  +-- proof_log      log an explicit event            |
|  +-- proof_verify   verify chain integrity           |
|  +-- proof_query    search proofs                    |
|  +-- proof_export   export for external audit        |
|                                                      |
|  Resources:                                          |
|  +-- proofs://chain     chain status + health        |
|  +-- proofs://head      current chain head           |
|  +-- proofs://stats     per-agent/tool statistics    |
|  +-- proofs://latest    last N proofs                |
|  +-- proofs://agent/{id}       by agent              |
|  +-- proofs://session/{id}     by session            |
|  +-- proofs://trace/{id}       by trace              |
|  +-- proofs://segment/{id}     by segment            |
|  +-- proofs://checkpoints      checkpoint history    |
|  +-- proofs://verify/latest    last verification     |
+---------------+--------------------------------------+
                |
                v
+------------------------------------------------------+
|              Storage (local filesystem)               |
|                                                      |
|  ~/.agentproofs/                                     |
|  +-- segments/                                       |
|  |   +-- 000001.jsonl        proof segment 1         |
|  |   +-- 000002.jsonl        proof segment 2         |
|  |   +-- ...                                         |
|  +-- manifests/                                      |
|  |   +-- 000001.manifest.json  signed segment digest |
|  |   +-- ...                                         |
|  +-- checkpoints/                                    |
|  |   +-- checkpoint-{seq}.json  external anchors     |
|  +-- keys/                                           |
|  |   +-- agent.key           Ed25519 private key     |
|  |   +-- agent.pub           Ed25519 public key      |
|  |   +-- rotated/            archived old keys       |
|  +-- index.sqlite            derived query index     |
|  +-- daemon.sock             Unix domain socket      |
|  +-- daemon.pid              PID file                |
+------------------------------------------------------+
```

### Single-Writer Daemon

The daemon is the sole process that writes to the chain. This eliminates race conditions from concurrent hook invocations.

```
Hook/SDK/MCP client                    Daemon
       |                                  |
       |-- event (via socket/HTTP) ------>|
       |                                  |-- acquire write lock (in-process)
       |                                  |-- read chain head
       |                                  |-- assign sequence
       |                                  |-- compute hash
       |                                  |-- sign
       |                                  |-- append to segment file
       |                                  |-- fsync
       |                                  |-- update SQLite index
       |                                  |-- release write lock
       |<--------- ack (proof_id) --------|
```

**Daemon lifecycle:**
- Starts automatically on first `npx agentproofs` or first hook event
- PID file prevents duplicate daemons
- Graceful shutdown appends `daemon_stopped` event
- Crash recovery: on startup, verify tail of last segment, truncate partial writes

## Event Model

### Event Types

| Event Type | When | Captured By |
|-----------|------|-------------|
| `session_started` | Agent session begins | Session init hook |
| `session_ended` | Agent session ends | Stop hook |
| `tool_started` | Before tool execution | PreToolUse hook |
| `tool_completed` | Tool finished successfully | PostToolUse hook |
| `tool_failed` | Tool returned error | PostToolUse hook |
| `tool_denied` | User denied tool permission | PreToolUse hook (on deny) |
| `decision` | Agent made explicit decision | Explicit proof_log call |
| `delegation_started` | Agent delegated to sub-agent | Explicit proof_log call |
| `delegation_completed` | Sub-agent returned result | Explicit proof_log call |
| `approval_requested` | Agent asked user for approval | Hook on permission prompt |
| `approval_granted` | User approved action | Hook on permission grant |
| `approval_denied` | User denied action | Hook on permission deny |
| `policy_violation` | Action blocked by policy | Policy hook |
| `checkpoint_created` | Chain checkpoint recorded | Daemon (periodic) |
| `key_rotated` | Signing key changed | Key rotation ceremony |
| `daemon_started` | Daemon process started | Daemon init |
| `daemon_stopped` | Daemon process stopping | Daemon shutdown |
| `error` | Unexpected error in proof system | Daemon error handler |

### Event Pairing

Tool executions are paired: `tool_started` + (`tool_completed` | `tool_failed` | `tool_denied`). The `tool_invocation_id` links them. If a `tool_started` has no matching completion (crash, timeout), the next daemon startup detects orphaned starts and logs `tool_failed` with reason `"orphaned_start_detected"`.

## Proof Entry Schema

```typescript
interface ProofEntry {
  // -- Chain metadata --
  schema_version: 1;                // Schema version for forward compat
  chain_id: string;                 // Unique chain identifier (generated on first run)
  id: string;                       // Unique proof ID: "ap_" + 16 hex chars
  sequence: number;                 // Monotonic counter (1, 2, 3, ...)
  prev_hash: string;                // SHA-256 of previous entry ("genesis" for first)
  hash: string;                     // SHA-256 of canonical form (excluded from hash computation)
  signature: string;                // Ed25519 signature of hash (excluded from hash computation)

  // -- Crypto metadata --
  hash_algorithm: 'sha256';         // Explicit algorithm declaration
  signature_algorithm: 'ed25519';   // Explicit algorithm declaration
  key_id: string;                   // Fingerprint of signing key (supports rotation)

  // -- Timing --
  timestamp: string;                // ISO 8601 with milliseconds, UTC
  monotonic_time_ns?: number;       // Monotonic clock (for ordering within same ms)

  // -- Who --
  agent_id: string;                 // Agent identifier (e.g., "claude-code")
  session_id: string;               // Session identifier
  user_id?: string;                 // Human who authorized (optional)
  host_id?: string;                 // Machine identifier
  process_id?: number;              // OS process ID of daemon

  // -- What --
  event_type: EventType;            // See Event Types table
  tool_invocation_id?: string;      // Links tool_started to tool_completed/failed
  trace_id?: string;                // Distributed trace ID (links related events)
  span_id?: string;                 // Span within trace

  action: {
    tool?: string;                  // Tool name: "Bash", "Edit", "Write", etc.
    input_hash: string;             // SHA-256 of raw input
    output_hash: string;            // SHA-256 of raw output
    input_summary?: string;         // Optional human-readable summary (redaction level 1+)
    output_summary?: string;        // Optional human-readable summary (redaction level 1+)
    input_encrypted?: string;       // Optional encrypted payload (redaction level 2+)
    output_encrypted?: string;      // Optional encrypted payload (redaction level 2+)
    duration_ms?: number;           // Execution time
    success: boolean;               // Did it succeed?
    error_message?: string;         // If failed, why (no PII)
  };

  // -- Why --
  context: {
    working_dir?: string;           // Current working directory
    namespace?: string;             // Project namespace for filtering
    reason?: string;                // Why this action was taken
    parent_event_id?: string;       // If triggered by another event (delegation chain)
    tags?: string[];                // Arbitrary tags for querying
    origin: 'hook' | 'sdk' | 'mcp' | 'manual' | 'daemon';  // How event was captured
    git_commit?: string;            // Current HEAD commit
    repo_dirty?: boolean;           // Uncommitted changes present?
    model_id?: string;              // AI model identifier
    model_version?: string;         // AI model version
  };

  // -- Compliance --
  compliance?: {
    eu_ai_act_category?: 'minimal' | 'limited' | 'high' | 'unacceptable';
    data_categories?: string[];     // e.g., ["personal_data", "financial", "health"]
    retention_days?: number;        // Override default retention
    redaction_level: 0 | 1 | 2 | 3; // Privacy ladder level
  };
}

type EventType =
  | 'session_started'
  | 'session_ended'
  | 'tool_started'
  | 'tool_completed'
  | 'tool_failed'
  | 'tool_denied'
  | 'decision'
  | 'delegation_started'
  | 'delegation_completed'
  | 'approval_requested'
  | 'approval_granted'
  | 'approval_denied'
  | 'policy_violation'
  | 'checkpoint_created'
  | 'key_rotated'
  | 'daemon_started'
  | 'daemon_stopped'
  | 'error';
```

## Canonicalization Specification

Hash computation uses a strict canonical form to ensure deterministic hashing across versions and runtimes.

### Rules (based on RFC 8785 JCS principles)

1. **Field order**: fixed, explicit order as listed in schema (not alphabetical sort)
2. **Encoding**: UTF-8, no BOM
3. **Numbers**: no leading zeros, no trailing zeros after decimal, no positive sign, `-0` normalized to `0`
4. **Strings**: minimal JSON escaping (only required escapes per RFC 8259)
5. **null/undefined**: omitted fields are excluded entirely (not set to null)
6. **Booleans**: lowercase `true`/`false`
7. **Arrays**: preserved order (tags, data_categories)
8. **Timestamps**: always UTC, always millisecond precision, always `Z` suffix
9. **Excluded fields**: `hash` and `signature` are never included in hash computation

### Canonical field order

```
schema_version, chain_id, id, sequence, prev_hash,
hash_algorithm, signature_algorithm, key_id,
timestamp, monotonic_time_ns,
agent_id, session_id, user_id, host_id, process_id,
event_type, tool_invocation_id, trace_id, span_id,
action.tool, action.input_hash, action.output_hash,
action.input_summary, action.output_summary,
action.input_encrypted, action.output_encrypted,
action.duration_ms, action.success, action.error_message,
context.working_dir, context.namespace, context.reason,
context.parent_event_id, context.tags, context.origin,
context.git_commit, context.repo_dirty,
context.model_id, context.model_version,
compliance.eu_ai_act_category, compliance.data_categories,
compliance.retention_days, compliance.redaction_level
```

### Hash computation

```
canonical_bytes = canonicalize(proof_entry)  // Fixed field order, rules above
hash = SHA-256(canonical_bytes)              // Hex-encoded, lowercase
signature = Ed25519.sign(hash_bytes, private_key)  // Base64-encoded
```

## Privacy Ladder

Users choose their privacy level. Default is Level 0 (maximum privacy).

| Level | Name | What is stored | Use case |
|-------|------|---------------|----------|
| **0** | Hashes only | SHA-256 of input/output, no content | Personal audit, maximum privacy |
| **1** | Redactable summaries | Hashes + optional human-readable summaries | Team accountability, incident triage |
| **2** | Encrypted payloads | Hashes + summaries + AES-256-GCM encrypted input/output stored locally | Incident response, forensics (decryptable by key holder) |
| **3** | Selective disclosure | Level 2 + export capability with per-field decryption for auditor | External audit, compliance review |

**Level 0 verification flow:**
1. Agent shows proof entry (with input_hash)
2. Auditor computes SHA-256 of the claimed input
3. Hashes match = proven that this input was used

**Level 2 encryption:**
- Separate encryption key from signing key
- Payload encryption key can be rotated independently
- Deletion of encryption key = irreversible redaction (proof skeleton remains)

## Chain Verification Algorithm

```
function verify(segments, public_keys):
  total_verified = 0
  prev_entry = null

  for each segment in segments:
    // Verify segment manifest signature
    verify_manifest(segment.manifest, public_keys)

    for each entry in segment.entries:
      // 1. Check prev_hash linkage
      if prev_entry == null:
        assert entry.prev_hash == "genesis"
      else:
        assert entry.prev_hash == prev_entry.hash

      // 2. Check schema version is known
      assert entry.schema_version in KNOWN_VERSIONS

      // 3. Recompute canonical hash
      computed = SHA-256(canonicalize(entry))
      assert computed == entry.hash

      // 4. Verify signature against key_id
      key = public_keys[entry.key_id]
      assert key != null  // key_id must be known
      assert Ed25519.verify(entry.hash, entry.signature, key)

      // 5. Check monotonic sequence
      if prev_entry != null:
        assert entry.sequence == prev_entry.sequence + 1

      // 6. Check monotonic timestamp
      if prev_entry != null:
        assert entry.timestamp >= prev_entry.timestamp

      // 7. Check key rotation continuity
      if entry.event_type == "key_rotated":
        verify_key_rotation(entry, prev_entry, public_keys)

      prev_entry = entry
      total_verified++

  return { valid: true, verified: total_verified }
```

## Key Rotation Protocol

Key rotation is a chain event, not an out-of-band operation.

```
1. Generate new Ed25519 keypair
2. Create key_rotated proof entry:
   - Signed by OLD key
   - Contains new public key in action.output_summary
   - Contains new key_id
   - Contains reason for rotation
3. Next proof entry:
   - Signed by NEW key
   - key_id references new key
4. Old private key:
   - Archived to keys/rotated/{key_id}.key
   - Or securely deleted (if compromised)
5. Verification:
   - Verifier follows key_id transitions
   - Each transition must be signed by preceding key
   - Chain of custody from genesis key to current key
```

### Compromised key response

```
1. Generate new keypair immediately
2. Log key_rotated event with reason: "key_compromise"
3. Create external checkpoint immediately (if v2 anchoring available)
4. Archive or delete old key
5. All proofs signed by compromised key remain verifiable
   but carry advisory: "signed by compromised key {key_id}"
```

## Storage Architecture

### Segments

The chain is split into segments for manageability.

| Parameter | Default | Description |
|-----------|---------|-------------|
| Segment size | 10,000 proofs | Max proofs per segment file |
| Segment trigger | size OR time | Whichever threshold hits first |
| Segment time | 24 hours | Max age of active segment |

When a segment is sealed:
1. Daemon stops writing to current segment
2. Computes segment digest (hash of all proof hashes)
3. Signs digest with current key
4. Writes manifest to `manifests/{segment_id}.manifest.json`
5. Creates new segment file
6. First proof in new segment links to last proof of old segment (continuity)

### Segment manifest

```json
{
  "segment_id": "000001",
  "chain_id": "ch_abc123",
  "first_sequence": 1,
  "last_sequence": 10000,
  "first_hash": "abc...",
  "last_hash": "def...",
  "segment_hash": "SHA-256 of concatenated proof hashes",
  "proof_count": 10000,
  "created_at": "2026-04-01T00:00:00.000Z",
  "sealed_at": "2026-04-01T23:59:59.999Z",
  "key_id": "key_abc",
  "signature": "Ed25519 signature of segment_hash"
}
```

### Retention via segments

Retention does NOT mean deleting individual proofs (that would break the chain).

```
Retention flow:
1. Segment is sealed and manifested
2. Retention timer starts from sealed_at
3. When retention expires:
   a. Proof skeletons remain (id, sequence, hash, prev_hash, signature, event_type, timestamp)
   b. Action payloads are zeroed (summaries, encrypted blobs)
   c. Manifest is updated with retention_applied: true
   d. Segment can be archived to cold storage
   e. Chain integrity remains verifiable (hashes computed from original, stored in manifest)
4. Full segment deletion only after:
   a. All proofs expired
   b. Signed deletion certificate created
   c. Manifest archived externally
```

### SQLite sidecar index

The index is a **derived cache**, not a trust anchor.

- Rebuilt from JSONL segments on demand (`npx agentproofs rebuild-index`)
- Used only for query performance (filtering, pagination, aggregation)
- Verification always runs against JSONL segments, never against SQLite
- Schema: proofs table mirroring ProofEntry fields, indexed on common query patterns

```sql
CREATE TABLE proofs (
  id TEXT PRIMARY KEY,
  sequence INTEGER UNIQUE,
  event_type TEXT,
  tool TEXT,
  agent_id TEXT,
  session_id TEXT,
  trace_id TEXT,
  namespace TEXT,
  timestamp TEXT,
  success INTEGER,
  segment_id TEXT,
  -- no hashes, signatures, or payload in index
  -- those live in canonical JSONL
);
CREATE INDEX idx_event_type ON proofs(event_type);
CREATE INDEX idx_tool ON proofs(tool);
CREATE INDEX idx_agent ON proofs(agent_id);
CREATE INDEX idx_session ON proofs(session_id);
CREATE INDEX idx_trace ON proofs(trace_id);
CREATE INDEX idx_namespace ON proofs(namespace);
CREATE INDEX idx_timestamp ON proofs(timestamp);
CREATE INDEX idx_segment ON proofs(segment_id);
```

## MCP Tools

### proof_log

Log an explicit agent event to the proof chain.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_type | EventType | yes | Event type (see Event Types table) |
| tool | string | no | Tool name (e.g., "Bash", "Edit") |
| tool_invocation_id | string | no | Links to corresponding started/completed pair |
| trace_id | string | no | Distributed trace ID |
| input_summary | string | no | Human-readable input description |
| output_summary | string | no | Human-readable output description |
| input_hash | string | no | Pre-computed input hash (auto-computed from summary if not provided) |
| output_hash | string | no | Pre-computed output hash (auto-computed from summary if not provided) |
| success | boolean | yes | Did the action succeed? |
| reason | string | no | Why this action was taken |
| namespace | string | no | Project namespace |
| tags | string[] | no | Searchable tags |
| duration_ms | number | no | Execution time |
| origin | string | no | How event was captured (hook/sdk/mcp/manual) |
| parent_event_id | string | no | Parent event for delegation chains |
| redaction_level | number | no | Privacy level (0-3) |

Returns: `{ proof_id, sequence, hash, signature, key_id }`

### proof_verify

Verify the integrity of the proof chain.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| from_sequence | number | no | Start verification from this sequence |
| to_sequence | number | no | End verification at this sequence |
| verify_signatures | boolean | no | Verify Ed25519 signatures (default: true) |
| verify_segments | boolean | no | Verify segment manifests (default: true) |
| verify_checkpoints | boolean | no | Verify external checkpoints (default: false) |

Returns:
```json
{
  "valid": true,
  "total_proofs": 847,
  "verified": 847,
  "first_invalid_sequence": null,
  "first_invalid_reason": null,
  "last_valid_hash": "abc...",
  "chain_hash": "def...",
  "segments_verified": 1,
  "checkpoint_status": "none",
  "key_transitions": 0
}
```

### proof_query

Search the proof chain.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| proof_id | string | no | Specific proof by ID |
| agent_id | string | no | Filter by agent |
| session_id | string | no | Filter by session |
| trace_id | string | no | Filter by trace |
| event_type | EventType | no | Filter by event type |
| tool | string | no | Filter by tool |
| namespace | string | no | Filter by namespace |
| tags | string[] | no | Filter by tags (AND) |
| from_date | string | no | ISO date |
| to_date | string | no | ISO date |
| success | boolean | no | Filter by success/failure |
| redaction_level | number | no | Filter by min redaction level |
| sort | 'asc' \| 'desc' | no | Sort order (default: desc) |
| limit | number | no | Max results (default: 50) |
| offset | number | no | Pagination offset |

Returns: `{ results: ProofEntry[], total, has_more }`

### proof_export

Export proofs for external audit.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| format | string | yes | "jsonl", "json", "csv" |
| from_date | string | no | Start date |
| to_date | string | no | End date |
| namespace | string | no | Filter by namespace |
| export_scope | string | no | "full", "filtered", "trace", "session" |
| trace_id | string | no | Export specific trace |
| session_id | string | no | Export specific session |
| include_verification | boolean | no | Include chain verification result |
| include_hash_material | boolean | no | Include canonical hash input for re-verification |
| include_signatures | boolean | no | Include signatures in export |
| include_redacted_summaries | boolean | no | Include summaries (redaction level 1+) |
| sign_export | boolean | no | Sign the export file itself |
| checkpoint_bundle | boolean | no | Include external checkpoint proofs |

Returns: `{ file_path, total_proofs, chain_valid, export_hash, export_signature? }`

## MCP Resources

| URI | Description |
|-----|-------------|
| `proofs://chain` | Chain status: length, last hash, last sequence, health, public key, chain_id |
| `proofs://head` | Current chain head: latest proof entry |
| `proofs://stats` | Statistics: proofs per agent, per tool, per namespace, per event type, per day |
| `proofs://latest` | Last 20 proof entries |
| `proofs://verify/latest` | Result of most recent verification |
| `proofs://agent/{agent_id}` | Proofs from specific agent |
| `proofs://session/{session_id}` | Proofs from specific session |
| `proofs://trace/{trace_id}` | All proofs in a trace |
| `proofs://segment/{segment_id}` | Proofs in a specific segment |
| `proofs://checkpoints` | External checkpoint history |

## CLI Commands

```bash
# Daemon
npx agentproofs                      # Start daemon + MCP server
npx agentproofs daemon start         # Start daemon in background
npx agentproofs daemon stop          # Graceful shutdown
npx agentproofs daemon status        # Check daemon health

# Verification
npx agentproofs verify               # Verify entire chain
npx agentproofs verify --from 100    # Verify from sequence 100
npx agentproofs verify --signatures  # Include signature verification
npx agentproofs verify --checkpoints # Include external checkpoint verification

# Inspection
npx agentproofs stats                # Chain statistics
npx agentproofs tail                 # Live tail (follow new proofs)
npx agentproofs tail -n 10           # Last 10 proofs
npx agentproofs query --tool Bash    # Query by tool
npx agentproofs query --trace <id>   # Query by trace
npx agentproofs query --session <id> # Query by session
npx agentproofs show <proof_id>      # Show single proof detail

# Export
npx agentproofs export               # Export full chain as JSONL
npx agentproofs export --format csv  # Export as CSV
npx agentproofs export --sign        # Export + sign the export file
npx agentproofs export --scope trace --trace <id>  # Export specific trace

# Key management
npx agentproofs pubkey               # Print public key
npx agentproofs rotate-key           # Rotate signing key
npx agentproofs verify-key <pubkey>  # Verify chain against known public key
npx agentproofs keys                 # List all keys (current + rotated)

# Index management
npx agentproofs rebuild-index        # Rebuild SQLite index from JSONL

# Segments
npx agentproofs segments             # List all segments
npx agentproofs seal                 # Force-seal current segment

# External anchoring (v2)
npx agentproofs checkpoint           # Create external checkpoint
npx agentproofs anchors              # List external anchors
```

## Hook Architecture

### Auto-capture hooks

```
~/.claude/scripts/hooks/agentproofs-capture.js
```

**PreToolUse hook:**
- Emits `tool_started` event to daemon
- Includes tool name, input_hash, tool_invocation_id
- On user denial: emits `tool_denied` event

**PostToolUse hook:**
- Emits `tool_completed` or `tool_failed` event to daemon
- Includes tool name, input_hash, output_hash, success, duration_ms
- Links to corresponding `tool_started` via tool_invocation_id

**Stop hook:**
- Emits `session_ended` event to daemon

**What hooks capture:**
- Tool name (Bash, Edit, Write, Read, Grep, Glob, Agent, etc.)
- Input hash (SHA-256 of tool input)
- Output hash (SHA-256 of tool output)
- Success/failure
- Duration
- Working directory
- Session info
- Git commit + dirty state

**What hooks do NOT capture:**
- Raw input content (only hash, unless redaction level 1+)
- Raw output content (only hash, unless redaction level 1+)
- Model reasoning or chain-of-thought
- No PII unless explicitly configured

### Hook-to-daemon communication

```
Hook process                         Daemon
    |                                  |
    |-- POST /event {                  |
    |     event_type: "tool_completed" |
    |     tool: "Bash"                 |
    |     input_hash: "abc..."         |
    |     output_hash: "def..."        |
    |     ...                          |
    |   } --------------------------->|
    |                                  |-- process + append
    |<-- 200 { proof_id, seq } --------|
```

Transport: Unix domain socket at `~/.agentproofs/daemon.sock` (preferred) with localhost HTTP fallback.

Fire-and-forget mode: hooks can send without waiting for ack (for performance). The daemon queues internally and writes sequentially.

## Configuration

All via environment variables. Defaults work for v1.

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTPROOFS_DATA_DIR` | `~/.agentproofs/` | Base data directory |
| `AGENTPROOFS_AGENT_ID` | `"claude-code"` | Agent identifier |
| `AGENTPROOFS_USER_ID` | `""` | Human user identifier |
| `AGENTPROOFS_NAMESPACE` | `"default"` | Default namespace |
| `AGENTPROOFS_LOG_LEVEL` | `"info"` | Daemon log level |
| `AGENTPROOFS_RETENTION_DAYS` | `365` | Default proof retention |
| `AGENTPROOFS_SEGMENT_SIZE` | `10000` | Max proofs per segment |
| `AGENTPROOFS_SEGMENT_MAX_AGE` | `86400` | Max segment age in seconds |
| `AGENTPROOFS_REDACTION_LEVEL` | `0` | Default privacy level (0-3) |
| `AGENTPROOFS_SOCKET_PATH` | `~/.agentproofs/daemon.sock` | Unix socket path |
| `AGENTPROOFS_HTTP_PORT` | `0` | HTTP fallback port (0 = disabled) |
| `AGENTPROOFS_KEY_STORE` | `"file"` | Key storage: "file", "keychain" (v2), "hsm" (v3) |
| `AGENTPROOFS_CHECKPOINT_INTERVAL` | `0` | Proofs between external checkpoints (0 = disabled) |

## Package Details

| Field | Value |
|-------|-------|
| Name | `agentproofs` |
| npm | `npx agentproofs` |
| GitHub | `AdelElo13/agentproofs` |
| License | MIT |
| Core dependencies | `@modelcontextprotocol/sdk`, `zod` |
| Optional dependencies | `better-sqlite3` (query index) |
| No | blockchain, cloud services, embeddings, external DBs |
| Node | >= 18 |

## File Structure

```
agentproofs/
+-- bin/
|   +-- cli.mjs                     CLI entry point
+-- src/
|   +-- index.ts                    MCP server entry
|   +-- daemon.ts                   Single-writer daemon (socket + queue + writer)
|   +-- server.ts                   MCP server setup (tools + resources)
|   +-- config.ts                   Environment config + defaults
|   +-- chain.ts                    Proof chain: append, read, verify
|   +-- crypto.ts                   Ed25519 keygen, sign, verify + SHA-256
|   +-- canonical.ts                Canonicalization (deterministic JSON)
|   +-- proof.ts                    ProofEntry creation + hashing
|   +-- query.ts                    Query/filter/search (SQLite-backed)
|   +-- export.ts                   Export to JSONL/JSON/CSV
|   +-- segments.ts                 Segment management + manifests
|   +-- retention.ts                Retention policy + segment archival
|   +-- keys.ts                     Key management + rotation
|   +-- resources.ts                MCP resources
|   +-- types.ts                    TypeScript interfaces + event types
|   +-- privacy.ts                  Privacy ladder (levels 0-3, encryption)
|   +-- index-db.ts                 SQLite sidecar index
|   +-- recovery.ts                 Crash recovery + orphan detection
+-- templates/
|   +-- hooks/
|       +-- agentproofs-pre.js      PreToolUse auto-capture hook
|       +-- agentproofs-post.js     PostToolUse auto-capture hook
|       +-- agentproofs-stop.js     Stop hook (session_ended)
+-- tests/
|   +-- canonical.test.ts           Canonicalization determinism + edge cases
|   +-- chain.test.ts               Append, genesis, linkage, tamper detection
|   +-- crypto.test.ts              Keygen, sign, verify, reject tampered
|   +-- daemon.test.ts              Single writer, queuing, crash recovery
|   +-- export.test.ts              JSONL/JSON/CSV format, signed exports
|   +-- keys.test.ts                Key rotation, compromised key, key listing
|   +-- privacy.test.ts             Privacy levels 0-3, encryption/decryption
|   +-- proof.test.ts               Entry creation, hash computation, stability
|   +-- query.test.ts               Filtering, pagination, SQLite index
|   +-- retention.test.ts           Segment retention, skeleton preservation
|   +-- segments.test.ts            Segment creation, sealing, manifests
|   +-- integration/
|       +-- server.test.ts          MCP server full lifecycle
|       +-- daemon.test.ts          Daemon socket communication
|       +-- hooks.test.ts           Hook-to-daemon event flow
+-- package.json
+-- tsconfig.json
+-- tsup.config.ts
+-- vitest.config.ts
+-- README.md
+-- LICENSE
+-- ARCHITECTURE.md
```

## Test Plan

| Area | Tests | What |
|------|-------|------|
| Canonical | 8 | Deterministic output, field order, null handling, number normalization, cross-runtime consistency, schema version, timestamp normalization, array order |
| Crypto | 8 | Keygen, sign, verify, reject tampered, deterministic hash, key serialization, key fingerprint, multi-key verify |
| Chain | 12 | Append, genesis, prev_hash linking, verify valid, detect tampered, detect deleted, detect inserted, sequence monotonic, timestamp monotonic, empty chain, cross-segment continuity, partial write recovery |
| Proof | 8 | Create entry, hash computation, hash stability, field validation, optional fields, compliance fields, event type validation, tool_invocation_id pairing |
| Daemon | 10 | Single writer serialization, concurrent event handling, queue ordering, socket communication, HTTP fallback, graceful shutdown, crash recovery, orphaned start detection, PID file, backpressure |
| Query | 10 | By agent, by tool, by namespace, by date range, by tags, by success, by event type, by trace_id, pagination, empty results |
| Export | 6 | JSONL format, JSON format, CSV format, signed export, date filtering, scope filtering (trace/session) |
| Segments | 8 | Create segment, seal on size, seal on time, manifest signing, cross-segment linkage, force seal, segment listing, manifest verification |
| Keys | 8 | Generate keypair, rotate key, rotation proof entry, compromised key flow, key listing, key archival, verify with rotated keys, key fingerprint |
| Privacy | 6 | Level 0 hash-only, level 1 summaries, level 2 encrypted payloads, level 3 selective disclosure, payload encryption/decryption, encryption key rotation |
| Retention | 6 | Skeleton preservation, payload zeroing, segment archival, manifest update, full segment deletion with certificate, retention timer |
| Integration | 6 | MCP server starts, proof_log tool, proof_verify tool, proof_query tool, daemon socket lifecycle, hook-to-daemon flow |
| **Total** | **96** | |

## Versioning Roadmap

### V1 — Ship something that works

**Goal:** Usable local proof chain with honest claims.

- Single-writer daemon with Unix socket
- Ed25519 auto-generated keys
- JSONL segmented chain
- Canonical hash computation (documented spec)
- proof_log / proof_verify / proof_query / proof_export
- PreToolUse + PostToolUse hooks (tool_started, tool_completed, tool_failed)
- Session lifecycle events (session_started, session_ended)
- CLI: verify, stats, tail, query, export, pubkey
- SQLite sidecar index (rebuildable)
- Privacy level 0 (hashes only) and level 1 (summaries)
- Crash recovery (orphaned start detection, partial write truncation)
- Honest threat model documentation

### V2 — Reliable enough for serious users

**Goal:** Production-grade for teams and compliance-conscious deployments.

- Approval events (approval_requested, granted, denied)
- tool_denied events
- Policy violation events
- Key rotation with chain continuity
- External checkpointing (S3 object lock, Rekor witness, configurable)
- Privacy level 2 (encrypted local payloads)
- OS keychain key storage (macOS Keychain, Linux secret-service)
- Signed segment manifests with external anchoring
- Retention with segment archival (skeleton preservation)
- Dashboard resource (proofs://dashboard)
- Performance: verified up to 1M proofs

### V3 — Enterprise-grade proof layer

**Goal:** Meets enterprise security and compliance bar.

- Hardware-backed keys (HSM, Secure Enclave, TPM)
- Privacy level 3 (selective disclosure export)
- Multi-agent federation (cross-agent chain verification)
- Remote witness verification (multiple independent witnesses)
- Policy integration (OPA, Cedar)
- Compliance packs (EU AI Act, SOC2, ISO 27001 mappings)
- Federated checkpoint consensus
- Encrypted payload key escrow
- Audit report generation

## What Success Looks Like

After v1, a user can:

```bash
# 1. Install and start
npx agentproofs

# 2. Use Claude Code normally — tool calls auto-captured via hooks

# 3. Verify the chain at any time
npx agentproofs verify
# Chain valid: 847 proofs verified across 1 segment
# Trust level: L0 (local, key integrity assumed)
# No tampering detected.

# 4. Query what happened
npx agentproofs query --tool Bash --from 2026-04-01
# Shows tool_started/tool_completed pairs with timestamps

# 5. See a session trace
npx agentproofs query --session sess_abc123
# Full timeline: session_started -> tool calls -> session_ended

# 6. Export for audit
npx agentproofs export --sign
# Exports signed JSONL + verification metadata

# 7. Share public key for external verification
npx agentproofs pubkey
# ed25519:abc123... (auditor verifies proofs came from this agent)
```

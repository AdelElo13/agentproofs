# agentproofs

Signed, hash-chained proof logs for AI agent tool executions and auditable events. MCP-native. Local-first.

## The problem

Your AI agent just modified 200 files, ran 50 shell commands, and made 12 architectural decisions. Your team lead asks: *"What exactly did the AI do?"*

Without agentproofs: you scroll through terminal history and hope nothing got lost.

With agentproofs: every action is cryptographically signed and hash-chained. Modify, delete, or insert any record and the chain breaks. You have a verifiable, tamper-evident audit trail.

## How is this different from just logging?

A log file is a text file. Anyone with write access can edit it, and you'd never know.

agentproofs creates a **hash chain**: each proof contains the hash of the previous one. Change anything and every subsequent hash becomes invalid. On top of that, every entry is **signed with Ed25519** — so you can prove which agent created which proof.

```
Proof 1: { event: "Bash: npm install", hash: a3f... }
    | prev_hash: a3f...
Proof 2: { event: "Write: src/server.ts", hash: 7c1... }
    | prev_hash: 7c1...
Proof 3: { event: "Decision: use JWT", hash: e9b... }
```

Tamper with Proof 2? Its hash changes. Proof 3's `prev_hash` no longer matches. Chain broken. Tampering detected.

## Quick start

```bash
# Initialize (generates Ed25519 keypair + data directory)
npx agentproofs init

# Install auto-capture hooks for Claude Code
npx agentproofs install-hooks

# Use Claude Code normally — every tool call is captured automatically

# See what happened
npx agentproofs tail

# Verify nothing was tampered with
npx agentproofs verify
```

## What it looks like

**`npx agentproofs tail`** — see every action your agent took:

```
     1 ✓ 2026-04-06 11:29:00 session_started "Session started"
     2 ✓ 2026-04-06 11:29:00 tool_started Bash "npm install express"
     3 ✓ 2026-04-06 11:29:00 tool_completed Bash "npm install express" 4200ms
     4 ✓ 2026-04-06 11:29:00 tool_completed Write "create src/server.ts" 30ms
     5 ✓ 2026-04-06 11:29:00 tool_completed Write "create src/routes/auth.ts" 25ms
     6 ✓ 2026-04-06 11:29:00 decision "Use JWT over session cookies"
     7 ✓ 2026-04-06 11:29:00 tool_completed Edit "edit src/middleware/auth.ts" 15ms
     8 ✓ 2026-04-06 11:29:00 tool_started Bash "npm test"
     9 ✗ 2026-04-06 11:29:00 tool_failed Bash "npm test" 8500ms
    10 ✓ 2026-04-06 11:29:00 tool_completed Edit "fix test assertions" 10ms
    11 ✓ 2026-04-06 11:29:00 tool_completed Bash "npm test" 7200ms
    12 ✓ 2026-04-06 11:29:00 session_ended "Session ended"
```

Every line is a signed proof. The ✗ on line 9 shows a failed `npm test` — the agent then fixed the tests (line 10) and re-ran them (line 11). The full story is preserved.

**`npx agentproofs verify`** — cryptographically verify the entire chain:

```
✓ Chain valid: 12 proofs verified
  Trust level: L0 (local, key integrity assumed)
  No tampering detected.
```

**`npx agentproofs stats`** — see what your agent has been doing:

```
Chain Statistics
  Total proofs: 12

  By event type:
    tool_completed           6
    tool_started             2
    session_started          1
    decision                 1
    tool_failed              1
    session_ended            1

  By tool:
    Bash                     5
    Write                    2
    Edit                     2
```

**`npx agentproofs query --failed`** — find what went wrong:

```
Showing 1 of 1 proofs

     9 ✗ 2026-04-06 11:29:00 tool_failed Bash "npm test"
```

## Who is this for?

- **Teams using AI agents** who need accountability for what the AI did
- **Regulated industries** that need audit trails (finance, healthcare, legal)
- **Security-conscious developers** who want tamper-evident logs
- **Companies preparing for EU AI Act** (Articles 12/19 logging obligations)
- **Anyone who wants to answer**: "what did the AI agent actually do?"

## How it works

1. **`npx agentproofs init`** generates an Ed25519 keypair — your agent's cryptographic identity
2. **Hooks** capture every tool call automatically (PreToolUse + PostToolUse + Stop)
3. **Each event** is hashed (SHA-256) and signed (Ed25519), linking to the previous proof's hash
4. **A single-writer daemon** serializes all writes — no race conditions, even with parallel agents
5. **Privacy by default** — only hashes of input/output are stored, not the actual content

### Privacy

| Data | Stored? | How |
|------|---------|-----|
| Tool name | Yes | Plain text |
| Input content | **No** | Only SHA-256 hash |
| Output content | **No** | Only SHA-256 hash |
| Summaries | Optional | Opt-in per event |
| Working directory | Yes | Plain text |
| Timestamp | Yes | ISO 8601 UTC |

To prove what happened without revealing content: show the proof entry (with `input_hash`), and the auditor computes SHA-256 of the claimed input. Hashes match = proven.

## Threat model — be honest

agentproofs is tamper-**evident**, not tamper-**proof**. Here's exactly what it protects against:

| Threat | Protected? |
|--------|-----------|
| Someone edits the log after the fact (without key access) | **Yes** — hash chain breaks |
| Someone deletes log entries | **Yes** — sequence gaps detected |
| Someone inserts fake entries | **Yes** — hash linkage breaks |
| Someone forges proofs from outside | **Yes** — signature check fails |
| Attacker with access to the signing key | **No (v1)** — they can rewrite the chain |
| Events that were never captured | **No** �� can't prove what wasn't logged |

**Trust level L0 (v1):** Tamper-evident on host, assuming key integrity. Good for team accountability and personal audit trails. Future versions add external anchoring (L1), hardware-backed keys (L2), and federated witnesses (L3).

## CLI reference

```bash
npx agentproofs [command] [options]
```

| Command | Description |
|---------|-------------|
| `init` | Initialize data directory and generate keys |
| `install-hooks` | Install Claude Code auto-capture hooks |
| `verify` | Verify chain integrity |
| `stats` | Show chain statistics |
| `tail [-n count]` | Show latest proofs |
| `query [filters]` | Search proofs |
| `show <id>` | Show single proof detail |
| `export [options]` | Export proofs for audit |
| `pubkey` | Print public key (share with auditors) |
| `keys` | List keys |
| `segments` | List chain segments |

### Query filters

```bash
npx agentproofs query --tool Bash          # by tool
npx agentproofs query --failed             # only failures
npx agentproofs query --type decision      # by event type
npx agentproofs query --from 2026-04-01    # by date
npx agentproofs query --namespace my-app   # by project
npx agentproofs query --limit 100 --asc    # pagination + sort
```

### Export

```bash
npx agentproofs export                     # JSONL (default)
npx agentproofs export --format csv        # CSV for spreadsheets
npx agentproofs export --format json       # JSON array
npx agentproofs export --sign              # signed export (auditor can verify)
```

## MCP Server

agentproofs also runs as an MCP server, so AI agents can log and query proofs directly:

```json
{
  "mcpServers": {
    "agentproofs": {
      "command": "npx",
      "args": ["agentproofs"]
    }
  }
}
```

**Tools:** `proof_log`, `proof_verify`, `proof_query`, `proof_export`

**Resources:** `proofs://chain`, `proofs://stats`, `proofs://latest`

## Event types

agentproofs captures 18 event types covering the full agent lifecycle:

| Category | Events |
|----------|--------|
| **Session** | `session_started`, `session_ended` |
| **Tools** | `tool_started`, `tool_completed`, `tool_failed`, `tool_denied` |
| **Decisions** | `decision` |
| **Delegation** | `delegation_started`, `delegation_completed` |
| **Approval** | `approval_requested`, `approval_granted`, `approval_denied` |
| **Policy** | `policy_violation` |
| **System** | `checkpoint_created`, `key_rotated`, `daemon_started`, `daemon_stopped`, `error` |

## Architecture

```
Hooks/SDK  →  Unix socket  →  Daemon (single writer)  →  JSONL segments
                                |— assign sequence
                                |— compute canonical hash
                                |— sign (Ed25519)
                                |— append + fsync
```

Storage layout:
```
~/.agentproofs/
  segments/         Append-only JSONL proof chain
  manifests/        Signed segment digests
  keys/             Ed25519 keypair
  exports/          Audit exports
```

## EU AI Act

agentproofs is designed to support the logging and traceability obligations under EU AI Act Articles 12 and 19, where applicable. It is **not** a compliance certification — compliance depends on the risk classification of your specific use case (see Article 6). agentproofs provides the mechanism; the obligation depends on classification.

## Configuration

All via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTPROOFS_DATA_DIR` | `~/.agentproofs/` | Data directory |
| `AGENTPROOFS_AGENT_ID` | `claude-code` | Agent identifier |
| `AGENTPROOFS_NAMESPACE` | `default` | Default namespace |
| `AGENTPROOFS_REDACTION_LEVEL` | `0` | Privacy level (0-3) |

## Development

```bash
npm install
npm test          # 132 tests
npm run build     # TypeScript → dist/
npm run typecheck # Type verification
```

## License

MIT

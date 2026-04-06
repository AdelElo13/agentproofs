# agentproofs

Signed, hash-chained proof logs for AI agent tool executions and auditable events. MCP-native. Local-first.

## What it does

Every captured agent event gets a cryptographically signed proof appended to a hash-chained log. The chain is append-only — any modification, insertion, or deletion breaks the chain and is immediately detectable.

```
Proof 1: { event: "tool_started: Bash", hash: abc, sig: ... }
    | prev_hash: abc
Proof 2: { event: "tool_completed: Bash", hash: def, sig: ... }
    | prev_hash: def
Proof 3: { event: "decision: use JWT", hash: ghi, sig: ... }
```

## Quick start

```bash
# Initialize
npx agentproofs init

# Install Claude Code auto-capture hooks
npx agentproofs install-hooks

# Use Claude Code normally — every tool call is auto-captured

# Verify chain integrity
npx agentproofs verify

# See recent activity
npx agentproofs tail

# Search proofs
npx agentproofs query --tool Bash --from 2026-04-01

# Export for audit
npx agentproofs export --sign
```

## How it works

1. **Ed25519 keypair** generated on first run — your agent's cryptographic identity
2. **Every tool call** captured via Claude Code hooks (PreToolUse + PostToolUse)
3. **Each proof** is hashed (SHA-256) and signed (Ed25519), linking to the previous proof's hash
4. **Tamper detection** — modify, delete, or insert any entry and the chain breaks
5. **Privacy by default** — only hashes of input/output are stored, not content

## MCP Server

agentproofs runs as an MCP server with 4 tools and 3 resources:

**Tools:**
- `proof_log` — Log an agent event
- `proof_verify` — Verify chain integrity
- `proof_query` — Search proofs
- `proof_export` — Export for audit

**Resources:**
- `proofs://chain` — Chain status and health
- `proofs://stats` — Statistics by agent, tool, namespace
- `proofs://latest` — Last 20 proof entries

Add to your MCP config:

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

## CLI

```bash
npx agentproofs [command] [options]
```

| Command | Description |
|---------|-------------|
| `(default)` | Start MCP server |
| `init` | Initialize data directory and keys |
| `install-hooks` | Install Claude Code auto-capture hooks |
| `verify` | Verify chain integrity |
| `stats` | Show chain statistics |
| `tail` | Show latest proofs |
| `query` | Search proofs |
| `show <id>` | Show single proof detail |
| `export` | Export proofs for audit |
| `pubkey` | Print public key |
| `keys` | List keys |
| `segments` | List chain segments |

### Examples

```bash
# Verify the entire chain
npx agentproofs verify
# > Chain valid: 847 proofs verified
# > Trust level: L0 (local, key integrity assumed)

# Last 10 events
npx agentproofs tail -n 10

# All Bash commands this week
npx agentproofs query --tool Bash --from 2026-04-01

# Failed actions only
npx agentproofs query --failed

# Export signed JSONL
npx agentproofs export --sign

# Export as CSV
npx agentproofs export --format csv

# Share your public key
npx agentproofs pubkey
# > ed25519:MCowBQYDK2Vw...
```

## Event types

agentproofs captures 18 event types:

| Event | When |
|-------|------|
| `session_started` | Agent session begins |
| `session_ended` | Agent session ends |
| `tool_started` | Before tool execution |
| `tool_completed` | Tool finished successfully |
| `tool_failed` | Tool returned error |
| `tool_denied` | User denied tool permission |
| `decision` | Agent made explicit decision |
| `delegation_started` | Agent delegated to sub-agent |
| `delegation_completed` | Sub-agent returned |
| `approval_requested` | Agent asked user for approval |
| `approval_granted` | User approved |
| `approval_denied` | User denied |
| `policy_violation` | Action blocked by policy |
| `checkpoint_created` | Chain checkpoint recorded |
| `key_rotated` | Signing key changed |
| `daemon_started` | Daemon process started |
| `daemon_stopped` | Daemon process stopping |
| `error` | Unexpected error |

## Privacy

| Data | Stored? | How |
|------|---------|-----|
| Tool name | Yes | Plain text |
| Input content | **No** | Only SHA-256 hash |
| Output content | **No** | Only SHA-256 hash |
| Summaries | Optional | Opt-in per event |
| Working directory | Yes | Plain text |
| Timestamp | Yes | ISO 8601 UTC |
| Agent/session ID | Yes | Plain text |

To prove what happened without revealing content:
1. Show the proof entry (with `input_hash`)
2. Auditor computes SHA-256 of the claimed input
3. Hashes match = proven that this input was used

## Threat model

Be honest about what this protects against:

| Threat | Protected? | Notes |
|--------|-----------|-------|
| Post-hoc tampering (no key access) | Yes | Hash chain breaks |
| Entry deletion | Yes | Sequence gaps detected |
| Entry insertion | Yes | Hash linkage breaks |
| Forged proofs (external) | Yes | Signature check fails |
| Host compromise with key access | **No (v1)** | Attacker can rewrite + re-sign |
| Events never captured | **No** | Can't prove what wasn't logged |

**Trust level L0 (v1):** Tamper-evident on host, assuming key integrity. Suitable for personal audit trails and team accountability.

Future versions add external anchoring (L1), hardware-backed keys (L2), and federated witnesses (L3).

## Architecture

Single-writer daemon ensures no race conditions:

```
Hook/SDK  -->  Unix socket  -->  Daemon (single writer)  -->  JSONL segments
                                  |-- assign sequence
                                  |-- compute hash
                                  |-- sign (Ed25519)
                                  |-- append + fsync
```

Storage:
```
~/.agentproofs/
  segments/         # Append-only JSONL proof chain
  manifests/        # Signed segment digests
  keys/             # Ed25519 keypair
  checkpoints/      # External anchors (v2)
  exports/          # Audit exports
```

## EU AI Act

agentproofs is designed to support the logging and traceability obligations under EU AI Act Articles 12 and 19, where applicable. It is **not** a compliance certification — compliance depends on risk classification of your specific use case.

## Configuration

All via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTPROOFS_DATA_DIR` | `~/.agentproofs/` | Base data directory |
| `AGENTPROOFS_AGENT_ID` | `claude-code` | Agent identifier |
| `AGENTPROOFS_NAMESPACE` | `default` | Default namespace |
| `AGENTPROOFS_REDACTION_LEVEL` | `0` | Privacy level (0-3) |
| `AGENTPROOFS_SEGMENT_SIZE` | `10000` | Max proofs per segment |

## Development

```bash
# Install
npm install

# Test
npm test

# Build
npm run build

# Type check
npm run typecheck
```

## License

MIT

# agentproofs

Trust, observability, and cost attribution for AI agents. Prove what your agents did — and whether it was worth it.

## Two layers, one platform

| Layer | Question | Module |
|-------|----------|--------|
| **Trust** | Did the agent do what it claimed? | Proof chain (Ed25519 signed, hash-linked) |
| **Observability** | Was it worth the money? | AgentTrace (decision trees, cost attribution) |

```
Your agents spent $8.14. Here's what was worth it.

  Effective spend:  $4.72 (58%)
  Identified waste: $3.42 (42%)

  [WARNING] Research Agent read 12 irrelevant files (-$0.89, 85% confidence)
  > Action: Add "focus on src/auth/" to agent prompt. Saves ~$4.45/week.
```

Every action is also cryptographically signed and hash-chained. Modify, delete, or insert any record and the chain breaks.

## Quick start

```bash
# Initialize (generates Ed25519 keypair + data directory)
npx agentproofs init

# Install auto-capture hooks for Claude Code
npx agentproofs install-hooks

# Use Claude Code normally — every tool call is captured and traced

# See what happened (tamper-evident)
npx agentproofs tail

# Verify nothing was tampered with
npx agentproofs verify

# See where your tokens went
npx agentproofs trace <session.jsonl> --project my-app
```

## Layer 1: Proof Chain (Trust)

Your AI agent just modified 200 files, ran 50 shell commands, and made 12 architectural decisions. Your team lead asks: *"What exactly did the AI do?"*

Without agentproofs: you scroll through terminal history and hope nothing got lost.

With agentproofs: every action is cryptographically signed and hash-chained.

```
Proof 1: { event: "Bash: npm install", hash: a3f... }
    | prev_hash: a3f...
Proof 2: { event: "Write: src/server.ts", hash: 7c1... }
    | prev_hash: 7c1...
Proof 3: { event: "Decision: use JWT", hash: e9b... }
```

Tamper with Proof 2? Its hash changes. Proof 3's `prev_hash` no longer matches. Chain broken. Tampering detected.

### How is this different from just logging?

A log file is a text file. Anyone with write access can edit it, and you'd never know.

agentproofs creates a **hash chain**: each proof contains the hash of the previous one. Change anything and every subsequent hash becomes invalid. On top of that, every entry is **signed with Ed25519** — so you can prove which agent created which proof.

### What it looks like

**`npx agentproofs tail`**:
```
     1 ✓ 2026-04-06 11:29:00 session_started "Session started"
     2 ✓ 2026-04-06 11:29:00 tool_started Bash "npm install express"
     3 ✓ 2026-04-06 11:29:00 tool_completed Bash "npm install express" 4200ms
     4 ✓ 2026-04-06 11:29:00 tool_completed Write "create src/server.ts" 30ms
     5 ✓ 2026-04-06 11:29:00 decision "Use JWT over session cookies"
     6 ✗ 2026-04-06 11:29:00 tool_failed Bash "npm test" 8500ms
     7 ✓ 2026-04-06 11:29:00 tool_completed Edit "fix test assertions" 10ms
     8 ✓ 2026-04-06 11:29:00 tool_completed Bash "npm test" 7200ms
```

**`npx agentproofs verify`**:
```
✓ Chain valid: 8 proofs verified
  Trust level: L0 (local, key integrity assumed)
  No tampering detected.
```

## Layer 2: AgentTrace (Observability)

Existing tools (LangSmith, Langfuse, Helicone) trace **LLM calls** — prompt in, completion out. AgentTrace traces **agent decisions** — why an agent chose tool X over tool Y, where tokens were wasted, and which delegations were worth the money.

### Decision tree, not call log

```
Session ($1.97, 42% waste)
├── Research Agent ($0.54, 55% waste)
│   ├── Read package.json — dead_end ($0.03)
│   ├── Read tsconfig.json — dead_end ($0.03)
│   ├── ...6 more irrelevant files...
│   ├── Read auth/middleware.ts — success ($0.03)
│   └── Read auth/providers.ts — success ($0.03)
├── Docs Agent ($0.38, 45% waste)
│   ├── Fetch next-auth.js.org — success ($0.06)
│   ├── Fetch auth0.com/docs — redundant ($0.06)
│   └── ...3 more redundant fetches...
└── Implementation Agent ($0.68, 13% waste)
    ├── Write oauth.ts — success ($0.12)
    ├── Bash: npm test — failure ($0.08)
    ├── Edit oauth.ts — success ($0.11)
    └── Bash: npm test — success ($0.08)
```

### Recommendations with projected savings

Every finding includes:
- **Specific action** to take (not vague advice)
- **Type**: config / prompt / workflow / tool_choice
- **Effort**: trivial / easy / moderate
- **Projected weekly savings** (based on ~5 similar sessions/week)
- **Confidence score** with evidence trail

Mark a recommendation as "applied" and AgentTrace tracks whether your waste actually decreased in subsequent sessions.

### Key features

| Feature | Description |
|---------|-------------|
| **Decision Tree** | Visualize agent reasoning paths, not just API calls |
| **Cost Attribution** | Per-decision and per-agent cost breakdown |
| **Waste Detection** | Dead-end exploration, retry loops, redundant work |
| **Confidence Scores** | Every finding has a confidence score + evidence |
| **Recommendations** | Specific actions with effort level and projected savings |
| **Before/After Tracking** | Mark as applied, measure real savings over time |
| **Zero-Code Integration** | Claude Code hook auto-traces every session |

## Who is this for?

- **Developers spending $100+/month on AI agents** who want to know where the money goes
- **Teams using AI agents** who need accountability for what the AI did
- **Regulated industries** that need audit trails (finance, healthcare, legal)
- **Security-conscious developers** who want tamper-evident logs
- **Companies preparing for EU AI Act** (Articles 12/19 logging obligations)

## Architecture

```
packages/
  Proof chain:  hooks → daemon → JSONL segments (signed, hash-linked)
  AgentTrace:   session logs → parser → decision tree → waste analysis → recommendations
  Dashboard:    proof viewer + cost summary + agent breakdown + insights panel
```

### Proof chain internals

```
Hooks/SDK  →  Unix socket  →  Daemon (single writer)  →  JSONL segments
                                |— assign sequence
                                |— compute canonical hash
                                |— sign (Ed25519)
                                |— append + fsync
```

### AgentTrace internals

```
Session JSONL  →  Parser  →  Decision tree  →  Waste analyzer  →  Insights
                                |— token attribution per decision
                                |— delegation tree nesting
                                |— cost calculation (Anthropic/OpenAI/Google pricing)
```

### Model pricing built-in

- **Anthropic**: Claude Opus 4.6, Sonnet 4.6, Haiku 4.5
- **OpenAI**: GPT-5.3, GPT-5.3-Codex, o3
- **Google**: Gemini 2.5 Pro, Gemini 2.5 Flash

## Privacy

| Data | Stored? | How |
|------|---------|-----|
| Tool name | Yes | Plain text |
| Input content | **No** | Only SHA-256 hash (proof chain) |
| Output content | **No** | Only SHA-256 hash (proof chain) |
| Token counts | Yes | Per-decision attribution (trace) |
| Cost data | Yes | Calculated from token counts |
| Summaries | Optional | Opt-in per event |

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
| `export [options]` | Export proofs for audit |
| `trace <file>` | Parse session and generate cost report |
| `pubkey` | Print public key (share with auditors) |

### Query filters

```bash
npx agentproofs query --tool Bash          # by tool
npx agentproofs query --failed             # only failures
npx agentproofs query --type decision      # by event type
npx agentproofs query --from 2026-04-01    # by date
npx agentproofs query --namespace my-app   # by project
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

## EU AI Act

agentproofs is designed to support the logging and traceability obligations under EU AI Act Articles 12 and 19. It is **not** a compliance certification — compliance depends on the risk classification of your specific use case. agentproofs provides the mechanism; the obligation depends on classification.

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `AGENTPROOFS_DATA_DIR` | `~/.agentproofs/` | Data directory |
| `AGENTPROOFS_AGENT_ID` | `claude-code` | Agent identifier |
| `AGENTPROOFS_NAMESPACE` | `default` | Default namespace |
| `AGENTPROOFS_REDACTION_LEVEL` | `0` | Privacy level (0-3) |

## Development

```bash
npm install
npm test          # 243 tests
npm run build     # TypeScript → dist/
npm run typecheck # Type verification
```

## License

MIT

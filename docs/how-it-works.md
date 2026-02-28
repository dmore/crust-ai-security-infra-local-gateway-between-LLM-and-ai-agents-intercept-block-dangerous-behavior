# How It Works

## Architecture

```text
                    REQUEST SIDE                         RESPONSE SIDE
                         │                                    │
Agent Request ──▶ [Layer 0: History Scan] ──▶ LLM ──▶ [Layer 1: Rules] ──▶ Execute
                         │                                    │
                      ↓ BLOCK                              ↓ BLOCK
                   (14-30μs)                             (14-30μs)
               "Bad agent detected"                   "Action blocked"

Layer 1 Rule Evaluation (16 steps):
  1.  Sanitize tool name → strip null bytes, control chars
  2.  Extract paths, commands, content from tool arguments
  3.  Normalize Unicode → NFKC, strip invisible chars and confusables
  4.  Block null bytes in write content
  5.  Detect encoding obfuscation (base64, hex)
  6.  Block evasive commands (fork bombs, unparseable shell)
  7.  Self-protection → block management API access (hardcoded)
  8.  Block management API via Unix socket / named pipe
  9.  DLP Secret Detection → block real API keys/tokens
  10. Filter bare shell globs (not real paths)
  11. Normalize paths → expand ~, env vars
  12. Expand globs against real filesystem
  13. Block /proc access (hardcoded)
  14. Resolve symlinks → match both original and resolved
  15. Operation-based rules → path/command/host matching
  16. Fallback rules (content-only) → raw JSON matching for ANY tool
```

**Layer 0 (Request History):** Scans tool_calls in conversation history. Catches "bad agent" patterns where malicious actions already occurred in past turns.

**Layer 1 (Response Rules):** Scans LLM-generated tool_calls in responses. Fast pattern matching with friendly error messages.

**[MCP Gateway](mcp.md) (`crust mcp-gateway`):** Wraps [MCP](https://modelcontextprotocol.io) servers as a transparent stdio proxy. Inspects both directions — client→server requests (`tools/call`, `resources/read`) and server→client responses (DLP secret scanning). Works with any MCP server (filesystem, database, custom).

**[ACP Mode](acp.md) (`crust acp-wrap`):** Wraps [ACP](https://agentclientprotocol.com) agents as a transparent stdio proxy. Intercepts `fs/read_text_file`, `fs/write_text_file`, and `terminal/create` requests. Supports JetBrains IDEs and other ACP-compatible editors.

**Auto-detect (`crust wrap`):** Inspects both MCP and ACP methods in both directions. Response DLP scans all server responses for leaked secrets. Method names are disjoint — no conflict.

---

## Rule Schema (Progressive Disclosure)

```yaml
# Level 1: One-liner
- block: "**/.env"

# Level 2: With exceptions
- block: "**/.env"
  except: "**/.env.example"

# Level 3: With actions
- block: "/etc/**"
  actions: [delete]
  message: "Cannot delete system files"

# Level 4: Advanced match
- name: block-proc-access
  match:
    path: "re:/proc/\\d+/environ"
    tool: [Bash, Read]

# Level 5: Composite (AND/OR)
- name: block-symlink-bypass
  all:
    - command: "re:ln\\s+-s"
    - path: "/etc/**"

# Fallback Rules (Content-only) - matches ANY tool including MCP
- name: block-domain
  match:
    content: "malicious.com"  # Matches raw JSON args
  message: "Cannot access malicious.com"
```

---

## When Each Layer Blocks

| Attack | Layer 0 | Layer 1 | MCP Gateway | ACP Mode |
|--------|---------|---------|-------------|----------|
| Bad agent with secrets in history | ✅ Blocked | - | - | - |
| Poisoned conversation replay | ✅ Blocked | - | - | - |
| LLM generates `cat .env` | - | ✅ Blocked | - | - |
| LLM generates `rm -rf /etc` | - | ✅ Blocked | - | - |
| `$(cat .env)` obfuscation | - | ✅ Blocked | - | - |
| `eval "cat .env"` wrapping | - | ✅ Blocked (recursive parse) | - | - |
| Fork bomb `f(){ f|f& }; f` | - | ✅ Blocked (AST) | - | - |
| `echo payload \| base64 -d \| sh` | - | ✅ Blocked (pre-filter) | - | - |
| Hex-encoded command `$'\x63\x61\x74'` | - | ✅ Blocked (pre-filter) | - | - |
| Symlink bypass | - | ✅ Blocked (composite) | - | - |
| Leaking real API keys/tokens | - | ✅ Blocked (DLP) | ✅ Blocked (DLP) | ✅ Blocked (DLP) |
| MCP client reads `.env` | - | - | ✅ Blocked (inbound) | - |
| MCP client reads SSH keys | - | - | ✅ Blocked (inbound) | - |
| MCP `resources/read file:///etc/shadow` | - | - | ✅ Blocked (inbound) | - |
| MCP server returns API keys in results | - | - | ✅ Blocked (response DLP) | - |
| MCP server returns tokens in results | - | - | ✅ Blocked (response DLP) | - |
| ACP agent reads `.env` via IDE | - | - | - | ✅ Blocked |
| ACP agent reads SSH keys via IDE | - | - | - | ✅ Blocked |
| ACP agent runs `cat /etc/shadow` | - | - | - | ✅ Blocked |

---

## Shell Command Analysis

The rule engine uses a hybrid interpreter+AST approach to extract paths and operations from shell commands (Bash tool calls, `sh -c` wrappers, etc.).

**Interpreter mode:** A sandboxed shell interpreter expands variables, command substitutions, and tilde/glob patterns in dry-run mode. This produces fully expanded paths — `DIR=/tmp; ls $DIR` yields `/tmp`, not `$DIR`.

**AST fallback:** When a statement contains constructs unsafe for interpretation (process substitution `<()`, background `&`, heredocs, coprocs, fd redirects), the parser falls back to AST extraction which reads literal text from the syntax tree.

**Hybrid mode:** When a script mixes safe and unsafe statements, the engine runs the interpreter on safe statements (preserving variable expansion) and uses AST fallback only for unsafe ones. Inner commands of process substitutions and coprocs are recursively interpreted when possible.

```text
DIR=/tmp; diff <(ls $DIR) <(ls $DIR/sub)

Without hybrid:  diff, ls (literal — $DIR unexpanded)
With hybrid:     diff, ls /tmp, ls /tmp/sub (fully expanded)
```

### Evasion Detection

The shell parser detects several evasion techniques at the AST level:

| Technique | Detection |
|-----------|-----------|
| **Fork bombs** | AST walk detects self-recursive `FuncDecl` (e.g., `bomb(){ bomb\|bomb& }; bomb`) |
| **Eval wrapping** | `eval` args are joined and recursively parsed as shell code (like `sh -c`) |
| **Base64 encoding** | Pre-filter regex catches `base64 -d` / `base64 --decode` patterns |
| **Hex encoding** | Pre-filter catches 3+ consecutive `\xNN` escape sequences |

The pre-filter runs before the shell parser (step 5) and catches encoding-based obfuscation where the actual command is hidden in encoded form — invisible to the parser at parse time. Other evasion techniques (fork bombs, eval) are detected at the AST level (step 6) after parsing.

---

## DLP Secret Detection

Step 9 of the evaluation pipeline runs hardcoded DLP (Data Loss Prevention) patterns against all operations. These patterns detect real API keys and tokens by their format, regardless of file path or tool name.

In stdio proxy modes (MCP Gateway, ACP Wrap, Auto-detect), DLP also scans **server/agent responses** before they reach the client. This catches secrets leaked by the subprocess — for example, an MCP server returning file content that contains an AWS access key. The response is replaced with a JSON-RPC error so the secret never reaches the client.

| Provider | Pattern |
|----------|---------|
| AWS | Access key IDs (`AKIA...`, `ASIA...`) |
| GitHub | Personal access tokens, fine-grained tokens (`ghp_...`, `github_pat_...`) |
| GitLab | Personal access tokens (`glpat-...`) |
| Slack | Bot/app tokens, webhook URLs |
| Stripe | Live keys, webhook signing secrets (`sk_live_...`, `whsec_...`) |
| Google | API keys (`AIza...`) |
| SendGrid | API keys (`SG....`) |
| Heroku | API keys (`heroku_...`) |
| OpenAI | Project keys (`sk-proj-...`) |
| Anthropic | API keys (`sk-ant-api03-...`) |
| Shopify | Shared secrets, access tokens (`shpss_...`, `shpat_...`) |
| Databricks | Access tokens (`dapi...`) |
| PyPI | Upload tokens (`pypi-...`) |
| npm | Auth tokens (`npm_...`) |
| age | Secret keys (`AGE-SECRET-KEY-...`) |

Patterns are sourced from [gitleaks v8.24](https://github.com/gitleaks/gitleaks), curated for blocking (not warning). See `internal/rules/dlp.go` for the full list.

In addition, [gitleaks](https://github.com/gitleaks/gitleaks) is used as a secondary scanner if installed, providing coverage for additional token formats beyond the hardcoded set.

---

## Built-in Rule Principles

1. **Protect secrets first** - Credentials are the #1 target; block all access paths
2. **Prevent persistence** - Stop attackers from surviving reboots (cron, systemd, RC files)
3. **Block lateral movement** - Internal networks, cloud metadata, container escapes
4. **Allow legitimate dev work** - Never block normal coding tasks; use exceptions for `.example` files
5. **Fail safe** - When in doubt, block and explain why

---

## Protection Categories (Examples)

The rule engine can protect against various attack vectors:

| Category | Examples |
|----------|----------|
| Credentials | .env, SSH keys, cloud creds, tokens, DLP secret detection |
| System | `/etc/passwd`, `/etc/shadow`, binaries, kernel modules, boot |
| Persistence | Shell RC, cron, systemd, git hooks |
| Privilege Escalation | Sudoers, PAM, LD_PRELOAD |
| Container Escape | Docker/containerd sockets |
| Network | Internal networks, cloud metadata |

See `internal/rules/builtin/security.yaml` for actual built-in rules.


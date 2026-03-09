# MCP Gateway

Crust can secure MCP servers via stdio proxy (`crust mcp gateway`) or HTTP reverse proxy (`crust mcp http`).

## Stdio Gateway

Wrap any [MCP](https://modelcontextprotocol.io) server as a transparent stdio proxy — intercepting requests in both directions and scanning responses for leaked secrets.

```bash
crust mcp gateway -- npx -y @modelcontextprotocol/server-filesystem /path/to/dir
```

### How It Works

```text
MCP Client (Claude Desktop, IDE, etc.)
  │ stdin/stdout (JSON-RPC 2.0)
  ▼
┌──────────────────────────────────────┐
│         crust mcp gateway            │
│                                      │
│  Client→Server (inbound):            │
│    ├─ tools/call      → Evaluate     │
│    ├─ resources/read  → Evaluate     │
│    └─ everything else → pass         │
│                                      │
│  Server→Client (outbound):           │
│    ├─ responses       → DLP scan     │
│    ├─ server requests → Evaluate     │
│    └─ everything else → pass         │
│                                      │
│  BLOCKED → JSON-RPC error            │
│  ALLOWED → forward unchanged         │
└──────────────────────────────────────┘
  │ stdin/stdout
  ▼
Real MCP Server (filesystem, database, etc.)
```

## HTTP Gateway (Streamable HTTP)

For remote MCP servers that expose an HTTP endpoint ([MCP Streamable HTTP transport](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports)):

```bash
crust mcp http --upstream https://mcp-server.example.com/mcp
```

### How It Works

```text
MCP Client (Claude Desktop, VS Code, etc.)
  │ HTTP (JSON-RPC 2.0 over POST/GET/DELETE)
  ▼
┌──────────────────────────────────────┐
│         crust mcp http               │
│                                      │
│  POST (Client→Server requests):      │
│    ├─ tools/call      → Evaluate     │
│    ├─ resources/read  → Evaluate     │
│    └─ everything else → proxy        │
│                                      │
│  POST response (Server→Client):      │
│    ├─ JSON response   → DLP scan     │
│    ├─ SSE stream      → per-event    │
│    └─ errors          → transparent  │
│                                      │
│  GET SSE (Server notifications):     │
│    ├─ server requests → Evaluate     │
│    ├─ responses       → DLP scan     │
│    └─ everything else → proxy        │
│                                      │
│  DELETE → proxy + session cleanup    │
│                                      │
│  BLOCKED → JSON-RPC error (-32001)   │
│  ALLOWED → forward unchanged         │
└──────────────────────────────────────┘
  │ HTTP
  ▼
Remote MCP Server (https://...)
```

### CSRF Protection

The HTTP gateway validates `Origin` and `Sec-Fetch-Site` headers on all requests — including WebSocket upgrades — blocking cross-origin browser requests per the [MCP spec security requirements](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports). This prevents browser CSRF attacks (CVE-2025-49596) and WebSocket hijack attacks (CVE-2026-25253) where a malicious website connects to a local server. Non-browser clients (MCP SDKs, CLI tools) don't send `Origin` and are unaffected.

### WebSocket Proxy

<!-- nosemgrep: javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket -->
The HTTP gateway transparently proxies WebSocket upgrade requests to the upstream server. Origin validation is applied before the upgrade handshake, blocking cross-origin browser connections while allowing legitimate local clients. Supports both `ws://` and `wss://` (TLS) upstream servers.

### Session Management

The gateway proxies `Mcp-Session-Id` headers bidirectionally and tracks active sessions. When a client sends a DELETE request, the gateway forwards it to the upstream server and cleans up the local session.

## Common

### Prerequisites

1. **Crust** installed and on your `PATH`
2. **An MCP server** — any server that speaks [MCP](https://modelcontextprotocol.io) over stdio or HTTP

### Supported MCP Servers

Any MCP server works. Common examples:

| Server | Install | Command |
|--------|---------|---------|
| [Filesystem](https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem) | `npm i -g @modelcontextprotocol/server-filesystem` | `npx @modelcontextprotocol/server-filesystem /path` |
| [Everything](https://github.com/modelcontextprotocol/servers/tree/main/src/everything) | `npm i -g @modelcontextprotocol/server-everything` | `npx @modelcontextprotocol/server-everything` |
| [PostgreSQL](https://github.com/modelcontextprotocol/servers/tree/main/src/postgres) | `npm i -g @modelcontextprotocol/server-postgres` | `npx @modelcontextprotocol/server-postgres $DATABASE_URL` |
| Custom server | — | Any command that speaks MCP over stdio or HTTP |

### Inspection

Crust inspects both directions:

- **Inbound (Client→Server):** Evaluates `tools/call` and `resources/read` requests against path rules, DLP patterns, and content matching. Tool arguments are extracted using **shape-based detection** — any tool with a `path` field is treated as file access, regardless of the tool name.
- **Outbound (Server→Client):** Scans server responses for leaked secrets using DLP patterns. If a server returns file content containing API keys or tokens, the response is blocked before it reaches the client.

Allowed messages pass through byte-for-byte unchanged. Blocked messages receive a JSON-RPC error response with code `-32001` and a `[Crust]`-prefixed message explaining the block reason and a "Do not retry" directive.

### Claude Desktop

Add Crust as a wrapper in your Claude Desktop MCP config (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "crust",
      "args": ["mcp", "gateway", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/you/projects"]
    }
  }
}
```

### Auto-discover and Patch

`crust mcp discover` scans known IDE/client config files and can automatically patch them to route stdio MCP servers through `crust wrap`.

```bash
# Scan and display discovered MCP servers
crust mcp discover

# Patch configs to route through crust wrap
crust mcp discover --patch

# Undo all patches (restore from backups)
crust mcp discover --restore

# Machine-readable output
crust mcp discover --json
```

Supported clients: Claude Desktop, Cursor, Windsurf, Claude Code, Neovim (mcphub).

When the Crust daemon starts (`crust start`), it automatically patches these configs and restores them on `crust stop`. The `mcp discover` command is useful for manual control outside the daemon lifecycle.

**Crash resilience:** `crust wrap` runs independently of the daemon — it spawns the child process directly and inspects stdio in-process. If the Crust daemon crashes, wrapped MCP servers continue working with security rules still enforced.

### Auto-detect Mode

If you don't know whether a subprocess speaks MCP or ACP, use `crust wrap`:

```bash
crust wrap -- npx -y @modelcontextprotocol/server-filesystem /path/to/dir
```

This inspects both MCP (inbound) and ACP (outbound) methods simultaneously. Since the method names are disjoint, there is no conflict.

### What Gets Blocked

The same rules apply as the HTTP gateway and ACP modes. Security-relevant tool calls are evaluated against path rules, DLP patterns, and content matching:

**Inbound (Client→Server):**

| Scenario | Result |
|----------|--------|
| `tools/call read_text_file /app/main.go` | Allowed |
| `tools/call read_text_file /app/.env` | Blocked — `.env` files contain secrets |
| `tools/call write_file /app/.env` | Blocked — cannot write to `.env` |
| `tools/call read_text_file ~/.ssh/id_rsa` | Blocked — SSH private keys |
| `resources/read file:///etc/shadow` | Blocked — system auth files |
| `tools/call list_directory /app/src` | Allowed |
| `initialize`, `tools/list`, notifications | Passed through unchanged |

**Outbound (Server→Client) — Response DLP:**

| Scenario | Result |
|----------|--------|
| Server returns file content with no secrets | Allowed |
| Server returns content with AWS key (`AKIA...`) | Blocked — DLP detects API key |
| Server returns content with GitHub token (`ghp_...`) | Blocked — DLP detects token |
| Server returns content with Stripe key (`sk_live_...`) | Blocked — DLP detects secret |

## CLI Reference

### `mcp gateway` (stdio)

```bash
crust mcp gateway [flags] -- <mcp-server-command> [args...]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `~/.crust/config.yaml` | Path to configuration file |
| `--rules-dir` | `~/.crust/rules/` | Directory for custom rules |
| `--log-level` | `warn` | Log level (`trace`, `debug`, `info`, `warn`, `error`) |
| `--disable-builtin` | `false` | Disable built-in security rules (locked rules remain active) |

Logs go to stderr so they don't interfere with the JSON-RPC stdio stream.

### `mcp http` (Streamable HTTP)

```bash
crust mcp http --upstream <url> [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--upstream` | (required) | Upstream MCP server URL |
| `--listen` | `127.0.0.1:9091` | Local listen address |
| `--config` | `~/.crust/config.yaml` | Configuration file |
| `--rules-dir` | `~/.crust/rules/` | Custom rules directory |
| `--log-level` | `warn` | Log level |
| `--disable-builtin` | `false` | Disable built-in rules |

### `mcp discover`

```bash
crust mcp discover [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Output as JSON |
| `--patch` | `false` | Patch configs to route through `crust wrap` |
| `--restore` | `false` | Restore configs from backups |

Scans the following config files:

| Client | Config Path (macOS) |
|--------|-------------------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Cursor | `~/.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Claude Code | `~/.claude.json` |
| Neovim (mcphub) | `~/.config/mcphub/servers.json` |

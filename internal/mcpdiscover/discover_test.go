package mcpdiscover

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFixture(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDiscoverWithClients_StdioServer(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "config.json", `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user"],
				"env": {"NODE_ENV": "production"}
			}
		}
	}`)

	clients := []clientDef{{
		Client:     ClientCursor,
		ConfigPath: func() string { return path },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	}}

	result := DiscoverWithClients(clients)
	if len(result.Errors) > 0 {
		t.Fatalf("unexpected errors: %v", result.Errors)
	}
	if len(result.Servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(result.Servers))
	}

	srv := result.Servers[0]
	if srv.Name != "filesystem" {
		t.Errorf("name = %q, want %q", srv.Name, "filesystem")
	}
	if srv.Client != ClientCursor {
		t.Errorf("client = %q, want %q", srv.Client, ClientCursor)
	}
	if srv.Transport != TransportStdio {
		t.Errorf("transport = %q, want %q", srv.Transport, TransportStdio)
	}
	if srv.Command != "npx" {
		t.Errorf("command = %q, want %q", srv.Command, "npx")
	}
	if len(srv.Args) != 3 || srv.Args[0] != "-y" {
		t.Errorf("args = %v, want [-y @modelcontextprotocol/server-filesystem /home/user]", srv.Args)
	}
	if srv.Env["NODE_ENV"] != "production" {
		t.Errorf("env NODE_ENV = %q, want %q", srv.Env["NODE_ENV"], "production")
	}
	if srv.AlreadyWrapped {
		t.Error("should not be marked as wrapped")
	}
}

func TestDiscoverWithClients_HTTPServer(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "config.json", `{
		"mcpServers": {
			"remote": {
				"url": "https://mcp.example.com/sse"
			}
		}
	}`)

	clients := []clientDef{{
		Client:     ClientClaudeDesktop,
		ConfigPath: func() string { return path },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url", "serverUrl"},
	}}

	result := DiscoverWithClients(clients)
	if len(result.Servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(result.Servers))
	}

	srv := result.Servers[0]
	if srv.Transport != TransportHTTP {
		t.Errorf("transport = %q, want %q", srv.Transport, TransportHTTP)
	}
	if srv.URL != "https://mcp.example.com/sse" {
		t.Errorf("url = %q", srv.URL)
	}
}

func TestDiscoverWithClients_ServerUrl(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "config.json", `{
		"mcpServers": {
			"windsurf-remote": {
				"serverUrl": "https://mcp.windsurf.example.com"
			}
		}
	}`)

	clients := []clientDef{{
		Client:     ClientWindsurf,
		ConfigPath: func() string { return path },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url", "serverUrl"},
	}}

	result := DiscoverWithClients(clients)
	if len(result.Servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(result.Servers))
	}
	if result.Servers[0].URL != "https://mcp.windsurf.example.com" {
		t.Errorf("url = %q", result.Servers[0].URL)
	}
}

func TestDiscoverWithClients_MixedServers(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "config.json", `{
		"mcpServers": {
			"local": {
				"command": "python",
				"args": ["server.py"]
			},
			"remote": {
				"url": "https://mcp.example.com"
			}
		}
	}`)

	clients := []clientDef{{
		Client:     ClientClaudeCode,
		ConfigPath: func() string { return path },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	}}

	result := DiscoverWithClients(clients)
	if len(result.Servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(result.Servers))
	}

	var stdio, http int
	for _, s := range result.Servers {
		switch s.Transport {
		case TransportStdio:
			stdio++
		case TransportHTTP:
			http++
		}
	}
	if stdio != 1 || http != 1 {
		t.Errorf("expected 1 stdio + 1 http, got %d stdio + %d http", stdio, http)
	}
}

func TestDiscoverWithClients_AlreadyWrapped(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "config.json", `{
		"mcpServers": {
			"wrapped": {
				"command": "/usr/local/bin/crust",
				"args": ["wrap", "--", "npx", "server"]
			}
		}
	}`)

	clients := []clientDef{{
		Client:     ClientCursor,
		ConfigPath: func() string { return path },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	}}

	result := DiscoverWithClients(clients)
	if len(result.Servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(result.Servers))
	}
	if !result.Servers[0].AlreadyWrapped {
		t.Error("should be marked as already wrapped")
	}
}

func TestDiscoverWithClients_MissingFile(t *testing.T) {
	clients := []clientDef{{
		Client:     ClientCursor,
		ConfigPath: func() string { return "/nonexistent/path/config.json" },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	}}

	result := DiscoverWithClients(clients)
	if len(result.Servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(result.Servers))
	}
	if len(result.Errors) != 0 {
		t.Errorf("missing file should not produce errors, got %v", result.Errors)
	}
}

func TestDiscoverWithClients_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "config.json", `{invalid}`)

	clients := []clientDef{{
		Client:     ClientCursor,
		ConfigPath: func() string { return path },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	}}

	result := DiscoverWithClients(clients)
	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(result.Errors))
	}
	if result.Errors[0].Client != ClientCursor {
		t.Errorf("error client = %q, want %q", result.Errors[0].Client, ClientCursor)
	}
}

func TestDiscoverWithClients_EmptyServers(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "config.json", `{"mcpServers": {}}`)

	clients := []clientDef{{
		Client:     ClientCursor,
		ConfigPath: func() string { return path },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	}}

	result := DiscoverWithClients(clients)
	if len(result.Servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(result.Servers))
	}
}

func TestDiscoverWithClients_NoServersKey(t *testing.T) {
	dir := t.TempDir()
	path := writeFixture(t, dir, "config.json", `{"otherKey": "value"}`)

	clients := []clientDef{{
		Client:     ClientCursor,
		ConfigPath: func() string { return path },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	}}

	result := DiscoverWithClients(clients)
	if len(result.Servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(result.Servers))
	}
}

func TestDiscoverWithClients_EmptyConfigPath(t *testing.T) {
	clients := []clientDef{{
		Client:     ClientCursor,
		ConfigPath: func() string { return "" },
		ServersKey: "mcpServers",
		URLKeys:    []string{"url"},
	}}

	result := DiscoverWithClients(clients)
	if len(result.Servers) != 0 {
		t.Errorf("expected 0 servers, got %d", len(result.Servers))
	}
}

func TestIsCrustWrapped(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		args []string
		want bool
	}{
		{"crust binary", "/usr/local/bin/crust", nil, true},
		{"crust.exe binary", `C:\Program Files\crust.exe`, nil, true},
		{"wrap arg", "node", []string{"wrap", "--", "server.js"}, true},
		{"mcp-gateway arg", "something", []string{"mcp-gateway"}, true},
		{"gateway arg", "something", []string{"mcp", "gateway"}, true},
		{"wrap after --", "node", []string{"--", "wrap"}, false},
		{"unrelated", "npx", []string{"-y", "server"}, false},
		{"empty", "", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isCrustWrapped(tt.cmd, tt.args); got != tt.want {
				t.Errorf("isCrustWrapped(%q, %v) = %v, want %v", tt.cmd, tt.args, got, tt.want)
			}
		})
	}
}

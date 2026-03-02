package mcpgateway

import (
	"testing"
)

// --- Edge-case blocking (malformed inputs, resources/read) ---
// Path-based blocking, passthrough, batch handling, error shapes, and DLP are
// covered by jsonrpc/proxy_test.go (unit) and stdio_e2e_test.go (real MCP server).
// These tests verify MCP-specific converter edge cases in the full pipeline.

func TestPipeClientToServer_BlocksEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		msg  string
	}{
		{"resource_env_read", `{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"file:///app/.env"}}`},
		{"malformed_tools_call", `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":"not-an-object"}`},
		{"null_params", `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":null}`},
		{"empty_tool_name", `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"","arguments":{}}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwd, errOut := runPipe(t, tt.msg+"\n")
			if fwd != "" {
				t.Errorf("server should not receive blocked request, got: %s", fwd)
			}
			if errOut == "" {
				t.Error("client should receive an error response")
			}
		})
	}
}

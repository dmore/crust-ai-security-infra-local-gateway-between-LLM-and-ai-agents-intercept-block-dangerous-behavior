package mcpgateway

import (
	"encoding/json"
	"testing"

	"github.com/BakeLens/crust/internal/jsonrpc"
	"github.com/BakeLens/crust/internal/testutil"
)

func TestInspectRequest_AllowedToolCall(t *testing.T) {
	engine := testutil.NewEngine(t)
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"read_text_file","arguments":{"path":"/tmp/safe.txt"}}`),
	}
	result := InspectRequest(engine, msg)
	if result.Decision != Forward {
		t.Errorf("expected Forward, got %v (block=%s)", result.Decision, result.BlockMsg)
	}
	if result.ToolName != "read_text_file" {
		t.Errorf("expected ToolName=read_text_file, got %q", result.ToolName)
	}
}

func TestInspectRequest_BlockedEnvFile(t *testing.T) {
	engine := testutil.NewEngine(t)
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`2`),
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"read_text_file","arguments":{"path":"/app/.env"}}`),
	}
	result := InspectRequest(engine, msg)
	if result.Decision != Block {
		t.Errorf("expected Block, got %v", result.Decision)
	}
	if result.BlockMsg == "" {
		t.Error("expected non-empty BlockMsg")
	}
	if result.RuleName == "" {
		t.Error("expected non-empty RuleName")
	}
}

func TestInspectRequest_MalformedParams(t *testing.T) {
	engine := testutil.NewEngine(t)
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`3`),
		Method:  "tools/call",
		Params:  json.RawMessage(`"not-an-object"`),
	}
	result := InspectRequest(engine, msg)
	if result.Decision != Block {
		t.Errorf("expected Block for malformed params, got %v", result.Decision)
	}
}

func TestInspectRequest_NonSecurityMethod(t *testing.T) {
	engine := testutil.NewEngine(t)
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`4`),
		Method:  "tools/list",
		Params:  json.RawMessage(`{}`),
	}
	result := InspectRequest(engine, msg)
	if result.Decision != Forward {
		t.Errorf("expected Forward for tools/list, got %v", result.Decision)
	}
}

func TestInspectRequest_NotificationDLP(t *testing.T) {
	engine := testutil.NewEngine(t)
	// Notification (no ID) with DLP-triggering content in params
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		Method:  "notifications/message",
		Params:  json.RawMessage(`{"message":"key=AKIAIOSFODNN7EXAMPLE"}`),
	}
	result := InspectRequest(engine, msg)
	if result.Decision != Block {
		t.Errorf("expected Block for DLP in notification, got %v", result.Decision)
	}
}

func TestInspectResponse_Clean(t *testing.T) {
	engine := testutil.NewEngine(t)
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Result:  json.RawMessage(`{"content":[{"type":"text","text":"hello world"}]}`),
	}
	result := InspectResponse(engine, msg)
	if result.Decision != Forward {
		t.Errorf("expected Forward for clean response, got %v (block=%s)", result.Decision, result.BlockMsg)
	}
}

func TestInspectResponse_DLPInResult(t *testing.T) {
	engine := testutil.NewEngine(t)
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Result:  json.RawMessage(`{"content":[{"type":"text","text":"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}]}`),
	}
	result := InspectResponse(engine, msg)
	if result.Decision != Block {
		t.Errorf("expected Block for AWS key in result, got %v", result.Decision)
	}
	if result.BlockMsg == "" {
		t.Error("expected non-empty BlockMsg")
	}
}

func TestInspectResponse_DLPInError(t *testing.T) {
	engine := testutil.NewEngine(t)
	msg := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Error:   json.RawMessage(`{"code":-1,"message":"debug: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm"}`),
	}
	result := InspectResponse(engine, msg)
	if result.Decision != Block {
		t.Errorf("expected Block for GitHub token in error, got %v", result.Decision)
	}
}

package autowrap

import (
	"bytes"
	"encoding/json"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/jsonrpc"
	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/mcpgateway"
	"github.com/BakeLens/crust/internal/rules"
)

var testLog = logger.New("wrap-test")

func newTestEngine(t *testing.T) *rules.Engine {
	t.Helper()
	engine, err := rules.NewEngine(rules.EngineConfig{
		UserRulesDir:   t.TempDir(),
		DisableBuiltin: false,
	})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}
	return engine
}

// runInboundPipe runs PipeInspect with MCPMethodToToolCall (inbound direction).
func runInboundPipe(t *testing.T, input string) (fwd, errOut string) {
	t.Helper()
	engine := newTestEngine(t)
	var fwdBuf, errBuf bytes.Buffer
	fwdWriter := jsonrpc.NewLockedWriter(&fwdBuf)
	errWriter := jsonrpc.NewLockedWriter(&errBuf)
	jsonrpc.PipeInspect(testLog, engine, strings.NewReader(input),
		fwdWriter, errWriter, mcpgateway.MCPMethodToToolCall, "MCP", "Inbound")
	return fwdBuf.String(), errBuf.String()
}

// runOutboundPipe runs PipeInspect with BothMethodToToolCall (outbound direction).
func runOutboundPipe(t *testing.T, input string) (fwd, errOut string) {
	t.Helper()
	engine := newTestEngine(t)
	var fwdBuf, errBuf bytes.Buffer
	fwdWriter := jsonrpc.NewLockedWriter(&fwdBuf)
	errWriter := jsonrpc.NewLockedWriter(&errBuf)
	jsonrpc.PipeInspect(testLog, engine, strings.NewReader(input),
		fwdWriter, errWriter, BothMethodToToolCall, "Stdio", "Outbound")
	return fwdBuf.String(), errBuf.String()
}

// --- Inbound (MCP) direction ---

func TestPipeInbound_BlocksMCP(t *testing.T) {
	tests := []struct {
		name string
		msg  string
	}{
		{"env_read", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/app/.env"}}}`},
		{"ssh_key_read", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/home/user/.ssh/id_rsa"}}}`},
		{"resource_env_read", `{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"file:///app/.env"}}`},
		{"malformed_params", `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":"not-an-object"}`},
		{"null_params", `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":null}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwd, errOut := runInboundPipe(t, tt.msg+"\n")
			if fwd != "" {
				t.Errorf("subprocess should not receive blocked request, got: %s", fwd)
			}
			if errOut == "" {
				t.Error("client should receive an error response")
			}
		})
	}
}

func TestPipeInbound_PassesMCP(t *testing.T) {
	tests := []struct {
		name string
		msg  string
	}{
		{"normal_read", `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/app/src/main.go"}}}`},
		{"non_security_method", `{"jsonrpc":"2.0","id":20,"method":"initialize","params":{"capabilities":{}}}`},
		{"tools_list", `{"jsonrpc":"2.0","id":30,"method":"tools/list","params":{}}`},
		{"response", `{"jsonrpc":"2.0","id":5,"result":{"content":"data"}}`},
		{"invalid_json", `not valid json at all`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwd, errOut := runInboundPipe(t, tt.msg+"\n")
			if fwd != tt.msg+"\n" {
				t.Errorf("message should pass through unchanged\ngot:  %q\nwant: %q", fwd, tt.msg+"\n")
			}
			if errOut != "" {
				t.Errorf("client should not receive errors, got: %s", errOut)
			}
		})
	}
}

func TestPipeInbound_ErrorShape(t *testing.T) {
	_, errOut := runInboundPipe(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/app/.env"}}}`+"\n")
	var resp jsonrpc.ErrorResponse
	if err := json.Unmarshal(bytes.TrimSpace([]byte(errOut)), &resp); err != nil {
		t.Fatalf("expected JSON-RPC error, got: %s", errOut)
	}
	if resp.Error.Code != jsonrpc.BlockedError {
		t.Errorf("error code = %d, want %d", resp.Error.Code, jsonrpc.BlockedError)
	}
	if !strings.Contains(resp.Error.Message, "[Crust]") {
		t.Errorf("error message missing [Crust]: %s", resp.Error.Message)
	}
}

// --- Outbound (ACP) direction ---

func TestPipeOutbound_BlocksACP(t *testing.T) {
	tests := []struct {
		name string
		msg  string
	}{
		{"env_read", `{"jsonrpc":"2.0","id":1,"method":"fs/read_text_file","params":{"sessionId":"s1","path":"/app/.env"}}`},
		{"ssh_key_read", `{"jsonrpc":"2.0","id":2,"method":"fs/read_text_file","params":{"sessionId":"s1","path":"/home/user/.ssh/id_rsa"}}`},
		{"env_write", `{"jsonrpc":"2.0","id":3,"method":"fs/write_text_file","params":{"sessionId":"s1","path":"/app/.env","content":"SECRET=abc"}}`},
		{"malformed_params", `{"jsonrpc":"2.0","id":4,"method":"fs/read_text_file","params":"not-an-object"}`},
		{"null_params", `{"jsonrpc":"2.0","id":5,"method":"fs/read_text_file","params":null}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwd, errOut := runOutboundPipe(t, tt.msg+"\n")
			if fwd != "" {
				t.Errorf("client should not receive blocked request, got: %s", fwd)
			}
			if errOut == "" {
				t.Error("subprocess should receive an error response")
			}
		})
	}
}

func TestPipeOutbound_PassesACP(t *testing.T) {
	tests := []struct {
		name string
		msg  string
	}{
		{"normal_read", `{"jsonrpc":"2.0","id":10,"method":"fs/read_text_file","params":{"sessionId":"s1","path":"/app/src/main.go"}}`},
		{"non_security_method", `{"jsonrpc":"2.0","id":20,"method":"session/prompt","params":{"text":"hello"}}`},
		{"response", `{"jsonrpc":"2.0","id":5,"result":{"content":"data"}}`},
		{"invalid_json", `not valid json at all`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwd, errOut := runOutboundPipe(t, tt.msg+"\n")
			if fwd != tt.msg+"\n" {
				t.Errorf("message should pass through unchanged\ngot:  %q\nwant: %q", fwd, tt.msg+"\n")
			}
			if errOut != "" {
				t.Errorf("subprocess should not receive errors, got: %s", errOut)
			}
		})
	}
}

func TestPipeOutbound_ErrorShape(t *testing.T) {
	_, errOut := runOutboundPipe(t, `{"jsonrpc":"2.0","id":1,"method":"fs/read_text_file","params":{"sessionId":"s1","path":"/app/.env"}}`+"\n")
	var resp jsonrpc.ErrorResponse
	if err := json.Unmarshal(bytes.TrimSpace([]byte(errOut)), &resp); err != nil {
		t.Fatalf("expected JSON-RPC error, got: %s", errOut)
	}
	if resp.Error.Code != jsonrpc.BlockedError {
		t.Errorf("error code = %d, want %d", resp.Error.Code, jsonrpc.BlockedError)
	}
	if !strings.Contains(resp.Error.Message, "[Crust]") {
		t.Errorf("error message missing [Crust]: %s", resp.Error.Message)
	}
}

// --- Cross-protocol ---

func TestPipeInbound_IgnoresACPMethods(t *testing.T) {
	// Inbound uses MCPMethodToToolCall only — ACP methods pass through unexamined.
	msg := `{"jsonrpc":"2.0","id":1,"method":"fs/read_text_file","params":{"sessionId":"s1","path":"/app/.env"}}`
	fwd, errOut := runInboundPipe(t, msg+"\n")
	if fwd != msg+"\n" {
		t.Errorf("ACP methods should pass through in inbound direction\ngot:  %q\nwant: %q", fwd, msg+"\n")
	}
	if errOut != "" {
		t.Errorf("should not generate errors for ACP methods in inbound direction, got: %s", errOut)
	}
}

func TestPipeOutbound_BlocksMCPMethods(t *testing.T) {
	// Outbound uses BothMethodToToolCall — MCP methods with sensitive paths are blocked.
	msg := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/app/.env"}}}`
	fwd, errOut := runOutboundPipe(t, msg+"\n")
	if fwd != "" {
		t.Errorf("MCP methods with .env should be blocked on outbound, got forwarded: %s", fwd)
	}
	if errOut == "" {
		t.Error("subprocess should receive an error response for blocked MCP method")
	}
}

// --- Response DLP ---

func TestPipeOutbound_ResponseDLP_BlocksSecrets(t *testing.T) {
	tests := []struct {
		name string
		msg  string
	}{
		{"aws_key", `{"jsonrpc":"2.0","id":1,"result":{"content":"key=AKIAIOSFODNN7EXAMPLE"}}`},
		{"github_token", `{"jsonrpc":"2.0","id":2,"result":{"text":"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm"}}`},
		{"openai_key", `{"jsonrpc":"2.0","id":3,"result":{"config":"sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwd, _ := runOutboundPipe(t, tt.msg+"\n")
			// Response should NOT be forwarded (DLP blocks it)
			if strings.Contains(fwd, "AKIA") || strings.Contains(fwd, "ghp_") || strings.Contains(fwd, "sk-proj-") {
				t.Errorf("response with secret should be blocked by DLP, got forwarded: %s", fwd)
			}
		})
	}
}

func TestPipeOutbound_ResponseDLP_PassesClean(t *testing.T) {
	msg := `{"jsonrpc":"2.0","id":1,"result":{"content":"safe data, no secrets here"}}`
	fwd, _ := runOutboundPipe(t, msg+"\n")
	if fwd != msg+"\n" {
		t.Errorf("clean response should pass through\ngot:  %q\nwant: %q", fwd, msg+"\n")
	}
}

func TestPipeOutbound_ResponseDLP_BlocksErrorFieldSecrets(t *testing.T) {
	tests := []struct {
		name string
		msg  string
	}{
		{"aws_key_in_error", `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"failed to read config: AKIAIOSFODNN7EXAMPLE"}}`},
		{"github_token_in_error", `{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"auth failed: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwd, _ := runOutboundPipe(t, tt.msg+"\n")
			if strings.Contains(fwd, "AKIA") || strings.Contains(fwd, "ghp_") {
				t.Errorf("error response with secret should be blocked by DLP, got forwarded: %s", fwd)
			}
			// fwd should contain a replacement JSON-RPC error from Crust
			var resp jsonrpc.ErrorResponse
			if err := json.Unmarshal(bytes.TrimSpace([]byte(fwd)), &resp); err != nil {
				t.Fatalf("expected JSON-RPC error in fwd, got: %q", fwd)
			}
			if resp.Error.Code != jsonrpc.BlockedError {
				t.Errorf("error code = %d, want %d", resp.Error.Code, jsonrpc.BlockedError)
			}
		})
	}
}

func TestPipeOutbound_ResponseDLP_PassesCleanError(t *testing.T) {
	msg := `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"file not found"}}`
	fwd, _ := runOutboundPipe(t, msg+"\n")
	if fwd != msg+"\n" {
		t.Errorf("clean error response should pass through\ngot:  %q\nwant: %q", fwd, msg+"\n")
	}
}

func TestPipeOutbound_ResponseDLP_ErrorResponseShape(t *testing.T) {
	msg := `{"jsonrpc":"2.0","id":1,"result":{"content":"key=AKIAIOSFODNN7EXAMPLE"}}`
	fwd, _ := runOutboundPipe(t, msg+"\n")
	// fwd should contain a JSON-RPC error (sent to client via fwdWriter)
	var resp jsonrpc.ErrorResponse
	if err := json.Unmarshal(bytes.TrimSpace([]byte(fwd)), &resp); err != nil {
		t.Fatalf("expected JSON-RPC error in fwd, got: %q", fwd)
	}
	if resp.Error.Code != jsonrpc.BlockedError {
		t.Errorf("error code = %d, want %d", resp.Error.Code, jsonrpc.BlockedError)
	}
	if !strings.Contains(resp.Error.Message, "[Crust]") {
		t.Errorf("error message missing [Crust]: %s", resp.Error.Message)
	}
}

// --- Empty lines ---

func TestPipeInbound_EmptyLine(t *testing.T) {
	fwd, _ := runInboundPipe(t, "\n")
	if fwd != "\n" {
		t.Errorf("empty line should pass through, got: %q", fwd)
	}
}

func TestPipeOutbound_EmptyLine(t *testing.T) {
	fwd, _ := runOutboundPipe(t, "\n")
	if fwd != "\n" {
		t.Errorf("empty line should pass through, got: %q", fwd)
	}
}

// --- RunProxy (hang / exit code) ---

func TestRunProxy(t *testing.T) {
	t.Run("no_hang_on_exit", func(t *testing.T) {
		if _, err := exec.LookPath("true"); err != nil {
			t.Skip("'true' not found in PATH")
		}
		engine := newTestEngine(t)
		stdinR, stdinW := io.Pipe()
		defer stdinW.Close()

		done := make(chan int, 1)
		go func() {
			done <- jsonrpc.RunProxy(engine, []string{"true"}, stdinR, &bytes.Buffer{}, jsonrpc.ProxyConfig{
				Log:          testLog,
				ProcessLabel: "Subprocess",
				Inbound:      jsonrpc.PipeConfig{Label: "Inbound", Protocol: "MCP", Convert: mcpgateway.MCPMethodToToolCall},
				Outbound:     jsonrpc.PipeConfig{Label: "Outbound", Protocol: "Stdio", Convert: BothMethodToToolCall},
			})
		}()

		select {
		case code := <-done:
			if code != 0 {
				t.Errorf("exit code = %d, want 0", code)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("RunProxy hung — stdin not closed after subprocess exit")
		}
	})

	t.Run("propagates_exit_code", func(t *testing.T) {
		if _, err := exec.LookPath("false"); err != nil {
			t.Skip("'false' not found in PATH")
		}
		engine := newTestEngine(t)
		stdinR, stdinW := io.Pipe()
		defer stdinW.Close()

		done := make(chan int, 1)
		go func() {
			done <- jsonrpc.RunProxy(engine, []string{"false"}, stdinR, &bytes.Buffer{}, jsonrpc.ProxyConfig{
				Log:          testLog,
				ProcessLabel: "Subprocess",
				Inbound:      jsonrpc.PipeConfig{Label: "Inbound", Protocol: "MCP", Convert: mcpgateway.MCPMethodToToolCall},
				Outbound:     jsonrpc.PipeConfig{Label: "Outbound", Protocol: "Stdio", Convert: BothMethodToToolCall},
			})
		}()

		select {
		case code := <-done:
			if code == 0 {
				t.Error("expected non-zero exit code from 'false'")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("RunProxy hung")
		}
	})
}

// --- Multiple messages ---

func TestPipeInbound_MultipleMessages(t *testing.T) {
	msgs := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/app/.env"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/app/main.go"}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"initialize","params":{"capabilities":{}}}`,
	}, "\n") + "\n"

	fwd, errOut := runInboundPipe(t, msgs)

	fwdLines := strings.Split(strings.TrimRight(fwd, "\n"), "\n")
	if len(fwdLines) != 2 {
		t.Errorf("expected 2 subprocess messages (main.go + initialize), got %d: %v", len(fwdLines), fwdLines)
	}
	if errOut == "" {
		t.Error("client should receive error for .env read")
	}
}

func TestPipeOutbound_MultipleMessages(t *testing.T) {
	msgs := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"fs/read_text_file","params":{"sessionId":"s1","path":"/app/.env"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"fs/read_text_file","params":{"sessionId":"s1","path":"/app/main.go"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"text":"hi"}}`,
	}, "\n") + "\n"

	fwd, errOut := runOutboundPipe(t, msgs)

	fwdLines := strings.Split(strings.TrimRight(fwd, "\n"), "\n")
	if len(fwdLines) != 2 {
		t.Errorf("expected 2 client messages (main.go + prompt), got %d: %v", len(fwdLines), fwdLines)
	}
	if errOut == "" {
		t.Error("subprocess should receive error for .env read")
	}
}

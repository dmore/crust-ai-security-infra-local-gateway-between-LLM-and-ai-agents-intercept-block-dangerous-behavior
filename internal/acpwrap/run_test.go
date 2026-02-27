package acpwrap

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
	"github.com/BakeLens/crust/internal/rules"
)

var testLog = logger.New("acp-test")

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

// runPipe runs PipeInspect with ACPMethodToToolCall and returns what was
// forwarded and what error responses were generated.
func runPipe(t *testing.T, input string) (fwd, errOut string) {
	t.Helper()
	engine := newTestEngine(t)
	var fwdBuf, errBuf bytes.Buffer
	fwdWriter := jsonrpc.NewLockedWriter(&fwdBuf)
	errWriter := jsonrpc.NewLockedWriter(&errBuf)
	jsonrpc.PipeInspect(testLog, engine, strings.NewReader(input),
		fwdWriter, errWriter, ACPMethodToToolCall, "ACP", "Agent->IDE")
	return fwdBuf.String(), errBuf.String()
}

// --- RunProxy (hang / exit code) ---

func TestRunProxy(t *testing.T) {
	t.Run("no_hang_on_agent_exit", func(t *testing.T) {
		if _, err := exec.LookPath("true"); err != nil {
			t.Skip("'true' not found in PATH")
		}
		engine := newTestEngine(t)
		stdinR, stdinW := io.Pipe()
		defer stdinW.Close() // keep write end OPEN to expose the hang bug

		done := make(chan int, 1)
		go func() {
			done <- jsonrpc.RunProxy(engine, []string{"true"}, stdinR, &bytes.Buffer{}, jsonrpc.ProxyConfig{
				Log:          testLog,
				ProcessLabel: "Agent",
				Inbound:      jsonrpc.PipeConfig{Label: "IDE->Agent"},
				Outbound:     jsonrpc.PipeConfig{Label: "Agent->IDE", Protocol: "ACP", Convert: ACPMethodToToolCall},
			})
		}()

		select {
		case code := <-done:
			if code != 0 {
				t.Errorf("exit code = %d, want 0", code)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("RunProxy hung — IDE stdin not closed after agent exit")
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
				ProcessLabel: "Agent",
				Inbound:      jsonrpc.PipeConfig{Label: "IDE->Agent"},
				Outbound:     jsonrpc.PipeConfig{Label: "Agent->IDE", Protocol: "ACP", Convert: ACPMethodToToolCall},
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

// --- PipeInspect + ACPMethodToToolCall integration ---

func TestPipeAgentToIDE_Blocks(t *testing.T) {
	tests := []struct {
		name string
		msg  string
	}{
		{"env_read", `{"jsonrpc":"2.0","id":1,"method":"fs/read_text_file","params":{"sessionId":"s1","path":"/app/.env"}}`},
		{"ssh_key_read", `{"jsonrpc":"2.0","id":2,"method":"fs/read_text_file","params":{"sessionId":"s1","path":"/home/user/.ssh/id_rsa"}}`},
		{"env_write", `{"jsonrpc":"2.0","id":3,"method":"fs/write_text_file","params":{"sessionId":"s1","path":"/app/.env","content":"API_KEY=secret"}}`},
		{"malformed_read_params", `{"jsonrpc":"2.0","id":4,"method":"fs/read_text_file","params":"not-an-object"}`},
		{"malformed_terminal_params", `{"jsonrpc":"2.0","id":5,"method":"terminal/create","params":42}`},
		{"null_params", `{"jsonrpc":"2.0","id":6,"method":"fs/read_text_file","params":null}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwd, errOut := runPipe(t, tt.msg+"\n")
			if fwd != "" {
				t.Errorf("IDE should not receive blocked request, got: %s", fwd)
			}
			if errOut == "" {
				t.Error("agent should receive an error response")
			}
		})
	}
}

func TestPipeAgentToIDE_BlocksEnvRead_ErrorShape(t *testing.T) {
	fwd, errOut := runPipe(t, `{"jsonrpc":"2.0","id":1,"method":"fs/read_text_file","params":{"sessionId":"s1","path":"/app/.env"}}`+"\n")
	if fwd != "" {
		t.Errorf("IDE should not receive blocked request, got: %s", fwd)
	}
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

func TestPipeAgentToIDE_Passes(t *testing.T) {
	tests := []struct {
		name string
		msg  string
	}{
		{"normal_read", `{"jsonrpc":"2.0","id":10,"method":"fs/read_text_file","params":{"sessionId":"s1","path":"/app/src/main.go"}}`},
		{"non_security_method", `{"jsonrpc":"2.0","id":20,"method":"session/prompt","params":{"text":"hello"}}`},
		{"notification", `{"jsonrpc":"2.0","method":"session/update","params":{"status":"working"}}`},
		{"response", `{"jsonrpc":"2.0","id":5,"result":{"content":"file data"}}`},
		{"invalid_json", `not valid json at all`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fwd, errOut := runPipe(t, tt.msg+"\n")
			if fwd != tt.msg+"\n" {
				t.Errorf("message should pass through unchanged\ngot:  %q\nwant: %q", fwd, tt.msg+"\n")
			}
			if errOut != "" {
				t.Errorf("agent should not receive errors, got: %s", errOut)
			}
		})
	}
}

func TestPipeAgentToIDE_EmptyLine(t *testing.T) {
	fwd, _ := runPipe(t, "\n")
	if fwd != "\n" {
		t.Errorf("empty line should pass through, got: %q", fwd)
	}
}

func TestPipeAgentToIDE_MultipleMessages(t *testing.T) {
	msgs := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"fs/read_text_file","params":{"sessionId":"s1","path":"/app/.env"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"fs/read_text_file","params":{"sessionId":"s1","path":"/app/main.go"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"text":"hi"}}`,
	}, "\n") + "\n"

	fwd, errOut := runPipe(t, msgs)

	fwdLines := strings.Split(strings.TrimRight(fwd, "\n"), "\n")
	if len(fwdLines) != 2 {
		t.Errorf("expected 2 IDE messages (main.go + prompt), got %d: %v", len(fwdLines), fwdLines)
	}
	if errOut == "" {
		t.Error("agent should receive error for .env read")
	}
}

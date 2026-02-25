package acpwrap

import (
	"bytes"
	"encoding/json"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/rules"
)

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

// runPipe runs pipeAgentToIDE with the given input and returns what the IDE
// received and what error responses were sent back to the agent.
func runPipe(t *testing.T, input string) (ideOut, agentErr string) {
	t.Helper()
	engine := newTestEngine(t)
	var ideStdout, agentStdinBuf bytes.Buffer
	pipeAgentToIDE(engine, strings.NewReader(input), &ideStdout, &lockedWriter{w: &agentStdinBuf})
	return ideStdout.String(), agentStdinBuf.String()
}

// --- acpMethodToToolCall ---

func TestAcpMethodToToolCall(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		params   string
		wantName string
		wantKey  string
		wantVal  string
	}{
		{"fs_read", "fs/read_text_file", `{"sessionId":"s1","path":"/etc/passwd"}`, "read_file", "path", "/etc/passwd"},
		{"fs_write", "fs/write_text_file", `{"sessionId":"s1","path":"/home/user/.env","content":"SECRET=abc"}`, "write_file", "path", "/home/user/.env"},
		{"terminal", "terminal/create", `{"sessionId":"s1","command":"rm","args":["-rf","/"]}`, "bash", "command", "rm -rf /"},
		{"terminal_no_args", "terminal/create", `{"sessionId":"s1","command":"ls"}`, "bash", "command", "ls"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc, ok, err := acpMethodToToolCall(tt.method, json.RawMessage(tt.params))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !ok {
				t.Fatal("expected security-relevant")
			}
			if tc.Name != tt.wantName {
				t.Errorf("name = %s, want %s", tc.Name, tt.wantName)
			}
			var args map[string]any
			if err := json.Unmarshal(tc.Arguments, &args); err != nil {
				t.Fatal(err)
			}
			if got := args[tt.wantKey]; got != tt.wantVal {
				t.Errorf("%s = %v, want %s", tt.wantKey, got, tt.wantVal)
			}
		})
	}
}

func TestAcpMethodToToolCall_Unknown(t *testing.T) {
	for _, method := range []string{"session/prompt", "initialize", "fs/delete"} {
		_, ok, err := acpMethodToToolCall(method, nil)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", method, err)
		}
		if ok {
			t.Errorf("%s should not be security-relevant", method)
		}
	}
}

func TestAcpMethodToToolCall_MalformedParams(t *testing.T) {
	methods := []string{"fs/read_text_file", "fs/write_text_file", "terminal/create"}
	badInputs := []json.RawMessage{
		json.RawMessage(`{broken`),
		json.RawMessage(`"just a string"`),
		json.RawMessage(`null`),
		json.RawMessage(`42`),
		json.RawMessage(``),
	}
	for _, method := range methods {
		for _, input := range badInputs {
			_, ok, err := acpMethodToToolCall(method, input)
			if !ok {
				t.Errorf("%s with %q: expected ok=true (security-relevant)", method, input)
			}
			if err == nil {
				t.Errorf("%s with %q: expected error for malformed params", method, input)
			}
		}
	}
}

// --- shellQuote ---

func TestShellQuote(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"", "''"},
		{"simple", "simple"},
		{"-rf", "-rf"},
		{"/etc/passwd", "/etc/passwd"},
		{"file with spaces", "'file with spaces'"},
		{"; rm -rf /", "'; rm -rf /'"},
		{"$(whoami)", "'$(whoami)'"},
		{"`id`", "'`id`'"},
		{"it's", "'it'\"'\"'s'"},
		{"a&b", "'a&b'"},
		{"a|b", "'a|b'"},
		{"a>b", "'a>b'"},
		{"a<b", "'a<b'"},
	}
	for _, tt := range tests {
		if got := shellQuote(tt.input); got != tt.want {
			t.Errorf("shellQuote(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestAcpMethodToToolCall_TerminalArgQuoting(t *testing.T) {
	tests := []struct {
		name    string
		params  string
		wantCmd string
	}{
		{"spaces", `{"sessionId":"s1","command":"cp","args":["file with spaces.txt","dest"]}`, "cp 'file with spaces.txt' dest"},
		{"metachar", `{"sessionId":"s1","command":"echo","args":["; rm -rf /"]}`, "echo '; rm -rf /'"},
		{"single_quote", `{"sessionId":"s1","command":"echo","args":["it's"]}`, "echo 'it'\"'\"'s'"},
		{"empty_arg", `{"sessionId":"s1","command":"cmd","args":[""]}`, "cmd ''"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc, _, err := acpMethodToToolCall("terminal/create", json.RawMessage(tt.params))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			var args map[string]string
			if err := json.Unmarshal(tc.Arguments, &args); err != nil {
				t.Fatal(err)
			}
			if args["command"] != tt.wantCmd {
				t.Errorf("command = %q, want %q", args["command"], tt.wantCmd)
			}
		})
	}
}

// --- writeLine ---

func TestWriteLine(t *testing.T) {
	t.Run("does_not_mutate_input", func(t *testing.T) {
		var buf bytes.Buffer
		lw := &lockedWriter{w: &buf}

		// Slice with extra capacity (simulating scanner buffer)
		backing := make([]byte, 6, 100)
		copy(backing, "helloX")
		data := backing[:5]

		if err := lw.writeLine(data); err != nil {
			t.Fatal(err)
		}
		if backing[5] != 'X' {
			t.Errorf("writeLine mutated caller's buffer: byte after data is %q, want 'X'", backing[5])
		}
		if buf.String() != "hello\n" {
			t.Errorf("output = %q, want %q", buf.String(), "hello\n")
		}
	})

	t.Run("consecutive_writes", func(t *testing.T) {
		var buf bytes.Buffer
		lw := &lockedWriter{w: &buf}

		for _, line := range []string{"first", "second", "third"} {
			if err := lw.writeLine([]byte(line)); err != nil {
				t.Fatal(err)
			}
		}
		if got, want := buf.String(), "first\nsecond\nthird\n"; got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}

// --- runProxy (hang / exit code) ---

func TestRunProxy(t *testing.T) {
	t.Run("no_hang_on_agent_exit", func(t *testing.T) {
		if _, err := exec.LookPath("true"); err != nil {
			t.Skip("'true' not found in PATH")
		}
		engine := newTestEngine(t)
		ideR, ideW := io.Pipe()
		defer ideW.Close() // keep write end OPEN to expose the hang bug

		done := make(chan int, 1)
		go func() { done <- runProxy(engine, []string{"true"}, ideR, &bytes.Buffer{}) }()

		select {
		case code := <-done:
			if code != 0 {
				t.Errorf("exit code = %d, want 0", code)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("runProxy hung — IDE stdin not closed after agent exit")
		}
	})

	t.Run("propagates_exit_code", func(t *testing.T) {
		if _, err := exec.LookPath("false"); err != nil {
			t.Skip("'false' not found in PATH")
		}
		engine := newTestEngine(t)
		ideR, ideW := io.Pipe()
		defer ideW.Close()

		done := make(chan int, 1)
		go func() { done <- runProxy(engine, []string{"false"}, ideR, &bytes.Buffer{}) }()

		select {
		case code := <-done:
			if code == 0 {
				t.Error("expected non-zero exit code from 'false'")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("runProxy hung")
		}
	})
}

// --- pipeAgentToIDE ---

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
			ideOut, agentErr := runPipe(t, tt.msg+"\n")
			if ideOut != "" {
				t.Errorf("IDE should not receive blocked request, got: %s", ideOut)
			}
			if agentErr == "" {
				t.Error("agent should receive an error response")
			}
		})
	}
}

func TestPipeAgentToIDE_BlocksEnvRead_ErrorShape(t *testing.T) {
	ideOut, agentErr := runPipe(t, `{"jsonrpc":"2.0","id":1,"method":"fs/read_text_file","params":{"sessionId":"s1","path":"/app/.env"}}`+"\n")
	if ideOut != "" {
		t.Errorf("IDE should not receive blocked request, got: %s", ideOut)
	}
	var resp jsonRPCError
	if err := json.Unmarshal(bytes.TrimSpace([]byte(agentErr)), &resp); err != nil {
		t.Fatalf("expected JSON-RPC error, got: %s", agentErr)
	}
	if resp.Error.Code != jsonRPCBlockedError {
		t.Errorf("error code = %d, want %d", resp.Error.Code, jsonRPCBlockedError)
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
			ideOut, agentErr := runPipe(t, tt.msg+"\n")
			if ideOut != tt.msg+"\n" {
				t.Errorf("message should pass through unchanged\ngot:  %q\nwant: %q", ideOut, tt.msg+"\n")
			}
			if agentErr != "" {
				t.Errorf("agent should not receive errors, got: %s", agentErr)
			}
		})
	}
}

func TestPipeAgentToIDE_EmptyLine(t *testing.T) {
	ideOut, _ := runPipe(t, "\n")
	if ideOut != "\n" {
		t.Errorf("empty line should pass through, got: %q", ideOut)
	}
}

func TestPipeAgentToIDE_MultipleMessages(t *testing.T) {
	msgs := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"fs/read_text_file","params":{"sessionId":"s1","path":"/app/.env"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"fs/read_text_file","params":{"sessionId":"s1","path":"/app/main.go"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"session/prompt","params":{"text":"hi"}}`,
	}, "\n") + "\n"

	ideOut, agentErr := runPipe(t, msgs)

	ideLines := strings.Split(strings.TrimRight(ideOut, "\n"), "\n")
	if len(ideLines) != 2 {
		t.Errorf("expected 2 IDE messages (main.go + prompt), got %d: %v", len(ideLines), ideLines)
	}
	if agentErr == "" {
		t.Error("agent should receive error for .env read")
	}
}

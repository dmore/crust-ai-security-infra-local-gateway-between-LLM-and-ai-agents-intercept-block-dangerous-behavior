// Package acpwrap implements a transparent stdio proxy for ACP (Agent Client Protocol)
// agents, intercepting security-relevant JSON-RPC messages using Crust's rule engine.
package acpwrap

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"unicode"

	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/rules"
)

var log = logger.New("acp")

// JSON-RPC error codes
const (
	jsonRPCBlockedError = -32001 // Custom: blocked by security rule
)

// maxScannerBuf is the maximum size of a single JSONL message (10MB).
// ACP messages can contain full file contents in fs/write_text_file.
const maxScannerBuf = 10 * 1024 * 1024

// jsonRPCMessage represents a minimal JSON-RPC 2.0 message.
type jsonRPCMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// isRequest returns true if this is a JSON-RPC request (has method + id).
func (m *jsonRPCMessage) isRequest() bool {
	return m.Method != "" && len(m.ID) > 0
}

// jsonRPCError is a JSON-RPC 2.0 error response.
type jsonRPCError struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   jsonRPCErrorObj `json:"error"`
}

type jsonRPCErrorObj struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// lockedWriter is a mutex-protected writer for agent stdin.
// Both the IDE→Agent goroutine and the blocking logic write to it.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (lw *lockedWriter) writeLine(data []byte) error {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	if _, err := lw.w.Write(data); err != nil {
		return err
	}
	_, err := lw.w.Write([]byte{'\n'})
	return err
}

// ACP parameter types

type fsReadParams struct {
	SessionID string `json:"sessionId"`
	Path      string `json:"path"`
}

type fsWriteParams struct {
	SessionID string `json:"sessionId"`
	Path      string `json:"path"`
	Content   string `json:"content"`
}

type terminalCreateParams struct {
	SessionID string            `json:"sessionId"`
	Command   string            `json:"command"`
	Args      []string          `json:"args,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	Cwd       string            `json:"cwd,omitempty"`
}

// shellSafe is the set of characters that don't need quoting in shell arguments.
const shellSafe = "-_./:=+,"

// shellQuote quotes a shell argument if it contains special characters.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.ContainsFunc(s, func(c rune) bool {
		return !unicode.IsLetter(c) && !unicode.IsDigit(c) && !strings.ContainsRune(shellSafe, c)
	}) {
		return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
	}
	return s
}

// acpMethodToToolCall converts an ACP JSON-RPC method + params into a rules.ToolCall
// that the existing rule engine can evaluate.
// Returns (toolCall, true, nil) for successfully parsed security-relevant methods,
// (_, false, nil) for non-security methods, and (_, true, err) when a security-relevant
// method has malformed params (caller should block).
func acpMethodToToolCall(method string, params json.RawMessage) (rules.ToolCall, bool, error) {
	// Reject nil/null params on security-relevant methods (json.Unmarshal silently
	// zero-initializes the struct, which would produce an empty path and bypass rules).
	switch method {
	case "fs/read_text_file", "fs/write_text_file", "terminal/create":
		if len(params) == 0 || string(params) == "null" {
			return rules.ToolCall{}, true, fmt.Errorf("nil params for security method %s", method)
		}
	}

	switch method {
	case "fs/read_text_file":
		var p fsReadParams
		if err := json.Unmarshal(params, &p); err != nil {
			return rules.ToolCall{}, true, fmt.Errorf("malformed %s params: %w", method, err)
		}
		args, err := json.Marshal(map[string]string{"path": p.Path})
		if err != nil {
			return rules.ToolCall{}, true, fmt.Errorf("marshal error: %w", err)
		}
		return rules.ToolCall{Name: "read_file", Arguments: args}, true, nil

	case "fs/write_text_file":
		var p fsWriteParams
		if err := json.Unmarshal(params, &p); err != nil {
			return rules.ToolCall{}, true, fmt.Errorf("malformed %s params: %w", method, err)
		}
		args, err := json.Marshal(map[string]any{
			"path":    p.Path,
			"content": p.Content,
		})
		if err != nil {
			return rules.ToolCall{}, true, fmt.Errorf("marshal error: %w", err)
		}
		return rules.ToolCall{Name: "write_file", Arguments: args}, true, nil

	case "terminal/create":
		var p terminalCreateParams
		if err := json.Unmarshal(params, &p); err != nil {
			return rules.ToolCall{}, true, fmt.Errorf("malformed %s params: %w", method, err)
		}
		fullCmd := p.Command
		if len(p.Args) > 0 {
			quoted := make([]string, len(p.Args))
			for i, a := range p.Args {
				quoted[i] = shellQuote(a)
			}
			fullCmd += " " + strings.Join(quoted, " ")
		}
		args, err := json.Marshal(map[string]string{"command": fullCmd})
		if err != nil {
			return rules.ToolCall{}, true, fmt.Errorf("marshal error: %w", err)
		}
		return rules.ToolCall{Name: "bash", Arguments: args}, true, nil

	default:
		return rules.ToolCall{}, false, nil
	}
}

// Run starts the ACP proxy. It spawns the agent subprocess, wires up stdio,
// and evaluates security-relevant messages. Returns the agent's exit code.
func Run(engine *rules.Engine, agentCmd []string) int {
	return runProxy(engine, agentCmd, os.Stdin, os.Stdout)
}

// runProxy is the internal implementation of Run, accepting explicit IO handles
// so that ideStdin can be closed after the agent exits (unblocking the scanner).
func runProxy(engine *rules.Engine, agentCmd []string, ideStdin io.ReadCloser, ideStdout io.Writer) int {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, agentCmd[0], agentCmd[1:]...) //nolint:gosec // agentCmd is user-specified by design
	agentStdin, err := cmd.StdinPipe()
	if err != nil {
		log.Error("Failed to create agent stdin pipe: %v", err)
		return 1
	}
	agentStdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Error("Failed to create agent stdout pipe: %v", err)
		return 1
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		log.Error("Failed to start agent: %v", err)
		return 1
	}

	log.Info("Agent started: PID %d, command: %v", cmd.Process.Pid, agentCmd)
	log.Info("Rule engine: %d rules loaded", engine.RuleCount())

	writer := &lockedWriter{w: agentStdin}

	var wg sync.WaitGroup

	// Goroutine 1: IDE → Agent (pass-through, line-by-line with mutex)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer agentStdin.Close()
		pipeIDEToAgent(ideStdin, writer)
	}()

	// Goroutine 2: Agent → IDE (inspect security-relevant messages)
	wg.Add(1)
	go func() {
		defer wg.Done()
		pipeAgentToIDE(engine, agentStdout, ideStdout, writer)
	}()

	// Goroutine 3: Forward signals to child
	sigCh := forwardSignals()
	go func() {
		for sig := range sigCh {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		}
	}()

	// Wait for agent to exit
	waitErr := cmd.Wait()
	stopSignals(sigCh)
	cancel()

	// Close IDE stdin to unblock the pipeIDEToAgent goroutine's scanner.
	// In production this is os.Stdin; safe because crust exits immediately after.
	if ideStdin != nil {
		ideStdin.Close()
	}

	// Wait for pipe goroutines to finish draining
	wg.Wait()

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			return exitErr.ExitCode()
		}
		return 1
	}
	return 0
}

// pipeIDEToAgent reads JSONL from the IDE (our stdin) and forwards each line
// to the agent's stdin through the lockedWriter.
func pipeIDEToAgent(ideStdin io.Reader, writer *lockedWriter) {
	scanner := bufio.NewScanner(ideStdin)
	scanner.Buffer(make([]byte, 0, 64*1024), maxScannerBuf)

	for scanner.Scan() {
		if err := writer.writeLine(scanner.Bytes()); err != nil {
			log.Debug("IDE→Agent write error: %v", err)
			return
		}
	}
	if err := scanner.Err(); err != nil {
		log.Debug("IDE stdin scanner error: %v", err)
	}
}

// sendBlockError sends a JSON-RPC error response back to the agent's stdin.
func sendBlockError(writer *lockedWriter, id json.RawMessage, msg string) {
	resp, err := json.Marshal(jsonRPCError{
		JSONRPC: "2.0",
		ID:      id,
		Error:   jsonRPCErrorObj{Code: jsonRPCBlockedError, Message: msg},
	})
	if err != nil {
		log.Debug("Failed to marshal block response: %v", err)
		return
	}
	if err := writer.writeLine(resp); err != nil {
		log.Debug("Failed to send block response to agent: %v", err)
	}
}

// pipeAgentToIDE reads JSONL from the agent's stdout, inspects security-relevant
// messages, and either forwards them to the IDE or blocks them.
func pipeAgentToIDE(engine *rules.Engine, agentStdout io.Reader, ideStdout io.Writer, agentWriter *lockedWriter) {
	scanner := bufio.NewScanner(agentStdout)
	scanner.Buffer(make([]byte, 0, 64*1024), maxScannerBuf)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			fmt.Fprintln(ideStdout)
			continue
		}

		var msg jsonRPCMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			fmt.Fprintf(ideStdout, "%s\n", line) //nolint:gosec // not valid JSON — forward as-is
			continue
		}

		if !msg.isRequest() {
			fmt.Fprintf(ideStdout, "%s\n", line) //nolint:gosec // stdio pipe, not HTTP
			continue
		}

		toolCall, isSecurityRelevant, parseErr := acpMethodToToolCall(msg.Method, msg.Params)
		if !isSecurityRelevant {
			fmt.Fprintf(ideStdout, "%s\n", line) //nolint:gosec // stdio pipe, not HTTP
			continue
		}

		if parseErr != nil {
			log.Warn("Blocked ACP %s: %v", msg.Method, parseErr)
			sendBlockError(agentWriter, msg.ID, "[Crust] Blocked: malformed params for "+msg.Method)
			continue
		}

		result := engine.Evaluate(toolCall)

		if result.Matched && result.Action == rules.ActionBlock {
			log.Warn("Blocked ACP %s: rule=%s message=%s", msg.Method, result.RuleName, result.Message)
			sendBlockError(agentWriter, msg.ID, fmt.Sprintf("[Crust] Blocked by rule %q: %s", result.RuleName, result.Message))
			continue
		}

		if result.Matched && result.Action == rules.ActionLog {
			log.Info("Logged ACP %s: rule=%s", msg.Method, result.RuleName)
		}

		fmt.Fprintf(ideStdout, "%s\n", line) //nolint:gosec // stdio pipe, not HTTP
	}

	if err := scanner.Err(); err != nil {
		log.Debug("Agent stdout scanner error: %v", err)
	}
}

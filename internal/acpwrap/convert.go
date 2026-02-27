// Package acpwrap implements a transparent stdio proxy for ACP (Agent Client Protocol)
// agents, intercepting security-relevant JSON-RPC messages using Crust's rule engine.
package acpwrap

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"

	"github.com/BakeLens/crust/internal/rules"
)

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

// ACPMethodToToolCall converts an ACP JSON-RPC method + params into a rules.ToolCall.
//
// Returns:
//   - (*ToolCall, nil) for successfully parsed security-relevant methods
//   - (nil, nil) for non-security methods (caller should pass through)
//   - (nil, error) for security-relevant methods with malformed params (caller should block)
func ACPMethodToToolCall(method string, params json.RawMessage) (*rules.ToolCall, error) {
	// Reject nil/null params on security-relevant methods (json.Unmarshal silently
	// zero-initializes the struct, which would produce an empty path and bypass rules).
	switch method {
	case "fs/read_text_file", "fs/write_text_file", "terminal/create":
		if len(params) == 0 || string(params) == "null" {
			return nil, fmt.Errorf("nil params for security method %s", method)
		}
	default:
		return nil, nil // not security-relevant
	}

	switch method {
	case "fs/read_text_file":
		var p fsReadParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("malformed %s params: %w", method, err)
		}
		args, err := json.Marshal(map[string]string{"path": p.Path})
		if err != nil {
			return nil, fmt.Errorf("marshal error: %w", err)
		}
		return &rules.ToolCall{Name: "read_file", Arguments: args}, nil

	case "fs/write_text_file":
		var p fsWriteParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("malformed %s params: %w", method, err)
		}
		args, err := json.Marshal(map[string]any{
			"path":    p.Path,
			"content": p.Content,
		})
		if err != nil {
			return nil, fmt.Errorf("marshal error: %w", err)
		}
		return &rules.ToolCall{Name: "write_file", Arguments: args}, nil

	case "terminal/create":
		var p terminalCreateParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("malformed %s params: %w", method, err)
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
			return nil, fmt.Errorf("marshal error: %w", err)
		}
		return &rules.ToolCall{Name: "bash", Arguments: args}, nil

	default:
		return nil, nil
	}
}

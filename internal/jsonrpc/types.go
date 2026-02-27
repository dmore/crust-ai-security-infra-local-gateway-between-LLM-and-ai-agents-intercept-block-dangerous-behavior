// Package jsonrpc provides shared types and utilities for Crust's stdio proxy
// implementations (ACP wrap, MCP gateway, auto-detect wrap).
package jsonrpc

import (
	"encoding/json"
	"io"
	"sync"

	"github.com/BakeLens/crust/internal/rules"
)

// BlockedError is the JSON-RPC error code for requests blocked by a security rule.
const BlockedError = -32001

// MaxScannerBuf is the maximum size of a single JSONL message (10MB).
const MaxScannerBuf = 10 * 1024 * 1024

// Message represents a minimal JSON-RPC 2.0 message.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// IsRequest returns true if this is a JSON-RPC request (has method + id).
func (m *Message) IsRequest() bool {
	return m.Method != "" && len(m.ID) > 0
}

// IsNotification returns true if this is a JSON-RPC notification (has method but no id).
func (m *Message) IsNotification() bool {
	return m.Method != "" && len(m.ID) == 0
}

// ErrorResponse is a JSON-RPC 2.0 error response.
type ErrorResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   ErrorObj        `json:"error"`
}

// ErrorObj is the error object within a JSON-RPC error response.
type ErrorObj struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// LockedWriter is a mutex-protected writer for safe concurrent line writes.
// Both the pass-through goroutine and the blocking logic write through it.
type LockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// NewLockedWriter creates a new LockedWriter wrapping w.
func NewLockedWriter(w io.Writer) *LockedWriter {
	return &LockedWriter{w: w}
}

// WriteLine writes data followed by a newline, under the mutex.
func (lw *LockedWriter) WriteLine(data []byte) error {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	if _, err := lw.w.Write(data); err != nil {
		return err
	}
	_, err := lw.w.Write([]byte{'\n'})
	return err
}

// MethodConverter converts a JSON-RPC method + params into a rules.ToolCall.
//
// Returns:
//   - (*ToolCall, nil) for successfully parsed security-relevant methods
//   - (nil, nil) for non-security methods (caller should pass through)
//   - (nil, error) for security-relevant methods with malformed params (caller should block)
type MethodConverter func(method string, params json.RawMessage) (*rules.ToolCall, error)

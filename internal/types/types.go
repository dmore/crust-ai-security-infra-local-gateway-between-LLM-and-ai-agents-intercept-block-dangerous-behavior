// Package types defines common type-safe enums used across the codebase.
package types

import (
	"errors"
	"fmt"
)

// APIType represents the LLM API format being proxied.
type APIType int //nolint:recvcheck // UnmarshalText requires pointer receiver; all other methods use value receiver per encoding.TextMarshaler convention

const (
	// APITypeOpenAICompletion is the OpenAI-compatible API format (Chat Completions).
	APITypeOpenAICompletion APIType = iota
	// APITypeAnthropic is the Anthropic API format.
	APITypeAnthropic
	// APITypeOpenAIResponses is the OpenAI Responses API format (/v1/responses).
	APITypeOpenAIResponses
)

// APITypeUnknown is a sentinel for an unrecognized API type (e.g. in tests).
const APITypeUnknown APIType = -1

var apiTypeStrings = [...]string{"openai", "anthropic", "openai_responses"}

// String implements fmt.Stringer.
func (t APIType) String() string {
	if t >= 0 && int(t) < len(apiTypeStrings) {
		return apiTypeStrings[t]
	}
	return fmt.Sprintf("APIType(%d)", int(t))
}

// MarshalText implements encoding.TextMarshaler (used by yaml.v3 and encoding/json).
func (t APIType) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler (used by yaml.v3 and encoding/json).
func (t *APIType) UnmarshalText(b []byte) error {
	switch string(b) {
	case "openai":
		*t = APITypeOpenAICompletion
	case "anthropic":
		*t = APITypeAnthropic
	case "openai_responses":
		*t = APITypeOpenAIResponses
	default:
		return fmt.Errorf("unknown APIType %q", string(b))
	}
	return nil
}

// ParseAPIType converts a string to an APIType, returning an error if not recognized.
func ParseAPIType(s string) (APIType, error) {
	var t APIType
	if err := t.UnmarshalText([]byte(s)); err != nil {
		return APITypeUnknown, err
	}
	return t, nil
}

// Valid returns true if the APIType is a known valid value.
func (t APIType) Valid() bool {
	return t == APITypeOpenAICompletion || t == APITypeAnthropic || t == APITypeOpenAIResponses
}

// IsAnthropic returns true if this is the Anthropic API format.
func (t APIType) IsAnthropic() bool { return t == APITypeAnthropic }

// IsOpenAICompletion returns true if this is the OpenAI Chat Completions API format.
func (t APIType) IsOpenAICompletion() bool { return t == APITypeOpenAICompletion }

// IsOpenAIResponses returns true if this is the OpenAI Responses API format.
func (t APIType) IsOpenAIResponses() bool { return t == APITypeOpenAIResponses }

// BlockMode represents how blocked tool calls are handled in responses.
type BlockMode int //nolint:recvcheck // UnmarshalText requires pointer receiver; all other methods use value receiver per encoding.TextMarshaler convention

const (
	// BlockModeUnset is the zero value — no mode explicitly configured.
	BlockModeUnset BlockMode = iota
	// BlockModeRemove removes blocked tool calls from the response.
	BlockModeRemove
	// BlockModeReplace substitutes blocked tool calls with a text warning block.
	BlockModeReplace
)

var blockModeStrings = [...]string{"", "remove", "replace"}

// String implements fmt.Stringer.
func (m BlockMode) String() string {
	if m >= 0 && int(m) < len(blockModeStrings) {
		return blockModeStrings[m]
	}
	return fmt.Sprintf("BlockMode(%d)", int(m))
}

// MarshalText implements encoding.TextMarshaler (used by yaml.v3 and encoding/json).
func (m BlockMode) MarshalText() ([]byte, error) {
	if m == BlockModeUnset {
		return nil, errors.New("cannot marshal unset BlockMode")
	}
	return []byte(m.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler (used by yaml.v3 and encoding/json).
func (m *BlockMode) UnmarshalText(b []byte) error {
	switch string(b) {
	case "remove":
		*m = BlockModeRemove
	case "replace":
		*m = BlockModeReplace
	default:
		return fmt.Errorf("unknown BlockMode %q: must be 'remove' or 'replace'", string(b))
	}
	return nil
}

// ParseBlockMode converts a string to a BlockMode.
func ParseBlockMode(s string) (BlockMode, error) {
	var m BlockMode
	if err := m.UnmarshalText([]byte(s)); err != nil {
		return BlockModeUnset, err
	}
	return m, nil
}

// Valid returns true if the BlockMode is a known non-unset value.
func (m BlockMode) Valid() bool {
	return m == BlockModeRemove || m == BlockModeReplace
}

// IsReplace returns true if blocked calls should be replaced with a text warning block.
func (m BlockMode) IsReplace() bool { return m == BlockModeReplace }

// IsRemove returns true if blocked calls should be removed from the response.
func (m BlockMode) IsRemove() bool { return m == BlockModeRemove }

// LogLevel represents a log verbosity level.
type LogLevel string

const (
	LogLevelTrace LogLevel = "trace"
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
)

// Valid returns true if the LogLevel is a known valid value.
// Empty string is valid (defaults to info).
func (l LogLevel) Valid() bool {
	switch l {
	case LogLevelTrace, LogLevelDebug, LogLevelInfo, LogLevelWarn, LogLevelError, "":
		return true
	}
	return false
}

// MessageRole represents the role of a message in an LLM conversation.
type MessageRole string

const (
	RoleSystem    MessageRole = "system"
	RoleUser      MessageRole = "user"
	RoleAssistant MessageRole = "assistant"
)

// Agent represents a known AI coding agent brand.
type Agent string

const (
	AgentClaudeCode Agent = "claude-code"
	AgentCodex      Agent = "codex"
	AgentCline      Agent = "cline"
	AgentCursor     Agent = "cursor"
	AgentOpenClaw   Agent = "openclaw"
	AgentOpenCode   Agent = "opencode"
	AgentWindsurf   Agent = "windsurf"
	AgentUnknown    Agent = "unknown"
)

// Valid returns true if the Agent is a known value (not unknown).
func (a Agent) Valid() bool {
	switch a {
	case AgentClaudeCode, AgentCodex, AgentCline, AgentCursor,
		AgentOpenClaw, AgentOpenCode, AgentWindsurf:
		return true
	case AgentUnknown:
		return false
	}
	return false
}

// String returns the agent name.
func (a Agent) String() string {
	return string(a)
}

// AllAgents returns all known agent brands.
func AllAgents() []Agent {
	return []Agent{
		AgentClaudeCode,
		AgentCodex,
		AgentCline,
		AgentCursor,
		AgentOpenClaw,
		AgentOpenCode,
		AgentWindsurf,
	}
}

// ParseAgent converts a string to an Agent, returning AgentUnknown if not recognized.
func ParseAgent(s string) Agent {
	a := Agent(s)
	if a.Valid() {
		return a
	}
	return AgentUnknown
}

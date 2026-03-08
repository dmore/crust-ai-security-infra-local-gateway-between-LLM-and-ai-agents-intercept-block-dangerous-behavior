//go:generate go run ./cmd/schema-check

package plugin

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/BakeLens/crust/internal/rules"
)

// Plugin is a late-stage protection layer (step 13+).
// Runs only for tool calls that passed all built-in checks.
// Implementations must be safe for concurrent use.
type Plugin interface {
	// Name returns a unique identifier (e.g. "sandbox", "rate-limiter").
	Name() string

	// Init is called once when the plugin is registered.
	// cfg is plugin-specific JSON configuration; nil means use defaults.
	Init(cfg json.RawMessage) error

	// Evaluate inspects an allowed tool call.
	// Return nil to allow, non-nil to block.
	// Must be safe for concurrent calls.
	// The context carries the per-call timeout — plugins should respect ctx.Done().
	Evaluate(ctx context.Context, req Request) *Result

	// Close releases plugin resources (processes, connections, etc).
	Close() error
}

// Request is the data available to plugins.
// All fields are read-only deep copies — safe for concurrent use.
// Serialized as JSON over the wire protocol for external plugins.
//
// Every field is always present in the JSON encoding (no omitempty)
// to eliminate ambiguity between "absent" and "zero value".
//
// Operation and Operations use rules.Operation — the same enum used
// by the YAML rules engine — making the plugin protocol a strict
// child of the rules type system.
type Request struct {
	ToolName   string            `json:"tool_name"`
	Arguments  json.RawMessage   `json:"arguments"`
	Operation  rules.Operation   `json:"operation"`
	Operations []rules.Operation `json:"operations"`
	Command    string            `json:"command"`
	Paths      []string          `json:"paths"`
	Hosts      []string          `json:"hosts"`
	Content    string            `json:"content"`
	Evasive    bool              `json:"evasive"`

	// Rules is a snapshot of all active engine rules at evaluation time.
	// Plugins can use this for context-aware decisions (e.g., "is this path
	// already protected by a builtin rule?"). Read-only; plugins cannot
	// modify the engine's rules. Always present (empty array if no rules).
	Rules []RuleSnapshot `json:"rules"`
}

// RuleSnapshot is a read-only, JSON-safe view of an engine rule.
// Fields use the same typed enums as the YAML rules engine
// (rules.Source, rules.Severity, rules.Operation).
//
// Every field is always present in the JSON encoding (no omitempty)
// to eliminate ambiguity between "absent" and "zero value".
type RuleSnapshot struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Source      rules.Source      `json:"source"`
	Severity    rules.Severity    `json:"severity"`
	Priority    int               `json:"priority"`
	Actions     []rules.Operation `json:"actions"`
	BlockPaths  []string          `json:"block_paths"`
	BlockExcept []string          `json:"block_except"`
	BlockHosts  []string          `json:"block_hosts"`
	Message     string            `json:"message"`
	Locked      bool              `json:"locked"`
	Enabled     bool              `json:"enabled"`
	HitCount    int64             `json:"hit_count"`
}

// SnapshotRule converts a rules.Rule to a plugin RuleSnapshot.
// Centralizes the conversion logic between the two type systems.
func SnapshotRule(r *rules.Rule) RuleSnapshot {
	return RuleSnapshot{
		Name:        r.Name,
		Description: r.Description,
		Source:      r.Source,
		Severity:    r.GetSeverity(),
		Priority:    r.GetPriority(),
		Actions:     slices.Clone(r.Actions),
		BlockPaths:  slices.Clone(r.GetBlockPaths()),
		BlockExcept: slices.Clone(r.GetBlockExcept()),
		BlockHosts:  slices.Clone(r.GetBlockHosts()),
		Message:     r.Message,
		Locked:      r.IsLocked(),
		Enabled:     r.IsEnabled(),
		HitCount:    r.HitCount,
	}
}

// DeepCopy returns a copy of the request with all slices cloned.
// Prevents a plugin from mutating data seen by subsequent plugins.
func (r Request) DeepCopy() Request {
	cp := r
	cp.Arguments = slices.Clone(r.Arguments)
	cp.Operations = slices.Clone(r.Operations)
	cp.Paths = slices.Clone(r.Paths)
	cp.Hosts = slices.Clone(r.Hosts)
	cp.Rules = slices.Clone(r.Rules)
	// Clone inner slices of each RuleSnapshot to prevent shared backing arrays (Bug #4).
	for i := range cp.Rules {
		cp.Rules[i].Actions = slices.Clone(cp.Rules[i].Actions)
		cp.Rules[i].BlockPaths = slices.Clone(cp.Rules[i].BlockPaths)
		cp.Rules[i].BlockExcept = slices.Clone(cp.Rules[i].BlockExcept)
		cp.Rules[i].BlockHosts = slices.Clone(cp.Rules[i].BlockHosts)
	}
	return cp
}

// Result describes why a plugin blocked a call.
// Return nil from Evaluate to allow the call.
//
// Severity and Action use the same typed enums as the YAML rules engine.
type Result struct {
	Plugin   string         `json:"plugin"`
	RuleName string         `json:"rule_name"`
	Severity rules.Severity `json:"severity"`
	Action   rules.Action   `json:"action"`
	Message  string         `json:"message"`
}

// EffectiveAction returns the action, defaulting to "block" if empty or invalid.
func (r *Result) EffectiveAction() rules.Action {
	if rules.ValidResponseActions[r.Action] {
		return r.Action
	}
	return rules.ActionBlock
}

// EffectiveSeverity returns the severity, defaulting to "high" if invalid.
func (r *Result) EffectiveSeverity() rules.Severity {
	if rules.ValidSeverities[r.Severity] {
		return r.Severity
	}
	return rules.SeverityHigh
}

// Package testutil provides shared test helpers for Crust's proxy packages.
package testutil

import (
	"testing"

	"github.com/BakeLens/crust/internal/rules"
)

// NewEngine creates a rules.Engine with built-in rules and a temp user rules dir.
// Accepts *testing.T, *testing.F, or *testing.B.
func NewEngine(tb testing.TB) *rules.Engine {
	tb.Helper()
	engine, err := rules.NewEngine(rules.EngineConfig{
		UserRulesDir:   tb.TempDir(),
		DisableBuiltin: false,
	})
	if err != nil {
		tb.Fatalf("Failed to create engine: %v", err)
	}
	return engine
}

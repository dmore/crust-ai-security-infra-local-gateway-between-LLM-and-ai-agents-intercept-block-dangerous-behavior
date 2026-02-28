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

// NewEngineWithHome creates a rules.Engine with a custom home directory.
// This makes $HOME-based security rules (SSH keys, shell history, etc.)
// match paths under the given homeDir instead of the real system home.
func NewEngineWithHome(tb testing.TB, homeDir string) *rules.Engine {
	tb.Helper()
	normalizer := rules.NewNormalizerWithEnv(homeDir, homeDir, nil)
	engine, err := rules.NewEngineWithNormalizer(rules.EngineConfig{
		UserRulesDir:   tb.TempDir(),
		DisableBuiltin: false,
	}, normalizer)
	if err != nil {
		tb.Fatalf("Failed to create engine: %v", err)
	}
	return engine
}

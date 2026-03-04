package rules

// doc_consistency_test.go ensures that numbers and facts stated in documentation
// (README.md, docs/cli.md, docs/how-it-works.md) match the live source code.
//
// These tests act as a guardrail: if you add a DLP pattern, change the number
// of builtin rules, or rename a CLI command, the corresponding test will fail
// and tell you exactly which doc files to update.

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// packageDir returns the absolute path of the directory containing this file.
// Derived from the compiler's source path — stable across working-directory changes.
// Used by both repoRoot (this file) and getTestDataPath (scenario_test.go).
func packageDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(file)
}

// repoRoot returns the repository root: two directories above internal/rules/.
func repoRoot(t *testing.T) string {
	t.Helper()
	return filepath.Dir(filepath.Dir(packageDir()))
}

func readDoc(t *testing.T, relPath string) string {
	t.Helper()
	path := filepath.Join(repoRoot(t), relPath)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readDoc(%q): %v", relPath, err)
	}
	return string(data)
}

// docContains asserts that the document at relPath contains substr,
// and reports which file to update on failure.
func docContains(t *testing.T, relPath, substr string) {
	t.Helper()
	content := readDoc(t, relPath)
	if !strings.Contains(content, substr) {
		t.Errorf("%s does not contain %q — update this file to match the source code", relPath, substr)
	}
}

// ── DLP patterns ─────────────────────────────────────────────────────────────

// wantDLPPatternCount is the expected number of hardcoded DLP patterns.
// Update this constant AND the docs below whenever patterns are added or removed.
const wantDLPPatternCount = 34

// Docs that reference the DLP pattern count:
//   - README.md: "34 DLP token-detection patterns"
//   - docs/how-it-works.md: should mention 34

func TestDocConsistency_DLPPatternCount(t *testing.T) {
	got := len(dlpPatterns)
	if got != wantDLPPatternCount {
		t.Errorf("len(dlpPatterns) = %d, want %d\n"+
			"  → Update wantDLPPatternCount in this file AND:\n"+
			"    - README.md  (\"34 DLP token-detection patterns\")\n"+
			"    - docs/how-it-works.md",
			got, wantDLPPatternCount)
	}

	docContains(t, "README.md", "34 DLP token-detection patterns")
}

// ── Dynamic protection rules ─────────────────────────────────────────────────

// wantDynamicRuleCount is the number of rules produced by generateProtectionRules.
const wantDynamicRuleCount = 3

func TestDocConsistency_ProtectionRules(t *testing.T) {
	rules := generateProtectionRules(EngineConfig{UserRulesDir: t.TempDir()})

	if len(rules) != wantDynamicRuleCount {
		t.Errorf("generateProtectionRules() returned %d rules, want %d\n"+
			"  → Update wantDynamicRuleCount in this file",
			len(rules), wantDynamicRuleCount)
	}

	for _, r := range rules {
		if !r.IsLocked() {
			t.Errorf("protection rule %q must be locked (Locked: true)", r.Name)
		}
	}
}

// ── Builtin rule counts ───────────────────────────────────────────────────────

// wantTotalRuleCount = YAML rules + dynamic protection rules
// wantLockedRuleCount = YAML locked + dynamic (all locked)
// wantUserDisablableCount = total - locked
//
// Docs that reference these numbers:
//   - README.md: "26 security rules (19 locked, 7 user-disablable)"
//   - docs/cli.md: "19 locked" rules note for --disable-builtin

const (
	wantTotalRuleCount      = 26
	wantLockedRuleCount     = 19
	wantUserDisablableCount = 7
)

func TestDocConsistency_BuiltinRuleCounts(t *testing.T) {
	loader := NewLoader("")
	yamlRules, err := loader.LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin: %v", err)
	}

	dynamic := generateProtectionRules(EngineConfig{UserRulesDir: t.TempDir()})

	total := len(yamlRules) + len(dynamic)
	locked := len(dynamic) // all dynamic rules are locked
	for _, r := range yamlRules {
		if r.IsLocked() {
			locked++
		}
	}
	userDisablable := total - locked

	if total != wantTotalRuleCount {
		t.Errorf("total builtin rules = %d, want %d\n"+
			"  → Update wantTotalRuleCount in this file AND:\n"+
			"    - README.md  (\"26 security rules\")\n"+
			"    - docs/cli.md",
			total, wantTotalRuleCount)
	}
	if locked != wantLockedRuleCount {
		t.Errorf("locked builtin rules = %d, want %d\n"+
			"  → Update wantLockedRuleCount in this file AND:\n"+
			"    - README.md  (\"19 locked\")\n"+
			"    - docs/cli.md  (--disable-builtin description)",
			locked, wantLockedRuleCount)
	}
	if userDisablable != wantUserDisablableCount {
		t.Errorf("user-disablable rules = %d, want %d\n"+
			"  → Update wantUserDisablableCount in this file AND:\n"+
			"    - README.md  (\"7 user-disablable\")",
			userDisablable, wantUserDisablableCount)
	}

	// Assert docs reflect the source counts (README uses markdown bold around numbers)
	docContains(t, "README.md", "26 security rules")
	docContains(t, "README.md", "19 locked")
	docContains(t, "README.md", "7 user-disablable")
}

// ── CLI commands ──────────────────────────────────────────────────────────────

// requiredCLICommands lists top-level commands that must appear in docs/cli.md.
// Add a command here whenever a new top-level subcommand is introduced.
var requiredCLICommands = []string{
	"crust start",
	"crust stop",
	"crust status",
	"crust logs",
	"crust add-rule",
	"crust remove-rule",
	"crust list-rules",
	"crust reload-rules",
	"crust lint-rules",
	"crust doctor",
	"crust acp-wrap",
	"crust mcp",
	"crust wrap",
}

func TestDocConsistency_CLICommands(t *testing.T) {
	for _, cmd := range requiredCLICommands {
		docContains(t, "docs/cli.md", cmd)
	}
}

// ── Block mode strings ────────────────────────────────────────────────────────

// Verify the block mode description is consistent across all docs.
// The correct description is "text warning block" — NOT "echo command".
func TestDocConsistency_BlockModeDescription(t *testing.T) {
	stalePhrase := "echo command"
	docs := []string{"README.md", "docs/cli.md", "docs/configuration.md"}
	for _, doc := range docs {
		content := readDoc(t, doc)
		if strings.Contains(content, stalePhrase) {
			t.Errorf("%s contains stale phrase %q — replace with \"text warning block\"", doc, stalePhrase)
		}
	}
}

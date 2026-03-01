package rules

import (
	"testing"
)

// TestBuiltinRulesLoad verifies all 21 builtin security rules can be loaded.
// Tests rule: protect-env-files
// Tests rule: protect-ssh-keys
// Tests rule: protect-system-auth
// Tests rule: protect-crust
// Tests rule: protect-shell-history
// Tests rule: protect-cloud-credentials
// Tests rule: protect-gpg-keys
// Tests rule: protect-browser-data
// Tests rule: protect-git-credentials
// Tests rule: protect-package-tokens
// Tests rule: protect-shell-rc
// Tests rule: protect-ssh-authorized-keys
// Tests rule: protect-desktop-app-tokens
// Tests rule: protect-os-keychains
// Tests rule: protect-github-cli
// Tests rule: detect-private-key-write
// Tests rule: block-eval-exec
// Tests rule: protect-system-config
// Tests rule: protect-persistence
// Tests rule: detect-reverse-shell
// Tests rule: block-ssrf-metadata
// NOTE: protect-crust-api is hardcoded in engine.go (not a YAML rule)
func TestBuiltinRulesLoad(t *testing.T) {
	loader := NewLoader("")
	rules, err := loader.LoadBuiltin()
	if err != nil {
		t.Fatalf("Failed to load builtin rules: %v", err)
	}

	if len(rules) == 0 {
		t.Error("Expected at least one builtin rule")
	}

	// Check for critical security rules for personal users
	expectedRules := []string{
		"protect-env-files",
		"protect-ssh-keys",
		"protect-system-auth",
		"protect-crust",
		"protect-shell-history",
		"protect-cloud-credentials",
		"protect-gpg-keys",
		"protect-browser-data",
		"protect-git-credentials",
		"protect-package-tokens",
		"protect-shell-rc",
		"protect-ssh-authorized-keys",
		"protect-desktop-app-tokens",
		"protect-os-keychains",
		"protect-github-cli",
		"detect-private-key-write",
		"block-eval-exec",
		"protect-system-config",
		"protect-persistence",
		"detect-reverse-shell",
		"block-ssrf-metadata",
	}

	ruleNames := make(map[string]bool)
	for _, r := range rules {
		ruleNames[r.Name] = true
	}

	for _, name := range expectedRules {
		if !ruleNames[name] {
			t.Errorf("Missing expected builtin rule: %s", name)
		}
	}

	t.Logf("Loaded %d builtin rules", len(rules))
}

// TestLockedRulesSurviveDisableBuiltin verifies that locked rules remain active
// when --disable-builtin is set, while unlocked rules are removed.
func TestLockedRulesSurviveDisableBuiltin(t *testing.T) {
	loader := NewLoader("")
	rules, err := loader.LoadBuiltin()
	if err != nil {
		t.Fatalf("Failed to load builtin rules: %v", err)
	}

	// Verify locked rules exist
	lockedNames := []string{
		"protect-ssh-keys",
		"protect-system-auth",
		"protect-crust",
		"protect-shell-history",
		"protect-cloud-credentials",
		"protect-gpg-keys",
		"protect-git-credentials",
		"protect-ssh-authorized-keys",
		"protect-desktop-app-tokens",
		"protect-os-keychains",
		"protect-system-config",
		"protect-persistence",
		"detect-reverse-shell",
		"block-ssrf-metadata",
	}
	unlockedNames := []string{
		"protect-env-files",
		"protect-browser-data",
		"protect-package-tokens",
		"protect-shell-rc",
		"protect-github-cli",
		"detect-private-key-write",
		"block-eval-exec",
	}

	for _, r := range rules {
		for _, name := range lockedNames {
			if r.Name == name && !r.IsLocked() {
				t.Errorf("Rule %s should be locked", name)
			}
		}
		for _, name := range unlockedNames {
			if r.Name == name && r.IsLocked() {
				t.Errorf("Rule %s should NOT be locked", name)
			}
		}
	}

	// Simulate --disable-builtin: filter to locked only
	var locked []Rule
	for _, r := range rules {
		if r.IsLocked() {
			locked = append(locked, r)
		}
	}

	if len(locked) != len(lockedNames) {
		t.Errorf("Expected %d locked rules, got %d", len(lockedNames), len(locked))
	}

	lockedSet := make(map[string]bool)
	for _, r := range locked {
		lockedSet[r.Name] = true
	}

	for _, name := range lockedNames {
		if !lockedSet[name] {
			t.Errorf("Locked rule %s missing after filter", name)
		}
	}
	for _, name := range unlockedNames {
		if lockedSet[name] {
			t.Errorf("Unlocked rule %s should have been filtered out", name)
		}
	}

	t.Logf("Locked rules surviving --disable-builtin: %d/%d", len(locked), len(rules))
}

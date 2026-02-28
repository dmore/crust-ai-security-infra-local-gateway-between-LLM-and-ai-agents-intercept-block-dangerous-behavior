package rules

import (
	"testing"
)

func TestPreFilter_CommandSubstitution(t *testing.T) {
	pf := NewPreFilter()

	tests := []struct {
		cmd      string
		expected bool
		desc     string
	}{
		// $() and backticks are intentionally NOT detected by PreFilter.
		// The shell interpreter expands them in dry-run mode, so paths
		// inside substitutions are correctly extracted and matched against rules.
		{"echo $(cat /etc/passwd)", false, "$() handled by shell interpreter"},
		{"cat `whoami`", false, "backtick handled by shell interpreter"},
		{"ls $(pwd)", false, "$() handled by shell interpreter"},

		// Should NOT detect (safe commands)
		{"echo hello", false, "safe command"},
		{"ls -la", false, "safe command"},
		{"cat /etc/hosts", false, "safe command"},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			match := pf.Check(tt.cmd)
			if tt.expected && match == nil {
				t.Errorf("Expected match for %q, got none (%s)", tt.cmd, tt.desc)
			}
			if !tt.expected && match != nil {
				t.Errorf("Unexpected match for %q: %s (%s)", tt.cmd, match.PatternName, tt.desc)
			}
		})
	}
}

// eval is handled by the shell parser + extractor (recurses into eval argument).

func TestPreFilter_Base64Decode(t *testing.T) {
	pf := NewPreFilter()

	tests := []struct {
		cmd      string
		expected bool
	}{
		{"echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d", true},
		{"base64 --decode payload.txt", true},
		{"base64 -d < encoded.txt", true},
		{"base64 encode.txt", false}, // encoding, not decoding
		{"cat base64_file.txt", false},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			match := pf.Check(tt.cmd)
			if tt.expected && match == nil {
				t.Errorf("Expected match for %q, got none", tt.cmd)
			}
			if !tt.expected && match != nil {
				t.Errorf("Unexpected match for %q: %s", tt.cmd, match.PatternName)
			}
		})
	}
}

func TestPreFilter_HexEscape(t *testing.T) {
	pf := NewPreFilter()

	tests := []struct {
		cmd      string
		expected bool
	}{
		// 3+ consecutive hex escapes = dangerous (encoded commands)
		{"echo -e '\\x63\\x61\\x74'", true},
		{"printf '\\x2f\\x65\\x74\\x63'", true},
		// 1-2 hex escapes = safe (null bytes, ANSI colors)
		{"grep '\\x00' file", false},
		{"printf '\\x1b[31m'", false},
		{"echo hello", false},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			match := pf.Check(tt.cmd)
			if tt.expected && match == nil {
				t.Errorf("Expected match for %q, got none", tt.cmd)
			}
			if !tt.expected && match != nil {
				t.Errorf("Unexpected match for %q: %s", tt.cmd, match.PatternName)
			}
		})
	}
}

// Fork bomb detection moved to AST-level (astForkBomb in extractor.go).
// See TestForkBombDetection in false_positive_test.go.

// Network exfiltration (curl -d @file, nc -e, etc.) is handled by the
// command DB + rule engine, not the prefilter. See scenario_test.go.

// IFS manipulation and indirect expansion (${!var}) are handled by
// the shell parser + interpreter, not the prefilter.

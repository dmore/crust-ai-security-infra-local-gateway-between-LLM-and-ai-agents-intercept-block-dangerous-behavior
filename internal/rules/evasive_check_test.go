package rules

import (
	"encoding/json"
	"testing"
)

func TestEvasiveMarkingOnSecondaryFields(t *testing.T) {
	ext := NewExtractor()

	cases := []struct {
		name        string
		toolName    string
		args        map[string]any
		wantEvasive bool
	}{
		{
			name:        "safe command + broken script (unclosed quote)",
			toolName:    "mcp_tool",
			args:        map[string]any{"command": "echo safe", "script": "this has an unclosed 'quote"},
			wantEvasive: true, // fail-closed: any unparseable field triggers evasive
		},
		{
			name:        "safe command only",
			toolName:    "mcp_tool",
			args:        map[string]any{"command": "echo hello"},
			wantEvasive: false,
		},
		{
			name:        "natural language in script field",
			toolName:    "build_tool",
			args:        map[string]any{"script": "Build the project using make install"},
			wantEvasive: false, // permissive parser treats this as valid commands
		},
		{
			name:        "text starting with shell keyword if",
			toolName:    "helper",
			args:        map[string]any{"script": "if you want to delete, use rm"},
			wantEvasive: true, // fail-closed: unparseable input is blocked
		},
		{
			name:        "safe command + text starting with if keyword",
			toolName:    "mcp_tool",
			args:        map[string]any{"command": "echo safe", "script": "if you want to delete, use rm"},
			wantEvasive: true, // fail-closed: unparseable script field triggers evasive even with valid command field
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			argsJSON, _ := json.Marshal(tc.args)
			info := ext.Extract(tc.toolName, argsJSON)
			t.Logf("Evasive=%v Reason=%q Op=%v", info.Evasive, info.EvasiveReason, info.Operation)
			if info.Evasive != tc.wantEvasive {
				t.Errorf("Evasive = %v, want %v (reason: %s)", info.Evasive, tc.wantEvasive, info.EvasiveReason)
			}
		})
	}
}

// TestEvasive_PSTransformBypass is a regression test for a fuzz-discovered bypass:
// a command with $var="..." syntax triggers looksLikePowerShell (psVarAssignRe match),
// the PS transformation makes it parseable, and Evasive is never set — even though
// the original command fails bash parsing.
//
// Fix: PS transformation is gated behind runtime.GOOS == "windows", so on Linux/macOS
// a malformed command matching psVarAssignRe is never rescued from evasion detection.
func TestEvasive_PSTransformBypass(t *testing.T) {
	ext := NewExtractor()
	// $secret="password" matches psVarAssignRe (triggers looksLikePowerShell).
	// The unclosed single quote makes the command unparseable as bash on all platforms.
	// On non-Windows the GOOS guard prevents PS transform from running; on Windows the
	// transform finds no bare $secret references to substitute so parsing still fails.
	cmd := `$secret="password"; echo 'unclosed`
	args, err := json.Marshal(map[string]string{"command": cmd})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	info := ext.Extract("Bash", json.RawMessage(args))
	if !info.Evasive {
		t.Errorf("command %q should be flagged evasive (unparseable), got Evasive=false (reason: %s)",
			cmd, info.EvasiveReason)
	}
}

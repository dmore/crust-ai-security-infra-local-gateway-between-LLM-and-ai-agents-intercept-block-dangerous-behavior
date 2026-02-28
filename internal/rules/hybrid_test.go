package rules

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestHybridInterpAST(t *testing.T) {
	ext := NewExtractor()
	ext.env = map[string]string{"HOME": "/home/testuser"}

	tests := []struct {
		name       string
		cmd        string
		wantPaths  []string
		notEvasive bool
	}{
		{
			name:       "ProcSubst with variable expansion",
			cmd:        `DIR=/tmp; diff <(ls $DIR) <(ls $DIR/sub)`,
			wantPaths:  []string{"/tmp", "/tmp/sub"},
			notEvasive: true,
		},
		{
			name:       "Coproc with HOME expansion",
			cmd:        `coproc cat $HOME/.ssh/id_rsa`,
			wantPaths:  []string{"/home/testuser/.ssh/id_rsa"},
			notEvasive: true,
		},
		{
			name:       "fd dup redirect",
			cmd:        `echo hello 2>&1 | cat`,
			wantPaths:  []string{},
			notEvasive: true,
		},
		{
			name:       "safe and unsafe mix",
			cmd:        `echo safe; sleep 1 &`,
			wantPaths:  []string{},
			notEvasive: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ext.Extract("Bash", json.RawMessage(
				`{"command":`+mustJSON(tt.cmd)+`}`))
			if tt.notEvasive && info.Evasive {
				t.Errorf("expected not evasive, got reason: %s", info.EvasiveReason)
			}
			for _, want := range tt.wantPaths {
				if !slices.Contains(info.Paths, want) {
					t.Errorf("expected path %q in %v", want, info.Paths)
				}
			}
			t.Logf("OK: %q → command=%s paths=%v", tt.cmd, info.Command, info.Paths)
		})
	}
}

func TestHybridVarPropagation(t *testing.T) {
	ext := NewExtractor()
	info := ext.Extract("Bash", json.RawMessage(
		`{"command":"F=/etc/passwd; cat $F &"}`))
	if !slices.Contains(info.Paths, "/etc/passwd") {
		t.Errorf("expected /etc/passwd in paths from background stmt, got %v", info.Paths)
	}
}

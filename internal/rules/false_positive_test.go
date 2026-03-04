package rules

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestOpenClawEvasiveCommands(t *testing.T) {
	extractor := NewExtractor()

	cmds := []struct {
		name string
		cmd  string
	}{
		{"simple", "ls -la"},
		{"pipe", "cat file.go | head -20"},
		{"cmd_subst", "echo $(date)"},
		{"cmd_subst_only", "$(which python3)"},
		{"backtick_subst", "echo `date`"},
		{"proc_subst", "diff <(sort a.txt) <(sort b.txt)"},
		{"nested_subst", "cat $(find . -name '*.go')"},
		{"var_assign_subst", "RESULT=$(cat file.txt)"},
		{"subshell", "(cd /tmp && ls)"},
		{"heredoc", "cat <<EOF\nhello\nEOF"},
		{"redirect", "echo test > /dev/null 2>&1"},
		{"source_cmd", "source ~/.bashrc && echo done"},
		{"eval_cmd", "eval 'echo hello'"},
		{"xargs", "find . -name '*.go' | xargs grep pattern"},
		{"background", "sleep 1 &"},
		{"coproc", "coproc { sleep 1; }"},
		{"array_assign", "arr=(a b c); echo ${arr[@]}"},
		{"arithmetic", "echo $((1+2))"},
		{"brace_expand", "echo {a,b,c}"},
		{"process_subst_cat", "cat <(echo hello)"},
	}

	for _, tt := range cmds {
		t.Run(tt.name, func(t *testing.T) {
			info := extractor.Extract("exec", json.RawMessage(
				`{"command":`+mustJSON(tt.cmd)+`}`))
			if info.Evasive {
				t.Errorf("EVASIVE: %q → reason: %s", tt.cmd, info.EvasiveReason)
			} else {
				t.Logf("OK: %q → command=%s paths=%v", tt.cmd, info.Command, info.Paths)
			}
		})
	}
}

// TestUnparseableCommandEvasive verifies that commands which fail to parse
// ARE flagged as evasive. The rule engine cannot analyze unparseable input,
// so fail-closed (block) is the safe default to prevent bypass via malformed syntax.
func TestUnparseableCommandEvasive(t *testing.T) {
	ext := NewExtractor()

	cmds := []struct {
		name string
		cmd  string
	}{
		{"broken_pipe", "| cat"},
		{"broken_redirect", "echo >"},
		{"broken_heredoc", "cat <<"},
		{"broken_syntax", "if then fi"},
		{"lone_semicolons", "; ; ;"},
		{"broken_parens", "(((("},
		{"lone_bang", "!"},
	}

	for _, tt := range cmds {
		t.Run(tt.name, func(t *testing.T) {
			info := ext.Extract("Bash", json.RawMessage(
				`{"command":`+mustJSON(tt.cmd)+`}`))
			if !info.Evasive {
				t.Errorf("unparseable command should be evasive (fail-closed): %q", tt.cmd)
			}
		})
	}
}

// TestForkBombDetection verifies that the AST-based fork bomb detector
// catches all variants and does not false-positive on normal functions.
func TestForkBombDetection(t *testing.T) {
	ext := NewExtractor()

	must := []struct {
		name string
		cmd  string
	}{
		{"classic", ":(){ :|:& };:"},
		{"named", "bomb(){ bomb|bomb& };bomb"},
		{"multiline", "f(){\n  f\n};f"},
		{"nested_pipe", "x(){ x|x|x& };x"},
	}
	for _, tt := range must {
		t.Run("evasive/"+tt.name, func(t *testing.T) {
			info := ext.Extract("Bash", json.RawMessage(
				`{"command":`+mustJSON(tt.cmd)+`}`))
			if !info.Evasive {
				t.Errorf("fork bomb not detected: %q", tt.cmd)
			}
			t.Logf("OK evasive: %q → %s", tt.cmd, info.EvasiveReason)
		})
	}

	safe := []struct {
		name string
		cmd  string
	}{
		{"normal_func", "greet(){ echo hello; };greet"},
		{"no_self_call", "a(){ b; };a"},
		{"simple_cmd", "echo hello"},
	}
	for _, tt := range safe {
		t.Run("safe/"+tt.name, func(t *testing.T) {
			info := ext.Extract("Bash", json.RawMessage(
				`{"command":`+mustJSON(tt.cmd)+`}`))
			if info.Evasive {
				t.Errorf("false positive fork bomb: %q → %s", tt.cmd, info.EvasiveReason)
			}
		})
	}
}

// TestEvalRecursiveParsing verifies that eval arguments are recursively parsed
// as shell code, extracting paths from the inner command.
func TestEvalRecursiveParsing(t *testing.T) {
	ext := NewExtractor()

	tests := []struct {
		name      string
		cmd       string
		wantPaths []string
	}{
		{"eval_cat", `eval 'cat /etc/passwd'`, []string{"/etc/passwd"}},
		{"eval_double_quote", `eval "cat /etc/shadow"`, []string{"/etc/shadow"}},
		{"eval_multi_arg", `eval cat /etc/passwd`, []string{"/etc/passwd"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ext.Extract("Bash", json.RawMessage(
				`{"command":`+mustJSON(tt.cmd)+`}`))
			for _, want := range tt.wantPaths {
				if !slices.Contains(info.Paths, want) {
					t.Errorf("expected path %q in %v", want, info.Paths)
				}
			}
			t.Logf("OK: %q → paths=%v op=%v", tt.cmd, info.Paths, info.Operation)
		})
	}
}

func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

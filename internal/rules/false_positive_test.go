package rules

import (
	"encoding/json"
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

func mustJSON(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

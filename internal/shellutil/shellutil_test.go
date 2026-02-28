package shellutil

import (
	"testing"
)

func TestCommand(t *testing.T) {
	tests := []struct {
		name  string
		parts []string
	}{
		{"simple", []string{"ls"}},
		{"with_args", []string{"rm", "-rf", "/"}},
		{"space_in_arg", []string{"echo", "hello world"}},
		{"single_quote", []string{"echo", "it's here"}},
		{"special_chars", []string{"echo", "$(whoami)"}},
		{"empty_arg", []string{"echo", ""}},
		{"many_args", []string{"bash", "-c", "rm -rf /"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Command(tt.parts...)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == "" {
				t.Fatal("expected non-empty result")
			}
			t.Logf("Command(%v) = %q", tt.parts, got)
		})
	}
}

func TestCommand_Empty(t *testing.T) {
	_, err := Command()
	if err == nil {
		t.Fatal("expected error for empty command")
	}
}

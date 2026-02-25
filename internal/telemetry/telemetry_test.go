package telemetry

import "testing"

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{"short_ascii", "hello", 10, "hello"},
		{"exact_ascii", "hello", 5, "hello"},
		{"truncate_ascii", "hello world", 5, "hello...[truncated]"},
		// Multi-byte: "日本語テスト" is 6 runes but 18 bytes.
		// Truncating at maxLen=10 (bytes) should not corrupt mid-rune.
		{"multibyte_under_rune_limit", "日本語テスト", 10, "日本語テスト"},
		{"multibyte_truncate", "日本語テスト", 3, "日本語...[truncated]"},
		{"empty", "", 5, ""},
		{"emoji", "👋🌍🎉💻🚀", 3, "👋🌍🎉...[truncated]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateString(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncateString(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

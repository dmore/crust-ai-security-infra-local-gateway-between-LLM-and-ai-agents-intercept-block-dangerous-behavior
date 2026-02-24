package rules

import (
	"strings"
	"testing"
)

// TestDLPFalsePositives verifies DLP patterns do NOT fire on normal code
// that happens to contain similar-looking strings.
func TestDLPFalsePositives(t *testing.T) {
	engine, err := NewEngine(EngineConfig{DisableBuiltin: false})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	cases := []struct {
		desc string
		tool string
		args string
	}{
		// AWS: short strings starting with AKIA but too short
		{"AWS-like but too short", "Write",
			`{"file_path":"/tmp/test.py","content":"AKIA_PLACEHOLDER = 'not a key'"}`},
		// GitHub: ghp_ but too short (under 36 chars)
		{"GitHub-like but too short", "Write",
			`{"file_path":"/tmp/test.py","content":"ghp_short"}`},
		// Stripe: sk_test_ (test keys, not live)
		{"Stripe test key (not live)", "Write",
			`{"file_path":"/tmp/test.py","content":"STRIPE_KEY = 'sk_test_ABCDEFGHIJKLMNOPQRSTUVWXYZab'"}`},
		// Google: AIza-like but wrong length
		{"Google-like but wrong length", "Write",
			`{"file_path":"/tmp/test.py","content":"key = 'AIzaShort'"}`},
		// Normal code with "token" and "key" words
		{"normal code with key/token words", "Write",
			`{"file_path":"/tmp/test.py","content":"api_key = get_token()\nfor key in tokens:\n    print(key)"}`},
		// Hex strings that look like tokens but aren't prefixed
		{"plain hex string (no prefix)", "Write",
			`{"file_path":"/tmp/test.py","content":"hash = 'aabbccddeeff00112233445566778899'"}`},
		// UUIDs (look like Heroku but missing prefix)
		{"UUID without heroku_ prefix", "Write",
			`{"file_path":"/tmp/test.py","content":"id = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'"}`},
		// Base64 content (not a token)
		{"base64 data (not a token)", "Write",
			`{"file_path":"/tmp/test.py","content":"data = 'SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0Lg=='"}`},
		// Documentation/comments mentioning token formats
		{"documentation about token format", "Write",
			`{"file_path":"/tmp/README.md","content":"Tokens start with ghp_ followed by 36 alphanumeric characters."}`},
		// npm-like but wrong length
		{"npm-like but wrong length", "Write",
			`{"file_path":"/tmp/test.js","content":"const npm_version = '1.0.0'"}`},
		// Normal curl command without secrets
		{"curl without secrets", "Bash",
			`{"command":"curl -H 'Content-Type: application/json' https://api.example.com/data"}`},
		// Short dapi-like string (not 32 hex chars)
		{"dapi-like but too short", "Write",
			`{"file_path":"/tmp/test.py","content":"dapibus = 'lorem ipsum'"}`},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			call := ToolCall{Name: tc.tool, Arguments: []byte(tc.args)}
			result := engine.Evaluate(call)
			if result.Matched && strings.HasPrefix(result.RuleName, "builtin:dlp-") {
				t.Errorf("False positive: DLP rule '%s' fired on benign content", result.RuleName)
			} else {
				t.Logf("PASS: not blocked by DLP")
			}
		})
	}
}

// TestDLPBypass_Caught tests bypass attempts the normalizer defeats.
func TestDLPBypass_Caught(t *testing.T) {
	engine, err := NewEngine(EngineConfig{DisableBuiltin: false})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	cases := []struct {
		desc string
		tool string
		args string
	}{
		{
			"unicode escape in JSON decodes to literal AWS key",
			"Write",
			// \u0041 = A, \u004B = K → AKIA after json.Unmarshal
			`{"file_path":"/home/user/project/config.py","content":"KEY = '\u0041\u004BI\u0041` + "IOSFODNN7REALKEY1" + `'"}`,
		},
		{
			"zero-width joiner stripped from GitHub token",
			"Write",
			`{"file_path":"/home/user/project/config.py","content":"token = ` + "ghp_" + "\u200D" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123" + `"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			call := ToolCall{Name: tc.tool, Arguments: []byte(tc.args)}
			result := engine.Evaluate(call)
			if !result.Matched {
				t.Errorf("Expected BLOCKED but was ALLOWED — bypass succeeded")
			} else {
				t.Logf("Bypass defeated: blocked by '%s'", result.RuleName)
			}
		})
	}
}

// TestDLPBypass_NotCaught documents known gaps where DLP cannot detect secrets.
func TestDLPBypass_NotCaught(t *testing.T) {
	engine, err := NewEngine(EngineConfig{DisableBuiltin: false})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	cases := []struct {
		desc string
		tool string
		args string
	}{
		{
			"bash indirection: echo $SECRET > file (variable reference, no literal key)",
			"Bash",
			`{"command":"echo $AWS_SECRET_KEY > /home/user/project/config.py"}`,
		},
		{
			"base64-encoded key in write content",
			"Write",
			`{"file_path":"/home/user/project/deploy.sh","content":"echo QUtJQUlPU0ZPRE5ON1JFQUxLRVkx | base64 -d > /tmp/key"}`,
		},
		{
			"string concat in generated code",
			"Write",
			`{"file_path":"/home/user/project/config.py","content":"key = \"AK\" + \"IA\" + \"IOSFODNN7REALKEY1\""}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			call := ToolCall{Name: tc.tool, Arguments: []byte(tc.args)}
			result := engine.Evaluate(call)
			if result.Matched {
				t.Logf("Gap closed! Now blocked by '%s' (update test)", result.RuleName)
			} else {
				t.Logf("Known gap: not caught (as expected)")
			}
		})
	}
}

// TestDLPSecretDetection tests that the DLP engine blocks writes containing secrets.
func TestDLPSecretDetection(t *testing.T) {
	engine, err := NewEngine(EngineConfig{DisableBuiltin: false})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	cases := []struct {
		desc string
		tool string
		args string
	}{
		{
			"DLP: writing AWS access key",
			"Write",
			`{"file_path":"/home/user/project/config.py","content":"AWS_KEY = '` + "AKIA" + "IOSFODNN7REALKEY1" + `'"}`,
		},
		{
			"DLP: writing GitHub PAT",
			"Write",
			`{"file_path":"/home/user/project/.gitconfig","content":"token = ` + "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123" + `"}`,
		},
		{
			"DLP: writing GitHub fine-grained token",
			"Write",
			`{"file_path":"/home/user/project/config.json","content":"` + "github_pat_" + "01ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP" + `"}`,
		},
		{
			"DLP: writing Slack bot token",
			"Write",
			`{"file_path":"/home/user/project/slack.py","content":"SLACK_TOKEN = '` + "xoxb-" + "1234567890123-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWXYZab" + `'"}`,
		},
		{
			"DLP: writing Slack webhook URL",
			"Write",
			`{"file_path":"/home/user/project/webhook.yml","content":"url: ` + "https://hooks.slack" + ".com/services/" + "T0ABCDEFG/B0ABCDEFG/abcdefghijklmnopqrstuvwx" + `"}`,
		},
		{
			"DLP: writing Stripe live key",
			"Write",
			`{"file_path":"/home/user/project/stripe.py","content":"STRIPE_KEY = '` + "sk" + "_live_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZab" + `'"}`,
		},
		{
			"DLP: writing Google API key",
			"Write",
			`{"file_path":"/home/user/project/google.py","content":"API_KEY = '` + "AIza" + "SyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456" + `'"}`,
		},
		{
			"DLP: writing SendGrid API key",
			"Write",
			`{"file_path":"/home/user/project/email.py","content":"SENDGRID_KEY = '` + "SG." + "abcdefghijklmnopqrstuv" + "." + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr" + `'"}`,
		},
		{
			"DLP: writing Heroku API key",
			"Write",
			`{"file_path":"/home/user/project/heroku.py","content":"HEROKU_KEY = '` + "heroku_" + "a1b2c3d4-e5f6-7890-abcd-ef1234567890" + `'"}`,
		},
		{
			"DLP: MCP tool writing AWS key via shape detection",
			"save_file",
			`{"file_path":"/home/user/project/creds.py","content":"KEY = '` + "AKIA" + "IOSFODNN7EXAMPLE2" + `'"}`,
		},
		{
			"DLP: editing in Stripe live key",
			"Edit",
			`{"file_path":"/home/user/project/config.py","old_string":"KEY = ''","new_string":"KEY = '` + "sk" + "_live_" + "51234567890abcdefghijklmnopq" + `'"}`,
		},
		// --- New patterns ---
		{
			"DLP: writing GitLab PAT",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"GITLAB_TOKEN = '` + "glpat-" + "ABCDEFghijklmnopqrstuv" + `'"}`,
		},
		{
			"DLP: writing PyPI token",
			"Write",
			`{"file_path":"/home/user/project/.pypirc","content":"password = ` + "pypi-" + "AgEIcHlwaS5vcmcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + `"}`,
		},
		{
			"DLP: writing npm token",
			"Write",
			`{"file_path":"/home/user/project/.npmrc","content":"//registry.npmjs.org/:_authToken=` + "npm_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" + `"}`,
		},
		{
			"DLP: writing Shopify shared secret",
			"Write",
			`{"file_path":"/home/user/project/config.py","content":"SECRET = '` + "shpss_" + "aabbccddeeff00112233445566778899" + `'"}`,
		},
		{
			"DLP: writing Shopify access token",
			"Write",
			`{"file_path":"/home/user/project/config.py","content":"TOKEN = '` + "shpat_" + "aabbccddeeff00112233445566778899" + `'"}`,
		},
		{
			"DLP: writing Databricks token",
			"Write",
			`{"file_path":"/home/user/project/config.py","content":"TOKEN = '` + "dapi" + "aabbccddeeff00112233445566778899" + `'"}`,
		},
		{
			"DLP: writing Anthropic API key",
			"Write",
			`{"file_path":"/home/user/project/config.py","content":"ANTHROPIC_KEY = '` + "sk-ant-api03-" + strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst", 2) + `'"}`,
		},
		{
			"DLP: writing OpenAI project key",
			"Write",
			`{"file_path":"/home/user/project/config.py","content":"OPENAI_KEY = '` + "sk-proj-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst" + `'"}`,
		},
		{
			"DLP: writing Stripe webhook secret",
			"Write",
			`{"file_path":"/home/user/project/config.py","content":"WEBHOOK_SECRET = '` + "whsec_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZab" + `'"}`,
		},
		{
			"DLP: writing age secret key",
			"Write",
			`{"file_path":"/home/user/project/key.txt","content":"` + "AGE-SECRET-KEY-" + "1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ" + `"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			call := ToolCall{
				Name:      tc.tool,
				Arguments: []byte(tc.args),
			}
			result := engine.Evaluate(call)
			if !result.Matched {
				t.Errorf("Expected BLOCKED but was ALLOWED (tool=%s)", tc.tool)
			} else {
				t.Logf("PASS: Blocked by rule '%s'", result.RuleName)
			}
		})
	}
}

// TestToolNameSanitization verifies null bytes and control chars in tool names
// are stripped before extraction, so the tool is still correctly identified.
func TestToolNameSanitization(t *testing.T) {
	engine, err := NewEngine(EngineConfig{DisableBuiltin: false})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// "Wr\x00ite" with null byte should be sanitized to "Write" and still
	// trigger DLP on a GitHub token write.
	call := ToolCall{
		Name:      "Wr\x00ite",
		Arguments: []byte(`{"file_path":"/home/user/project/config.py","content":"token = ` + "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123" + `"}`),
	}
	result := engine.Evaluate(call)
	if !result.Matched {
		t.Errorf("Tool name with null byte: expected BLOCKED but was ALLOWED")
	} else {
		t.Logf("PASS: Null byte tool name sanitized, blocked by '%s'", result.RuleName)
	}
}

// TestNullByteWriteBlocked verifies that write content with null bytes is blocked.
func TestNullByteWriteBlocked(t *testing.T) {
	engine, err := NewEngine(EngineConfig{DisableBuiltin: false})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	call := ToolCall{
		Name:      "Write",
		Arguments: []byte(`{"file_path":"/tmp/test.txt","content":"hello` + "\x00" + `world"}`),
	}
	result := engine.Evaluate(call)
	if !result.Matched {
		t.Errorf("Null byte in write content: expected BLOCKED but was ALLOWED")
	} else if result.RuleName != "builtin:block-null-byte-write" {
		t.Errorf("Expected rule 'builtin:block-null-byte-write', got '%s'", result.RuleName)
	} else {
		t.Logf("PASS: Null byte write blocked by '%s'", result.RuleName)
	}
}

// TestNullByteWriteAllowsCleanContent verifies normal writes are not affected.
func TestNullByteWriteAllowsCleanContent(t *testing.T) {
	engine, err := NewEngine(EngineConfig{DisableBuiltin: false})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	call := ToolCall{
		Name:      "Write",
		Arguments: []byte(`{"file_path":"/tmp/test.txt","content":"hello world"}`),
	}
	result := engine.Evaluate(call)
	if result.Matched {
		t.Errorf("Clean write content: expected ALLOWED but was BLOCKED by '%s'", result.RuleName)
	} else {
		t.Logf("PASS: Clean write content allowed")
	}
}

// TestDLPScanAllOperations verifies DLP fires on execute/network operations, not just writes.
func TestDLPScanAllOperations(t *testing.T) {
	engine, err := NewEngine(EngineConfig{DisableBuiltin: false})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	cases := []struct {
		desc string
		tool string
		args string
	}{
		{
			"DLP blocks secret in curl command (OpExecute/OpNetwork)",
			"Bash",
			`{"command":"curl -H 'Authorization: Bearer ` + "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123" + `' https://api.github.com/user"}`,
		},
		{
			"DLP blocks AWS key in echo command (OpExecute)",
			"Bash",
			`{"command":"echo '` + "AKIA" + "IOSFODNN7REALKEY1" + `'"}`,
		},
		{
			"DLP blocks secret in Read tool (OpRead)",
			"Read",
			`{"file_path":"/home/user/project/config.py","content":"token = ` + "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123" + `"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			call := ToolCall{Name: tc.tool, Arguments: []byte(tc.args)}
			result := engine.Evaluate(call)
			if !result.Matched {
				t.Errorf("Expected BLOCKED but was ALLOWED — DLP missed secret in %s tool", tc.tool)
			} else {
				t.Logf("PASS: Blocked by '%s'", result.RuleName)
			}
		})
	}
}

// TestCommandUnicodeNormalization verifies that commands with zero-width
// invisible characters are normalized before PreFilter and rule matching.
func TestCommandUnicodeNormalization(t *testing.T) {
	engine, err := NewEngine(EngineConfig{DisableBuiltin: false})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	cases := []struct {
		desc    string
		args    string
		blocked bool
	}{
		{
			"zero-width joiner in command does not break matching",
			// A benign "ls" command with a zero-width joiner should not cause issues.
			`{"command":"l` + "\u200D" + `s /tmp"}`,
			false,
		},
		{
			"fullwidth chars in command flagged as evasive",
			// Fullwidth "cat" — IsSuspiciousInput flags this as evasive during extraction.
			`{"command":"` + "\uff43\uff41\uff54" + ` /etc/passwd"}`,
			true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			call := ToolCall{Name: "Bash", Arguments: []byte(tc.args)}
			result := engine.Evaluate(call)
			if tc.blocked && !result.Matched {
				t.Errorf("Expected BLOCKED but was ALLOWED")
			} else if !tc.blocked && result.Matched {
				t.Errorf("Expected ALLOWED but was BLOCKED by '%s'", result.RuleName)
			} else {
				t.Logf("PASS: result matched=%v rule='%s'", result.Matched, result.RuleName)
			}
		})
	}
}

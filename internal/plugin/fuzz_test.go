package plugin

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/rules"
)

// =============================================================================
// FuzzWireProtocol — fuzz JSON wire protocol parsing
// =============================================================================

func FuzzWireProtocol(f *testing.F) {
	// Seed corpus: valid wire requests and responses.
	f.Add([]byte(`{"method":"init","params":{"name":"test","config":{}}}`))
	f.Add([]byte(`{"method":"evaluate","params":{"tool_name":"Bash","command":"ls"}}`))
	f.Add([]byte(`{"method":"close"}`))
	f.Add([]byte(`{"result":null}`))
	f.Add([]byte(`{"result":{"plugin":"x","rule_name":"r","severity":"high","message":"m"}}`))
	f.Add([]byte(`{"error":"boom"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	f.Add([]byte(`{"method":"evaluate","params":{"tool_name":"Bash","operations":["read","write"],"paths":["/etc"],"hosts":["evil.com"],"rules":[{"name":"r1","source":"builtin","severity":"critical","actions":["read"],"block_paths":["**/.env"]}]}}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Unmarshal into WireRequest — must not panic.
		var req WireRequest
		if err := json.Unmarshal(data, &req); err == nil {
			// Valid JSON: verify round-trip.
			encoded, err := json.Marshal(req)
			if err != nil {
				t.Fatalf("Marshal(WireRequest) failed after successful Unmarshal: %v", err)
			}
			var req2 WireRequest
			if err := json.Unmarshal(encoded, &req2); err != nil {
				t.Fatalf("round-trip Unmarshal failed: %v", err)
			}
			if req.Method != req2.Method {
				t.Errorf("round-trip Method mismatch: %q vs %q", req.Method, req2.Method)
			}
		}

		// Unmarshal into WireResponse — must not panic.
		var resp WireResponse
		if err := json.Unmarshal(data, &resp); err == nil {
			encoded, err := json.Marshal(resp)
			if err != nil {
				t.Fatalf("Marshal(WireResponse) failed after successful Unmarshal: %v", err)
			}
			var resp2 WireResponse
			if err := json.Unmarshal(encoded, &resp2); err != nil {
				t.Fatalf("round-trip Unmarshal failed: %v", err)
			}
			if resp.Error != resp2.Error {
				t.Errorf("round-trip Error mismatch: %q vs %q", resp.Error, resp2.Error)
			}
		}
	})
}

// =============================================================================
// FuzzRequestDeepCopy — fuzz Request.DeepCopy isolation
// =============================================================================

func FuzzRequestDeepCopy(f *testing.F) {
	f.Add(
		"Bash",         // toolName
		`{"cmd":"ls"}`, // arguments
		"execute",      // operation
		"execute,read", // operations (comma-separated)
		"/home/user",   // paths (comma-separated)
		"example.com",  // hosts (comma-separated)
		"content",      // content
		true,           // evasive
		"rule1",        // ruleName
		"builtin",      // ruleSource
		"critical",     // ruleSeverity
		"read,write",   // ruleActions (comma-separated)
		"/etc/**",      // ruleBlockPaths (comma-separated)
	)
	f.Add("", "", "", "", "", "", "", false, "", "", "", "", "")
	f.Add("Read", `null`, "read", "read", "/tmp/a,/tmp/b", "a.com,b.com", "", false, "r", "user", "warning", "delete", "/x,/y,/z")

	f.Fuzz(func(t *testing.T, toolName, arguments, operation, operations, paths, hosts, content string, evasive bool, ruleName, ruleSource, ruleSeverity, ruleActions, ruleBlockPaths string) {
		splitNonEmpty := func(s, sep string) []string {
			if s == "" {
				return nil
			}
			parts := []string{}
			start := 0
			for i := range len(s) {
				if string(s[i]) == sep {
					parts = append(parts, s[start:i])
					start = i + 1
				}
			}
			parts = append(parts, s[start:])
			return parts
		}

		splitOps := func(s, sep string) []rules.Operation {
			raw := splitNonEmpty(s, sep)
			if raw == nil {
				return nil
			}
			ops := make([]rules.Operation, len(raw))
			for i, r := range raw {
				ops[i] = rules.Operation(r)
			}
			return ops
		}

		var args json.RawMessage
		if json.Valid([]byte(arguments)) {
			args = json.RawMessage(arguments)
		}

		req := Request{
			ToolName:   toolName,
			Arguments:  args,
			Operation:  rules.Operation(operation),
			Operations: splitOps(operations, ","),
			Paths:      splitNonEmpty(paths, ","),
			Hosts:      splitNonEmpty(hosts, ","),
			Content:    content,
			Evasive:    evasive,
			Rules: []RuleSnapshot{{
				Name:       ruleName,
				Source:     rules.Source(ruleSource),
				Severity:   rules.Severity(ruleSeverity),
				Actions:    splitOps(ruleActions, ","),
				BlockPaths: splitNonEmpty(ruleBlockPaths, ","),
			}},
		}

		cp := req.DeepCopy()

		// Verify equal content.
		if cp.ToolName != req.ToolName {
			t.Errorf("ToolName mismatch: %q vs %q", cp.ToolName, req.ToolName)
		}
		if cp.Operation != req.Operation {
			t.Errorf("Operation mismatch")
		}
		if cp.Content != req.Content {
			t.Errorf("Content mismatch")
		}
		if cp.Evasive != req.Evasive {
			t.Errorf("Evasive mismatch")
		}
		if len(cp.Operations) != len(req.Operations) {
			t.Errorf("Operations length mismatch")
		}
		if len(cp.Paths) != len(req.Paths) {
			t.Errorf("Paths length mismatch")
		}
		if len(cp.Hosts) != len(req.Hosts) {
			t.Errorf("Hosts length mismatch")
		}
		if len(cp.Rules) != len(req.Rules) {
			t.Errorf("Rules length mismatch")
		}

		// Mutate the copy — original must be unaffected.
		if len(cp.Operations) > 0 {
			cp.Operations[0] = rules.Operation("CORRUPTED")
			if req.Operations[0] == rules.Operation("CORRUPTED") {
				t.Error("DeepCopy: mutating copy Operations affected original")
			}
		}
		if len(cp.Paths) > 0 {
			cp.Paths[0] = "CORRUPTED"
			if req.Paths[0] == "CORRUPTED" {
				t.Error("DeepCopy: mutating copy Paths affected original")
			}
		}
		if len(cp.Hosts) > 0 {
			cp.Hosts[0] = "CORRUPTED"
			if req.Hosts[0] == "CORRUPTED" {
				t.Error("DeepCopy: mutating copy Hosts affected original")
			}
		}
		if len(cp.Arguments) > 0 {
			cp.Arguments[0] = 'X'
			if len(req.Arguments) > 0 && req.Arguments[0] == 'X' {
				t.Error("DeepCopy: mutating copy Arguments affected original")
			}
		}
		if len(cp.Rules) > 0 {
			cp.Rules[0].Name = "CORRUPTED"
			if req.Rules[0].Name == "CORRUPTED" {
				t.Error("DeepCopy: mutating copy Rules affected original")
			}
		}
	})
}

// =============================================================================
// FuzzResultValidation — fuzz severity/action validation
// =============================================================================

func FuzzResultValidation(f *testing.F) {
	f.Add("critical", "block")
	f.Add("high", "log")
	f.Add("warning", "alert")
	f.Add("info", "")
	f.Add("", "")
	f.Add("banana", "banana")
	f.Add("CRITICAL", "BLOCK")
	f.Add("HIGH", "allow")
	f.Add("\x00\xff", "\x00\xff")

	f.Fuzz(func(t *testing.T, severity, action string) {
		r := &Result{Severity: rules.Severity(severity), Action: rules.Action(action)}

		// EffectiveSeverity must always return a valid severity.
		es := r.EffectiveSeverity()
		if !rules.ValidSeverities[es] {
			t.Errorf("EffectiveSeverity(%q) = %q, which is not a valid severity", severity, es)
		}

		// EffectiveAction must always return a non-empty string.
		ea := r.EffectiveAction()
		if ea == "" {
			t.Errorf("EffectiveAction(%q) returned empty string", action)
		}

		// When action is empty, EffectiveAction must return "block".
		if action == "" && ea != rules.ActionBlock {
			t.Errorf("EffectiveAction(\"\") = %q, want \"block\"", ea)
		}

		// EffectiveAction must return a valid action.
		if !rules.ValidResponseActions[ea] {
			t.Errorf("EffectiveAction(%q) = %q, which is not a valid action", action, ea)
		}

		// When action is valid, EffectiveAction must return it as-is.
		if rules.ValidResponseActions[rules.Action(action)] && ea != rules.Action(action) {
			t.Errorf("EffectiveAction(%q) = %q, want %q", action, ea, action)
		}

		// When action is invalid or empty, EffectiveAction must return "block".
		if !rules.ValidResponseActions[rules.Action(action)] && ea != rules.ActionBlock {
			t.Errorf("EffectiveAction(%q) = %q, want \"block\"", action, ea)
		}
	})
}

// =============================================================================
// FuzzEvaluateRequest — fuzz the full Registry.Evaluate path
// =============================================================================

func FuzzEvaluateRequest(f *testing.F) {
	f.Add("Bash", `{"command":"ls"}`, "execute", "/home/user", "example.com", false)
	f.Add("Read", `null`, "read", "/etc/passwd", "", true)
	f.Add("", "", "", "", "", false)
	f.Add("Write", `{"path":"/tmp/x"}`, "write", "/tmp/x,/tmp/y", "a.com,b.com", true)

	f.Fuzz(func(t *testing.T, toolName, arguments, operation, paths, hosts string, evasive bool) {
		var args json.RawMessage
		if json.Valid([]byte(arguments)) {
			args = json.RawMessage(arguments)
		}

		var pathSlice, hostSlice []string
		if paths != "" {
			pathSlice = splitSimple(paths)
		}
		if hosts != "" {
			hostSlice = splitSimple(hosts)
		}

		req := Request{
			ToolName:  toolName,
			Arguments: args,
			Operation: rules.Operation(operation),
			Paths:     pathSlice,
			Hosts:     hostSlice,
			Evasive:   evasive,
			Rules: []RuleSnapshot{
				{Name: "fuzz-rule", Source: rules.SourceBuiltin, Severity: rules.SeverityHigh, Actions: []rules.Operation{rules.OpRead}},
			},
		}

		// Registry with an allow plugin and a block plugin.
		pool := NewPool(4, 100*time.Millisecond)
		reg := NewRegistry(pool)
		defer reg.Close()

		reg.Register(&allowPlugin{name: "allow"}, nil)
		reg.Register(&blockPlugin{
			name:   "blocker",
			result: Result{RuleName: "fuzz:block", Severity: rules.SeverityHigh, Message: "blocked by fuzz"},
		}, nil)

		result := reg.Evaluate(t.Context(), req)

		// Must never panic; result must be valid if non-nil.
		if result != nil {
			if result.Plugin == "" {
				t.Error("non-nil result should have Plugin name set")
			}
			if !rules.ValidSeverities[result.Severity] {
				t.Errorf("result has invalid severity %q after Evaluate normalization", result.Severity)
			}
		}
	})
}

// splitSimple splits a string by comma — simple helper for fuzz targets.
func splitSimple(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	start := 0
	for i := range len(s) {
		if s[i] == ',' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}

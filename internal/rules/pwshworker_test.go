//go:build windows

package rules

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// psaFinding is a PSScriptAnalyzer diagnostic result.
type psaFinding struct {
	RuleName string `json:"RuleName"`
	Severity string `json:"Severity"`
	Line     int    `json:"Line"`
	Column   int    `json:"Column"`
	Message  string `json:"Message"`
}

// TestPSScriptAnalyzer lints psBootstrapScript with PSScriptAnalyzer.
// It is skipped when PSScriptAnalyzer is not installed or pwsh is absent.
// Run with: go test -run TestPSScriptAnalyzer ./internal/rules/...
func TestPSScriptAnalyzer(t *testing.T) {
	pwshPath, ok := FindPwsh()
	if !ok {
		t.Skip("pwsh/powershell not found")
	}

	// Check PSScriptAnalyzer availability.
	check := exec.Command(pwshPath, "-NoProfile", "-NonInteractive", "-Command",
		"if (Get-Module -ListAvailable PSScriptAnalyzer) { exit 0 } else { exit 1 }")
	if err := check.Run(); err != nil {
		t.Skip("PSScriptAnalyzer not installed: run Install-Module PSScriptAnalyzer")
	}

	// Write the bootstrap script to a temp .ps1 file so PSScriptAnalyzer can
	// analyze it by path (avoids all -ScriptDefinition quoting issues).
	// Prepend UTF-8 BOM: PSUseBOMForUnicodeEncodedFile fires on BOM-less UTF-8 files.
	tmpPath := filepath.Join(t.TempDir(), "crust-psa.ps1")
	content := append([]byte{0xEF, 0xBB, 0xBF}, []byte(psBootstrapScript)...)
	if err := os.WriteFile(tmpPath, content, 0o600); err != nil {
		t.Fatal(err)
	}

	// PowerShell script: analyze the temp file and emit JSON.
	// @() wraps the result so ConvertTo-Json always produces an array.
	psScript := `
Import-Module PSScriptAnalyzer
$results = Invoke-ScriptAnalyzer -Path '` + tmpPath + `' -IncludeDefaultRules
$out = @($results | Select-Object RuleName,
    @{N='Severity';E={$_.Severity.ToString()}},
    Line, Column, Message) | ConvertTo-Json -Compress -Depth 2
if (-not $out) { $out = '[]' }
Write-Output $out
`
	cmd := exec.Command(pwshPath, "-NoProfile", "-NonInteractive", "-Command", psScript)
	raw, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		stderr := ""
		if errors.As(err, &ee) {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("PSScriptAnalyzer invocation failed: %v\nstderr: %s", err, stderr)
	}

	output := strings.TrimSpace(string(raw))
	if output == "" || output == "null" {
		output = "[]"
	}

	var findings []psaFinding
	if err := json.Unmarshal([]byte(output), &findings); err != nil {
		// PSScriptAnalyzer returns a single object (not array) for exactly one finding.
		var single psaFinding
		if err2 := json.Unmarshal([]byte(output), &single); err2 != nil {
			t.Fatalf("parse PSScriptAnalyzer output: %v\nraw: %s", err, output)
		}
		findings = []psaFinding{single}
	}

	for _, f := range findings {
		t.Errorf("PSScriptAnalyzer [%s/%s] line %d:%d — %s",
			f.Severity, f.RuleName, f.Line, f.Column, f.Message)
	}
	if len(findings) == 0 {
		t.Logf("PSScriptAnalyzer: no findings (all 70 default rules passed)")
	}
}

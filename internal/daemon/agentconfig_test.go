package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPatchAndRestore(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.json")

	// Write initial config
	initial := map[string]any{
		"baseUrl": "https://api.example.com",
		"model":   "gpt-4",
	}
	data, err := json.MarshalIndent(initial, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	proxyURL := "http://localhost:9090"

	// Patch
	if err := patchAgentConfig(configPath, "baseUrl", proxyURL); err != nil {
		t.Fatalf("patch: %v", err)
	}

	// Verify patched config
	patched := readJSON(t, configPath)
	if got := patched["baseUrl"]; got != proxyURL {
		t.Errorf("after patch: baseUrl = %q, want %q", got, proxyURL)
	}
	if got := patched["model"]; got != "gpt-4" {
		t.Errorf("after patch: model = %q, want %q", got, "gpt-4")
	}

	// Verify backup exists
	backupPath := configPath + backupSuffix
	backup, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("backup missing: %v", err)
	}
	if string(backup) != "https://api.example.com" {
		t.Errorf("backup = %q, want %q", backup, "https://api.example.com")
	}

	// Restore
	if err := restoreAgentConfig(configPath, "baseUrl"); err != nil {
		t.Fatalf("restore: %v", err)
	}

	// Verify restored config
	restored := readJSON(t, configPath)
	if got := restored["baseUrl"]; got != "https://api.example.com" {
		t.Errorf("after restore: baseUrl = %q, want %q", got, "https://api.example.com")
	}
	if got := restored["model"]; got != "gpt-4" {
		t.Errorf("after restore: model = %q, want %q", got, "gpt-4")
	}

	// Verify backup removed
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Error("backup file should be removed after restore")
	}
}

func TestPatchIdempotent(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.json")

	proxyURL := "http://localhost:9090"

	// Config already pointing at proxy
	initial := map[string]any{"baseUrl": proxyURL}
	data, _ := json.MarshalIndent(initial, "", "  ")
	_ = os.WriteFile(configPath, data, 0o644)

	if err := patchAgentConfig(configPath, "baseUrl", proxyURL); err != nil {
		t.Fatalf("patch: %v", err)
	}

	// No backup should be created
	backupPath := configPath + backupSuffix
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Error("should not create backup when already patched")
	}
}

func TestPatchMissingFile(t *testing.T) {
	err := patchAgentConfig("/nonexistent/path/config.json", "baseUrl", "http://localhost:9090")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestRestoreNoBackup(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.json")
	_ = os.WriteFile(configPath, []byte(`{"baseUrl":"x"}`), 0o644)

	err := restoreAgentConfig(configPath, "baseUrl")
	if err == nil {
		t.Error("expected error when no backup exists")
	}
}

func TestPatchEmptyOriginal(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "agent.json")

	// Config without baseUrl key
	initial := map[string]any{"model": "gpt-4"}
	data, _ := json.MarshalIndent(initial, "", "  ")
	_ = os.WriteFile(configPath, data, 0o644)

	proxyURL := "http://localhost:9090"

	if err := patchAgentConfig(configPath, "baseUrl", proxyURL); err != nil {
		t.Fatalf("patch: %v", err)
	}

	// Verify patched
	patched := readJSON(t, configPath)
	if got := patched["baseUrl"]; got != proxyURL {
		t.Errorf("baseUrl = %q, want %q", got, proxyURL)
	}

	// Restore should set baseUrl to "" (the backup content)
	if err := restoreAgentConfig(configPath, "baseUrl"); err != nil {
		t.Fatalf("restore: %v", err)
	}

	restored := readJSON(t, configPath)
	if got := restored["baseUrl"]; got != "" {
		t.Errorf("after restore: baseUrl = %q, want empty", got)
	}
}

func readJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		t.Fatal(err)
	}
	return obj
}

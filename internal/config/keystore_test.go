package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/zalando/go-keyring"
)

func init() {
	// Use in-memory mock keyring for all tests — never touches real OS keyring.
	keyring.MockInit()
}

func TestKeystoreGet_Keyring(t *testing.T) {
	if err := keyring.Set(keystoreService, "test_key", "secret123"); err != nil {
		t.Fatalf("mock keyring set: %v", err)
	}
	t.Cleanup(func() { keyring.Delete(keystoreService, "test_key") })
	val, err := keystoreGet("test_key")
	if err != nil {
		t.Fatalf("keystoreGet: %v", err)
	}
	if val != "secret123" {
		t.Errorf("got %q, want %q", val, "secret123")
	}
}

func TestKeystoreGet_NotFound(t *testing.T) {
	_, err := keystoreGet("nonexistent_key_" + t.Name())
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("got err=%v, want ErrKeyNotFound", err)
	}
}

func TestKeystoreSet_Keyring(t *testing.T) {
	if err := keystoreSet("set_test", "value456"); err != nil {
		t.Fatalf("keystoreSet: %v", err)
	}
	t.Cleanup(func() { keyring.Delete(keystoreService, "set_test") })
	val, err := keyring.Get(keystoreService, "set_test")
	if err != nil {
		t.Fatalf("keyring.Get: %v", err)
	}
	if val != "value456" {
		t.Errorf("got %q, want %q", val, "value456")
	}
}

func TestKeystoreDelete(t *testing.T) {
	if err := keystoreSet("del_test", "tobedeleted"); err != nil {
		t.Fatalf("keystoreSet: %v", err)
	}
	if err := keystoreDelete("del_test"); err != nil {
		t.Fatalf("keystoreDelete: %v", err)
	}
	_, err := keystoreGet("del_test")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("got err=%v, want ErrKeyNotFound after delete", err)
	}
}

func TestFileFallback_SetAndGet(t *testing.T) {
	// Override secrets file path to temp dir.
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	// Create .crust dir
	if err := os.MkdirAll(filepath.Join(tmp, ".crust"), 0700); err != nil {
		t.Fatal(err)
	}

	if err := fileSet("file_key", "file_val"); err != nil {
		t.Fatalf("fileSet: %v", err)
	}

	val, err := fileGet("file_key")
	if err != nil {
		t.Fatalf("fileGet: %v", err)
	}
	if val != "file_val" {
		t.Errorf("got %q, want %q", val, "file_val")
	}

	// Verify file permissions on Unix.
	path := filepath.Join(tmp, ".crust", secretsFileName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file perms = %o, want 0600", perm)
	}
}

func TestFileFallback_Delete(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	if err := os.MkdirAll(filepath.Join(tmp, ".crust"), 0700); err != nil {
		t.Fatal(err)
	}

	if err := fileSet("del_key", "val"); err != nil {
		t.Fatalf("fileSet: %v", err)
	}
	if err := fileDelete("del_key"); err != nil {
		t.Fatalf("fileDelete: %v", err)
	}
	_, err := fileGet("del_key")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("got err=%v, want ErrKeyNotFound after delete", err)
	}
}

func TestLoadSecretsWithDefaults_CLIOverride(t *testing.T) {
	s, err := LoadSecretsWithDefaults("cli-api-key", "cli-db-key")
	if err != nil {
		t.Fatalf("LoadSecretsWithDefaults: %v", err)
	}
	if s.LLMAPIKey != "cli-api-key" {
		t.Errorf("LLMAPIKey = %q, want %q", s.LLMAPIKey, "cli-api-key")
	}
	if s.DBKey != "cli-db-key" {
		t.Errorf("DBKey = %q, want %q", s.DBKey, "cli-db-key")
	}
}

func TestSaveAndLoadSecrets(t *testing.T) {
	s := &Secrets{LLMAPIKey: "saved-api", DBKey: "saved-db-key-16ch"}
	if err := SaveSecrets(s); err != nil {
		t.Fatalf("SaveSecrets: %v", err)
	}
	t.Cleanup(func() {
		keystoreDelete(keyLLMAPIKey)
		keystoreDelete(keyDBKey)
	})

	loaded, err := LoadSecrets()
	if err != nil {
		t.Fatalf("LoadSecrets: %v", err)
	}
	if loaded.LLMAPIKey != "saved-api" {
		t.Errorf("LLMAPIKey = %q, want %q", loaded.LLMAPIKey, "saved-api")
	}
	if loaded.DBKey != "saved-db-key-16ch" {
		t.Errorf("DBKey = %q, want %q", loaded.DBKey, "saved-db-key-16ch")
	}
}

func TestSecrets_Validate(t *testing.T) {
	s := &Secrets{}
	if err := s.Validate(); err == nil {
		t.Error("Validate should fail when LLMAPIKey is empty")
	}
	s.LLMAPIKey = "test"
	if err := s.Validate(); err != nil {
		t.Errorf("Validate should pass: %v", err)
	}
}

func TestSecrets_ValidateDBKey(t *testing.T) {
	s := &Secrets{DBKey: "short"}
	if err := s.ValidateDBKey(); err == nil {
		t.Error("ValidateDBKey should fail for keys shorter than 16 chars")
	}
	s.DBKey = "sixteen_char_key"
	if err := s.ValidateDBKey(); err != nil {
		t.Errorf("ValidateDBKey should pass: %v", err)
	}
}

func TestSecrets_MaskLLMAPIKey(t *testing.T) {
	tests := []struct {
		key  string
		want string
	}{
		{"", "(not set)"},
		{"short", "****"},
		{"sk-ant-1234567890", "sk-a****7890"},
	}
	for _, tt := range tests {
		s := &Secrets{LLMAPIKey: tt.key}
		if got := s.MaskLLMAPIKey(); got != tt.want {
			t.Errorf("MaskLLMAPIKey(%q) = %q, want %q", tt.key, got, tt.want)
		}
	}
}

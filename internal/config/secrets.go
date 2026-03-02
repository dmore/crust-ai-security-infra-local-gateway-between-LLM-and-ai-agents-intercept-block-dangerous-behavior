package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
)

const (
	// Keystore key names for Crust's own secrets.
	keyLLMAPIKey = "llm_api_key" //nolint:gosec // G101: not a credential, just a key name
	keyDBKey     = "db_key"
)

// Secrets holds sensitive configuration loaded from the OS keyring
// or file fallback (~/.crust/secrets.json).
// SECURITY: Secrets are never loaded from environment variables
// (env vars are visible via /proc/<pid>/environ on Linux).
type Secrets struct {
	LLMAPIKey string
	DBKey     string
}

// LoadSecrets loads secrets from the keystore (OS keyring → file fallback).
// If no DB encryption key exists, one is auto-generated and stored.
func LoadSecrets() (*Secrets, error) {
	var s Secrets

	if val, err := keystoreGet(keyLLMAPIKey); err == nil {
		s.LLMAPIKey = val
	} else if !errors.Is(err, ErrKeyNotFound) {
		return nil, err
	}

	if val, err := keystoreGet(keyDBKey); err == nil {
		s.DBKey = val
	} else if !errors.Is(err, ErrKeyNotFound) {
		return nil, err
	}

	// Auto-generate DB encryption key on first run.
	if s.DBKey == "" {
		key, err := generateDBKey()
		if err != nil {
			return nil, err
		}
		if err := keystoreSet(keyDBKey, key); err != nil {
			return nil, err
		}
		s.DBKey = key
	}

	return &s, nil
}

// generateDBKey returns a cryptographically random 32-byte hex string (64 chars).
func generateDBKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// LoadSecretsWithDefaults loads secrets, using provided defaults (CLI flags)
// if the keystore has no value set.
func LoadSecretsWithDefaults(apiKey, dbKey string) (*Secrets, error) {
	s, err := LoadSecrets()
	if err != nil {
		return nil, err
	}

	// CLI flags override keystore values (highest priority).
	if apiKey != "" {
		s.LLMAPIKey = apiKey
	}
	if dbKey != "" {
		s.DBKey = dbKey
	}

	return s, nil
}

// SaveSecrets persists secrets to the keystore (OS keyring → file fallback).
func SaveSecrets(s *Secrets) error {
	if s.LLMAPIKey != "" {
		if err := keystoreSet(keyLLMAPIKey, s.LLMAPIKey); err != nil {
			return err
		}
	}
	if s.DBKey != "" {
		if err := keystoreSet(keyDBKey, s.DBKey); err != nil {
			return err
		}
	}
	return nil
}

// Validate validates that required secrets are set.
func (s *Secrets) Validate() error {
	if s.LLMAPIKey == "" {
		return errors.New("LLM API key is required (use --api-key flag)")
	}
	return nil
}

// ValidateDBKey validates the database encryption key if set.
func (s *Secrets) ValidateDBKey() error {
	if s.DBKey != "" && len(s.DBKey) < 16 {
		return errors.New("database encryption key must be at least 16 characters")
	}
	return nil
}

// HasDBEncryption returns true if database encryption is configured.
func (s *Secrets) HasDBEncryption() bool {
	return s.DBKey != ""
}

// MaskLLMAPIKey returns a masked version of the LLM API key for logging.
func (s *Secrets) MaskLLMAPIKey() string {
	if s.LLMAPIKey == "" {
		return "(not set)"
	}
	if len(s.LLMAPIKey) <= 8 {
		return "****"
	}
	return s.LLMAPIKey[:4] + "****" + s.LLMAPIKey[len(s.LLMAPIKey)-4:]
}

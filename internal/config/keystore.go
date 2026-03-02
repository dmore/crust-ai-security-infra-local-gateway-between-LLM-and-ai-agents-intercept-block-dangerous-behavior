package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/BakeLens/crust/internal/fileutil"
	"github.com/zalando/go-keyring"
)

const (
	keystoreService = "crust"
	secretsFileName = "secrets.json"
)

// ErrKeyNotFound is returned when a secret key is not found in any store.
var ErrKeyNotFound = errors.New("secret not found")

// secretsMap is the JSON structure of the fallback secrets file.
type secretsMap map[string]string

// secretsFilePath returns the path to ~/.crust/secrets.json.
func secretsFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}
	return filepath.Join(home, ".crust", secretsFileName)
}

// keystoreGet retrieves a secret by key name.
// Priority: OS keyring first, then file fallback.
func keystoreGet(key string) (string, error) {
	val, err := keyring.Get(keystoreService, key)
	if err == nil && val != "" {
		return val, nil
	}
	return fileGet(key)
}

// keystoreSet stores a secret.
// Tries OS keyring first; falls back to file if keyring is unavailable.
func keystoreSet(key, value string) error {
	if err := keyring.Set(keystoreService, key, value); err == nil {
		return nil
	}
	// Keyring unavailable (headless/Docker/CI), use file fallback.
	return fileSet(key, value)
}

// keystoreDelete removes a secret from both keyring and file.
func keystoreDelete(key string) error {
	//nolint:errcheck // best-effort: keyring entry may not exist
	keyring.Delete(keystoreService, key)
	return fileDelete(key)
}

// fileGet reads a secret from the fallback secrets.json file with a shared lock.
func fileGet(key string) (string, error) {
	path := secretsFilePath()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrKeyNotFound
		}
		return "", err
	}
	defer f.Close()

	if err := lockShared(f); err != nil {
		return "", err
	}
	defer unlock(f)

	var secrets secretsMap
	if err := json.NewDecoder(f).Decode(&secrets); err != nil {
		return "", ErrKeyNotFound
	}

	val, ok := secrets[key]
	if !ok {
		return "", ErrKeyNotFound
	}
	return val, nil
}

// fileSet writes a secret to the fallback secrets.json file with an exclusive lock.
func fileSet(key, value string) error {
	path := secretsFilePath()

	if err := fileutil.SecureMkdirAll(filepath.Dir(path)); err != nil {
		return err
	}

	f, err := fileutil.SecureOpenFile(path, os.O_RDWR|os.O_CREATE)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := lockExclusive(f); err != nil {
		return err
	}
	defer unlock(f)

	// Read existing secrets (may be empty or invalid).
	secrets := make(secretsMap)
	if err := json.NewDecoder(f).Decode(&secrets); err != nil {
		secrets = make(secretsMap) // reset on decode error
	}

	secrets[key] = value

	data, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	_, err = f.Write(data)
	return err
}

// fileDelete removes a secret from the fallback secrets.json file.
func fileDelete(key string) error {
	path := secretsFilePath()
	f, err := fileutil.SecureOpenFile(path, os.O_RDWR)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	if err := lockExclusive(f); err != nil {
		return err
	}
	defer unlock(f)

	var secrets secretsMap
	if err := json.NewDecoder(f).Decode(&secrets); err != nil {
		return nil // file empty or invalid
	}

	delete(secrets, key)

	data, err := json.MarshalIndent(secrets, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	if err := f.Truncate(0); err != nil {
		return err
	}
	if _, err := f.Seek(0, 0); err != nil {
		return err
	}
	_, err = f.Write(data)
	return err
}

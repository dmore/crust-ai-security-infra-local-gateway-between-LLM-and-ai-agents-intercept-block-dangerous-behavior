package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BakeLens/crust/internal/fileutil"
	"github.com/BakeLens/crust/internal/logger"
	"github.com/zalando/go-keyring"
)

var ksLog = logger.New("keystore")

const (
	keystoreService = "crust"
	secretsFileName = "secrets.json"
)

// ErrKeyNotFound is returned when a secret key is not found in any store.
var ErrKeyNotFound = errors.New("secret not found")

// secretsMap is the JSON structure of the fallback secrets file.
type secretsMap map[string]string

// errNoHomeDir is returned when the home directory cannot be determined.
var errNoHomeDir = errors.New("cannot determine home directory; set $HOME")

// secretsFilePath returns the path to ~/.crust/secrets.json.
func secretsFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errNoHomeDir
	}
	return filepath.Join(home, ".crust", secretsFileName), nil
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
	if err := keyring.Set(keystoreService, key, value); err != nil {
		ksLog.Warn("OS keyring unavailable, using file fallback: %v", err)
		return fileSet(key, value)
	}
	return nil
}

// keystoreDelete removes a secret from both keyring and file.
func keystoreDelete(key string) error {
	//nolint:errcheck // best-effort: keyring entry may not exist
	keyring.Delete(keystoreService, key)
	return fileDelete(key)
}

// fileGet reads a secret from the fallback secrets.json file with a shared lock.
func fileGet(key string) (string, error) {
	path, err := secretsFilePath()
	if err != nil {
		return "", err
	}
	f, err := fileutil.OpenReadLocked(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", ErrKeyNotFound
		}
		return "", err
	}
	defer f.Close()
	defer fileutil.Unlock(f)

	var secrets secretsMap
	if err := json.NewDecoder(f).Decode(&secrets); err != nil {
		return "", fmt.Errorf("secrets.json is corrupted: %w", err)
	}

	val, ok := secrets[key]
	if !ok {
		return "", ErrKeyNotFound
	}
	return val, nil
}

// fileSet writes a secret to the fallback secrets.json file with an exclusive lock.
func fileSet(key, value string) error {
	path, err := secretsFilePath()
	if err != nil {
		return err
	}

	if err := fileutil.SecureMkdirAll(filepath.Dir(path)); err != nil {
		return err
	}

	f, err := fileutil.OpenExclusive(path, os.O_RDWR|os.O_CREATE)
	if err != nil {
		return err
	}
	defer f.Close()
	defer fileutil.Unlock(f)

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
	path, err := secretsFilePath()
	if err != nil {
		return err
	}
	f, err := fileutil.OpenExclusive(path, os.O_RDWR)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	defer fileutil.Unlock(f)

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

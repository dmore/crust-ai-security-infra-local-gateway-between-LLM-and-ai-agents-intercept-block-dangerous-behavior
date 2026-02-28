package daemon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BakeLens/crust/internal/fileutil"
)

const backupSuffix = ".crust-backup"

// agentConfig describes how to patch a single agent's config file.
type agentConfig struct {
	// Name is a human-readable label for log messages.
	Name string
	// ConfigPath returns the absolute path to the agent's config file.
	ConfigPath func() string
	// URLKey is the JSON key that holds the base URL (e.g., "baseUrl").
	URLKey string
	// PathSuffix is appended to the proxy base URL (e.g., "/v1" for
	// OpenAI-compatible agents). Empty for agents that use the bare URL.
	PathSuffix string
}

// knownAgents lists agents whose configs are patched on daemon start
// and restored on daemon stop.
var knownAgents = []agentConfig{
	{
		Name: "OpenClaw",
		ConfigPath: func() string {
			home, err := os.UserHomeDir()
			if err != nil || home == "" {
				return ""
			}
			return filepath.Join(home, ".openclaw", "openclaw.json")
		},
		URLKey: "baseUrl",
	},
}

// PatchAgentConfigs reads each known agent's config file, saves the
// original URL value to a backup file alongside it, and overwrites
// the URL to point at the Crust proxy.
//
// Only agents whose config file already exists are touched.
// Errors are non-fatal — a failed patch just means that agent
// won't go through the proxy automatically.
func PatchAgentConfigs(proxyPort int) {
	for _, agent := range knownAgents {
		path := agent.ConfigPath()
		if path == "" {
			continue
		}
		proxyURL := fmt.Sprintf("http://localhost:%d%s", proxyPort, agent.PathSuffix)
		if err := patchAgentConfig(path, agent.URLKey, proxyURL); err != nil {
			// Silently skip — config file may not exist.
			continue
		}
	}
}

// RestoreAgentConfigs restores every known agent config from its
// backup file. Called from CleanupPID on daemon shutdown.
func RestoreAgentConfigs() {
	for _, agent := range knownAgents {
		path := agent.ConfigPath()
		if path == "" {
			continue
		}
		_ = restoreAgentConfig(path, agent.URLKey) //nolint:errcheck // best-effort restore
	}
}

// patchAgentConfig saves the original value of urlKey into a backup
// file, then overwrites it with proxyURL.
func patchAgentConfig(configPath, urlKey, proxyURL string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err // file doesn't exist or unreadable
	}

	obj := make(map[string]any)
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}

	original, _ := obj[urlKey].(string)
	if original == proxyURL {
		return nil // already pointing at Crust
	}

	// Save original value to backup file
	backupPath := configPath + backupSuffix
	if err := fileutil.SecureWriteFile(backupPath, []byte(original)); err != nil {
		return err
	}

	// Patch the URL
	obj[urlKey] = proxyURL
	patched, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return err
	}

	return fileutil.SecureWriteFile(configPath, append(patched, '\n'))
}

// restoreAgentConfig reads the original URL from the backup file
// and writes it back into the config, then removes the backup.
func restoreAgentConfig(configPath, urlKey string) error {
	backupPath := configPath + backupSuffix
	original, err := os.ReadFile(backupPath)
	if err != nil {
		return err // no backup — nothing to restore
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	obj := make(map[string]any)
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}

	obj[urlKey] = string(original)
	restored, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return err
	}

	if err := fileutil.SecureWriteFile(configPath, append(restored, '\n')); err != nil {
		return err
	}

	return os.Remove(backupPath)
}

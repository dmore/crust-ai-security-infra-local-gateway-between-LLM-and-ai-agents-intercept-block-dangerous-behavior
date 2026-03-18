//go:build libcrust

package libcrust

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BakeLens/crust/internal/daemon"
	"github.com/BakeLens/crust/internal/daemon/registry"
)

// protectState tracks the auto-protect lifecycle.
var protect struct {
	mu      sync.Mutex
	running bool
	port    int
}

// StartProtect starts the full protection stack:
// 1. Starts HTTP proxy in auto mode on an auto-assigned port
// 2. Patches all registered agent configs (HTTP URL + MCP wrapping)
// Returns the proxy port, or error.
func StartProtect() (int, error) {
	protect.mu.Lock()
	defer protect.mu.Unlock()

	if protect.running {
		return protect.port, nil
	}

	// Start proxy in auto mode (port 0 = auto-assign, empty upstream = auto mode).
	if err := StartProxy(0, "", "", ""); err != nil {
		return 0, fmt.Errorf("start proxy: %w", err)
	}

	// Get the assigned port.
	addr := ProxyAddress()
	if addr == "" {
		StopProxy()
		return 0, fmt.Errorf("proxy started but address is empty")
	}
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		StopProxy()
		return 0, fmt.Errorf("parse proxy address %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		StopProxy()
		return 0, fmt.Errorf("parse port %q: %w", portStr, err)
	}

	// Patch all agent configs to route through the proxy.
	daemon.PatchAgentConfigs(port)

	// Install Claude Code PreToolUse hook for direct tool call interception.
	crustBin := daemon.ResolveCrustBin()
	if crustBin != "" {
		if err := InstallClaudeHook(crustBin); err != nil {
			// Non-fatal: Claude Code hooks are supplementary protection.
			fmt.Fprintf(os.Stderr, "crust: install claude hook: %v\n", err)
		}
	}

	protect.running = true
	protect.port = port

	// Write port file so evaluate-hook can find the running instance.
	writePortFile(port)

	return port, nil
}

// StopProtect tears down the full protection stack:
// 1. Restores all patched agent configs
// 2. Stops the HTTP proxy
func StopProtect() {
	protect.mu.Lock()
	defer protect.mu.Unlock()

	if !protect.running {
		return
	}

	// Remove Claude Code hooks.
	if err := UninstallClaudeHook(); err != nil {
		fmt.Fprintf(os.Stderr, "crust: uninstall claude hook: %v\n", err)
	}

	daemon.RestoreAgentConfigs()
	StopProxy()
	removePortFile()
	protect.running = false
	protect.port = 0
}

// ProtectPort returns the proxy port, or 0 if not running.
func ProtectPort() int {
	protect.mu.Lock()
	defer protect.mu.Unlock()
	return protect.port
}

// ProtectStatus returns the current protection status as JSON.
func ProtectStatus() string {
	protect.mu.Lock()
	port := protect.port
	running := protect.running
	protect.mu.Unlock()

	// Get list of patched agents from registry.
	var patched []string
	for _, t := range registry.Default.Targets() {
		if registry.Default.IsPatched(t.Name()) {
			patched = append(patched, t.Name())
		}
	}
	if patched == nil {
		patched = []string{}
	}

	status := map[string]any{
		"active":         running,
		"proxy_port":     port,
		"patched_agents": patched,
	}
	out, _ := json.Marshal(status)
	return string(out)
}

// ListAgents returns a JSON array of all registered agents with their status.
func ListAgents() string {
	type agentInfo struct {
		Name    string `json:"name"`
		Patched bool   `json:"patched"`
	}
	var agents []agentInfo
	for _, t := range registry.Default.Targets() {
		agents = append(agents, agentInfo{
			Name:    t.Name(),
			Patched: registry.Default.IsPatched(t.Name()),
		})
	}
	if agents == nil {
		agents = []agentInfo{}
	}
	out, _ := json.Marshal(agents)
	return string(out)
}

// EnableAgent patches a single agent by name.
func EnableAgent(name string) error {
	protect.mu.Lock()
	port := protect.port
	protect.mu.Unlock()

	crustBin := daemon.ResolveCrustBin()
	for _, t := range registry.Default.Targets() {
		if t.Name() == name {
			return t.Patch(port, crustBin)
		}
	}
	return fmt.Errorf("agent %q not found", name)
}

// DisableAgent restores a single agent by name.
func DisableAgent(name string) error {
	for _, t := range registry.Default.Targets() {
		if t.Name() == name {
			return t.Restore()
		}
	}
	return fmt.Errorf("agent %q not found", name)
}

// portFilePath returns ~/.crust/protect.port
func portFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".crust", "protect.port")
}

// writePortFile writes the proxy port to ~/.crust/protect.port.
// Hook processes read this to find the running evaluation endpoint.
func writePortFile(port int) {
	p := portFilePath()
	if p == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	_ = os.WriteFile(p, []byte(strconv.Itoa(port)), 0o600)
}

// removePortFile removes ~/.crust/protect.port.
func removePortFile() {
	p := portFilePath()
	if p != "" {
		_ = os.Remove(p)
	}
}

// ReadPortFile reads the proxy port from ~/.crust/protect.port.
// Returns 0 if the file doesn't exist or is invalid.
func ReadPortFile() int {
	p := portFilePath()
	if p == "" {
		return 0
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(string(data))
	if err != nil {
		return 0
	}
	return port
}

// EvaluateViaRunningInstance evaluates a tool call by connecting to a running
// crust instance's HTTP endpoint. This avoids cold-starting the rule engine
// (~4s) by reusing the already-loaded engine in the running GUI/CLI process.
//
// hookInput is the raw JSON from Claude Code's PreToolUse hook (contains
// tool_name and tool_input fields among others).
//
// Returns the evaluation result JSON, or empty string if no running instance
// is available (caller should fall back to cold-start Evaluate).
func EvaluateViaRunningInstance(hookInput string) string {
	port := ReadPortFile()
	if port == 0 {
		return ""
	}

	// Quick HTTP POST to the running instance's /crust/evaluate endpoint.
	client := &http.Client{Timeout: 3 * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/crust/evaluate", port)
	resp, err := client.Post(url, "application/json", strings.NewReader(hookInput))
	if err != nil {
		return "" // instance not reachable, fall back
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "" // unexpected status, fall back
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return ""
	}
	return string(body)
}

package daemon

import (
	"log"

	"github.com/BakeLens/crust/internal/daemon/registry"
	"github.com/BakeLens/crust/internal/mcpdiscover"
)

// PatchAgentConfigs routes all registered agents through the Crust proxy.
// Called once on daemon startup. Non-fatal: a failed patch is logged and skipped.
func PatchAgentConfigs(proxyPort int) {
	crustBin, err := mcpdiscover.CrustBinaryPath()
	if err != nil {
		log.Printf("crust: cannot resolve binary path, skipping MCP wrapping: %v", err)
	}
	registry.Default.PatchAll(proxyPort, crustBin)
}

// RestoreAgentConfigs restores all patched agent configs to their originals.
// Called on daemon shutdown and by crust stop when the daemon has already exited.
func RestoreAgentConfigs() {
	registry.Default.RestoreAll()
}

package mcpdiscover

import (
	"encoding/json"
	"os"
	"strings"
)

// Discover scans all known client config locations and returns discovered MCP servers.
func Discover() DiscoverResult {
	return DiscoverWithClients(knownClients)
}

// DiscoverWithClients scans the given client definitions (used for testing).
func DiscoverWithClients(clients []ClientDef) DiscoverResult {
	var result DiscoverResult
	for _, client := range clients {
		path := client.ConfigPath()
		if path == "" {
			continue
		}
		servers, err := parseConfigFile(path, client)
		if err != nil {
			if !os.IsNotExist(err) {
				result.Errors = append(result.Errors, DiscoverError{
					Client: client.Client, ConfigPath: path, Err: err,
				})
			}
			continue
		}
		result.Servers = append(result.Servers, servers...)
	}
	return result
}

// readServersMap reads a config file and returns (root, servers-map, original-bytes, error).
// Shared by both discovery and patching.
func readServersMap(path string, serversKey string) (
	root map[string]json.RawMessage,
	servers map[string]json.RawMessage,
	data []byte,
	err error,
) {
	data, err = os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, err
	}
	if err = json.Unmarshal(data, &root); err != nil {
		return nil, nil, nil, err
	}
	serversRaw, ok := root[serversKey]
	if !ok || len(serversRaw) == 0 {
		return root, nil, data, nil
	}
	if err = json.Unmarshal(serversRaw, &servers); err != nil {
		return nil, nil, nil, err
	}
	return root, servers, data, nil
}

// extractArgs extracts string args from a parsed JSON "args" array.
func extractArgs(def map[string]any) []string {
	rawArgs, ok := def["args"].([]any)
	if !ok {
		return nil
	}
	args := make([]string, 0, len(rawArgs))
	for _, a := range rawArgs {
		if s, ok := a.(string); ok {
			args = append(args, s)
		}
	}
	return args
}

// parseConfigFile reads a config file and extracts MCP server definitions.
func parseConfigFile(path string, client ClientDef) ([]MCPServer, error) {
	_, servers, _, err := readServersMap(path, client.ServersKey)
	if err != nil {
		return nil, err
	}

	var result []MCPServer
	for name, raw := range servers {
		srv := MCPServer{
			Name:       name,
			Client:     client.Client,
			ConfigPath: path,
		}

		var def map[string]any
		if err := json.Unmarshal(raw, &def); err != nil {
			continue
		}

		if cmd, ok := def["command"].(string); ok {
			srv.Transport = TransportStdio
			srv.Command = cmd
			srv.Args = extractArgs(def)
			if env, ok := def["env"].(map[string]any); ok {
				srv.Env = make(map[string]string)
				for k, v := range env {
					if s, ok := v.(string); ok {
						srv.Env[k] = s
					}
				}
			}
			srv.AlreadyWrapped = isCrustWrapped(cmd, srv.Args)
		} else {
			for _, urlKey := range client.URLKeys {
				if u, ok := def[urlKey].(string); ok && u != "" {
					srv.Transport = TransportHTTP
					srv.URL = u
					break
				}
			}
		}

		result = append(result, srv)
	}
	return result, nil
}

// isCrustWrapped returns true if the command is already routed through crust.
func isCrustWrapped(cmd string, args []string) bool {
	if strings.HasSuffix(cmd, "crust") || strings.HasSuffix(cmd, "crust.exe") {
		return true
	}
	// Check if args contain "wrap", "gateway", or legacy "mcp-gateway"
	for _, a := range args {
		if a == "wrap" || a == "mcp-gateway" || a == "gateway" {
			return true
		}
		if a == "--" {
			break
		}
	}
	return false
}

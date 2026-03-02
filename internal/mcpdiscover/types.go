// Package mcpdiscover scans known IDE/client config files
// for MCP server definitions and can patch them to route through Crust.
package mcpdiscover

// ClientType identifies which MCP client owns a config file.
type ClientType string

const (
	ClientClaudeDesktop ClientType = "Claude Desktop"
	ClientClaudeCode    ClientType = "Claude Code"
	ClientCursor        ClientType = "Cursor"
	ClientWindsurf      ClientType = "Windsurf"
	ClientNeovim        ClientType = "Neovim (mcphub)"
)

// TransportType indicates whether the MCP server uses stdio or HTTP.
type TransportType string

const (
	TransportStdio TransportType = "stdio"
	TransportHTTP  TransportType = "http"
)

// MCPServer represents a discovered MCP server definition.
type MCPServer struct {
	Name       string            `json:"name"`
	Client     ClientType        `json:"client"`
	ConfigPath string            `json:"configPath"`
	Transport  TransportType     `json:"transport"`
	Command    string            `json:"command,omitempty"`
	Args       []string          `json:"args,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	URL        string            `json:"url,omitempty"`

	AlreadyWrapped bool `json:"alreadyWrapped"`
}

// DiscoverResult holds all discovered servers and any non-fatal scan errors.
type DiscoverResult struct {
	Servers []MCPServer     `json:"servers"`
	Errors  []DiscoverError `json:"errors"`
}

// DiscoverError records a non-fatal discovery error.
type DiscoverError struct {
	Client     ClientType `json:"client"`
	ConfigPath string     `json:"configPath"`
	Err        error      `json:"err"`
}

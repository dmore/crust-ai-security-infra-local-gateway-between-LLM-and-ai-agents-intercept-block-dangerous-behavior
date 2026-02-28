// Package mcpgateway implements a transparent stdio proxy for MCP (Model Context Protocol)
// servers, intercepting security-relevant JSON-RPC messages using Crust's rule engine.
//
// Unlike ACP wrap (which inspects agent->IDE direction), the MCP gateway inspects the
// client->server direction because MCP clients send tool calls TO the server.
package mcpgateway

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/BakeLens/crust/internal/rules"
)

// MCP parameter types

// toolsCallParams represents the params of a MCP tools/call request.
type toolsCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// resourcesReadParams represents the params of a MCP resources/read request.
type resourcesReadParams struct {
	URI string `json:"uri"`
}

// samplingCreateMessageParams represents the params of a MCP sampling/createMessage request.
// The server asks the client's LLM to process messages (potentially instructing tool use).
type samplingCreateMessageParams struct {
	Messages  json.RawMessage `json:"messages"`
	MaxTokens int             `json:"maxTokens"`
}

// elicitationCreateParams represents the params of a MCP elicitation/create request.
// The server presents a form or URL to the user (phishing vector).
type elicitationCreateParams struct {
	Message string `json:"message"`
}

// MCPMethodToToolCall converts an MCP JSON-RPC method + params into a rules.ToolCall.
//
// Returns:
//   - (*ToolCall, nil) for successfully parsed security-relevant methods
//   - (nil, nil) for non-security methods (caller should pass through)
//   - (nil, error) for security-relevant methods with malformed params (caller should block)
func MCPMethodToToolCall(method string, params json.RawMessage) (*rules.ToolCall, error) {
	// Reject nil/null params on security-relevant methods (json.Unmarshal silently
	// zero-initializes the struct, which would produce an empty name and bypass rules).
	switch method {
	case "tools/call", "resources/read", "sampling/createMessage", "elicitation/create":
		if len(params) == 0 || string(params) == "null" {
			return nil, fmt.Errorf("nil params for security method %s", method)
		}
	default:
		return nil, nil // not security-relevant
	}

	switch method {
	case "tools/call":
		var p toolsCallParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("malformed %s params: %w", method, err)
		}
		if p.Name == "" {
			return nil, fmt.Errorf("empty tool name in %s", method)
		}
		// MCP tool names are dynamic — pass through directly.
		// The rule engine's shape-based extraction handles argument parsing.
		args := p.Arguments
		if len(args) == 0 {
			args = json.RawMessage("{}")
		}
		return &rules.ToolCall{Name: p.Name, Arguments: args}, nil

	case "resources/read":
		var p resourcesReadParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("malformed %s params: %w", method, err)
		}
		if p.URI == "" {
			return nil, fmt.Errorf("empty URI in %s", method)
		}

		parsed, err := url.Parse(p.URI)
		if err != nil {
			return nil, fmt.Errorf("invalid URI in %s: %w", method, err)
		}

		// Detect filesystem paths vs remote URLs.
		// url.Parse("C:\Users\...") yields Scheme="c" (single char), which would
		// fall through to the remote-URL branch and bypass filesystem rules.
		// Valid URL schemes are always ≥2 chars (RFC 3986), so a single-letter
		// scheme is always a Windows drive letter.
		isFilePath := parsed.Scheme == "file" || parsed.Scheme == ""
		if !isFilePath && len(parsed.Scheme) == 1 {
			isFilePath = true
		}

		if isFilePath {
			var path string
			if len(parsed.Scheme) == 1 {
				// Drive-letter URI: url.Parse splits "C:" into Scheme,
				// losing it from Path. Use raw URI to preserve the full path.
				path = p.URI
			} else {
				path = parsed.Path
				if path == "" {
					path = p.URI
				}
				// file:///C:/Users/... → parsed.Path="/C:/Users/..."
				// Strip leading "/" before a Windows drive letter (X:).
				if len(path) >= 3 && path[0] == '/' && path[2] == ':' {
					path = path[1:]
				}
			}
			args, err := json.Marshal(map[string]string{"path": path})
			if err != nil {
				return nil, fmt.Errorf("marshal error: %w", err)
			}
			return &rules.ToolCall{Name: "read_file", Arguments: args}, nil
		}

		args, err := json.Marshal(map[string]string{"url": p.URI})
		if err != nil {
			return nil, fmt.Errorf("marshal error: %w", err)
		}
		return &rules.ToolCall{Name: "mcp_resource_read", Arguments: args}, nil

	case "sampling/createMessage":
		var p samplingCreateMessageParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("malformed %s params: %w", method, err)
		}
		// Pass full params as arguments so DLP and content-based rules
		// can inspect the embedded messages and system prompt.
		return &rules.ToolCall{Name: "mcp_sampling", Arguments: params}, nil

	case "elicitation/create":
		var p elicitationCreateParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("malformed %s params: %w", method, err)
		}
		if p.Message == "" {
			return nil, fmt.Errorf("empty message in %s", method)
		}
		// Pass full params so rule engine can inspect the message and schema.
		return &rules.ToolCall{Name: "mcp_elicitation", Arguments: params}, nil

	default:
		return nil, nil
	}
}

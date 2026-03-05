package mcpgateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/jsonrpc"
	"github.com/BakeLens/crust/internal/testutil"
)

func newGateway(t *testing.T, upstreamURL string) *HTTPGateway {
	t.Helper()
	engine := testutil.NewEngine(t)
	gw, err := NewHTTPGateway(upstreamURL, engine)
	if err != nil {
		t.Fatalf("NewHTTPGateway: %v", err)
	}
	return gw
}

// --- Unit tests (protocol-level, no real MCP server needed) ---

func TestHTTP_InvalidContentType(t *testing.T) {
	// Use a dummy upstream — request never reaches it
	gw := newGateway(t, "http://127.0.0.1:1")
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()

	gw.ServeHTTP(w, req)

	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("status = %d, want 415", w.Code)
	}
}

func TestHTTP_MethodNotAllowed(t *testing.T) {
	gw := newGateway(t, "http://127.0.0.1:1")
	req := httptest.NewRequest(http.MethodPut, "/", nil)
	w := httptest.NewRecorder()

	gw.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestHTTP_Upstream5xx(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}))
	defer upstream.Close()

	gw := newGateway(t, upstream.URL)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	gw.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Code)
	}
}

func TestNewHTTPGateway_InvalidURL(t *testing.T) {
	engine := testutil.NewEngine(t)
	_, err := NewHTTPGateway("not-a-url", engine)
	if err == nil {
		t.Error("expected error for invalid URL")
	}

	_, err = NewHTTPGateway("ftp://example.com", engine)
	if err == nil {
		t.Error("expected error for non-http scheme")
	}
}

// --- E2E Tests with Real MCP HTTP Server ---
// These use @modelcontextprotocol/server-everything with streamableHttp transport.

// skipHTTPE2E skips if -short or npx not available.
func skipHTTPE2E(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("E2E: skipped in -short mode")
	}
	if _, err := exec.LookPath("npx"); err != nil {
		t.Skip("E2E: npx not found in PATH")
	}
}

// freePort returns an available TCP port.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// startRealMCPHTTP starts the MCP everything server with Streamable HTTP transport.
// Returns the upstream URL and a cleanup function.
func startRealMCPHTTP(t *testing.T) (upstreamURL string, cleanup func()) {
	t.Helper()
	port := freePort(t)
	upstreamURL = fmt.Sprintf("http://127.0.0.1:%d/mcp", port)

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "npx", "-y", "@modelcontextprotocol/server-everything", "streamableHttp")
	cmd.Env = append(os.Environ(), fmt.Sprintf("PORT=%d", port))
	// Don't set cmd.Stderr — nil sends to /dev/null, avoiding the
	// "Test I/O incomplete" issue that occurs with os.Stderr or io.Discard.
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("failed to start MCP HTTP server: %v", err)
	}

	// Wait for server to be ready
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 200*time.Millisecond)
		if err == nil {
			conn.Close()
			time.Sleep(200 * time.Millisecond)
			return upstreamURL, func() {
				cancel()
				cmd.Wait()
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	cancel()
	cmd.Wait()
	t.Fatalf("MCP HTTP server failed to start within 15s on port %d", port)
	return "", nil
}

// sseResponse sends a JSON-RPC message through the gateway and parses the SSE response.
func sseResponse(t *testing.T, gw *HTTPGateway, sessionID string, body string) (*testResponse, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		req.Header.Set(sessionHeader, sessionID)
	}
	w := httptest.NewRecorder()

	gw.ServeHTTP(w, req)

	resp := w.Result()
	respBody, _ := io.ReadAll(resp.Body)
	newSID := resp.Header.Get(sessionHeader)

	ct := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "text/event-stream") {
		events := ReadSSEEvents(context.Background(), strings.NewReader(string(respBody)))
		for event := range events {
			if event.Type == sseMessageType || event.Type == "" {
				var tr testResponse
				if err := json.Unmarshal([]byte(event.Data), &tr); err == nil {
					return &tr, newSID
				}
			}
		}
		t.Logf("no JSON-RPC message in SSE response: %s", respBody)
		return nil, newSID
	}

	var tr testResponse
	if err := json.Unmarshal(respBody, &tr); err != nil {
		t.Logf("failed to parse JSON response: %v\nbody: %s", err, respBody)
		return nil, newSID
	}
	return &tr, newSID
}

// initHTTPSession initializes a session with the real MCP HTTP server through the gateway.
// Returns the session ID.
func initHTTPSession(t *testing.T, gw *HTTPGateway) string {
	t.Helper()
	_, sid := sseResponse(t, gw, "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"crust-e2e","version":"1.0.0"}}}`)
	if sid == "" {
		t.Fatal("no session ID from initialize")
	}

	// Send initialized notification
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(
		`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(sessionHeader, sid)
	w := httptest.NewRecorder()
	gw.ServeHTTP(w, req)

	return sid
}

func TestHTTPE2E_Initialize(t *testing.T) {
	skipHTTPE2E(t)
	upstreamURL, cleanup := startRealMCPHTTP(t)
	defer cleanup()

	gw := newGateway(t, upstreamURL)

	resp, sid := sseResponse(t, gw, "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"crust-e2e","version":"1.0.0"}}}`)

	if resp == nil {
		t.Fatal("no response for initialize")
	}
	if resp.Error != nil {
		t.Fatalf("initialize returned error: %s", resp.Error.Message)
	}
	if sid == "" {
		t.Error("expected Mcp-Session-Id header in response")
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to parse init result: %v", err)
	}
	if _, ok := result["protocolVersion"]; !ok {
		t.Error("initialize response missing protocolVersion")
	}
	if _, ok := result["serverInfo"]; !ok {
		t.Error("initialize response missing serverInfo")
	}
	if !gw.sessions.Exists(sid) {
		t.Error("gateway should track session from initialize response")
	}
}

func TestHTTPE2E_ToolsCallAllowed(t *testing.T) {
	skipHTTPE2E(t)
	upstreamURL, cleanup := startRealMCPHTTP(t)
	defer cleanup()

	gw := newGateway(t, upstreamURL)
	sid := initHTTPSession(t, gw)

	// Call echo tool (allowed — not a security-sensitive path)
	resp, _ := sseResponse(t, gw, sid,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello crust"}}}`)

	if resp == nil {
		t.Fatal("no response for echo tool call")
	}
	if resp.Error != nil {
		t.Fatalf("echo returned error: code=%d msg=%s", resp.Error.Code, resp.Error.Message)
	}
	if !strings.Contains(string(resp.Result), "hello crust") {
		t.Errorf("expected echo content, got: %s", string(resp.Result))
	}
}

func TestHTTPE2E_ToolsCallBlocked(t *testing.T) {
	skipHTTPE2E(t)
	upstreamURL, cleanup := startRealMCPHTTP(t)
	defer cleanup()

	gw := newGateway(t, upstreamURL)

	// Initialize (no need for full session for blocking — blocked before reaching upstream)
	_, sid := sseResponse(t, gw, "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"crust-e2e","version":"1.0.0"}}}`)

	// Try to read .env file (BLOCKED by inbound path rules — never reaches upstream)
	resp, _ := sseResponse(t, gw, sid,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"/app/.env"}}}`)

	if resp == nil {
		t.Fatal("no response for blocked .env read")
	}
	if resp.Error == nil {
		t.Fatalf("expected Crust block error for .env read, got success: %s", string(resp.Result))
	}
	if resp.Error.Code != jsonrpc.BlockedError {
		t.Errorf("error code = %d, want %d", resp.Error.Code, jsonrpc.BlockedError)
	}
	if !strings.Contains(resp.Error.Message, "[Crust]") {
		t.Errorf("error message missing [Crust] prefix: %s", resp.Error.Message)
	}
}

func TestHTTPE2E_ResourceReadBlocked(t *testing.T) {
	skipHTTPE2E(t)
	upstreamURL, cleanup := startRealMCPHTTP(t)
	defer cleanup()

	gw := newGateway(t, upstreamURL)
	_, sid := sseResponse(t, gw, "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"crust-e2e","version":"1.0.0"}}}`)

	// resources/read with .env URI (BLOCKED by path rules — never reaches upstream)
	resp, _ := sseResponse(t, gw, sid,
		`{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"file:///app/.env"}}`)

	if resp == nil {
		t.Fatal("no response for blocked .env read")
	}
	if resp.Error == nil {
		t.Fatalf("expected Crust block for .env read, got success: %s", string(resp.Result))
	}
	if resp.Error.Code != jsonrpc.BlockedError {
		t.Errorf("error code = %d, want %d", resp.Error.Code, jsonrpc.BlockedError)
	}
}

func TestHTTPE2E_ResponseDLP(t *testing.T) {
	skipHTTPE2E(t)
	upstreamURL, cleanup := startRealMCPHTTP(t)
	defer cleanup()

	gw := newGateway(t, upstreamURL)
	sid := initHTTPSession(t, gw)

	// Use the echo tool to make the server return an AWS key in its response.
	// The echo tool echoes back its message — DLP should catch the AWS key pattern.
	resp, _ := sseResponse(t, gw, sid,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"message":"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}}}`)

	if resp == nil {
		t.Fatal("no response for echo with AWS key")
	}
	// Response DLP should block: the server's echo response contains an AWS key pattern
	if resp.Error == nil {
		t.Fatalf("expected DLP block for AWS key in echo response, got success: %s", string(resp.Result))
	}
	if resp.Error.Code != jsonrpc.BlockedError {
		t.Errorf("error code = %d, want %d", resp.Error.Code, jsonrpc.BlockedError)
	}
	if !strings.Contains(resp.Error.Message, "[Crust]") {
		t.Errorf("error message missing [Crust]: %s", resp.Error.Message)
	}
}

func TestHTTPE2E_ToolsListPassthrough(t *testing.T) {
	skipHTTPE2E(t)
	upstreamURL, cleanup := startRealMCPHTTP(t)
	defer cleanup()

	gw := newGateway(t, upstreamURL)
	sid := initHTTPSession(t, gw)

	// tools/list is not security-relevant — should pass through to the real server
	resp, _ := sseResponse(t, gw, sid,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)

	if resp == nil {
		t.Fatal("no response for tools/list")
	}
	if resp.Error != nil {
		t.Fatalf("tools/list returned error: %s", resp.Error.Message)
	}

	var result map[string]any
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("failed to parse result: %v", err)
	}
	tools, ok := result["tools"].([]any)
	if !ok || len(tools) == 0 {
		t.Fatal("tools/list returned no tools")
	}

	// Verify the real server's echo tool is present
	toolNames := make(map[string]bool)
	for _, tool := range tools {
		if m, ok := tool.(map[string]any); ok {
			if name, ok := m["name"].(string); ok {
				toolNames[name] = true
			}
		}
	}
	if !toolNames["echo"] {
		t.Errorf("expected echo tool in tools/list, got: %v", toolNames)
	}
}

func TestHTTPE2E_SessionDelete(t *testing.T) {
	skipHTTPE2E(t)
	upstreamURL, cleanup := startRealMCPHTTP(t)
	defer cleanup()

	gw := newGateway(t, upstreamURL)
	sid := initHTTPSession(t, gw)

	if !gw.sessions.Exists(sid) {
		t.Fatal("session should be tracked after initialize")
	}

	// DELETE to terminate session
	req := httptest.NewRequest(http.MethodDelete, "/", nil)
	req.Header.Set(sessionHeader, sid)
	w := httptest.NewRecorder()
	gw.ServeHTTP(w, req)

	if gw.sessions.Exists(sid) {
		t.Error("session should be removed after DELETE")
	}
}

func TestHTTPE2E_MixedStream(t *testing.T) {
	skipHTTPE2E(t)
	upstreamURL, cleanup := startRealMCPHTTP(t)
	defer cleanup()

	gw := newGateway(t, upstreamURL)
	sid := initHTTPSession(t, gw)

	// Allowed: echo tool with safe message
	resp, _ := sseResponse(t, gw, sid,
		`{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"echo","arguments":{"message":"safe message"}}}`)
	if resp == nil || resp.Error != nil {
		t.Error("echo with safe message should succeed")
	}

	// Blocked: read .env
	resp, _ = sseResponse(t, gw, sid,
		`{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"/secrets/.env"}}}`)
	if resp == nil || resp.Error == nil {
		t.Error("read .env should be blocked")
	}

	// Blocked: DLP in echo response
	resp, _ = sseResponse(t, gw, sid,
		`{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"echo","arguments":{"message":"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm"}}}`)
	if resp == nil || resp.Error == nil {
		t.Error("echo with GitHub token should be blocked by response DLP")
	}

	// Allowed: another safe echo
	resp, _ = sseResponse(t, gw, sid,
		`{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"echo","arguments":{"message":"all clear"}}}`)
	if resp == nil || resp.Error != nil {
		t.Fatal("echo with safe message should succeed")
	}
	if !strings.Contains(string(resp.Result), "all clear") {
		t.Errorf("expected 'all clear' in echo response, got: %s", string(resp.Result))
	}
}

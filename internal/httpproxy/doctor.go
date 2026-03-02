package httpproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BakeLens/crust/internal/config"
)

// DoctorStatus represents the result of a provider endpoint check.
type DoctorStatus int

const (
	StatusOK         DoctorStatus = iota // 200: endpoint and key valid
	StatusAuthError                      // 401/403: endpoint OK, key issue
	StatusPathError                      // 404: wrong URL path
	StatusConnError                      // connection failed
	StatusOtherError                     // unexpected status code
)

// String returns a short label for the status (OK, AUTH, PATH, CONN, ERR).
func (s DoctorStatus) String() string {
	switch s {
	case StatusOK:
		return "OK"
	case StatusAuthError:
		return "AUTH"
	case StatusPathError:
		return "PATH"
	case StatusConnError:
		return "CONN"
	default:
		return "ERR"
	}
}

// DoctorResult holds the outcome of checking a single provider.
type DoctorResult struct {
	Name       string
	URL        string
	Diagnosis  string
	Status     DoctorStatus
	StatusCode int
	Duration   time.Duration
	HasAPIKey  bool
	IsUser     bool
}

// DoctorOptions configures the doctor check.
type DoctorOptions struct {
	Timeout       time.Duration
	Retries       int // number of retries for CONN errors (default 1)
	UserProviders map[string]config.ProviderConfig
}

// providerEntry is an internal representation of a provider for checking.
type providerEntry struct {
	name   string
	config config.ProviderConfig
	isUser bool
}

// RunDoctor checks all providers (builtin + user) concurrently and returns
// results sorted by provider name. CONN errors are retried up to
// opts.Retries times with a short backoff.
func RunDoctor(opts DoctorOptions) []DoctorResult {
	providers := mergeProviders(opts.UserProviders)
	retries := opts.Retries

	client := &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: opts.Timeout,
			DialContext:         (&net.Dialer{Timeout: opts.Timeout}).DialContext,
		},
	}
	defer client.CloseIdleConnections()

	results := make([]DoctorResult, len(providers))
	var wg sync.WaitGroup
	for i, entry := range providers {
		wg.Add(1)
		go func(i int, entry providerEntry) {
			defer wg.Done()
			r := checkProvider(client, entry)
			for attempt := range retries {
				if r.Status != StatusConnError {
					break
				}
				time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
				r = checkProvider(client, entry)
			}
			results[i] = r
		}(i, entry)
	}
	wg.Wait()
	return results
}

// isAnthropicProvider reports whether a provider URL uses the Anthropic
// Messages API protocol. Reuses detectAPIType for URLs whose path contains
// "/anthropic" or "/v1/messages", and additionally checks the host for
// api.anthropic.com (which has no path marker).
func isAnthropicProvider(providerURL string) bool {
	u, err := url.Parse(providerURL)
	if err != nil {
		return false
	}
	if u.Host == "api.anthropic.com" {
		return true
	}
	return detectAPIType(u.Path).IsAnthropic()
}

// buildTestURL constructs a lightweight test endpoint URL for a provider,
// using the same version-handling logic as buildUpstreamURL.
// For Anthropic-protocol providers it targets /v1/messages (the only
// guaranteed endpoint); for OpenAI-protocol providers it targets /v1/models.
func buildTestURL(providerURL string) (string, error) {
	u, err := url.Parse(providerURL)
	if err != nil {
		return "", fmt.Errorf("invalid provider URL %q: %w", providerURL, err)
	}

	// Pick the right test path: Anthropic providers have no /models endpoint.
	testPath := "/v1/models"
	if isAnthropicProvider(providerURL) {
		testPath = "/v1/messages"
	}

	// Same logic as buildUpstreamURL auto mode:
	// strip client /v1 when provider path already has a version segment.
	if pathHasVersion(u.Path) {
		testPath = stripLeadingVersion(testPath)
	}

	u.Path = path.Join(u.Path, testPath)
	return u.String(), nil
}

// checkProvider sends a lightweight request to verify a provider endpoint.
// It reuses detectAPIType and injectAuth from the proxy to ensure the same
// protocol detection and auth logic used for real requests.
func checkProvider(client *http.Client, entry providerEntry) DoctorResult {
	result := DoctorResult{
		Name:      entry.name,
		HasAPIKey: entry.config.APIKey != "",
		IsUser:    entry.isUser,
	}

	testURL, err := buildTestURL(entry.config.URL)
	if err != nil {
		result.URL = entry.config.URL
		result.Status = StatusConnError
		result.Diagnosis = fmt.Sprintf("invalid URL: %v", err)
		return result
	}
	result.URL = testURL

	// Use isAnthropicProvider to decide HTTP method:
	// Anthropic endpoints only support POST /v1/messages, not GET /v1/models.
	isAnthropic := isAnthropicProvider(entry.config.URL)
	method := http.MethodGet
	if isAnthropic {
		method = http.MethodPost
	}

	// Anthropic POST needs a body; empty POST may cause 500 on some proxies.
	var body io.Reader
	if isAnthropic {
		body = bytes.NewReader([]byte(`{}`))
	}
	req, err := http.NewRequestWithContext(context.Background(), method, testURL, body)
	if err != nil {
		result.Status = StatusConnError
		result.Diagnosis = fmt.Sprintf("bad request: %v", err)
		return result
	}

	// Reuse injectAuth from proxy — same auth header logic for real requests.
	if entry.config.APIKey != "" {
		injectAuth(req.Header, entry.config.APIKey, "", isAnthropic)
	}

	start := time.Now()
	resp, err := client.Do(req) //nolint:gosec // doctor checks known provider URLs, not user-tainted input
	result.Duration = time.Since(start)

	if err != nil || resp == nil {
		result.Status = StatusConnError
		result.Diagnosis = classifyConnError(err)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	switch resp.StatusCode {
	case http.StatusOK:
		result.Status = StatusOK
		result.Diagnosis = "endpoint OK, key valid"
		if !result.HasAPIKey {
			result.Diagnosis = "endpoint OK, no API key configured"
		}
	case http.StatusUnauthorized, http.StatusForbidden:
		result.Status = StatusAuthError
		if result.HasAPIKey {
			result.Diagnosis = "endpoint OK, key invalid or expired"
		} else {
			result.Diagnosis = "endpoint OK, no API key configured"
		}
	case http.StatusNotFound:
		result.Status = StatusPathError
		result.Diagnosis = "endpoint NOT found (path may be wrong)"
	case http.StatusMethodNotAllowed:
		// 405 means the path exists but doesn't accept the method — path is correct
		result.Status = StatusOK
		result.Diagnosis = "endpoint exists (method not allowed, path OK)"
	case http.StatusBadRequest:
		// 400 = endpoint alive but rejected the probe (e.g. Anthropic empty body,
		// Gemini without API key). Path is correct; treat as OK.
		result.Status = StatusOK
		result.Diagnosis = "endpoint OK (bad request, path OK)"
		if !result.HasAPIKey {
			result.Diagnosis = "endpoint OK, no API key configured"
		}
	default:
		result.Status = StatusOtherError
		result.Diagnosis = fmt.Sprintf("unexpected status %d", resp.StatusCode)
	}
	return result
}

// mergeProviders combines builtin and user providers, deduped by normalized URL.
// User providers with the same key override builtins. Sorted by name.
func mergeProviders(userProviders map[string]config.ProviderConfig) []providerEntry {
	seen := make(map[string]bool) // normalized URL → already added
	var entries []providerEntry

	// User providers first (higher priority)
	for name, prov := range userProviders {
		norm := normalizeProviderURL(prov.URL)
		if seen[norm] {
			continue
		}
		seen[norm] = true
		entries = append(entries, providerEntry{name: name, config: prov, isUser: true})
	}

	// Builtins (skip if URL already covered)
	for name, prov := range builtinProviders {
		norm := normalizeProviderURL(prov.URL)
		if seen[norm] {
			continue
		}
		seen[norm] = true
		entries = append(entries, providerEntry{name: name, config: prov})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].name < entries[j].name
	})
	return entries
}

// normalizeProviderURL strips trailing slash and lowercases scheme+host for dedup.
func normalizeProviderURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return strings.ToLower(u.Scheme+"://"+u.Host) + strings.TrimSuffix(u.Path, "/")
}

// classifyConnError returns a human-readable diagnosis for a connection error.
func classifyConnError(err error) string {
	var netErr net.Error
	if ok := errors.As(err, &netErr); ok && netErr.Timeout() {
		return "connection timed out"
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "DNS lookup failed: " + dnsErr.Name
	}
	return fmt.Sprintf("connection error: %v", err)
}

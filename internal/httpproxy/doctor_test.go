package httpproxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/config"
)

func TestBuildTestURL(t *testing.T) {
	tests := []struct {
		name        string
		providerURL string
		wantURL     string
	}{
		// OpenAI-protocol providers → /v1/models
		{"OpenAI (no path)", "https://api.openai.com", "https://api.openai.com/v1/models"},
		{"DeepSeek (no path)", "https://api.deepseek.com", "https://api.deepseek.com/v1/models"},
		{"Mistral (no path)", "https://api.mistral.ai", "https://api.mistral.ai/v1/models"},
		{"Moonshot (no path)", "https://api.moonshot.ai", "https://api.moonshot.ai/v1/models"},
		{"GLM versioned /v4", "https://open.bigmodel.cn/api/paas/v4", "https://open.bigmodel.cn/api/paas/v4/models"},
		{"Gemini v1beta/openai", "https://generativelanguage.googleapis.com/v1beta/openai", "https://generativelanguage.googleapis.com/v1beta/openai/models"},
		{"Groq with /openai", "https://api.groq.com/openai", "https://api.groq.com/openai/v1/models"},
		{"Qwen compatible-mode", "https://dashscope.aliyuncs.com/compatible-mode", "https://dashscope.aliyuncs.com/compatible-mode/v1/models"},
		{"Codex backend", "https://chatgpt.com/backend-api/codex", "https://chatgpt.com/backend-api/codex/v1/models"},
		// Anthropic-protocol providers → /v1/messages (no /models endpoint)
		{"Anthropic (no path)", "https://api.anthropic.com", "https://api.anthropic.com/v1/messages"},
		{"MiniMax /anthropic", "https://api.minimax.io/anthropic", "https://api.minimax.io/anthropic/v1/messages"},
		{"HF synthetic /anthropic", "https://api.synthetic.new/anthropic", "https://api.synthetic.new/anthropic/v1/messages"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildTestURL(tt.providerURL)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.wantURL {
				t.Errorf("buildTestURL(%q) = %q, want %q", tt.providerURL, got, tt.wantURL)
			}
		})
	}
}

func TestCheckProvider_StatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantStatus DoctorStatus
	}{
		{"200 OK", http.StatusOK, StatusOK},
		{"401 Unauthorized", http.StatusUnauthorized, StatusAuthError},
		{"403 Forbidden", http.StatusForbidden, StatusAuthError},
		{"404 Not Found", http.StatusNotFound, StatusPathError},
		{"405 Method Not Allowed", http.StatusMethodNotAllowed, StatusOK},
		{"500 Internal Server Error", http.StatusInternalServerError, StatusOtherError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer srv.Close()

			result := checkProvider(srv.Client(), providerEntry{
				name:   "test",
				config: config.ProviderConfig{URL: srv.URL},
			})
			if result.Status != tt.wantStatus {
				t.Errorf("status = %v, want %v (diagnosis: %s)", result.Status, tt.wantStatus, result.Diagnosis)
			}
			if result.StatusCode != tt.statusCode {
				t.Errorf("statusCode = %d, want %d", result.StatusCode, tt.statusCode)
			}
		})
	}
}

func TestCheckProvider_ConnError(t *testing.T) {
	result := checkProvider(
		&http.Client{Timeout: 200 * time.Millisecond},
		providerEntry{
			name:   "unreachable",
			config: config.ProviderConfig{URL: "http://192.0.2.1:1"}, // TEST-NET
		},
	)
	if result.Status != StatusConnError {
		t.Errorf("status = %v, want StatusConnError (diagnosis: %s)", result.Status, result.Diagnosis)
	}
}

func TestCheckProvider_AuthHeader(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		// urlSuffix is appended to the test server URL to trigger protocol detection.
		// "/anthropic" → Anthropic protocol (X-Api-Key); empty → OpenAI (Bearer).
		urlSuffix string
		apiKey    string
		wantAuth  string
		wantXKey  string
	}{
		{"bearer auth", "gpt", "", "sk-123", "Bearer sk-123", ""},
		{"anthropic x-api-key", "claude", "/anthropic", "sk-ant-123", "", "sk-ant-123"},
		{"no key", "gpt", "", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotAuth, gotXKey string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotAuth = r.Header.Get("Authorization")
				gotXKey = r.Header.Get("X-Api-Key")
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			checkProvider(srv.Client(), providerEntry{
				name:   tt.provider,
				config: config.ProviderConfig{URL: srv.URL + tt.urlSuffix, APIKey: tt.apiKey},
			})
			if gotAuth != tt.wantAuth {
				t.Errorf("Authorization = %q, want %q", gotAuth, tt.wantAuth)
			}
			if gotXKey != tt.wantXKey {
				t.Errorf("X-Api-Key = %q, want %q", gotXKey, tt.wantXKey)
			}
		})
	}
}

func TestCheckProvider_AnthropicProtocol(t *testing.T) {
	// Anthropic-protocol providers should use POST and treat 400 as OK
	// (empty body rejected = endpoint alive).
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusBadRequest) // empty POST body → 400
	}))
	defer srv.Close()

	result := checkProvider(srv.Client(), providerEntry{
		name:   "minimax",
		config: config.ProviderConfig{URL: srv.URL + "/anthropic"},
	})
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST for Anthropic provider", gotMethod)
	}
	if result.Status != StatusOK {
		t.Errorf("status = %v, want StatusOK for Anthropic 400 (diagnosis: %s)", result.Status, result.Diagnosis)
	}
}

func TestMergeProviders_Dedup(t *testing.T) {
	user := map[string]config.ProviderConfig{
		"my-gpt": {URL: "https://api.openai.com", APIKey: "sk-user"},
	}
	entries := mergeProviders(user)

	// "my-gpt" should be present (user), and builtin "gpt"/"openai"/"o1" etc.
	// should be deduped because they share the same URL.
	var openaiCount int
	for _, e := range entries {
		u, _ := url.Parse(e.config.URL)
		if u != nil && u.Host == "api.openai.com" {
			openaiCount++
		}
	}
	if openaiCount != 1 {
		t.Errorf("expected 1 openai entry after dedup, got %d", openaiCount)
	}

	// Verify user entry is the one that survived
	for _, e := range entries {
		if e.name == "my-gpt" {
			if !e.isUser {
				t.Error("expected my-gpt to be marked as user provider")
			}
			if e.config.APIKey != "sk-user" {
				t.Error("expected user API key to be preserved")
			}
			return
		}
	}
	t.Error("my-gpt entry not found in merged providers")
}

func TestBuiltinProviders_Accessor(t *testing.T) {
	providers := BuiltinProviders()
	if len(providers) == 0 {
		t.Fatal("BuiltinProviders() returned empty map")
	}

	// Verify it's a copy — modifying it shouldn't affect the original
	providers["test-mutation"] = config.ProviderConfig{URL: "http://mutated"}
	fresh := BuiltinProviders()
	if _, ok := fresh["test-mutation"]; ok {
		t.Error("BuiltinProviders() returned a reference, not a copy")
	}

	// Spot-check known providers
	for _, key := range []string{"gpt", "claude", "glm", "gemini", "deepseek"} {
		if _, ok := fresh[key]; !ok {
			t.Errorf("expected builtin provider %q not found", key)
		}
	}
}

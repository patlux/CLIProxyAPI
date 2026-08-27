package executor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestOpenAICompatExecutorForwardsConfiguredInboundHeader(t *testing.T) {
	var affinity string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		affinity = r.Header.Get("X-Session-Affinity")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	defer server.Close()

	executor := NewOpenAICompatExecutor("openai-compatibility", &config.Config{})
	auth := &cliproxyauth.Auth{
		Provider: "openai-compatibility",
		Attributes: map[string]string{
			"base_url":                  server.URL,
			"api_key":                   "test",
			"header:X-Session-Affinity": "$X-Session-Affinity",
		},
	}
	req := cliproxyexecutor.Request{
		Model:   "test-model",
		Payload: []byte(`{"model":"test-model","messages":[{"role":"user","content":"hi"}]}`),
	}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
		Headers:      http.Header{"X-Session-Affinity": []string{"pi-session-1"}},
	}

	if _, err := executor.Execute(context.Background(), auth, req, opts); err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	if affinity != "pi-session-1" {
		t.Fatalf("X-Session-Affinity = %q, want %q", affinity, "pi-session-1")
	}
}

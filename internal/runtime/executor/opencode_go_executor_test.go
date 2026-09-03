package executor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestOpenCodeGoExecutorRoutesMuseToResponses(t *testing.T) {
	var gotPath string
	var gotPayload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, errRead := io.ReadAll(r.Body)
		if errRead != nil {
			t.Errorf("read request: %v", errRead)
		}
		if errUnmarshal := json.Unmarshal(body, &gotPayload); errUnmarshal != nil {
			t.Errorf("decode request: %v", errUnmarshal)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"resp_1","object":"response","status":"completed","output":[{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`))
	}))
	defer server.Close()

	executor := NewOpenCodeGoExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"base_url": server.URL,
		"api_key":  "test-key",
	}}
	req := cliproxyexecutor.Request{
		Model:   "muse-spark-1.3-contributor",
		Payload: []byte(`{"model":"muse-spark-1.3-contributor","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}]}`),
	}
	resp, errExecute := executor.Execute(context.Background(), auth, req, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAIResponse,
	})
	if errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if gotPath != "/responses" {
		t.Fatalf("request path = %q, want /responses", gotPath)
	}
	if _, exists := gotPayload["input"]; !exists {
		t.Fatalf("responses payload is missing input: %#v", gotPayload)
	}
	if !json.Valid(resp.Payload) {
		t.Fatalf("response is not valid JSON: %s", resp.Payload)
	}
}

func TestOpenCodeGoExecutorKeepsChatModelsOnChatCompletions(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-1","choices":[{"message":{"role":"assistant","content":"ok"}}]}`))
	}))
	defer server.Close()

	executor := NewOpenCodeGoExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{Attributes: map[string]string{
		"base_url": server.URL,
		"api_key":  "test-key",
	}}
	req := cliproxyexecutor.Request{
		Model:   "glm-5.3-flash",
		Payload: []byte(`{"model":"glm-5.3-flash","messages":[{"role":"user","content":"hi"}]}`),
	}
	if _, errExecute := executor.Execute(context.Background(), auth, req, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
	}); errExecute != nil {
		t.Fatalf("Execute() error = %v", errExecute)
	}
	if gotPath != "/chat/completions" {
		t.Fatalf("request path = %q, want /chat/completions", gotPath)
	}
}

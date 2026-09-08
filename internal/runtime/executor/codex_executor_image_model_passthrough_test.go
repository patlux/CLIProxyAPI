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
	"github.com/tidwall/gjson"
)

// Candidate names are transport probes, not declarations of upstream support.
func TestCodexExecutorImageModelPassthrough(t *testing.T) {
	for _, model := range []string{"gpt-image-2", "gpt-image-2.5", "gpt-image-nonexistent-validation-probe"} {
		t.Run(model, func(t *testing.T) {
			for _, stream := range []bool{false, true} {
				name := "nonstream"
				if stream {
					name = "stream"
				}
				t.Run(name, func(t *testing.T) {
					bodies := make(chan []byte, 1)
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						body, err := io.ReadAll(r.Body)
						if err != nil {
							t.Errorf("read request: %v", err)
						}
						bodies <- body
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = io.WriteString(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_probe\",\"status\":\"completed\",\"output\":[]}}\n\n")
					}))
					defer server.Close()
					executor := NewCodexExecutor(&config.Config{})
					auth := &cliproxyauth.Auth{Attributes: map[string]string{"base_url": server.URL, "api_key": "test"}}
					payload, err := json.Marshal(map[string]any{
						"model": "gpt-5.6-sol", "input": "Transport probe", "stream": stream,
						"tools":       []map[string]string{{"type": "image_generation", "model": model, "quality": "low", "size": "1024x1024"}},
						"tool_choice": map[string]string{"type": "image_generation"},
					})
					if err != nil {
						t.Fatal(err)
					}
					req := cliproxyexecutor.Request{Model: "gpt-5.6-sol", Payload: payload}
					opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai-response"), Stream: stream}
					if stream {
						result, err := executor.ExecuteStream(context.Background(), auth, req, opts)
						if err != nil {
							t.Fatal(err)
						}
						for chunk := range result.Chunks {
							if chunk.Err != nil {
								t.Fatal(chunk.Err)
							}
						}
					} else {
						if _, err := executor.Execute(context.Background(), auth, req, opts); err != nil {
							t.Fatal(err)
						}
					}
					body := <-bodies
					for path, want := range map[string]string{"tools.0.type": "image_generation", "tools.0.model": model, "tools.0.quality": "low", "tools.0.size": "1024x1024", "tool_choice.type": "image_generation"} {
						if got := gjson.GetBytes(body, path).String(); got != want {
							t.Errorf("%s = %q, want %q", path, got, want)
						}
					}
					if got := len(gjson.GetBytes(body, "tools").Array()); got != 1 {
						t.Errorf("tool count = %d, want 1", got)
					}
				})
			}
		})
	}
}

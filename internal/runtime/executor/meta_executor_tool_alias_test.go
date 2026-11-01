package executor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

func metaToolAliasTestAuth(serverURL string) *cliproxyauth.Auth {
	return &cliproxyauth.Auth{
		Provider: "meta",
		Attributes: map[string]string{
			"api_key":  "meta-token",
			"base_url": serverURL,
		},
	}
}

func writeMetaFunctionCallSSE(w http.ResponseWriter, toolName string) {
	w.Header().Set("Content-Type", "text/event-stream")
	completed, _ := json.Marshal(map[string]any{
		"type": "response.completed",
		"response": map[string]any{
			"id":     "resp_1",
			"object": "response",
			"status": "completed",
			"model":  "muse-spark-1.3",
			"output": []map[string]any{
				{
					"type":      "function_call",
					"id":        "fc_1",
					"call_id":   "call_1",
					"name":      toolName,
					"arguments": `{"command":"ls"}`,
				},
			},
			"usage": map[string]any{
				"input_tokens":  1,
				"output_tokens": 1,
				"total_tokens":  2,
			},
		},
	})
	_, _ = w.Write([]byte("data: "))
	_, _ = w.Write(completed)
	_, _ = w.Write([]byte("\n\n"))
}

func TestMetaExecutor_AliasesMuseBuiltinToolNames(t *testing.T) {
	var gotBody []byte
	bashAlias := helps.MetaToolAliasName("bash")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, errRead := io.ReadAll(r.Body)
		if errRead != nil {
			t.Fatalf("read request body: %v", errRead)
		}
		gotBody = body
		writeMetaFunctionCallSSE(w, bashAlias)
	}))
	defer server.Close()

	exec := NewMetaExecutor(&config.Config{})
	auth := metaToolAliasTestAuth(server.URL)

	payload := []byte(`{
		"model": "muse-spark-1.3",
		"input": [
			{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "list files"}]},
			{"type": "function_call", "name": "bash", "call_id": "call_0", "arguments": "{\"command\":\"pwd\"}"}
		],
		"tools": [
			{"type": "function", "name": "bash", "parameters": {"type": "object"}},
			{"type": "function", "name": "read", "parameters": {"type": "object"}}
		]
	}`)

	resp, errExec := exec.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "muse-spark-1.3",
		Payload: payload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("openai-response"),
	})
	if errExec != nil {
		t.Fatalf("Execute() error = %v", errExec)
	}

	if got := gjson.GetBytes(gotBody, "tools.0.name").String(); got != bashAlias {
		t.Fatalf("upstream bash tool name = %q, want alias %q", got, bashAlias)
	}
	if got := gjson.GetBytes(gotBody, "tools.1.name").String(); got != "read" {
		t.Fatalf("upstream non-colliding tool name = %q, want read", got)
	}
	if got := gjson.GetBytes(gotBody, "input.1.name").String(); got != bashAlias {
		t.Fatalf("upstream history name = %q, want alias %q", got, bashAlias)
	}
	if got := gjson.GetBytes(resp.Payload, "output.#(type==\"function_call\").name").String(); got != "bash" {
		t.Fatalf("client function call name = %q, want bash; payload=%s", got, resp.Payload)
	}
}

func TestMetaExecutorStream_RestoresMuseBuiltinToolNames(t *testing.T) {
	bashAlias := helps.MetaToolAliasName("bash")
	addedSSE := `event: response.output_item.added
data: {"type":"response.output_item.added","output_index":1,"item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"` + bashAlias + `","arguments":""}}

`
	doneSSE := `event: response.output_item.done
data: {"type":"response.output_item.done","output_index":1,"item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"` + bashAlias + `","arguments":"{\"command\":\"ls\"}"}}

`
	completed, _ := json.Marshal(map[string]any{
		"type": "response.completed",
		"response": map[string]any{
			"id":     "resp_1",
			"object": "response",
			"status": "completed",
			"model":  "muse-spark-1.3",
			"output": []map[string]any{
				{
					"type":      "function_call",
					"id":        "fc_1",
					"call_id":   "call_1",
					"name":      bashAlias,
					"arguments": `{"command":"ls"}`,
				},
			},
			"usage": map[string]any{"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
		},
	})
	completedSSE := "event: response.completed\ndata: " + string(completed) + "\n\n"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, addedSSE+doneSSE+completedSSE)
	}))
	defer server.Close()

	exec := NewMetaExecutor(&config.Config{})
	auth := metaToolAliasTestAuth(server.URL)

	streamResult, errStream := exec.ExecuteStream(context.Background(), auth, cliproxyexecutor.Request{
		Model: "muse-spark-1.3",
		Payload: []byte(`{
			"model": "muse-spark-1.3",
			"input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": "list files"}]}],
			"tools": [{"type": "function", "name": "bash", "parameters": {"type": "object"}}]
		}`),
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("openai-response"),
		Stream:       true,
	})
	if errStream != nil {
		t.Fatalf("ExecuteStream() error = %v", errStream)
	}

	var combined strings.Builder
	for chunk := range streamResult.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream chunk error = %v", chunk.Err)
		}
		combined.Write(chunk.Payload)
		combined.WriteByte('\n')
	}
	got := combined.String()
	if strings.Contains(got, bashAlias) {
		t.Fatalf("stream leaked alias %q to the client:\n%s", bashAlias, got)
	}
	if !strings.Contains(got, `"name":"bash"`) {
		t.Fatalf("stream did not restore the bash tool name:\n%s", got)
	}
}

package helps

import (
	"testing"

	"github.com/tidwall/gjson"
)

func TestAliasMetaToolNames_RenamesMuseBuiltinCollisions(t *testing.T) {
	input := []byte(`{
		"model": "muse-spark-1.3",
		"tools": [
			{"type": "function", "name": "read", "parameters": {"type": "object"}},
			{"type": "function", "name": "bash", "parameters": {"type": "object"}},
			{"type": "function", "name": "web_search", "parameters": {"type": "object"}},
			{"type": "function", "name": "web_fetch", "parameters": {"type": "object"}},
			{"type": "function", "name": "create_goal", "parameters": {"type": "object"}},
			{"type": "function", "name": "workflow", "parameters": {"type": "object"}},
			{"type": "namespace", "name": "group", "tools": [
				{"type": "function", "name": "read_file", "parameters": {"type": "object"}}
			]},
			{"type": "web_search", "external_web_access": true}
		],
		"tool_choice": {"type": "function", "name": "bash"},
		"input": [
			{"type": "message", "role": "user", "content": "hi"},
			{"type": "function_call", "name": "bash", "call_id": "call_1", "arguments": "{}"},
			{"type": "additional_tools", "tools": [
				{"type": "function", "name": "edit_file", "parameters": {"type": "object"}}
			]}
		]
	}`)

	out, aliases := AliasMetaToolNames(input)

	if got := gjson.GetBytes(out, "tools.0.name").String(); got != "read" {
		t.Fatalf("non-colliding tool renamed: %q", got)
	}
	bashAlias := MetaToolAliasName("bash")
	if got := gjson.GetBytes(out, "tools.1.name").String(); got != bashAlias {
		t.Fatalf("bash alias = %q, want %q", got, bashAlias)
	}
	if got := gjson.GetBytes(out, "tools.2.name").String(); got != MetaToolAliasName("web_search") {
		t.Fatalf("web_search alias = %q", got)
	}
	if got := gjson.GetBytes(out, "tools.3.name").String(); got != MetaToolAliasName("web_fetch") {
		t.Fatalf("web_fetch alias = %q", got)
	}
	if got := gjson.GetBytes(out, "tools.4.name").String(); got != MetaToolAliasName("create_goal") {
		t.Fatalf("create_goal alias = %q", got)
	}
	if got := gjson.GetBytes(out, "tools.5.name").String(); got != MetaToolAliasName("workflow") {
		t.Fatalf("workflow alias = %q", got)
	}
	if got := gjson.GetBytes(out, "tools.6.tools.0.name").String(); got != MetaToolAliasName("read_file") {
		t.Fatalf("nested read_file alias = %q", got)
	}
	if got := gjson.GetBytes(out, "tools.7.name").String(); got != "" {
		t.Fatalf("server web_search tool gained a name: %q", got)
	}
	if got := gjson.GetBytes(out, "tool_choice.name").String(); got != bashAlias {
		t.Fatalf("tool_choice alias = %q, want %q", got, bashAlias)
	}
	if got := gjson.GetBytes(out, "input.1.name").String(); got != bashAlias {
		t.Fatalf("history function_call alias = %q, want %q", got, bashAlias)
	}
	if got := gjson.GetBytes(out, "input.2.tools.0.name").String(); got != MetaToolAliasName("edit_file") {
		t.Fatalf("additional_tools alias = %q", got)
	}

	want := map[string]string{
		bashAlias:                        "bash",
		MetaToolAliasName("web_search"):  "web_search",
		MetaToolAliasName("web_fetch"):   "web_fetch",
		MetaToolAliasName("create_goal"): "create_goal",
		MetaToolAliasName("workflow"):    "workflow",
		MetaToolAliasName("read_file"):   "read_file",
		MetaToolAliasName("edit_file"):   "edit_file",
	}
	if len(aliases) != len(want) {
		t.Fatalf("aliases = %#v, want %d entries", aliases, len(want))
	}
	for alias, original := range want {
		if aliases[alias] != original {
			t.Fatalf("aliases[%q] = %q, want %q", alias, aliases[alias], original)
		}
	}
	if !gjson.ValidBytes(out) {
		t.Fatalf("aliased body is not valid JSON: %s", out)
	}
}

func TestAliasMetaToolNames_NoCollisionLeavesBodyUntouched(t *testing.T) {
	input := []byte(`{
		"model": "muse-spark-1.3",
		"tools": [
			{"type": "function", "name": "read", "parameters": {"type": "object"}},
			{"type": "function", "name": "Bash", "parameters": {"type": "object"}}
		],
		"input": [{"role": "user", "content": "hi"}]
	}`)

	out, aliases := AliasMetaToolNames(input)
	if string(out) != string(input) {
		t.Fatalf("body changed without collisions: %s", out)
	}
	if len(aliases) != 0 {
		t.Fatalf("aliases = %#v, want empty", aliases)
	}
}

func TestAliasMetaToolNames_AvoidsExistingToolNames(t *testing.T) {
	// A client tool that already uses the default alias of "bash" must not be
	// shadowed by the generated alias.
	defaultAlias := MetaToolAliasName("bash")
	input := []byte(`{"tools": [
		{"type": "function", "name": "bash"},
		{"type": "function", "name": "` + defaultAlias + `"}
	]}`)

	out, aliases := AliasMetaToolNames(input)
	got := gjson.GetBytes(out, "tools.0.name").String()
	if got == defaultAlias {
		t.Fatalf("alias %q shadows an existing tool name", got)
	}
	if aliases[got] != "bash" {
		t.Fatalf("alias map = %#v", aliases)
	}
	if other := gjson.GetBytes(out, "tools.1.name").String(); other != defaultAlias {
		t.Fatalf("existing tool renamed: %q", other)
	}
}

func TestRestoreMetaToolNames_NonStreamPayload(t *testing.T) {
	alias := MetaToolAliasName("bash")
	payload := []byte(`{
		"id": "resp_1",
		"object": "response",
		"output": [
			{"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "` + alias + `"}]},
			{"type": "function_call", "name": "` + alias + `", "call_id": "call_1", "arguments": "{\"command\":\"ls\"}"}
		]
	}`)

	out := RestoreMetaToolNames(payload, MetaToolNameAliases{alias: "bash"})
	if got := gjson.GetBytes(out, "output.1.name").String(); got != "bash" {
		t.Fatalf("function call name = %q, want bash", got)
	}
	// Message text must not be rewritten.
	if got := gjson.GetBytes(out, "output.0.content.0.text").String(); got != alias {
		t.Fatalf("message text changed: %q", got)
	}
}

func TestRestoreMetaToolNames_StreamEvents(t *testing.T) {
	alias := MetaToolAliasName("web_search")
	aliases := MetaToolNameAliases{alias: "web_search"}

	added := []byte(`{"type":"response.output_item.added","item":{"type":"function_call","name":"` + alias + `","call_id":"c1"}}`)
	if got := gjson.GetBytes(RestoreMetaToolNames(added, aliases), "item.name").String(); got != "web_search" {
		t.Fatalf("output_item.added name = %q", got)
	}

	completed := []byte(`{"type":"response.completed","response":{"output":[{"type":"function_call","name":"` + alias + `","call_id":"c1"}]}}`)
	if got := gjson.GetBytes(RestoreMetaToolNames(completed, aliases), "response.output.0.name").String(); got != "web_search" {
		t.Fatalf("response.completed name = %q", got)
	}

	// Non-call items keep their names.
	message := []byte(`{"type":"response.output_item.done","item":{"type":"message","name":"` + alias + `"}}`)
	if got := gjson.GetBytes(RestoreMetaToolNames(message, aliases), "item.name").String(); got != alias {
		t.Fatalf("message item name changed: %q", got)
	}
}

func TestRestoreMetaToolNames_WithoutAliases(t *testing.T) {
	payload := []byte(`{"output":[{"type":"function_call","name":"bash"}]}`)
	if got := RestoreMetaToolNames(payload, nil); string(got) != string(payload) {
		t.Fatalf("payload changed without aliases: %s", got)
	}
}

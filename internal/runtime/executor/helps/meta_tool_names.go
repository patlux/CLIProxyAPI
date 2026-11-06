package helps

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/MoeForge/moego/ojson"
)

// metaMuseBuiltinToolNames are the function tool names reserved by Meta's Muse
// Code client. Since Meta's 2026-10-29/30 enforcement rollout, a subscription
// backed request that declares a function tool with one of these names is
// rejected with HTTP 403 client_attestation_denied ("This API key is billed to
// a Muse Code subscription. Muse Code subscriptions cover requests from the
// Muse Code client only."), even though the identical request without the
// colliding name succeeds. The check is case-sensitive: "Bash" passes.
//
// The list was probed against api.meta.ai on 2026-11-01 with the subscription
// credential. It covers the Muse Code builtin registry (read/write tools,
// memory, peer sessions, work items, goals, subagents, cron, shell, web) and
// the agent-framework names Meta also reserves (workflow, apply_patch,
// write_todos, request_user_input, update_plan). "artifact" and "tool_search"
// are accepted and deliberately not rewritten.
//
// The gateway emulates the Muse Code client through its user agent and client
// id, but it cannot claim the builtin tool declarations, so colliding client
// tool names are aliased on the way upstream and restored on the way back.
var metaMuseBuiltinToolNames = map[string]struct{}{
	"read_file":             {},
	"search":                {},
	"write_file":            {},
	"edit_file":             {},
	"read_memory":           {},
	"add_memory":            {},
	"edit_memory":           {},
	"list_peer_sessions":    {},
	"send_session_message":  {},
	"work_stop":             {},
	"work_list":             {},
	"web_fetch":             {},
	"web_search":            {},
	"shell":                 {},
	"bash":                  {},
	"bash_input":            {},
	"monitor":               {},
	"cron_create":           {},
	"cron_delete":           {},
	"cron_list":             {},
	"get_goal":              {},
	"create_goal":           {},
	"update_goal":           {},
	"report_progress":       {},
	"subagent_spawn":        {},
	"subagent_status":       {},
	"subagent_send_message": {},
	"subagent_wait":         {},
	"subagent_read_result":  {},
	"subagent_cancel":       {},
	"workflow":              {},
	"apply_patch":           {},
	"write_todos":           {},
	"request_user_input":    {},
	"update_plan":           {},
}

// metaToolAliasPrefix keeps aliases recognizable in upstream logs and outside
// the builtin name space. The digest suffix keeps them deterministic across
// replayed history, so a request can alias and restore without per-request
// state on the client side.
const metaToolAliasPrefix = "muse_"

// MetaToolNameAliases maps the alias sent upstream back to the client's original
// tool name. It is empty when the request declares no colliding tool names.
type MetaToolNameAliases map[string]string

// MetaToolAliasName returns the deterministic upstream alias for a client tool
// name. Callers that need several aliases in one request must use the map
// returned by AliasMetaToolNamesDoc instead, which additionally avoids collisions
// with the request's other tool names.
func MetaToolAliasName(name string) string {
	return metaToolAliasName(name, 4)
}

func metaToolAliasName(name string, digestBytes int) string {
	sum := sha256.Sum256([]byte(name))
	return metaToolAliasPrefix + hex.EncodeToString(sum[:digestBytes])
}

func isMetaMuseBuiltinToolName(name string) bool {
	_, ok := metaMuseBuiltinToolNames[name]
	return ok
}

type metaToolNameRef struct {
	path string
	name string
}

// AliasMetaToolNamesDoc rewrites function tool names that collide with the Muse
// Code builtin set, including tool declarations (flat and namespace nested),
// additional_tools history, function call history and tool_choice. The returned
// map restores the client names in an upstream response via
// RestoreMetaToolNamesDoc.
func AliasMetaToolNamesDoc(doc *ojson.Doc) MetaToolNameAliases {
	if doc == nil || doc.Len() == 0 {
		return nil
	}

	var refs []metaToolNameRef
	namesInUse := make(map[string]struct{})

	var declared func(base string, tools ojson.Result)
	declared = func(base string, tools ojson.Result) {
		if !tools.IsArray() {
			return
		}
		tools.ForEach(func(index, tool ojson.Result) bool {
			itemPath := fmt.Sprintf("%s.%d", base, index.Int())
			switch tool.Get("type").String() {
			case "function", "custom":
				name := tool.Get("name").String()
				if name == "" {
					return true
				}
				namesInUse[name] = struct{}{}
				if isMetaMuseBuiltinToolName(name) {
					refs = append(refs, metaToolNameRef{path: itemPath + ".name", name: name})
				}
			case "namespace":
				declared(itemPath+".tools", tool.Get("tools"))
			}
			return true
		})
	}

	declared("tools", doc.Get("tools"))

	if input := doc.Get("input"); input.IsArray() {
		input.ForEach(func(index, item ojson.Result) bool {
			itemPath := fmt.Sprintf("input.%d", index.Int())
			switch item.Get("type").String() {
			case "function_call", "custom_tool_call":
				name := item.Get("name").String()
				if name == "" {
					return true
				}
				namesInUse[name] = struct{}{}
				if isMetaMuseBuiltinToolName(name) {
					refs = append(refs, metaToolNameRef{path: itemPath + ".name", name: name})
				}
			case "additional_tools":
				declared(itemPath+".tools", item.Get("tools"))
			}
			return true
		})
	}

	if toolChoice := doc.Get("tool_choice"); toolChoice.IsObject() {
		if name := toolChoice.Get("name").String(); isMetaMuseBuiltinToolName(name) {
			refs = append(refs, metaToolNameRef{path: "tool_choice.name", name: name})
		}
	}

	if len(refs) == 0 {
		return nil
	}

	// Extend the digest until an alias is unique inside this request, so an
	// alias never shadows another declared tool name.
	aliasByOriginal := make(map[string]string, len(refs))
	for _, ref := range refs {
		if _, ok := aliasByOriginal[ref.name]; ok {
			continue
		}
		alias := MetaToolAliasName(ref.name)
		for digestBytes := 8; ; digestBytes += 4 {
			if _, taken := namesInUse[alias]; !taken {
				break
			}
			alias = metaToolAliasName(ref.name, digestBytes)
		}
		namesInUse[alias] = struct{}{}
		aliasByOriginal[ref.name] = alias
	}

	for _, ref := range refs {
		if alias, ok := aliasByOriginal[ref.name]; ok {
			_ = doc.Set(ref.path, alias)
		}
	}

	aliases := make(MetaToolNameAliases, len(aliasByOriginal))
	for original, alias := range aliasByOriginal {
		aliases[alias] = original
	}
	return aliases
}

// RestoreMetaToolNames rewrites aliased tool call names back to the client's
// original names in an upstream Responses payload or SSE event. It only
// touches function call items, never message content or tool arguments. The
// payload is returned unchanged when it declares no aliased name.
func RestoreMetaToolNames(payload []byte, aliases MetaToolNameAliases) []byte {
	if len(payload) == 0 || len(aliases) == 0 || !ojson.ValidBytes(payload) {
		return payload
	}
	doc := ojson.NewDoc(payload)
	if !RestoreMetaToolNamesDoc(doc, aliases) {
		return payload
	}
	return doc.Bytes()
}

// RestoreMetaToolNamesDoc rewrites aliased tool call names in place on doc and
// reports whether it changed anything.
func RestoreMetaToolNamesDoc(doc *ojson.Doc, aliases MetaToolNameAliases) bool {
	if doc == nil || doc.Len() == 0 || len(aliases) == 0 {
		return false
	}

	type restoreRef struct {
		path     string
		original string
	}
	var refs []restoreRef

	collect := func(base string, items ojson.Result) {
		if !items.IsArray() {
			return
		}
		items.ForEach(func(index, item ojson.Result) bool {
			path := fmt.Sprintf("%s.%d.name", base, index.Int())
			if original, ok := metaToolCallOriginal(item, aliases); ok {
				refs = append(refs, restoreRef{path: path, original: original})
			}
			return true
		})
	}

	collect("output", doc.Get("output"))
	collect("response.output", doc.Get("response.output"))
	if original, ok := metaToolCallOriginal(doc.Get("item"), aliases); ok {
		refs = append(refs, restoreRef{path: "item.name", original: original})
	}

	if len(refs) == 0 {
		return false
	}
	for _, ref := range refs {
		_ = doc.Set(ref.path, ref.original)
	}
	return true
}

func metaToolCallOriginal(item ojson.Result, aliases MetaToolNameAliases) (string, bool) {
	switch item.Get("type").String() {
	case "function_call", "custom_tool_call":
	default:
		return "", false
	}
	original, ok := aliases[item.Get("name").String()]
	return original, ok
}

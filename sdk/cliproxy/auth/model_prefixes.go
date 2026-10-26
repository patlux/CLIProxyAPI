package auth

import (
	"encoding/json"
	"strings"
)

const additionalPrefixesAttribute = "additional_prefixes"

// ApplyAdditionalPrefixesMetadata projects extra model namespaces into routing
// attributes, so watcher updates participate in the model-publication fence.
// All prefixes refer to this same auth ID, quota state and refresh lifecycle.
func ApplyAdditionalPrefixesMetadata(auth *Auth, metadata map[string]any) {
	if auth == nil {
		return
	}
	delete(auth.Attributes, additionalPrefixesAttribute)
	encoded, err := json.Marshal(metadata[additionalPrefixesAttribute])
	if err != nil {
		return
	}
	var values []string
	if json.Unmarshal(encoded, &values) != nil {
		return
	}
	prefixes := normalizeAdditionalPrefixes(auth.Prefix, values)
	if len(prefixes) == 0 {
		return
	}
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	encoded, _ = json.Marshal(prefixes)
	auth.Attributes[additionalPrefixesAttribute] = string(encoded)
}

// ModelPrefixes returns the primary namespace followed by unique extra ones.
// An empty primary prefix retains the caller's existing unprefixed behavior.
func (auth *Auth) ModelPrefixes() []string {
	if auth == nil {
		return nil
	}
	var additional []string
	_ = json.Unmarshal([]byte(auth.Attributes[additionalPrefixesAttribute]), &additional)
	return append([]string{strings.TrimSpace(auth.Prefix)}, normalizeAdditionalPrefixes(auth.Prefix, additional)...)
}

func normalizeAdditionalPrefixes(primary string, values []string) []string {
	seen := map[string]bool{strings.TrimSpace(primary): true}
	var prefixes []string
	for _, value := range values {
		value = strings.Trim(strings.TrimSpace(value), "/")
		if value == "" || strings.ContainsAny(value, "/ \t\r\n") || seen[value] {
			continue
		}
		seen[value] = true
		prefixes = append(prefixes, value)
	}
	return prefixes
}

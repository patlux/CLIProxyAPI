package auth

import (
	"reflect"
	"testing"
)

func TestAdditionalPrefixesMetadata(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value any
		want  []string
	}{
		{"json list", []any{"shared", " /second/ ", "work", "shared", "", "bad/nested", "bad space"}, []string{"work", "shared", "second"}},
		{"typed list", []string{"shared"}, []string{"work", "shared"}},
		{"absent", nil, []string{"work"}},
		{"wrong type", "shared", []string{"work"}},
		{"mixed list", []any{"shared", 5}, []string{"work"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := &Auth{Prefix: "work", Attributes: map[string]string{additionalPrefixesAttribute: `["stale"]`}}
			ApplyAdditionalPrefixesMetadata(auth, map[string]any{additionalPrefixesAttribute: tc.value})
			if got := auth.ModelPrefixes(); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("prefixes = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRewriteModelForAdditionalPrefix(t *testing.T) {
	auth := &Auth{Prefix: "work"}
	ApplyAdditionalPrefixesMetadata(auth, map[string]any{additionalPrefixesAttribute: []string{"shared"}})
	for input, want := range map[string]string{
		"work/model(high)":   "model(high)",
		"shared/model(high)": "model(high)",
		"sharedness/model":   "sharedness/model",
		"other/model":        "other/model",
		"model":              "model",
	} {
		if got := rewriteModelForAuth(input, auth); got != want {
			t.Errorf("rewrite %q = %q, want %q", input, got, want)
		}
	}
	ApplyAdditionalPrefixesMetadata(auth, nil)
	if got := rewriteModelForAuth("shared/model", auth); got != "shared/model" {
		t.Fatalf("removed prefix remains routable: %s", got)
	}
}

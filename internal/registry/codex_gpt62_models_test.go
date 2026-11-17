package registry

import (
	"testing"

	"github.com/MoeForge/moego/json"
)

// GPT-6.2 Astra and Sol shipped in Codex on 2026-11-17 for paid plans only.
// The embedded catalogs carry them until the official remote catalog does.
func TestEmbeddedCatalogsExposeGPT62ForPaidCodexPlans(t *testing.T) {
	var parsed staticModelsJSON
	if errUnmarshal := json.Unmarshal(embeddedModelsJSON, &parsed); errUnmarshal != nil {
		t.Fatalf("parse embedded models.json: %v", errUnmarshal)
	}
	want := []string{"gpt-6.2-astra", "gpt-6.2-sol"}
	tiers := map[string][]*ModelInfo{
		"codex-team": parsed.CodexTeam,
		"codex-plus": parsed.CodexPlus,
		"codex-pro":  parsed.CodexPro,
	}
	for tier, models := range tiers {
		ids := make(map[string]*ModelInfo, len(models))
		for _, model := range models {
			ids[model.ID] = model
		}
		for _, id := range want {
			model, ok := ids[id]
			if !ok {
				t.Fatalf("%s is missing %s", tier, id)
			}
			if model.Thinking == nil || len(model.Thinking.Levels) == 0 {
				t.Fatalf("%s %s has no thinking levels", tier, id)
			}
		}
	}
	for _, model := range parsed.CodexFree {
		for _, id := range want {
			if model.ID == id {
				t.Fatalf("codex-free must not expose %s", id)
			}
		}
	}

	var client struct {
		Models []struct {
			Slug string `json:"slug"`
		} `json:"models"`
	}
	if errUnmarshal := json.Unmarshal(embeddedCodexClientModelsJSON, &client); errUnmarshal != nil {
		t.Fatalf("parse embedded codex_client_models.json: %v", errUnmarshal)
	}
	slugs := make(map[string]bool, len(client.Models))
	for _, model := range client.Models {
		slugs[model.Slug] = true
	}
	for _, id := range want {
		if !slugs[id] {
			t.Fatalf("codex client catalog is missing %s", id)
		}
	}
	if errValidate := ValidateCodexClientModelsJSON(embeddedCodexClientModelsJSON); errValidate != nil {
		t.Fatalf("embedded codex client catalog is invalid: %v", errValidate)
	}
}

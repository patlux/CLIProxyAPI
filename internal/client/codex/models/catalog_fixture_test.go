package models

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

// useLegacyCodexClientCatalog isolates metadata transformation tests from the
// rolling embedded catalog. GPT-5.5 retired upstream; keep its known values as
// a synthetic fixture so old-client fallback behavior remains covered.
func useLegacyCodexClientCatalog(t *testing.T) {
	t.Helper()
	_, revision := registry.GetCodexClientModelsSnapshot()
	codexClientModelTemplatesMu.Lock()
	previousLoaded := codexClientModelTemplatesLoaded
	previousRevision := codexClientModelTemplatesRevision
	previousTemplates := codexClientModelTemplates
	previousDefault := codexClientDefaultTemplate
	previousErr := codexClientModelTemplatesErr
	codexClientModelTemplatesLoaded = false
	codexClientModelTemplatesMu.Unlock()
	t.Cleanup(func() {
		codexClientModelTemplatesMu.Lock()
		defer codexClientModelTemplatesMu.Unlock()
		codexClientModelTemplatesLoaded = previousLoaded
		codexClientModelTemplatesRevision = previousRevision
		codexClientModelTemplates = previousTemplates
		codexClientDefaultTemplate = previousDefault
		codexClientModelTemplatesErr = previousErr
	})
	snapshot := []byte(`{"models":[{
  "slug":"gpt-5.5", "display_name":"GPT-5.5",
  "description":"Synthetic legacy model fixture", "base_instructions":"Fixture instructions",
  "minimal_client_version":"0.137.0", "visibility":"list",
  "context_window":272000, "max_context_window":272000, "priority":0,
  "default_reasoning_level":"low", "supported_reasoning_levels":[{"effort":"low","description":"Fast"}],
  "comp_hash":"2911", "input_modalities":["text","image"],
  "supports_image_detail_original":true, "multi_agent_version":null
 }]}`)
	if _, _, err := loadCodexClientModelTemplatesSnapshot(snapshot, revision); err != nil {
		t.Fatalf("load legacy test catalog: %v", err)
	}
}

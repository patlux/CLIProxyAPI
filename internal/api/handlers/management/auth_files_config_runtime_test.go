package management

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// A configuration-synthesized OpenAI-compatibility credential has no auth file,
// yet the panel lists its runtime state. It must stay a config-sourced
// credential so model registration keeps working after a config reload.
func TestConfigSynthesizedOpenAICompatCredentialIsListedAsRuntimeOnly(t *testing.T) {
	cfg := &config.Config{
		OpenAICompatibility: []config.OpenAICompatibility{{
			Name:          "compat",
			BaseURL:       "https://compat.example.com/v1",
			APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "sk-secret"}},
			Models:        []config.OpenAICompatibilityModel{{Name: "model-a", Alias: "alias-a"}},
		}},
	}

	auths, errSynthesize := synthesizer.NewConfigSynthesizer().Synthesize(&synthesizer.SynthesisContext{
		Config:      cfg,
		Now:         time.Now(),
		IDGenerator: synthesizer.NewStableIDGenerator(),
	})
	if errSynthesize != nil {
		t.Fatalf("Synthesize() error = %v", errSynthesize)
	}
	if len(auths) != 1 {
		t.Fatalf("Synthesize() returned %d auths, want 1", len(auths))
	}
	auth := auths[0]

	if got := auth.AuthSourceKind(); got != coreauth.AuthSourceConfig {
		t.Fatalf("AuthSourceKind() = %q, want %q", got, coreauth.AuthSourceConfig)
	}
	if !coreauth.IsConfigAPIKeyAuth(auth) {
		t.Fatal("IsConfigAPIKeyAuth() = false, config API-key credentials must register their models")
	}
	if !isAuthFileListable(auth) {
		t.Fatal("isAuthFileListable() = false, the panel must list the runtime credential state")
	}

	entry := (&Handler{}).buildAuthFileEntry(auth, authFileQuotaContext{})
	if entry == nil {
		t.Fatal("buildAuthFileEntry() = nil, want a runtime credential entry")
	}
	if runtimeOnly, _ := entry["runtime_only"].(bool); !runtimeOnly {
		t.Fatalf("entry runtime_only = %#v, want true", entry["runtime_only"])
	}
	raw, _ := json.Marshal(entry)
	if strings.Contains(string(raw), "sk-secret") {
		t.Fatalf("entry leaked the API key: %s", raw)
	}
}

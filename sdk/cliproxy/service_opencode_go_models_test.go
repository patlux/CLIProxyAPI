package cliproxy

import (
	"context"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	internalregistry "github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestRegisterModelsForOpenCodeGoUsesConfiguredFlashOnly(t *testing.T) {
	const authID = "opencode-go-account"
	modelRegistry := internalregistry.GetGlobalRegistry()
	modelRegistry.UnregisterClient(authID)
	t.Cleanup(func() { modelRegistry.UnregisterClient(authID) })

	service := &Service{cfg: &config.Config{OpenAICompatibility: []config.OpenAICompatibility{{
		Name:    "opencode-go",
		BaseURL: "https://opencode.ai/zen/go/v1",
		Models: []internalconfig.OpenAICompatibilityModel{{
			Name:  "deepseek-v4-flash",
			Alias: "deepseek-v4-flash",
		}},
	}}}}
	auth := &coreauth.Auth{
		ID:       authID,
		Provider: "opencode-go",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			coreauth.AttributeAPIKey:   "routing-key",
			coreauth.AttributeAuthKind: coreauth.AuthKindOAuth,
			"base_url":                 "https://opencode.ai/zen/go/v1",
		},
	}
	service.registerModelsForAuth(context.Background(), auth)
	models := modelRegistry.GetModelsForClient(authID)
	if len(models) != 1 || models[0].ID != "deepseek-v4-flash" {
		t.Fatalf("registered models = %#v, want deepseek-v4-flash only", models)
	}
}

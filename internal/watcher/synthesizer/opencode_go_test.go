package synthesizer

import (
	"path/filepath"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestSynthesizeOpenCodeGoOAuthMapsRoutingCredential(t *testing.T) {
	authDir := t.TempDir()
	ctx := &SynthesisContext{AuthDir: authDir, Now: time.Now()}
	raw := []byte(`{
		"type":"opencode-go",
		"auth_kind":"oauth",
		"email":"person@example.com",
		"access_token":"identity-token",
		"refresh_token":"refresh-token",
		"api_key":"go-routing-key",
		"base_url":"https://opencode.ai/zen/go/v1"
	}`)
	auths, errSynthesize := SynthesizeAuthFile(ctx, filepath.Join(authDir, "opencode.json"), raw)
	if errSynthesize != nil {
		t.Fatalf("SynthesizeAuthFile() error = %v", errSynthesize)
	}
	if len(auths) != 1 {
		t.Fatalf("auth len = %d, want 1", len(auths))
	}
	auth := auths[0]
	if auth.AuthKind() != coreauth.AuthKindOAuth {
		t.Fatalf("AuthKind() = %q, want oauth", auth.AuthKind())
	}
	if auth.Attributes[coreauth.AttributeAPIKey] != "go-routing-key" {
		t.Fatalf("api_key attribute = %q", auth.Attributes[coreauth.AttributeAPIKey])
	}
	if auth.Attributes["base_url"] != "https://opencode.ai/zen/go/v1" {
		t.Fatalf("base_url attribute = %q", auth.Attributes["base_url"])
	}
	if auth.Attributes[coreauth.AttributeAPIKey] == auth.Metadata["access_token"] {
		t.Fatal("OAuth identity token was incorrectly used as routing key")
	}
}

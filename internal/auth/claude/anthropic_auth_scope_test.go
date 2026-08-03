package claude

import (
	"net/url"
	"strings"
	"testing"
)

func TestGenerateAuthURLIncludesDesignScopes(t *testing.T) {
	auth := &ClaudeAuth{}
	generated, _, errGenerate := auth.GenerateAuthURL("state", &PKCECodes{
		CodeVerifier:  "verifier",
		CodeChallenge: "challenge",
	})
	if errGenerate != nil {
		t.Fatalf("GenerateAuthURL returned error: %v", errGenerate)
	}
	parsed, errParse := url.Parse(generated)
	if errParse != nil {
		t.Fatalf("parse generated URL: %v", errParse)
	}
	scopes := strings.Fields(parsed.Query().Get("scope"))
	available := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		available[scope] = true
	}
	for _, required := range []string{"user:inference", "user:design:read", "user:design:write"} {
		if !available[required] {
			t.Fatalf("generated OAuth URL missing scope %q: %v", required, scopes)
		}
	}
}

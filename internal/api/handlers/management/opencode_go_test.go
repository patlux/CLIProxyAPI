package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/opencodego"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestAssociateOpenCodeGoKeyEnablesIdentityWithoutReplacingOAuthToken(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{
		ID:       "opencode-go-account.json",
		Provider: opencodego.Provider,
		Status:   coreauth.StatusDisabled,
		Disabled: true,
		Metadata: map[string]any{
			"auth_kind":     coreauth.AuthKindOAuth,
			"access_token":  "identity-access-token",
			"refresh_token": "identity-refresh-token",
			"email":         "person@example.com",
		},
		Attributes: map[string]string{coreauth.AttributeAuthKind: coreauth.AuthKindOAuth},
	}
	index := auth.EnsureIndex()
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}
	h := &Handler{authManager: manager}
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	request := httptest.NewRequest(http.MethodPost, "/v0/management/opencode-go/associate-key", strings.NewReader(`{"auth_index":"`+index+`","api_key":"go-routing-key","workspace_id":"wrk_test"}`))
	request.Header.Set("Content-Type", "application/json")
	ctx.Request = request
	h.AssociateOpenCodeGoKey(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	updated, ok := manager.GetByID(auth.ID)
	if !ok || updated == nil {
		t.Fatal("updated auth not found")
	}
	if updated.Disabled || updated.Status != coreauth.StatusActive {
		t.Fatalf("disabled/status = %v/%s, want active", updated.Disabled, updated.Status)
	}
	if updated.Attributes[coreauth.AttributeWeight] != "1" || updated.Metadata[coreauth.AttributeWeight] != 1 {
		t.Fatalf("weight = %q/%#v, want 1", updated.Attributes[coreauth.AttributeWeight], updated.Metadata[coreauth.AttributeWeight])
	}
	if updated.Attributes[coreauth.AttributeAPIKey] != "go-routing-key" {
		t.Fatalf("routing key = %q", updated.Attributes[coreauth.AttributeAPIKey])
	}
	if updated.Metadata["access_token"] != "identity-access-token" {
		t.Fatal("OAuth identity token was replaced")
	}
	if updated.Metadata["workspace_id"] != "wrk_test" {
		t.Fatalf("workspace_id = %#v", updated.Metadata["workspace_id"])
	}
}

func TestAuthFileEntryMasksAPIKeyAccount(t *testing.T) {
	auth := &coreauth.Auth{
		ID:       "key.json",
		FileName: "key.json",
		Provider: "example",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			coreauth.AttributePath:     t.TempDir() + "/key.json",
			coreauth.AttributeAPIKey:   "super-secret-api-key",
			coreauth.AttributeAuthKind: coreauth.AuthKindAPIKey,
		},
		CreatedAt: time.Now(),
	}
	entry := (&Handler{}).buildAuthFileEntry(auth)
	account, _ := entry["account"].(string)
	if account == "super-secret-api-key" || !strings.Contains(account, "...") {
		t.Fatalf("account = %q, want masked API key", account)
	}
	raw, _ := json.Marshal(entry)
	if strings.Contains(string(raw), "super-secret-api-key") {
		t.Fatalf("entry leaked API key: %s", raw)
	}
}

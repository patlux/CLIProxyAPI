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
	claudeauth "github.com/router-for-me/CLIProxyAPI/v7/internal/auth/claude"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type authTokenRefreshExecutor struct {
	calls int
}

func (e *authTokenRefreshExecutor) Identifier() string { return "claude" }
func (e *authTokenRefreshExecutor) Execute(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}
func (e *authTokenRefreshExecutor) ExecuteStream(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}
func (e *authTokenRefreshExecutor) CountTokens(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}
func (e *authTokenRefreshExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}
func (e *authTokenRefreshExecutor) Refresh(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	e.calls++
	auth.Metadata["access_token"] = "refreshed-access-token"
	auth.Metadata["refresh_token"] = "rotated-refresh-token"
	auth.Metadata["expired"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	return auth, nil
}

func callAuthToken(t *testing.T, h *Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	request := httptest.NewRequest(http.MethodPost, "/v0/management/auth-token", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	ctx.Request = request
	h.AuthToken(ctx)
	return recorder
}

func TestAuthTokenReturnsOnlySelectedOAuthAccessToken(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{
		ID:       "claude-personal",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		Metadata: map[string]any{
			"access_token":  "selected-access-token",
			"refresh_token": "must-not-leak",
			"expired":       time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			"type":          "claude",
		},
	}
	index := auth.EnsureIndex()
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	recorder := callAuthToken(t, &Handler{authManager: manager}, `{"auth_index":"`+index+`","provider":"claude"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", recorder.Header().Get("Cache-Control"))
	}
	if strings.Contains(recorder.Body.String(), "must-not-leak") || strings.Contains(recorder.Body.String(), "refresh_token") {
		t.Fatalf("response leaked refresh credentials: %s", recorder.Body.String())
	}
	var response map[string]any
	if errUnmarshal := json.Unmarshal(recorder.Body.Bytes(), &response); errUnmarshal != nil {
		t.Fatalf("decode response: %v", errUnmarshal)
	}
	if response["access_token"] != "selected-access-token" || response["auth_index"] != index || response["provider"] != "claude" {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestAuthTokenReturnsAccessTokenFromFreshClaudeLoginStorage(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	auth := &coreauth.Auth{
		ID:       "claude-fresh-login",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		Storage: &claudeauth.ClaudeTokenStorage{
			AccessToken:  "fresh-login-access-token",
			RefreshToken: "must-not-leak",
			Expire:       time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		},
		Metadata: map[string]any{
			"expired": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
			"type":    "claude",
		},
	}
	index := auth.EnsureIndex()
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	recorder := callAuthToken(t, &Handler{authManager: manager}, `{"auth_index":"`+index+`","provider":"claude"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "fresh-login-access-token") || strings.Contains(recorder.Body.String(), "must-not-leak") {
		t.Fatalf("unexpected response: %s", recorder.Body.String())
	}
}

func TestAuthTokenRefreshesExpiringCredential(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	executor := &authTokenRefreshExecutor{}
	manager.RegisterExecutor(executor)
	auth := &coreauth.Auth{
		ID:       "claude-expiring",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		Metadata: map[string]any{
			"access_token":  "old-access-token",
			"refresh_token": "refresh-token",
			"expired":       time.Now().Add(time.Minute).UTC().Format(time.RFC3339),
			"type":          "claude",
		},
	}
	index := auth.EnsureIndex()
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	recorder := callAuthToken(t, &Handler{authManager: manager}, `{"auth_index":"`+index+`","provider":"claude"}`)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	if executor.calls != 1 {
		t.Fatalf("refresh calls = %d, want 1", executor.calls)
	}
	if !strings.Contains(recorder.Body.String(), "refreshed-access-token") || strings.Contains(recorder.Body.String(), "rotated-refresh-token") {
		t.Fatalf("unexpected response: %s", recorder.Body.String())
	}
}

func TestAuthTokenRejectsExpiredCredentialAfterIneffectiveRefresh(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	manager.RegisterExecutor(&ineffectiveAuthTokenRefreshExecutor{})
	auth := &coreauth.Auth{
		ID:       "claude-expired",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		Metadata: map[string]any{
			"access_token":  "expired-access-token",
			"refresh_token": "refresh-token",
			"expired":       time.Now().Add(-time.Minute).UTC().Format(time.RFC3339),
			"type":          "claude",
		},
	}
	index := auth.EnsureIndex()
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	recorder := callAuthToken(t, &Handler{authManager: manager}, `{"auth_index":"`+index+`","provider":"claude"}`)
	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502: %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "expired-access-token") || strings.Contains(recorder.Body.String(), "refresh-token") {
		t.Fatalf("response leaked credentials: %s", recorder.Body.String())
	}
}

type ineffectiveAuthTokenRefreshExecutor struct{}

func (*ineffectiveAuthTokenRefreshExecutor) Identifier() string { return "claude" }
func (*ineffectiveAuthTokenRefreshExecutor) Execute(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}
func (*ineffectiveAuthTokenRefreshExecutor) ExecuteStream(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}
func (*ineffectiveAuthTokenRefreshExecutor) CountTokens(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}
func (*ineffectiveAuthTokenRefreshExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}
func (*ineffectiveAuthTokenRefreshExecutor) Refresh(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	return auth, nil
}

func TestAuthTokenRejectsWrongProviderAndNonOAuthCredential(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	oauth := &coreauth.Auth{
		ID:       "claude-oauth",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		Metadata: map[string]any{"access_token": "token", "type": "claude"},
	}
	oauthIndex := oauth.EnsureIndex()
	if _, errRegister := manager.Register(context.Background(), oauth); errRegister != nil {
		t.Fatalf("register OAuth auth: %v", errRegister)
	}
	apiKey := &coreauth.Auth{
		ID:         "claude-api-key",
		Provider:   "claude",
		Status:     coreauth.StatusActive,
		Attributes: map[string]string{"api_key": "secret-api-key"},
	}
	apiKeyIndex := apiKey.EnsureIndex()
	if _, errRegister := manager.Register(context.Background(), apiKey); errRegister != nil {
		t.Fatalf("register API key auth: %v", errRegister)
	}

	wrongProvider := callAuthToken(t, &Handler{authManager: manager}, `{"auth_index":"`+oauthIndex+`","provider":"codex"}`)
	if wrongProvider.Code != http.StatusConflict {
		t.Fatalf("wrong-provider status = %d, want 409", wrongProvider.Code)
	}
	apiKeyResponse := callAuthToken(t, &Handler{authManager: manager}, `{"auth_index":"`+apiKeyIndex+`","provider":"claude"}`)
	if apiKeyResponse.Code != http.StatusConflict {
		t.Fatalf("API-key status = %d, want 409", apiKeyResponse.Code)
	}
	if strings.Contains(apiKeyResponse.Body.String(), "secret-api-key") {
		t.Fatalf("API-key response leaked credential: %s", apiKeyResponse.Body.String())
	}
}

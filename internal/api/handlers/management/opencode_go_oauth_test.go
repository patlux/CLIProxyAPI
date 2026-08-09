package management

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/opencodego"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type fakeOpenCodeGoOAuthService struct {
	bundle *opencodego.TokenBundle
}

func (*fakeOpenCodeGoOAuthService) GenerateAuthURL(context.Context, string, string, *opencodego.PKCECodes) (string, error) {
	return "https://auth.example.test/authorize", nil
}

func (s *fakeOpenCodeGoOAuthService) ExchangeCodeForTokens(context.Context, string, string, *opencodego.PKCECodes) (*opencodego.TokenBundle, error) {
	return s.bundle, nil
}

func TestRequestOpenCodeGoTokenStoresNonRoutableIdentity(t *testing.T) {
	oldFactory := newOpenCodeGoOAuthService
	defer func() { newOpenCodeGoOAuthService = oldFactory }()
	newOpenCodeGoOAuthService = func(*config.Config) openCodeGoOAuthService {
		return &fakeOpenCodeGoOAuthService{bundle: &opencodego.TokenBundle{
			AccessToken:  "identity-access",
			RefreshToken: "identity-refresh",
			TokenType:    "Bearer",
			ExpiresAt:    time.Now().Add(time.Hour),
			AccountID:    "acc_test",
			Email:        "person@example.com",
		}}
	}

	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir, Port: 8318}, manager)
	h.tokenStore = newMemoryPersistingAuthStore()

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/opencode-go-auth-url", nil)
	h.RequestOpenCodeGoToken(ctx)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	state := strings.TrimSpace(gjsonString(recorder.Body.Bytes(), "state"))
	if state == "" {
		t.Fatal("missing OAuth state")
	}
	if _, errCallback := WriteOAuthCallbackFileForPendingSession(authDir, opencodego.Provider, state, "test-code", ""); errCallback != nil {
		t.Fatalf("write callback: %v", errCallback)
	}

	deadline := time.Now().Add(3 * time.Second)
	var saved *coreauth.Auth
	for time.Now().Before(deadline) {
		saved = h.tokenStore.(*memoryPersistingAuthStore).first()
		if saved != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if saved == nil {
		t.Fatal("OAuth identity was not saved")
	}
	if saved.Provider != opencodego.Provider || saved.Metadata["access_token"] != "identity-access" {
		t.Fatalf("unexpected saved identity: %#v", saved)
	}
	if saved.Metadata[coreauth.AttributeWeight] != 0 {
		t.Fatalf("weight = %#v, want 0 before key association", saved.Metadata[coreauth.AttributeWeight])
	}
	if _, exists := saved.Metadata[coreauth.AttributeAPIKey]; exists {
		t.Fatal("OAuth identity unexpectedly contains a routing API key")
	}
	if _, errStat := filepath.Abs(authDir); errStat != nil {
		t.Fatalf("auth dir invalid: %v", errStat)
	}
}

type memoryPersistingAuthStore struct {
	mu    sync.Mutex
	auths map[string]*coreauth.Auth
}

func newMemoryPersistingAuthStore() *memoryPersistingAuthStore {
	return &memoryPersistingAuthStore{auths: make(map[string]*coreauth.Auth)}
}

func (s *memoryPersistingAuthStore) SetBaseDir(string)                              {}
func (s *memoryPersistingAuthStore) List(context.Context) ([]*coreauth.Auth, error) { return nil, nil }
func (s *memoryPersistingAuthStore) Save(_ context.Context, auth *coreauth.Auth) (string, error) {
	s.mu.Lock()
	s.auths[auth.ID] = auth.Clone()
	s.mu.Unlock()
	return auth.FileName, nil
}
func (s *memoryPersistingAuthStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	delete(s.auths, id)
	s.mu.Unlock()
	return nil
}
func (s *memoryPersistingAuthStore) first() *coreauth.Auth {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, auth := range s.auths {
		return auth.Clone()
	}
	return nil
}

func gjsonString(raw []byte, key string) string {
	needle := `"` + key + `":"`
	start := strings.Index(string(raw), needle)
	if start < 0 {
		return ""
	}
	remaining := string(raw)[start+len(needle):]
	end := strings.IndexByte(remaining, '"')
	if end < 0 {
		return ""
	}
	return remaining[:end]
}

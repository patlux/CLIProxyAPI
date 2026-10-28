package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// Exercise the real v8 route, persistence transaction and sticky selector. No
// provider requests, real credentials, browser state or network listener needed.
func TestFiveHourLimitV8RoutesAndStickyFailover(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	dir := t.TempDir()
	store := fileauth.NewFileTokenStore()
	store.SetBaseDir(dir)
	selector := coreauth.NewSessionAffinitySelector(&coreauth.SoonestResetFirstSelector{})
	defer selector.Stop()
	manager := coreauth.NewManager(store, selector, nil)
	for _, id := range []string{"a.json", "b.json"} {
		priority := "0"
		if id == "a.json" {
			priority = "80"
		}
		a := &coreauth.Auth{ID: id, FileName: id, Provider: "claude", Status: coreauth.StatusActive,
			Attributes: map[string]string{"path": filepath.Join(dir, id), "weight": "10", "priority": priority},
			Metadata:   map[string]any{"type": "claude", "weight": 10},
		}
		if _, err := manager.Register(context.Background(), a); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{AuthDir: dir}
	cfg.RemoteManagement.SecretKey = "synthetic-config-marker"
	h := management.NewHandlerWithoutConfigFilePath(cfg, manager)
	h.SetLocalPassword("synthetic-test-password")
	s := &Server{cfg: cfg, engine: gin.New(), mgmt: h}
	s.managementRoutesEnabled.Store(true)
	s.registerManagementV8Routes()
	request := func(name, value, weight string, authorized bool) int {
		t.Helper()
		req := httptest.NewRequest(http.MethodPatch, "/v8/management/credentials/five-hour-limit", strings.NewReader(`{"name":"`+name+`","five_hour_limit_percent":`+value+`,"weight":`+weight+`}`))
		req.RemoteAddr = "127.0.0.1:1234"
		if authorized {
			req.Header.Set("Authorization", "Bearer synthetic-test-password")
		}
		res := httptest.NewRecorder()
		s.engine.ServeHTTP(res, req)
		return res.Code
	}
	pick := func(session string) *coreauth.Auth {
		t.Helper()
		a, _ := selector.Pick(context.Background(), "claude", "test-model", executor.Options{Metadata: map[string]any{executor.DerivedSessionIDMetadataKey: session}}, manager.List())
		return a
	}
	if got := pick("existing"); got == nil || got.ID != "a.json" {
		t.Fatalf("initial pick=%v", got)
	}
	if status := request("a.json", "50", "0", false); status != 401 {
		t.Fatalf("unauthenticated status=%d", status)
	}
	if status := request("a.json", "50", "0", true); status != 200 {
		t.Fatalf("policy status=%d", status)
	}
	if got := pick("existing"); got == nil || got.ID != "b.json" {
		t.Fatalf("sticky session failed to move: %v", got)
	}
	if got := pick("new"); got == nil || got.ID != "b.json" {
		t.Fatalf("new session failed to move: %v", got)
	}
	if status := request("b.json", "50", "0", true); status != 200 {
		t.Fatalf("second policy status=%d", status)
	}
	if got := pick("all-paused"); got != nil {
		t.Fatalf("all-paused routing bypassed cap: %v", got)
	}
	if status := request("a.json", "null", "10", true); status != 200 {
		t.Fatalf("remove status=%d", status)
	}
	if got := pick("restored"); got == nil || got.ID != "a.json" {
		t.Fatalf("removed cap did not restore routing: %v", got)
	}
}

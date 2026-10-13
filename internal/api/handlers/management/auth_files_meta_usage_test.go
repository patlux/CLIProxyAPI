package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestListAuthFilesExposesMetaSubsUsage(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	manager := coreauth.NewManager(nil, nil, nil)
	cfg := &config.Config{AuthDir: t.TempDir()}
	manager.SetConfig(cfg)
	registerAuthForLookupTest(t, manager, &coreauth.Auth{
		ID: "meta-1", Index: "meta-index", Provider: "meta", Status: coreauth.StatusActive,
		Attributes: map[string]string{"runtime_only": "true"},
		Metadata: map[string]any{
			"api_key": "LLM|secret",
			"subs_usage": map[string]any{
				"window": map[string]any{"window_duration_mins": 300, "used_percent": 12.5, "resets_at": int64(2_000_000_000)},
				"weekly": map[string]any{"used_percent": 34.0, "resets_at": int64(2_000_604_800)},
			},
		},
	})
	h := NewHandlerWithoutConfigFilePath(cfg, manager)
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files", nil)
	h.ListAuthFiles(ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Files []struct {
			Provider  string         `json:"provider"`
			SubsUsage map[string]any `json:"subs_usage"`
		} `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Files) != 1 || payload.Files[0].SubsUsage == nil {
		t.Fatalf("payload = %s", rec.Body.String())
	}
	window := payload.Files[0].SubsUsage["window"].(map[string]any)
	if window["used_percent"] != 12.5 {
		t.Fatalf("window = %#v", window)
	}
	if strings.Contains(rec.Body.String(), "LLM|secret") {
		t.Fatalf("inventory leaked credential material: %s", rec.Body.String())
	}
}

package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestFiveHourLimitV8PersistsAndRemoves(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	dir := t.TempDir()
	store := fileauth.NewFileTokenStore()
	store.SetBaseDir(dir)
	manager := coreauth.NewManager(store, nil, nil)
	record := &coreauth.Auth{
		ID: "account.json", FileName: "account.json", Provider: "claude",
		Attributes: map[string]string{"path": filepath.Join(dir, "account.json")},
		Metadata:   map[string]any{"type": "claude", "priority": float64(80)},
	}
	if _, err := manager.Register(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: dir}, manager)
	for _, value := range []string{"50", "null"} {
		rec := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(rec)
		ctx.Request = httptest.NewRequest(http.MethodPatch, "/v8/management/credentials/five-hour-limit", strings.NewReader(`{"name":"account.json","five_hour_limit_percent":`+value+`,"weight":0}`))
		h.PatchFiveHourLimit(ctx)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
		}
		updated, _ := manager.GetByID(record.ID)
		entry := h.buildAuthFileEntryLocked(updated, authFileQuotaContext{v8: true})
		if entry["five_hour_limit_editable"] != true {
			t.Fatalf("missing capability: %v", entry)
		}
		if value == "50" && entry["five_hour_limit_percent"] != 50 {
			t.Fatalf("limit not listed: %v", entry)
		}
		if value == "null" && entry["five_hour_limit_percent"] != nil {
			t.Fatalf("limit not removed: %v", entry)
		}
		if _, ok := h.buildAuthFileEntryLocked(updated, authFileQuotaContext{})["five_hour_limit_percent"]; ok {
			t.Fatal("changed deprecated v0 contract")
		}
		raw, err := os.ReadFile(filepath.Join(dir, "account.json"))
		if err != nil {
			t.Fatal(err)
		}
		var saved map[string]any
		if err := json.Unmarshal(raw, &saved); err != nil {
			t.Fatal(err)
		}
		if saved["priority"] != float64(80) {
			t.Fatal("priority changed")
		}
		if value == "50" && saved["five_hour_limit_percent"] != float64(50) {
			t.Fatalf("limit not persisted: %v", saved)
		}
		if value == "null" && saved["five_hour_limit_percent"] != nil {
			t.Fatal("limit remains on disk")
		}
		restartedStore := fileauth.NewFileTokenStore()
		restartedStore.SetBaseDir(dir)
		reloaded, err := restartedStore.List(context.Background())
		if err != nil || len(reloaded) != 1 {
			t.Fatalf("reload: %v, %v", reloaded, err)
		}
		limit, set := fiveHourLimit(reloaded[0].Metadata)
		if (value == "50" && (!set || limit != 50)) || (value == "null" && set) {
			t.Fatalf("reloaded limit=%d set=%v", limit, set)
		}
	}
}

func TestFiveHourLimitV8RejectsInvalidInput(t *testing.T) {
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, coreauth.NewManager(&memoryAuthStore{}, nil, nil))
	for _, body := range []string{
		`{}`, `null`, `{"name":"a","five_hour_limit_percent":0}`, `{"name":"a","five_hour_limit_percent":101}`,
		`{"name":"a","five_hour_limit_percent":-1}`, `{"name":"a","five_hour_limit_percent":50.5}`,
		`{"name":"a","five_hour_limit_percent":"50"}`, `{"name":"a","five_hour_limit_percent":true}`,
		`{"name":"a","five_hour_limit_percent":50,"priority":90}`, `{"name":"a","five_hour_limit_percent":50} {}`,
	} {
		rec := httptest.NewRecorder()
		ctx, _ := gin.CreateTestContext(rec)
		ctx.Request = httptest.NewRequest(http.MethodPatch, "/v8/management/credentials/five-hour-limit", strings.NewReader(body))
		h.PatchFiveHourLimit(ctx)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d", body, rec.Code)
		}
	}
}

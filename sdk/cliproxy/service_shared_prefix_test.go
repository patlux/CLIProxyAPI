package cliproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

// Exercise the real file synthesizer, catalog publication, selector and upstream
// model resolution without OAuth secrets, network requests or duplicate auths.
func TestSharedPrefixRouting(t *testing.T) {
	ctx := coreauth.WithSkipPersist(context.Background())
	selector := coreauth.NewSessionAffinitySelector(&coreauth.SoonestResetFirstSelector{})
	t.Cleanup(selector.Stop)
	manager := coreauth.NewManager(nil, selector, nil)
	manager.RegisterExecutor(sharedPrefixExecutor{})
	cfg := &config.Config{SDKConfig: config.SDKConfig{ForceModelPrefix: true}}
	manager.SetConfig(cfg)
	service := &Service{cfg: cfg, coreManager: manager}
	reg := GlobalModelRegistry()
	directory := t.TempDir()

	register := func(id, prefix string, additional []string) *coreauth.Auth {
		t.Helper()
		data, err := json.Marshal(map[string]any{
			"type": "claude", "prefix": prefix, "additional_prefixes": additional,
			"email": "synthetic@example.invalid",
		})
		if err != nil {
			t.Fatal(err)
		}
		auths, err := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{
			AuthDir: directory, Config: cfg, Now: time.Now(),
		}, filepath.Join(directory, id), data)
		if err != nil || len(auths) != 1 {
			t.Fatalf("synthesize = %d auths, %v; want one shared identity", len(auths), err)
		}
		auth, err := manager.Register(ctx, auths[0])
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { reg.UnregisterClient(auth.ID) })
		if !service.registerModelsForAuth(ctx, auth) {
			t.Fatal("catalog publication rejected")
		}
		return auth
	}

	shared := register("shared-prefix-test.json", "work", []string{"general"})
	ordinary := register("ordinary-prefix-test.json", "general", nil)
	const model = "claude-opus-5-5"
	for _, route := range []string{"work/" + model, "general/" + model} {
		if !reg.ClientSupportsModel(shared.ID, route) {
			t.Fatalf("shared credential does not publish %s", route)
		}
		if got := manager.ResolveExecutionModel(shared, route+"(high)"); got != model+"(high)" {
			t.Fatalf("upstream = %q for %s", got, route)
		}
	}
	if reg.ClientSupportsModel(ordinary.ID, "work/"+model) {
		t.Fatal("ordinary credential entered the work namespace")
	}
	for _, auth := range []*coreauth.Auth{shared, ordinary} {
		for _, entry := range reg.GetModelsForClient(auth.ID) {
			if !strings.HasPrefix(entry.ID, "work/") && !strings.HasPrefix(entry.ID, "general/") {
				t.Fatalf("unexpected bare/nested model: %s", entry.ID)
			}
		}
	}

	publish := func(early, late *coreauth.Auth, observed time.Time) {
		t.Helper()
		_, err := manager.MergeQuotaResetHints(map[string]coreauth.QuotaResetHint{
			early.ID: {ObservedAt: observed, ResetAt: observed.Add(time.Hour)},
			late.ID:  {ObservedAt: observed, ResetAt: observed.Add(24 * time.Hour)},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	execute := func(route, session string, want *coreauth.Auth) {
		t.Helper()
		response, err := manager.Execute(ctx, []string{"claude"}, executor.Request{Model: route + "/" + model}, executor.Options{
			Metadata: map[string]any{executor.DerivedSessionIDMetadataKey: session},
		})
		if err != nil || string(response.Payload) != want.ID+":"+model {
			t.Fatalf("execute %s/%s = %s, %v; want %s", route, session, response.Payload, err, want.ID)
		}
	}

	now := time.Now()
	publish(ordinary, shared, now.Add(-time.Second))
	execute("work", "work-session", shared)
	execute("general", "outside-old", ordinary)
	publish(shared, ordinary, now)
	execute("general", "outside-new", shared)
	// The existing cache-affinity contract remains intact when the reset order changes.
	execute("general", "outside-old", ordinary)
	for _, route := range []string{"work/" + model, "general/" + model} {
		request := executor.Request{Model: route}
		want := shared.ID + ":" + model
		count, err := manager.ExecuteCount(ctx, []string{"claude"}, request, executor.Options{})
		if err != nil || string(count.Payload) != want {
			t.Fatalf("count %s = %s, %v", route, count.Payload, err)
		}
		stream, err := manager.ExecuteStream(ctx, []string{"claude"}, request, executor.Options{})
		if err != nil {
			t.Fatal(err)
		}
		var payload string
		for chunk := range stream.Chunks {
			if chunk.Err != nil {
				t.Fatal(chunk.Err)
			}
			payload += string(chunk.Payload)
		}
		if payload != want {
			t.Fatalf("stream %s = %s, want %s", route, payload, want)
		}
	}

	// A quota failure through either namespace blocks the same upstream state.
	retryAfter := time.Hour
	manager.MarkResult(ctx, coreauth.Result{
		AuthID: shared.ID, Provider: "claude", Model: model, Success: false,
		Error:      &coreauth.Error{HTTPStatus: http.StatusTooManyRequests, Message: "synthetic quota"},
		RetryAfter: &retryAfter,
	})
	for _, route := range []string{"work/" + model, "general/" + model} {
		if !registry.GetGlobalRegistry().IsModelQuotaExceededForClient(shared.ID, route) {
			t.Fatalf("quota state not shared with %s", route)
		}
	}
	execute("general", "outside-new", ordinary)
	if _, err := manager.Execute(ctx, []string{"claude"}, executor.Request{Model: "work/" + model}, executor.Options{}); err == nil {
		t.Fatal("work namespace unexpectedly fell back to an ordinary credential")
	}
	// Removing the shared prefix republishes the same identity, not a stale
	// second registration. Existing work access and quota state survive.
	shared = register(shared.ID, "work", nil)
	if reg.ClientSupportsModel(shared.ID, "general/"+model) || !reg.ClientSupportsModel(shared.ID, "work/"+model) {
		t.Fatal("prefix removal left stale or lost primary routes")
	}
	execute("general", "outside-after-removal", ordinary)
	shared.Disabled = true
	shared.Status = coreauth.StatusDisabled
	shared, err := manager.Update(ctx, shared)
	if err != nil || !service.registerModelsForAuth(ctx, shared) {
		t.Fatalf("disable publication: %v", err)
	}
	if len(reg.GetModelsForClient(shared.ID)) != 0 {
		t.Fatal("disabled credential still publishes models")
	}
}

type sharedPrefixExecutor struct{}

func (sharedPrefixExecutor) Identifier() string { return "claude" }
func (sharedPrefixExecutor) Execute(_ context.Context, auth *coreauth.Auth, req executor.Request, _ executor.Options) (executor.Response, error) {
	return executor.Response{Payload: []byte(auth.ID + ":" + req.Model)}, nil
}
func (sharedPrefixExecutor) ExecuteStream(_ context.Context, auth *coreauth.Auth, req executor.Request, _ executor.Options) (*executor.StreamResult, error) {
	chunks := make(chan executor.StreamChunk, 1)
	chunks <- executor.StreamChunk{Payload: []byte(auth.ID + ":" + req.Model)}
	close(chunks)
	return &executor.StreamResult{Chunks: chunks}, nil
}
func (sharedPrefixExecutor) Refresh(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	return auth, nil
}
func (e sharedPrefixExecutor) CountTokens(ctx context.Context, auth *coreauth.Auth, req executor.Request, opts executor.Options) (executor.Response, error) {
	return e.Execute(ctx, auth, req, opts)
}
func (sharedPrefixExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("HTTP not used")
}

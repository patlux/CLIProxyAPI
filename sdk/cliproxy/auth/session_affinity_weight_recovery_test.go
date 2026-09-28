package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// A quota reconciler can temporarily remove every account from weighted routing.
// Restoring a fallback account must recover the existing session, not just new ones.
func TestManagerSessionAffinityRecoversAfterAllWeightsBecomeZero(t *testing.T) {
	ctx := WithSkipPersist(context.Background())
	const provider = "claude"
	const model = "anthropic/claude-opus-5-5"
	const privateID = "weight-recovery-private"
	const sharedID = "weight-recovery-shared"

	manager := NewManager(nil, nil, nil)
	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &WeightedRoundRobinSelector{},
		TTL:      time.Hour,
	})
	defer affinity.Stop()
	manager.SetSelector(affinity)
	manager.RegisterExecutor(schedulerTestExecutor{provider: provider})

	for _, auth := range []*Auth{
		{ID: privateID, Provider: provider, Status: StatusActive, Attributes: map[string]string{"priority": "80", AttributeWeight: "20"}},
		{ID: sharedID, Provider: provider, Status: StatusActive, Attributes: map[string]string{AttributeWeight: "0"}},
	} {
		if _, err := manager.Register(ctx, auth); err != nil {
			t.Fatalf("Register(%s): %v", auth.ID, err)
		}
		registry.GetGlobalRegistry().RegisterClient(auth.ID, provider, []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
	}

	// Rebuild request metadata each time, as independent HTTP requests do.
	pick := func(session string) (*Auth, error) {
		opts := cliproxyexecutor.Options{Metadata: map[string]any{
			cliproxyexecutor.DerivedSessionIDMetadataKey: session,
		}}
		auth, _, _, err := manager.pickNextMixed(ctx, []string{provider}, model, opts, nil)
		return auth, err
	}
	assertPick := func(session, want string) {
		t.Helper()
		auth, err := pick(session)
		if err != nil {
			t.Fatalf("pick(%s): %v", session, err)
		}
		if auth == nil || auth.ID != want {
			t.Fatalf("pick(%s) = %v, want %s", session, auth, want)
		}
	}
	setWeight := func(id, weight string) {
		t.Helper()
		manager.mu.RLock()
		auth := manager.auths[id].Clone()
		manager.mu.RUnlock()
		auth.Attributes[AttributeWeight] = weight
		if _, err := manager.Update(ctx, auth); err != nil {
			t.Fatalf("Update(%s): %v", id, err)
		}
	}

	assertPick("existing-session", privateID)
	setWeight(privateID, "0")
	for _, session := range []string{"existing-session", "new-session-during-outage"} {
		_, err := pick(session)
		var authErr *Error
		if !errors.As(err, &authErr) || authErr.Code != "auth_not_found" || authErr.Message != "no auth candidates" {
			t.Fatalf("pick(%s) error = %v, want auth_not_found: no auth candidates", session, err)
		}
	}

	setWeight(sharedID, "20")
	assertPick("existing-session", sharedID)
	assertPick("new-session-after-recovery", sharedID)
	// Recovery of the preferred account must not steal the repaired binding.
	setWeight(privateID, "20")
	assertPick("existing-session", sharedID)
	assertPick("new-session-after-private-recovery", privateID)
}

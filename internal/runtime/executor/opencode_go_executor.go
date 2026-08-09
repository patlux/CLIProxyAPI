package executor

import (
	"context"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/opencodego"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// OpenCodeGoExecutor uses the OpenAI-compatible transport with a separately
// imported Go routing key and refreshes only the account identity OAuth session.
type OpenCodeGoExecutor struct {
	*OpenAICompatExecutor
	cfg *config.Config
}

func NewOpenCodeGoExecutor(cfg *config.Config) *OpenCodeGoExecutor {
	return &OpenCodeGoExecutor{
		OpenAICompatExecutor: NewOpenAICompatExecutor(opencodego.Provider, cfg),
		cfg:                  cfg,
	}
}

func (e *OpenCodeGoExecutor) Identifier() string { return opencodego.Provider }

func (e *OpenCodeGoExecutor) Refresh(ctx context.Context, auth *cliproxyauth.Auth) (*cliproxyauth.Auth, error) {
	log.Debug("opencode go executor: refresh called")
	if refreshed, handled, err := helps.RefreshAuthViaHome(ctx, e.cfg, auth); handled {
		return refreshed, err
	}
	if auth == nil {
		return nil, statusErr{code: 500, msg: "opencode go executor: auth is nil"}
	}
	refreshToken := ""
	if auth.Metadata != nil {
		refreshToken, _ = auth.Metadata["refresh_token"].(string)
	}
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return auth, nil
	}
	bundle, errRefresh := opencodego.NewService(e.cfg, auth.ProxyURL).RefreshTokens(ctx, refreshToken)
	if errRefresh != nil {
		return nil, errRefresh
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["access_token"] = bundle.AccessToken
	auth.Metadata["refresh_token"] = bundle.RefreshToken
	auth.Metadata["token_type"] = bundle.TokenType
	auth.Metadata["expires_at"] = bundle.ExpiresAt.UTC().Format(time.RFC3339)
	auth.Metadata["last_refresh"] = time.Now().UTC().Format(time.RFC3339)
	auth.Metadata["account_id"] = bundle.AccountID
	auth.Metadata["email"] = bundle.Email
	auth.Metadata["new_account"] = bundle.NewAccount
	auth.Metadata["type"] = opencodego.Provider
	return auth, nil
}

package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/opencodego"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// OpenCodeGoAuthenticator advertises refresh scheduling for management-created records.
// Interactive login uses the existing management OAuth callback flow.
type OpenCodeGoAuthenticator struct{}

func NewOpenCodeGoAuthenticator() *OpenCodeGoAuthenticator { return &OpenCodeGoAuthenticator{} }

func (*OpenCodeGoAuthenticator) Provider() string { return opencodego.Provider }

func (*OpenCodeGoAuthenticator) RefreshLead() *time.Duration {
	lead := opencodego.RefreshLead()
	return &lead
}

func (*OpenCodeGoAuthenticator) Login(context.Context, *config.Config, *LoginOptions) (*coreauth.Auth, error) {
	return nil, fmt.Errorf("cliproxy auth: OpenCode Go login is available through the management OAuth endpoint")
}

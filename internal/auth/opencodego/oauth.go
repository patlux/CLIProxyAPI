package opencodego

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	"golang.org/x/sync/singleflight"
)

const (
	Provider           = "opencode-go"
	Issuer             = "https://auth.opencode.ai"
	ClientID           = "app"
	DefaultRedirectURI = "http://127.0.0.1:8317/v0/management/oauth-callback"
	UserAgent          = "CLIProxyAPI-OpenCode-Go/1"
	discoveryPath      = "/.well-known/oauth-authorization-server"
	requestTimeout     = 30 * time.Second
	refreshLead        = 5 * time.Minute
)

// Endpoints contains issuer-discovered OAuth endpoints.
type Endpoints struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	ResponseTypes         []string `json:"response_types_supported"`
}

// TokenBundle contains verified OpenCode account identity and its OAuth session tokens.
type TokenBundle struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresAt    time.Time
	AccountID    string
	Email        string
	NewAccount   bool
}

// Identity contains claims accepted after signature and issuer validation.
type Identity struct {
	AccountID  string
	Email      string
	NewAccount bool
	ExpiresAt  time.Time
}

// Service implements OpenCode OAuth discovery, exchange, verification, and refresh.
type Service struct {
	httpClient *http.Client
	issuer     string
	clientID   string

	mu        sync.Mutex
	endpoints *Endpoints
	keys      map[string]*ecdsa.PublicKey

	refreshGroup singleflight.Group
}

// NewService creates a service using CLIProxyAPI's configured proxy policy.
func NewService(cfg *config.Config, proxyURL string) *Service {
	effectiveProxyURL := strings.TrimSpace(proxyURL)
	var sdkConfig config.SDKConfig
	if cfg != nil {
		sdkConfig = cfg.SDKConfig
		if effectiveProxyURL == "" {
			effectiveProxyURL = strings.TrimSpace(cfg.ProxyURL)
		}
	}
	sdkConfig.ProxyURL = effectiveProxyURL
	return NewServiceWithClient(util.SetProxy(&sdkConfig, &http.Client{}), Issuer, ClientID)
}

// NewServiceWithClient creates an injectable service for tests.
func NewServiceWithClient(client *http.Client, issuer, clientID string) *Service {
	if client == nil {
		client = &http.Client{}
	}
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	clientID = strings.TrimSpace(clientID)
	return &Service{httpClient: client, issuer: issuer, clientID: clientID}
}

// RefreshLead returns the proactive refresh lead time.
func RefreshLead() time.Duration { return refreshLead }

// GenerateAuthURL builds a PKCE authorization URL for a loopback callback.
func (s *Service) GenerateAuthURL(ctx context.Context, state, redirectURI string, pkce *PKCECodes) (string, error) {
	if pkce == nil || strings.TrimSpace(pkce.CodeVerifier) == "" || strings.TrimSpace(pkce.CodeChallenge) == "" {
		return "", errors.New("opencode go oauth: PKCE codes are required")
	}
	if strings.TrimSpace(state) == "" {
		return "", errors.New("opencode go oauth: state is required")
	}
	if strings.TrimSpace(redirectURI) == "" {
		return "", errors.New("opencode go oauth: redirect URI is required")
	}
	endpoints, errDiscovery := s.discover(ctx)
	if errDiscovery != nil {
		return "", errDiscovery
	}
	authURL, errParse := url.Parse(endpoints.AuthorizationEndpoint)
	if errParse != nil {
		return "", fmt.Errorf("opencode go oauth: invalid authorization endpoint: %w", errParse)
	}
	query := authURL.Query()
	query.Set("client_id", s.clientID)
	query.Set("redirect_uri", strings.TrimSpace(redirectURI))
	query.Set("response_type", "code")
	query.Set("state", strings.TrimSpace(state))
	query.Set("provider", "google")
	query.Set("code_challenge_method", "S256")
	query.Set("code_challenge", pkce.CodeChallenge)
	authURL.RawQuery = query.Encode()
	return authURL.String(), nil
}

// ExchangeCodeForTokens exchanges and verifies a one-time authorization code.
func (s *Service) ExchangeCodeForTokens(ctx context.Context, code, redirectURI string, pkce *PKCECodes) (*TokenBundle, error) {
	if pkce == nil || strings.TrimSpace(pkce.CodeVerifier) == "" {
		return nil, errors.New("opencode go oauth: PKCE verifier is required")
	}
	values := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {s.clientID},
		"code":          {strings.TrimSpace(code)},
		"redirect_uri":  {strings.TrimSpace(redirectURI)},
		"code_verifier": {pkce.CodeVerifier},
	}
	return s.requestTokens(ctx, values)
}

// RefreshTokens rotates both OAuth tokens. A missing replacement refresh token is rejected.
func (s *Service) RefreshTokens(ctx context.Context, refreshToken string) (*TokenBundle, error) {
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return nil, errors.New("opencode go oauth: refresh token is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	result, errRefresh, _ := s.refreshGroup.Do(refreshToken, func() (any, error) {
		refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), requestTimeout)
		defer cancel()
		bundle, errRequest := s.requestTokens(refreshCtx, url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {refreshToken},
		})
		if errRequest != nil {
			return nil, errRequest
		}
		if strings.TrimSpace(bundle.RefreshToken) == "" {
			return nil, errors.New("opencode go oauth: refresh response did not rotate the refresh token")
		}
		return bundle, nil
	})
	if errRefresh != nil {
		return nil, errRefresh
	}
	bundle, okBundle := result.(*TokenBundle)
	if !okBundle || bundle == nil {
		return nil, errors.New("opencode go oauth: invalid refresh result")
	}
	return bundle, nil
}

func (s *Service) requestTokens(ctx context.Context, values url.Values) (*TokenBundle, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	endpoints, errDiscovery := s.discover(ctx)
	if errDiscovery != nil {
		return nil, errDiscovery
	}
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, errRequest := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoints.TokenEndpoint, strings.NewReader(values.Encode()))
	if errRequest != nil {
		return nil, fmt.Errorf("opencode go oauth: create token request: %w", errRequest)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	resp, errDo := s.httpClient.Do(req)
	if errDo != nil {
		return nil, fmt.Errorf("opencode go oauth: token request failed: %w", errDo)
	}
	defer func() { _ = resp.Body.Close() }()
	body, errRead := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if errRead != nil {
		return nil, fmt.Errorf("opencode go oauth: read token response: %w", errRead)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, tokenResponseError(resp.StatusCode, body)
	}
	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if errDecode := json.Unmarshal(body, &tokenResponse); errDecode != nil {
		return nil, fmt.Errorf("opencode go oauth: decode token response: %w", errDecode)
	}
	identity, errVerify := s.VerifyAccessToken(ctx, tokenResponse.AccessToken)
	if errVerify != nil {
		return nil, errVerify
	}
	expiresAt := identity.ExpiresAt
	if tokenResponse.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)
	}
	return &TokenBundle{
		AccessToken:  strings.TrimSpace(tokenResponse.AccessToken),
		RefreshToken: strings.TrimSpace(tokenResponse.RefreshToken),
		TokenType:    strings.TrimSpace(tokenResponse.TokenType),
		ExpiresAt:    expiresAt,
		AccountID:    identity.AccountID,
		Email:        identity.Email,
		NewAccount:   identity.NewAccount,
	}, nil
}

func (s *Service) discover(ctx context.Context) (*Endpoints, error) {
	s.mu.Lock()
	if s.endpoints != nil {
		copyEndpoints := *s.endpoints
		s.mu.Unlock()
		return &copyEndpoints, nil
	}
	s.mu.Unlock()

	var endpoints Endpoints
	if errFetch := s.getJSON(ctx, s.issuer+discoveryPath, &endpoints); errFetch != nil {
		return nil, fmt.Errorf("opencode go oauth: discovery failed: %w", errFetch)
	}
	if strings.TrimRight(endpoints.Issuer, "/") != s.issuer {
		return nil, errors.New("opencode go oauth: discovery issuer mismatch")
	}
	if strings.TrimSpace(endpoints.AuthorizationEndpoint) == "" || strings.TrimSpace(endpoints.TokenEndpoint) == "" || strings.TrimSpace(endpoints.JWKSURI) == "" {
		return nil, errors.New("opencode go oauth: discovery response is incomplete")
	}
	s.mu.Lock()
	s.endpoints = &endpoints
	s.mu.Unlock()
	return &endpoints, nil
}

// VerifyAccessToken verifies ES256 signature and account claims against issuer JWKS.
func (s *Service) VerifyAccessToken(ctx context.Context, rawToken string) (*Identity, error) {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return nil, errors.New("opencode go oauth: access token is empty")
	}
	parse := func(forceRefresh bool) (*Identity, error) {
		if forceRefresh {
			s.mu.Lock()
			s.keys = nil
			s.mu.Unlock()
		}
		keys, errKeys := s.jwks(ctx)
		if errKeys != nil {
			return nil, errKeys
		}
		claims := &accessClaims{}
		parser := jwt.NewParser(
			jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
			jwt.WithIssuer(s.issuer),
			jwt.WithAudience(s.clientID),
			jwt.WithExpirationRequired(),
			jwt.WithLeeway(30*time.Second),
		)
		token, errParse := parser.ParseWithClaims(rawToken, claims, func(token *jwt.Token) (any, error) {
			kid, _ := token.Header["kid"].(string)
			key := keys[strings.TrimSpace(kid)]
			if key == nil {
				return nil, errors.New("opencode go oauth: signing key not found")
			}
			return key, nil
		})
		if errParse != nil || token == nil || !token.Valid {
			return nil, fmt.Errorf("opencode go oauth: access token verification failed: %w", errParse)
		}
		accountID := strings.TrimSpace(claims.Properties.AccountID)
		if accountID == "" {
			accountID = strings.TrimSpace(claims.Subject)
		}
		email := strings.TrimSpace(claims.Properties.Email)
		if accountID == "" || email == "" || !strings.EqualFold(strings.TrimSpace(claims.Type), "account") {
			return nil, errors.New("opencode go oauth: access token account claims are incomplete")
		}
		expiresAt := time.Time{}
		if claims.ExpiresAt != nil {
			expiresAt = claims.ExpiresAt.Time
		}
		return &Identity{AccountID: accountID, Email: email, NewAccount: claims.Properties.NewAccount, ExpiresAt: expiresAt}, nil
	}
	identity, errVerify := parse(false)
	if errVerify == nil {
		return identity, nil
	}
	return parse(true)
}

type accessClaims struct {
	jwt.RegisteredClaims
	Type       string `json:"type"`
	Properties struct {
		AccountID  string `json:"accountID"`
		Email      string `json:"email"`
		NewAccount bool   `json:"newAccount"`
	} `json:"properties"`
}

type jwksDocument struct {
	Keys []struct {
		KTY string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
	} `json:"keys"`
}

func (s *Service) jwks(ctx context.Context) (map[string]*ecdsa.PublicKey, error) {
	s.mu.Lock()
	if len(s.keys) > 0 {
		out := s.keys
		s.mu.Unlock()
		return out, nil
	}
	s.mu.Unlock()
	endpoints, errDiscovery := s.discover(ctx)
	if errDiscovery != nil {
		return nil, errDiscovery
	}
	var document jwksDocument
	if errFetch := s.getJSON(ctx, endpoints.JWKSURI, &document); errFetch != nil {
		return nil, fmt.Errorf("opencode go oauth: JWKS fetch failed: %w", errFetch)
	}
	keys := make(map[string]*ecdsa.PublicKey)
	for _, item := range document.Keys {
		if item.KTY != "EC" || item.Crv != "P-256" || item.Alg != "ES256" || item.Use != "sig" || strings.TrimSpace(item.Kid) == "" {
			continue
		}
		x, errX := decodeCoordinate(item.X)
		y, errY := decodeCoordinate(item.Y)
		if errX != nil || errY != nil || !elliptic.P256().IsOnCurve(x, y) {
			continue
		}
		keys[item.Kid] = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	}
	if len(keys) == 0 {
		return nil, errors.New("opencode go oauth: JWKS contains no accepted ES256 key")
	}
	s.mu.Lock()
	s.keys = keys
	s.mu.Unlock()
	return keys, nil
}

func decodeCoordinate(value string) (*big.Int, error) {
	raw, errDecode := base64.RawURLEncoding.DecodeString(strings.TrimSpace(value))
	if errDecode != nil {
		return nil, errDecode
	}
	if len(raw) == 0 {
		return nil, errors.New("empty coordinate")
	}
	return new(big.Int).SetBytes(raw), nil
}

func (s *Service) getJSON(ctx context.Context, endpoint string, out any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	requestCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, errRequest := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if errRequest != nil {
		return errRequest
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	resp, errDo := s.httpClient.Do(req)
	if errDo != nil {
		return errDo
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	return decoder.Decode(out)
}

func tokenResponseError(status int, body []byte) error {
	var payload struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &payload)
	code := strings.TrimSpace(payload.Error)
	if code == "" {
		code = http.StatusText(status)
	}
	description := strings.TrimSpace(payload.ErrorDescription)
	if description != "" {
		return fmt.Errorf("opencode go oauth: token endpoint returned %d %s: %s", status, code, description)
	}
	return fmt.Errorf("opencode go oauth: token endpoint returned %d %s", status, code)
}

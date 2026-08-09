package opencodego

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGeneratePKCECodes(t *testing.T) {
	pkce, err := GeneratePKCECodes()
	if err != nil {
		t.Fatalf("GeneratePKCECodes() error = %v", err)
	}
	if len(pkce.CodeVerifier) != 128 {
		t.Fatalf("verifier length = %d, want 128", len(pkce.CodeVerifier))
	}
	if pkce.CodeChallenge == "" || strings.ContainsAny(pkce.CodeChallenge, "+/=") {
		t.Fatalf("challenge = %q, want base64url without padding", pkce.CodeChallenge)
	}
}

func TestOAuthExchangeVerifyAndRefreshRotation(t *testing.T) {
	privateKey, errKey := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if errKey != nil {
		t.Fatalf("generate key: %v", errKey)
	}
	var refreshCalls atomic.Int32
	server := newFakeIssuer(t, privateKey, &refreshCalls)
	defer server.Close()

	service := NewServiceWithClient(server.Client(), server.URL, ClientID)
	pkce, errPKCE := GeneratePKCECodes()
	if errPKCE != nil {
		t.Fatalf("generate PKCE: %v", errPKCE)
	}
	authURL, errAuthURL := service.GenerateAuthURL(context.Background(), "state-1", DefaultRedirectURI, pkce)
	if errAuthURL != nil {
		t.Fatalf("GenerateAuthURL() error = %v", errAuthURL)
	}
	parsed, _ := url.Parse(authURL)
	if parsed.Query().Get("client_id") != ClientID || parsed.Query().Get("provider") != "google" || parsed.Query().Get("code_challenge") != pkce.CodeChallenge {
		t.Fatalf("unexpected authorization URL: %s", authURL)
	}

	bundle, errExchange := service.ExchangeCodeForTokens(context.Background(), "one-time-code", DefaultRedirectURI, pkce)
	if errExchange != nil {
		t.Fatalf("ExchangeCodeForTokens() error = %v", errExchange)
	}
	if bundle.AccountID != "acc_test" || bundle.Email != "person@example.com" || bundle.RefreshToken != "refresh-1" {
		t.Fatalf("unexpected bundle: %#v", bundle)
	}
	refreshed, errRefresh := service.RefreshTokens(context.Background(), bundle.RefreshToken)
	if errRefresh != nil {
		t.Fatalf("RefreshTokens() error = %v", errRefresh)
	}
	if refreshed.RefreshToken != "refresh-2" || refreshed.AccessToken == bundle.AccessToken || refreshCalls.Load() != 1 {
		t.Fatalf("refresh did not rotate both tokens: %#v calls=%d", refreshed, refreshCalls.Load())
	}
}

func TestVerifyAccessTokenRejectsWrongAudience(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	server := newFakeIssuer(t, privateKey, nil)
	defer server.Close()
	service := NewServiceWithClient(server.Client(), server.URL, ClientID)
	raw := signAccessToken(t, privateKey, server.URL, "wrong-client", "kid-1")
	if _, errVerify := service.VerifyAccessToken(context.Background(), raw); errVerify == nil {
		t.Fatal("VerifyAccessToken() error = nil, want audience rejection")
	}
}

func TestCredentialFileNameIsPathSafe(t *testing.T) {
	name := CredentialFileName("../../hostile-account", "a/../../b@example.com")
	if strings.Contains(name, "/") || strings.Contains(name, "..") || !strings.HasPrefix(name, "opencode-go-") {
		t.Fatalf("CredentialFileName() = %q, want path-safe name", name)
	}
}

func newFakeIssuer(t *testing.T, privateKey *ecdsa.PrivateKey, refreshCalls *atomic.Int32) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	mux := http.NewServeMux()
	server = httptest.NewServer(mux)
	mux.HandleFunc(discoveryPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != UserAgent {
			t.Errorf("User-Agent = %q, want %q", r.Header.Get("User-Agent"), UserAgent)
		}
		_ = json.NewEncoder(w).Encode(Endpoints{Issuer: server.URL, AuthorizationEndpoint: server.URL + "/authorize", TokenEndpoint: server.URL + "/token", JWKSURI: server.URL + "/jwks", ResponseTypes: []string{"code"}})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		x := privateKey.PublicKey.X.FillBytes(make([]byte, 32))
		y := privateKey.PublicKey.Y.FillBytes(make([]byte, 32))
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{"kty": "EC", "kid": "kid-1", "use": "sig", "alg": "ES256", "crv": "P-256", "x": base64.RawURLEncoding.EncodeToString(x), "y": base64.RawURLEncoding.EncodeToString(y)}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != UserAgent {
			t.Errorf("token User-Agent = %q, want %q", r.Header.Get("User-Agent"), UserAgent)
		}
		if errParse := r.ParseForm(); errParse != nil {
			t.Fatalf("parse form: %v", errParse)
		}
		refresh := r.Form.Get("grant_type") == "refresh_token"
		if refresh && refreshCalls != nil {
			refreshCalls.Add(1)
		}
		access := signAccessToken(t, privateKey, server.URL, ClientID, "kid-1")
		refreshToken := "refresh-1"
		if refresh {
			refreshToken = "refresh-2"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": access, "refresh_token": refreshToken, "expires_in": 3600, "token_type": "Bearer"})
	})
	return server
}

func signAccessToken(t *testing.T, privateKey *ecdsa.PrivateKey, issuer, audience, kid string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":        issuer,
		"aud":        audience,
		"exp":        time.Now().Add(time.Hour).Unix(),
		"sub":        "acc_test",
		"type":       "account",
		"properties": map[string]any{"accountID": "acc_test", "email": "person@example.com", "newAccount": false},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = kid
	raw, errSign := token.SignedString(privateKey)
	if errSign != nil {
		t.Fatalf("sign token: %v", errSign)
	}
	return raw
}

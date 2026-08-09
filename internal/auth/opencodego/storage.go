package opencodego

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// TokenStorage persists OAuth identity while keeping an imported Go API key separate.
type TokenStorage struct {
	Type         string         `json:"type"`
	AuthKind     string         `json:"auth_kind"`
	AccessToken  string         `json:"access_token"`
	RefreshToken string         `json:"refresh_token"`
	TokenType    string         `json:"token_type"`
	ExpiresAt    string         `json:"expires_at"`
	LastRefresh  string         `json:"last_refresh"`
	AccountID    string         `json:"account_id"`
	Email        string         `json:"email"`
	NewAccount   bool           `json:"new_account"`
	WorkspaceID  string         `json:"workspace_id,omitempty"`
	APIKey       string         `json:"api_key,omitempty"`
	BaseURL      string         `json:"base_url,omitempty"`
	Priority     int            `json:"priority,omitempty"`
	Weight       int            `json:"weight,omitempty"`
	Metadata     map[string]any `json:"-"`
}

func (s *TokenStorage) SetMetadata(metadata map[string]any) { s.Metadata = metadata }

// SaveTokenToFile writes the flattened auth record atomically with mode 0600.
func (s *TokenStorage) SaveTokenToFile(path string) error {
	if s == nil {
		return errorsNew("opencode go auth storage is nil")
	}
	if errMkdir := os.MkdirAll(filepath.Dir(path), 0o700); errMkdir != nil {
		return fmt.Errorf("opencode go auth: create credential directory: %w", errMkdir)
	}
	data := make(map[string]any, len(s.Metadata)+16)
	for key, value := range s.Metadata {
		data[key] = value
	}
	data["type"] = Provider
	data["auth_kind"] = "oauth"
	data["access_token"] = s.AccessToken
	data["refresh_token"] = s.RefreshToken
	data["token_type"] = s.TokenType
	data["expires_at"] = s.ExpiresAt
	data["last_refresh"] = s.LastRefresh
	data["account_id"] = s.AccountID
	data["email"] = s.Email
	data["new_account"] = s.NewAccount
	if strings.TrimSpace(s.WorkspaceID) != "" {
		data["workspace_id"] = strings.TrimSpace(s.WorkspaceID)
	}
	if strings.TrimSpace(s.APIKey) != "" {
		data["api_key"] = strings.TrimSpace(s.APIKey)
	}
	if strings.TrimSpace(s.BaseURL) != "" {
		data["base_url"] = strings.TrimSpace(s.BaseURL)
	}
	if s.Priority != 0 {
		data["priority"] = s.Priority
	}
	if s.Weight != 0 {
		data["weight"] = s.Weight
	}
	raw, errMarshal := json.Marshal(data)
	if errMarshal != nil {
		return fmt.Errorf("opencode go auth: marshal credential: %w", errMarshal)
	}
	return writeAtomic(path, raw, 0o600)
}

// CredentialFileName creates a stable, path-safe filename from verified identity claims.
func CredentialFileName(accountID, email string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(accountID)))
	hash := hex.EncodeToString(digest[:])[:8]
	return fmt.Sprintf("opencode-go-%s-%s.json", hash, sanitizeFilenamePart(email))
}

func sanitizeFilenamePart(value string) string {
	value = strings.TrimSpace(value)
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '@' && r != '.' && r != '-' && r != '_'
	})
	clean := strings.Join(parts, "-")
	for strings.Contains(clean, "..") {
		clean = strings.ReplaceAll(clean, "..", "-")
	}
	clean = strings.Trim(clean, ".-_")
	if clean == "" {
		return "account"
	}
	return clean
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	temp, errTemp := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if errTemp != nil {
		return fmt.Errorf("opencode go auth: create temporary credential: %w", errTemp)
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if errChmod := temp.Chmod(mode); errChmod != nil {
		_ = temp.Close()
		return fmt.Errorf("opencode go auth: chmod temporary credential: %w", errChmod)
	}
	if _, errWrite := temp.Write(data); errWrite != nil {
		_ = temp.Close()
		return fmt.Errorf("opencode go auth: write temporary credential: %w", errWrite)
	}
	if errSync := temp.Sync(); errSync != nil {
		_ = temp.Close()
		return fmt.Errorf("opencode go auth: sync temporary credential: %w", errSync)
	}
	if errClose := temp.Close(); errClose != nil {
		return fmt.Errorf("opencode go auth: close temporary credential: %w", errClose)
	}
	if errRename := os.Rename(tempPath, path); errRename != nil {
		return fmt.Errorf("opencode go auth: replace credential: %w", errRename)
	}
	directory, errOpenDir := os.Open(dir)
	if errOpenDir == nil {
		defer func() { _ = directory.Close() }()
		if errSyncDir := directory.Sync(); errSyncDir != nil {
			return fmt.Errorf("opencode go auth: sync credential directory: %w", errSyncDir)
		}
	}
	return nil
}

func errorsNew(message string) error { return fmt.Errorf("%s", message) }

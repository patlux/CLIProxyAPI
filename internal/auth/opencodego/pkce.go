package opencodego

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// PKCECodes contains the verifier and S256 challenge for one login attempt.
type PKCECodes struct {
	CodeVerifier  string
	CodeChallenge string
}

// GeneratePKCECodes creates an RFC 7636 verifier at the maximum supported length.
func GeneratePKCECodes() (*PKCECodes, error) {
	random := make([]byte, 96)
	if _, errRead := rand.Read(random); errRead != nil {
		return nil, fmt.Errorf("opencode go pkce: generate verifier: %w", errRead)
	}
	verifier := base64.RawURLEncoding.EncodeToString(random)
	digest := sha256.Sum256([]byte(verifier))
	return &PKCECodes{
		CodeVerifier:  verifier,
		CodeChallenge: base64.RawURLEncoding.EncodeToString(digest[:]),
	}, nil
}

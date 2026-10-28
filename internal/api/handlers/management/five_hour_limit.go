package management

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

const fiveHourLimitField = "five_hour_limit_percent"

// fiveHourLimit exposes only a valid, non-secret account policy. The limits
// sidecar enforces this policy using its existing quota-weight reconciler.
func fiveHourLimit(metadata map[string]any) (int, bool) {
	raw, err := json.Marshal(metadata[fiveHourLimitField])
	if err != nil || bytes.Equal(raw, []byte("null")) {
		return 0, false
	}
	var value int
	if err := json.Unmarshal(raw, &value); err != nil || value < 1 || value > 100 {
		return 0, false
	}
	return value, true
}

// PatchFiveHourLimit is a v8-only policy endpoint. An optional weight lets the
// sidecar atomically apply a policy and its current routing decision without
// modifying manual priority, disabled state, or provider cooldowns.
func (h *Handler) PatchFiveHourLimit(c *gin.Context) {
	var request struct {
		Name   string          `json:"name"`
		Limit  json.RawMessage `json:"five_hour_limit_percent"`
		Weight *int            `json:"weight"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil || strings.TrimSpace(request.Name) == "" || request.Limit == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name and five_hour_limit_percent are required"})
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"error": "expected a single JSON object"})
		return
	}
	if !bytes.Equal(bytes.TrimSpace(request.Limit), []byte("null")) {
		var value int
		if err := json.Unmarshal(request.Limit, &value); err != nil || value < 1 || value > 100 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "five_hour_limit_percent must be an integer between 1 and 100, or null"})
			return
		}
	}
	if request.Weight != nil && (*request.Weight < 0 || *request.Weight > 20) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "weight must be between 0 and 20"})
		return
	}
	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	var target *coreauth.Auth
	for _, auth := range h.authManager.List() {
		if auth.ID == request.Name || auth.FileName == request.Name {
			target = auth
			break
		}
	}
	if target == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "auth file not found"})
		return
	}
	if target.AuthSourceKind() == coreauth.AuthSourceConfig || coreauth.IsPluginVirtualAuth(target) || isRuntimeListedCredential(target) ||
		(target.Provider != "claude" && target.Provider != "codex" && target.Provider != "kimi") {
		c.JSON(http.StatusConflict, gin.H{"error": "five-hour limits require a supported auth-file account"})
		return
	}
	// Reuse the credential transaction and persistence path, not a second
	// policy store. The deprecated v0 API remains unchanged.
	fields := map[string]any{"name": request.Name, fiveHourLimitField: request.Limit}
	if request.Weight != nil {
		fields[coreauth.AttributeWeight] = *request.Weight
	}
	body, err := json.Marshal(fields)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not encode policy"})
		return
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	h.PatchAuthFileFields(c)
}

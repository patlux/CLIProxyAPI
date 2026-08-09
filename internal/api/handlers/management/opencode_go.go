package management

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/auth/opencodego"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type openCodeGoAssociateRequest struct {
	AuthIndex   string `json:"auth_index"`
	APIKey      string `json:"api_key"`
	WorkspaceID string `json:"workspace_id"`
}

// AssociateOpenCodeGoKey links an existing Go API key to a verified OAuth identity.
// OAuth tokens remain identity/session credentials and are never used for Go routing.
func (h *Handler) AssociateOpenCodeGoKey(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	var request openCodeGoAssociateRequest
	if errBind := c.ShouldBindJSON(&request); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	authIndex := strings.TrimSpace(request.AuthIndex)
	apiKey := strings.TrimSpace(request.APIKey)
	if authIndex == "" || apiKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "auth_index and api_key are required"})
		return
	}
	auth := h.authByIndex(authIndex)
	if auth == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "credential not found"})
		return
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), opencodego.Provider) || auth.AuthKind() != coreauth.AuthKindOAuth {
		c.JSON(http.StatusConflict, gin.H{"error": "credential is not an OpenCode Go OAuth identity"})
		return
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	auth.Metadata[coreauth.AttributeAPIKey] = apiKey
	auth.Metadata["base_url"] = "https://opencode.ai/zen/go/v1"
	auth.Metadata["auth_kind"] = coreauth.AuthKindOAuth
	auth.Metadata["routing_key_required"] = false
	auth.Metadata[coreauth.AttributeWeight] = 1
	if workspaceID := strings.TrimSpace(request.WorkspaceID); workspaceID != "" {
		auth.Metadata["workspace_id"] = workspaceID
	}
	auth.Attributes[coreauth.AttributeAPIKey] = apiKey
	auth.Attributes["base_url"] = "https://opencode.ai/zen/go/v1"
	auth.Attributes[coreauth.AttributeAuthKind] = coreauth.AuthKindOAuth
	auth.Attributes[coreauth.AttributeWeight] = "1"
	auth.Disabled = false
	auth.Status = coreauth.StatusActive
	auth.StatusMessage = ""
	auth.Metadata["disabled"] = false
	auth.UpdatedAt = time.Now()
	if _, errUpdate := h.authManager.Update(c.Request.Context(), auth); errUpdate != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to associate routing credential"})
		return
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{"status": "ok", "auth_index": authIndex})
}

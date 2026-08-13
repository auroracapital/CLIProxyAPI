package management

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/clienterror"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func requireLoopback(c *gin.Context) bool {
	if c != nil && c.Request != nil && remoteAddressIsLoopback(c.Request.RemoteAddr) && !requestHasProxyOrigin(c.Request) {
		return true
	}
	if c != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "loopback access required"})
	}
	return false
}

// ReconcileMiddleware authorizes the hub-local controller without enabling
// general or remote management access. Proxy-origin requests fail before key
// comparison even when nginx connects from loopback.
func (h *Handler) ReconcileMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireLoopback(c) {
			c.Abort()
			return
		}
		provided := ""
		if authorization := strings.TrimSpace(c.GetHeader("Authorization")); authorization != "" {
			parts := strings.SplitN(authorization, " ", 2)
			if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
				provided = strings.TrimSpace(parts[1])
			}
		}
		if provided == "" {
			provided = strings.TrimSpace(c.GetHeader("X-Management-Key"))
		}
		if h == nil || h.reconcilerPassword == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(h.reconcilerPassword)) != 1 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid reconciler key"})
			return
		}
		c.Next()
	}
}

func requestHasProxyOrigin(req *http.Request) bool {
	if req == nil {
		return false
	}
	for _, header := range []string{"Forwarded", "X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"} {
		if strings.TrimSpace(req.Header.Get(header)) != "" {
			return true
		}
	}
	return false
}

func remoteAddressIsLoopback(remoteAddr string) bool {
	host, _, errSplit := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if errSplit != nil {
		host = strings.Trim(strings.TrimSpace(remoteAddr), "[]")
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// GetAuthReconcileStatus returns only categorical desired-seat lifecycle data.
func (h *Handler) GetAuthReconcileStatus(c *gin.Context) {
	if !requireLoopback(c) {
		return
	}
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	items := make([]gin.H, 0)
	for _, auth := range h.authManager.List() {
		if !isReconcileManagedAuth(auth) {
			continue
		}
		generation, durableDisabled, errGeneration := h.authManager.ReconcileCredentialGeneration(c.Request.Context(), auth.ID)
		if errGeneration != nil {
			// The controller's transaction contract is meaningful only when the
			// backing store can prove the durable generation. Returning partial
			// inventory would make an unsupported or unhealthy store look like an
			// ordinary credential problem, so fail the whole snapshot closed.
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "durable credential generations unavailable"})
			return
		}
		generation = opaqueReconcileGeneration(h.reconcilerPassword, generation)
		runtimeGeneration := opaqueReconcileGeneration(h.reconcilerPassword, strings.TrimSpace(auth.Attributes[coreauth.AttributeSourceGeneration]))
		items = append(items, gin.H{
			"auth_index":         lockedAuthIndex(auth),
			"provider":           strings.ToLower(strings.TrimSpace(auth.Provider)),
			"credential_status":  reconcileCredentialStatus(auth.Status),
			"disabled":           auth.Disabled,
			"unavailable":        auth.Unavailable,
			"state":              auth.ReconcileState,
			"reason":             auth.ReconcileReason,
			"next_attempt":       auth.ReconcileNextAttempt,
			"updated_at":         auth.UpdatedAt,
			"generation":         generation,
			"runtime_generation": runtimeGeneration,
			"durable_disabled":   durableDisabled,
		})
	}
	c.JSON(http.StatusOK, gin.H{"credentials": items})
}

// GetAuthReconcileInventory returns the minimum filesystem mapping required to
// build the root-protected desired-seat inventory. The route is separately
// protected by ReconcileMiddleware and never exposed through general telemetry.
func (h *Handler) GetAuthReconcileInventory(c *gin.Context) {
	if !requireLoopback(c) {
		return
	}
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	items := make([]gin.H, 0)
	for _, auth := range h.authManager.List() {
		if !isReconcileManagedAuth(auth) {
			continue
		}
		path := strings.TrimSpace(authAttribute(auth, coreauth.AttributePath))
		if path == "" {
			continue
		}
		items = append(items, gin.H{
			"auth_index": lockedAuthIndex(auth),
			"provider":   strings.ToLower(strings.TrimSpace(auth.Provider)),
			"name":       filepath.Base(path),
			"path":       path,
		})
	}
	c.JSON(http.StatusOK, gin.H{"files": items})
}

func (h *Handler) GetAuthReconcileModels(c *gin.Context) {
	if !requireLoopback(c) {
		return
	}
	auth := h.reconcileAuthByIndex(c.Query("auth_index"))
	if auth == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "credential not found"})
		return
	}
	models := registry.GetGlobalRegistry().GetModelsForClient(auth.ID)
	items := make([]gin.H, 0, len(models))
	for _, model := range models {
		if model != nil && strings.TrimSpace(model.ID) != "" {
			items = append(items, gin.H{"id": model.ID})
		}
	}
	c.JSON(http.StatusOK, gin.H{"models": items})
}

func reconcileCredentialStatus(status coreauth.Status) string {
	switch status {
	case coreauth.StatusActive, coreauth.StatusPending, coreauth.StatusRefreshing,
		coreauth.StatusError, coreauth.StatusDisabled:
		return string(status)
	default:
		return string(coreauth.StatusUnknown)
	}
}

func (h *Handler) SetAuthReconcileState(c *gin.Context) {
	if !requireLoopback(c) {
		return
	}
	var req struct {
		AuthIndex   string                  `json:"auth_index"`
		State       coreauth.ReconcileState `json:"state"`
		Reason      string                  `json:"reason"`
		NextAttempt time.Time               `json:"next_attempt"`
		Generation  string                  `json:"generation"`
		Disabled    *bool                   `json:"disabled"`
	}
	if errBind := c.ShouldBindJSON(&req); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	auth := h.reconcileAuthByIndex(req.AuthIndex)
	if auth == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "credential not found"})
		return
	}
	if len(strings.TrimSpace(req.Generation)) != 64 {
		c.JSON(http.StatusPreconditionRequired, gin.H{"error": "credential generation required"})
		return
	}
	rawGeneration, _, errGeneration := h.authManager.ReconcileCredentialGeneration(c.Request.Context(), auth.ID)
	if errGeneration != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "reconcile state update failed"})
		return
	}
	if opaqueReconcileGeneration(h.reconcilerPassword, rawGeneration) != strings.ToLower(strings.TrimSpace(req.Generation)) {
		c.JSON(http.StatusPreconditionFailed, gin.H{"error": "reconcile state update failed"})
		return
	}
	updated, generation, errSet := h.authManager.SetReconcileStateCAS(c.Request.Context(), auth.ID, rawGeneration, req.State, req.Reason, req.NextAttempt, req.Disabled)
	if errSet != nil {
		status := http.StatusBadRequest
		if errors.Is(errSet, coreauth.ErrReconcileGenerationMismatch) {
			status = http.StatusPreconditionFailed
		} else {
			var committed *coreauth.ReconcileCommittedError
			if errors.As(errSet, &committed) {
				c.JSON(http.StatusConflict, gin.H{"error": "reconcile state committed but runtime publication failed", "outcome": "committed", "generation": opaqueReconcileGeneration(h.reconcilerPassword, committed.Generation)})
				return
			}
		}
		c.JSON(status, gin.H{"error": "reconcile state update failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"auth_index": lockedAuthIndex(updated), "state": updated.ReconcileState, "generation": opaqueReconcileGeneration(h.reconcilerPassword, generation), "disabled": updated.Disabled})
}

func (h *Handler) RefreshAuthCredential(c *gin.Context) {
	if !requireLoopback(c) {
		return
	}
	var req struct {
		AuthIndex string `json:"auth_index"`
	}
	if errBind := c.ShouldBindJSON(&req); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	auth := h.reconcileAuthByIndex(req.AuthIndex)
	if auth == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "credential not found"})
		return
	}
	if _, errRefresh := h.authManager.RefreshCredential(c.Request.Context(), auth.ID); errRefresh != nil {
		status := clienterror.HTTPStatusFromError(errRefresh)
		c.JSON(http.StatusBadGateway, gin.H{"outcome": reconcileFailureOutcome(status)})
		return
	}
	generation, disabled, errGeneration := h.authManager.ReconcileCredentialGeneration(c.Request.Context(), auth.ID)
	if errGeneration != nil {
		c.JSON(http.StatusConflict, gin.H{"outcome": "retryable"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"outcome": "succeeded", "generation": opaqueReconcileGeneration(h.reconcilerPassword, generation), "disabled": disabled})
}

func opaqueReconcileGeneration(secret, generation string) string {
	secret = strings.TrimSpace(secret)
	generation = strings.ToLower(strings.TrimSpace(generation))
	if secret == "" || len(generation) != 64 {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte("reconcile-generation\x00" + generation))
	return hex.EncodeToString(mac.Sum(nil))
}

func reconcileFailureOutcome(status int) string {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return "auth_required"
	case http.StatusTooManyRequests:
		return "cooling"
	default:
		if status >= 500 || status == 0 {
			return "retryable"
		}
		return "rejected"
	}
}

func (h *Handler) ProbeAuthCredential(c *gin.Context) {
	if !requireLoopback(c) {
		return
	}
	var req struct {
		AuthIndex string          `json:"auth_index"`
		Model     string          `json:"model"`
		Payload   json.RawMessage `json:"payload"`
	}
	if errBind := c.ShouldBindJSON(&req); errBind != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}
	auth := h.reconcileAuthByIndex(req.AuthIndex)
	if auth == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "credential not found"})
		return
	}
	payload := bytes.Clone(req.Payload)
	outcome, errProbe := h.authManager.ProbeCredential(c.Request.Context(), auth.ID, strings.ToLower(strings.TrimSpace(auth.Provider)), strings.TrimSpace(req.Model), coreexecutor.Request{Payload: payload}, coreexecutor.Options{OriginalRequest: bytes.Clone(payload), SourceFormat: sdktranslator.FormatOpenAI, ResponseFormat: sdktranslator.FormatOpenAI})
	if errProbe != nil {
		c.JSON(http.StatusBadGateway, outcome)
		return
	}
	c.JSON(http.StatusOK, outcome)
}

func isReconcileManagedAuth(auth *coreauth.Auth) bool {
	if auth == nil || auth.Metadata == nil {
		return false
	}
	if auth.AuthSourceKind() != coreauth.AuthSourceFile {
		return false
	}
	return !coreauth.IsConfigAPIKeyAuth(auth) && !coreauth.IsPluginVirtualAuth(auth)
}

func (h *Handler) reconcileAuthByIndex(authIndex string) *coreauth.Auth {
	authIndex = strings.TrimSpace(authIndex)
	if authIndex == "" || h == nil || h.authManager == nil {
		return nil
	}
	for _, auth := range h.authManager.List() {
		if !isReconcileManagedAuth(auth) {
			continue
		}
		if lockedAuthIndex(auth) == authIndex {
			return auth
		}
	}
	return nil
}

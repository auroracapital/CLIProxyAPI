package auth

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/clienterror"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// ProbeOutcome is the privacy-safe result of one exact-seat upstream probe.
// It deliberately omits auth identity and upstream response content.
type ProbeOutcome struct {
	Outcome   string `json:"outcome"`
	HTTPClass string `json:"http_class"`
}

// SetReconcileState persists a categorical desired-seat lifecycle state.
func (m *Manager) SetReconcileState(ctx context.Context, authID string, state ReconcileState, reason string, nextAttempt time.Time) (*Auth, error) {
	if m == nil {
		return nil, errors.New("auth manager is nil")
	}
	auth, ok := m.GetByID(strings.TrimSpace(authID))
	if !ok || auth == nil {
		return nil, errors.New("auth not found")
	}
	auth.ReconcileState = normalizeReconcileState(state)
	auth.ReconcileReason = sanitizeReconcileReason(reason)
	auth.ReconcileNextAttempt = nextAttempt
	auth.UpdatedAt = time.Now()
	return m.commitReconcileUpdate(ctx, auth)
}

// RefreshCredential runs the manager's serialized refresh path for one exact
// credential. Callers own lifecycle transitions around the refresh attempt.
func (m *Manager) RefreshCredential(ctx context.Context, authID string) (*Auth, error) {
	return m.refreshAuthForRequest(ctx, strings.TrimSpace(authID), "")
}

// ProbeCredential executes exactly one provider attempt on the named credential.
// It bypasses ordinary ready-state selection only for ReconcileStateProbing and
// never retries another credential or model.
func (m *Manager) ProbeCredential(ctx context.Context, authID, provider, model string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (ProbeOutcome, error) {
	if m == nil {
		return ProbeOutcome{}, errors.New("auth manager is nil")
	}
	authID = strings.TrimSpace(authID)
	provider = strings.ToLower(strings.TrimSpace(provider))
	model = strings.TrimSpace(model)
	if authID == "" || provider == "" || model == "" {
		return ProbeOutcome{}, errors.New("probe target is incomplete")
	}
	m.mu.RLock()
	auth := m.auths[authID]
	executorKey := executorKeyFromAuth(auth)
	executor := m.executors[executorKey]
	m.mu.RUnlock()
	if auth == nil || executor == nil || !strings.EqualFold(strings.TrimSpace(auth.Provider), provider) {
		return ProbeOutcome{}, errors.New("probe target is unavailable")
	}
	if !credentialSupportsProbeModel(auth.ID, model) {
		return ProbeOutcome{}, errors.New("probe model is unavailable for credential")
	}
	if normalizeReconcileState(auth.ReconcileState) != ReconcileStateProbing {
		return ProbeOutcome{}, errors.New("credential is not in probing state")
	}
	probeAuth := auth.Clone()
	probeAuth.ReconcileState = ReconcileStateReady
	probeAuth.Disabled = false
	probeAuth.Status = StatusActive
	probeAuth.Unavailable = false
	req.Model = model
	preparedAuth, errPrepare := m.prepareHomeAuthSnapshot(ctx, executor, probeAuth)
	if errPrepare != nil {
		status := clienterror.HTTPStatusFromError(errPrepare)
		return ProbeOutcome{Outcome: probeOutcome(status), HTTPClass: probeHTTPClass(status)}, errPrepare
	}
	if preparedAuth == nil || preparedAuth.ID != authID {
		return ProbeOutcome{}, errors.New("probe auth preparation changed target")
	}
	response, errExecute := executor.Execute(ctx, preparedAuth, req, opts)
	_ = response
	if errExecute != nil {
		status := clienterror.HTTPStatusFromError(errExecute)
		return ProbeOutcome{Outcome: probeOutcome(status), HTTPClass: probeHTTPClass(status)}, errExecute
	}
	return ProbeOutcome{Outcome: "succeeded", HTTPClass: "2xx"}, nil
}

func credentialSupportsProbeModel(authID, model string) bool {
	for _, info := range registry.GetGlobalRegistry().GetModelsForClient(authID) {
		if info != nil && strings.EqualFold(strings.TrimSpace(info.ID), strings.TrimSpace(model)) {
			return true
		}
	}
	return false
}

// AdmitCredential makes a probed credential selectable only after an attributed
// successful probe and clears stale runtime cooldown/error state.
func (m *Manager) AdmitCredential(ctx context.Context, authID string, outcome ProbeOutcome) (*Auth, error) {
	if outcome.Outcome != "succeeded" {
		return nil, errors.New("successful probe required for admission")
	}
	auth, ok := m.GetByID(strings.TrimSpace(authID))
	if !ok || auth == nil {
		return nil, errors.New("auth not found")
	}
	if normalizeReconcileState(auth.ReconcileState) != ReconcileStateProbing {
		return nil, errors.New("credential is not in probing state")
	}
	auth.ReconcileState = ReconcileStateReady
	auth.ReconcileReason = ""
	auth.ReconcileNextAttempt = time.Time{}
	auth.Unavailable = false
	auth.NextRetryAfter = time.Time{}
	auth.LastError = nil
	auth.StatusMessage = ""
	if auth.Status == StatusError || auth.Status == StatusRefreshing || auth.Status == StatusPending {
		auth.Status = StatusActive
	}
	auth.UpdatedAt = time.Now()
	return m.commitReconcileUpdate(ctx, auth)
}

// commitReconcileUpdate makes controller-visible lifecycle transitions durable
// before publishing them to the scheduler. The general Update path deliberately
// treats persistence as best effort for ordinary runtime bookkeeping; the
// reconciler cannot do that because reporting a transition that will disappear
// on restart could incorrectly admit an unhealthy credential.
func (m *Manager) commitReconcileUpdate(ctx context.Context, auth *Auth) (*Auth, error) {
	if m == nil || auth == nil || strings.TrimSpace(auth.ID) == "" {
		return nil, errors.New("auth update is incomplete")
	}
	SyncReconcileMetadata(auth)
	if errPersist := m.persistReconcileUpdate(ctx, auth); errPersist != nil {
		return nil, errPersist
	}
	updated, errUpdate := m.Update(WithSkipPersist(ctx), auth)
	if errUpdate != nil {
		return nil, errUpdate
	}
	if updated == nil {
		return nil, errors.New("auth disappeared during reconcile update")
	}
	return updated, nil
}

func (m *Manager) persistReconcileUpdate(ctx context.Context, auth *Auth) error {
	if shouldSkipPersist(ctx) {
		return errors.New("reconcile persistence cannot be skipped")
	}
	m.mu.RLock()
	store := m.store
	m.mu.RUnlock()
	if store == nil || auth.Metadata == nil || IsConfigAPIKeyAuth(auth) || IsPluginVirtualAuth(auth) || strings.EqualFold(strings.TrimSpace(auth.Attributes["runtime_only"]), "true") {
		return errors.New("credential has no durable reconcile store")
	}
	_, errSave := store.Save(ctx, auth)
	return errSave
}

func sanitizeReconcileReason(reason string) string {
	reason = strings.ToLower(strings.TrimSpace(reason))
	var out strings.Builder
	for _, r := range reason {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			out.WriteRune(r)
		}
		if out.Len() >= 64 {
			break
		}
	}
	return out.String()
}

func probeOutcome(status int) string {
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

func probeHTTPClass(status int) string {
	if status <= 0 {
		return "transport"
	}
	return strconv.Itoa(status/100) + "xx"
}

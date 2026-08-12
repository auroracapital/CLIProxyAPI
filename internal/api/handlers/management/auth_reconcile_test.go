package management

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type managementProbeExecutor struct {
	calls           []string
	requestPayload  []byte
	originalRequest []byte
	refreshErr      error
}

type managementReconcileStore struct{}

func (*managementReconcileStore) List(context.Context) ([]*coreauth.Auth, error) { return nil, nil }
func (*managementReconcileStore) Save(context.Context, *coreauth.Auth) (string, error) {
	return "saved", nil
}
func (*managementReconcileStore) Delete(context.Context, string) error { return nil }

func (*managementProbeExecutor) Identifier() string { return "gemini" }
func (e *managementProbeExecutor) Execute(_ context.Context, auth *coreauth.Auth, req coreexecutor.Request, opts coreexecutor.Options) (coreexecutor.Response, error) {
	e.calls = append(e.calls, auth.ID)
	e.requestPayload = append([]byte(nil), req.Payload...)
	e.originalRequest = append([]byte(nil), opts.OriginalRequest...)
	return coreexecutor.Response{Payload: []byte("ok")}, nil
}
func (*managementProbeExecutor) ExecuteStream(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	return nil, errors.New("unused")
}
func (e *managementProbeExecutor) Refresh(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	if e.refreshErr != nil {
		return nil, e.refreshErr
	}
	return auth.Clone(), nil
}
func (*managementProbeExecutor) CountTokens(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{}, errors.New("unused")
}
func (*managementProbeExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, errors.New("unused")
}

func newManagementReconcileHandler(t *testing.T) (*Handler, *managementProbeExecutor, string) {
	t.Helper()
	executor := &managementProbeExecutor{}
	manager := coreauth.NewManager(nil, nil, nil)
	manager.SetStore(&managementReconcileStore{})
	manager.RegisterExecutor(executor)
	auth := &coreauth.Auth{ID: "private-seat-id", FileName: "/private/auth/seat.json", Provider: "gemini", Status: coreauth.StatusActive, ReconcileState: coreauth.ReconcileStateProbing, Metadata: map[string]any{"type": "gemini"}}
	index := auth.EnsureIndex()
	registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: "gemini-probe"}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	return NewHandlerWithoutConfigFilePath(&config.Config{}, manager), executor, index
}

func TestAuthReconcileEndpointsRequireLoopback(t *testing.T) {
	h, _, _ := newManagementReconcileHandler(t)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodGet, "/v0/management/auth-files/reconcile-status", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	c.Request = req
	h.GetAuthReconcileStatus(c)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

func TestAuthReconcileEndpointsRejectForwardedLoopbackFromRemotePeer(t *testing.T) {
	h, _, _ := newManagementReconcileHandler(t)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodGet, "/v0/management/auth-files/reconcile-status", nil)
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Real-IP", "127.0.0.1")
	c.Request = req
	h.GetAuthReconcileStatus(c)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
}

func TestAuthReconcileEndpointsRejectLoopbackPeerWithProxyHeaders(t *testing.T) {
	for _, header := range []string{"Forwarded", "X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"} {
		t.Run(header, func(t *testing.T) {
			h, _, _ := newManagementReconcileHandler(t)
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			req := httptest.NewRequest(http.MethodGet, "/v0/management/auth-files/reconcile-status", nil)
			req.RemoteAddr = "127.0.0.1:1234"
			req.Header.Set(header, "203.0.113.10")
			c.Request = req
			h.GetAuthReconcileStatus(c)
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", recorder.Code)
			}
		})
	}
}

func TestGetAuthReconcileStatusOmitsIdentityAndPaths(t *testing.T) {
	h, _, _ := newManagementReconcileHandler(t)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodGet, "/v0/management/auth-files/reconcile-status", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	c.Request = req
	h.GetAuthReconcileStatus(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	for _, secret := range []string{"private-seat-id", "/private/auth/seat.json"} {
		if strings.Contains(recorder.Body.String(), secret) {
			t.Fatalf("response leaked %q: %s", secret, recorder.Body.String())
		}
	}
}

func TestProbeAuthCredentialUsesExactSeatAndAdmits(t *testing.T) {
	h, executor, index := newManagementReconcileHandler(t)
	body, _ := json.Marshal(map[string]any{"auth_index": index, "model": "gemini-probe", "payload": json.RawMessage(`{"messages":[{"role":"user","content":"ping"}]}`), "admit": true})
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodPost, "/v0/management/auth-files/probe", strings.NewReader(string(body)))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Content-Type", "application/json")
	c.Request = req
	h.ProbeAuthCredential(c)
	if recorder.Code != http.StatusOK || len(executor.calls) != 1 || executor.calls[0] != "private-seat-id" {
		t.Fatalf("status=%d calls=%#v body=%s", recorder.Code, executor.calls, recorder.Body.String())
	}
	if string(executor.requestPayload) != string(executor.originalRequest) || !strings.Contains(string(executor.originalRequest), `"content":"ping"`) {
		t.Fatalf("request=%s original=%s", executor.requestPayload, executor.originalRequest)
	}
	auth := h.authByIndex(index)
	if auth == nil || auth.ReconcileState != coreauth.ReconcileStateReady {
		t.Fatalf("auth = %#v", auth)
	}
}

func TestRefreshAuthCredentialReturnsCategoricalFailure(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		outcome string
	}{
		{name: "unauthorized", status: http.StatusUnauthorized, outcome: "auth_required"},
		{name: "forbidden", status: http.StatusForbidden, outcome: "auth_required"},
		{name: "rate limited", status: http.StatusTooManyRequests, outcome: "cooling"},
		{name: "unavailable", status: http.StatusServiceUnavailable, outcome: "retryable"},
		{name: "invalid", status: http.StatusBadRequest, outcome: "rejected"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h, executor, index := newManagementReconcileHandler(t)
			executor.refreshErr = &coreauth.Error{HTTPStatus: test.status, Message: "sentinel private upstream error"}
			body, _ := json.Marshal(map[string]any{"auth_index": index})
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			req := httptest.NewRequest(http.MethodPost, "/v0/management/auth-files/refresh", strings.NewReader(string(body)))
			req.RemoteAddr = "127.0.0.1:1234"
			req.Header.Set("Content-Type", "application/json")
			c.Request = req
			h.RefreshAuthCredential(c)
			if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), `"outcome":"`+test.outcome+`"`) {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), "sentinel") {
				t.Fatalf("response leaked upstream error: %s", recorder.Body.String())
			}
		})
	}
}

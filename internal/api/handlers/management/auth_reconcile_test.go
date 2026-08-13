package management

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
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

type managementUnsupportedStore struct{}

type managementCommittedStore struct {
	managementReconcileStore
	manager *coreauth.Manager
}

func (s *managementCommittedStore) SaveReconcileCAS(_ context.Context, auth *coreauth.Auth, _ string) (string, string, error) {
	if s.manager != nil {
		s.manager.Remove(context.Background(), auth.ID)
	}
	return "saved", strings.Repeat("b", 64), nil
}

func (*managementReconcileStore) List(context.Context) ([]*coreauth.Auth, error) { return nil, nil }
func (*managementReconcileStore) Save(context.Context, *coreauth.Auth) (string, error) {
	return "saved", nil
}
func (*managementReconcileStore) Delete(context.Context, string) error { return nil }
func (*managementReconcileStore) LoadReconcile(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, string, error) {
	return auth.Clone(), strings.Repeat("a", 64), nil
}

func (*managementUnsupportedStore) List(context.Context) ([]*coreauth.Auth, error) { return nil, nil }
func (*managementUnsupportedStore) Save(context.Context, *coreauth.Auth) (string, error) {
	return "saved", nil
}
func (*managementUnsupportedStore) Delete(context.Context, string) error { return nil }

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
	auth := &coreauth.Auth{ID: "private-seat-id", FileName: "seat.json", Provider: "gemini", Status: coreauth.StatusActive, ReconcileState: coreauth.ReconcileStateProbing, Attributes: map[string]string{coreauth.AttributePath: "/private/auth/seat.json", coreauth.AttributeSourceBackend: coreauth.AuthSourceFile}, Metadata: map[string]any{"type": "gemini"}}
	index := auth.EnsureIndex()
	registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: "gemini-probe"}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	h := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	h.reconcilerPassword = "reconciler-test-key"
	return h, executor, index
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

func TestReconcileMiddlewareAcceptsOnlyLoopbackReconcilerKey(t *testing.T) {
	h := &Handler{reconcilerPassword: "reconciler-test-key"}
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       int
	}{
		{name: "loopback bearer", remoteAddr: "127.0.0.1:1234", headers: map[string]string{"Authorization": "Bearer reconciler-test-key"}, want: http.StatusNoContent},
		{name: "loopback management header", remoteAddr: "[::1]:1234", headers: map[string]string{"X-Management-Key": "reconciler-test-key"}, want: http.StatusNoContent},
		{name: "wrong key", remoteAddr: "127.0.0.1:1234", headers: map[string]string{"Authorization": "Bearer wrong"}, want: http.StatusUnauthorized},
		{name: "remote peer", remoteAddr: "203.0.113.10:1234", headers: map[string]string{"Authorization": "Bearer reconciler-test-key"}, want: http.StatusForbidden},
		{name: "proxy origin", remoteAddr: "127.0.0.1:1234", headers: map[string]string{"Authorization": "Bearer reconciler-test-key", "X-Forwarded-For": "203.0.113.10"}, want: http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			router := gin.New()
			router.Use(h.ReconcileMiddleware())
			router.GET("/reconcile", func(c *gin.Context) { c.Status(http.StatusNoContent) })
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/reconcile", nil)
			req.RemoteAddr = test.remoteAddr
			for name, value := range test.headers {
				req.Header.Set(name, value)
			}
			router.ServeHTTP(recorder, req)
			if recorder.Code != test.want {
				t.Fatalf("status = %d, want %d; body=%s", recorder.Code, test.want, recorder.Body.String())
			}
		})
	}
}

func TestReconcilerKeyDoesNotAuthorizeGeneralManagement(t *testing.T) {
	h := &Handler{cfg: &config.Config{}, reconcilerPassword: "reconciler-test-key", failedAttempts: make(map[string]*attemptInfo)}
	allowed, status, _ := h.AuthenticateManagementKey("127.0.0.1", true, "reconciler-test-key")
	if allowed || status != http.StatusForbidden {
		t.Fatalf("allowed=%t status=%d, want false/403", allowed, status)
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
	var payload struct {
		Credentials []struct {
			CredentialStatus string `json:"credential_status"`
			Disabled         bool   `json:"disabled"`
			Unavailable      bool   `json:"unavailable"`
		} `json:"credentials"`
	}
	if errDecode := json.Unmarshal(recorder.Body.Bytes(), &payload); errDecode != nil {
		t.Fatal(errDecode)
	}
	if len(payload.Credentials) != 1 || payload.Credentials[0].CredentialStatus != "active" || payload.Credentials[0].Disabled || payload.Credentials[0].Unavailable {
		t.Fatalf("categorical credential status = %#v", payload.Credentials)
	}
}

func TestReconcileScopedInventoryAndModelsAreExactSeatOnly(t *testing.T) {
	h, _, index := newManagementReconcileHandler(t)

	inventoryRecorder := httptest.NewRecorder()
	inventoryContext, _ := gin.CreateTestContext(inventoryRecorder)
	inventoryRequest := httptest.NewRequest(http.MethodGet, "/v0/management/auth-files/reconcile-inventory", nil)
	inventoryRequest.RemoteAddr = "127.0.0.1:1234"
	inventoryContext.Request = inventoryRequest
	h.GetAuthReconcileInventory(inventoryContext)
	if inventoryRecorder.Code != http.StatusOK || !strings.Contains(inventoryRecorder.Body.String(), index) || !strings.Contains(inventoryRecorder.Body.String(), "seat.json") {
		t.Fatalf("inventory status=%d body=%s", inventoryRecorder.Code, inventoryRecorder.Body.String())
	}
	if strings.Contains(inventoryRecorder.Body.String(), "private-seat-id") {
		t.Fatalf("inventory leaked internal auth id: %s", inventoryRecorder.Body.String())
	}

	modelsRecorder := httptest.NewRecorder()
	modelsContext, _ := gin.CreateTestContext(modelsRecorder)
	modelsRequest := httptest.NewRequest(http.MethodGet, "/v0/management/auth-files/reconcile-models?auth_index="+index, nil)
	modelsRequest.RemoteAddr = "127.0.0.1:1234"
	modelsContext.Request = modelsRequest
	h.GetAuthReconcileModels(modelsContext)
	if modelsRecorder.Code != http.StatusOK || !strings.Contains(modelsRecorder.Body.String(), "gemini-probe") {
		t.Fatalf("models status=%d body=%s", modelsRecorder.Code, modelsRecorder.Body.String())
	}

	missingRecorder := httptest.NewRecorder()
	missingContext, _ := gin.CreateTestContext(missingRecorder)
	missingRequest := httptest.NewRequest(http.MethodGet, "/v0/management/auth-files/reconcile-models?auth_index=missing", nil)
	missingRequest.RemoteAddr = "127.0.0.1:1234"
	missingContext.Request = missingRequest
	h.GetAuthReconcileModels(missingContext)
	if missingRecorder.Code != http.StatusNotFound {
		t.Fatalf("missing models status=%d body=%s", missingRecorder.Code, missingRecorder.Body.String())
	}
}

func TestReconcileCredentialStatusIsClosed(t *testing.T) {
	if got := reconcileCredentialStatus(coreauth.Status("private-status")); got != "unknown" {
		t.Fatalf("status = %q, want unknown", got)
	}
}

func TestSetAuthReconcileStateRequiresAndAdvancesDurableGeneration(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/seat.json"
	if errWrite := os.WriteFile(path, []byte(`{"type":"claude","refresh_token":"restored","disabled":true,"reconcile_state":"probing"}`), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	store := sdkauth.NewFileTokenStore()
	store.SetBaseDir(dir)
	manager := coreauth.NewManager(nil, nil, nil)
	manager.SetStore(store)
	auth := &coreauth.Auth{ID: "seat.json", FileName: "seat.json", Provider: "claude", Status: coreauth.StatusActive, ReconcileState: coreauth.ReconcileStateProbing, Attributes: map[string]string{coreauth.AttributePath: path, coreauth.AttributeSourceBackend: coreauth.AuthSourceFile}, Metadata: map[string]any{"type": "claude", "refresh_token": "stale", "disabled": false}}
	index := auth.EnsureIndex()
	if _, errRegister := manager.Register(coreauth.WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	generation, durableDisabled, errGeneration := manager.ReconcileCredentialGeneration(context.Background(), auth.ID)
	if errGeneration != nil || !durableDisabled {
		t.Fatalf("generation=%q disabled=%t err=%v", generation, durableDisabled, errGeneration)
	}
	auth.Attributes[coreauth.AttributeSourceGeneration] = generation
	if _, errUpdate := manager.Update(coreauth.WithSkipPersist(context.Background()), auth); errUpdate != nil {
		t.Fatal(errUpdate)
	}
	h := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	h.reconcilerPassword = "reconciler-test-key"

	request := func(payload map[string]any) *httptest.ResponseRecorder {
		body, errJSON := json.Marshal(payload)
		if errJSON != nil {
			t.Fatal(errJSON)
		}
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		req := httptest.NewRequest(http.MethodPost, "/v0/management/auth-files/reconcile-state", strings.NewReader(string(body)))
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("Content-Type", "application/json")
		c.Request = req
		h.SetAuthReconcileState(c)
		return recorder
	}
	missing := request(map[string]any{"auth_index": index, "state": "cooling"})
	if missing.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing generation status=%d body=%s", missing.Code, missing.Body.String())
	}
	opaqueGeneration := opaqueReconcileGeneration(h.reconcilerPassword, generation)
	accepted := request(map[string]any{"auth_index": index, "state": "cooling", "reason": "probe_rejected", "generation": opaqueGeneration, "disabled": true})
	if accepted.Code != http.StatusOK || !strings.Contains(accepted.Body.String(), `"disabled":true`) || strings.Contains(accepted.Body.String(), generation) {
		t.Fatalf("accepted status=%d body=%s", accepted.Code, accepted.Body.String())
	}
	stale := request(map[string]any{"auth_index": index, "state": "ready", "generation": opaqueGeneration})
	if stale.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale generation status=%d body=%s", stale.Code, stale.Body.String())
	}
	var persisted map[string]any
	if errJSON := json.Unmarshal(mustReadManagementFile(t, path), &persisted); errJSON != nil {
		t.Fatal(errJSON)
	}
	if persisted["refresh_token"] != "restored" || persisted["disabled"] != true || persisted["reconcile_state"] != "cooling" {
		t.Fatalf("durable projection changed unexpectedly")
	}
}

func TestSetAuthReconcileStateReturnsCategoricalCommittedGeneration(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	store := &managementCommittedStore{manager: manager}
	manager.SetStore(store)
	auth := &coreauth.Auth{
		ID:             "seat.json",
		FileName:       "seat.json",
		Provider:       "claude",
		Status:         coreauth.StatusActive,
		ReconcileState: coreauth.ReconcileStateProbing,
		Attributes: map[string]string{
			coreauth.AttributePath:          "/private/auth/seat.json",
			coreauth.AttributeSourceBackend: coreauth.AuthSourceFile,
		},
		Metadata: map[string]any{"type": "claude", "disabled": false},
	}
	index := auth.EnsureIndex()
	if _, errRegister := manager.Register(coreauth.WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	h := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	h.reconcilerPassword = "reconciler-test-key"
	body, _ := json.Marshal(map[string]any{
		"auth_index": index,
		"state":      "cooling",
		"generation": opaqueReconcileGeneration(h.reconcilerPassword, strings.Repeat("a", 64)),
	})
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodPost, "/v0/management/auth-files/reconcile-state", strings.NewReader(string(body)))
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Content-Type", "application/json")
	c.Request = req
	h.SetAuthReconcileState(c)
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), `"outcome":"committed"`) {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), opaqueReconcileGeneration(h.reconcilerPassword, strings.Repeat("b", 64))) {
		t.Fatalf("committed opaque generation missing: %s", recorder.Body.String())
	}
}

func mustReadManagementFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	return raw
}

func TestGetAuthReconcileStatusIncludesOnlyFileBackedDesiredSeats(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	manager.SetStore(&managementReconcileStore{})
	want := make(map[string]string, 19)
	for i := 0; i < 19; i++ {
		provider := "claude"
		if i%2 == 1 {
			provider = "codex"
		}
		auth := &coreauth.Auth{
			ID:             "file-seat-" + string(rune('a'+i)),
			FileName:       "/opt/crsproxy/auths/seat-" + string(rune('a'+i)) + ".json",
			Provider:       provider,
			Status:         coreauth.StatusActive,
			ReconcileState: coreauth.ReconcileStateReady,
			Metadata:       map[string]any{"type": provider},
		}
		index := auth.EnsureIndex()
		want[index] = provider
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatal(errRegister)
		}
	}
	configAuth := &coreauth.Auth{
		ID:             "config-kimi-client",
		Provider:       "openai-compatible-kimi",
		Status:         coreauth.StatusActive,
		ReconcileState: coreauth.ReconcileStateReady,
		Attributes: map[string]string{
			coreauth.AttributeAPIKey: "not-a-real-key",
			coreauth.AttributeSource: "config:kimi[test]",
		},
		Metadata: map[string]any{},
	}
	configIndex := configAuth.EnsureIndex()
	if _, errRegister := manager.Register(context.Background(), configAuth); errRegister != nil {
		t.Fatal(errRegister)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodGet, "/v0/management/auth-files/reconcile-status", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	c.Request = req
	h.GetAuthReconcileStatus(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Credentials []struct {
			AuthIndex string `json:"auth_index"`
			Provider  string `json:"provider"`
		} `json:"credentials"`
	}
	if errDecode := json.Unmarshal(recorder.Body.Bytes(), &payload); errDecode != nil {
		t.Fatal(errDecode)
	}
	if len(payload.Credentials) != len(want) {
		t.Fatalf("credential count = %d, want %d; body=%s", len(payload.Credentials), len(want), recorder.Body.String())
	}
	for _, credential := range payload.Credentials {
		provider, ok := want[credential.AuthIndex]
		if !ok {
			t.Fatalf("unexpected auth_index %q", credential.AuthIndex)
		}
		if credential.Provider != provider {
			t.Fatalf("provider for %q = %q, want %q", credential.AuthIndex, credential.Provider, provider)
		}
		delete(want, credential.AuthIndex)
	}
	if len(want) != 0 {
		t.Fatalf("missing file-backed credentials: %v", want)
	}
	if strings.Contains(recorder.Body.String(), configIndex) {
		t.Fatalf("config-backed auth_index leaked into desired inventory: %s", recorder.Body.String())
	}
}

func TestGetAuthReconcileStatusFailsClosedWithoutGenerationStore(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	manager.SetStore(&managementUnsupportedStore{})
	auth := &coreauth.Auth{
		ID:       "file-seat",
		FileName: "seat.json",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			coreauth.AttributePath:          "/opt/crsproxy/auths/seat.json",
			coreauth.AttributeSourceBackend: coreauth.AuthSourceFile,
		},
		Metadata: map[string]any{"type": "claude"},
	}
	if _, errRegister := manager.Register(coreauth.WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	h := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)
	h.reconcilerPassword = "reconciler-test-key"
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	req := httptest.NewRequest(http.MethodGet, "/v0/management/auth-files/reconcile-status", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	c.Request = req
	h.GetAuthReconcileStatus(c)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), auth.ID) || strings.Contains(recorder.Body.String(), auth.FileName) {
		t.Fatalf("failed-closed response exposed credential identity: %s", recorder.Body.String())
	}
}

func TestAuthReconcileMutationsRejectNonPersistableCredentials(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	manager.SetStore(&managementReconcileStore{})
	configAuth := &coreauth.Auth{
		ID:             "config-kimi-client",
		Provider:       "openai-compatible-kimi",
		Status:         coreauth.StatusActive,
		ReconcileState: coreauth.ReconcileStateReady,
		Attributes: map[string]string{
			coreauth.AttributeAPIKey: "not-a-real-key",
			coreauth.AttributeSource: "config:kimi[test]",
		},
		Metadata: map[string]any{},
	}
	configIndex := configAuth.EnsureIndex()
	if _, errRegister := manager.Register(context.Background(), configAuth); errRegister != nil {
		t.Fatal(errRegister)
	}
	h := NewHandlerWithoutConfigFilePath(&config.Config{}, manager)

	tests := []struct {
		name    string
		path    string
		body    map[string]any
		handler func(*gin.Context)
	}{
		{name: "state", path: "/v0/management/auth-files/reconcile-state", body: map[string]any{"auth_index": configIndex, "state": "cooling"}, handler: h.SetAuthReconcileState},
		{name: "refresh", path: "/v0/management/auth-files/refresh", body: map[string]any{"auth_index": configIndex}, handler: h.RefreshAuthCredential},
		{name: "probe", path: "/v0/management/auth-files/probe", body: map[string]any{"auth_index": configIndex, "model": "kimi", "payload": map[string]any{"messages": []any{}}, "admit": true}, handler: h.ProbeAuthCredential},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, errMarshal := json.Marshal(test.body)
			if errMarshal != nil {
				t.Fatal(errMarshal)
			}
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			req := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader(string(body)))
			req.RemoteAddr = "127.0.0.1:1234"
			req.Header.Set("Content-Type", "application/json")
			c.Request = req
			test.handler(c)
			if recorder.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404; body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestProbeAuthCredentialUsesExactSeatWithoutAdmitting(t *testing.T) {
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
	if auth == nil || auth.ReconcileState != coreauth.ReconcileStateProbing {
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

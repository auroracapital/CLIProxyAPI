package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type smartSlateExecutor struct {
	mu        sync.Mutex
	calls     []string
	authCalls []string
	metadata  []map[string]any
	failModel string
	failErr   error
	failFor   map[string]error
	streamErr bool
	streamFor func(context.Context, coreexecutor.Request) *coreexecutor.StreamResult
}

func (*smartSlateExecutor) Identifier() string { return "smart-slate-provider" }

func (e *smartSlateExecutor) Execute(_ context.Context, auth *coreauth.Auth, req coreexecutor.Request, opts coreexecutor.Options) (coreexecutor.Response, error) {
	e.mu.Lock()
	e.calls = append(e.calls, req.Model)
	if auth != nil {
		e.authCalls = append(e.authCalls, auth.ID)
	}
	e.metadata = append(e.metadata, cloneSchedulerMetadata(opts.Metadata))
	e.mu.Unlock()
	if err := e.failFor[req.Model]; err != nil {
		return coreexecutor.Response{}, err
	}
	if req.Model == e.failModel {
		return coreexecutor.Response{}, e.failErr
	}
	return coreexecutor.Response{Payload: []byte(req.Model)}, nil
}

type smartProviderExecutor struct {
	id      string
	mu      sync.Mutex
	calls   []string
	failFor map[string]error
}

func (e *smartProviderExecutor) Identifier() string { return e.id }
func (e *smartProviderExecutor) Execute(_ context.Context, _ *coreauth.Auth, req coreexecutor.Request, _ coreexecutor.Options) (coreexecutor.Response, error) {
	e.mu.Lock()
	e.calls = append(e.calls, req.Model)
	e.mu.Unlock()
	if err := e.failFor[req.Model]; err != nil {
		return coreexecutor.Response{}, err
	}
	return coreexecutor.Response{Payload: []byte(e.id + ":" + req.Model)}, nil
}
func (e *smartProviderExecutor) ExecuteStream(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	return nil, errors.New("not implemented")
}
func (e *smartProviderExecutor) Refresh(context.Context, *coreauth.Auth) (*coreauth.Auth, error) {
	return nil, nil
}
func (e *smartProviderExecutor) CountTokens(ctx context.Context, auth *coreauth.Auth, req coreexecutor.Request, opts coreexecutor.Options) (coreexecutor.Response, error) {
	return e.Execute(ctx, auth, req, opts)
}
func (e *smartProviderExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, errors.New("not implemented")
}

func (e *smartSlateExecutor) ExecuteStream(ctx context.Context, _ *coreauth.Auth, req coreexecutor.Request, opts coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	e.mu.Lock()
	e.calls = append(e.calls, req.Model)
	e.metadata = append(e.metadata, cloneSchedulerMetadata(opts.Metadata))
	e.mu.Unlock()
	if e.streamFor != nil {
		return e.streamFor(ctx, req), nil
	}
	chunks := make(chan coreexecutor.StreamChunk, 1)
	if req.Model == e.failModel && e.streamErr {
		chunks <- coreexecutor.StreamChunk{Err: e.failErr}
	} else {
		chunks <- coreexecutor.StreamChunk{Payload: []byte(req.Model)}
	}
	close(chunks)
	return &coreexecutor.StreamResult{Chunks: chunks}, nil
}

func (*smartSlateExecutor) Refresh(context.Context, *coreauth.Auth) (*coreauth.Auth, error) {
	return nil, nil
}

func (e *smartSlateExecutor) CountTokens(ctx context.Context, auth *coreauth.Auth, req coreexecutor.Request, opts coreexecutor.Options) (coreexecutor.Response, error) {
	return e.Execute(ctx, auth, req, opts)
}

func (*smartSlateExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, errors.New("not implemented")
}

func newSmartSlateHandler(t *testing.T, executor *smartSlateExecutor, models ...string) *BaseAPIHandler {
	t.Helper()
	manager := coreauth.NewManager(nil, &coreauth.RoundRobinSelector{}, nil)
	manager.SetRetryConfig(0, 0, 0)
	manager.RegisterExecutor(executor)
	auth := &coreauth.Auth{ID: "smart-slate-auth", Provider: executor.Identifier(), Status: coreauth.StatusActive}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	infos := make([]*registry.ModelInfo, 0, len(models))
	for _, model := range models {
		infos = append(infos, &registry.ModelInfo{ID: model})
	}
	registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, infos)
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
	return NewBaseAPIHandlers(nil, manager)
}

func TestSmartModelSlateFallsBackOnlyAfterPrimaryModelFails(t *testing.T) {
	busy := &coreauth.Error{HTTPStatus: http.StatusServiceUnavailable, Message: "busy"}
	executor := &smartSlateExecutor{failModel: "primary", failErr: busy}
	handler := newSmartSlateHandler(t, executor, "primary", "fallback")
	req := coreexecutor.Request{Model: "primary"}
	decision := modelRouteDecision{Models: []string{"primary", "fallback"}, TaskClass: smartTaskCode, ScoreVersion: smartRouteScoreVersion}

	response, selectedModel, errExecute := handler.executeModelSlate(context.Background(), []string{executor.Identifier()}, req, coreexecutor.Options{Metadata: map[string]any{coreexecutor.RequestedModelMetadataKey: "auto"}}, decision)
	if errExecute != nil {
		t.Fatal(errExecute)
	}
	if string(response.Payload) != "fallback" {
		t.Fatalf("payload = %q, want fallback", response.Payload)
	}
	if selectedModel != "fallback" {
		t.Fatalf("selected model = %q, want fallback", selectedModel)
	}
	executor.mu.Lock()
	calls := append([]string(nil), executor.calls...)
	executor.mu.Unlock()
	if len(calls) != 2 || calls[0] != "primary" || calls[1] != "fallback" {
		t.Fatalf("calls = %#v", calls)
	}
}

func TestSmartRoutingExhaustsDistinctAccountsBeforeNextModel(t *testing.T) {
	executor := &smartSlateExecutor{failModel: "primary", failErr: &coreauth.Error{HTTPStatus: http.StatusServiceUnavailable, Message: "busy"}}
	manager := coreauth.NewManager(nil, &coreauth.LeastPressureSelector{}, nil)
	manager.SetRetryConfig(0, 0, 0)
	manager.RegisterExecutor(executor)
	for _, id := range []string{"account-a", "account-b"} {
		registry.GetGlobalRegistry().RegisterClient(id, executor.Identifier(), []*registry.ModelInfo{{ID: "primary"}, {ID: "fallback"}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
		if _, errRegister := manager.Register(context.Background(), &coreauth.Auth{ID: id, Provider: executor.Identifier(), Status: coreauth.StatusActive}); errRegister != nil {
			t.Fatal(errRegister)
		}
	}
	handler := NewBaseAPIHandlers(nil, manager)
	response, model, errExecute := handler.executeModelSlate(context.Background(), []string{executor.Identifier()}, coreexecutor.Request{Model: "primary"}, coreexecutor.Options{}, modelRouteDecision{Models: []string{"primary", "fallback"}})
	if errExecute != nil || model != "fallback" || string(response.Payload) != "fallback" {
		t.Fatalf("model=%q response=%q err=%v", model, response.Payload, errExecute)
	}
	executor.mu.Lock()
	calls := append([]string(nil), executor.calls...)
	authCalls := append([]string(nil), executor.authCalls...)
	executor.mu.Unlock()
	if len(calls) != 3 || calls[0] != "primary" || calls[1] != "primary" || calls[2] != "fallback" {
		t.Fatalf("model calls = %#v", calls)
	}
	if authCalls[0] == authCalls[1] {
		t.Fatalf("primary repeated credential: %#v", authCalls)
	}
}

func TestSmartRoutingAttemptBoundIsModelsTimesDistinctAccounts(t *testing.T) {
	models := []string{"bounded-primary", "bounded-fallback"}
	executor := &smartSlateExecutor{failFor: map[string]error{
		models[0]: &coreauth.Error{HTTPStatus: http.StatusServiceUnavailable, Message: "busy"},
		models[1]: &coreauth.Error{HTTPStatus: http.StatusServiceUnavailable, Message: "busy"},
	}}
	manager := coreauth.NewManager(nil, &coreauth.LeastPressureSelector{}, nil)
	manager.SetRetryConfig(0, 0, 0)
	manager.RegisterExecutor(executor)
	accounts := []string{"bounded-account-a", "bounded-account-b"}
	for _, id := range accounts {
		registry.GetGlobalRegistry().RegisterClient(id, executor.Identifier(), []*registry.ModelInfo{{ID: models[0]}, {ID: models[1]}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
		if _, errRegister := manager.Register(context.Background(), &coreauth.Auth{ID: id, Provider: executor.Identifier(), Status: coreauth.StatusActive}); errRegister != nil {
			t.Fatal(errRegister)
		}
	}
	handler := NewBaseAPIHandlers(nil, manager)
	_, _, errExecute := handler.executeModelSlate(context.Background(), []string{executor.Identifier()}, coreexecutor.Request{Model: models[0]}, coreexecutor.Options{}, modelRouteDecision{Models: models})
	if errExecute == nil {
		t.Fatal("expected every bounded attempt to fail")
	}
	executor.mu.Lock()
	calls := append([]string(nil), executor.calls...)
	authCalls := append([]string(nil), executor.authCalls...)
	executor.mu.Unlock()
	wantAttempts := len(models) * len(accounts)
	if len(calls) != wantAttempts {
		t.Fatalf("attempts=%d calls=%#v, want models(%d) * accounts(%d) = %d", len(calls), calls, len(models), len(accounts), wantAttempts)
	}
	for modelIndex, model := range models {
		start := modelIndex * len(accounts)
		if calls[start] != model || calls[start+1] != model {
			t.Fatalf("calls=%#v, account attempts were not exhausted model-first", calls)
		}
		if authCalls[start] == authCalls[start+1] {
			t.Fatalf("model %q repeated account: %#v", model, authCalls[start:start+2])
		}
	}
}

func TestSmartModelSlateDoesNotFallbackOnInvalidRequest(t *testing.T) {
	invalid := &coreauth.Error{HTTPStatus: http.StatusBadRequest, Code: "invalid_request_error", Message: `{"error":{"type":"invalid_request_error","message":"bad"}}`}
	executor := &smartSlateExecutor{failModel: "primary", failErr: invalid}
	handler := newSmartSlateHandler(t, executor, "primary", "fallback")

	_, _, errExecute := handler.executeModelSlate(context.Background(), []string{executor.Identifier()}, coreexecutor.Request{Model: "primary"}, coreexecutor.Options{}, modelRouteDecision{Models: []string{"primary", "fallback"}})
	if errExecute == nil {
		t.Fatal("expected invalid request error")
	}
	executor.mu.Lock()
	calls := len(executor.calls)
	executor.mu.Unlock()
	if calls != 1 {
		t.Fatalf("calls = %d, invalid request must not cross-model fallback", calls)
	}
}

func TestSmartStreamSlateRetriesBeforeFirstPayload(t *testing.T) {
	busy := &coreauth.Error{HTTPStatus: http.StatusServiceUnavailable, Message: "busy"}
	executor := &smartSlateExecutor{failModel: "primary", failErr: busy, streamErr: true}
	handler := newSmartSlateHandler(t, executor, "primary", "fallback")

	result, selectedModel, errExecute := handler.executeStreamModelSlate(context.Background(), []string{executor.Identifier()}, coreexecutor.Request{Model: "primary"}, coreexecutor.Options{}, modelRouteDecision{Models: []string{"primary", "fallback"}})
	if errExecute != nil {
		t.Fatal(errExecute)
	}
	var payload []byte
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatal(chunk.Err)
		}
		payload = append(payload, chunk.Payload...)
	}
	if string(payload) != "fallback" {
		t.Fatalf("payload = %q, want fallback", payload)
	}
	if selectedModel != "fallback" {
		t.Fatalf("selected model = %q, want fallback", selectedModel)
	}
}

func TestSmartStreamSlateCancellationStopsBootstrapWait(t *testing.T) {
	executor := &smartSlateExecutor{streamFor: func(_ context.Context, _ coreexecutor.Request) *coreexecutor.StreamResult {
		return &coreexecutor.StreamResult{Chunks: make(chan coreexecutor.StreamChunk)}
	}}
	handler := newSmartSlateHandler(t, executor, "primary")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, _, errExecute := handler.executeStreamModelSlate(ctx, []string{executor.Identifier()}, coreexecutor.Request{Model: "primary"}, coreexecutor.Options{}, modelRouteDecision{Models: []string{"primary"}})
		done <- errExecute
	}()
	cancel()
	select {
	case errExecute := <-done:
		if !errors.Is(errExecute, context.Canceled) {
			t.Fatalf("error = %v, want context canceled", errExecute)
		}
	case <-time.After(time.Second):
		t.Fatal("stream bootstrap did not stop after cancellation")
	}
}

func TestSmartStreamSlateIgnoresEmptyBootstrapChunks(t *testing.T) {
	executor := &smartSlateExecutor{streamFor: func(_ context.Context, req coreexecutor.Request) *coreexecutor.StreamResult {
		chunks := make(chan coreexecutor.StreamChunk, 2)
		chunks <- coreexecutor.StreamChunk{}
		chunks <- coreexecutor.StreamChunk{Payload: []byte(req.Model)}
		close(chunks)
		return &coreexecutor.StreamResult{Chunks: chunks}
	}}
	handler := newSmartSlateHandler(t, executor, "primary")
	result, _, errExecute := handler.executeStreamModelSlate(context.Background(), []string{executor.Identifier()}, coreexecutor.Request{Model: "primary"}, coreexecutor.Options{}, modelRouteDecision{Models: []string{"primary"}})
	if errExecute != nil {
		t.Fatal(errExecute)
	}
	chunk := <-result.Chunks
	if string(chunk.Payload) != "primary" {
		t.Fatalf("first payload = %q, want primary", chunk.Payload)
	}
}

func TestSmartModelSlateDoesNotFallbackOnPolicyOrPermissionErrors(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusMethodNotAllowed, http.StatusNotImplemented} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			executor := &smartSlateExecutor{failModel: "primary", failErr: &coreauth.Error{HTTPStatus: status, Message: "terminal"}}
			handler := newSmartSlateHandler(t, executor, "primary", "fallback")
			_, _, errExecute := handler.executeModelSlate(context.Background(), []string{executor.Identifier()}, coreexecutor.Request{Model: "primary"}, coreexecutor.Options{}, modelRouteDecision{Models: []string{"primary", "fallback"}})
			if errExecute == nil {
				t.Fatal("expected terminal error")
			}
			executor.mu.Lock()
			calls := len(executor.calls)
			executor.mu.Unlock()
			if calls != 1 {
				t.Fatalf("calls = %d, terminal error must not cross-model fallback", calls)
			}
		})
	}
}

func TestSmartModelSlateFallbackStatusMatrix(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusPaymentRequired, http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			executor := &smartSlateExecutor{failModel: "primary", failErr: &coreauth.Error{HTTPStatus: status, Message: "retryable"}}
			handler := newSmartSlateHandler(t, executor, "primary", "fallback")
			response, model, errExecute := handler.executeModelSlate(context.Background(), []string{executor.Identifier()}, coreexecutor.Request{Model: "primary"}, coreexecutor.Options{}, modelRouteDecision{Models: []string{"primary", "fallback"}})
			if errExecute != nil || model != "fallback" || string(response.Payload) != "fallback" {
				t.Fatalf("response=%q model=%q err=%v", response.Payload, model, errExecute)
			}
		})
	}
}

func TestSmartModelSlateRequestFaultStatusMatrix(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusConflict, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			executor := &smartSlateExecutor{failModel: "primary", failErr: &coreauth.Error{HTTPStatus: status, Message: "invalid"}}
			handler := newSmartSlateHandler(t, executor, "primary", "fallback")
			_, _, errExecute := handler.executeModelSlate(context.Background(), []string{executor.Identifier()}, coreexecutor.Request{Model: "primary"}, coreexecutor.Options{}, modelRouteDecision{Models: []string{"primary", "fallback"}})
			if errExecute == nil {
				t.Fatal("expected terminal request error")
			}
			executor.mu.Lock()
			calls := len(executor.calls)
			executor.mu.Unlock()
			if calls != 1 {
				t.Fatalf("calls = %d, request fault must stop fallback", calls)
			}
		})
	}
}

func TestSmartModelSlateGenericNotFoundDoesNotFallback(t *testing.T) {
	executor := &smartSlateExecutor{failModel: "primary", failErr: &coreauth.Error{HTTPStatus: http.StatusNotFound, Message: `{"error":{"message":"missing conversation"}}`}}
	handler := newSmartSlateHandler(t, executor, "primary", "fallback")

	_, _, errExecute := handler.executeModelSlate(context.Background(), []string{executor.Identifier()}, coreexecutor.Request{Model: "primary"}, coreexecutor.Options{}, modelRouteDecision{Models: []string{"primary", "fallback"}})
	if errExecute == nil {
		t.Fatal("expected terminal not-found error")
	}
	executor.mu.Lock()
	calls := append([]string(nil), executor.calls...)
	executor.mu.Unlock()
	if len(calls) != 1 || calls[0] != "primary" {
		t.Fatalf("calls = %#v, generic 404 must not cross models", calls)
	}
}

func TestSmartModelSlateModelNotFoundFallsBack(t *testing.T) {
	executor := &smartSlateExecutor{failModel: "primary", failErr: &coreauth.Error{HTTPStatus: http.StatusNotFound, Code: "model_not_found", Message: "model is unavailable"}}
	handler := newSmartSlateHandler(t, executor, "primary", "fallback")

	response, model, errExecute := handler.executeModelSlate(context.Background(), []string{executor.Identifier()}, coreexecutor.Request{Model: "primary"}, coreexecutor.Options{}, modelRouteDecision{Models: []string{"primary", "fallback"}})
	if errExecute != nil || model != "fallback" || string(response.Payload) != "fallback" {
		t.Fatalf("response=%q model=%q error=%v", response.Payload, model, errExecute)
	}
}

func TestSmartModelSlateStructuredRequestFaultStopsFallback(t *testing.T) {
	for _, body := range []string{
		`{"error":{"type":"invalid_request_error","message":"bad"}}`,
		`{"error":{"code":"context_length_exceeded","message":"too long"}}`,
		`{"response":{"error":{"code":"invalid_prompt"}}}`,
	} {
		t.Run(body, func(t *testing.T) {
			executor := &smartSlateExecutor{failModel: "primary", failErr: &coreauth.Error{HTTPStatus: http.StatusBadGateway, Message: body}}
			handler := newSmartSlateHandler(t, executor, "primary", "fallback")
			_, _, errExecute := handler.executeModelSlate(context.Background(), []string{executor.Identifier()}, coreexecutor.Request{Model: "primary"}, coreexecutor.Options{}, modelRouteDecision{Models: []string{"primary", "fallback"}})
			if errExecute == nil {
				t.Fatal("expected terminal structured request fault")
			}
			executor.mu.Lock()
			calls := append([]string(nil), executor.calls...)
			executor.mu.Unlock()
			if len(calls) != 1 {
				t.Fatalf("calls = %#v, structured request fault crossed models", calls)
			}
		})
	}
}

func TestSmartModelSlateAttemptCountIsBoundedBySlate(t *testing.T) {
	models := []string{"model-a", "model-b", "model-c"}
	failures := make(map[string]error, len(models))
	for _, model := range models {
		failures[model] = &coreauth.Error{HTTPStatus: http.StatusServiceUnavailable, Message: "busy"}
	}
	executor := &smartSlateExecutor{failFor: failures}
	handler := newSmartSlateHandler(t, executor, models...)
	_, _, errExecute := handler.executeModelSlate(context.Background(), []string{executor.Identifier()}, coreexecutor.Request{Model: models[0]}, coreexecutor.Options{}, modelRouteDecision{Models: models})
	if errExecute == nil {
		t.Fatal("expected exhausted slate error")
	}
	executor.mu.Lock()
	calls := append([]string(nil), executor.calls...)
	metadata := append([]map[string]any(nil), executor.metadata...)
	executor.mu.Unlock()
	if len(calls) != len(models) {
		t.Fatalf("calls = %#v, want exactly one attempt per model", calls)
	}
	for index, attemptMetadata := range metadata {
		if got := attemptMetadata["smart_route_attempt"]; got != index {
			t.Fatalf("attempt %d metadata ordinal = %#v", index, got)
		}
	}
}

func TestSmartSlateResolvesProviderPerSelectedModel(t *testing.T) {
	primaryProvider := &smartProviderExecutor{id: "provider-primary", failFor: map[string]error{"primary": &coreauth.Error{HTTPStatus: http.StatusServiceUnavailable, Message: "busy"}}}
	fallbackProvider := &smartProviderExecutor{id: "provider-fallback"}
	manager := coreauth.NewManager(nil, &coreauth.RoundRobinSelector{}, nil)
	manager.SetRetryConfig(0, 0, 0)
	for _, setup := range []struct {
		executor *smartProviderExecutor
		model    string
	}{
		{executor: primaryProvider, model: "primary"},
		{executor: fallbackProvider, model: "fallback"},
	} {
		manager.RegisterExecutor(setup.executor)
		authID := setup.executor.id + "-auth"
		registry.GetGlobalRegistry().RegisterClient(authID, setup.executor.id, []*registry.ModelInfo{{ID: setup.model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(authID) })
		if _, errRegister := manager.Register(context.Background(), &coreauth.Auth{ID: authID, Provider: setup.executor.id, Status: coreauth.StatusActive}); errRegister != nil {
			t.Fatal(errRegister)
		}
	}
	handler := NewBaseAPIHandlers(nil, manager)
	decision := modelRouteDecision{
		Models: []string{"primary", "fallback"},
		Providers: map[string][]string{
			"primary":  {primaryProvider.id},
			"fallback": {fallbackProvider.id},
		},
	}
	response, model, errExecute := handler.executeModelSlate(context.Background(), []string{primaryProvider.id}, coreexecutor.Request{Model: "primary"}, coreexecutor.Options{}, decision)
	if errExecute != nil || model != "fallback" || string(response.Payload) != "provider-fallback:fallback" {
		t.Fatalf("response=%q model=%q err=%v", response.Payload, model, errExecute)
	}
	primaryProvider.mu.Lock()
	primaryCalls := append([]string(nil), primaryProvider.calls...)
	primaryProvider.mu.Unlock()
	fallbackProvider.mu.Lock()
	fallbackCalls := append([]string(nil), fallbackProvider.calls...)
	fallbackProvider.mu.Unlock()
	if fmt.Sprint(primaryCalls) != "[primary]" || fmt.Sprint(fallbackCalls) != "[fallback]" {
		t.Fatalf("primary calls=%v fallback calls=%v", primaryCalls, fallbackCalls)
	}
}

func TestSmartStreamEmptyClosedPrimaryFallsBack(t *testing.T) {
	executor := &smartSlateExecutor{streamFor: func(_ context.Context, req coreexecutor.Request) *coreexecutor.StreamResult {
		chunks := make(chan coreexecutor.StreamChunk, 1)
		if req.Model == "fallback" {
			chunks <- coreexecutor.StreamChunk{Payload: []byte("fallback")}
		}
		close(chunks)
		return &coreexecutor.StreamResult{Chunks: chunks}
	}}
	handler := newSmartSlateHandler(t, executor, "primary", "fallback")
	result, model, errExecute := handler.executeStreamModelSlate(context.Background(), []string{executor.Identifier()}, coreexecutor.Request{Model: "primary"}, coreexecutor.Options{}, modelRouteDecision{Models: []string{"primary", "fallback"}})
	if errExecute != nil || model != "fallback" {
		t.Fatalf("model=%q err=%v", model, errExecute)
	}
	if chunk := <-result.Chunks; string(chunk.Payload) != "fallback" {
		t.Fatalf("payload = %q", chunk.Payload)
	}
}

func TestSmartStreamPayloadThenErrorNeverFallsBack(t *testing.T) {
	executor := &smartSlateExecutor{streamFor: func(_ context.Context, req coreexecutor.Request) *coreexecutor.StreamResult {
		chunks := make(chan coreexecutor.StreamChunk, 2)
		chunks <- coreexecutor.StreamChunk{Payload: []byte("visible")}
		chunks <- coreexecutor.StreamChunk{Err: &coreauth.Error{HTTPStatus: http.StatusServiceUnavailable, Message: "late"}}
		close(chunks)
		return &coreexecutor.StreamResult{Chunks: chunks}
	}}
	handler := newSmartSlateHandler(t, executor, "primary", "fallback")
	result, model, errExecute := handler.executeStreamModelSlate(context.Background(), []string{executor.Identifier()}, coreexecutor.Request{Model: "primary"}, coreexecutor.Options{}, modelRouteDecision{Models: []string{"primary", "fallback"}})
	if errExecute != nil || model != "primary" {
		t.Fatalf("model=%q err=%v", model, errExecute)
	}
	var gotErr error
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			gotErr = chunk.Err
		}
	}
	if gotErr == nil {
		t.Fatal("expected late stream error")
	}
	executor.mu.Lock()
	calls := append([]string(nil), executor.calls...)
	executor.mu.Unlock()
	if len(calls) != 1 || calls[0] != "primary" {
		t.Fatalf("calls = %#v, fallback occurred after visible payload", calls)
	}
}

func TestSmartCountSlateUsesPrimaryOnly(t *testing.T) {
	executor := &smartSlateExecutor{failModel: "primary", failErr: &coreauth.Error{HTTPStatus: http.StatusServiceUnavailable, Message: "busy"}}
	handler := newSmartSlateHandler(t, executor, "primary", "fallback")
	_, model, errExecute := handler.executeCountModelSlate(context.Background(), []string{executor.Identifier()}, coreexecutor.Request{Model: "primary"}, coreexecutor.Options{}, modelRouteDecision{Models: []string{"primary", "fallback"}})
	if errExecute == nil || model != "primary" {
		t.Fatalf("model=%q err=%v", model, errExecute)
	}
	executor.mu.Lock()
	calls := append([]string(nil), executor.calls...)
	executor.mu.Unlock()
	if len(calls) != 1 || calls[0] != "primary" {
		t.Fatalf("count calls = %#v, must use primary tokenizer only", calls)
	}
}

func TestRequestWithSelectedModelPreservesActualRoute(t *testing.T) {
	updated := requestWithSelectedModel([]byte(`{"model":"auto","input":"hello"}`), "fallback-model")
	if string(updated) != `{"model":"fallback-model","input":"hello"}` {
		t.Fatalf("updated request = %s", updated)
	}
}

func TestSmartAutoRequestExecutesSelectedPrimaryModel(t *testing.T) {
	executor := &smartSlateExecutor{}
	handler := newSmartSlateHandler(t, executor, "smart-live-primary", "smart-live-fallback")
	handler.UpdateClients(smartRouterHandler(internalconfig.AutoRoutingConfig{
		Enabled:       true,
		DefaultModels: []string{"smart-live-primary", "smart-live-fallback"},
	}).Cfg)

	body, _, errMsg := handler.ExecuteWithAuthManager(context.Background(), "openai", "auto", []byte(`{"model":"auto","messages":[{"role":"user","content":"hello"}]}`), "")
	if errMsg != nil {
		t.Fatalf("ExecuteWithAuthManager() error = %+v", errMsg)
	}
	if string(body) != "smart-live-primary" {
		t.Fatalf("body = %q, want selected primary model", body)
	}
	executor.mu.Lock()
	calls := append([]string(nil), executor.calls...)
	executor.mu.Unlock()
	if len(calls) != 1 || calls[0] != "smart-live-primary" {
		t.Fatalf("calls = %#v, smart decision did not reach selected model", calls)
	}
	executor.mu.Lock()
	metadata := executor.metadata[0]
	executor.mu.Unlock()
	if metadata[coreexecutor.RequestedModelMetadataKey] != "auto" || metadata["smart_route_task"] != smartTaskGeneral || metadata["smart_route_score_version"] != smartRouteScoreVersion {
		t.Fatalf("smart route metadata = %#v", metadata)
	}
}

func TestSmartFallbackLifecycleReportsActualModelAndRequestedAuto(t *testing.T) {
	executor := &smartSlateExecutor{failModel: "smart-lifecycle-primary", failErr: &coreauth.Error{HTTPStatus: http.StatusServiceUnavailable, Message: "busy"}}
	handler := newSmartSlateHandler(t, executor, "smart-lifecycle-primary", "smart-lifecycle-fallback")
	handler.UpdateClients(smartRouterHandler(internalconfig.AutoRoutingConfig{
		Enabled:       true,
		DefaultModels: []string{"smart-lifecycle-primary", "smart-lifecycle-fallback"},
	}).Cfg)
	var completion pluginapi.RequestCompletion
	handler.SetPluginHost(&handlerInterceptorTestHost{completeRequest: func(_ context.Context, got pluginapi.RequestCompletion) {
		completion = got
	}})
	body, _, errMsg := handler.ExecuteWithAuthManager(context.Background(), "openai", "auto", []byte(`{"model":"auto","messages":[{"role":"user","content":"hello"}]}`), "")
	if errMsg != nil || string(body) != "smart-lifecycle-fallback" {
		t.Fatalf("body=%q err=%#v", body, errMsg)
	}
	if completion.Model != "smart-lifecycle-fallback" || completion.RequestedModel != "auto" || completion.Outcome != pluginapi.RequestCompletionSucceeded {
		t.Fatalf("completion = %#v", completion)
	}
}

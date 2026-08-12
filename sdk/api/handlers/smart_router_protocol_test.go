package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	. "github.com/router-for-me/CLIProxyAPI/v7/internal/constant"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	_ "github.com/router-for-me/CLIProxyAPI/v7/internal/translator"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

const (
	smartProtocolPrimary  = "smart-protocol-primary"
	smartProtocolFallback = "smart-protocol-fallback"
)

type smartProtocolExecutor struct{}

func (smartProtocolExecutor) Identifier() string { return Codex }

func (smartProtocolExecutor) Execute(ctx context.Context, _ *coreauth.Auth, req coreexecutor.Request, opts coreexecutor.Options) (coreexecutor.Response, error) {
	if req.Model == smartProtocolPrimary {
		return coreexecutor.Response{}, &coreauth.Error{HTTPStatus: http.StatusServiceUnavailable, Message: "primary unavailable"}
	}
	raw := smartProtocolTerminal(req.Model)
	var param any
	payload := sdktranslator.TranslateNonStream(ctx, sdktranslator.FromString(Codex), coreexecutor.ResponseFormatOrSource(opts), req.Model, opts.OriginalRequest, req.Payload, raw, &param)
	return coreexecutor.Response{Payload: payload}, nil
}

func (smartProtocolExecutor) ExecuteStream(ctx context.Context, _ *coreauth.Auth, req coreexecutor.Request, opts coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	if req.Model == smartProtocolPrimary {
		chunks := make(chan coreexecutor.StreamChunk, 1)
		chunks <- coreexecutor.StreamChunk{Err: &coreauth.Error{HTTPStatus: http.StatusServiceUnavailable, Message: "primary unavailable"}}
		close(chunks)
		return &coreexecutor.StreamResult{Chunks: chunks}, nil
	}
	events := [][]byte{
		[]byte(`data: {"type":"response.created","response":{"id":"resp-smart","created_at":1700000000,"model":"` + req.Model + `","status":"in_progress","output":[]}}`),
		[]byte(`data: {"type":"response.output_text.delta","item_id":"msg-smart","output_index":0,"content_index":0,"delta":"ok"}`),
		append([]byte("data: "), smartProtocolTerminal(req.Model)...),
	}
	chunks := make(chan coreexecutor.StreamChunk, len(events))
	var param any
	for _, event := range events {
		for _, payload := range sdktranslator.TranslateStream(ctx, sdktranslator.FromString(Codex), coreexecutor.ResponseFormatOrSource(opts), req.Model, opts.OriginalRequest, req.Payload, event, &param) {
			if len(payload) > 0 {
				chunks <- coreexecutor.StreamChunk{Payload: payload}
			}
		}
	}
	close(chunks)
	return &coreexecutor.StreamResult{Chunks: chunks}, nil
}

func (smartProtocolExecutor) CountTokens(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{}, errors.New("not implemented")
}

func (smartProtocolExecutor) Refresh(context.Context, *coreauth.Auth) (*coreauth.Auth, error) {
	return nil, nil
}

func (smartProtocolExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, errors.New("not implemented")
}

func smartProtocolTerminal(model string) []byte {
	return []byte(`{"type":"response.completed","response":{"id":"resp-smart","created_at":1700000000,"model":"` + model + `","status":"completed","output":[{"type":"message","id":"msg-smart","role":"assistant","content":[{"type":"output_text","text":"ok"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`)
}

func newSmartProtocolHandler(t *testing.T) *BaseAPIHandler {
	t.Helper()
	manager := coreauth.NewManager(nil, &coreauth.RoundRobinSelector{}, nil)
	manager.SetRetryConfig(0, 0, 0)
	executor := smartProtocolExecutor{}
	manager.RegisterExecutor(executor)
	auth := &coreauth.Auth{ID: "smart-protocol-auth", Provider: executor.Identifier(), Status: coreauth.StatusActive}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	models := []*registry.ModelInfo{{ID: smartProtocolPrimary}, {ID: smartProtocolFallback}}
	registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, models)
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
	return NewBaseAPIHandlers(&sdkconfig.SDKConfig{AutoRouting: internalconfig.AutoRoutingConfig{
		Mode:          "active",
		MaxFallbacks:  2,
		DefaultModels: []string{smartProtocolPrimary, smartProtocolFallback},
	}}, manager)
}

func TestSmartAutoReportsCommittedModelAcrossProtocols(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		request  string
		path     string
	}{
		{name: "chat", protocol: OpenAI, request: `{"model":"auto","messages":[{"role":"user","content":"hello"}]}`, path: "model"},
		{name: "responses", protocol: OpenaiResponse, request: `{"model":"auto","input":"hello"}`, path: "model"},
		{name: "claude", protocol: Claude, request: `{"model":"auto","max_tokens":32,"messages":[{"role":"user","content":"hello"}]}`, path: "model"},
		{name: "gemini", protocol: Gemini, request: `{"model":"auto","contents":[{"role":"user","parts":[{"text":"hello"}]}]}`, path: "modelVersion"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := newSmartProtocolHandler(t)
			body, _, errMsg := handler.ExecuteWithAuthManager(context.Background(), test.protocol, "auto", []byte(test.request), "")
			if errMsg != nil {
				t.Fatalf("ExecuteWithAuthManager() error = %+v", errMsg)
			}
			if got := gjson.GetBytes(body, test.path).String(); got != smartProtocolFallback {
				t.Fatalf("%s = %q, want %q; body=%s", test.path, got, smartProtocolFallback, body)
			}
		})
	}
}

func TestSmartAutoStreamingReportsCommittedModelAcrossProtocols(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		request  string
		modelKey string
	}{
		{name: "chat", protocol: OpenAI, request: `{"model":"auto","messages":[{"role":"user","content":"hello"}],"stream":true}`, modelKey: `"model":"` + smartProtocolFallback + `"`},
		{name: "responses", protocol: OpenaiResponse, request: `{"model":"auto","input":"hello","stream":true}`, modelKey: `"model":"` + smartProtocolFallback + `"`},
		{name: "claude", protocol: Claude, request: `{"model":"auto","max_tokens":32,"messages":[{"role":"user","content":"hello"}],"stream":true}`, modelKey: `"model":"` + smartProtocolFallback + `"`},
		{name: "gemini", protocol: Gemini, request: `{"model":"auto","contents":[{"role":"user","parts":[{"text":"hello"}]}]}`, modelKey: `"modelVersion":"` + smartProtocolFallback + `"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := newSmartProtocolHandler(t)
			data, _, errs := handler.ExecuteStreamWithAuthManager(context.Background(), test.protocol, "auto", []byte(test.request), "")
			var output strings.Builder
			for chunk := range data {
				output.Write(chunk)
			}
			for errMsg := range errs {
				if errMsg != nil {
					t.Fatalf("stream error = %+v", errMsg)
				}
			}
			if !strings.Contains(output.String(), test.modelKey) {
				t.Fatalf("stream omitted committed model %q: %s", test.modelKey, output.String())
			}
		})
	}
}

func TestSmartAutoLifecycleAttributesCommittedFallbackModel(t *testing.T) {
	handler := newSmartProtocolHandler(t)
	completions := make(chan pluginapi.RequestCompletion, 1)
	handler.SetPluginHost(&handlerInterceptorTestHost{
		completeRequest: func(_ context.Context, completion pluginapi.RequestCompletion) {
			completions <- completion
		},
	})

	_, _, errMsg := handler.ExecuteWithAuthManager(context.Background(), OpenAI, "auto", []byte(`{"model":"auto","messages":[{"role":"user","content":"hello"}]}`), "")
	if errMsg != nil {
		t.Fatalf("ExecuteWithAuthManager() error = %+v", errMsg)
	}
	completion := <-completions
	if completion.Model != smartProtocolFallback || completion.RequestedModel != "auto" || completion.Outcome != pluginapi.RequestCompletionSucceeded {
		t.Fatalf("completion = %#v", completion)
	}
}

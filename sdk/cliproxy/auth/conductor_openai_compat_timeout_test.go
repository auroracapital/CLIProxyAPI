package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

// A hanging openai-compat upstream and a healthy one serve the same alias. With
// first-byte-timeout set on the hanging provider, the conductor must give up on
// it after the timeout, cool only that auth/model briefly (transient), and serve
// the request from the healthy provider without a quota or credential cooldown.
func TestManagerOpenAICompatFirstByteTimeoutFailsOverToHealthyRoute(t *testing.T) {
	const (
		routeModel       = "timeout-alias-latest"
		hangProvider     = "timeout-hang"
		healthyProvider  = "timeout-healthy"
		firstByteTimeout = 300 * time.Millisecond
		margin           = 1500 * time.Millisecond
	)
	cliproxyauth.SetTransientErrorCooldownSeconds(10)
	t.Cleanup(func() { cliproxyauth.SetTransientErrorCooldownSeconds(0) })

	for _, path := range []string{"execute", "stream"} {
		t.Run(path, func(t *testing.T) {
			var hangHits, healthyHits atomic.Int32
			stop := make(chan struct{})
			hanging := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				hangHits.Add(1)
				select { // never answers; ends when the client gives up or the test ends
				case <-r.Context().Done():
				case <-stop:
				}
			}))
			healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				healthyHits.Add(1)
				if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
					w.Header().Set("Content-Type", "text/event-stream")
					_, _ = w.Write([]byte("data: {\"id\":\"h\",\"object\":\"chat.completion.chunk\",\"model\":\"up\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"healthy\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"))
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"h","object":"chat.completion","model":"up","choices":[{"index":0,"message":{"role":"assistant","content":"healthy"},"finish_reason":"stop"}]}`))
			}))
			t.Cleanup(func() { close(stop); hanging.Close(); healthy.Close() })

			cfg := &internalconfig.Config{OpenAICompatibility: []internalconfig.OpenAICompatibility{
				{Name: hangProvider, BaseURL: hanging.URL + "/v1", FirstByteTimeout: firstByteTimeout.String(), Models: []internalconfig.OpenAICompatibilityModel{{Name: routeModel}}},
				{Name: healthyProvider, BaseURL: healthy.URL + "/v1", FirstByteTimeout: "5s", Models: []internalconfig.OpenAICompatibilityModel{{Name: routeModel}}},
			}}
			manager := cliproxyauth.NewManager(nil, &cliproxyauth.RoundRobinSelector{}, nil)
			manager.SetConfig(cfg)
			manager.SetRetryConfig(0, 30*time.Second, 0)
			// Same keys the service uses: openai-compatible-<name>.
			hangKey, healthyKey := util.OpenAICompatibleProviderKey(hangProvider), util.OpenAICompatibleProviderKey(healthyProvider)
			manager.RegisterExecutor(executor.NewOpenAICompatExecutor(hangKey, cfg))
			manager.RegisterExecutor(executor.NewOpenAICompatExecutor(healthyKey, cfg))

			hangID, healthyID := "timeout-hang-"+t.Name(), "timeout-healthy-"+t.Name()
			for _, candidate := range []*cliproxyauth.Auth{
				// The hanging route has the higher priority, so it is always tried first.
				{ID: hangID, Provider: hangKey, Status: cliproxyauth.StatusActive, Attributes: map[string]string{
					"base_url": hanging.URL + "/v1", "api_key": "k", "compat_name": hangProvider, "priority": "10",
				}},
				{ID: healthyID, Provider: healthyKey, Status: cliproxyauth.StatusActive, Attributes: map[string]string{
					"base_url": healthy.URL + "/v1", "api_key": "k", "compat_name": healthyProvider, "priority": "1",
				}},
			} {
				registry.GetGlobalRegistry().RegisterClient(candidate.ID, candidate.Provider, []*registry.ModelInfo{{ID: routeModel}})
				id := candidate.ID
				t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
				if _, errRegister := manager.Register(context.Background(), candidate); errRegister != nil {
					t.Fatal(errRegister)
				}
			}

			request := cliproxyexecutor.Request{
				Model:   routeModel,
				Payload: []byte(`{"model":"` + routeModel + `","messages":[{"role":"user","content":"hi"}]}`),
			}
			providers := []string{hangKey, healthyKey}
			run := func() (string, time.Duration) {
				t.Helper()
				start := time.Now()
				var body string
				switch path {
				case "execute":
					response, errExecute := manager.Execute(context.Background(), providers, request, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai")})
					if errExecute != nil {
						t.Fatalf("Execute error = %v", errExecute)
					}
					body = string(response.Payload)
				case "stream":
					result, errStream := manager.ExecuteStream(context.Background(), providers, request, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai"), Stream: true})
					if errStream != nil {
						t.Fatalf("ExecuteStream error = %v", errStream)
					}
					var builder strings.Builder
					for chunk := range result.Chunks {
						if chunk.Err != nil {
							t.Fatalf("stream chunk error = %v", chunk.Err)
						}
						builder.Write(chunk.Payload)
					}
					body = builder.String()
				}
				return body, time.Since(start)
			}

			body, elapsed := run()
			if !strings.Contains(body, "healthy") {
				t.Fatalf("response = %q, want it served by the healthy route", body)
			}
			if elapsed < firstByteTimeout || elapsed > firstByteTimeout+margin {
				t.Fatalf("failover took %s, want between %s and %s", elapsed, firstByteTimeout, firstByteTimeout+margin)
			}
			if hangHits.Load() != 1 || healthyHits.Load() != 1 {
				t.Fatalf("hits hang=%d healthy=%d, want 1 and 1", hangHits.Load(), healthyHits.Load())
			}

			hang, _ := manager.GetByID(hangID)
			state := hang.ModelStates[routeModel]
			if state == nil || !state.Unavailable {
				t.Fatalf("hanging route model state = %+v, want a transient cooldown", state)
			}
			if remaining := time.Until(state.NextRetryAfter); remaining <= 0 || remaining > 11*time.Second {
				t.Fatalf("cooldown remaining = %s, want about transient-error-cooldown-seconds (10s)", remaining)
			}
			if state.Quota.Exceeded || hang.Quota.Exceeded {
				t.Fatal("a first-byte timeout must not mark quota exhaustion")
			}
			if state.LastError == nil || state.LastError.HTTPStatus != http.StatusGatewayTimeout {
				t.Fatalf("last error = %+v, want HTTP 504", state.LastError)
			}

			// While parked, the next request goes straight to the healthy route.
			body, elapsed = run()
			if !strings.Contains(body, "healthy") || elapsed > margin {
				t.Fatalf("second request body=%q elapsed=%s, want healthy route without waiting", body, elapsed)
			}
			if hangHits.Load() != 1 {
				t.Fatalf("parked route was retried: hang hits = %d", hangHits.Load())
			}
		})
	}
}

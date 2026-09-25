package executor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

const timeoutTestProvider = "timeout-compat"

func newTimeoutTestExecutor(t *testing.T, handler http.HandlerFunc, firstByte, total string) (*OpenAICompatExecutor, *cliproxyauth.Auth) {
	t.Helper()
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler(w, r.WithContext(contextWithRelease(r.Context(), release)))
	}))
	// Unblock stalled handlers before Close so the test never waits on them.
	t.Cleanup(func() { close(release); server.Close() })
	cfg := &config.Config{OpenAICompatibility: []config.OpenAICompatibility{{
		Name:             timeoutTestProvider,
		BaseURL:          server.URL + "/v1",
		FirstByteTimeout: firstByte,
		Timeout:          total,
	}}}
	auth := &cliproxyauth.Auth{Provider: timeoutTestProvider, Attributes: map[string]string{
		"base_url":    server.URL + "/v1",
		"api_key":     "test",
		"compat_name": timeoutTestProvider,
	}}
	return NewOpenAICompatExecutor(timeoutTestProvider, cfg), auth
}

type releaseKey struct{}

func contextWithRelease(ctx context.Context, release chan struct{}) context.Context {
	return context.WithValue(ctx, releaseKey{}, release)
}

// stall blocks until the client goes away or the test ends.
func stall(r *http.Request) {
	release, _ := r.Context().Value(releaseKey{}).(chan struct{})
	select {
	case <-r.Context().Done():
	case <-release:
	}
}

var timeoutTestRequest = cliproxyexecutor.Request{
	Model:   "compatible-model",
	Payload: []byte(`{"model":"compatible-model","messages":[{"role":"user","content":"hi"}]}`),
}

func requireGatewayTimeout(t *testing.T, err error, elapsed, limit time.Duration, marker string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	var status interface{ StatusCode() int }
	if !errors.As(err, &status) || status.StatusCode() != http.StatusGatewayTimeout {
		t.Fatalf("error = %v, want HTTP 504 status error", err)
	}
	if !strings.Contains(err.Error(), marker) {
		t.Fatalf("error = %q, want it to mention %q", err.Error(), marker)
	}
	var scoped interface{ IsCredentialScoped() bool }
	if errors.As(err, &scoped) && scoped.IsCredentialScoped() {
		t.Fatal("timeout must not be credential-scoped")
	}
	if elapsed > limit {
		t.Fatalf("attempt took %s, want under %s", elapsed, limit)
	}
}

func TestOpenAICompatFirstByteTimeoutNonStream(t *testing.T) {
	executor, auth := newTimeoutTestExecutor(t, func(_ http.ResponseWriter, r *http.Request) { stall(r) }, "200ms", "")
	start := time.Now()
	_, err := executor.Execute(context.Background(), auth, timeoutTestRequest, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai")})
	requireGatewayTimeout(t, err, time.Since(start), 2*time.Second, "first-byte-timeout")
}

func TestOpenAICompatTotalTimeoutNonStream(t *testing.T) {
	executor, auth := newTimeoutTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":`))
		w.(http.Flusher).Flush()
		stall(r)
	}, "5s", "300ms")
	start := time.Now()
	_, err := executor.Execute(context.Background(), auth, timeoutTestRequest, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai")})
	requireGatewayTimeout(t, err, time.Since(start), 2*time.Second, "(timeout)")
}

func TestOpenAICompatFirstByteTimeoutStreamHeadersThenStall(t *testing.T) {
	executor, auth := newTimeoutTestExecutor(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		stall(r)
	}, "200ms", "")
	start := time.Now()
	_, err := executor.ExecuteStream(context.Background(), auth, timeoutTestRequest, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai"), Stream: true})
	requireGatewayTimeout(t, err, time.Since(start), 2*time.Second, "first-byte-timeout")
}

// Once bytes flow, a slow stream must not be cut off: streams have no total cap.
func TestOpenAICompatStreamHasNoTotalCapAfterFirstByte(t *testing.T) {
	executor, auth := newTimeoutTestExecutor(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		_, _ = w.Write([]byte("data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"compatible-model\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"he\"}}]}\n\n"))
		flusher.Flush()
		time.Sleep(600 * time.Millisecond) // longer than both timeouts below
		_, _ = w.Write([]byte("data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"compatible-model\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"llo\"},\"finish_reason\":\"stop\"}]}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		flusher.Flush()
	}, "200ms", "200ms")
	result, err := executor.ExecuteStream(context.Background(), auth, timeoutTestRequest, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai"), Stream: true})
	if err != nil {
		t.Fatalf("ExecuteStream error = %v", err)
	}
	var body strings.Builder
	for chunk := range result.Chunks {
		if chunk.Err != nil {
			t.Fatalf("stream chunk error = %v", chunk.Err)
		}
		body.Write(chunk.Payload)
	}
	if !strings.Contains(body.String(), "llo") {
		t.Fatalf("stream was cut before the late chunk: %q", body.String())
	}
}

// Unset timeouts keep today's behaviour: a slow but healthy upstream is waited for.
func TestOpenAICompatNoTimeoutConfiguredWaits(t *testing.T) {
	executor, auth := newTimeoutTestExecutor(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(400 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","object":"chat.completion","model":"compatible-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}, "", "")
	if _, err := executor.Execute(context.Background(), auth, timeoutTestRequest, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai")}); err != nil {
		t.Fatalf("Execute error = %v", err)
	}
}

// A caller cancellation must stay a cancellation, not become a 504.
func TestOpenAICompatParentCancelIsNotReportedAsTimeout(t *testing.T) {
	executor, auth := newTimeoutTestExecutor(t, func(_ http.ResponseWriter, r *http.Request) { stall(r) }, "5s", "")
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err := executor.Execute(ctx, auth, timeoutTestRequest, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai")})
	if err == nil {
		t.Fatal("expected cancellation error")
	}
	var status interface{ StatusCode() int }
	if errors.As(err, &status) && status.StatusCode() == http.StatusGatewayTimeout {
		t.Fatalf("parent cancellation was reported as a 504: %v", err)
	}
}

func TestOpenAICompatAttemptTimeoutParsing(t *testing.T) {
	cases := map[string]time.Duration{"": 0, "0": 0, "0s": 0, "-5s": 0, "junk": 0, "20s": 20 * time.Second, "20": 20 * time.Second, "1m30s": 90 * time.Second, " 45s ": 45 * time.Second}
	for raw, want := range cases {
		compat := &config.OpenAICompatibility{FirstByteTimeout: raw, Timeout: raw}
		if got := compat.FirstByteTimeoutDuration(); got != want {
			t.Errorf("FirstByteTimeoutDuration(%q) = %s, want %s", raw, got, want)
		}
		if got := compat.TimeoutDuration(); got != want {
			t.Errorf("TimeoutDuration(%q) = %s, want %s", raw, got, want)
		}
	}
}

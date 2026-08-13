package executor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestParseOpenAICompatRetryAfter(t *testing.T) {
	now := time.Date(2026, 8, 13, 5, 0, 0, 0, time.UTC)
	for _, testCase := range []struct {
		name string
		raw  string
		want time.Duration
	}{
		{name: "delta seconds", raw: "2", want: 2 * time.Second},
		{name: "http date", raw: now.Add(3 * time.Second).Format(http.TimeFormat), want: 3 * time.Second},
		{name: "zero", raw: "0"},
		{name: "negative", raw: "-1"},
		{name: "duration overflow", raw: "9223372036854775807"},
		{name: "past date", raw: now.Add(-time.Second).Format(http.TimeFormat)},
		{name: "fractional is invalid", raw: "1.5"},
		{name: "malformed", raw: "secret"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			got := parseOpenAICompatRetryAfter(http.Header{"Retry-After": []string{testCase.raw}}, now)
			if testCase.want == 0 {
				if got != nil {
					t.Fatalf("RetryAfter(%q) = %v, want nil", testCase.raw, *got)
				}
				return
			}
			if got == nil || *got != testCase.want {
				t.Fatalf("RetryAfter(%q) = %v, want %v", testCase.raw, got, testCase.want)
			}
		})
	}
}

func TestOpenAICompatExecutorCarriesUpstreamRetryAfter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"type":"rate_limit_error","message":"limited"}}`))
	}))
	defer server.Close()

	executor := NewOpenAICompatExecutor("openai-compatibility", &config.Config{})
	auth := &cliproxyauth.Auth{Provider: "openai-compatibility", Attributes: map[string]string{
		"base_url": server.URL + "/v1",
		"api_key":  "fixture",
	}}
	_, errExecute := executor.Execute(context.Background(), auth, cliproxyexecutor.Request{
		Model:   "fixture-model",
		Payload: []byte(`{"model":"fixture-model","messages":[]}`),
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai")})
	if errExecute == nil {
		t.Fatal("Execute error = nil, want rate limit")
	}
	retryable, ok := errExecute.(interface{ RetryAfter() *time.Duration })
	if !ok || retryable.RetryAfter() == nil || *retryable.RetryAfter() != 7*time.Second {
		t.Fatalf("Execute error = %#v, want RetryAfter 7s", errExecute)
	}
}

func TestNewOpenAICompatStatusErrorCarriesOnlyParsedRetryAfter(t *testing.T) {
	now := time.Date(2026, 8, 13, 5, 0, 0, 0, time.UTC)
	err := newOpenAICompatStatusError(http.StatusTooManyRequests, "rate limited", http.Header{
		"Retry-After":   []string{"7"},
		"Authorization": []string{"Bearer private"},
	}, now)
	if err.StatusCode() != http.StatusTooManyRequests || err.Error() != "rate limited" || err.RetryAfter() == nil || *err.RetryAfter() != 7*time.Second {
		t.Fatalf("status error = %#v", err)
	}
}

package auth

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type countingRefreshExecutor struct {
	id           string
	refreshCalls atomic.Int32
}

type blockingRefreshExecutor struct {
	countingRefreshExecutor
	once    sync.Once
	started chan struct{}
	release chan struct{}
}

func (e *blockingRefreshExecutor) Refresh(ctx context.Context, auth *Auth) (*Auth, error) {
	e.once.Do(func() { close(e.started) })
	select {
	case <-e.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return e.countingRefreshExecutor.Refresh(ctx, auth)
}

func (e *countingRefreshExecutor) Identifier() string { return e.id }

func (e *countingRefreshExecutor) Execute(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *countingRefreshExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}

func (e *countingRefreshExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	e.refreshCalls.Add(1)
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["access_token"] = "refreshed-token"
	return auth, nil
}

func (e *countingRefreshExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *countingRefreshExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func TestRefreshAuthForRequest_UsesExecutorKeyFromAuth(t *testing.T) {
	ctx := context.Background()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	executor := &countingRefreshExecutor{id: "openai-compatible-custom"}
	manager.RegisterExecutor(executor)

	auth := &Auth{
		ID:       "compat-oauth",
		Provider: "plugin-provider",
		Attributes: map[string]string{
			"compat_name":  "custom",
			"provider_key": "custom",
			"base_url":     "https://compat.example.com/v1",
		},
		Metadata: map[string]any{
			"access_token":  "old-token",
			"refresh_token": "refresh-1",
		},
	}
	if _, errRegister := manager.Register(ctx, auth); errRegister != nil {
		t.Fatalf("register auth: %v", errRegister)
	}

	refreshed, errRefresh := manager.refreshAuthForRequest(ctx, auth.ID, "old-token")
	if errRefresh != nil {
		t.Fatalf("refreshAuthForRequest() error = %v", errRefresh)
	}
	if executor.refreshCalls.Load() != 1 {
		t.Fatalf("refresh calls = %d, want 1", executor.refreshCalls.Load())
	}
	if refreshed == nil || refreshed.Metadata["access_token"] != "refreshed-token" {
		t.Fatalf("refreshed auth = %#v, want updated access_token", refreshed)
	}
}

func TestDeleteCredentialWaitsForRefreshAndWins(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	executor := &blockingRefreshExecutor{
		countingRefreshExecutor: countingRefreshExecutor{id: "openai-compatible-custom"},
		started:                 make(chan struct{}),
		release:                 make(chan struct{}),
	}
	manager.RegisterExecutor(executor)
	auth := &Auth{ID: "refresh-delete", Provider: "plugin-provider", Attributes: map[string]string{"compat_name": "custom", "provider_key": "custom"}, Metadata: map[string]any{"access_token": "old", "refresh_token": "refresh"}}
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	refreshDone := make(chan error, 1)
	go func() {
		_, errRefresh := manager.refreshAuthForRequest(context.Background(), auth.ID, "old")
		refreshDone <- errRefresh
	}()
	<-executor.started
	deleteStarted := make(chan struct{})
	deleteDone := make(chan error, 1)
	go func() {
		deleteDone <- manager.DeleteCredential(context.Background(), auth.ID, func() error {
			close(deleteStarted)
			return nil
		})
	}()
	select {
	case <-deleteStarted:
		t.Fatal("delete entered durable mutation before refresh completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(executor.release)
	if errRefresh := <-refreshDone; errRefresh != nil {
		t.Fatal(errRefresh)
	}
	if errDelete := <-deleteDone; errDelete != nil {
		t.Fatal(errDelete)
	}
	if _, exists := manager.GetByID(auth.ID); exists {
		t.Fatal("refresh resurrected deleted auth")
	}
}

package auth

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type leastPressureExecutor struct {
	mu      sync.Mutex
	calls   []string
	failID  string
	streams map[string]chan cliproxyexecutor.StreamChunk
}

func (*leastPressureExecutor) Identifier() string { return "gemini" }
func (e *leastPressureExecutor) Execute(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.mu.Lock()
	e.calls = append(e.calls, auth.ID)
	e.mu.Unlock()
	if auth.ID == e.failID {
		return cliproxyexecutor.Response{}, &Error{HTTPStatus: http.StatusServiceUnavailable, Message: "busy"}
	}
	return cliproxyexecutor.Response{Payload: []byte("ok")}, nil
}
func (e *leastPressureExecutor) ExecuteStream(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.mu.Lock()
	e.calls = append(e.calls, auth.ID)
	ch := e.streams[auth.ID]
	e.mu.Unlock()
	return &cliproxyexecutor.StreamResult{Chunks: ch}, nil
}
func (*leastPressureExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) { return auth, nil }
func (*leastPressureExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}
func (*leastPressureExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func newLeastPressureManager(t *testing.T, executor *leastPressureExecutor) *Manager {
	t.Helper()
	manager := NewManager(nil, &LeastPressureSelector{}, nil)
	manager.RegisterExecutor(executor)
	model := "gemini-test"
	for _, id := range []string{"auth-a", "auth-b"} {
		registry.GetGlobalRegistry().RegisterClient(id, "gemini", []*registry.ModelInfo{{ID: model}})
		if _, errRegister := manager.Register(context.Background(), &Auth{ID: id, Provider: "gemini", Status: StatusActive}); errRegister != nil {
			t.Fatal(errRegister)
		}
	}
	t.Cleanup(func() {
		registry.GetGlobalRegistry().UnregisterClient("auth-a")
		registry.GetGlobalRegistry().UnregisterClient("auth-b")
	})
	return manager
}

func TestLeastPressureSchedulerReservationIsAtomicAndReleasable(t *testing.T) {
	manager := newLeastPressureManager(t, &leastPressureExecutor{})
	opts := requestPressureReservation(cliproxyexecutor.Options{})

	first, _, errFirst := manager.pickNext(context.Background(), "gemini", "gemini-test", opts, nil)
	if errFirst != nil {
		t.Fatal(errFirst)
	}
	second, _, errSecond := manager.pickNext(context.Background(), "gemini", "gemini-test", opts, nil)
	if errSecond != nil {
		t.Fatal(errSecond)
	}
	if first.ID == second.ID {
		t.Fatalf("concurrent reservations selected the same auth %q", first.ID)
	}
	releaseCredentialPressure(first)
	releaseCredentialPressure(second)

	manager.scheduler.pressure.mu.Lock()
	defer manager.scheduler.pressure.mu.Unlock()
	if len(manager.scheduler.pressure.inFlight) != 0 {
		t.Fatalf("in-flight reservations leaked: %#v", manager.scheduler.pressure.inFlight)
	}
}

func TestLeastPressureRetryReleasesFailedAttemptBeforeNextCredential(t *testing.T) {
	executor := &leastPressureExecutor{failID: "auth-a"}
	manager := newLeastPressureManager(t, executor)
	manager.SetRetryConfig(0, 0, 0)

	response, errExecute := manager.Execute(context.Background(), []string{"gemini"}, cliproxyexecutor.Request{Model: "gemini-test"}, cliproxyexecutor.Options{})
	if errExecute != nil {
		t.Fatal(errExecute)
	}
	if string(response.Payload) != "ok" {
		t.Fatalf("response = %q", response.Payload)
	}
	executor.mu.Lock()
	calls := append([]string(nil), executor.calls...)
	executor.mu.Unlock()
	if len(calls) != 2 || calls[0] == calls[1] {
		t.Fatalf("calls = %#v, want failed auth then distinct retry auth", calls)
	}
	manager.scheduler.pressure.mu.Lock()
	defer manager.scheduler.pressure.mu.Unlock()
	if len(manager.scheduler.pressure.inFlight) != 0 {
		t.Fatalf("in-flight reservations leaked after retry: %#v", manager.scheduler.pressure.inFlight)
	}
}

func TestLeastPressureStreamLeaseEndsOnCompletionAndCancellation(t *testing.T) {
	for _, test := range []struct {
		name   string
		cancel bool
	}{
		{name: "completion"},
		{name: "cancellation", cancel: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			streamA := make(chan cliproxyexecutor.StreamChunk, 2)
			streamB := make(chan cliproxyexecutor.StreamChunk, 2)
			streamA <- cliproxyexecutor.StreamChunk{Payload: []byte("started")}
			streamB <- cliproxyexecutor.StreamChunk{Payload: []byte("started")}
			if !test.cancel {
				close(streamA)
				close(streamB)
			}
			executor := &leastPressureExecutor{streams: map[string]chan cliproxyexecutor.StreamChunk{"auth-a": streamA, "auth-b": streamB}}
			manager := newLeastPressureManager(t, executor)
			ctx, cancel := context.WithCancel(context.Background())
			result, errStream := manager.ExecuteStream(ctx, []string{"gemini"}, cliproxyexecutor.Request{Model: "gemini-test"}, cliproxyexecutor.Options{Stream: true})
			if errStream != nil {
				t.Fatal(errStream)
			}
			if test.cancel {
				cancel()
			}
			for range result.Chunks {
			}
			cancel()
			manager.scheduler.pressure.mu.Lock()
			leaked := len(manager.scheduler.pressure.inFlight)
			manager.scheduler.pressure.mu.Unlock()
			if leaked != 0 {
				t.Fatalf("in-flight reservations leaked: %d", leaked)
			}
		})
	}
}

func TestLeastPressureActiveStreamPushesNextStreamToAnotherCredential(t *testing.T) {
	streamA := make(chan cliproxyexecutor.StreamChunk, 1)
	streamB := make(chan cliproxyexecutor.StreamChunk, 1)
	executor := &leastPressureExecutor{streams: map[string]chan cliproxyexecutor.StreamChunk{"auth-a": streamA, "auth-b": streamB}}
	manager := newLeastPressureManager(t, executor)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, errFirst := manager.ExecuteStream(ctx, []string{"gemini"}, cliproxyexecutor.Request{Model: "gemini-test"}, cliproxyexecutor.Options{Stream: true})
	if errFirst != nil {
		t.Fatal(errFirst)
	}
	second, errSecond := manager.ExecuteStream(ctx, []string{"gemini"}, cliproxyexecutor.Request{Model: "gemini-test"}, cliproxyexecutor.Options{Stream: true})
	if errSecond != nil {
		t.Fatal(errSecond)
	}

	executor.mu.Lock()
	calls := append([]string(nil), executor.calls...)
	executor.mu.Unlock()
	if len(calls) != 2 || calls[0] == calls[1] {
		t.Fatalf("active stream calls = %#v, want distinct credentials", calls)
	}

	close(streamA)
	close(streamB)
	for range first.Chunks {
	}
	for range second.Chunks {
	}
	manager.scheduler.pressure.mu.Lock()
	leaked := len(manager.scheduler.pressure.inFlight)
	manager.scheduler.pressure.mu.Unlock()
	if leaked != 0 {
		t.Fatalf("in-flight reservations leaked after both streams completed: %d", leaked)
	}
}

func TestLeastPressureConcurrentSelectionRaceSafe(t *testing.T) {
	manager := newLeastPressureManager(t, &leastPressureExecutor{})
	var wait sync.WaitGroup
	errCh := make(chan error, 100)
	for index := 0; index < 100; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			auth, _, errPick := manager.pickNext(context.Background(), "gemini", "gemini-test", requestPressureReservation(cliproxyexecutor.Options{}), nil)
			if errPick != nil {
				errCh <- errPick
				return
			}
			releaseCredentialPressure(auth)
		}()
	}
	wait.Wait()
	close(errCh)
	for errConcurrent := range errCh {
		t.Fatal(errConcurrent)
	}
}

func TestLeastPressurePrefersCapacityAndRecentSuccess(t *testing.T) {
	now := time.Now()
	highCapacity := &Auth{ID: "high-capacity", Attributes: map[string]string{AttributeWeight: "4"}}
	lowCapacity := &Auth{ID: "low-capacity"}
	for index := 0; index < 20; index++ {
		highCapacity.recordRecentRequest(now, true)
	}
	for index := 0; index < 10; index++ {
		lowCapacity.recordRecentRequest(now, false)
	}
	tracker := &credentialPressureTracker{inFlight: map[string]int64{
		highCapacity.ID: 2,
		lowCapacity.ID:  1,
	}}

	tracker.mu.Lock()
	selected := pickLeastPressureAuth([]*Auth{lowCapacity, highCapacity}, tracker, "gemini:model", nil, now)
	tracker.mu.Unlock()
	if selected == nil || selected.ID != highCapacity.ID {
		t.Fatalf("selected = %#v, want higher-capacity recently-successful credential", selected)
	}
}

func TestLeastPressureExcludesNonPositiveCapacity(t *testing.T) {
	selector := &LeastPressureSelector{}
	disabledByCapacity := &Auth{ID: "zero", Provider: "gemini", Status: StatusActive, Attributes: map[string]string{AttributeWeight: "0"}}
	ready := &Auth{ID: "ready", Provider: "gemini", Status: StatusActive}

	selected, errPick := selector.Pick(context.Background(), "gemini", "model", cliproxyexecutor.Options{}, []*Auth{disabledByCapacity, ready})
	if errPick != nil {
		t.Fatal(errPick)
	}
	if selected.ID != ready.ID {
		t.Fatalf("selected = %q, want %q", selected.ID, ready.ID)
	}
}

func TestLeastPressureStreamPrepareCancellationReleasesLease(t *testing.T) {
	executor := &leastPressureExecutor{streams: map[string]chan cliproxyexecutor.StreamChunk{}}
	manager := newLeastPressureManager(t, executor)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = manager.ExecuteStream(ctx, []string{"gemini"}, cliproxyexecutor.Request{Model: "gemini-test"}, cliproxyexecutor.Options{Stream: true})
	manager.scheduler.pressure.mu.Lock()
	leaked := len(manager.scheduler.pressure.inFlight)
	manager.scheduler.pressure.mu.Unlock()
	if leaked != 0 {
		t.Fatalf("in-flight reservations leaked after canceled stream prepare: %d", leaked)
	}
}

package auth

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strings"
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
	streamA <- cliproxyexecutor.StreamChunk{Payload: []byte("started")}
	streamB <- cliproxyexecutor.StreamChunk{Payload: []byte("started")}
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
	selected := pickLeastPressureAuth([]*Auth{lowCapacity, highCapacity}, tracker, "gemini:model", "model", nil, now)
	tracker.mu.Unlock()
	if selected == nil || selected.ID != highCapacity.ID {
		t.Fatalf("selected = %#v, want higher-capacity recently-successful credential", selected)
	}
}

func TestLeastPressurePredictsBurstAndRefreshExpiryRisk(t *testing.T) {
	now := time.Now()
	steady := &Auth{ID: "steady"}
	bursty := &Auth{ID: "bursty"}
	for index := 0; index < 20; index++ {
		bursty.recordRecentRequest(now, true)
	}
	tracker := &credentialPressureTracker{}
	tracker.mu.Lock()
	picked := pickLeastPressureAuth([]*Auth{bursty, steady}, tracker, "burst", "model", nil, now)
	tracker.mu.Unlock()
	if picked == nil || picked.ID != steady.ID {
		t.Fatalf("burst selection = %#v, want steady", picked)
	}

	fresh := &Auth{ID: "fresh", Metadata: map[string]any{"expires_at": now.Add(time.Hour).Unix()}}
	expiring := &Auth{ID: "expiring", Metadata: map[string]any{"expires_at": now.Add(5 * time.Minute).Unix()}}
	tracker.mu.Lock()
	picked = pickLeastPressureAuth([]*Auth{expiring, fresh}, tracker, "expiry", "model", nil, now)
	tracker.mu.Unlock()
	if picked == nil || picked.ID != fresh.ID {
		t.Fatalf("expiry selection = %#v, want fresh", picked)
	}
}

func TestLeastPressureScoreSaturatesWithoutOverflow(t *testing.T) {
	auth := &Auth{ID: "saturated"}
	auth.recentRequests.buckets[0] = recentRequestBucket{bucketID: recentRequestBucketID(time.Now()), success: math.MaxInt64, failed: math.MaxInt64}
	score := credentialPressureScore(auth, "model", math.MaxInt64, credentialPressureObservation{
		latencyEWMA:         time.Duration(math.MaxInt64),
		consecutiveFailures: math.MaxInt64,
	}, time.Now())
	if score < 0 {
		t.Fatalf("overflowed pressure score = %d", score)
	}
}

func TestLeastPressurePrefersLowerLatencyAndResetsFailureStreak(t *testing.T) {
	tracker := &credentialPressureTracker{observations: map[string]credentialPressureObservation{
		"slow": {latencyEWMA: 5 * time.Second},
		"fast": {latencyEWMA: 50 * time.Millisecond},
	}}
	slow := &Auth{ID: "slow"}
	fast := &Auth{ID: "fast"}

	tracker.mu.Lock()
	picked := pickLeastPressureAuth([]*Auth{slow, fast}, tracker, "latency", "model", nil, time.Now())
	tracker.mu.Unlock()
	if picked == nil || picked.ID != fast.ID {
		t.Fatalf("latency selection = %#v, want fast", picked)
	}

	tracker.observeOutcome(fast.ID, false)
	tracker.observeOutcome(fast.ID, false)
	tracker.observeOutcome(fast.ID, true)
	tracker.mu.Lock()
	observation := tracker.observations[fast.ID]
	tracker.mu.Unlock()
	if observation.consecutiveFailures != 0 {
		t.Fatalf("consecutive failures = %d, want reset after success", observation.consecutiveFailures)
	}
}

func TestLeastPressurePenalizesFailureStreakAndQuotaRecoveryRisk(t *testing.T) {
	now := time.Now()
	model := "model"
	tracker := &credentialPressureTracker{observations: map[string]credentialPressureObservation{
		"flaky": {consecutiveFailures: 3},
	}}
	flaky := &Auth{ID: "flaky"}
	steady := &Auth{ID: "steady"}
	tracker.mu.Lock()
	picked := pickLeastPressureAuth([]*Auth{flaky, steady}, tracker, "failures", model, nil, now)
	tracker.mu.Unlock()
	if picked == nil || picked.ID != steady.ID {
		t.Fatalf("failure selection = %#v, want steady", picked)
	}

	recovering := &Auth{ID: "recovering", ModelStates: map[string]*ModelState{
		model: {Quota: QuotaState{BackoffLevel: 4}},
	}}
	clean := &Auth{ID: "clean"}
	tracker.mu.Lock()
	picked = pickLeastPressureAuth([]*Auth{recovering, clean}, tracker, "quota", model, nil, now)
	tracker.mu.Unlock()
	if picked == nil || picked.ID != clean.ID {
		t.Fatalf("quota recovery selection = %#v, want clean", picked)
	}

	authLevelRecovering := &Auth{ID: "auth-level-recovering", Quota: QuotaState{BackoffLevel: 2}, ModelStates: map[string]*ModelState{
		model: {},
	}}
	tracker.mu.Lock()
	picked = pickLeastPressureAuth([]*Auth{authLevelRecovering, clean}, tracker, "auth-quota", model, nil, now)
	tracker.mu.Unlock()
	if picked == nil || picked.ID != clean.ID {
		t.Fatalf("auth-level quota selection = %#v, want clean", picked)
	}
}

func TestLeastPressureLeaseRecordsBoundedLatencyEWMA(t *testing.T) {
	tracker := &credentialPressureTracker{inFlight: map[string]int64{"auth": 1}}
	lease := &credentialPressureLease{tracker: tracker, authID: "auth", startedAt: time.Now().Add(-100 * time.Millisecond)}
	lease.Release()
	lease.Release()
	tracker.mu.Lock()
	observation := tracker.observations["auth"]
	leaked := tracker.inFlight["auth"]
	tracker.mu.Unlock()
	if leaked != 0 {
		t.Fatalf("in-flight = %d, want released", leaked)
	}
	if observation.latencyEWMA < 50*time.Millisecond || observation.latencyEWMA > time.Second {
		t.Fatalf("latency EWMA = %s, want measured request duration", observation.latencyEWMA)
	}
}

func TestLeastPressureObservationMapIsBounded(t *testing.T) {
	tracker := &credentialPressureTracker{observations: make(map[string]credentialPressureObservation, maxCredentialPressureObservations)}
	for index := 0; index < maxCredentialPressureObservations; index++ {
		tracker.observations[fmt.Sprintf("auth-%d", index)] = credentialPressureObservation{latencyEWMA: time.Second}
	}
	tracker.observeOutcome("new-auth", false)
	tracker.mu.Lock()
	count := len(tracker.observations)
	_, found := tracker.observations["new-auth"]
	tracker.mu.Unlock()
	if !found || count != 1 {
		t.Fatalf("observations count=%d found_new=%t, want bounded reset", count, found)
	}
}

func TestLeastPressureManagerOutcomeObservationIsRaceSafe(t *testing.T) {
	manager := newLeastPressureManager(t, &leastPressureExecutor{})
	const observations = 200
	var wait sync.WaitGroup
	for index := 0; index < observations; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			manager.observeCredentialPressureOutcome(Result{AuthID: "auth-a", Success: index%3 == 0})
		}(index)
	}
	wait.Wait()
	tracker := manager.selector.(*LeastPressureSelector).tracker()
	tracker.mu.Lock()
	_, found := tracker.observations["auth-a"]
	tracker.mu.Unlock()
	if !found {
		t.Fatal("expected pressure outcome observation")
	}
}

func TestLeastPressureDoesNotPenalizeRequestOrCancellationFaults(t *testing.T) {
	manager := newLeastPressureManager(t, &leastPressureExecutor{})
	for _, resultErr := range []*Error{
		{HTTPStatus: http.StatusBadRequest, Message: "invalid request"},
		{Code: requestScopedErrorCode, Message: "client canceled"},
	} {
		manager.observeCredentialPressureOutcome(Result{AuthID: "auth-a", Success: false, Error: resultErr})
	}
	tracker := manager.selector.(*LeastPressureSelector).tracker()
	tracker.mu.Lock()
	observation := tracker.observations["auth-a"]
	tracker.mu.Unlock()
	if observation.consecutiveFailures != 0 {
		t.Fatalf("request-scoped failures changed streak to %d", observation.consecutiveFailures)
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

func TestLeastPressureMixedProviderExcludesNonPositiveCapacity(t *testing.T) {
	manager := NewManager(nil, &LeastPressureSelector{}, nil)
	geminiExec := &leastPressureExecutor{}
	manager.RegisterExecutor(geminiExec)
	otherExec := &namedLeastPressureExecutor{id: "claude"}
	manager.RegisterExecutor(otherExec)
	model := "shared-pressure-model"
	for _, auth := range []*Auth{
		{ID: "gemini-zero", Provider: "gemini", Status: StatusActive, Attributes: map[string]string{AttributeWeight: "0"}},
		{ID: "claude-ready", Provider: "claude", Status: StatusActive},
	} {
		registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: model}})
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatal(errRegister)
		}
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
	}
	auth, _, provider, errPick := manager.pickNextMixed(context.Background(), []string{"gemini", "claude"}, model, requestPressureReservation(cliproxyexecutor.Options{}), nil)
	if errPick != nil {
		t.Fatal(errPick)
	}
	defer releaseCredentialPressure(auth)
	if auth.ID != "claude-ready" || provider != "claude" {
		t.Fatalf("auth=%q provider=%q, zero-capacity mixed candidate was admitted", auth.ID, provider)
	}
}

func TestLeastPressureMixedProviderChoosesLowerPressure(t *testing.T) {
	manager := NewManager(nil, &LeastPressureSelector{}, nil)
	manager.RegisterExecutor(&leastPressureExecutor{})
	manager.RegisterExecutor(&namedLeastPressureExecutor{id: "claude"})
	model := "mixed-lower-pressure-model"
	for _, auth := range []*Auth{
		{ID: "gemini-busy", Provider: "gemini", Status: StatusActive},
		{ID: "claude-idle", Provider: "claude", Status: StatusActive},
	} {
		registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: model}})
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatal(errRegister)
		}
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
	}
	manager.scheduler.pressure.mu.Lock()
	if manager.scheduler.pressure.inFlight == nil {
		manager.scheduler.pressure.inFlight = make(map[string]int64)
	}
	manager.scheduler.pressure.inFlight["gemini-busy"] = 3
	manager.scheduler.pressure.mu.Unlock()
	picked, _, provider, errPick := manager.pickNextMixed(context.Background(), []string{"gemini", "claude"}, model, requestPressureReservation(cliproxyexecutor.Options{}), nil)
	if errPick != nil {
		t.Fatal(errPick)
	}
	defer releaseCredentialPressure(picked)
	if picked.ID != "claude-idle" || provider != "claude" {
		t.Fatalf("picked=%q provider=%q, want idle Claude credential", picked.ID, provider)
	}
}

func TestLeastPressureRespectsPriorityBeforePressure(t *testing.T) {
	selector := &LeastPressureSelector{}
	busyHigh := &Auth{ID: "busy-high", Provider: "gemini", Status: StatusActive, Attributes: map[string]string{"priority": "10"}}
	idleLow := &Auth{ID: "idle-low", Provider: "gemini", Status: StatusActive, Attributes: map[string]string{"priority": "0"}}
	selector.pressure.inFlight = map[string]int64{busyHigh.ID: 100}
	picked, errPick := selector.Pick(context.Background(), "gemini", "model", cliproxyexecutor.Options{}, []*Auth{idleLow, busyHigh})
	if errPick != nil {
		t.Fatal(errPick)
	}
	if picked.ID != busyHigh.ID {
		t.Fatalf("picked=%q, want higher-priority credential despite pressure", picked.ID)
	}
}

func TestLeastPressureExcludesCooldownUnavailableAndDisabled(t *testing.T) {
	selector := &LeastPressureSelector{}
	model := "model"
	now := time.Now()
	auths := []*Auth{
		{ID: "disabled", Provider: "gemini", Status: StatusActive, Disabled: true},
		{ID: "unavailable", Provider: "gemini", Status: StatusActive, Unavailable: true},
		{ID: "cooling", Provider: "gemini", Status: StatusActive, ModelStates: map[string]*ModelState{model: {Status: StatusActive, Unavailable: true, NextRetryAfter: now.Add(time.Hour)}}},
		{ID: "ready", Provider: "gemini", Status: StatusActive},
	}
	picked, errPick := selector.Pick(context.Background(), "gemini", model, cliproxyexecutor.Options{}, auths)
	if errPick != nil {
		t.Fatal(errPick)
	}
	if picked.ID != "ready" {
		t.Fatalf("picked=%q, want only ready credential", picked.ID)
	}
}

func TestLeastPressureEqualScoreTieRotationIsFair(t *testing.T) {
	selector := &LeastPressureSelector{}
	auths := []*Auth{
		{ID: "auth-a", Provider: "gemini", Status: StatusActive},
		{ID: "auth-b", Provider: "gemini", Status: StatusActive},
		{ID: "auth-c", Provider: "gemini", Status: StatusActive},
	}
	counts := make(map[string]int)
	for index := 0; index < 300; index++ {
		picked, errPick := selector.Pick(context.Background(), "gemini", "model", cliproxyexecutor.Options{}, auths)
		if errPick != nil {
			t.Fatal(errPick)
		}
		counts[picked.ID]++
	}
	for _, auth := range auths {
		if counts[auth.ID] != 100 {
			t.Fatalf("counts=%#v, want exact equal-score rotation", counts)
		}
	}
}

type routingEventCapture struct {
	mu     sync.Mutex
	events []cliproxyexecutor.RoutingEvent
}

func (c *routingEventCapture) ObserveRouting(event cliproxyexecutor.RoutingEvent) {
	c.mu.Lock()
	c.events = append(c.events, event)
	c.mu.Unlock()
}

func TestShadowLeastPressurePredictsWithoutChangingProductionSelection(t *testing.T) {
	fallback := &RoundRobinSelector{}
	selector := NewShadowLeastPressureSelector(fallback)
	busy := &Auth{ID: "auth-a", Provider: "gemini", Status: StatusActive}
	idle := &Auth{ID: "auth-b", Provider: "gemini", Status: StatusActive}
	selector.pressure.inFlight = map[string]int64{busy.ID: 10}
	observer := &routingEventCapture{}
	opts := cliproxyexecutor.Options{RoutingObserver: observer}

	first, errFirst := selector.Pick(context.Background(), "gemini", "model", opts, []*Auth{busy, idle})
	if errFirst != nil {
		t.Fatal(errFirst)
	}
	second, errSecond := selector.Pick(context.Background(), "gemini", "model", opts, []*Auth{busy, idle})
	if errSecond != nil {
		t.Fatal(errSecond)
	}
	if first.ID != busy.ID || second.ID != idle.ID {
		t.Fatalf("production round-robin changed: first=%q second=%q", first.ID, second.ID)
	}
	if len(selector.pressure.inFlight) != 1 || selector.pressure.inFlight[busy.ID] != 10 {
		t.Fatalf("shadow prediction mutated in-flight state: %#v", selector.pressure.inFlight)
	}
	if len(selector.pressure.cursors) != 0 {
		t.Fatalf("shadow prediction mutated tie cursors: %#v", selector.pressure.cursors)
	}
	observer.mu.Lock()
	events := append([]cliproxyexecutor.RoutingEvent(nil), observer.events...)
	observer.mu.Unlock()
	if len(events) != 2 || events[0].Stage != "account_prediction" || events[0].ShadowMatch || !events[1].ShadowMatch {
		t.Fatalf("shadow events = %#v", events)
	}
	if events[0].SeatBucket != routingSeatBucket(busy.ID) || events[1].SeatBucket != routingSeatBucket(idle.ID) ||
		strings.Contains(events[0].SeatBucket+events[1].SeatBucket, "auth-") {
		t.Fatalf("shadow seat buckets = %#v", events)
	}
	if events[0].PredictedSeatBucket != routingSeatBucket(idle.ID) || events[1].PredictedSeatBucket != routingSeatBucket(idle.ID) {
		t.Fatalf("shadow predicted seat buckets = %#v", events)
	}
}

func TestShadowLeastPressureReservationTracksActualNotPrediction(t *testing.T) {
	selector := NewShadowLeastPressureSelector(&RoundRobinSelector{})
	busy := &Auth{ID: "auth-a", Provider: "gemini", Status: StatusActive}
	idle := &Auth{ID: "auth-b", Provider: "gemini", Status: StatusActive}
	selector.pressure.inFlight = map[string]int64{busy.ID: 10}
	selected, errPick := selector.Pick(context.Background(), "gemini", "model", requestPressureReservation(cliproxyexecutor.Options{}), []*Auth{busy, idle})
	if errPick != nil {
		t.Fatal(errPick)
	}
	if selected.ID != busy.ID || selector.pressure.inFlight[busy.ID] != 11 || selector.pressure.inFlight[idle.ID] != 0 {
		t.Fatalf("selected=%q pressure=%#v", selected.ID, selector.pressure.inFlight)
	}
	releaseCredentialPressure(selected)
	if selector.pressure.inFlight[busy.ID] != 10 {
		t.Fatalf("actual reservation did not release: %#v", selector.pressure.inFlight)
	}
}

func TestLeastPressureConcurrentLoadIsDistributedAndLeakFree(t *testing.T) {
	manager := newLeastPressureManager(t, &leastPressureExecutor{})
	var wait sync.WaitGroup
	var countsMu sync.Mutex
	counts := make(map[string]int)
	errorsCh := make(chan error, 300)
	for index := 0; index < 300; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			picked, _, errPick := manager.pickNext(context.Background(), "gemini", "gemini-test", requestPressureReservation(cliproxyexecutor.Options{}), nil)
			if errPick != nil {
				errorsCh <- errPick
				return
			}
			countsMu.Lock()
			counts[picked.ID]++
			countsMu.Unlock()
			releaseCredentialPressure(picked)
		}()
	}
	wait.Wait()
	close(errorsCh)
	for errConcurrent := range errorsCh {
		t.Fatal(errConcurrent)
	}
	if counts["auth-a"] == 0 || counts["auth-b"] == 0 {
		t.Fatalf("load was not distributed: %#v", counts)
	}
	manager.scheduler.pressure.mu.Lock()
	leaked := len(manager.scheduler.pressure.inFlight)
	manager.scheduler.pressure.mu.Unlock()
	if leaked != 0 {
		t.Fatalf("in-flight reservations leaked after load: %d", leaked)
	}
}

func TestLeastPressureStreamBootstrapFailureReleasesEveryLease(t *testing.T) {
	executor := &leastPressureExecutor{streams: map[string]chan cliproxyexecutor.StreamChunk{}}
	manager := newLeastPressureManager(t, executor)
	_, errStream := manager.ExecuteStream(context.Background(), []string{"gemini"}, cliproxyexecutor.Request{Model: "gemini-test"}, cliproxyexecutor.Options{Stream: true})
	if errStream == nil {
		t.Fatal("expected invalid stream error")
	}
	manager.scheduler.pressure.mu.Lock()
	leaked := len(manager.scheduler.pressure.inFlight)
	manager.scheduler.pressure.mu.Unlock()
	if leaked != 0 {
		t.Fatalf("in-flight reservations leaked after bootstrap failures: %d", leaked)
	}
}

func TestLeastPressureSelectorRollbackRestoresRoundRobin(t *testing.T) {
	manager := newLeastPressureManager(t, &leastPressureExecutor{})
	if _, ok := manager.Selector().(*LeastPressureSelector); !ok {
		t.Fatalf("initial selector = %T", manager.Selector())
	}
	manager.SetSelector(&RoundRobinSelector{})
	if _, ok := manager.Selector().(*RoundRobinSelector); !ok {
		t.Fatalf("rolled-back selector = %T", manager.Selector())
	}
	if manager.scheduler.strategy != schedulerStrategyRoundRobin || manager.scheduler.pressure != nil {
		t.Fatalf("scheduler rollback strategy=%v pressure=%#v", manager.scheduler.strategy, manager.scheduler.pressure)
	}
	first, _, errFirst := manager.pickNext(context.Background(), "gemini", "gemini-test", cliproxyexecutor.Options{}, nil)
	second, _, errSecond := manager.pickNext(context.Background(), "gemini", "gemini-test", cliproxyexecutor.Options{}, nil)
	if errFirst != nil || errSecond != nil || first.ID == second.ID {
		t.Fatalf("round-robin after rollback first=%#v second=%#v errors=(%v,%v)", first, second, errFirst, errSecond)
	}
}

type namedLeastPressureExecutor struct{ id string }

func (e *namedLeastPressureExecutor) Identifier() string { return e.id }
func (*namedLeastPressureExecutor) Execute(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}
func (*namedLeastPressureExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}
func (*namedLeastPressureExecutor) Refresh(context.Context, *Auth) (*Auth, error) { return nil, nil }
func (*namedLeastPressureExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}
func (*namedLeastPressureExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

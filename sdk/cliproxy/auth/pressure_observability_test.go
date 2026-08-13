package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestRoutingPressureSnapshotIsOpaqueSortedAndCapacityNormalized(t *testing.T) {
	manager := NewManager(nil, &LeastPressureSelector{}, nil)
	auths := []*Auth{
		{ID: "private-seat-b@example.test", Provider: "gemini", Status: StatusActive, Attributes: map[string]string{AttributeWeight: "4"}},
		{ID: "/opt/crsproxy/auths/private-seat-a.json", Provider: "gemini", Status: StatusActive},
	}
	for _, auth := range auths {
		if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
			t.Fatal(errRegister)
		}
	}
	tracker := manager.selector.(*LeastPressureSelector).tracker()
	tracker.mu.Lock()
	tracker.inFlight = map[string]int64{auths[0].ID: 2, auths[1].ID: 1}
	tracker.mu.Unlock()

	snapshot := manager.RoutingPressureSnapshot()
	if snapshot.SchemaVersion != 1 || snapshot.Selector != "least_pressure" || snapshot.ActiveLeases != 3 || snapshot.ActiveSeats != 2 || len(snapshot.Seats) != 2 {
		t.Fatalf("snapshot = %#v", snapshot)
	}
	opaque := regexp.MustCompile(`^h1_[0-9a-f]{16}$`)
	pressures := map[int64]int64{}
	for index, seat := range snapshot.Seats {
		if !opaque.MatchString(seat.SeatBucket) {
			t.Fatalf("seat bucket = %q, want opaque bucket", seat.SeatBucket)
		}
		if index > 0 && snapshot.Seats[index-1].SeatBucket >= seat.SeatBucket {
			t.Fatalf("seats not deterministically sorted: %#v", snapshot.Seats)
		}
		pressures[seat.Capacity] = seat.ConcurrencyPressureMilli
	}
	if pressures[1] != 1000 || pressures[4] != 500 {
		t.Fatalf("normalized pressures = %#v, want capacity 1 => 1000 and capacity 4 => 500", pressures)
	}
	raw, errJSON := json.Marshal(snapshot)
	if errJSON != nil {
		t.Fatal(errJSON)
	}
	for _, forbidden := range []string{auths[0].ID, auths[1].ID, "private-seat", "@example.test", "/opt/crsproxy/auths", "gemini"} {
		if regexp.MustCompile(regexp.QuoteMeta(forbidden)).Match(raw) {
			t.Fatalf("snapshot leaked %q: %s", forbidden, raw)
		}
	}
}

func TestRoutingPressureSnapshotSchemaCannotCarrySensitiveMaterial(t *testing.T) {
	for _, value := range []any{RoutingPressureSnapshot{}, RoutingPressureSeat{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			name := typeOf.Field(index).Name
			for _, forbidden := range []string{"Auth", "ID", "Model", "Provider", "Token", "Email", "Path", "Metadata", "Latency", "Quota", "Failure"} {
				if regexp.MustCompile(`(?i)` + forbidden).MatchString(name) {
					t.Fatalf("field %s can carry forbidden %s material", name, forbidden)
				}
			}
		}
	}
}

func TestRoutingPressureSnapshotConcurrentReserveReleaseReturnsToZero(t *testing.T) {
	manager := newLeastPressureManager(t, &leastPressureExecutor{})
	const workers = 100
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			auth, _, errPick := manager.pickNext(context.Background(), "gemini", "gemini-test", requestPressureReservation(cliproxyexecutor.Options{}), nil)
			if errPick != nil {
				t.Errorf("pick: %v", errPick)
				return
			}
			_ = manager.RoutingPressureSnapshot()
			releaseCredentialPressure(auth)
		}()
	}
	wait.Wait()
	snapshot := manager.RoutingPressureSnapshot()
	if snapshot.ActiveLeases != 0 || snapshot.ActiveSeats != 0 || len(snapshot.Seats) != 0 {
		t.Fatalf("final snapshot = %#v, want zero active pressure", snapshot)
	}
}

type panicPressureExecutor struct {
	count bool
}

func (*panicPressureExecutor) Identifier() string { return "panic-pressure" }
func (e *panicPressureExecutor) Execute(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if !e.count {
		panic("execute panic")
	}
	return cliproxyexecutor.Response{}, nil
}
func (*panicPressureExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	panic("stream panic")
}

func TestLeastPressureRecoveredStreamPanicReleasesLeaseAndTerminatesAttempt(t *testing.T) {
	executor := &panicPressureExecutor{}
	manager := NewManager(nil, &LeastPressureSelector{}, nil)
	manager.RegisterExecutor(executor)
	model := "panic-stream-model"
	registry.GetGlobalRegistry().RegisterClient("panic-stream-seat", executor.Identifier(), []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient("panic-stream-seat") })
	if _, errRegister := manager.Register(context.Background(), &Auth{ID: "panic-stream-seat", Provider: executor.Identifier(), Status: StatusActive}); errRegister != nil {
		t.Fatal(errRegister)
	}
	observer := &pressureRoutingObserver{}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("expected stream executor panic")
			}
		}()
		_, _ = manager.ExecuteStream(context.Background(), []string{executor.Identifier()}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{RoutingObserver: observer})
	}()
	if snapshot := manager.RoutingPressureSnapshot(); snapshot.ActiveLeases != 0 || snapshot.ActiveSeats != 0 {
		t.Fatalf("post-panic snapshot = %#v, want zero active pressure", snapshot)
	}
	events := observer.Events()
	if len(events) != 2 || events[0].Stage != "account_selection" || events[0].Outcome != "selected" || events[1].Stage != "account_attempt" || events[1].Outcome != "failed" || events[0].Attempt != events[1].Attempt {
		t.Fatalf("panic events = %#v, want exactly selected/failed pair", events)
	}
}
func (*panicPressureExecutor) Refresh(context.Context, *Auth) (*Auth, error) { return nil, nil }
func (e *panicPressureExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if e.count {
		panic("count panic")
	}
	return cliproxyexecutor.Response{}, nil
}
func (*panicPressureExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func TestLeastPressureRecoveredPanicReleasesNonStreamAndCountLeases(t *testing.T) {
	for _, count := range []bool{false, true} {
		t.Run(map[bool]string{false: "execute", true: "count"}[count], func(t *testing.T) {
			executor := &panicPressureExecutor{count: count}
			manager := NewManager(nil, &LeastPressureSelector{}, nil)
			manager.RegisterExecutor(executor)
			model := "panic-model"
			registry.GetGlobalRegistry().RegisterClient("panic-seat", executor.Identifier(), []*registry.ModelInfo{{ID: model}})
			t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient("panic-seat") })
			if _, errRegister := manager.Register(context.Background(), &Auth{ID: "panic-seat", Provider: executor.Identifier(), Status: StatusActive}); errRegister != nil {
				t.Fatal(errRegister)
			}

			func() {
				defer func() {
					if recover() == nil {
						t.Fatal("expected executor panic")
					}
				}()
				if count {
					_, _ = manager.ExecuteCount(context.Background(), []string{executor.Identifier()}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
					return
				}
				_, _ = manager.Execute(context.Background(), []string{executor.Identifier()}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
			}()

			snapshot := manager.RoutingPressureSnapshot()
			if snapshot.ActiveLeases != 0 || snapshot.ActiveSeats != 0 {
				t.Fatalf("post-panic snapshot = %#v, want zero active pressure", snapshot)
			}
		})
	}
}

type pressureRoutingObserver struct {
	mu     sync.Mutex
	events []cliproxyexecutor.RoutingEvent
}

type routingFaultExecutor struct {
	err error
}

func (*routingFaultExecutor) Identifier() string { return "routing-fault" }
func (e *routingFaultExecutor) Execute(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, e.err
}
func (e *routingFaultExecutor) ExecuteStream(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, e.err
}
func (*routingFaultExecutor) Refresh(context.Context, *Auth) (*Auth, error) { return nil, nil }
func (*routingFaultExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}
func (*routingFaultExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func (o *pressureRoutingObserver) ObserveRouting(event cliproxyexecutor.RoutingEvent) {
	o.mu.Lock()
	o.events = append(o.events, event)
	o.mu.Unlock()
}

func (o *pressureRoutingObserver) Events() []cliproxyexecutor.RoutingEvent {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]cliproxyexecutor.RoutingEvent(nil), o.events...)
}

func TestAccountRoutingSelectedAndTerminalEventsCorrelateAcrossRetry(t *testing.T) {
	executor := &leastPressureExecutor{failID: "auth-a"}
	manager := newLeastPressureManager(t, executor)
	manager.SetRetryConfig(0, 0, 0)
	observer := &pressureRoutingObserver{}
	rawRequestID := "private-request-id-person@example.test"
	ctx := logging.WithRequestID(context.Background(), rawRequestID)

	response, errExecute := manager.Execute(ctx, []string{"gemini"}, cliproxyexecutor.Request{Model: "gemini-test"}, cliproxyexecutor.Options{RoutingObserver: observer})
	if errExecute != nil || string(response.Payload) != "ok" {
		t.Fatalf("response=%q err=%v", response.Payload, errExecute)
	}
	events := observer.Events()
	if len(events) != 4 {
		t.Fatalf("events=%#v, want selected/failed then selected/success", events)
	}
	requestBucket := events[0].RequestBucket
	if requestBucket == "" || strings.Contains(requestBucket, "private") {
		t.Fatalf("request bucket=%q, want opaque nonempty bucket", requestBucket)
	}
	terminalBySeat := make(map[string]string)
	selectedBySeat := make(map[string]bool)
	ordinals := make(map[int]int)
	for _, event := range events {
		if (event.Stage != "account_selection" && event.Stage != "account_attempt") || event.RequestBucket != requestBucket {
			t.Fatalf("uncorrelated event=%#v, bucket=%q", event, requestBucket)
		}
		if event.SeatBucket == "" || strings.Contains(event.SeatBucket, "auth-") {
			t.Fatalf("seat bucket leaked identity: %#v", event)
		}
		switch event.Outcome {
		case "selected":
			if event.Stage != "account_selection" {
				t.Fatalf("selected stage=%q, want account_selection", event.Stage)
			}
			selectedBySeat[event.SeatBucket] = true
		case "failed", "success":
			if event.Stage != "account_attempt" {
				t.Fatalf("terminal stage=%q, want account_attempt", event.Stage)
			}
			terminalBySeat[event.SeatBucket] = event.Outcome
		default:
			t.Fatalf("unexpected outcome=%q", event.Outcome)
		}
		ordinals[event.Attempt]++
	}
	if len(selectedBySeat) != 2 || len(terminalBySeat) != 2 {
		t.Fatalf("selected=%#v terminal=%#v", selectedBySeat, terminalBySeat)
	}
	seenFailure := false
	seenSuccess := false
	for seat, outcome := range terminalBySeat {
		if !selectedBySeat[seat] {
			t.Fatalf("terminal event for unselected seat %q", seat)
		}
		seenFailure = seenFailure || outcome == "failed"
		seenSuccess = seenSuccess || outcome == "success"
	}
	if !seenFailure || !seenSuccess {
		t.Fatalf("terminal outcomes=%#v, want failure and success", terminalBySeat)
	}
	if !reflect.DeepEqual(ordinals, map[int]int{1: 2, 2: 2}) {
		t.Fatalf("attempt ordinals=%#v, want exactly paired monotonic ordinals", ordinals)
	}
	raw, errJSON := json.Marshal(events)
	if errJSON != nil {
		t.Fatal(errJSON)
	}
	if strings.Contains(string(raw), rawRequestID) || strings.Contains(string(raw), "person@example.test") || strings.Contains(string(raw), "auth-a") || strings.Contains(string(raw), "auth-b") {
		t.Fatalf("routing events leaked identity: %s", raw)
	}
}

func TestAccountRoutingModelPoolEmitsOneTerminalForOneSelection(t *testing.T) {
	alias := "private-pool-alias"
	executor := &openAICompatPoolExecutor{
		id: openAICompatPoolProviderKey,
		executeErrors: map[string]error{
			"first-upstream": &Error{HTTPStatus: http.StatusBadRequest, Message: "requested model is not supported"},
		},
	}
	manager := newOpenAICompatPoolTestManager(t, alias, []internalconfig.OpenAICompatibilityModel{
		{Name: "first-upstream", Alias: alias},
		{Name: "second-upstream", Alias: alias},
	}, executor)
	observer := &pressureRoutingObserver{}
	ctx := logging.WithRequestID(context.Background(), "private-pool-request")
	response, errExecute := manager.Execute(ctx, []string{openAICompatPoolProviderKey}, cliproxyexecutor.Request{Model: alias}, cliproxyexecutor.Options{RoutingObserver: observer})
	if errExecute != nil || string(response.Payload) != "second-upstream" {
		t.Fatalf("response=%q err=%v", response.Payload, errExecute)
	}
	if got := executor.ExecuteModels(); !reflect.DeepEqual(got, []string{"first-upstream", "second-upstream"}) {
		t.Fatalf("upstream attempts=%v", got)
	}
	events := observer.Events()
	if len(events) != 2 || events[0].Stage != "account_selection" || events[0].Outcome != "selected" || events[1].Stage != "account_attempt" || events[1].Outcome != "success" || events[0].Attempt != events[1].Attempt {
		t.Fatalf("pool events=%#v, want one selected/success pair", events)
	}
}

func TestAccountRoutingRequestFaultAndCancellationPairExactly(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		outcome string
	}{
		{name: "request-invalid", err: &Error{HTTPStatus: http.StatusBadRequest, Message: "invalid request"}, outcome: "rejected"},
		{name: "canceled", err: context.Canceled, outcome: "canceled"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			executor := &routingFaultExecutor{err: tc.err}
			manager := NewManager(nil, &LeastPressureSelector{}, nil)
			manager.RegisterExecutor(executor)
			model := "routing-fault-model"
			authID := "routing-fault-seat-" + tc.name
			registry.GetGlobalRegistry().RegisterClient(authID, executor.Identifier(), []*registry.ModelInfo{{ID: model}})
			t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(authID) })
			if _, errRegister := manager.Register(context.Background(), &Auth{ID: authID, Provider: executor.Identifier(), Status: StatusActive}); errRegister != nil {
				t.Fatal(errRegister)
			}
			observer := &pressureRoutingObserver{}
			_, errExecute := manager.Execute(context.Background(), []string{executor.Identifier()}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{RoutingObserver: observer})
			if !errors.Is(errExecute, tc.err) && (errExecute == nil || errExecute.Error() != tc.err.Error()) {
				t.Fatalf("execute error=%v, want %v", errExecute, tc.err)
			}
			events := observer.Events()
			if len(events) != 2 || events[0].Stage != "account_selection" || events[1].Stage != "account_attempt" || events[1].Outcome != tc.outcome || events[0].Attempt != events[1].Attempt {
				t.Fatalf("events=%#v, want selected/%s pair", events, tc.outcome)
			}
		})
	}
}

func TestAccountRoutingCountPairsSelectionAndTerminal(t *testing.T) {
	manager := newLeastPressureManager(t, &leastPressureExecutor{})
	observer := &pressureRoutingObserver{}
	_, errCount := manager.ExecuteCount(context.Background(), []string{"gemini"}, cliproxyexecutor.Request{Model: "gemini-test"}, cliproxyexecutor.Options{RoutingObserver: observer})
	if errCount != nil {
		t.Fatal(errCount)
	}
	events := observer.Events()
	if len(events) != 2 || events[0].Stage != "account_selection" || events[0].Outcome != "selected" || events[1].Stage != "account_attempt" || events[1].Outcome != "success" || events[0].Attempt != events[1].Attempt {
		t.Fatalf("count events=%#v, want selected/success pair", events)
	}
}

func TestAccountRoutingStreamSuccessWaitsForCompletion(t *testing.T) {
	chunks := make(chan cliproxyexecutor.StreamChunk, 1)
	chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("ok")}
	executor := &leastPressureExecutor{streams: map[string]chan cliproxyexecutor.StreamChunk{"auth-a": chunks}}
	manager := newLeastPressureManager(t, executor)
	observer := &pressureRoutingObserver{}
	result, errStream := manager.ExecuteStream(context.Background(), []string{"gemini"}, cliproxyexecutor.Request{Model: "gemini-test"}, cliproxyexecutor.Options{RoutingObserver: observer})
	if errStream != nil {
		t.Fatal(errStream)
	}
	if events := observer.Events(); len(events) != 1 || events[0].Outcome != "selected" {
		t.Fatalf("pre-completion events=%#v, want selection only", events)
	}
	close(chunks)
	for range result.Chunks {
	}
	events := observer.Events()
	if len(events) != 2 || events[1].Stage != "account_attempt" || events[1].Outcome != "success" {
		t.Fatalf("completed stream events=%#v, want selected/success", events)
	}
}

func TestAccountRoutingSilentStreamCancellationPairsTerminalAndReleasesLease(t *testing.T) {
	chunks := make(chan cliproxyexecutor.StreamChunk, 1)
	chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("started")}
	executor := &leastPressureExecutor{streams: map[string]chan cliproxyexecutor.StreamChunk{"auth-a": chunks}}
	manager := newLeastPressureManager(t, executor)
	observer := &pressureRoutingObserver{}
	ctx, cancel := context.WithCancel(context.Background())
	result, errStream := manager.ExecuteStream(ctx, []string{"gemini"}, cliproxyexecutor.Request{Model: "gemini-test"}, cliproxyexecutor.Options{RoutingObserver: observer})
	if errStream != nil {
		t.Fatal(errStream)
	}
	if chunk := <-result.Chunks; chunk.Err != nil || string(chunk.Payload) != "started" {
		t.Fatalf("first chunk = %#v", chunk)
	}
	cancel()
	select {
	case _, open := <-result.Chunks:
		if open {
			t.Fatal("canceled stream remained open")
		}
	case <-time.After(time.Second):
		t.Fatal("canceled silent stream did not close")
	}
	var events []cliproxyexecutor.RoutingEvent
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		events = observer.Events()
		if len(events) == 2 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if len(events) != 2 || events[0].Stage != "account_selection" || events[1].Stage != "account_attempt" || events[1].Outcome != "canceled" || events[0].Attempt != events[1].Attempt {
		t.Fatalf("canceled stream events = %#v, want selected/canceled pair", events)
	}
	if snapshot := manager.RoutingPressureSnapshot(); snapshot.ActiveLeases != 0 || snapshot.ActiveSeats != 0 {
		t.Fatalf("post-cancel snapshot = %#v, want zero active pressure", snapshot)
	}
	close(chunks)
}

func TestMarkResultRequestFaultsAreRecentAndFailureCounterNeutral(t *testing.T) {
	manager := newLeastPressureManager(t, &leastPressureExecutor{})
	before, _ := manager.GetByID("auth-a")
	beforeRecent := before.RecentRequestsSnapshot(time.Now())
	for _, errResult := range []*Error{
		{HTTPStatus: http.StatusBadRequest, Message: "invalid request"},
		{Code: requestScopedErrorCode, Message: "client canceled"},
	} {
		manager.MarkResult(context.Background(), Result{AuthID: "auth-a", Provider: "gemini", Model: "gemini-test", Success: false, Error: errResult})
	}
	after, _ := manager.GetByID("auth-a")
	if after.Failed != before.Failed || after.Success != before.Success {
		t.Fatalf("totals changed from success=%d failed=%d to success=%d failed=%d", before.Success, before.Failed, after.Success, after.Failed)
	}
	if got := after.RecentRequestsSnapshot(time.Now()); !reflect.DeepEqual(got, beforeRecent) {
		t.Fatalf("recent request counters changed:\nbefore=%#v\nafter=%#v", beforeRecent, got)
	}
	tracker := manager.selector.(*LeastPressureSelector).tracker()
	tracker.mu.Lock()
	observation := tracker.observations["auth-a"]
	tracker.mu.Unlock()
	if observation.consecutiveFailures != 0 {
		t.Fatalf("consecutive failure pressure=%d, want zero", observation.consecutiveFailures)
	}
}

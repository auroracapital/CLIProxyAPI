package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type blockingReconcilePreparer struct {
	reconcileExecutor
	once    sync.Once
	started chan struct{}
	release chan struct{}
}

func (*blockingReconcilePreparer) ShouldPrepareRequestAuth(*Auth) bool { return true }

func (e *blockingReconcilePreparer) PrepareRequestAuth(ctx context.Context, auth *Auth) (*Auth, error) {
	e.once.Do(func() { close(e.started) })
	select {
	case <-e.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	updated := auth.Clone()
	updated.Metadata["project_id"] = "prepared"
	return updated, nil
}

type reconcileGenerationStore struct {
	auth         *Auth
	generation   string
	removeOnSave func()
	saveChanges  bool
}

func (s *reconcileGenerationStore) List(context.Context) ([]*Auth, error) { return nil, nil }
func (s *reconcileGenerationStore) Save(_ context.Context, auth *Auth) (string, error) {
	if s.saveChanges {
		s.auth = auth.Clone()
		s.generation = strings.Repeat("c", 64)
	}
	return "", nil
}
func (s *reconcileGenerationStore) Delete(context.Context, string) error { return nil }
func (s *reconcileGenerationStore) LoadReconcile(context.Context, *Auth) (*Auth, string, error) {
	return s.auth.Clone(), s.generation, nil
}
func (s *reconcileGenerationStore) SaveReconcileCAS(_ context.Context, auth *Auth, expected string) (string, string, error) {
	if expected != s.generation {
		return "", "", ErrReconcileGenerationMismatch
	}
	s.auth = auth.Clone()
	s.generation = strings.Repeat("b", 64)
	if s.removeOnSave != nil {
		s.removeOnSave()
	}
	return "saved", s.generation, nil
}

func TestSetReconcileStateCASUsesDurableAdmissionAndRejectsStaleGeneration(t *testing.T) {
	manager := newReconcileManager(t, &reconcileExecutor{}, ReconcileStateProbing)
	durable := &Auth{ID: "seat-a", Provider: "gemini", Status: StatusDisabled, Disabled: true, ReconcileState: ReconcileStateProbing, Metadata: map[string]any{"type": "gemini", "disabled": true, "refresh_token": "restored"}}
	generation := strings.Repeat("a", 64)
	store := &reconcileGenerationStore{auth: durable, generation: generation}
	manager.SetStore(store)
	disabled := true
	updated, nextGeneration, errSet := manager.SetReconcileStateCAS(context.Background(), "seat-a", generation, ReconcileStateCooling, "probe_rejected", time.Now().Add(time.Minute), &disabled)
	if errSet != nil {
		t.Fatal(errSet)
	}
	if nextGeneration == generation || updated == nil || !updated.Disabled || updated.Metadata["refresh_token"] != "restored" || updated.ReconcileState != ReconcileStateCooling {
		t.Fatalf("updated=%#v generation=%q", updated, nextGeneration)
	}
	if _, _, errStale := manager.SetReconcileStateCAS(context.Background(), "seat-a", generation, ReconcileStateReady, "", time.Time{}, nil); !errors.Is(errStale, ErrReconcileGenerationMismatch) {
		t.Fatalf("stale generation error=%v", errStale)
	}
	delayed := updated.Clone()
	delayed.Attributes = map[string]string{AttributeSourceBackend: AuthSourceFile, AttributeSourceGeneration: generation}
	if manager.ReconcileSourceGenerationCurrent(context.Background(), delayed) {
		t.Fatal("delayed watcher generation was accepted")
	}
}

func TestSetReconcileStateCASReadyPerformsAdmissionCleanup(t *testing.T) {
	generation := strings.Repeat("a", 64)
	durable := &Auth{
		ID:             "seat-a",
		Provider:       "gemini",
		Status:         StatusError,
		Unavailable:    true,
		NextRetryAfter: time.Now().Add(time.Hour),
		LastError:      &Error{Code: "rate_limited"},
		StatusMessage:  "cooling",
		ReconcileState: ReconcileStateProbing,
		Metadata:       map[string]any{"type": "gemini", "disabled": false},
	}
	store := &reconcileGenerationStore{auth: durable, generation: generation}
	manager := newReconcileManager(t, &reconcileExecutor{}, ReconcileStateProbing)
	manager.SetStore(store)
	updated, _, errSet := manager.SetReconcileStateCAS(context.Background(), "seat-a", generation, ReconcileStateReady, "", time.Time{}, nil)
	if errSet != nil {
		t.Fatal(errSet)
	}
	if updated.Status != StatusActive || updated.Unavailable || !updated.NextRetryAfter.IsZero() || updated.LastError != nil || updated.StatusMessage != "" || updated.ReconcileState != ReconcileStateReady {
		t.Fatalf("admission cleanup incomplete: %#v", updated)
	}
}

func TestSetReconcileStateCASReportsCommittedGenerationWithoutResurrectingRemovedAuth(t *testing.T) {
	generation := strings.Repeat("a", 64)
	durable := &Auth{ID: "seat-a", Provider: "gemini", Status: StatusActive, ReconcileState: ReconcileStateProbing, Metadata: map[string]any{"type": "gemini"}}
	manager := newReconcileManager(t, &reconcileExecutor{}, ReconcileStateProbing)
	store := &reconcileGenerationStore{auth: durable, generation: generation}
	store.removeOnSave = func() { manager.Remove(context.Background(), "seat-a") }
	manager.SetStore(store)
	updated, committedGeneration, errSet := manager.SetReconcileStateCAS(context.Background(), "seat-a", generation, ReconcileStateCooling, "probe_retryable", time.Now().Add(time.Minute), nil)
	if updated != nil {
		t.Fatalf("removed auth was republished: %#v", updated)
	}
	var committed *ReconcileCommittedError
	if !errors.As(errSet, &committed) || committed.Generation != committedGeneration || committedGeneration != strings.Repeat("b", 64) {
		t.Fatalf("generation=%q error=%v", committedGeneration, errSet)
	}
	if _, exists := manager.GetByID("seat-a"); exists {
		t.Fatal("committed CAS resurrected removed runtime auth")
	}
}

func TestSetReconcileStateCASWaitsForPreparationThenRebasesLifecycle(t *testing.T) {
	generation := strings.Repeat("a", 64)
	durable := &Auth{ID: "seat-a", Provider: "gemini", Status: StatusActive, ReconcileState: ReconcileStateRefreshing, Metadata: map[string]any{"type": "gemini", "disabled": false}}
	store := &reconcileGenerationStore{auth: durable, generation: generation, saveChanges: true}
	executor := &blockingReconcilePreparer{started: make(chan struct{}), release: make(chan struct{})}
	manager := NewManager(store, &RoundRobinSelector{}, nil)
	manager.RegisterExecutor(executor)
	registry.GetGlobalRegistry().RegisterClient(durable.ID, durable.Provider, []*registry.ModelInfo{{ID: "gemini-probe"}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(durable.ID) })
	if _, errRegister := manager.Register(WithSkipPersist(context.Background()), durable); errRegister != nil {
		t.Fatal(errRegister)
	}
	prepareDone := make(chan error, 1)
	go func() {
		current, _ := manager.GetByID(durable.ID)
		_, errPrepare := manager.prepareRequestAuth(context.Background(), executor, current)
		prepareDone <- errPrepare
	}()
	<-executor.started
	casDone := make(chan struct {
		auth       *Auth
		generation string
		err        error
	}, 1)
	go func() {
		updated, nextGeneration, errSet := manager.SetReconcileStateCAS(context.Background(), durable.ID, generation, ReconcileStateProbing, "refresh_succeeded", time.Time{}, nil)
		casDone <- struct {
			auth       *Auth
			generation string
			err        error
		}{updated, nextGeneration, errSet}
	}()
	select {
	case result := <-casDone:
		t.Fatalf("CAS completed before preparation released: %#v", result)
	case <-time.After(20 * time.Millisecond):
	}
	close(executor.release)
	if errPrepare := <-prepareDone; errPrepare != nil {
		t.Fatal(errPrepare)
	}
	result := <-casDone
	if !errors.Is(result.err, ErrReconcileGenerationMismatch) || result.auth != nil {
		t.Fatalf("stale CAS did not fail after preparation changed generation: %#v", result)
	}
	preparedGeneration := store.generation
	updated, nextGeneration, errRetry := manager.SetReconcileStateCAS(context.Background(), durable.ID, preparedGeneration, ReconcileStateProbing, "refresh_succeeded", time.Time{}, nil)
	if errRetry != nil {
		t.Fatal(errRetry)
	}
	if updated == nil || updated.ReconcileState != ReconcileStateProbing || updated.Metadata["project_id"] != "prepared" || nextGeneration == preparedGeneration {
		t.Fatalf("retry did not rebase prepared credential: auth=%#v generation=%q", updated, nextGeneration)
	}
}

type reconcileExecutor struct {
	calls        []string
	err          error
	prepareCalls int
	prepareErr   error
}

type reconcileFailingStore struct{ err error }

func (*reconcileFailingStore) List(context.Context) ([]*Auth, error) { return nil, nil }
func (s *reconcileFailingStore) Save(context.Context, *Auth) (string, error) {
	return "", s.err
}
func (*reconcileFailingStore) Delete(context.Context, string) error { return nil }

type reconcileMemoryStore struct{}

func (*reconcileMemoryStore) List(context.Context) ([]*Auth, error) { return nil, nil }
func (*reconcileMemoryStore) Save(context.Context, *Auth) (string, error) {
	return "saved", nil
}
func (*reconcileMemoryStore) Delete(context.Context, string) error { return nil }

func (*reconcileExecutor) Identifier() string { return "gemini" }
func (e *reconcileExecutor) Execute(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.calls = append(e.calls, auth.ID)
	return cliproxyexecutor.Response{Payload: []byte("ok")}, e.err
}
func (e *reconcileExecutor) ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	_, errExecute := e.Execute(ctx, auth, req, opts)
	return nil, errExecute
}
func (*reconcileExecutor) Refresh(context.Context, *Auth) (*Auth, error) {
	return nil, errors.New("not implemented")
}
func (e *reconcileExecutor) CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return e.Execute(ctx, auth, req, opts)
}
func (*reconcileExecutor) HttpRequest(context.Context, *Auth, *http.Request) (*http.Response, error) {
	return nil, errors.New("not implemented")
}
func (e *reconcileExecutor) ShouldPrepareRequestAuth(*Auth) bool { return true }
func (e *reconcileExecutor) PrepareRequestAuth(_ context.Context, auth *Auth) (*Auth, error) {
	e.prepareCalls++
	return auth, e.prepareErr
}

func newReconcileManager(t *testing.T, executor *reconcileExecutor, states ...ReconcileState) *Manager {
	t.Helper()
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.SetStore(&reconcileMemoryStore{})
	manager.SetRetryConfig(0, 0, 0)
	manager.RegisterExecutor(executor)
	for index, state := range states {
		id := "seat-" + string(rune('a'+index))
		registry.GetGlobalRegistry().RegisterClient(id, "gemini", []*registry.ModelInfo{{ID: "gemini-probe"}})
		if _, errRegister := manager.Register(context.Background(), &Auth{ID: id, Provider: "gemini", Status: StatusActive, ReconcileState: state, Metadata: map[string]any{"type": "gemini"}}); errRegister != nil {
			t.Fatal(errRegister)
		}
	}
	t.Cleanup(func() {
		for index := range states {
			registry.GetGlobalRegistry().UnregisterClient("seat-" + string(rune('a'+index)))
		}
	})
	return manager
}

func TestReconcileStatesAreExcludedUntilReady(t *testing.T) {
	for _, state := range []ReconcileState{ReconcileStateCooling, ReconcileStateRefreshing, ReconcileStateProbing, ReconcileStateAuthRequired, ReconcileStateMisconfigured} {
		t.Run(string(state), func(t *testing.T) {
			manager := newReconcileManager(t, &reconcileExecutor{}, state, ReconcileStateReady)
			auth, _, errPick := manager.pickNext(context.Background(), "gemini", "gemini-probe", cliproxyexecutor.Options{}, nil)
			if errPick != nil {
				t.Fatal(errPick)
			}
			if auth.ID != "seat-b" {
				t.Fatalf("selected %q, excluded state %q was routed", auth.ID, state)
			}
		})
	}
}

func TestLegacyEmptyReconcileStateIsReady(t *testing.T) {
	manager := newReconcileManager(t, &reconcileExecutor{}, "")
	auth, _, errPick := manager.pickNext(context.Background(), "gemini", "gemini-probe", cliproxyexecutor.Options{}, nil)
	if errPick != nil || auth.ID != "seat-a" {
		t.Fatalf("auth=%#v err=%v", auth, errPick)
	}
}

func TestProbeCredentialTargetsExactlyOneProbingSeat(t *testing.T) {
	executor := &reconcileExecutor{}
	manager := newReconcileManager(t, executor, ReconcileStateProbing, ReconcileStateReady)
	outcome, errProbe := manager.ProbeCredential(context.Background(), "seat-a", "gemini", "gemini-probe", cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
	if errProbe != nil || outcome.Outcome != "succeeded" {
		t.Fatalf("outcome=%#v err=%v", outcome, errProbe)
	}
	if len(executor.calls) != 1 || executor.calls[0] != "seat-a" {
		t.Fatalf("probe calls = %#v", executor.calls)
	}
	if executor.prepareCalls != 1 {
		t.Fatalf("prepare calls = %d, want 1", executor.prepareCalls)
	}
	current, _ := manager.GetByID("seat-a")
	if current.ReconcileState != ReconcileStateProbing {
		t.Fatalf("successful probe admitted credential before admission: %#v", current)
	}
}

func TestProbeCredentialRejectsUnregisteredModelWithoutDispatch(t *testing.T) {
	executor := &reconcileExecutor{}
	manager := newReconcileManager(t, executor, ReconcileStateProbing)
	if _, errProbe := manager.ProbeCredential(context.Background(), "seat-a", "gemini", "not-registered", cliproxyexecutor.Request{}, cliproxyexecutor.Options{}); errProbe == nil {
		t.Fatal("unregistered probe model was accepted")
	}
	if executor.prepareCalls != 0 || len(executor.calls) != 0 {
		t.Fatalf("unregistered model prepared/dispatched: prepare=%d calls=%#v", executor.prepareCalls, executor.calls)
	}
}

func TestProbeCredentialPreparationFailureDoesNotDispatch(t *testing.T) {
	executor := &reconcileExecutor{prepareErr: &Error{HTTPStatus: http.StatusUnauthorized, Message: "unauthorized"}}
	manager := newReconcileManager(t, executor, ReconcileStateProbing)
	outcome, errProbe := manager.ProbeCredential(context.Background(), "seat-a", "gemini", "gemini-probe", cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
	if errProbe == nil || outcome.Outcome != "auth_required" || len(executor.calls) != 0 {
		t.Fatalf("outcome=%#v err=%v calls=%#v", outcome, errProbe, executor.calls)
	}
}

func TestProbeFailureDoesNotAdmitCredential(t *testing.T) {
	executor := &reconcileExecutor{err: &Error{HTTPStatus: http.StatusUnauthorized, Message: "unauthorized"}}
	manager := newReconcileManager(t, executor, ReconcileStateProbing)
	outcome, errProbe := manager.ProbeCredential(context.Background(), "seat-a", "gemini", "gemini-probe", cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
	if errProbe == nil || outcome.Outcome != "auth_required" || outcome.HTTPClass != "4xx" {
		t.Fatalf("outcome=%#v err=%v", outcome, errProbe)
	}
	if _, errAdmit := manager.AdmitCredential(context.Background(), "seat-a", outcome); errAdmit == nil {
		t.Fatal("failed probe admitted credential")
	}
	auth, _ := manager.GetByID("seat-a")
	if normalizeReconcileState(auth.ReconcileState) != ReconcileStateProbing {
		t.Fatalf("state changed after failed probe: %q", auth.ReconcileState)
	}
}

func TestSuccessfulProbeAdmissionReadiesCredential(t *testing.T) {
	manager := newReconcileManager(t, &reconcileExecutor{}, ReconcileStateProbing)
	outcome, errProbe := manager.ProbeCredential(context.Background(), "seat-a", "gemini", "gemini-probe", cliproxyexecutor.Request{}, cliproxyexecutor.Options{})
	if errProbe != nil {
		t.Fatal(errProbe)
	}
	auth, errAdmit := manager.AdmitCredential(context.Background(), "seat-a", outcome)
	if errAdmit != nil {
		t.Fatal(errAdmit)
	}
	if auth.ReconcileState != ReconcileStateReady || !auth.ReconcileNextAttempt.IsZero() {
		t.Fatalf("admitted auth = %#v", auth)
	}
}

func TestSetReconcileStateSanitizesReason(t *testing.T) {
	manager := newReconcileManager(t, &reconcileExecutor{}, ReconcileStateReady)
	next := time.Now().Add(time.Minute)
	auth, errSet := manager.SetReconcileState(context.Background(), "seat-a", ReconcileStateCooling, "RATE limited: person@example.com", next)
	if errSet != nil {
		t.Fatal(errSet)
	}
	if auth.ReconcileReason != "ratelimitedpersonexamplecom" || !auth.ReconcileNextAttempt.Equal(next) {
		t.Fatalf("auth = %#v", auth)
	}
}

func TestSetReconcileStateDoesNotPublishFailedPersistence(t *testing.T) {
	manager := newReconcileManager(t, &reconcileExecutor{}, ReconcileStateReady)
	auth, _ := manager.GetByID("seat-a")
	auth.Metadata = map[string]any{"type": "gemini"}
	if _, errUpdate := manager.Update(context.Background(), auth); errUpdate != nil {
		t.Fatal(errUpdate)
	}
	manager.SetStore(&reconcileFailingStore{err: errors.New("disk unavailable")})
	if _, errSet := manager.SetReconcileState(context.Background(), "seat-a", ReconcileStateCooling, "rate_limited", time.Now().Add(time.Minute)); errSet == nil {
		t.Fatal("state update succeeded despite persistence failure")
	}
	current, _ := manager.GetByID("seat-a")
	if current.ReconcileState != ReconcileStateReady || current.ReconcileReason != "" {
		t.Fatalf("failed durable update changed runtime state: %#v", current)
	}
}

func TestAdmissionDoesNotPublishFailedPersistence(t *testing.T) {
	manager := newReconcileManager(t, &reconcileExecutor{}, ReconcileStateProbing)
	auth, _ := manager.GetByID("seat-a")
	auth.Metadata = map[string]any{"type": "gemini"}
	if _, errUpdate := manager.Update(context.Background(), auth); errUpdate != nil {
		t.Fatal(errUpdate)
	}
	manager.SetStore(&reconcileFailingStore{err: errors.New("disk unavailable")})
	if _, errAdmit := manager.AdmitCredential(context.Background(), "seat-a", ProbeOutcome{Outcome: "succeeded", HTTPClass: "2xx"}); errAdmit == nil {
		t.Fatal("admission succeeded despite persistence failure")
	}
	current, _ := manager.GetByID("seat-a")
	if current.ReconcileState != ReconcileStateProbing {
		t.Fatalf("failed durable admission changed runtime state: %#v", current)
	}
}

func TestSetReconcileStateRejectsSkipPersistContext(t *testing.T) {
	manager := newReconcileManager(t, &reconcileExecutor{}, ReconcileStateReady)
	ctx := WithSkipPersist(context.Background())
	if _, errSet := manager.SetReconcileState(ctx, "seat-a", ReconcileStateCooling, "rate_limited", time.Now().Add(time.Minute)); errSet == nil {
		t.Fatal("reconcile state accepted a skip-persist context")
	}
	current, _ := manager.GetByID("seat-a")
	if current.ReconcileState != ReconcileStateReady {
		t.Fatalf("skip-persist update changed runtime state: %#v", current)
	}
}

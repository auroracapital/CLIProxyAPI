package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

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

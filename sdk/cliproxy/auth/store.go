package auth

import (
	"context"
	"errors"
)

// ErrReconcileGenerationMismatch means the backing credential changed after
// the caller selected the version it intended to update.
var ErrReconcileGenerationMismatch = errors.New("reconcile credential generation mismatch")

// ReconcileCommittedError reports that the durable compare-and-swap succeeded
// but the runtime entry disappeared before publication. Callers must not retry
// the old generation or recreate runtime state without revalidating the
// authoritative file through the watcher/service layer.
type ReconcileCommittedError struct {
	Generation string
	Cause      error
}

func (e *ReconcileCommittedError) Error() string {
	return "reconcile credential committed but runtime publication failed"
}

func (e *ReconcileCommittedError) Unwrap() error {
	return e.Cause
}

// Store abstracts persistence of Auth state across restarts.
type Store interface {
	// List returns all auth records stored in the backend.
	List(ctx context.Context) ([]*Auth, error)
	// Save persists the provided auth record, replacing any existing one with same ID.
	Save(ctx context.Context, auth *Auth) (string, error)
	// Delete removes the auth record identified by id.
	Delete(ctx context.Context, id string) error
}

// ReconcileStore provides compare-and-swap persistence for controller-owned
// lifecycle changes. Implementations must derive the returned Auth from the
// authoritative durable credential rather than an in-memory manager snapshot.
type ReconcileStore interface {
	LoadReconcile(context.Context, *Auth) (*Auth, string, error)
	SaveReconcileCAS(context.Context, *Auth, string) (string, string, error)
}

// ReconcileGenerationStore exposes durable generation checks independently of
// compare-and-swap writes so read-only status remains testable and extensible.
type ReconcileGenerationStore interface {
	LoadReconcile(context.Context, *Auth) (*Auth, string, error)
}

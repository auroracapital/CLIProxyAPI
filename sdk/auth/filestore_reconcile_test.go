package auth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestFileStorePersistsReconcileLifecycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seat.json")
	if errWrite := os.WriteFile(path, []byte(`{"type":"claude","access_token":"token","disabled":false}`), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	store := NewFileTokenStore()
	store.SetBaseDir(dir)
	next := time.Now().UTC().Add(time.Hour).Truncate(time.Nanosecond)
	auth := &cliproxyauth.Auth{
		ID:                   "seat.json",
		FileName:             "seat.json",
		Provider:             "claude",
		Status:               cliproxyauth.StatusActive,
		Metadata:             map[string]any{"type": "claude", "access_token": "token"},
		ReconcileState:       cliproxyauth.ReconcileStateCooling,
		ReconcileReason:      "rate_limited",
		ReconcileNextAttempt: next,
	}
	cliproxyauth.SyncReconcileMetadata(auth)
	if _, errSave := store.Save(context.Background(), auth); errSave != nil {
		t.Fatal(errSave)
	}
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	var metadata map[string]any
	if errJSON := json.Unmarshal(raw, &metadata); errJSON != nil {
		t.Fatal(errJSON)
	}
	if metadata["reconcile_state"] != "cooling" || metadata["reconcile_reason"] != "rate_limited" || metadata["reconcile_next_attempt"] != next.Format(time.RFC3339Nano) {
		t.Fatalf("metadata = %#v", metadata)
	}
	loaded, errList := store.List(context.Background())
	if errList != nil || len(loaded) != 1 {
		t.Fatalf("loaded=%#v err=%v", loaded, errList)
	}
	if loaded[0].ReconcileState != cliproxyauth.ReconcileStateCooling || loaded[0].ReconcileReason != "rate_limited" || !loaded[0].ReconcileNextAttempt.Equal(next) {
		t.Fatalf("loaded lifecycle = %#v", loaded[0])
	}
}

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestFileStoreReconcileCASRebasesOnDurableCredential(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seat.json")
	original := []byte(`{"type":"xai","refresh_token":"restored","access_token":"old","disabled":true,"reconcile_state":"probing"}`)
	if errWrite := os.WriteFile(path, original, 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	store := NewFileTokenStore()
	store.SetBaseDir(dir)
	stale := &cliproxyauth.Auth{
		ID:       "seat.json",
		FileName: "seat.json",
		Provider: "xai",
		Status:   cliproxyauth.StatusActive,
		Disabled: false,
		Attributes: map[string]string{
			cliproxyauth.AttributePath: path,
		},
		Metadata: map[string]any{
			"type":          "xai",
			"refresh_token": "stale-refreshed",
			"access_token":  "stale-new",
			"disabled":      false,
		},
	}
	durable, generation, errLoad := store.LoadReconcile(context.Background(), stale)
	if errLoad != nil {
		t.Fatal(errLoad)
	}
	if !durable.Disabled || durable.Metadata["refresh_token"] != "restored" {
		t.Fatalf("durable auth did not come from disk")
	}
	durable.ReconcileState = cliproxyauth.ReconcileStateCooling
	durable.ReconcileReason = "probe_rejected"
	cliproxyauth.SyncReconcileMetadata(durable)
	_, nextGeneration, errSave := store.SaveReconcileCAS(context.Background(), durable, generation)
	if errSave != nil || nextGeneration == generation {
		t.Fatalf("CAS save generation=%q err=%v", nextGeneration, errSave)
	}
	var final map[string]any
	if errJSON := json.Unmarshal(mustReadFile(t, path), &final); errJSON != nil {
		t.Fatal(errJSON)
	}
	if final["disabled"] != true || final["refresh_token"] != "restored" || final["access_token"] != "old" {
		t.Fatalf("stale credential overwrote durable rollback")
	}
	if final["reconcile_state"] != "cooling" || final["reconcile_reason"] != "probe_rejected" {
		t.Fatalf("lifecycle was not persisted")
	}
	if _, _, errStale := store.SaveReconcileCAS(context.Background(), stale, generation); !errors.Is(errStale, cliproxyauth.ErrReconcileGenerationMismatch) {
		t.Fatalf("stale CAS error=%v", errStale)
	}
}

func TestFileStoreReconcileCASSerializesExternalWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seat.json")
	if errWrite := os.WriteFile(path, []byte(`{"type":"xai","refresh_token":"first","disabled":false}`), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	store := NewFileTokenStore()
	store.SetBaseDir(dir)
	reference := &cliproxyauth.Auth{ID: "seat.json", FileName: "seat.json", Provider: "xai", Attributes: map[string]string{cliproxyauth.AttributePath: path}, Metadata: map[string]any{"type": "xai"}}
	loaded, generation, errLoad := store.LoadReconcile(context.Background(), reference)
	if errLoad != nil {
		t.Fatal(errLoad)
	}
	loaded.ReconcileState = cliproxyauth.ReconcileStateCooling
	cliproxyauth.SyncReconcileMetadata(loaded)

	unlock, errLock := lockReconcilePath(path)
	if errLock != nil {
		t.Fatal(errLock)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	result := make(chan error, 1)
	go func() {
		defer wg.Done()
		_, _, errSave := store.SaveReconcileCAS(context.Background(), loaded, generation)
		result <- errSave
	}()
	if errWrite := os.WriteFile(path, []byte(`{"type":"xai","refresh_token":"external","disabled":true}`), 0o600); errWrite != nil {
		unlock()
		t.Fatal(errWrite)
	}
	unlock()
	wg.Wait()
	if errCAS := <-result; !errors.Is(errCAS, cliproxyauth.ErrReconcileGenerationMismatch) {
		t.Fatalf("external generation was overwritten: %v", errCAS)
	}
	var final map[string]any
	if errJSON := json.Unmarshal(mustReadFile(t, path), &final); errJSON != nil {
		t.Fatal(errJSON)
	}
	if got := fmt.Sprint(final["refresh_token"]); got != "external" || final["disabled"] != true {
		t.Fatalf("external writer did not remain authoritative")
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	return raw
}

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

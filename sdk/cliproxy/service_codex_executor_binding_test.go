package cliproxy

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

type blockingGenerationStore struct {
	auth       *coreauth.Auth
	generation string
	once       sync.Once
	loaded     chan struct{}
	release    chan struct{}
}

func (*blockingGenerationStore) List(context.Context) ([]*coreauth.Auth, error) { return nil, nil }
func (*blockingGenerationStore) Save(context.Context, *coreauth.Auth) (string, error) {
	return "saved", nil
}
func (*blockingGenerationStore) Delete(context.Context, string) error { return nil }
func (s *blockingGenerationStore) LoadReconcile(context.Context, *coreauth.Auth) (*coreauth.Auth, string, error) {
	s.once.Do(func() { close(s.loaded) })
	<-s.release
	return s.auth.Clone(), s.generation, nil
}

func TestDelayedDeleteDoesNotRemoveNewerFileGeneration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "seat.json")
	if errWrite := os.WriteFile(path, []byte(`{"type":"claude","refresh_token":"new"}`), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	store := sdkAuth.NewFileTokenStore()
	store.SetBaseDir(dir)
	manager := coreauth.NewManager(store, nil, nil)
	auth := &coreauth.Auth{ID: "seat.json", FileName: "seat.json", Provider: "claude", Status: coreauth.StatusActive, Attributes: map[string]string{coreauth.AttributePath: path, coreauth.AttributeSourceBackend: coreauth.AuthSourceFile}, Metadata: map[string]any{"type": "claude"}}
	if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	_, generation, errLoad := store.LoadReconcile(context.Background(), auth)
	if errLoad != nil {
		t.Fatal(errLoad)
	}
	auth.Attributes[coreauth.AttributeSourceGeneration] = generation
	if _, errUpdate := manager.Update(coreauth.WithSkipPersist(context.Background()), auth); errUpdate != nil {
		t.Fatal(errUpdate)
	}
	service := &Service{cfg: &config.Config{}, coreManager: manager}
	service.handleAuthUpdate(context.Background(), watcher.AuthUpdate{Action: watcher.AuthUpdateActionDelete, ID: auth.ID, Path: path, Generation: "old-generation"})
	if _, ok := manager.GetByID(auth.ID); !ok {
		t.Fatal("delayed delete removed newer auth generation")
	}
}

func TestDelayedDeleteRemovesRuntimeAuthWhenReplacementIsInvalid(t *testing.T) {
	for _, replacement := range []string{`not-json`, `{"type":"codex","refresh_token":"wrong-provider"}`} {
		t.Run(replacement, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "seat.json")
			if errWrite := os.WriteFile(path, []byte(replacement), 0o600); errWrite != nil {
				t.Fatal(errWrite)
			}
			store := sdkAuth.NewFileTokenStore()
			store.SetBaseDir(dir)
			manager := coreauth.NewManager(store, nil, nil)
			auth := &coreauth.Auth{ID: "seat.json", FileName: "seat.json", Provider: "claude", Status: coreauth.StatusActive, Attributes: map[string]string{coreauth.AttributePath: path, coreauth.AttributeSourceBackend: coreauth.AuthSourceFile, coreauth.AttributeSourceGeneration: "old-generation"}, Metadata: map[string]any{"type": "claude"}}
			if _, errRegister := manager.Register(coreauth.WithSkipPersist(context.Background()), auth); errRegister != nil {
				t.Fatal(errRegister)
			}
			service := &Service{cfg: &config.Config{}, coreManager: manager}
			service.handleAuthUpdate(context.Background(), watcher.AuthUpdate{Action: watcher.AuthUpdateActionDelete, ID: auth.ID, Path: path, Generation: "old-generation"})
			if _, ok := manager.GetByID(auth.ID); ok {
				t.Fatal("invalid replacement retained stale runtime credential")
			}
		})
	}
}

func TestDeleteWaitsForWatcherValidateAndPublishThenWins(t *testing.T) {
	generation := "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0"
	auth := &coreauth.Auth{
		ID:       "seat.json",
		FileName: "seat.json",
		Provider: "claude",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			coreauth.AttributePath:             "/private/auth/seat.json",
			coreauth.AttributeSourceBackend:    coreauth.AuthSourceFile,
			coreauth.AttributeSourceGeneration: generation,
		},
		Metadata: map[string]any{"type": "claude"},
	}
	manager := coreauth.NewManager(nil, nil, nil)
	if _, errRegister := manager.Register(coreauth.WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	store := &blockingGenerationStore{auth: auth, generation: generation, loaded: make(chan struct{}), release: make(chan struct{})}
	manager.SetStore(store)
	service := &Service{cfg: &config.Config{}, coreManager: manager}
	watcherDone := make(chan *coreauth.Auth, 1)
	go func() { watcherDone <- service.prepareCoreAuthForModelRegistration(context.Background(), auth) }()
	<-store.loaded
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
		t.Fatal("delete entered durable mutation while watcher publication was in flight")
	case <-time.After(20 * time.Millisecond):
	}
	close(store.release)
	if prepared := <-watcherDone; prepared == nil {
		t.Fatal("watcher did not publish the validated credential before deletion")
	}
	if errDelete := <-deleteDone; errDelete != nil {
		t.Fatal(errDelete)
	}
	if _, exists := manager.GetByID(auth.ID); exists {
		t.Fatal("in-flight watcher publication resurrected deleted auth")
	}
}

func TestEnsureExecutorsForAuth_CodexDoesNotReplaceInNormalMode(t *testing.T) {
	service := &Service{
		cfg:         &config.Config{},
		coreManager: coreauth.NewManager(nil, nil, nil),
	}
	auth := &coreauth.Auth{
		ID:       "codex-auth-1",
		Provider: "codex",
		Status:   coreauth.StatusActive,
	}

	service.ensureExecutorsForAuth(auth)
	firstExecutor, okFirst := service.coreManager.Executor("codex")
	if !okFirst || firstExecutor == nil {
		t.Fatal("expected codex executor after first bind")
	}

	service.ensureExecutorsForAuth(auth)
	secondExecutor, okSecond := service.coreManager.Executor("codex")
	if !okSecond || secondExecutor == nil {
		t.Fatal("expected codex executor after second bind")
	}

	if firstExecutor != secondExecutor {
		t.Fatal("expected codex executor to stay unchanged in normal mode")
	}
}

func TestEnsureExecutorsForAuthWithMode_CodexForceReplace(t *testing.T) {
	service := &Service{
		cfg:         &config.Config{},
		coreManager: coreauth.NewManager(nil, nil, nil),
	}
	auth := &coreauth.Auth{
		ID:       "codex-auth-2",
		Provider: "codex",
		Status:   coreauth.StatusActive,
	}

	service.ensureExecutorsForAuth(auth)
	firstExecutor, okFirst := service.coreManager.Executor("codex")
	if !okFirst || firstExecutor == nil {
		t.Fatal("expected codex executor after first bind")
	}

	service.ensureExecutorsForAuthWithMode(auth, true)
	secondExecutor, okSecond := service.coreManager.Executor("codex")
	if !okSecond || secondExecutor == nil {
		t.Fatal("expected codex executor after forced rebind")
	}

	if firstExecutor == secondExecutor {
		t.Fatal("expected codex executor replacement in force mode")
	}
}

func TestSyncPluginModelRuntime_UnrelatedAuthDoesNotReplaceWebsocketExecutor(t *testing.T) {
	testCases := []struct {
		name        string
		provider    string
		homeEnabled bool
	}{
		{name: "codex standard mode", provider: "codex"},
		{name: "codex home mode", provider: "codex", homeEnabled: true},
		{name: "xai standard mode", provider: "xai"},
		{name: "xai home mode", provider: "xai", homeEnabled: true},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			cfg := &config.Config{}
			cfg.Home.Enabled = tt.homeEnabled
			service := &Service{
				cfg:         cfg,
				coreManager: coreauth.NewManager(nil, nil, nil),
				pluginHost:  pluginhost.New(),
			}
			providerAuth := &coreauth.Auth{
				ID:       tt.provider + "-auth",
				Provider: tt.provider,
				Status:   coreauth.StatusActive,
			}
			unrelatedAuth := &coreauth.Auth{
				ID:       "unrelated-auth",
				Provider: "claude",
				Status:   coreauth.StatusActive,
			}
			t.Cleanup(func() {
				GlobalModelRegistry().UnregisterClient(providerAuth.ID)
				GlobalModelRegistry().UnregisterClient(unrelatedAuth.ID)
				sdkAuth.RegisterPluginAuthParser(nil)
				sdktranslator.SetPluginHooks(nil)
			})

			if _, errRegister := service.coreManager.Register(ctx, providerAuth); errRegister != nil {
				t.Fatalf("register %s auth: %v", tt.provider, errRegister)
			}
			if _, errRegister := service.coreManager.Register(ctx, unrelatedAuth); errRegister != nil {
				t.Fatalf("register unrelated auth: %v", errRegister)
			}
			service.ensureExecutorsForAuth(providerAuth)
			firstExecutor, okFirst := service.coreManager.Executor(tt.provider)
			if !okFirst || firstExecutor == nil {
				t.Fatalf("expected %s executor before plugin model sync", tt.provider)
			}

			updatedAuth := unrelatedAuth.Clone()
			updatedAuth.Label = "updated unrelated auth"
			service.handleAuthUpdate(ctx, watcher.AuthUpdate{
				Action: watcher.AuthUpdateActionModify,
				ID:     updatedAuth.ID,
				Auth:   updatedAuth,
			})

			secondExecutor, okSecond := service.coreManager.Executor(tt.provider)
			if !okSecond || secondExecutor == nil {
				t.Fatalf("expected %s executor after plugin model sync", tt.provider)
			}
			if firstExecutor != secondExecutor {
				t.Fatalf("expected unrelated auth sync to preserve the %s executor", tt.provider)
			}
		})
	}
}

func TestEnsureExecutorsForAuth_XAIDoesNotReplaceInNormalMode(t *testing.T) {
	service := &Service{
		cfg:         &config.Config{},
		coreManager: coreauth.NewManager(nil, nil, nil),
	}
	auth := &coreauth.Auth{
		ID:       "xai-auth-1",
		Provider: "xai",
		Status:   coreauth.StatusActive,
	}

	service.ensureExecutorsForAuth(auth)
	firstExecutor, okFirst := service.coreManager.Executor("xai")
	if !okFirst || firstExecutor == nil {
		t.Fatal("expected xai executor after first bind")
	}
	if _, isXAIAutoExecutor := firstExecutor.(*executor.XAIAutoExecutor); !isXAIAutoExecutor {
		t.Fatalf("xai executor type = %T, want *executor.XAIAutoExecutor", firstExecutor)
	}

	service.ensureExecutorsForAuth(auth)
	secondExecutor, okSecond := service.coreManager.Executor("xai")
	if !okSecond || secondExecutor == nil {
		t.Fatal("expected xai executor after second bind")
	}
	if firstExecutor != secondExecutor {
		t.Fatal("expected xai executor to stay unchanged in normal mode")
	}
}

func TestEnsureExecutorsForAuthWithMode_XAIForceReplace(t *testing.T) {
	service := &Service{
		cfg:         &config.Config{},
		coreManager: coreauth.NewManager(nil, nil, nil),
	}
	auth := &coreauth.Auth{
		ID:       "xai-auth-2",
		Provider: "xai",
		Status:   coreauth.StatusActive,
	}

	service.ensureExecutorsForAuth(auth)
	firstExecutor, okFirst := service.coreManager.Executor("xai")
	if !okFirst || firstExecutor == nil {
		t.Fatal("expected xai executor after first bind")
	}

	service.ensureExecutorsForAuthWithMode(auth, true)
	secondExecutor, okSecond := service.coreManager.Executor("xai")
	if !okSecond || secondExecutor == nil {
		t.Fatal("expected xai executor after forced rebind")
	}
	if firstExecutor == secondExecutor {
		t.Fatal("expected xai executor replacement in force mode")
	}
	if _, isXAIAutoExecutor := secondExecutor.(*executor.XAIAutoExecutor); !isXAIAutoExecutor {
		t.Fatalf("xai executor type = %T, want *executor.XAIAutoExecutor", secondExecutor)
	}
}

func TestEnsureExecutorsForAuth_XAIReplacesExecutorAfterConfigUpdate(t *testing.T) {
	service := &Service{
		cfg:         &config.Config{},
		coreManager: coreauth.NewManager(nil, nil, nil),
		pluginHost:  pluginhost.New(),
	}
	t.Cleanup(func() {
		sdkAuth.RegisterPluginAuthParser(nil)
		sdktranslator.SetPluginHooks(nil)
	})
	auth := &coreauth.Auth{
		ID:       "xai-auth-config-update",
		Provider: "xai",
		Status:   coreauth.StatusActive,
	}

	service.ensureExecutorsForAuth(auth)
	firstExecutor, okFirst := service.coreManager.Executor("xai")
	if !okFirst || firstExecutor == nil {
		t.Fatal("expected xai executor before config update")
	}

	service.applyWatcherConfigUpdate(&config.Config{})
	service.ensureExecutorsForAuth(auth)

	secondExecutor, okSecond := service.coreManager.Executor("xai")
	if !okSecond || secondExecutor == nil {
		t.Fatal("expected xai executor after config update")
	}
	if firstExecutor == secondExecutor {
		t.Fatal("expected stale xai executor replacement after config update")
	}
	if _, isXAIAutoExecutor := secondExecutor.(*executor.XAIAutoExecutor); !isXAIAutoExecutor {
		t.Fatalf("xai executor type = %T, want *executor.XAIAutoExecutor", secondExecutor)
	}
}

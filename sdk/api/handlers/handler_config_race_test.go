package handlers

import (
	"context"
	"sync"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestSmartRouterConcurrentHotReloadUsesImmutableSnapshot(t *testing.T) {
	registerSmartRouterModel(t, "race-client", "codex", "race-model", nil)
	handler := NewBaseAPIHandlers(&sdkconfig.SDKConfig{AutoRouting: internalconfig.AutoRoutingConfig{Mode: "active", DefaultModels: []string{"race-model"}}}, nil)
	var wait sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for index := 0; index < 250; index++ {
				handler.applyModelRouter(context.Background(), "openai", "auto", []byte(`{"messages":[{"role":"user","content":"debug code"}]}`), false, modelExecutionOptions{})
			}
		}()
	}
	for index := 0; index < 250; index++ {
		mode := "active"
		if index%2 == 0 {
			mode = "shadow"
		}
		handler.UpdateClients(&sdkconfig.SDKConfig{AutoRouting: internalconfig.AutoRoutingConfig{Mode: mode, DefaultModels: []string{"race-model"}, TaskModels: map[string][]string{"code": {"race-model"}}}})
	}
	wait.Wait()
}

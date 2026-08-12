package api

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestEffectiveSDKConfigCopiesCodexOptimizeMultiAgentV2(t *testing.T) {
	cfg := &config.Config{
		Codex: config.CodexConfig{OptimizeMultiAgentV2: true},
		Routing: config.RoutingConfig{
			Auto:          config.AutoRoutingConfig{Enabled: true},
			Observability: config.RoutingObservabilityConfig{Enabled: true},
		},
	}

	sdkCfg := effectiveSDKConfig(cfg)
	if sdkCfg == nil || !sdkCfg.CodexOptimizeMultiAgentV2 {
		t.Fatalf("CodexOptimizeMultiAgentV2 = false, want true")
	}
	if !sdkCfg.AutoRouting.Enabled {
		t.Fatal("AutoRouting.Enabled = false, want true")
	}
	if !sdkCfg.RoutingObservability.Enabled {
		t.Fatal("RoutingObservability.Enabled = false, want true")
	}
}

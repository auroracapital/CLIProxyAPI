package handlers

import (
	"context"
	"reflect"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
)

func TestSmartRouterPolicyDefaultsPreserveConfiguredOrder(t *testing.T) {
	registerSmartRouterModel(t, "policy-balanced-first-client", "claude", "policy-balanced-first", nil)
	registerSmartRouterModel(t, "policy-balanced-second-client", "codex", "policy-balanced-second", nil)
	handler := smartRouterHandler(internalconfig.AutoRoutingConfig{
		Enabled:       true,
		DefaultModels: []string{"policy-balanced-first", "policy-balanced-second"},
	})

	decision := handler.applyModelRouter(context.Background(), "openai", "auto", []byte(`{"messages":[]}`), false, modelExecutionOptions{})
	if !reflect.DeepEqual(decision.Models, []string{"policy-balanced-first", "policy-balanced-second"}) {
		t.Fatalf("balanced models = %#v, want configured order", decision.Models)
	}
}

func TestSmartRouterPolicyReordersCompatibleSlateForObjective(t *testing.T) {
	registerSmartRouterModel(t, "policy-quality-cheap-client", "gemini", "policy-quality-cheap", nil)
	registerSmartRouterModel(t, "policy-quality-best-client", "claude", "policy-quality-best", nil)
	handler := smartRouterHandler(internalconfig.AutoRoutingConfig{
		Enabled:       true,
		DefaultModels: []string{"policy-quality-cheap", "policy-quality-best"},
		Policy: internalconfig.AutoRoutingPolicyConfig{
			Objective:     "quality",
			QualityModels: []string{"policy-quality-best", "policy-quality-cheap"},
		},
	})

	decision := handler.applyModelRouter(context.Background(), "openai", "auto", []byte(`{"messages":[]}`), false, modelExecutionOptions{})
	if !reflect.DeepEqual(decision.Models, []string{"policy-quality-best", "policy-quality-cheap"}) {
		t.Fatalf("quality models = %#v", decision.Models)
	}
}

func TestSmartRouterPolicyNeverResurrectsCapabilityFilteredModel(t *testing.T) {
	registerSmartRouterModel(t, "policy-tools-incompatible-client", "claude", "policy-tools-incompatible", &registry.ModelInfo{})
	registerSmartRouterModel(t, "policy-tools-compatible-client", "codex", "policy-tools-compatible", &registry.ModelInfo{SupportedParameters: []string{"tools"}})
	handler := smartRouterHandler(internalconfig.AutoRoutingConfig{
		Enabled:       true,
		DefaultModels: []string{"policy-tools-compatible", "policy-tools-incompatible"},
		Policy: internalconfig.AutoRoutingPolicyConfig{
			Objective:     "latency",
			LatencyModels: []string{"policy-tools-incompatible", "policy-tools-compatible"},
		},
	})

	decision := handler.applyModelRouter(context.Background(), "openai", "auto", []byte(`{"tools":[{"type":"function"}],"messages":[]}`), false, modelExecutionOptions{})
	if !reflect.DeepEqual(decision.Models, []string{"policy-tools-compatible"}) {
		t.Fatalf("capability-filtered models = %#v", decision.Models)
	}
}

func TestSmartRouterProviderPolicyUsesHealthByDefaultAndExplicitPriority(t *testing.T) {
	const model = "policy-provider-model"
	registerSmartRouterModel(t, "policy-provider-health-a", "health-provider", model, nil)
	registerSmartRouterModel(t, "policy-provider-health-b", "health-provider", model, nil)
	registerSmartRouterModel(t, "policy-provider-priority", "priority-provider", model, nil)
	requirements := smartRouteRequirements{TaskClass: smartTaskGeneral}

	healthOrder := eligibleSmartProviders(registry.GetGlobalRegistry(), model, requirements, internalconfig.AutoRoutingPolicyConfig{})
	if !reflect.DeepEqual(healthOrder, []string{"health-provider", "priority-provider"}) {
		t.Fatalf("health provider order = %#v", healthOrder)
	}
	priorityOrder := eligibleSmartProviders(registry.GetGlobalRegistry(), model, requirements, internalconfig.AutoRoutingPolicyConfig{
		ProviderStrategy: "priority",
		ProviderPriority: []string{"priority-provider"},
	})
	if !reflect.DeepEqual(priorityOrder, []string{"priority-provider", "health-provider"}) {
		t.Fatalf("priority provider order = %#v", priorityOrder)
	}
}

func TestSmartRouterPolicyHotReloadCopyIsIsolated(t *testing.T) {
	handler := smartRouterHandler(internalconfig.AutoRoutingConfig{Policy: internalconfig.AutoRoutingPolicyConfig{
		Objective:        "cost",
		CostModels:       []string{"cost-a", "cost-b"},
		ProviderPriority: []string{"codex", "claude"},
		ProviderStrategy: "priority",
	}})
	first := handler.autoRoutingConfig()
	first.Policy.CostModels[0] = "mutated"
	first.Policy.ProviderPriority[0] = "mutated"
	second := handler.autoRoutingConfig()
	if !reflect.DeepEqual(second.Policy.CostModels, []string{"cost-a", "cost-b"}) ||
		!reflect.DeepEqual(second.Policy.ProviderPriority, []string{"codex", "claude"}) {
		t.Fatalf("stored policy was mutated through a returned copy: %#v", second.Policy)
	}
}

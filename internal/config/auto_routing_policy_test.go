package config

import (
	"reflect"
	"testing"
)

func TestNormalizeAutoRoutingPolicy(t *testing.T) {
	cfg := &Config{Routing: RoutingConfig{Auto: AutoRoutingConfig{Policy: AutoRoutingPolicyConfig{
		Objective:        " COST ",
		QualityModels:    []string{" quality-a ", "QUALITY-A", "auto"},
		CostModels:       []string{" cost-a ", "cost-b"},
		LatencyModels:    []string{" latency-a "},
		ProviderStrategy: " PRIORITY ",
		ProviderPriority: []string{" codex ", "CODEX", "claude"},
	}}}}
	cfg.NormalizeAutoRoutingConfig()

	policy := cfg.Routing.Auto.Policy
	if policy.Objective != "cost" || policy.ProviderStrategy != "priority" {
		t.Fatalf("policy modes = %#v", policy)
	}
	if !reflect.DeepEqual(policy.QualityModels, []string{"quality-a"}) ||
		!reflect.DeepEqual(policy.CostModels, []string{"cost-a", "cost-b"}) ||
		!reflect.DeepEqual(policy.LatencyModels, []string{"latency-a"}) ||
		!reflect.DeepEqual(policy.ProviderPriority, []string{"codex", "claude"}) {
		t.Fatalf("normalized policy = %#v", policy)
	}
}

func TestNormalizeAutoRoutingPolicyInvalidValuesUseDeterministicDefaults(t *testing.T) {
	cfg := &Config{Routing: RoutingConfig{Auto: AutoRoutingConfig{Policy: AutoRoutingPolicyConfig{
		Objective:        "fastest-ish",
		ProviderStrategy: "random",
	}}}}
	cfg.NormalizeAutoRoutingConfig()
	if cfg.Routing.Auto.Policy.Objective != "balanced" || cfg.Routing.Auto.Policy.ProviderStrategy != "health" {
		t.Fatalf("policy = %#v", cfg.Routing.Auto.Policy)
	}
}

func TestParseAutoRoutingPolicyFromYAML(t *testing.T) {
	cfg, errParse := ParseConfigBytes([]byte(`routing:
  auto:
    mode: shadow
    policy:
      objective: latency
      latency-models: [fast-a, fast-b]
      provider-strategy: priority
      provider-priority: [gemini, codex]
`))
	if errParse != nil {
		t.Fatal(errParse)
	}
	policy := cfg.Routing.Auto.Policy
	if policy.Objective != "latency" || policy.ProviderStrategy != "priority" ||
		!reflect.DeepEqual(policy.LatencyModels, []string{"fast-a", "fast-b"}) ||
		!reflect.DeepEqual(policy.ProviderPriority, []string{"gemini", "codex"}) {
		t.Fatalf("parsed policy = %#v", policy)
	}
}

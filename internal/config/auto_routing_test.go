package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadConfigNormalizesAutoRouting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte(`routing:
  auto:
    enabled: true
    max-fallbacks: 99
    default-models: [" model-a ", AUTO, model-a, model-b]
    task-models:
      " Code ": [model-c, " model-c ", auto]
      unknown: [model-d]
`)
	if errWrite := os.WriteFile(path, data, 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	cfg, errLoad := LoadConfig(path)
	if errLoad != nil {
		t.Fatal(errLoad)
	}
	if cfg.Routing.Auto.MaxFallbacks != 5 {
		t.Fatalf("max fallbacks = %d, want 5", cfg.Routing.Auto.MaxFallbacks)
	}
	if !reflect.DeepEqual(cfg.Routing.Auto.DefaultModels, []string{"model-a", "model-b"}) {
		t.Fatalf("default models = %#v", cfg.Routing.Auto.DefaultModels)
	}
	if !reflect.DeepEqual(cfg.Routing.Auto.TaskModels, map[string][]string{"code": {"model-c"}}) {
		t.Fatalf("task models = %#v", cfg.Routing.Auto.TaskModels)
	}
}

func TestNormalizeAutoRoutingConfigUsesDefaultSlateLimit(t *testing.T) {
	cfg := &Config{Routing: RoutingConfig{Auto: AutoRoutingConfig{MaxFallbacks: -1}}}
	cfg.NormalizeAutoRoutingConfig()
	if cfg.Routing.Auto.MaxFallbacks != 3 {
		t.Fatalf("max fallbacks = %d, want 3", cfg.Routing.Auto.MaxFallbacks)
	}
}

func TestNormalizeAutoRoutingMode(t *testing.T) {
	for _, test := range []struct {
		name    string
		auto    AutoRoutingConfig
		mode    string
		enabled bool
	}{
		{name: "legacy enabled", auto: AutoRoutingConfig{Enabled: true}, mode: "active", enabled: true},
		{name: "separate endpoint", auto: AutoRoutingConfig{Enabled: true, Mode: " REJECT "}, mode: "reject"},
		{name: "auto only endpoint", auto: AutoRoutingConfig{Mode: " EXCLUSIVE "}, mode: "exclusive"},
		{name: "shadow", auto: AutoRoutingConfig{Enabled: true, Mode: " SHADOW "}, mode: "shadow"},
		{name: "invalid fails off", auto: AutoRoutingConfig{Enabled: true, Mode: "invalid"}, mode: "off"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := &Config{Routing: RoutingConfig{Auto: test.auto}}
			cfg.NormalizeAutoRoutingConfig()
			if cfg.Routing.Auto.Mode != test.mode || cfg.Routing.Auto.Enabled != test.enabled {
				t.Fatalf("auto = %#v, want mode=%q enabled=%v", cfg.Routing.Auto, test.mode, test.enabled)
			}
		})
	}
}

func TestParseConfigBytesNormalizesAutoRouting(t *testing.T) {
	cfg, errParse := ParseConfigBytes([]byte("routing:\n  auto:\n    mode: SHADOW\n    max-fallbacks: 99\n"))
	if errParse != nil {
		t.Fatal(errParse)
	}
	if cfg.Routing.Auto.Mode != "shadow" || cfg.Routing.Auto.Enabled || cfg.Routing.Auto.MaxFallbacks != 5 {
		t.Fatalf("auto = %#v", cfg.Routing.Auto)
	}
}

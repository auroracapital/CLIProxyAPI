package cliproxy

import (
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestNormalizedRoutingRuntimeStateLeastPressure(t *testing.T) {
	state := normalizedRoutingRuntimeState(&internalconfig.Config{
		Routing: internalconfig.RoutingConfig{Strategy: "lp"},
	})
	if state.strategy != "least-pressure" {
		t.Fatalf("strategy = %q, want least-pressure", state.strategy)
	}
	if _, ok := newRoutingSelector(state).(*coreauth.LeastPressureSelector); !ok {
		t.Fatalf("selector type = %T, want *auth.LeastPressureSelector", newRoutingSelector(state))
	}
}

func TestNormalizedRoutingRuntimeStateShadowLeastPressure(t *testing.T) {
	state := normalizedRoutingRuntimeState(&internalconfig.Config{
		Routing: internalconfig.RoutingConfig{Strategy: "shadow-lp"},
	})
	if state.strategy != "shadow-least-pressure" {
		t.Fatalf("strategy = %q, want shadow-least-pressure", state.strategy)
	}
	if _, ok := newRoutingSelector(state).(*coreauth.ShadowLeastPressureSelector); !ok {
		t.Fatalf("selector type = %T, want *auth.ShadowLeastPressureSelector", newRoutingSelector(state))
	}
}

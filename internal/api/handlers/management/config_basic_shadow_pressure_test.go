package management

import "testing"

func TestNormalizeRoutingStrategyShadowLeastPressure(t *testing.T) {
	for _, input := range []string{"shadow-least-pressure", "shadowleastpressure", "shadow-lp", " SHADOW-LP "} {
		got, ok := normalizeRoutingStrategy(input)
		if !ok || got != "shadow-least-pressure" {
			t.Fatalf("normalizeRoutingStrategy(%q) = %q, %v; want shadow-least-pressure, true", input, got, ok)
		}
	}
}

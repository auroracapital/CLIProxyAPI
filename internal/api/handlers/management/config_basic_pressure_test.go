package management

import "testing"

func TestNormalizeRoutingStrategyLeastPressure(t *testing.T) {
	for _, input := range []string{"least-pressure", "leastpressure", "least-loaded", "leastloaded", "lp"} {
		got, ok := normalizeRoutingStrategy(input)
		if !ok || got != "least-pressure" {
			t.Fatalf("normalizeRoutingStrategy(%q) = %q, %v; want least-pressure, true", input, got, ok)
		}
	}
}

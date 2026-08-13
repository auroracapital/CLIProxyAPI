package executor

import (
	"strings"
	"time"
	"unicode"
)

// RoutingEvent is a closed, categorical observation of a routing decision or
// attempt. It intentionally has no request body, headers, account identifier,
// auth path, token, email, upstream body, or free-form metadata fields.
type RoutingEvent struct {
	SchemaVersion       int
	Stage               string
	Mode                string
	TaskClass           string
	ScoreVersion        string
	Model               string
	Provider            string
	Reason              string
	Outcome             string
	Attempt             int
	CandidateCount      int
	Duration            time.Duration
	Selector            string
	ShadowMatch         bool
	SeatBucket          string
	PredictedSeatBucket string
}

const routingEventSchemaVersion = 1

var routingEventEnums = map[string]map[string]struct{}{
	"stage":    values("model_decision", "model_attempt", "stream_attempt", "count_attempt", "account_selection", "account_prediction"),
	"mode":     values("active", "shadow"),
	"task":     values("", "code", "reasoning", "research", "agent", "multimodal", "writing", "general"),
	"score":    values("", "v1", "v2"),
	"reason":   values("", "general_default", "hard_multimodal", "hard_tools", "keyword_code", "keyword_reasoning", "keyword_research", "keyword_agent", "keyword_writing", "keyword_general", "no_compatible_model", "transport", "request_fault", "unauthorized", "quota", "route_unavailable", "timeout", "too_early", "rate_limited", "upstream_unavailable", "terminal"),
	"outcome":  values("selected", "unavailable", "started", "success", "failed", "committed", "predicted"),
	"selector": values("", "custom", "round_robin", "shadow_least_pressure", "least_pressure", "weighted_round_robin", "fill_first", "session_affinity"),
}

func values(items ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(items))
	for _, item := range items {
		out[item] = struct{}{}
	}
	return out
}

// NormalizeRoutingEvent enforces the closed telemetry contract at the final
// emission boundary. Model/provider identifiers are bounded to printable safe
// characters; all other strings fail closed to an allowlisted categorical value.
func NormalizeRoutingEvent(event RoutingEvent) RoutingEvent {
	event.SchemaVersion = routingEventSchemaVersion
	event.Stage = routingEnum("stage", event.Stage, "model_decision")
	event.Mode = routingEnum("mode", event.Mode, "active")
	event.TaskClass = routingEnum("task", event.TaskClass, "")
	event.ScoreVersion = routingEnum("score", event.ScoreVersion, "")
	event.Reason = routingEnum("reason", event.Reason, "")
	event.Outcome = routingEnum("outcome", event.Outcome, "failed")
	event.Selector = routingEnum("selector", event.Selector, "")
	event.Model = routingIdentifier(event.Model)
	event.Provider = routingIdentifier(event.Provider)
	event.SeatBucket = routingSeatBucket(event.SeatBucket)
	event.PredictedSeatBucket = routingSeatBucket(event.PredictedSeatBucket)
	if event.Attempt < 0 {
		event.Attempt = 0
	} else if event.Attempt > 100 {
		event.Attempt = 100
	}
	if event.CandidateCount < 0 {
		event.CandidateCount = 0
	} else if event.CandidateCount > 1000 {
		event.CandidateCount = 1000
	}
	if event.Duration < 0 {
		event.Duration = 0
	} else if event.Duration > time.Hour {
		event.Duration = time.Hour
	}
	return event
}

func routingSeatBucket(value string) string {
	if len(value) != 19 || !strings.HasPrefix(value, "h1_") {
		return ""
	}
	for _, r := range value[3:] {
		if !(unicode.IsDigit(r) || r >= 'a' && r <= 'f') {
			return ""
		}
	}
	return value
}

func routingEnum(kind, value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if _, ok := routingEventEnums[kind][value]; ok {
		return value
	}
	return fallback
}

func routingIdentifier(value string) string {
	value = strings.TrimSpace(value)
	lower := strings.ToLower(value)
	for _, forbidden := range []string{"bearer", "token", ".json", "/opt/", "/home/", "/users/", "\\", "@", ".."} {
		if strings.Contains(lower, forbidden) {
			return ""
		}
	}
	if len(value) > 128 {
		return ""
	}
	for _, r := range value {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("._:/+-", r)) {
			return ""
		}
	}
	return value
}

// RoutingObserver receives privacy-safe routing events synchronously. Callers
// should keep observers non-blocking; the default structured-log observer is.
type RoutingObserver interface {
	ObserveRouting(RoutingEvent)
}

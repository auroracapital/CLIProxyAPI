package handlers

import (
	"strings"
	"sync/atomic"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
)

const routingEventQueueSize = 256

var defaultRoutingLogObserver = newStructuredRoutingObserver()

// structuredRoutingObserver decouples request execution from log IO. When the
// bounded queue is full events are dropped; telemetry must never add backpressure
// to provider dispatch.
type structuredRoutingObserver struct {
	events  chan coreexecutor.RoutingEvent
	logger  *log.Logger
	dropped atomic.Uint64
	invalid atomic.Uint64
}

func newStructuredRoutingObserver() *structuredRoutingObserver {
	return newStructuredRoutingObserverWithLogger(log.StandardLogger())
}

func newStructuredRoutingObserverWithLogger(logger *log.Logger) *structuredRoutingObserver {
	if logger == nil {
		logger = log.StandardLogger()
	}
	observer := &structuredRoutingObserver{events: make(chan coreexecutor.RoutingEvent, routingEventQueueSize), logger: logger}
	go observer.run()
	return observer
}

func (o *structuredRoutingObserver) ObserveRouting(event coreexecutor.RoutingEvent) {
	if o == nil {
		return
	}
	select {
	case o.events <- event:
	default:
		o.dropped.Add(1)
	}
}

func (o *structuredRoutingObserver) run() {
	for event := range o.events {
		fields, ok := routingLogFields(event)
		if !ok {
			o.invalid.Add(1)
			continue
		}
		o.logger.WithFields(fields).Info("routing decision")
	}
}

func routingLogFields(event coreexecutor.RoutingEvent) (log.Fields, bool) {
	normalized := coreexecutor.NormalizeRoutingEvent(event)
	if !routingEventEnumsWereValid(event, normalized) {
		return nil, false
	}
	if normalized.Model != "" && registry.GetGlobalRegistry().GetModelInfo(normalized.Model, "") == nil {
		normalized.Model = ""
	}
	normalized.Provider = routingProviderCategory(normalized.Provider)
	return log.Fields{
		"routing_schema_version":        normalized.SchemaVersion,
		"routing_stage":                 normalized.Stage,
		"routing_mode":                  normalized.Mode,
		"routing_task":                  normalized.TaskClass,
		"routing_score_version":         normalized.ScoreVersion,
		"routing_model":                 normalized.Model,
		"routing_provider":              normalized.Provider,
		"routing_reason":                normalized.Reason,
		"routing_outcome":               normalized.Outcome,
		"routing_attempt":               normalized.Attempt,
		"routing_candidate_count":       normalized.CandidateCount,
		"routing_duration_ms":           normalized.Duration.Milliseconds(),
		"routing_selector":              normalized.Selector,
		"routing_shadow_match":          normalized.ShadowMatch,
		"routing_seat_bucket":           normalized.SeatBucket,
		"routing_predicted_seat_bucket": normalized.PredictedSeatBucket,
		"routing_request_bucket":        normalized.RequestBucket,
	}, true
}

func routingEventEnumsWereValid(raw, normalized coreexecutor.RoutingEvent) bool {
	return strings.ToLower(strings.TrimSpace(raw.Stage)) == normalized.Stage &&
		strings.ToLower(strings.TrimSpace(raw.Mode)) == normalized.Mode &&
		strings.ToLower(strings.TrimSpace(raw.TaskClass)) == normalized.TaskClass &&
		strings.ToLower(strings.TrimSpace(raw.ScoreVersion)) == normalized.ScoreVersion &&
		strings.ToLower(strings.TrimSpace(raw.Reason)) == normalized.Reason &&
		strings.ToLower(strings.TrimSpace(raw.Outcome)) == normalized.Outcome &&
		strings.ToLower(strings.TrimSpace(raw.Selector)) == normalized.Selector
}

func routingProviderCategory(provider string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	switch provider {
	case "", "aistudio", "antigravity", "claude", "codex", "gemini", "gemini-cli", "gemini-interactions", "kimi", "openai", "openai-compatibility", "vertex", "xai":
		return provider
	default:
		if strings.HasPrefix(provider, "openai-compatible-") {
			return "openai-compatible"
		}
		return "custom"
	}
}

func emitRoutingEvent(observer coreexecutor.RoutingObserver, event coreexecutor.RoutingEvent) {
	if observer != nil {
		func() {
			defer func() {
				if recover() != nil {
					log.Warn("routing observer panicked; event dropped")
				}
			}()
			observer.ObserveRouting(event)
		}()
	}
}

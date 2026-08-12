package handlers

import (
	"sync/atomic"

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
	dropped atomic.Uint64
}

func newStructuredRoutingObserver() *structuredRoutingObserver {
	observer := &structuredRoutingObserver{events: make(chan coreexecutor.RoutingEvent, routingEventQueueSize)}
	go observer.run()
	return observer
}

func (o *structuredRoutingObserver) ObserveRouting(event coreexecutor.RoutingEvent) {
	if o == nil {
		return
	}
	event = coreexecutor.NormalizeRoutingEvent(event)
	select {
	case o.events <- event:
	default:
		o.dropped.Add(1)
	}
}

func (o *structuredRoutingObserver) run() {
	for event := range o.events {
		log.WithFields(log.Fields{
			"routing_schema_version":  event.SchemaVersion,
			"routing_stage":           event.Stage,
			"routing_mode":            event.Mode,
			"routing_task":            event.TaskClass,
			"routing_score_version":   event.ScoreVersion,
			"routing_model":           event.Model,
			"routing_provider":        event.Provider,
			"routing_reason":          event.Reason,
			"routing_outcome":         event.Outcome,
			"routing_attempt":         event.Attempt,
			"routing_candidate_count": event.CandidateCount,
			"routing_duration_ms":     event.Duration.Milliseconds(),
			"routing_selector":        event.Selector,
			"routing_shadow_match":    event.ShadowMatch,
		}).Info("routing decision")
	}
}

func emitRoutingEvent(observer coreexecutor.RoutingObserver, event coreexecutor.RoutingEvent) {
	if observer != nil {
		observer.ObserveRouting(coreexecutor.NormalizeRoutingEvent(event))
	}
}

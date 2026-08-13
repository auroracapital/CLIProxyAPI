package auth

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/credentialweight"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// RoutingPressureSeat is an opaque, active-only view of one credential's
// capacity-normalized concurrency pressure.
type RoutingPressureSeat struct {
	SeatBucket               string `json:"seat_bucket"`
	InFlight                 int64  `json:"in_flight"`
	Capacity                 int64  `json:"capacity"`
	ConcurrencyPressureMilli int64  `json:"concurrency_pressure_milli"`
}

// RoutingPressureSnapshot is a privacy-safe point-in-time view of active
// least-pressure reservations. It intentionally excludes identities, models,
// credential material, paths, and historical pressure signals.
type RoutingPressureSnapshot struct {
	SchemaVersion         int                    `json:"schema_version"`
	Selector              string                 `json:"selector"`
	TelemetryInstance     string                 `json:"telemetry_instance"`
	ActiveLeases          int64                  `json:"active_leases"`
	ActiveSeats           int                    `json:"active_seats"`
	Seats                 []RoutingPressureSeat  `json:"seats"`
	EligibleRoutes        []RoutingEligibleRoute `json:"eligible_routes"`
	RoutingEventsDropped  uint64                 `json:"routing_events_dropped"`
	RoutingEventsRejected uint64                 `json:"routing_events_rejected"`
}

// RoutingEligibleRoute lists opaque seats eligible for one opaque provider/model route.
type RoutingEligibleRoute struct {
	RouteBucket string                `json:"route_bucket"`
	Seats       []RoutingEligibleSeat `json:"seats"`
}

// RoutingEligibleSeat carries only the opaque seat bucket and configured
// capacity needed to validate capacity-normalized long-window fairness.
type RoutingEligibleSeat struct {
	SeatBucket string `json:"seat_bucket"`
	Capacity   int64  `json:"capacity"`
}

// RoutingPressureSnapshot returns an active-only pressure snapshot. One
// concurrency pressure unit is 1000 milli at one in-flight request per unit of
// configured credential capacity.
func (m *Manager) RoutingPressureSnapshot() RoutingPressureSnapshot {
	snapshot := RoutingPressureSnapshot{
		SchemaVersion:  2,
		Selector:       "custom",
		Seats:          make([]RoutingPressureSeat, 0),
		EligibleRoutes: make([]RoutingEligibleRoute, 0),
	}
	snapshot.TelemetryInstance, snapshot.RoutingEventsDropped, snapshot.RoutingEventsRejected = cliproxyexecutor.RoutingEventHealth()
	if m == nil {
		return snapshot
	}

	selector := m.Selector()
	var tracker *credentialPressureTracker
	switch value := selector.(type) {
	case *LeastPressureSelector:
		snapshot.Selector = "least_pressure"
		tracker = value.tracker()
	case *ShadowLeastPressureSelector:
		snapshot.Selector = "shadow_least_pressure"
		tracker = value.tracker()
	case *RoundRobinSelector:
		snapshot.Selector = "round_robin"
	case *WeightedRoundRobinSelector:
		snapshot.Selector = "weighted_round_robin"
	case *FillFirstSelector:
		snapshot.Selector = "fill_first"
	case *SessionAffinitySelector:
		snapshot.Selector = "session_affinity"
	}
	if tracker == nil {
		return snapshot
	}

	auths := m.List()
	capacityByID := make(map[string]int64)
	eligibleByRoute := make(map[string]map[string]int64)
	now := time.Now()
	for _, auth := range auths {
		if auth == nil || auth.ID == "" {
			continue
		}
		capacity := authWeight(auth)
		if capacity <= 0 {
			continue
		}
		capacityByID[auth.ID] = capacity
		seatBucket := routingSeatBucket(auth.ID)
		if seatBucket == "" {
			continue
		}
		for _, model := range registry.GetGlobalRegistry().GetModelsForClient(auth.ID) {
			if model == nil || strings.TrimSpace(model.ID) == "" {
				continue
			}
			if blocked, _, _ := isAuthBlockedForModel(auth, model.ID, now); blocked {
				continue
			}
			route := routingRouteBucket(executorKeyFromAuth(auth), model.ID)
			if route == "" {
				continue
			}
			if eligibleByRoute[route] == nil {
				eligibleByRoute[route] = make(map[string]int64)
			}
			eligibleByRoute[route][seatBucket] = capacity
		}
	}

	tracker.mu.Lock()
	for authID, inFlight := range tracker.inFlight {
		if inFlight <= 0 {
			continue
		}
		capacity := capacityByID[authID]
		if capacity <= 0 {
			capacity = credentialweight.Default
		}
		seatBucket := routingSeatBucket(authID)
		if seatBucket == "" {
			continue
		}
		snapshot.ActiveLeases = saturatingAddInt64(snapshot.ActiveLeases, inFlight)
		snapshot.Seats = append(snapshot.Seats, RoutingPressureSeat{
			SeatBucket:               seatBucket,
			InFlight:                 inFlight,
			Capacity:                 capacity,
			ConcurrencyPressureMilli: saturatingMulDiv(inFlight, 1000, capacity),
		})
	}
	tracker.mu.Unlock()

	sort.Slice(snapshot.Seats, func(i, j int) bool {
		return snapshot.Seats[i].SeatBucket < snapshot.Seats[j].SeatBucket
	})
	snapshot.ActiveSeats = len(snapshot.Seats)
	for route, seats := range eligibleByRoute {
		eligibleSeats := make([]RoutingEligibleSeat, 0, len(seats))
		for seat, capacity := range seats {
			eligibleSeats = append(eligibleSeats, RoutingEligibleSeat{SeatBucket: seat, Capacity: capacity})
		}
		sort.Slice(eligibleSeats, func(i, j int) bool {
			return eligibleSeats[i].SeatBucket < eligibleSeats[j].SeatBucket
		})
		snapshot.EligibleRoutes = append(snapshot.EligibleRoutes, RoutingEligibleRoute{RouteBucket: route, Seats: eligibleSeats})
	}
	sort.Slice(snapshot.EligibleRoutes, func(i, j int) bool {
		return snapshot.EligibleRoutes[i].RouteBucket < snapshot.EligibleRoutes[j].RouteBucket
	})
	return snapshot
}

func routingRouteBucket(provider, model string) string {
	provider = routingPressureProviderCategory(provider)
	model = strings.TrimSpace(model)
	if provider == "" || model == "" {
		return ""
	}
	digest := sha256.Sum256([]byte("cliproxy-routing-route-v1\x00" + provider + "\x00" + model))
	return fmt.Sprintf("g1_%x", digest[:8])
}

func routingPressureProviderCategory(provider string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	switch provider {
	case "aistudio", "antigravity", "claude", "codex", "gemini", "gemini-cli", "gemini-interactions", "kimi", "openai", "openai-compatibility", "vertex", "xai":
		return provider
	default:
		if strings.HasPrefix(provider, "openai-compatible-") {
			return "openai-compatible"
		}
		return "custom"
	}
}

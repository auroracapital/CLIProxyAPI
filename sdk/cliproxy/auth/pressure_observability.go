package auth

import (
	"sort"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/credentialweight"
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
	SchemaVersion int                   `json:"schema_version"`
	Selector      string                `json:"selector"`
	ActiveLeases  int64                 `json:"active_leases"`
	ActiveSeats   int                   `json:"active_seats"`
	Seats         []RoutingPressureSeat `json:"seats"`
}

// RoutingPressureSnapshot returns an active-only pressure snapshot. One
// concurrency pressure unit is 1000 milli at one in-flight request per unit of
// configured credential capacity.
func (m *Manager) RoutingPressureSnapshot() RoutingPressureSnapshot {
	snapshot := RoutingPressureSnapshot{
		SchemaVersion: 1,
		Selector:      "custom",
		Seats:         make([]RoutingPressureSeat, 0),
	}
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

	capacityByID := make(map[string]int64)
	for _, auth := range m.List() {
		if auth == nil || auth.ID == "" {
			continue
		}
		capacity := authWeight(auth)
		if capacity <= 0 {
			continue
		}
		capacityByID[auth.ID] = capacity
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
	return snapshot
}

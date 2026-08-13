package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/credentialweight"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/thinking"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	cliproxysession "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/session"
)

var routingSeatBucketKey, routingSeatBucketEnabled = newRoutingSeatBucketKey()

func newRoutingSeatBucketKey() ([32]byte, bool) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return key, false
	}
	return key, true
}

func routingSeatBucket(authID string) string {
	authID = strings.TrimSpace(authID)
	if authID == "" || !routingSeatBucketEnabled {
		return ""
	}
	digest := hmac.New(sha256.New, routingSeatBucketKey[:])
	_, _ = digest.Write([]byte("cliproxy-routing-seat-v1\x00"))
	_, _ = digest.Write([]byte(authID))
	return fmt.Sprintf("h1_%x", digest.Sum(nil)[:8])
}

func predictedRoutingSeatBucket(auth *Auth) string {
	if auth == nil {
		return ""
	}
	return routingSeatBucket(auth.ID)
}

// RoundRobinSelector provides a simple provider scoped round-robin selection strategy.
type RoundRobinSelector struct {
	mu      sync.Mutex
	cursors map[string]int
	maxKeys int
}

// WeightedRoundRobinSelector provides smooth weighted round-robin selection.
type WeightedRoundRobinSelector struct {
	mu      sync.Mutex
	states  map[string]*smoothWeightedState
	maxKeys int
}

// LeastPressureSelector chooses the credential with the lowest observed pressure.
// Pressure combines current in-flight executions, configured credential weight as
// capacity, and the recent failure ratio. Manager execution paths reserve the
// selected credential atomically; direct Pick calls remain observation-only.
type LeastPressureSelector struct {
	pressure credentialPressureTracker
}

// ShadowLeastPressureSelector executes its fallback selector while predicting
// which eligible credential least-pressure would choose. Only the actual
// production selection is tracked as in-flight; the prediction never reserves
// capacity or advances a least-pressure tie cursor.
type ShadowLeastPressureSelector struct {
	fallback Selector
	pressure credentialPressureTracker
}

// NewShadowLeastPressureSelector creates a prediction-only least-pressure
// wrapper around the production selector.
func NewShadowLeastPressureSelector(fallback Selector) *ShadowLeastPressureSelector {
	if fallback == nil {
		fallback = &RoundRobinSelector{}
	}
	return &ShadowLeastPressureSelector{fallback: fallback}
}

type credentialPressureTracker struct {
	mu           sync.Mutex
	inFlight     map[string]int64
	cursors      map[string]int
	observations map[string]credentialPressureObservation
}

type credentialPressureLease struct {
	tracker   *credentialPressureTracker
	authID    string
	startedAt time.Time
	once      sync.Once
}

type credentialPressureObservation struct {
	latencyEWMA         time.Duration
	consecutiveFailures int64
}

const maxCredentialPressureObservations = 4096

func (l *credentialPressureLease) Release() {
	if l == nil || l.tracker == nil || l.authID == "" {
		return
	}
	l.once.Do(func() {
		now := time.Now()
		l.tracker.mu.Lock()
		defer l.tracker.mu.Unlock()
		if current := l.tracker.inFlight[l.authID]; current > 1 {
			l.tracker.inFlight[l.authID] = current - 1
		} else {
			delete(l.tracker.inFlight, l.authID)
		}
		if !l.startedAt.IsZero() && now.After(l.startedAt) {
			l.tracker.observeLatencyLocked(l.authID, now.Sub(l.startedAt))
		}
	})
}

func (t *credentialPressureTracker) observeLatencyLocked(authID string, latency time.Duration) {
	if t == nil || authID == "" || latency <= 0 {
		return
	}
	const maxObservedLatency = 10 * time.Minute
	if latency > maxObservedLatency {
		latency = maxObservedLatency
	}
	t.ensureObservationCapacityLocked(authID)
	observation := t.observations[authID]
	if observation.latencyEWMA <= 0 {
		observation.latencyEWMA = latency
	} else {
		// Give the newest request 25% weight. Integer duration arithmetic keeps
		// the hot selection path deterministic and allocation-free.
		observation.latencyEWMA = (observation.latencyEWMA*3 + latency) / 4
	}
	t.observations[authID] = observation
}

func (t *credentialPressureTracker) observeOutcome(authID string, success bool) {
	if t == nil || authID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ensureObservationCapacityLocked(authID)
	observation := t.observations[authID]
	if success {
		observation.consecutiveFailures = 0
	} else if observation.consecutiveFailures < math.MaxInt64 {
		observation.consecutiveFailures++
	}
	t.observations[authID] = observation
}

func (t *credentialPressureTracker) ensureObservationCapacityLocked(authID string) {
	if t.observations == nil {
		t.observations = make(map[string]credentialPressureObservation)
		return
	}
	if _, exists := t.observations[authID]; !exists && len(t.observations) >= maxCredentialPressureObservations {
		t.observations = make(map[string]credentialPressureObservation)
	}
}

func (s *LeastPressureSelector) tracker() *credentialPressureTracker {
	if s == nil {
		return nil
	}
	return &s.pressure
}

func (s *ShadowLeastPressureSelector) tracker() *credentialPressureTracker {
	if s == nil {
		return nil
	}
	return &s.pressure
}

func recentRequestTotals(auth *Auth, now time.Time) (success, failed int64) {
	if auth == nil {
		return 0, 0
	}
	currentBucketID := recentRequestBucketID(now)
	for i := 0; i < recentRequestBucketCount; i++ {
		bucketID := currentBucketID - int64(i)
		bucket := auth.recentRequests.buckets[recentRequestBucketIndex(bucketID)]
		if bucket.bucketID != bucketID {
			continue
		}
		success = saturatingAddInt64(success, bucket.success)
		failed = saturatingAddInt64(failed, bucket.failed)
	}
	return success, failed
}

func credentialPressureScore(auth *Auth, model string, inFlight int64, observation credentialPressureObservation, now time.Time) int64 {
	capacity := authWeight(auth)
	if capacity <= 0 {
		capacity = credentialweight.Default
	}
	// One unit of concurrency pressure is comparable to a 100% recent failure
	// ratio. Request volume is capacity-normalized so a bursty but successful seat
	// is spread before it reaches an upstream admission limit. A small prior keeps
	// one historical failure from permanently dominating an otherwise idle seat.
	concurrencyPressure := saturatingMulDiv(inFlight, 1000, capacity)
	success, failed := recentRequestTotals(auth, now)
	total := saturatingAddInt64(success, failed)
	requestRatePressure := saturatingMulDiv(total, 25, capacity)
	failurePressure := saturatingMulDiv(failed, 1000, saturatingAddInt64(total, 10))
	expiryPressure := credentialExpiryPressure(auth, now)
	latencyPressure := credentialLatencyPressure(observation.latencyEWMA)
	consecutiveFailurePressure := saturatingMulDiv(observation.consecutiveFailures, 250, 1)
	if consecutiveFailurePressure > 1000 {
		consecutiveFailurePressure = 1000
	}
	quotaPressure := credentialQuotaRecoveryPressure(auth, model, now)
	return saturatingAddInt64(
		saturatingAddInt64(concurrencyPressure, requestRatePressure),
		saturatingAddInt64(
			saturatingAddInt64(failurePressure, expiryPressure),
			saturatingAddInt64(saturatingAddInt64(latencyPressure, consecutiveFailurePressure), quotaPressure),
		),
	)
}

func credentialLatencyPressure(latency time.Duration) int64 {
	if latency <= 0 {
		return 0
	}
	// Ten milliseconds is one pressure point. Cap latency so an old outlier
	// cannot permanently starve a credential after it has recovered.
	pressure := int64(latency / (10 * time.Millisecond))
	if pressure > 1000 {
		return 1000
	}
	return pressure
}

func credentialQuotaRecoveryPressure(auth *Auth, model string, now time.Time) int64 {
	if auth == nil {
		return 0
	}
	quota := auth.Quota
	if state := auth.ModelStates[canonicalModelKey(model)]; state != nil && quotaStateHasPressureSignal(state.Quota) {
		quota = state.Quota
	}
	// Exceeded credentials with an open recovery window are hard-excluded by
	// availability filtering. Backoff level remains a useful provider-supplied
	// risk signal during recovery without guessing at quota providers do not
	// expose. An explicit future recovery time adds a bounded proximity penalty.
	pressure := int64(0)
	if quota.BackoffLevel > 0 {
		pressure = saturatingMulDiv(int64(quota.BackoffLevel), 100, 1)
	}
	if pressure > 1000 {
		pressure = 1000
	}
	if !quota.NextRecoverAt.IsZero() && quota.NextRecoverAt.After(now) {
		remaining := quota.NextRecoverAt.Sub(now)
		const recoveryRiskWindow = 30 * time.Minute
		if remaining < recoveryRiskWindow {
			pressure = saturatingAddInt64(pressure, int64((recoveryRiskWindow-remaining)*500/recoveryRiskWindow))
		}
	}
	return pressure
}

func quotaStateHasPressureSignal(quota QuotaState) bool {
	return quota.Exceeded || quota.BackoffLevel > 0 || !quota.NextRecoverAt.IsZero()
}

func credentialExpiryPressure(auth *Auth, now time.Time) int64 {
	if auth == nil {
		return 0
	}
	expiresAt, okExpiry := auth.ExpirationTime()
	if !okExpiry || expiresAt.IsZero() {
		return 0
	}
	remaining := expiresAt.Sub(now)
	if remaining <= 0 {
		return 1000
	}
	const riskWindow = 30 * time.Minute
	if remaining >= riskWindow {
		return 0
	}
	return int64((riskWindow - remaining) * 1000 / riskWindow)
}

func saturatingMulDiv(value, multiplier, divisor int64) int64 {
	if value <= 0 || multiplier <= 0 || divisor <= 0 {
		return 0
	}
	if value > math.MaxInt64/multiplier {
		return math.MaxInt64 / divisor
	}
	return value * multiplier / divisor
}

func pickLeastPressureAuth(auths []*Auth, tracker *credentialPressureTracker, cursorKey, model string, predicate func(*Auth) bool, now time.Time) *Auth {
	if tracker == nil {
		return nil
	}
	if tracker.inFlight == nil {
		tracker.inFlight = make(map[string]int64)
	}
	if tracker.cursors == nil {
		tracker.cursors = make(map[string]int)
	}
	if _, exists := tracker.cursors[cursorKey]; !exists && len(tracker.cursors) >= 4096 {
		tracker.cursors = make(map[string]int)
	}
	bestScore := int64(math.MaxInt64)
	ties := make([]*Auth, 0, len(auths))
	for _, candidate := range auths {
		if candidate == nil || (predicate != nil && !predicate(candidate)) {
			continue
		}
		score := credentialPressureScore(candidate, model, tracker.inFlight[candidate.ID], tracker.observations[candidate.ID], now)
		switch {
		case score < bestScore:
			bestScore = score
			ties = append(ties[:0], candidate)
		case score == bestScore:
			ties = append(ties, candidate)
		}
	}
	if len(ties) == 0 {
		return nil
	}
	cursor := tracker.cursors[cursorKey]
	index := normalizeCursor(cursor, len(ties))
	tracker.cursors[cursorKey] = cursor + 1
	return ties[index]
}

type smoothWeightedState struct {
	current map[string]int64
	weights map[string]int64
}

type weightedSelectorStateModelKey struct{}

func requestPressureReservation(opts cliproxyexecutor.Options) cliproxyexecutor.Options {
	if len(opts.Metadata) == 0 {
		opts.Metadata = make(map[string]any)
	} else {
		copyMetadata := make(map[string]any, len(opts.Metadata)+1)
		for key, value := range opts.Metadata {
			copyMetadata[key] = value
		}
		opts.Metadata = copyMetadata
	}
	opts.Metadata[pressureReservationMetadataKey] = true
	return opts
}

const pressureReservationMetadataKey = "cliproxy_internal_pressure_reservation"

func pressureReservationRequested(opts cliproxyexecutor.Options) bool {
	requested, _ := opts.Metadata[pressureReservationMetadataKey].(bool)
	return requested
}

func attachCredentialPressureLease(auth *Auth, tracker *credentialPressureTracker) {
	if auth == nil || tracker == nil || auth.ID == "" {
		return
	}
	auth.pressureLease = &credentialPressureLease{tracker: tracker, authID: auth.ID, startedAt: time.Now()}
}

func releaseCredentialPressure(auth *Auth) {
	if auth == nil || auth.pressureLease == nil {
		return
	}
	auth.pressureLease.Release()
	auth.pressureLease = nil
}

func takeCredentialPressureLease(auth *Auth) *credentialPressureLease {
	if auth == nil {
		return nil
	}
	lease := auth.pressureLease
	auth.pressureLease = nil
	return lease
}

func withWeightedSelectorStateModel(ctx context.Context, selector Selector, routeModel string) context.Context {
	if _, ok := selector.(*WeightedRoundRobinSelector); !ok || strings.TrimSpace(routeModel) == "" {
		return ctx
	}
	return context.WithValue(ctx, weightedSelectorStateModelKey{}, routeModel)
}

func weightedSelectorStateModel(ctx context.Context, availabilityModel string) string {
	if ctx != nil {
		if routeModel, ok := ctx.Value(weightedSelectorStateModelKey{}).(string); ok && strings.TrimSpace(routeModel) != "" {
			return routeModel
		}
	}
	return availabilityModel
}

// FillFirstSelector selects the first available credential (deterministic ordering).
// This "burns" one account before moving to the next, which can help stagger
// rolling-window subscription caps (e.g. chat message limits).
type FillFirstSelector struct{}

type blockReason int

const (
	blockReasonNone blockReason = iota
	blockReasonCooldown
	blockReasonDisabled
	blockReasonOther
)

type modelCooldownError struct {
	model    string
	resetIn  time.Duration
	provider string
}

func newModelCooldownError(model, provider string, resetIn time.Duration) *modelCooldownError {
	if resetIn < 0 {
		resetIn = 0
	}
	return &modelCooldownError{
		model:    model,
		provider: provider,
		resetIn:  resetIn,
	}
}

func (e *modelCooldownError) Error() string {
	modelName := e.model
	if modelName == "" {
		modelName = "requested model"
	}
	message := fmt.Sprintf("All credentials for model %s are cooling down", modelName)
	if e.provider != "" {
		message = fmt.Sprintf("%s via provider %s", message, e.provider)
	}
	resetSeconds := int(math.Ceil(e.resetIn.Seconds()))
	if resetSeconds < 0 {
		resetSeconds = 0
	}
	displayDuration := e.resetIn
	if displayDuration > 0 && displayDuration < time.Second {
		displayDuration = time.Second
	} else {
		displayDuration = displayDuration.Round(time.Second)
	}
	errorBody := map[string]any{
		"code":          "model_cooldown",
		"message":       message,
		"model":         e.model,
		"reset_time":    displayDuration.String(),
		"reset_seconds": resetSeconds,
	}
	if e.provider != "" {
		errorBody["provider"] = e.provider
	}
	payload := map[string]any{"error": errorBody}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprintf(`{"error":{"code":"model_cooldown","message":"%s"}}`, message)
	}
	return string(data)
}

func (e *modelCooldownError) StatusCode() int {
	return http.StatusTooManyRequests
}

func (e *modelCooldownError) Headers() http.Header {
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	resetSeconds := int(math.Ceil(e.resetIn.Seconds()))
	if resetSeconds < 0 {
		resetSeconds = 0
	}
	headers.Set("Retry-After", strconv.Itoa(resetSeconds))
	return headers
}

func authPriority(auth *Auth) int {
	if auth == nil || auth.Attributes == nil {
		return 0
	}
	raw := strings.TrimSpace(auth.Attributes["priority"])
	if raw == "" {
		return 0
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil {
		return 0
	}
	return parsed
}

func authWeight(auth *Auth) int64 {
	if auth == nil {
		return credentialweight.Default
	}
	if rawWeight, ok := auth.Attributes[AttributeWeight]; ok && strings.TrimSpace(rawWeight) != "" {
		weight, errParse := credentialweight.ParseString(rawWeight)
		if errParse != nil {
			return 0
		}
		return weight
	}
	if rawWeight, ok := auth.Metadata[AttributeWeight]; ok {
		weight, errParse := credentialweight.ParseValue(rawWeight)
		if errParse != nil {
			return 0
		}
		return weight
	}
	return credentialweight.Default
}

func canonicalModelKey(model string) string {
	model = strings.TrimSpace(model)
	if model == "" {
		return ""
	}
	parsed := thinking.ParseSuffix(model)
	modelName := strings.TrimSpace(parsed.ModelName)
	if modelName == "" {
		return model
	}
	return modelName
}

func authWebsocketsEnabled(auth *Auth) bool {
	if auth == nil {
		return false
	}
	if len(auth.Attributes) > 0 {
		if raw := strings.TrimSpace(auth.Attributes["websockets"]); raw != "" {
			parsed, errParse := strconv.ParseBool(raw)
			if errParse == nil {
				return parsed
			}
		}
	}
	if len(auth.Metadata) == 0 {
		return false
	}
	raw, ok := auth.Metadata["websockets"]
	if !ok || raw == nil {
		return false
	}
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		parsed, errParse := strconv.ParseBool(strings.TrimSpace(v))
		if errParse == nil {
			return parsed
		}
	default:
	}
	return false
}

func preferCodexWebsocketAuths(ctx context.Context, provider string, available []*Auth) []*Auth {
	if len(available) == 0 {
		return available
	}
	if !cliproxyexecutor.DownstreamWebsocket(ctx) {
		return available
	}
	if !strings.EqualFold(strings.TrimSpace(provider), "codex") {
		return available
	}

	wsEnabled := make([]*Auth, 0, len(available))
	for i := 0; i < len(available); i++ {
		candidate := available[i]
		if authWebsocketsEnabled(candidate) {
			wsEnabled = append(wsEnabled, candidate)
		}
	}
	if len(wsEnabled) > 0 {
		return wsEnabled
	}
	return available
}

func collectAvailableByPriority(auths []*Auth, model string, now time.Time) (available map[int][]*Auth, cooldownCount int, earliest time.Time) {
	available = make(map[int][]*Auth)
	for i := 0; i < len(auths); i++ {
		candidate := auths[i]
		blocked, reason, next := isAuthBlockedForModel(candidate, model, now)
		if !blocked {
			priority := authPriority(candidate)
			available[priority] = append(available[priority], candidate)
			continue
		}
		if reason == blockReasonCooldown {
			cooldownCount++
			if !next.IsZero() && (earliest.IsZero() || next.Before(earliest)) {
				earliest = next
			}
		}
	}
	return available, cooldownCount, earliest
}

func getAvailableAuths(auths []*Auth, provider, model string, now time.Time) ([]*Auth, error) {
	return getAvailableAuthsWithPriorityMode(auths, provider, model, now, false)
}

func getAvailableAuthsAcrossPriorities(auths []*Auth, provider, model string, now time.Time) ([]*Auth, error) {
	return getAvailableAuthsWithPriorityMode(auths, provider, model, now, true)
}

func getAvailableAuthsWithPriorityMode(auths []*Auth, provider, model string, now time.Time, allPriorities bool) ([]*Auth, error) {
	if len(auths) == 0 {
		return nil, &Error{Code: "auth_not_found", Message: "no auth candidates"}
	}

	availableByPriority, cooldownCount, earliest := collectAvailableByPriority(auths, model, now)
	if len(availableByPriority) == 0 {
		if cooldownCount == len(auths) && !earliest.IsZero() {
			providerForError := provider
			if providerForError == "mixed" {
				providerForError = ""
			}
			resetIn := earliest.Sub(now)
			if resetIn < 0 {
				resetIn = 0
			}
			return nil, newModelCooldownError(model, providerForError, resetIn)
		}
		return nil, &Error{Code: "auth_unavailable", Message: "no auth available"}
	}

	return availableAuthsFromPriorityBuckets(availableByPriority, allPriorities), nil
}

// availableAuthsFromPriorityBuckets flattens availability buckets into a stable, ID-sorted slice.
// When allPriorities is false only the highest available priority tier is returned.
// When allPriorities is true every tier is merged, so the result carries no priority ordering:
// use it for membership checks or feed it to highestPriorityAuths, never as a priority-ordered
// selection order.
func availableAuthsFromPriorityBuckets(availableByPriority map[int][]*Auth, allPriorities bool) []*Auth {
	var candidates []*Auth
	if allPriorities {
		total := 0
		for _, bucket := range availableByPriority {
			total += len(bucket)
		}
		candidates = make([]*Auth, 0, total)
		for _, bucket := range availableByPriority {
			candidates = append(candidates, bucket...)
		}
	} else {
		bestPriority := 0
		found := false
		for priority := range availableByPriority {
			if !found || priority > bestPriority {
				bestPriority = priority
				found = true
			}
		}
		bucket := availableByPriority[bestPriority]
		candidates = make([]*Auth, 0, len(bucket))
		candidates = append(candidates, bucket...)
	}
	if len(candidates) > 1 {
		sort.Slice(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })
	}
	return candidates
}

// highestPriorityAuths narrows an availability slice to its highest priority tier while
// preserving the input order. The input slice is returned unchanged when every candidate
// already shares the highest priority, so the common single-tier case allocates nothing.
func highestPriorityAuths(auths []*Auth) []*Auth {
	if len(auths) <= 1 {
		return auths
	}
	bestPriority := 0
	bestCount := 0
	for _, auth := range auths {
		priority := authPriority(auth)
		switch {
		case bestCount == 0 || priority > bestPriority:
			bestPriority = priority
			bestCount = 1
		case priority == bestPriority:
			bestCount++
		}
	}
	if bestCount == len(auths) {
		return auths
	}
	highest := make([]*Auth, 0, bestCount)
	for _, auth := range auths {
		if authPriority(auth) == bestPriority {
			highest = append(highest, auth)
		}
	}
	return highest
}

// Pick selects the next available auth for the provider in a round-robin manner.
func (s *RoundRobinSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	now := time.Now()
	available, err := getAvailableAuths(auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	key := provider + ":" + canonicalModelKey(model)
	s.mu.Lock()
	if s.cursors == nil {
		s.cursors = make(map[string]int)
	}
	limit := s.maxKeys
	if limit <= 0 {
		limit = 4096
	}

	s.ensureCursorKey(key, limit)
	index := s.cursors[key]
	if index >= 2_147_483_640 {
		index = 0
	}
	s.cursors[key] = index + 1
	s.mu.Unlock()
	return available[index%len(available)], nil
}

// ensureCursorKey ensures the cursor map has capacity for the given key.
// Must be called with s.mu held.
func (s *RoundRobinSelector) ensureCursorKey(key string, limit int) {
	if _, ok := s.cursors[key]; !ok && len(s.cursors) >= limit {
		s.cursors = make(map[string]int)
	}
}

func positiveWeightAuths(auths []*Auth) []*Auth {
	weightedCandidates := make([]*Auth, 0, len(auths))
	for _, auth := range auths {
		if authWeight(auth) > 0 {
			weightedCandidates = append(weightedCandidates, auth)
		}
	}
	return weightedCandidates
}

// Pick selects the next available auth using smooth weighted round-robin.
func (s *WeightedRoundRobinSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	available, errAvailable := getAvailableAuths(positiveWeightAuths(auths), provider, model, time.Now())
	if errAvailable != nil {
		return nil, errAvailable
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	stateModel := weightedSelectorStateModel(ctx, model)
	key := provider + ":" + canonicalModelKey(stateModel)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.states == nil {
		s.states = make(map[string]*smoothWeightedState)
	}
	limit := s.maxKeys
	if limit <= 0 {
		limit = 4096
	}
	if _, ok := s.states[key]; !ok && len(s.states) >= limit {
		s.states = make(map[string]*smoothWeightedState)
	}
	state := s.states[key]
	if state == nil {
		state = &smoothWeightedState{}
		s.states[key] = state
	}
	weights := authWeightVector(available)
	state.prepare(weights)
	picked := pickSmoothWeightedAuth(available, state.current)
	if picked == nil {
		return nil, &Error{Code: "auth_unavailable", Message: "no auth available with positive weight"}
	}
	return picked, nil
}

// Pick selects the least-pressured available credential without reserving it.
// Manager execution paths use the scheduler's atomic reserve variant instead.
func (s *LeastPressureSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	available, errAvailable := getAvailableAuths(positiveWeightAuths(auths), provider, model, time.Now())
	if errAvailable != nil {
		return nil, errAvailable
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	tracker := s.tracker()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	selected := pickLeastPressureAuth(available, tracker, provider+":"+canonicalModelKey(model), model, nil, time.Now())
	if selected == nil {
		return nil, &Error{Code: "auth_unavailable", Message: "no auth available"}
	}
	if pressureReservationRequested(opts) {
		tracker.inFlight[selected.ID]++
		selected.pressureLease = &credentialPressureLease{tracker: tracker, authID: selected.ID, startedAt: time.Now()}
	}
	return selected, nil
}

// Pick predicts least pressure without changing that prediction's state, then
// executes the configured production selector exactly once.
func (s *ShadowLeastPressureSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	if s == nil || s.fallback == nil {
		return nil, &Error{Code: "auth_unavailable", Message: "shadow selector is unavailable"}
	}
	available, errAvailable := getAvailableAuths(positiveWeightAuths(auths), provider, model, time.Now())
	if errAvailable != nil {
		return nil, errAvailable
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	tracker := s.tracker()
	tracker.mu.Lock()
	predicted := predictLeastPressureAuth(available, tracker, model, time.Now())
	tracker.mu.Unlock()

	actual, errPick := s.fallback.Pick(ctx, provider, model, opts, auths)
	if errPick != nil {
		return nil, errPick
	}
	if actual == nil {
		return nil, &Error{Code: "auth_unavailable", Message: "production selector returned no auth"}
	}
	if pressureReservationRequested(opts) {
		tracker.mu.Lock()
		if tracker.inFlight == nil {
			tracker.inFlight = make(map[string]int64)
		}
		tracker.inFlight[actual.ID]++
		tracker.mu.Unlock()
		actual.pressureLease = &credentialPressureLease{tracker: tracker, authID: actual.ID, startedAt: time.Now()}
	}
	if opts.RoutingObserver != nil {
		opts.RoutingObserver.ObserveRouting(cliproxyexecutor.RoutingEvent{
			Stage:               "account_prediction",
			Mode:                "shadow",
			Model:               model,
			Provider:            provider,
			Outcome:             "predicted",
			CandidateCount:      len(available),
			Selector:            "shadow_least_pressure",
			ShadowMatch:         predicted != nil && predicted.ID == actual.ID,
			SeatBucket:          routingSeatBucket(actual.ID),
			PredictedSeatBucket: predictedRoutingSeatBucket(predicted),
		})
	}
	return actual, nil
}

func predictLeastPressureAuth(auths []*Auth, tracker *credentialPressureTracker, model string, now time.Time) *Auth {
	if tracker == nil {
		return nil
	}
	var selected *Auth
	bestScore := int64(math.MaxInt64)
	for _, candidate := range auths {
		if candidate == nil {
			continue
		}
		score := credentialPressureScore(candidate, model, tracker.inFlight[candidate.ID], tracker.observations[candidate.ID], now)
		if selected == nil || score < bestScore || (score == bestScore && candidate.ID < selected.ID) {
			selected = candidate
			bestScore = score
		}
	}
	return selected
}

func (s *smoothWeightedState) prepare(weights map[string]int64) {
	if s.current == nil || !weightVectorsEqual(s.weights, weights) {
		s.current = make(map[string]int64)
	}
	s.weights = weights
}

func weightVectorsEqual(left, right map[string]int64) bool {
	if len(left) != len(right) {
		return false
	}
	for authID, weight := range left {
		if right[authID] != weight {
			return false
		}
	}
	return true
}

func authWeightVector(auths []*Auth) map[string]int64 {
	weights := make(map[string]int64, len(auths))
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		if weight := authWeight(auth); weight > 0 {
			weights[auth.ID] = weight
		}
	}
	return weights
}

func pickSmoothWeightedAuth(auths []*Auth, current map[string]int64) *Auth {
	active := make(map[string]struct{}, len(auths))
	var picked *Auth
	var pickedCurrent int64
	var totalWeight int64
	for _, auth := range auths {
		weight := authWeight(auth)
		if auth == nil || weight <= 0 {
			continue
		}
		active[auth.ID] = struct{}{}
		current[auth.ID] = saturatingAddInt64(current[auth.ID], weight)
		totalWeight = saturatingAddInt64(totalWeight, weight)
		if picked == nil || current[auth.ID] > pickedCurrent {
			picked = auth
			pickedCurrent = current[auth.ID]
		}
	}
	for authID := range current {
		if _, ok := active[authID]; !ok {
			delete(current, authID)
		}
	}
	if picked == nil {
		return nil
	}
	current[picked.ID] = saturatingAddInt64(current[picked.ID], -totalWeight)
	return picked
}

func saturatingAddInt64(value, delta int64) int64 {
	if delta > 0 && value > math.MaxInt64-delta {
		return math.MaxInt64
	}
	if delta < 0 && value < math.MinInt64-delta {
		return math.MinInt64
	}
	return value + delta
}

// Pick selects the first available auth for the provider in a deterministic manner.
func (s *FillFirstSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	now := time.Now()
	available, err := getAvailableAuths(auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	return available[0], nil
}

func isAuthBlockedForModel(auth *Auth, model string, now time.Time) (bool, blockReason, time.Time) {
	if auth == nil {
		return true, blockReasonOther, time.Time{}
	}
	if auth.Disabled || auth.Status == StatusDisabled || !auth.reconcileReady() {
		return true, blockReasonDisabled, time.Time{}
	}
	if model != "" {
		if len(auth.ModelStates) > 0 {
			modelKey := canonicalModelKey(model)
			matched := false
			blocked := false
			blockedReason := blockReasonNone
			nextRetry := time.Time{}
			for stateModel, state := range auth.ModelStates {
				if state == nil || canonicalModelKey(stateModel) != modelKey {
					continue
				}
				matched = true
				if state.Status == StatusDisabled {
					return true, blockReasonDisabled, time.Time{}
				}
				stateBlocked, reason, next := availabilityBlock(state.Unavailable, state.Quota.Exceeded, state.NextRetryAfter, state.Quota.NextRecoverAt, now)
				if !stateBlocked {
					continue
				}
				if next.IsZero() {
					return true, reason, time.Time{}
				}
				if !blocked || next.After(nextRetry) || (next.Equal(nextRetry) && reason == blockReasonCooldown) {
					blocked = true
					blockedReason = reason
					nextRetry = next
				}
			}
			if matched {
				return blocked, blockedReason, nextRetry
			}
			// Auth-level availability can aggregate failures from other models.
			return false, blockReasonNone, time.Time{}
		}
		return availabilityBlock(auth.Unavailable, auth.Quota.Exceeded, auth.NextRetryAfter, auth.Quota.NextRecoverAt, now)
	}
	return availabilityBlock(auth.Unavailable, auth.Quota.Exceeded, auth.NextRetryAfter, auth.Quota.NextRecoverAt, now)
}

func availabilityBlock(unavailable, quotaExceeded bool, nextRetryAfter, nextRecoverAt, now time.Time) (bool, blockReason, time.Time) {
	if !unavailable && !quotaExceeded {
		return false, blockReasonNone, time.Time{}
	}

	hasRecoveryTime := !nextRetryAfter.IsZero() || !nextRecoverAt.IsZero()
	var next time.Time
	for _, candidate := range []time.Time{nextRetryAfter, nextRecoverAt} {
		if candidate.After(now) && (next.IsZero() || candidate.After(next)) {
			next = candidate
		}
	}
	if !next.IsZero() {
		if quotaExceeded {
			return true, blockReasonCooldown, next
		}
		return true, blockReasonOther, next
	}
	if hasRecoveryTime {
		return false, blockReasonNone, time.Time{}
	}
	return true, blockReasonOther, time.Time{}
}

// SessionAffinitySelector wraps another selector with session-sticky behavior.
// It extracts session ID from multiple sources and maintains session-to-auth
// mappings with automatic failover when the bound auth becomes unavailable.
type SessionAffinitySelector struct {
	fallback Selector
	cache    *SessionCache
}

// SessionAffinityConfig configures the session affinity selector.
type SessionAffinityConfig struct {
	Fallback Selector
	TTL      time.Duration
}

// NewSessionAffinitySelector creates a new session-aware selector.
func NewSessionAffinitySelector(fallback Selector) *SessionAffinitySelector {
	return NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: fallback,
		TTL:      time.Hour,
	})
}

// NewSessionAffinitySelectorWithConfig creates a selector with custom configuration.
func NewSessionAffinitySelectorWithConfig(cfg SessionAffinityConfig) *SessionAffinitySelector {
	if cfg.Fallback == nil {
		cfg.Fallback = &RoundRobinSelector{}
	}
	if cfg.TTL <= 0 {
		cfg.TTL = time.Hour
	}
	return &SessionAffinitySelector{
		fallback: cfg.Fallback,
		cache:    NewSessionCache(cfg.TTL),
	}
}

// Pick selects an auth with session affinity when possible.
// Explicit Claude Code, Codex, OpenCode, pi, and request-body session signals
// precede execution metadata, stable derived identity, and the legacy hash fallback.
//
// An established binding outranks credential priority: a bound credential that is still
// available is reused even when a higher-priority credential recovers. Credential priority
// applies to cold bindings, requests without a session, and genuine bound-credential
// failover, so the fallback selector only ever receives the highest available priority tier.
//
// Note: The cache key includes provider, session ID, and model to handle cases where
// a session uses multiple models (e.g., gemini-2.5-pro and gemini-3-flash-preview)
// that may be supported by different auth credentials, and to avoid cross-provider conflicts.
func (s *SessionAffinitySelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	entry := selectorLogEntry(ctx)
	primaryID, fallbackID := extractSessionIDs(opts.Headers, opts.OriginalRequest, opts.Metadata)
	now := time.Now()
	availabilityCandidates := auths
	if _, weighted := s.fallback.(*WeightedRoundRobinSelector); weighted {
		availabilityCandidates = positiveWeightAuths(auths)
	}
	if primaryID == "" {
		fallbackAuths, errAvailable := getAvailableAuths(availabilityCandidates, provider, model, now)
		if errAvailable != nil {
			return nil, errAvailable
		}
		entry.Debugf("session-affinity: no session ID extracted, falling back to default selector | provider=%s model=%s", provider, model)
		return s.fallback.Pick(ctx, provider, model, opts, fallbackAuths)
	}

	// A single availability pass serves both lookups: the bound credential is validated against
	// every priority tier, while the fallback selector keeps seeing only the highest tier.
	available, err := getAvailableAuthsAcrossPriorities(availabilityCandidates, provider, model, now)
	if err != nil {
		return nil, err
	}
	fallbackAuths := highestPriorityAuths(available)

	cacheKey := provider + "::" + primaryID + "::" + model
	fallbackKey := ""
	if fallbackID != "" && fallbackID != primaryID {
		fallbackKey = provider + "::" + fallbackID + "::" + model
	}
	bind := func(authID string) {
		if fallbackKey != "" {
			s.cache.SetAliases(authID, cacheKey, fallbackKey)
			return
		}
		s.cache.Set(cacheKey, authID)
	}

	if cachedAuthID, ok := s.cache.GetAndRefresh(cacheKey); ok {
		for _, auth := range available {
			if auth.ID == cachedAuthID {
				bind(auth.ID)
				entry.WithFields(log.Fields{"provider": provider, "model": model}).Debug("session-affinity cache hit")
				return auth, nil
			}
		}
		// Cached auth not available, reselect via fallback selector for even distribution
		auth, err := s.fallback.Pick(ctx, provider, model, opts, fallbackAuths)
		if err != nil {
			return nil, err
		}
		bind(auth.ID)
		entry.WithFields(log.Fields{"provider": provider, "model": model}).Debug("session-affinity reselected unavailable binding")
		return auth, nil
	}

	if fallbackKey != "" {
		if cachedAuthID, ok := s.cache.Get(fallbackKey); ok {
			for _, auth := range available {
				if auth.ID == cachedAuthID {
					bind(auth.ID)
					entry.WithFields(log.Fields{"provider": provider, "model": model}).Debug("session-affinity fallback cache hit")
					return auth, nil
				}
			}
		}
	}

	auth, err := s.fallback.Pick(ctx, provider, model, opts, fallbackAuths)
	if err != nil {
		return nil, err
	}
	bind(auth.ID)
	entry.WithFields(log.Fields{"provider": provider, "model": model}).Debug("session-affinity new binding")
	return auth, nil
}

func selectorLogEntry(ctx context.Context) *log.Entry {
	if ctx == nil {
		return log.NewEntry(log.StandardLogger())
	}
	if reqID := logging.GetRequestID(ctx); reqID != "" {
		return log.WithField("request_id", reqID)
	}
	return log.NewEntry(log.StandardLogger())
}

// truncateSessionID shortens session ID for logging (first 8 chars + "...")
func truncateSessionID(id string) string {
	if len(id) <= 20 {
		return id
	}
	return id[:8] + "..."
}

// Stop releases resources held by the selector.
func (s *SessionAffinitySelector) Stop() {
	if s.cache != nil {
		s.cache.Stop()
	}
}

// InvalidateAuth removes all session bindings for a specific auth.
// Called when an auth becomes rate-limited or unavailable.
func (s *SessionAffinitySelector) InvalidateAuth(authID string) {
	if s.cache != nil {
		s.cache.InvalidateAuth(authID)
	}
}

// normalizedSessionCandidate validates an explicit client-provided session signal.
// It keeps opaque printable IDs intact while rejecting values that are unsafe or
// implausibly large for routing keys and logs.
func normalizedSessionCandidate(raw string) string {
	return cliproxysession.NormalizeExplicitID(raw)
}

func sessionHeaderValue(headers http.Header, name string) string {
	if headers == nil {
		return ""
	}
	if value := normalizedSessionCandidate(headers.Get(name)); value != "" {
		return value
	}
	for key, values := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		for _, raw := range values {
			if value := normalizedSessionCandidate(raw); value != "" {
				return value
			}
		}
	}
	return ""
}

// ExtractSessionID extracts a session identifier from explicit client signals,
// then falls back to execution metadata, derived identity, and message history.
// Priority order:
//  1. X-Claude-Code-Session-Id
//  2. Claude Code metadata.user_id session
//  3. Session-Id / Session_id (Codex and compatible clients)
//  4. X-Session-ID
//  5. X-Session-Affinity (OpenCode)
//  6. X-Client-Request-Id (pi Responses)
//  7. session_id / sessionId
//  8. prompt_cache_key, with conversation / conversation.id as an alias
//  9. metadata.user_id and conversation_id legacy body fields
//  10. explicit execution session metadata
//  11. stable context-derived session identity
//  12. stable hash from initial message content
func ExtractSessionID(headers http.Header, payload []byte, metadata map[string]any) string {
	primary, _ := extractSessionIDs(headers, payload, metadata)
	return primary
}

// extractSessionIDs returns (primaryID, fallbackID) for session affinity.
// fallbackID preserves an earlier binding when a stronger body identifier appears
// later, and lets callers bind both identifiers when both are present.
func extractSessionIDs(headers http.Header, payload []byte, metadata map[string]any) (string, string) {
	if sid := sessionHeaderValue(headers, "X-Claude-Code-Session-Id"); sid != "" {
		return "claude:" + sid, ""
	}
	if sid := cliproxysession.ClaudeMetadataSessionID(payload); sid != "" {
		return "claude:" + sid, ""
	}
	if sid := sessionHeaderValue(headers, "Session-Id"); sid != "" {
		return "codex:" + sid, ""
	}
	if sid := sessionHeaderValue(headers, "Session_id"); sid != "" {
		return "codex:" + sid, ""
	}
	if sid := sessionHeaderValue(headers, "X-Session-ID"); sid != "" {
		return "header:" + sid, ""
	}
	if sid := sessionHeaderValue(headers, "X-Session-Affinity"); sid != "" {
		return "affinity:" + sid, ""
	}
	if sid := sessionHeaderValue(headers, "X-Client-Request-Id"); sid != "" {
		return "clientreq:" + sid, ""
	}

	if len(payload) > 0 {
		for _, path := range []string{"session_id", "sessionId"} {
			if sid := normalizedSessionCandidate(gjson.GetBytes(payload, path).String()); sid != "" {
				return "session:" + sid, ""
			}
		}

		conversationID := ""
		conversation := gjson.GetBytes(payload, "conversation")
		if sid := normalizedSessionCandidate(conversation.Get("id").String()); sid != "" {
			conversationID = "conv:" + sid
		} else if conversation.Type == gjson.String {
			if sid := normalizedSessionCandidate(conversation.String()); sid != "" {
				conversationID = "conv:" + sid
			}
		}
		if sid := normalizedSessionCandidate(gjson.GetBytes(payload, "prompt_cache_key").String()); sid != "" {
			return "pck:" + sid, conversationID
		}
		if conversationID != "" {
			return conversationID, ""
		}

		if userID := normalizedSessionCandidate(gjson.GetBytes(payload, "metadata.user_id").String()); userID != "" {
			return "user:" + userID, ""
		}
		if conversationID := normalizedSessionCandidate(gjson.GetBytes(payload, "conversation_id").String()); conversationID != "" {
			return "conv:" + conversationID, ""
		}
	}

	if executionID, ok := metadata[cliproxyexecutor.ExecutionSessionMetadataKey].(string); ok {
		if executionID = normalizedSessionCandidate(executionID); executionID != "" {
			return "execution:" + executionID, ""
		}
	}
	if derivedID := normalizedSessionCandidate(cliproxysession.DerivedID(metadata)); derivedID != "" {
		return "derived:" + derivedID, ""
	}
	if len(payload) == 0 {
		return "", ""
	}
	return extractMessageHashIDs(payload)
}

func extractMessageHashIDs(payload []byte) (primaryID, fallbackID string) {
	var systemPrompt, firstUserMsg, firstAssistantMsg string

	// OpenAI/Claude messages format
	messages := gjson.GetBytes(payload, "messages")
	if messages.Exists() && messages.IsArray() {
		messages.ForEach(func(_, msg gjson.Result) bool {
			role := msg.Get("role").String()
			content := extractMessageContent(msg.Get("content"))
			if content == "" {
				return true
			}

			switch role {
			case "system":
				if systemPrompt == "" {
					systemPrompt = truncateString(content, 100)
				}
			case "user":
				if firstUserMsg == "" {
					firstUserMsg = truncateString(content, 100)
				}
			case "assistant":
				if firstAssistantMsg == "" {
					firstAssistantMsg = truncateString(content, 100)
				}
			}

			if systemPrompt != "" && firstUserMsg != "" && firstAssistantMsg != "" {
				return false
			}
			return true
		})
	}

	// Claude API: top-level "system" field (array or string)
	if systemPrompt == "" {
		topSystem := gjson.GetBytes(payload, "system")
		if topSystem.Exists() {
			if topSystem.IsArray() {
				topSystem.ForEach(func(_, part gjson.Result) bool {
					if text := part.Get("text").String(); text != "" && systemPrompt == "" {
						systemPrompt = truncateString(text, 100)
						return false
					}
					return true
				})
			} else if topSystem.Type == gjson.String {
				systemPrompt = truncateString(topSystem.String(), 100)
			}
		}
	}

	// Gemini format
	if systemPrompt == "" && firstUserMsg == "" {
		sysInstr := gjson.GetBytes(payload, "systemInstruction.parts")
		if sysInstr.Exists() && sysInstr.IsArray() {
			sysInstr.ForEach(func(_, part gjson.Result) bool {
				if text := part.Get("text").String(); text != "" && systemPrompt == "" {
					systemPrompt = truncateString(text, 100)
					return false
				}
				return true
			})
		}

		contents := gjson.GetBytes(payload, "contents")
		if contents.Exists() && contents.IsArray() {
			contents.ForEach(func(_, msg gjson.Result) bool {
				role := msg.Get("role").String()
				msg.Get("parts").ForEach(func(_, part gjson.Result) bool {
					text := part.Get("text").String()
					if text == "" {
						return true
					}
					switch role {
					case "user":
						if firstUserMsg == "" {
							firstUserMsg = truncateString(text, 100)
						}
					case "model":
						if firstAssistantMsg == "" {
							firstAssistantMsg = truncateString(text, 100)
						}
					}
					return false
				})
				if firstUserMsg != "" && firstAssistantMsg != "" {
					return false
				}
				return true
			})
		}
	}

	// OpenAI Responses API format (v1/responses)
	if systemPrompt == "" && firstUserMsg == "" {
		if instr := gjson.GetBytes(payload, "instructions").String(); instr != "" {
			systemPrompt = truncateString(instr, 100)
		}

		input := gjson.GetBytes(payload, "input")
		if input.Exists() && input.IsArray() {
			input.ForEach(func(_, item gjson.Result) bool {
				itemType := item.Get("type").String()
				if itemType == "reasoning" {
					return true
				}
				// Skip non-message typed items (function_call, function_call_output, etc.)
				// but allow items with no type that have a role (inline message format).
				if itemType != "" && itemType != "message" {
					return true
				}

				role := item.Get("role").String()
				if itemType == "" && role == "" {
					return true
				}

				// Handle both string content and array content (multimodal).
				content := item.Get("content")
				var text string
				if content.Type == gjson.String {
					text = content.String()
				} else {
					text = extractResponsesAPIContent(content)
				}
				if text == "" {
					return true
				}

				switch role {
				case "developer", "system":
					if systemPrompt == "" {
						systemPrompt = truncateString(text, 100)
					}
				case "user":
					if firstUserMsg == "" {
						firstUserMsg = truncateString(text, 100)
					}
				case "assistant":
					if firstAssistantMsg == "" {
						firstAssistantMsg = truncateString(text, 100)
					}
				}

				if firstUserMsg != "" && firstAssistantMsg != "" {
					return false
				}
				return true
			})
		}
	}

	if systemPrompt == "" && firstUserMsg == "" {
		return "", ""
	}

	shortHash := computeSessionHash(systemPrompt, firstUserMsg, "")
	if firstAssistantMsg == "" {
		return shortHash, ""
	}

	fullHash := computeSessionHash(systemPrompt, firstUserMsg, firstAssistantMsg)
	return fullHash, shortHash
}

func computeSessionHash(systemPrompt, userMsg, assistantMsg string) string {
	h := fnv.New64a()
	if systemPrompt != "" {
		h.Write([]byte("sys:" + systemPrompt + "\n"))
	}
	if userMsg != "" {
		h.Write([]byte("usr:" + userMsg + "\n"))
	}
	if assistantMsg != "" {
		h.Write([]byte("ast:" + assistantMsg + "\n"))
	}
	return fmt.Sprintf("msg:%016x", h.Sum64())
}

func truncateString(s string, maxLen int) string {
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}

// extractMessageContent extracts text content from a message content field.
// Handles both string content and array content (multimodal messages).
// For array content, extracts text from all text-type elements.
func extractMessageContent(content gjson.Result) string {
	// String content: "Hello world"
	if content.Type == gjson.String {
		return content.String()
	}

	// Array content: [{"type":"text","text":"Hello"},{"type":"image",...}]
	if content.IsArray() {
		var texts []string
		content.ForEach(func(_, part gjson.Result) bool {
			// Handle Claude format: {"type":"text","text":"content"}
			if part.Get("type").String() == "text" {
				if text := part.Get("text").String(); text != "" {
					texts = append(texts, text)
				}
			}
			// Handle OpenAI format: {"type":"text","text":"content"}
			// Same structure as Claude, already handled above
			return true
		})
		if len(texts) > 0 {
			return strings.Join(texts, " ")
		}
	}

	return ""
}

func extractResponsesAPIContent(content gjson.Result) string {
	if !content.IsArray() {
		return ""
	}
	var texts []string
	content.ForEach(func(_, part gjson.Result) bool {
		partType := part.Get("type").String()
		if partType == "input_text" || partType == "output_text" || partType == "text" {
			if text := part.Get("text").String(); text != "" {
				texts = append(texts, text)
			}
		}
		return true
	})
	if len(texts) > 0 {
		return strings.Join(texts, " ")
	}
	return ""
}

// extractSessionID is kept for backward compatibility.
// Deprecated: Use ExtractSessionID instead.
func extractSessionID(payload []byte) string {
	return ExtractSessionID(nil, payload, nil)
}

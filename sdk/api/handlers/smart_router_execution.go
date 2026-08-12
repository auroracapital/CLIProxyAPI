package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/clienterror"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
	"golang.org/x/net/context"
)

func modelSlate(primary string, routed []string) []string {
	if len(routed) == 0 {
		return []string{primary}
	}
	seen := make(map[string]struct{}, len(routed)+1)
	out := make([]string, 0, len(routed)+1)
	for _, model := range append([]string{primary}, routed...) {
		model = strings.TrimSpace(model)
		if model == "" {
			continue
		}
		if _, ok := seen[model]; ok {
			continue
		}
		seen[model] = struct{}{}
		out = append(out, model)
	}
	return out
}

func fallbackProviders(model string, initial []string) []string {
	providers := util.GetProviderName(model)
	if len(providers) == 0 {
		return initial
	}
	return providers
}

func providersForSlateModel(decision modelRouteDecision, model string, initial []string) []string {
	if forced := strings.ToLower(strings.TrimSpace(decision.ForcedProvider)); forced != "" {
		if providers := decision.Providers[model]; len(providers) > 0 && containsFold(providers, forced) {
			return []string{forced}
		}
		return nil
	}
	if providers := decision.Providers[model]; len(providers) > 0 {
		return append([]string(nil), providers...)
	}
	return fallbackProviders(model, initial)
}

func shouldStopModelFallback(ctx context.Context, err error) bool {
	if err == nil {
		return true
	}
	if ctx != nil && ctx.Err() != nil {
		return true
	}
	var terminated *coreexecutor.RequestTerminatedError
	if errors.As(err, &terminated) {
		return true
	}
	status := clienterror.HTTPStatusFromError(err)
	if clienterror.IsRequestFault(status, err) {
		return true
	}
	if status == 0 {
		var retryable interface{ IsRetryable() bool }
		if errors.As(err, &retryable) && retryable != nil && retryable.IsRetryable() {
			return false
		}
		var authErr *coreauth.Error
		if errors.As(err, &authErr) && authErr != nil && authErr.Retryable {
			return false
		}
		return !isTransportError(err)
	}
	// Cross-model fallback is intentionally narrower than credential retry. Only
	// failures that can plausibly be fixed by another compatible route may move to
	// the next model. In particular, policy/permission and unsupported-method
	// failures must remain visible to the caller rather than being route-shopped.
	switch status {
	case http.StatusUnauthorized,
		http.StatusPaymentRequired,
		http.StatusRequestTimeout,
		http.StatusTooEarly,
		http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return false
	case http.StatusNotFound:
		return !isModelRouteUnavailableError(err)
	default:
		return true
	}
}

func isModelRouteUnavailableError(err error) bool {
	if err == nil {
		return false
	}
	var authErr *coreauth.Error
	if errors.As(err, &authErr) && authErr != nil {
		switch strings.ToLower(strings.TrimSpace(authErr.Code)) {
		case "model_not_found", "unknown_model", "unsupported_model", "model_unsupported", "provider_not_found", "auth_not_found":
			return true
		}
	}
	body := err.Error()
	if !gjson.Valid(body) {
		return false
	}
	for _, path := range []string{"error.code", "code", "response.error.code", "body.error.code"} {
		switch strings.ToLower(strings.TrimSpace(gjson.Get(body, path).String())) {
		case "model_not_found", "unknown_model", "unsupported_model", "model_unsupported":
			return true
		}
	}
	return false
}

func isTransportError(err error) bool {
	if err == nil {
		return false
	}
	var netErr interface {
		error
		Timeout() bool
		Temporary() bool
	}
	if errors.As(err, &netErr) {
		return true
	}
	var urlErr interface{ Unwrap() error }
	return errors.As(err, &urlErr) && (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled))
}

func routeAttemptOptions(opts coreexecutor.Options, requestedModel, taskClass, scoreVersion string, ordinal int) coreexecutor.Options {
	copyOpts := opts
	copyOpts.Metadata = cloneSchedulerMetadata(opts.Metadata)
	if copyOpts.Metadata == nil {
		copyOpts.Metadata = make(map[string]any)
	}
	copyOpts.Metadata[coreexecutor.RequestedModelMetadataKey] = requestedModel
	copyOpts.Metadata["smart_route"] = true
	copyOpts.Metadata["smart_route_task"] = taskClass
	copyOpts.Metadata["smart_route_score_version"] = scoreVersion
	copyOpts.Metadata["smart_route_attempt"] = ordinal
	return copyOpts
}

func cloneSchedulerMetadata(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]any, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}

func (h *BaseAPIHandler) executeModelSlate(ctx context.Context, providers []string, req coreexecutor.Request, opts coreexecutor.Options, decision modelRouteDecision) (coreexecutor.Response, string, error) {
	if h == nil || h.AuthManager == nil {
		return coreexecutor.Response{}, "", errors.New("auth manager is unavailable")
	}
	if len(decision.Models) == 0 {
		response, errExecute := h.AuthManager.Execute(ctx, providers, req, opts)
		return response, req.Model, errExecute
	}
	models := modelSlate(req.Model, decision.Models)
	var lastErr error
	for index, model := range models {
		attemptReq := req
		attemptReq.Model = model
		attemptOpts := routeAttemptOptions(opts, requestedModelAliasFromHandlerOptions(opts, req.Model), decision.TaskClass, decision.ScoreVersion, index)
		attemptOpts.OriginalRequest = requestWithSelectedModel(attemptOpts.OriginalRequest, model)
		modelProviders := providersForSlateModel(decision, model, providers)
		provider := ""
		if len(modelProviders) > 0 {
			provider = modelProviders[0]
		}
		emitRoutingEvent(attemptOpts.RoutingObserver, coreexecutor.RoutingEvent{Stage: "model_attempt", Mode: "active", TaskClass: decision.TaskClass, ScoreVersion: decision.ScoreVersion, Model: model, Provider: provider, Attempt: index, CandidateCount: len(models), Outcome: "started"})
		response, errExecute := h.AuthManager.Execute(ctx, modelProviders, attemptReq, attemptOpts)
		if errExecute == nil {
			emitRoutingEvent(attemptOpts.RoutingObserver, coreexecutor.RoutingEvent{Stage: "model_attempt", Mode: "active", TaskClass: decision.TaskClass, ScoreVersion: decision.ScoreVersion, Model: model, Provider: provider, Attempt: index, CandidateCount: len(models), Outcome: "success"})
			return response, model, nil
		}
		emitRoutingEvent(attemptOpts.RoutingObserver, coreexecutor.RoutingEvent{Stage: "model_attempt", Mode: "active", TaskClass: decision.TaskClass, ScoreVersion: decision.ScoreVersion, Model: model, Provider: provider, Reason: fallbackReason(errExecute), Attempt: index, CandidateCount: len(models), Outcome: "failed"})
		lastErr = errExecute
		if shouldStopModelFallback(ctx, errExecute) {
			return coreexecutor.Response{}, model, errExecute
		}
	}
	return coreexecutor.Response{}, "", lastErr
}

func (h *BaseAPIHandler) executeCountModelSlate(ctx context.Context, providers []string, req coreexecutor.Request, opts coreexecutor.Options, decision modelRouteDecision) (coreexecutor.Response, string, error) {
	if h == nil || h.AuthManager == nil {
		return coreexecutor.Response{}, "", errors.New("auth manager is unavailable")
	}
	if len(decision.Models) == 0 {
		response, errExecute := h.AuthManager.ExecuteCount(ctx, providers, req, opts)
		return response, req.Model, errExecute
	}
	models := modelSlate(req.Model, decision.Models)
	model := models[0]
	attemptReq := req
	attemptReq.Model = model
	attemptOpts := routeAttemptOptions(opts, requestedModelAliasFromHandlerOptions(opts, req.Model), decision.TaskClass, decision.ScoreVersion, 0)
	attemptOpts.OriginalRequest = requestWithSelectedModel(attemptOpts.OriginalRequest, model)
	modelProviders := providersForSlateModel(decision, model, providers)
	provider := ""
	if len(modelProviders) > 0 {
		provider = modelProviders[0]
	}
	emitRoutingEvent(attemptOpts.RoutingObserver, coreexecutor.RoutingEvent{Stage: "count_attempt", Mode: "active", TaskClass: decision.TaskClass, ScoreVersion: decision.ScoreVersion, Model: model, Provider: provider, Attempt: 0, CandidateCount: len(models), Outcome: "started"})
	response, errExecute := h.AuthManager.ExecuteCount(ctx, modelProviders, attemptReq, attemptOpts)
	if errExecute != nil {
		emitRoutingEvent(attemptOpts.RoutingObserver, coreexecutor.RoutingEvent{Stage: "count_attempt", Mode: "active", TaskClass: decision.TaskClass, ScoreVersion: decision.ScoreVersion, Model: model, Provider: provider, Reason: fallbackReason(errExecute), Attempt: 0, CandidateCount: len(models), Outcome: "failed"})
		return coreexecutor.Response{}, model, errExecute
	}
	emitRoutingEvent(attemptOpts.RoutingObserver, coreexecutor.RoutingEvent{Stage: "count_attempt", Mode: "active", TaskClass: decision.TaskClass, ScoreVersion: decision.ScoreVersion, Model: model, Provider: provider, Attempt: 0, CandidateCount: len(models), Outcome: "success"})
	return response, model, nil
}

func (h *BaseAPIHandler) executeStreamModelSlate(ctx context.Context, providers []string, req coreexecutor.Request, opts coreexecutor.Options, decision modelRouteDecision) (*coreexecutor.StreamResult, string, error) {
	if h == nil || h.AuthManager == nil {
		return nil, "", errors.New("auth manager is unavailable")
	}
	if len(decision.Models) == 0 {
		result, errExecute := h.AuthManager.ExecuteStream(ctx, providers, req, opts)
		return result, req.Model, errExecute
	}
	models := modelSlate(req.Model, decision.Models)
	var lastErr error
	for index, model := range models {
		attemptCtx, cancelAttempt := context.WithCancel(ctx)
		attemptReq := req
		attemptReq.Model = model
		attemptOpts := routeAttemptOptions(opts, requestedModelAliasFromHandlerOptions(opts, req.Model), decision.TaskClass, decision.ScoreVersion, index)
		attemptOpts.OriginalRequest = requestWithSelectedModel(attemptOpts.OriginalRequest, model)
		modelProviders := providersForSlateModel(decision, model, providers)
		provider := ""
		if len(modelProviders) > 0 {
			provider = modelProviders[0]
		}
		emitRoutingEvent(attemptOpts.RoutingObserver, coreexecutor.RoutingEvent{Stage: "stream_attempt", Mode: "active", TaskClass: decision.TaskClass, ScoreVersion: decision.ScoreVersion, Model: model, Provider: provider, Attempt: index, CandidateCount: len(models), Outcome: "started"})
		result, errExecute := h.AuthManager.ExecuteStream(attemptCtx, modelProviders, attemptReq, attemptOpts)
		if errExecute == nil && result != nil && result.Chunks != nil {
			first, errFirst := firstStreamPayload(attemptCtx, result.Chunks)
			if errFirst == nil {
				emitRoutingEvent(attemptOpts.RoutingObserver, coreexecutor.RoutingEvent{Stage: "stream_attempt", Mode: "active", TaskClass: decision.TaskClass, ScoreVersion: decision.ScoreVersion, Model: model, Provider: provider, Attempt: index, CandidateCount: len(models), Outcome: "committed"})
				return prependStreamChunk(attemptCtx, result, first, cancelAttempt), model, nil
			}
			errExecute = errFirst
		}
		cancelAttempt()
		emitRoutingEvent(attemptOpts.RoutingObserver, coreexecutor.RoutingEvent{Stage: "stream_attempt", Mode: "active", TaskClass: decision.TaskClass, ScoreVersion: decision.ScoreVersion, Model: model, Provider: provider, Reason: fallbackReason(errExecute), Attempt: index, CandidateCount: len(models), Outcome: "failed"})
		lastErr = errExecute
		if shouldStopModelFallback(ctx, errExecute) {
			return nil, model, errExecute
		}
	}
	return nil, "", lastErr
}

func fallbackReason(err error) string {
	status := clienterror.HTTPStatusFromError(err)
	if status == 0 {
		return "transport"
	}
	if clienterror.IsRequestFault(status, err) {
		return "request_fault"
	}
	switch status {
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusPaymentRequired:
		return "quota"
	case http.StatusNotFound:
		return "route_unavailable"
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		return "timeout"
	case http.StatusTooEarly:
		return "too_early"
	case http.StatusTooManyRequests:
		return "rate_limited"
	default:
		if status >= http.StatusInternalServerError {
			return "upstream_unavailable"
		}
		return "terminal"
	}
}

func firstStreamPayload(ctx context.Context, chunks <-chan coreexecutor.StreamChunk) (coreexecutor.StreamChunk, error) {
	for {
		select {
		case <-ctx.Done():
			return coreexecutor.StreamChunk{}, ctx.Err()
		case chunk, ok := <-chunks:
			if !ok {
				return coreexecutor.StreamChunk{}, errors.New("upstream stream closed before first payload")
			}
			if chunk.Err != nil {
				return coreexecutor.StreamChunk{}, chunk.Err
			}
			if len(chunk.Payload) > 0 {
				return chunk, nil
			}
		}
	}
}

func prependStreamChunk(ctx context.Context, result *coreexecutor.StreamResult, first coreexecutor.StreamChunk, cancel context.CancelFunc) *coreexecutor.StreamResult {
	if result == nil {
		cancel()
		return nil
	}
	out := make(chan coreexecutor.StreamChunk, 1)
	go func() {
		defer close(out)
		defer cancel()
		select {
		case <-ctx.Done():
			return
		case out <- first:
		}
		for {
			select {
			case <-ctx.Done():
				return
			case chunk, ok := <-result.Chunks:
				if !ok {
					return
				}
				select {
				case <-ctx.Done():
					return
				case out <- chunk:
				}
			}
		}
	}()
	return &coreexecutor.StreamResult{Headers: result.Headers, Chunks: out}
}

func requestedModelAliasFromHandlerOptions(opts coreexecutor.Options, fallback string) string {
	if value, ok := opts.Metadata[coreexecutor.RequestedModelMetadataKey].(string); ok && strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return strings.TrimSpace(fallback)
}

func requestWithSelectedModel(raw []byte, model string) []byte {
	model = strings.TrimSpace(model)
	if model == "" || len(raw) == 0 || !gjson.ValidBytes(raw) {
		return raw
	}
	path := "model"
	if !gjson.GetBytes(raw, path).Exists() && gjson.GetBytes(raw, "request.model").Exists() {
		path = "request.model"
	}
	updated, errSet := sjson.SetBytes(raw, path, model)
	if errSet != nil {
		return raw
	}
	return updated
}

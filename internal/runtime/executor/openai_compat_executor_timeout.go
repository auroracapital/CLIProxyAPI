package executor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// Per-attempt timeouts for OpenAI-compatible upstreams.
//
// A hanging upstream used to hold the whole request until the TCP stack gave
// up (1m49s observed). These timeouts run on a child context of the attempt,
// never on the conductor's context, so the conductor sees an ordinary failed
// attempt and moves on. The failure is reported as HTTP 504: the conductor
// treats that as a transient upstream error, cools only this credential/model
// for transient-error-cooldown-seconds, and tries the next candidate. It is
// never credential-scoped and never a quota signal.

var (
	errOpenAICompatFirstByteTimeout = errors.New("openai compat: first-byte timeout")
	errOpenAICompatTotalTimeout     = errors.New("openai compat: total timeout")
)

// openAICompatAttempt carries the context and timers for one upstream attempt.
type openAICompatAttempt struct {
	ctx       context.Context
	cancel    context.CancelCauseFunc
	firstByte time.Duration
	total     time.Duration

	mu             sync.Mutex
	firstByteTimer *time.Timer
	totalTimer     *time.Timer
}

// attemptTimeouts returns the configured first-byte and total timeouts for auth.
func (e *OpenAICompatExecutor) attemptTimeouts(auth *cliproxyauth.Auth) (firstByte, total time.Duration) {
	compat := e.resolveCompatConfig(auth)
	if compat == nil {
		return 0, 0
	}
	return compat.FirstByteTimeoutDuration(), compat.TimeoutDuration()
}

// startOpenAICompatAttempt derives the attempt context. With both timeouts
// disabled it returns the parent context unchanged, so unset config keeps
// today's behaviour exactly.
func startOpenAICompatAttempt(parent context.Context, firstByte, total time.Duration) *openAICompatAttempt {
	attempt := &openAICompatAttempt{ctx: parent, firstByte: firstByte, total: total}
	if firstByte <= 0 && total <= 0 {
		return attempt
	}
	attempt.ctx, attempt.cancel = context.WithCancelCause(parent)
	if firstByte > 0 {
		attempt.firstByteTimer = time.AfterFunc(firstByte, func() { attempt.cancel(errOpenAICompatFirstByteTimeout) })
	}
	if total > 0 {
		attempt.totalTimer = time.AfterFunc(total, func() { attempt.cancel(errOpenAICompatTotalTimeout) })
	}
	return attempt
}

// firstByteReceived stops the first-byte timer. A total timer keeps running.
func (a *openAICompatAttempt) firstByteReceived() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.firstByteTimer != nil {
		a.firstByteTimer.Stop()
		a.firstByteTimer = nil
	}
}

// release stops all timers and frees the attempt context. Call it once the
// response body is fully consumed or abandoned.
func (a *openAICompatAttempt) release() {
	if a == nil {
		return
	}
	a.mu.Lock()
	if a.firstByteTimer != nil {
		a.firstByteTimer.Stop()
		a.firstByteTimer = nil
	}
	if a.totalTimer != nil {
		a.totalTimer.Stop()
		a.totalTimer = nil
	}
	a.mu.Unlock()
	if a.cancel != nil {
		a.cancel(nil)
	}
}

// timeoutError replaces err with a 504 status error when this attempt's own
// timer fired. Parent cancellation (client gone, conductor deadline) and
// ordinary transport errors are returned unchanged.
func (a *openAICompatAttempt) timeoutError(provider string, err error) error {
	if err == nil || a == nil || a.cancel == nil || a.ctx.Err() == nil {
		return err
	}
	cause := context.Cause(a.ctx)
	switch {
	case errors.Is(cause, errOpenAICompatFirstByteTimeout):
		return statusErr{code: http.StatusGatewayTimeout, msg: fmt.Sprintf("openai compat upstream %s sent no first byte within %s (first-byte-timeout)", provider, a.firstByte)}
	case errors.Is(cause, errOpenAICompatTotalTimeout):
		return statusErr{code: http.StatusGatewayTimeout, msg: fmt.Sprintf("openai compat upstream %s did not finish within %s (timeout)", provider, a.total)}
	default:
		return err
	}
}

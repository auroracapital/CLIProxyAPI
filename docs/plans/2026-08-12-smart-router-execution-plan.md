# Smart Model Router and Predictive Account Balancer

Status: implementation verified locally; live shadow/canary and 24-hour soak pending
Owner: primary agent
Canonical runtime: `healify-hub` only
Proxy path: nginx `:8317` -> CLIProxyAPI `127.0.0.1:8319`
Source baseline: CLIProxyAPI v7.2.128 (`bd34ceca`)

## 1. Outcome

Turn the canonical CLI proxy into a two-stage smart router:

1. When the client opts into `auto`, classify the request and select the best eligible model and provider for the task, subject to capability, quality, latency, cost, privacy, and availability policy.
2. Before contacting an upstream, predict which authenticated account is most likely to accept and complete the request, reserve that account atomically, and dispatch there.
3. If the selected path returns a retryable pressure or availability error, automatically retry a distinct eligible account/provider/model according to a bounded, request-safe fallback plan.
4. Keep every desired account authenticated and managed by the service. Operators do not manually toggle individual seat files during normal operation.

Explicit model requests remain explicit. Smart model selection applies to `auto` and future opt-in policy aliases; it must not silently downgrade a request for a named model. Equivalent provider/account failover remains allowed when it preserves the requested model and capabilities.

## 2. Non-negotiable invariants from the conversation

- OAuth refresh and login ownership stays hub-only. The Mac remains a client and must never become a second refresh-token writer.
- Selection is predictive first and retry-driven second. Retries are a safety net, not the load-balancing algorithm.
- The router must select all three dimensions: model, provider/capacity path, and account.
- Account selection must use observed pressure, not manual case-by-case enable/disable state.
- Every desired seat is continuously reconciled toward authenticated and eligible.
- A seat may be automatically quarantined only because of objective runtime evidence such as expiry, revoked auth, quota/cooldown, repeated retryable failures, or failed probes.
- A quarantined seat is automatically refreshed or re-authenticated and readmitted only after a real provider request succeeds.
- The service must automatically retry retryable failures, use a different candidate, honor provider `Retry-After`, and stop at a bounded request/time budget.
- No retry after downstream-visible streaming output has begun, unless the protocol can prove replay is safe.
- No secrets, raw tokens, full account emails, prompts, or PHI in routing logs or metrics.
- nginx remains the public/tailnet ingress and rate-limit layer; CLIProxyAPI remains bound to loopback on `:8319`.

## 3. Baseline findings

### 3.1 Runtime

- `crsproxy.service` and nginx are active on `healify-hub`.
- CLIProxyAPI has built-in cooldown state, provider/model failure state, quota backoff, distinct-credential retry, and config hot reload.
- Current config uses `routing.strategy: round-robin`, `request-retry: 2`, `max-retry-credentials: 3`, `disable-cooling: false`, and persisted cooldown status.
- Current `auto` behavior is not intelligent: it selects the first available registry model.
- Built-in account strategies are round-robin, weighted round-robin, and fill-first. None scores live pressure or reserves in-flight capacity at pick time.
- CLIProxyAPI already exposes the correct extension seams: `ModelRouter` runs before provider/auth resolution, and `Scheduler` runs before built-in credential selection.
- The scheduler candidate contract does not yet expose enough sanitized state for predictive selection: recent outcome windows, quota/cooldown detail, refresh freshness, or in-flight reservations.

### 3.2 Pool lifecycle

- The hub has a mixed pool of Claude, Codex, xAI/Antigravity, and Kimi-compatible capacity.
- Several seat files are objectively unhealthy, stale, disabled, expired, or incorrectly owned; the existing aggregate health check cannot reconcile them individually.
- The existing `cliproxy-pool-health.timer` runs every 15 minutes and probes the pool as a whole. It can detect aggregate failure but cannot identify, repair, and readmit a specific seat.
- `auth-auto-refresh-workers: 16` handles refreshable credentials but cannot complete every interactive or email-code re-auth flow by itself.

## 4. Research-derived design principles

The target combines the useful parts of established routers without copying their opaque behavior:

- OpenRouter Auto: classify tasks into fine-grained types, rank eligible models, apply cost/capability restrictions, keep ordered fallbacks, expose the selected model, and preserve session coherence only while the remembered model remains suitable.
- OpenRouter provider routing: filter for required parameters/modalities, remove recently unhealthy paths, rank remaining paths by the configured objective, and retain ordered fallbacks.
- Factory Router/Droid: make routing decisions per task, reserve frontier models for harder work, include quality/latency/cost and prompt-cache continuity, and fail over across models/providers/capacity sources.
- Existing CLIProxyAPI: reuse provider/model registry, translation, cooldown, retry, per-model state, plugins, and single-writer token refresh rather than creating a second proxy stack.

## 5. Target request flow

```text
client request
  -> authenticate and validate
  -> detect explicit model vs auto policy
  -> extract capability requirements
  -> classify task and complexity
  -> rank model/provider candidates
  -> filter unavailable/incompatible paths
  -> rank eligible accounts by predicted acceptance pressure
  -> atomically reserve best account
  -> dispatch
      -> success: record outcome, release reservation, return selected-route metadata
      -> retryable pre-output failure: cool candidate, release, select next distinct path
      -> terminal/client error: release and return without retry
      -> streaming after first output: release on close; never replay invisibly
```

## 6. Routing contract

### 6.1 Request classification

Inputs:

- requested model/policy alias;
- final user instruction plus bounded conversation summary/features;
- input size and expected output size;
- tool definitions and tool-choice constraints;
- image/audio/video/document modality;
- structured-output/JSON-schema needs;
- reasoning effort, context size, streaming, and latency hints;
- session identifier/cache affinity;
- tenant policy, allowed providers/models, privacy/ZDR constraints, and budget tier.

Initial task taxonomy:

- code: completion, debugging, refactor, review, architecture, repository-scale agent task;
- reasoning: math, logic, planning, analysis;
- research: factual QA, browsing, synthesis, long report;
- writing: short generation, rewrite, translation, long-form;
- agent: tool use, multi-step execution, computer use;
- multimodal: image understanding/generation, audio, video, document extraction;
- safety-sensitive or high-stakes review.

Classifier implementation order:

1. Deterministic capability extraction and hard filters.
2. Low-latency local classifier/rules for obvious task types.
3. Optional small-model classifier only for ambiguous `auto` requests, with a strict timeout and deterministic fallback.
4. Offline evaluation-driven mapping from task/complexity/cost tier to an ordered model/provider slate.

The classifier must not retain request content and must degrade to a safe default slate if classification is unavailable.

### 6.2 Model/provider ranking

Hard filters precede scoring:

- model and provider currently registered and authenticated;
- supports required endpoint/protocol, tools, modality, parameters, structured output, context, and max output;
- allowed by organization/tenant privacy and provider policy;
- not in open cooldown or recent outage window;
- explicit requests retain the requested model.

Soft score for `auto` candidates:

```text
route_score =
    task_quality_fit
  + capability_margin
  + session_and_prompt_cache_value
  + recent_success_rate
  + throughput_score
  - latency_score
  - cost_score_by_selected_tier
  - recent_outage_penalty
  - provider_pressure_penalty
```

The output is an ordered slate, not one model. Every decision records a reason code and score components without prompt content.

### 6.3 Predictive account pressure score

Only already-eligible accounts enter scoring. Disabled, expired without refresh, unsupported, quarantined, or cooling candidates are excluded.

For candidate `a`, provider `p`, and model `m`:

```text
pressure(a,p,m) =
    w1 * normalized_in_flight
  + w2 * recent_request_rate
  + w3 * exponentially_weighted_failure_rate
  + w4 * rate_limit_and_quota_backoff
  + w5 * refresh_expiry_risk
  + w6 * latency_ewma
  + w7 * consecutive_failure_penalty
  - w8 * proven_remaining_quota
  - w9 * recent_success_bonus
```

Selection rules:

- Choose the lowest pressure in the highest priority tier.
- Use power-of-two choices or a stable jitter term among near-ties to avoid synchronized herding.
- Atomically acquire an in-flight lease before returning the candidate.
- Never expose or infer quota that a provider does not supply; use recent outcomes and cooldown as proxies.
- Persist durable cooldown/recovery state, but keep in-flight counters process-local and self-healing on restart.
- Add bounded session affinity only when it preserves cache value and the account stays within a configurable pressure margin of the best candidate.

### 6.4 Retry and fallback matrix

Retry with a distinct account/path:

- provider 408, 425, 429, 500, 502, 503, or 504;
- transport failure before any downstream-visible output;
- provider-declared capacity/quota exhaustion;
- revoked/expired credential after triggering refresh/quarantine;
- account-specific concurrency or admission rejection.

Do not retry by default:

- invalid request/schema/context that all equivalent candidates would reject;
- permission/policy/moderation result unless an explicit policy-approved fallback exists;
- client cancellation or deadline;
- non-idempotent side effects after acceptance;
- streaming once any content has been emitted downstream.

Budgets:

- distinct credential attempts are capped;
- model/provider fallbacks are capped separately;
- total retry wall time is capped and honors the caller deadline;
- `Retry-After` is honored only within the remaining budget;
- every retry excludes already-tried account/path tuples.

## 7. Pool reconciler contract

Desired state is a declarative seat inventory, not whatever JSON files happen to exist.

For every desired seat, the reconciler must:

1. verify file ownership/mode and parseability without logging secrets;
2. verify provider/type/identity metadata matches inventory;
3. ensure operator `disabled` is absent/false in normal operation;
4. check access-token freshness and refresh-token usability;
5. invoke only the hub-local refresh/re-auth workflow when needed;
6. serialize re-auth by provider/account to preserve single-writer semantics;
7. probe the exact seat with a minimal real request, not an aggregate pool request;
8. admit only after a successful attributed probe;
9. quarantine automatically with reason and next attempt after failure;
10. alert only when bounded automated recovery is exhausted or human 2FA is genuinely required.

The reconciler never copies auth material to the Mac, never deletes seat records, and never relies on a manual enable/disable toggle as recovery.

## 8. Work breakdown and dependencies

### Phase 0 — Baseline and safety freeze

Tasks:

- Capture service ownership, ports, version, config hash, binary hash, nginx config, timers, pool inventory, file ownership/modes, and current health.
- Back up config/binary/systemd units with timestamped, root-only copies.
- Record current model list and provider/account availability.
- Establish rollback commands and a known-good probe.
- Stop or wait for unrelated in-flight re-auth work before changing auth lifecycle files.

Exit gate: topology and rollback are independently verifiable; no Mac-local refresh writer exists.

### Phase 1 — Research and decision record

Parallel delegates:

- Router research: OpenRouter Auto/provider routing, Factory Router, LiteLLM/reliability patterns, and CLIProxyAPI extension constraints.
- Account scheduler audit/prototype: selection, retry, streaming lifecycle, concurrency, and pressure signals.
- Pool reconciler audit: desired inventory, refresh/re-auth, health probes, ownership drift, timers, and failure modes.
- QA/observability: fast CI, race/load/fault tests, shadow metrics, canary, rollback, and definition of done.

Exit gate: a decision record explains chosen algorithms, rejected alternatives, source links, and unresolved assumptions.

### Phase 2 — Contracts and fixtures

Tasks:

- Freeze request taxonomy, candidate model/provider matrix, policy schema, score inputs/weights, retry matrix, and decision metadata schema.
- Extend the scheduler plugin API with sanitized candidate fields: quota/cooldown state, recent outcome buckets, refresh freshness, and in-flight pressure.
- Define lease acquire/release callbacks or host-owned lifecycle accounting so plugin crashes cannot leak capacity forever.
- Define attributed per-seat probes that never expose credentials.
- Create golden routing fixtures for easy, hard, code, tool, long-context, multimodal, explicit-model, and ambiguous requests.
- Create failure fixtures for quota, expiry, revoked auth, timeout, 5xx, stream bootstrap failure, midstream failure, and cancellation.

Dependencies: Phase 1 research; live model/provider inventory.

Exit gate: contracts compile as tests or schemas before production code changes.

### Phase 3 — Smart model/provider router

Tasks:

- Implement `auto` detection while preserving explicit-model semantics.
- Extract hard capability requirements.
- Implement deterministic classifier and safe fallback slate.
- Add optional ambiguous-request classifier behind a strict timeout and feature flag.
- Rank eligible model/provider candidates using policy and recent health.
- Preserve session/cache affinity only within suitability and pressure bounds.
- Emit structured route decisions with hashed session and categorical reason codes.
- Support shadow mode, in which the router records its choice while production continues using the current route.

Dependencies: Phase 2 contracts; model registry and provider availability.

Exit gate: golden fixtures are deterministic, all hard constraints hold, and explicit models never change.

### Phase 4 — Least-pressure account scheduler

Tasks:

- Add sanitized pressure fields to scheduler candidates.
- Add concurrency-safe per-account/model/provider in-flight reservations.
- Implement least-pressure score, near-tie spreading, and session-affinity pressure ceiling.
- Release reservations on success, terminal error, retry, stream completion, bootstrap failure, cancellation, panic/fuse, and shutdown.
- Preserve cooldown and distinct-credential retry behavior.
- Record selection score components without identity/PII.
- Add feature flags for `round-robin`, `shadow-least-pressure`, and `least-pressure`.

Dependencies: Phase 2 contract; host lifecycle hooks.

Exit gate: Go race tests show no data race or leaked leases; concurrent picks do not herd onto one account; retry chooses a distinct eligible account.

### Phase 5 — Automatic pool reconciliation

Tasks:

- Promote `reauth_seats.json` or a replacement root-only inventory into complete desired state for all configured seats/providers.
- Repair unsafe file ownership/modes and eliminate persistent operator-disabled state from desired seats.
- Implement per-seat reconcile state machine: discovered -> refreshing -> probing -> active, or quarantined -> backoff -> refreshing.
- Add provider-specific refresh/re-auth adapters that reuse the existing hub-only workflows.
- Attribute probes to one exact seat using a host management callback or temporary selection pin that never reaches public clients.
- Serialize re-auth, add exponential backoff/jitter, and bound attempts.
- Replace aggregate-only health with aggregate plus per-seat readiness; retain pool-level model probes.
- Install a systemd service/timer with least privilege, lock file, atomic state writes, and journal-safe redaction.

Dependencies: no unrelated re-auth job in flight; attributed-probe mechanism; inventory approval inferred from existing configured seats only.

Exit gate: every desired seat is active or automatically quarantined with a recovery timer; none depends on a hand toggle; writable ownership and mode are correct.

### Phase 6 — QA and one-minute CI

One-minute PR gate target (parallel jobs, fail fast):

- `gofmt`/generated-file diff check;
- `go vet` on changed packages;
- focused unit tests for router, scheduler, lifecycle release, retry matrix, and plugin ABI;
- config/schema parsing and secret scan;
- build `./cmd/server` and smart-router plugin;
- Python compile/lint/unit tests for reconciler;
- deterministic golden routing fixtures.

Full CI:

- `go test ./...`;
- `go test -race` on auth, pluginhost, handlers, and new router packages;
- fuzz/property tests for score ordering, hard filters, retry exclusion, malformed payloads, and config reload;
- protocol matrix: OpenAI chat/responses/WebSocket, Anthropic messages, Gemini, streaming/non-streaming/count tokens;
- load test with skewed concurrency and injected slow/429/5xx candidates;
- soak test across refresh/config reload/restart;
- secret/PII log inspection and binary/config provenance checks.

Exit gate: fast gate remains under 60 seconds on CI runners or is split into parallel required checks whose critical path is under 60 seconds; full suite and race suite pass.

### Phase 7 — Shadow, canary, and production rollout

Tasks:

- Build arm64 artifacts reproducibly and record source commit/hash.
- Deploy alongside current binary/plugin without changing public ingress.
- Enable shadow model/provider and account decisions; compare to actual outcomes.
- Calibrate weights from observed acceptance, latency, and failure data.
- Canary internal/tailnet traffic first, then a bounded percentage or API-key cohort.
- Inject controlled 429, 503, timeout, expired-seat, and cancellation failures.
- Restart the service and verify state recovery, refresh ownership, and health probes.
- Promote only after gates remain green; preserve one-command rollback to previous binary/config/plugin.

Exit gate: canary satisfies the SLO and no safety invariant regresses.

### Phase 8 — Operations and handoff

Tasks:

- Document configuration, score weights, policy aliases, retry limits, and rollback.
- Add dashboards for route choice, candidate exclusion, retries, pressure distribution, pool readiness, refresh age, and reconciler state.
- Add alerts for pool exhaustion, repeated classifier fallback, skew/herding, lease leaks, persistent seat quarantine, and refresh single-writer violations.
- Document safe model/provider additions and automatic seat onboarding.
- Remove obsolete manual-toggle procedures from the runbook.

Exit gate: another operator can diagnose and roll back without accessing raw tokens or editing individual seat JSON.

## 9. Parallel execution map

```text
Phase 0 baseline ------------------------------------------+
                                                           |
  router research --------> model-router contract --------> implementation --+
  scheduler audit --------> pressure/lease contract ------> implementation --+--> integrated QA
  pool lifecycle audit ---> reconcile/probe contract -----> implementation --+
  QA/observability audit -> fixtures + rollout gates -------------------------+
                                                                              |
                                                     shadow -> canary -> live -+
```

Only one owner edits a given file set at a time. The primary agent owns integration, secrets, live service changes, rollback, and final acceptance. Delegates work in isolated worktrees or read-only against the hub.

## 10. Validation evidence

Current verified evidence, 2026-08-13:

- `go test ./... -count=1` passes across the repository.
- Focused routing, management, config, reconciliation, and least-pressure race tests pass.
- Changed-package `go vet` passes. Repository-wide vet still reports pre-existing warnings in untouched logging/plugin-host files.
- The controller compiles and all 19 Python unit tests pass.
- Formatting, `git diff --check`, workflow YAML parsing, and changed-file credential-pattern scan pass.
- A `linux/arm64` server build succeeds; the latest pre-rollout artifact hash is recorded in the session evidence.
- The service and timer templates pass `systemd-analyze verify` on the arm64 hub with systemd 255.
- Live topology remains nginx `:8317` to loopback CLIProxyAPI `:8319`; the Mac has no local CLIProxy/crsproxy listener or refresh process.
- The live hub still runs CLIProxyAPI `7.2.128` and has 19 auth files, nine of them mode `0664`; no new binary, config, unit, or inventory has been deployed.

Remaining production evidence:

- Build the complete root-protected desired inventory for all 19 current auth files without deleting or silently dropping any seat.
- Capture root-owned rollback copies and hashes for binary, config, nginx, and units immediately before deployment.
- Run semantic and account shadow modes, fixed-model least-pressure canary, controlled fault injection, rollback rehearsal, and a 24-hour zero-manual-toggle soak.

### Functional

- `auto` routes representative task fixtures to the intended model class/provider and returns the actual selected model.
- Explicit model requests remain unchanged.
- Capability constraints exclude incompatible models/providers before dispatch.
- A retryable first-path failure automatically selects a distinct valid path.
- A client/validation failure is returned without wasteful retry.
- Streaming bootstrap can retry before output; midstream failure cannot silently replay.

### Account selection

- With equal accounts and no pressure, distribution stays statistically balanced.
- With one account carrying in-flight work, new requests prefer lower-pressure accounts.
- With one account returning 429/quota, it enters cooldown before the next dispatch.
- With one account revoked/expired, it is quarantined, refreshed/re-authenticated, probed, and readmitted automatically.
- Concurrent selection under the race detector has no duplicate lease bug, data race, or persistent leak.

### Operations

- nginx `:8317`, CLIProxyAPI `:8319`, systemd ownership, and hub-only refresh remain intact.
- Mac has no local listener/process/service on `:8317` or `:8318`.
- All desired auth files are parseable, root/service-owned as intended, mode `0600`, and writable by the refresh service.
- Restart and config hot reload preserve routing availability and clear/reconstruct ephemeral in-flight state safely.
- Logs and metrics contain no raw token, key, email, prompt, PHI, or credential body.

## 11. Definition of done

The work is done only when all statements are evidenced:

1. A query-aware `auto` route is live on the hub and no longer resolves to an arbitrary first registry model.
2. Model/provider selection honors task fit, hard capabilities, policy, health, and an explicit cost/quality tier.
3. Account selection happens before dispatch using live pressure signals and an atomic in-flight reservation.
4. Bounded automatic retry selects distinct eligible candidates for retryable failures and is safe for streaming/cancellation.
5. Every desired seat is managed by declarative inventory and automatic refresh/re-auth/reprobe; normal operation requires no per-seat manual enable/disable.
6. Objective failures cause automatic quarantine, and only a successful attributed probe causes readmission.
7. Focused, full, race, fault-injection, load, and secret-safety tests pass.
8. The one-minute CI critical path meets its target or has measured evidence explaining and minimizing any overrun.
9. Shadow/canary evidence shows improved first-attempt acceptance, no worse terminal success rate, bounded added latency, and materially lower account-pressure skew.
10. Rollback is tested, the runbook is current, and hub-only OAuth ownership is re-verified.

Target production SLOs for acceptance:

- terminal request success >= 99.9% for requests with at least one healthy eligible path;
- first-attempt acceptance improves over round-robin baseline and reaches >= 98% after calibration, excluding client/policy errors;
- routing overhead p95 <= 25 ms for deterministic decisions and <= 150 ms when the optional classifier is invoked;
- no account exceeds 1.5x the median normalized pressure for more than five minutes when two or more equivalent accounts are healthy;
- zero leaked in-flight leases after cancellation, stream close, retry, plugin fuse, or service restart;
- zero manual seat toggles during the production soak window;
- zero secrets or account PII in router/reconciler telemetry.

## 12. Rollback

- Keep the previous binary, config, plugins, units, and hashes on the hub.
- Feature flags independently disable smart model routing, least-pressure scheduling, and reconciliation mutation.
- First rollback changes `auto` to the known-good default slate and account strategy to built-in round-robin while keeping cooldown/retry.
- Second rollback restores the prior binary/config and restarts `crsproxy.service`.
- nginx and public DNS remain unchanged throughout.
- A rollback is successful only after `/v1/models`, Claude and non-Claude generation probes, pool inventory, and hub-only refresh ownership all pass.

## 13. Open items to resolve through execution evidence

- Which providers expose reliable remaining-quota or concurrency signals versus requiring outcome-based estimation.
- Whether the optional request classifier should be local/rule-based only or call a fast model for ambiguous tasks after benchmark comparison.
- The initial quality/cost mapping for the currently available 58 model aliases.
- The exact per-provider semantics for retrying moderation, context, and tool-compatibility failures.
- Which dormant/revoked seat identities are still part of desired inventory; until proven otherwise, configured files are treated as desired and reconciled rather than deleted.

## 14. Primary research and implementation references

- OpenRouter Auto Router: <https://openrouter.ai/docs/guides/routing/routers/auto-router>
- OpenRouter Provider Routing: <https://openrouter.ai/docs/guides/routing/provider-selection>
- OpenRouter Model Fallbacks: <https://openrouter.ai/docs/guides/routing/model-fallbacks>
- Factory Router: <https://docs.factory.ai/model-independence/factory-router>
- CLIProxyAPI upstream: <https://github.com/router-for-me/CLIProxyAPI>
- CLIProxyAPI model routing seam: `sdk/api/handlers/handlers_routing.go` and `sdk/pluginapi/types.go`
- CLIProxyAPI credential scheduling and retry: `sdk/cliproxy/auth/scheduler.go`, `selector.go`, `conductor_selection.go`, and `conductor_execution.go`
- CLIProxyAPI plugin examples: `examples/plugin/scheduler` and `examples/plugin/claude-web-search-router`

Research limitations are explicit: OpenRouter and Factory publish product behavior but not their complete scoring models, training data, or production implementation. Their public behavior informs the contract and validation strategy; our score weights must be calibrated against this pool's own shadow and canary evidence.

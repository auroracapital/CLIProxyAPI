#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} != --inside || -z ${2:-} || -z ${3:-} ]]; then
  echo "internal helper; use verify_active_fault_fixture.sh" >&2
  exit 2
fi

binary=$2
expected_sha256=$3
fixture_root=$(mktemp -d /tmp/cliproxy-active-fault-fixture.XXXXXX)
proxy_pid=
mock_pid=
case_dir=

stop_case() {
  if [[ -n $proxy_pid ]]; then
    kill "$proxy_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
    proxy_pid=
  fi
  if [[ -n $mock_pid ]]; then
    kill "$mock_pid" 2>/dev/null || true
    wait "$mock_pid" 2>/dev/null || true
    mock_pid=
  fi
}

cleanup() {
  stop_case
  rm -rf -- "$fixture_root"
}
trap cleanup EXIT INT TERM

ip link set lo up
if ip route show | grep -q '^default'; then
  echo "fixture namespace unexpectedly has a default route" >&2
  exit 1
fi
if ip -o link show | grep -vE '^[0-9]+: lo:' | grep -q .; then
  echo "fixture namespace unexpectedly has a non-loopback interface" >&2
  exit 1
fi
actual_sha256=$(sha256sum "$binary" | awk '{print $1}')
if [[ $actual_sha256 != "$expected_sha256" ]]; then
  echo "binary SHA-256 changed after entering the namespace" >&2
  exit 1
fi

chown crsproxy:crsproxy "$fixture_root"
chmod 0750 "$fixture_root"

cat >"$fixture_root/mock.py" <<'PY'
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

scenario, hits_path = sys.argv[1:3]
lock = threading.Lock()
sequence = 0


def json_response(handler, status, value, headers=None):
    encoded = json.dumps(value, separators=(",", ":")).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(encoded)))
    for name, item in (headers or {}).items():
        handler.send_header(name, item)
    handler.end_headers()
    handler.wfile.write(encoded)


def good_response(handler, model):
    json_response(handler, 200, {
        "id": "fixture-response",
        "object": "chat.completion",
        "created": 1,
        "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "fixture-ok"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    })


def begin_stream(handler):
    handler.send_response(200)
    handler.send_header("Content-Type", "text/event-stream")
    handler.send_header("Cache-Control", "no-cache")
    handler.end_headers()


def write_stream(handler, data):
    handler.wfile.write(data.encode())
    handler.wfile.flush()


def good_stream(handler, model):
    begin_stream(handler)
    chunk = {
        "id": "fixture-stream",
        "object": "chat.completion.chunk",
        "created": 1,
        "model": model,
        "choices": [{"index": 0, "delta": {"content": "fixture-stream-ok"}, "finish_reason": None}],
    }
    write_stream(handler, "data: " + json.dumps(chunk, separators=(",", ":")) + "\n\n")
    write_stream(handler, "data: [DONE]\n\n")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        return

    def do_POST(self):
        global sequence
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {}
        token = self.headers.get("Authorization", "").removeprefix("Bearer ")
        labels = {
            "fixture-account-a": "a",
            "fixture-account-b": "b",
            "fixture-account-c": "c",
        }
        account = labels.get(token, "unknown")
        with lock:
            sequence += 1
            call = sequence
            with open(hits_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps({
                    "account": account,
                    "call": call,
                    "model": payload.get("model", ""),
                    "path": self.path,
                    "scenario": scenario,
                    "time": time.monotonic(),
                }, separators=(",", ":")) + "\n")

        model = payload.get("model", "fixture-primary-upstream")
        streaming = bool(payload.get("stream"))
        if scenario == "429" and call == 1:
            json_response(self, 429, {"error": {"type": "rate_limit_error", "message": "fixture limited"}}, {"Retry-After": "2"})
        elif scenario == "503" and call == 1:
            json_response(self, 503, {"error": {"type": "server_error", "message": "fixture unavailable"}})
        elif scenario == "timeout" and call == 1:
            json_response(self, 504, {"error": {"type": "timeout_error", "message": "fixture timeout"}})
        elif scenario == "cancel":
            begin_stream(self)
            time.sleep(10)
        elif scenario == "bootstrap-error" and call == 1:
            begin_stream(self)
            write_stream(self, 'event: error\ndata: {"status":503,"error":{"type":"server_error","message":"fixture bootstrap failed"}}\n\n')
        elif scenario == "payload-then-error":
            begin_stream(self)
            chunk = {
                "id": "fixture-visible",
                "object": "chat.completion.chunk",
                "created": 1,
                "model": model,
                "choices": [{"index": 0, "delta": {"content": "VISIBLE-ONCE"}, "finish_reason": None}],
            }
            write_stream(self, "data: " + json.dumps(chunk, separators=(",", ":")) + "\n\n")
            write_stream(self, 'event: error\ndata: {"status":503,"error":{"type":"server_error","message":"fixture late failure"}}\n\n')
        elif scenario == "invalid":
            json_response(self, 400, {"error": {"type": "invalid_request_error", "code": "invalid_value", "message": "fixture invalid"}})
        elif scenario == "policy":
            json_response(self, 502, {"error": {"type": "invalid_request", "code": "cyber_policy", "message": "fixture policy"}})
        elif scenario == "path-fallback" and call <= 2:
            json_response(self, 503, {"error": {"type": "server_error", "message": "fixture primary unavailable"}})
        elif streaming:
            good_stream(self, model)
        else:
            good_response(self, model)


ThreadingHTTPServer(("127.0.0.1", 18330), Handler).serve_forever()
PY
chown crsproxy:crsproxy "$fixture_root/mock.py"
chmod 0600 "$fixture_root/mock.py"

management_header='Authorization: Bearer fixture-management'
client_header='Authorization: Bearer fixture-client'

pressure() {
  curl -fsS --max-time 2 -H "$management_header" \
    http://127.0.0.1:18329/v0/management/routing-pressure
}

usage_totals() {
  curl -fsS --max-time 2 -H "$management_header" \
    http://127.0.0.1:18329/v0/management/api-key-usage |
    jq -r '([.. | objects | select(has("success") and has("failed")) | .success] | add // 0),
           ([.. | objects | select(has("success") and has("failed")) | .failed] | add // 0)' |
    paste -sd ' ' -
}

assert_zero_leases() {
  local snapshot=
  for _ in $(seq 1 100); do
    snapshot=$(pressure 2>/dev/null || true)
    if [[ -n $snapshot ]] && jq -e '
      .schema_version == 1 and
      .selector == "least_pressure" and
      .active_leases == 0 and
      .active_seats == 0 and
      (.seats | length) == 0
    ' <<<"$snapshot" >/dev/null; then
      return 0
    fi
    sleep 0.05
  done
  echo "routing pressure did not return to zero: ${snapshot:-unavailable}" >&2
  return 1
}

assert_one_active_lease() {
  local snapshot=
  for _ in $(seq 1 100); do
    snapshot=$(pressure 2>/dev/null || true)
    if [[ -n $snapshot ]] && jq -e '
      .schema_version == 1 and
      .selector == "least_pressure" and
      .active_leases == 1 and
      .active_seats == 1 and
      (.seats | length) == 1 and
      (.seats[0].seat_bucket | test("^h1_[0-9a-f]{16}$")) and
      .seats[0].in_flight == 1 and
      .seats[0].capacity == 1 and
      .seats[0].concurrency_pressure_milli == 1000
    ' <<<"$snapshot" >/dev/null; then
      printf '%s\n' "$snapshot" >"$case_dir/pressure-active.json"
      return 0
    fi
    sleep 0.05
  done
  echo "routing pressure never exposed the held lease: ${snapshot:-unavailable}" >&2
  return 1
}

start_case() {
  local scenario=$1
  stop_case
  case_dir="$fixture_root/$scenario"
  install -d -o crsproxy -g crsproxy -m 0750 "$case_dir" "$case_dir/auths"
  : >"$case_dir/hits.jsonl"
  chown crsproxy:crsproxy "$case_dir/hits.jsonl"
  chmod 0600 "$case_dir/hits.jsonl"

  cat >"$case_dir/config.yaml" <<EOF
host: 127.0.0.1
port: 18329
auth-dir: $case_dir/auths
api-keys:
  - fixture-client
remote-management:
  allow-remote: false
  secret-key: fixture-management
logging-to-file: false
usage-statistics-enabled: false
request-retry: 0
max-retry-credentials: 2
max-retry-interval: 0
disable-cooling: false
streaming:
  bootstrap-retries: 0
routing:
  strategy: least-pressure
  auto:
    mode: active
    max-fallbacks: 2
    default-models: [fault-primary, fault-fallback]
  observability:
    enabled: true
openai-compatibility:
  - name: fixture-primary
    base-url: http://127.0.0.1:18330/v1
    api-key-entries:
      - api-key: fixture-account-a
      - api-key: fixture-account-b
    models:
      - name: fixture-primary-upstream
        alias: fault-primary
        input-modalities: [text]
        output-modalities: [text]
  - name: fixture-fallback
    base-url: http://127.0.0.1:18330/v1
    api-key-entries:
      - api-key: fixture-account-c
    models:
      - name: fixture-fallback-upstream
        alias: fault-fallback
        input-modalities: [text]
        output-modalities: [text]
EOF
  chown crsproxy:crsproxy "$case_dir/config.yaml"
  chmod 0600 "$case_dir/config.yaml"

  setpriv --reuid=crsproxy --regid=crsproxy --clear-groups \
    python3 "$fixture_root/mock.py" "$scenario" "$case_dir/hits.jsonl" \
    >"$case_dir/mock.log" 2>&1 &
  mock_pid=$!
  (
    cd "$case_dir"
    exec setpriv --reuid=crsproxy --regid=crsproxy --clear-groups \
      env MANAGEMENT_PASSWORD=fixture-management \
      "$binary" -config "$case_dir/config.yaml"
  ) >"$case_dir/proxy.log" 2>&1 &
  proxy_pid=$!

  local ready=false
  for _ in $(seq 1 120); do
    if curl -sS --max-time 1 -H "$client_header" \
      http://127.0.0.1:18329/v1/models >"$case_dir/models.json" 2>/dev/null &&
      pressure >"$case_dir/pressure-baseline.json" 2>/dev/null; then
      ready=true
      break
    fi
    sleep 0.05
  done
  if [[ $ready != true ]]; then
    echo "isolated proxy did not become ready for $scenario" >&2
    sed -n '1,120p' "$case_dir/proxy.log" >&2
    return 1
  fi
  if [[ $(sha256sum "/proc/$proxy_pid/exe" | awk '{print $1}') != "$expected_sha256" ]]; then
    echo "running fixture executable SHA-256 mismatch" >&2
    return 1
  fi
  assert_zero_leases
}

nonstream_request() {
  local model=$1
  local output=$2
  curl -sS --max-time 12 -o "$output" -w '%{http_code}' \
    -H "$client_header" \
    -H 'Content-Type: application/json' \
    --data "$(jq -nc --arg model "$model" '{model:$model,messages:[{role:"user",content:"fixture-case"}],max_tokens:8,stream:false}')" \
    http://127.0.0.1:18329/v1/chat/completions
}

stream_request() {
  local model=$1
  local output=$2
  curl -sS -N --max-time 12 -o "$output" -w '%{http_code}' \
    -H "$client_header" \
    -H 'Content-Type: application/json' \
    --data "$(jq -nc --arg model "$model" '{model:$model,messages:[{role:"user",content:"fixture-case"}],max_tokens:8,stream:true}')" \
    http://127.0.0.1:18329/v1/chat/completions
}

hit_count() {
  wc -l <"$case_dir/hits.jsonl" | tr -d ' '
}

assert_distinct_two_hits() {
  [[ $(hit_count) == 2 ]] || {
    echo "expected two upstream hits, got $(hit_count)" >&2
    return 1
  }
  [[ $(jq -r '.account' "$case_dir/hits.jsonl" | sort -u | wc -l | tr -d ' ') == 2 ]] || {
    echo "retry did not use distinct accounts" >&2
    return 1
  }
  [[ $(jq -r '.account' "$case_dir/hits.jsonl" | grep -c '^unknown$' || true) == 0 ]] || {
    echo "mock received an unknown fake account" >&2
    return 1
  }
}

assert_account_events() {
  local expected_outcomes=$1
  python3 - "$case_dir/proxy.log" "$expected_outcomes" <<'PY'
import re
import sys
import time

expected = sys.argv[2].split(",") if sys.argv[2] else []
deadline = time.monotonic() + 2
events = []
while time.monotonic() < deadline:
    events = []
    for line in open(sys.argv[1], encoding="utf-8"):
        if "routing decision" not in line:
            continue
        fields = dict(re.findall(r"\b(routing_[a-z_]+)=(\S*)", line))
        if fields.get("routing_stage") in {"account_selection", "account_attempt"}:
            events.append(fields)
    if len(events) >= len(expected) * 2:
        time.sleep(0.1)
        events = []
        for line in open(sys.argv[1], encoding="utf-8"):
            if "routing decision" not in line:
                continue
            fields = dict(re.findall(r"\b(routing_[a-z_]+)=(\S*)", line))
            if fields.get("routing_stage") in {"account_selection", "account_attempt"}:
                events.append(fields)
        break
    time.sleep(0.05)
if len(events) != len(expected) * 2:
    raise SystemExit(f"expected {len(expected)} selected/terminal pairs, got {len(events)}: {events}")
selected = [event for event in events if event.get("routing_outcome") == "selected"]
terminal = [event for event in events if event.get("routing_stage") == "account_attempt"]
if len(selected) != len(expected) or len(terminal) != len(expected):
    raise SystemExit(f"missing selected/terminal account events: {events}")
request_buckets = {event.get("routing_request_bucket", "") for event in events}
if len(request_buckets) != 1 or not re.fullmatch(r"r1_[0-9a-f]{8}", next(iter(request_buckets))):
    raise SystemExit(f"account events do not share one opaque request bucket: {events}")
if any(event.get("routing_selector") != "least_pressure" for event in events):
    raise SystemExit(f"unexpected selector: {events}")
if [event.get("routing_outcome") for event in terminal] != expected:
    raise SystemExit(f"terminal outcomes {[event.get('routing_outcome') for event in terminal]}, want {expected}")

def identity(event):
    return (
        event.get("routing_request_bucket"), event.get("routing_attempt"),
        event.get("routing_seat_bucket"), event.get("routing_provider"),
        event.get("routing_model"),
    )

selected_keys = [identity(event) for event in selected]
terminal_keys = [identity(event) for event in terminal]
if len(set(selected_keys)) != len(selected_keys):
    raise SystemExit(f"duplicate selected account event: {events}")
if len(set(terminal_keys)) != len(terminal_keys):
    raise SystemExit(f"duplicate terminal account event: {events}")
if sorted(selected_keys) != sorted(terminal_keys):
    raise SystemExit(f"terminal account attempts do not pair one-to-one with selections: {events}")
for event in selected:
    if event.get("routing_stage") != "account_selection":
        raise SystemExit(f"selected event used wrong stage: {event}")
for event in terminal:
    if event.get("routing_stage") != "account_attempt":
        raise SystemExit(f"terminal event used wrong stage: {event}")
for event in events:
    if not re.fullmatch(r"h1_[0-9a-f]{16}", event.get("routing_seat_bucket", "")):
        raise SystemExit(f"invalid opaque seat bucket: {event}")

active_path = sys.argv[1].rsplit("/", 1)[0] + "/pressure-active.json"
try:
    import json
    active = json.load(open(active_path, encoding="utf-8"))
except FileNotFoundError:
    active = None
if active is not None:
    active_buckets = [seat.get("seat_bucket") for seat in active.get("seats", [])]
    if len(active_buckets) != 1 or active_buckets[0] not in {event.get("routing_seat_bucket") for event in selected}:
        raise SystemExit(f"active pressure seat does not match selected attempt: active={active} events={events}")
PY
}

run_retry_case() {
  local scenario=$1
  start_case "$scenario"
  local started elapsed http_code
  started=$(date +%s)
  http_code=$(nonstream_request fault-primary "$case_dir/response.json")
  elapsed=$(( $(date +%s) - started ))
  [[ $http_code == 200 ]] || { echo "$scenario returned HTTP $http_code" >&2; return 1; }
  [[ $(jq -r '.choices[0].message.content' "$case_dir/response.json") == fixture-ok ]] || {
    echo "$scenario response mismatch" >&2
    return 1
  }
  assert_distinct_two_hits
  assert_account_events failed,success
  if [[ $scenario == 429 ]]; then
    [[ $elapsed -lt 2 ]] || {
      echo "429 retried only after waiting for Retry-After instead of rotating immediately" >&2
      return 1
    }
    local first second
    first=$(sed -n '1p' "$case_dir/hits.jsonl" | jq -r '.time')
    second=$(sed -n '2p' "$case_dir/hits.jsonl" | jq -r '.time')
    python3 - "$first" "$second" <<'PY'
import sys
delta = float(sys.argv[2]) - float(sys.argv[1])
if delta >= 1.5:
    raise SystemExit(f"429 distinct-account rotation waited {delta:.3f}s")
PY
  fi
  assert_zero_leases
}

for retry_case in 429 503 timeout; do
  run_retry_case "$retry_case"
done

start_case invalid
invalid_http=$(nonstream_request fault-primary "$case_dir/response.json")
[[ $invalid_http == 400 ]] || { echo "invalid request returned HTTP $invalid_http" >&2; exit 1; }
[[ $(hit_count) == 1 ]] || { echo "invalid request retried" >&2; exit 1; }
assert_account_events rejected
assert_zero_leases

start_case policy
policy_http=$(nonstream_request auto "$case_dir/response.json")
[[ $policy_http != 200 ]] || { echo "policy request unexpectedly succeeded" >&2; exit 1; }
[[ $(hit_count) == 1 ]] || { echo "policy request retried or route-shopped" >&2; exit 1; }
assert_account_events rejected
assert_zero_leases

start_case bootstrap-error
bootstrap_http=$(stream_request fault-primary "$case_dir/response.sse")
[[ $bootstrap_http == 200 ]] || { echo "bootstrap retry returned HTTP $bootstrap_http" >&2; exit 1; }
assert_distinct_two_hits
assert_account_events failed,success
grep -q 'fixture-stream-ok' "$case_dir/response.sse" || { echo "bootstrap fallback payload missing" >&2; exit 1; }
if grep -q 'fixture bootstrap failed' "$case_dir/response.sse"; then
  echo "bootstrap error leaked before successful retry" >&2
  exit 1
fi
assert_zero_leases

start_case payload-then-error
payload_http=$(stream_request auto "$case_dir/response.sse")
[[ $payload_http == 200 ]] || { echo "late stream error returned HTTP $payload_http" >&2; exit 1; }
[[ $(hit_count) == 1 ]] || { echo "stream replayed after visible output" >&2; exit 1; }
[[ $(grep -o 'VISIBLE-ONCE' "$case_dir/response.sse" | wc -l | tr -d ' ') == 1 ]] || {
  echo "visible payload was lost or replayed" >&2
  exit 1
}
grep -q 'fixture late failure' "$case_dir/response.sse" || { echo "terminal stream error was not visible" >&2; exit 1; }
assert_account_events failed
assert_zero_leases

start_case cancel
cancel_usage_before=$(usage_totals)
curl -sS -N --max-time 2 -o "$case_dir/response.sse" \
  -H "$client_header" \
  -H 'Content-Type: application/json' \
  --data '{"model":"fault-primary","messages":[{"role":"user","content":"fixture-case"}],"stream":true}' \
  http://127.0.0.1:18329/v1/chat/completions >/dev/null 2>&1 &
cancel_curl_pid=$!
assert_one_active_lease
wait "$cancel_curl_pid" || true
[[ $(hit_count) == 1 ]] || { echo "canceled request retried" >&2; exit 1; }
assert_account_events canceled
assert_zero_leases
cancel_usage_after=$(usage_totals)
[[ $cancel_usage_after == "$cancel_usage_before" ]] || {
  echo "cancellation changed success/failure accounting: before=$cancel_usage_before after=$cancel_usage_after" >&2
  exit 1
}

start_case path-fallback
path_http=$(nonstream_request auto "$case_dir/response.json")
[[ $path_http == 200 ]] || { echo "path fallback returned HTTP $path_http" >&2; exit 1; }
[[ $(hit_count) == 3 ]] || { echo "path fallback hit count = $(hit_count), want 3" >&2; exit 1; }
python3 - "$case_dir/hits.jsonl" <<'PY'
import json
import sys

hits = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8")]
if [hit["account"] for hit in hits[:2]] not in (["a", "b"], ["b", "a"]):
    raise SystemExit(f"primary attempts were not distinct: {hits}")
if hits[0]["model"] != "fixture-primary-upstream" or hits[1]["model"] != "fixture-primary-upstream":
    raise SystemExit(f"primary model mismatch: {hits}")
if hits[2]["account"] != "c" or hits[2]["model"] != "fixture-fallback-upstream":
    raise SystemExit(f"fallback path mismatch: {hits}")
PY
sleep 0.1
python3 - "$case_dir/proxy.log" <<'PY'
import re
import sys

events = []
for line in open(sys.argv[1], encoding="utf-8"):
    if "routing decision" not in line or "routing_stage=model_attempt" not in line:
        continue
    events.append(dict(re.findall(r"\b(routing_[a-z_]+)=(\S*)", line)))
failed = [e for e in events if e.get("routing_model") == "fault-primary" and e.get("routing_outcome") == "failed"]
succeeded = [e for e in events if e.get("routing_model") == "fault-fallback" and e.get("routing_outcome") == "success"]
if len(failed) != 1 or len(succeeded) != 1:
    raise SystemExit(f"path fallback telemetry mismatch: {events}")
PY
assert_account_events failed,failed,success
assert_zero_leases

stop_case
printf 'status=ok namespace=loopback-only binary_sha256=%s cases=8 account_retries_distinct=4 path_fallback=1 cancellations_retried=0 post_output_replays=0 active_leases=0\n' \
  "$expected_sha256"

#!/usr/bin/env bash
set -euo pipefail

if [[ ${1:-} != --inside || -z ${2:-} ]]; then
  echo "internal helper; use verify_shadow_fixture.sh" >&2
  exit 2
fi

binary=$2
fixture_dir=$(mktemp -d /tmp/cliproxy-shadow-fixture.XXXXXX)
proxy_pid=
mock_pid=

cleanup() {
  if [[ -n $proxy_pid ]]; then
    kill "$proxy_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
  fi
  if [[ -n $mock_pid ]]; then
    kill "$mock_pid" 2>/dev/null || true
    wait "$mock_pid" 2>/dev/null || true
  fi
  rm -rf -- "$fixture_dir"
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

chown crsproxy:crsproxy "$fixture_dir"
chmod 0750 "$fixture_dir"
install -d -o crsproxy -g crsproxy -m 0750 "$fixture_dir/auths"
touch "$fixture_dir/hits.jsonl"
chown crsproxy:crsproxy "$fixture_dir/hits.jsonl"
chmod 0600 "$fixture_dir/hits.jsonl"

cat >"$fixture_dir/mock.py" <<'PY'
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

hits_path = sys.argv[1]

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {}
        with open(hits_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"path": self.path, "model": payload.get("model", "")}, separators=(",", ":")) + "\n")
        response = {
            "id": "fixture-response",
            "object": "chat.completion",
            "created": 1,
            "model": payload.get("model", "fixture-upstream"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "fixture-ok"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        }
        encoded = json.dumps(response, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

server = ThreadingHTTPServer(("127.0.0.1", 18320), Handler)
server.serve_forever()
PY

cat >"$fixture_dir/config.yaml" <<EOF
host: 127.0.0.1
port: 18319
auth-dir: $fixture_dir/auths
api-keys:
  - fixture-client
logging-to-file: false
usage-statistics-enabled: false
request-retry: 0
max-retry-credentials: 2
max-retry-interval: 0
routing:
  strategy: shadow-least-pressure
  auto:
    mode: shadow
    max-fallbacks: 1
    default-models: [fixture-text]
    task-models:
      code: [fixture-text]
      writing: [fixture-text]
  observability:
    enabled: true
openai-compatibility:
  - name: fixture
    base-url: http://127.0.0.1:18320/v1
    api-key-entries:
      - api-key: fixture-a
      - api-key: fixture-b
    models:
      - name: fixture-upstream
        alias: fixture-text
        input-modalities: [text]
        output-modalities: [text]
EOF
chown crsproxy:crsproxy "$fixture_dir/config.yaml" "$fixture_dir/mock.py"
chmod 0600 "$fixture_dir/config.yaml" "$fixture_dir/mock.py"

setpriv --reuid=crsproxy --regid=crsproxy --clear-groups python3 "$fixture_dir/mock.py" "$fixture_dir/hits.jsonl" >"$fixture_dir/mock.log" 2>&1 &
mock_pid=$!
(
  cd "$fixture_dir"
  exec setpriv --reuid=crsproxy --regid=crsproxy --clear-groups "$binary" -config "$fixture_dir/config.yaml"
) >"$fixture_dir/proxy.log" 2>&1 &
proxy_pid=$!

ready=false
for _ in $(seq 1 100); do
  if curl -sS --max-time 1 -H 'Authorization: Bearer fixture-client' http://127.0.0.1:18319/v1/models >"$fixture_dir/models.json" 2>/dev/null; then
    ready=true
    break
  fi
  sleep 0.05
done
if [[ $ready != true ]]; then
  echo "isolated proxy did not become ready" >&2
  sed -n '1,120p' "$fixture_dir/proxy.log" >&2
  exit 1
fi

request() {
  local model=$1
  local content=$2
  local output=$3
  curl -sS --max-time 10 -o "$output" -w '%{http_code}' \
    -H 'Authorization: Bearer fixture-client' \
    -H 'Content-Type: application/json' \
    --data "$(jq -nc --arg model "$model" --arg content "$content" '{model:$model,messages:[{role:"user",content:$content}],max_tokens:8,stream:false}')" \
    http://127.0.0.1:18319/v1/chat/completions
}

auto_code=$(request auto 'Debug this code and return one word.' "$fixture_dir/auto.json")
explicit_code=$(request fixture-text 'Return one word.' "$fixture_dir/explicit.json")
near_code=$(request Auto 'This is intentionally explicit.' "$fixture_dir/near.json")
sleep 0.2

[[ $auto_code == 200 ]] || { echo "auto request returned HTTP $auto_code" >&2; exit 1; }
[[ $explicit_code == 200 ]] || { echo "explicit request returned HTTP $explicit_code" >&2; exit 1; }
[[ $near_code != 200 ]] || { echo "near-auto request unexpectedly routed" >&2; exit 1; }
[[ $(jq -r '.choices[0].message.content' "$fixture_dir/auto.json") == fixture-ok ]] || { echo "auto response mismatch" >&2; exit 1; }
[[ $(jq -r '.choices[0].message.content' "$fixture_dir/explicit.json") == fixture-ok ]] || { echo "explicit response mismatch" >&2; exit 1; }
[[ $(wc -l <"$fixture_dir/hits.jsonl" | tr -d ' ') == 2 ]] || { echo "unexpected upstream hit count" >&2; exit 1; }
[[ $(jq -r 'select(.model == "fixture-upstream") | .model' "$fixture_dir/hits.jsonl" | wc -l | tr -d ' ') == 2 ]] || {
  echo "upstream did not receive the configured model exactly twice" >&2
  exit 1
}

python3 - "$fixture_dir/proxy.log" <<'PY'
import re
import sys

lines = [line.strip() for line in open(sys.argv[1], encoding="utf-8") if "routing decision" in line]
if not lines:
    raise SystemExit("no routing telemetry was emitted")

def fields(line):
    return dict(re.findall(r"\b(routing_[a-z_]+)=([^ ]*)", line))

events = [fields(line) for line in lines]
required = {
    "routing_schema_version", "routing_stage", "routing_mode", "routing_task",
    "routing_score_version", "routing_model", "routing_provider", "routing_reason",
    "routing_outcome", "routing_attempt", "routing_candidate_count",
    "routing_duration_ms", "routing_selector", "routing_shadow_match",
    "routing_seat_bucket", "routing_predicted_seat_bucket",
}
for event in events:
    missing = required.difference(event)
    if missing:
        raise SystemExit(f"routing event missing fields: {sorted(missing)}")

decisions = [event for event in events if event.get("routing_stage") == "model_decision"]
if len(decisions) != 1:
    raise SystemExit(f"expected exactly one semantic decision, got {len(decisions)}")
decision = decisions[0]
expected_decision = {
    "routing_mode": "shadow", "routing_task": "code", "routing_score_version": "v2",
    "routing_model": "fixture-text", "routing_reason": "keyword_code", "routing_outcome": "selected",
}
for key, value in expected_decision.items():
    if decision.get(key) != value:
        raise SystemExit(f"semantic decision {key}={decision.get(key)!r}, want {value!r}")

predictions = [event for event in events if event.get("routing_stage") == "account_prediction"]
if len(predictions) != 2:
    raise SystemExit(f"expected two account predictions, got {len(predictions)}")
for prediction in predictions:
    if prediction.get("routing_mode") != "shadow" or prediction.get("routing_candidate_count") != "2":
        raise SystemExit(f"invalid prediction event: {prediction}")
    if prediction.get("routing_selector") != "shadow_least_pressure":
        raise SystemExit(f"invalid prediction selector: {prediction}")
    actual = prediction.get("routing_seat_bucket", "")
    predicted = prediction.get("routing_predicted_seat_bucket", "")
    if not re.fullmatch(r"h1_[0-9a-f]{16}", actual) or not re.fullmatch(r"h1_[0-9a-f]{16}", predicted):
        raise SystemExit(f"invalid opaque seat buckets: {prediction}")
    if (actual == predicted) != (prediction.get("routing_shadow_match") == "true"):
        raise SystemExit(f"shadow comparison is inconsistent: {prediction}")

for forbidden in ("fixture-a", "fixture-b", "fixture-client", "Bearer", "@", "/auths/"):
    if any(forbidden in line for line in lines):
        raise SystemExit(f"routing telemetry leaked forbidden material: {forbidden}")
PY

printf 'status=ok namespace=loopback-only auto_http=%s explicit_http=%s near_auto_http=%s upstream_hits=2 semantic_decisions=1 account_predictions=2\n' \
  "$auto_code" "$explicit_code" "$near_code"

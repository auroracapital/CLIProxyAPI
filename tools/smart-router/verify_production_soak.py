#!/usr/bin/env python3
"""Record privacy-safe CLIProxy smart-router production soak evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any


ACCOUNT_STAGES = {"account_selection", "account_attempt"}
TELEMETRY_FIELD = re.compile(r"\b(routing_[a-z_]+)=(\S*)")
SEAT_BUCKET = re.compile(r"^h1_[0-9a-f]{16}$")
REQUEST_BUCKET = re.compile(r"^r1_[0-9a-f]{8}$")
FORBIDDEN_TELEMETRY = re.compile(
    r"(?i)(bearer\s+|access[_-]?token|refresh[_-]?token|@|/opt/crsproxy/auths|prompt|message|content)"
)
MANUAL_TOGGLE_PATH = "/v0/management/auth-files/status"


def command(*args: str) -> str:
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout.strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def api_json(path: str, token: str) -> Any:
    request = urllib.request.Request(
        "http://127.0.0.1:8319" + path,
        headers={"Authorization": "Bearer " + token},
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.load(response)


def unauthenticated_status(path: str) -> int:
    try:
        with urllib.request.urlopen("http://127.0.0.1:8319" + path, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def read_events(log_path: Path, offset: int, inode: int) -> tuple[list[dict[str, str]], int, int, int, int, int]:
    stat = log_path.stat()
    size = stat.st_size
    if stat.st_ino != inode or size < offset:
        offset = 0
    lines: list[str] = []
    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(offset)
        lines = handle.readlines()
        next_offset = handle.tell()
    events: list[dict[str, str]] = []
    invalid = 0
    sensitive = 0
    manual_toggles = 0
    for line in lines:
        if MANUAL_TOGGLE_PATH in line and re.search(
            r'\b(PATCH|PUT|POST|DELETE)\s+"?' + re.escape(MANUAL_TOGGLE_PATH), line
        ):
            manual_toggles += 1
        if "routing decision" not in line:
            continue
        fields = dict(TELEMETRY_FIELD.findall(line))
        if FORBIDDEN_TELEMETRY.search(line):
            sensitive += 1
        if fields.get("routing_stage") in ACCOUNT_STAGES:
            if not SEAT_BUCKET.fullmatch(fields.get("routing_seat_bucket", "")):
                invalid += 1
            if not REQUEST_BUCKET.fullmatch(fields.get("routing_request_bucket", "")):
                invalid += 1
            events.append(fields)
    return events, next_offset, stat.st_ino, invalid, sensitive, manual_toggles


def event_key(event: dict[str, str]) -> tuple[str, str, str, str, str]:
    return (
        event.get("routing_request_bucket", ""),
        event.get("routing_attempt", ""),
        event.get("routing_seat_bucket", ""),
        event.get("routing_provider", ""),
        event.get("routing_model", ""),
    )


def summarize_events(events: list[dict[str, str]]) -> dict[str, Any]:
    selected = Counter(event_key(event) for event in events if event.get("routing_stage") == "account_selection")
    terminal = Counter(event_key(event) for event in events if event.get("routing_stage") == "account_attempt")
    return {
        "selected": sum(selected.values()),
        "terminal": sum(terminal.values()),
        "duplicate_selected": sum(value - 1 for value in selected.values() if value > 1),
        "duplicate_terminal": sum(value - 1 for value in terminal.values() if value > 1),
        "unmatched_selected": sum((selected - terminal).values()),
        "unmatched_terminal": sum((terminal - selected).values()),
        "terminal_outcomes": dict(
            Counter(event.get("routing_outcome", "") for event in events if event.get("routing_stage") == "account_attempt")
        ),
    }


def event_key_string(event: dict[str, str]) -> str:
    return "|".join(event_key(event))


def update_lifecycle(path: Path, events: list[dict[str, str]]) -> dict[str, Any]:
    if path.exists():
        state = json.loads(path.read_text(encoding="utf-8"))
    else:
        state = {"selected": {}, "terminal": {}, "outcomes": {}, "manual_toggles": 0}
    selected = Counter({key: int(value) for key, value in state.get("selected", {}).items()})
    terminal = Counter({key: int(value) for key, value in state.get("terminal", {}).items()})
    outcomes = Counter({key: int(value) for key, value in state.get("outcomes", {}).items()})
    for event in events:
        if event.get("routing_stage") == "account_selection":
            selected[event_key_string(event)] += 1
        elif event.get("routing_stage") == "account_attempt":
            terminal[event_key_string(event)] += 1
            outcomes[event.get("routing_outcome", "")] += 1
    updated = {
        "selected": dict(selected),
        "terminal": dict(terminal),
        "outcomes": dict(outcomes),
        "manual_toggles": int(state.get("manual_toggles", 0)),
    }
    atomic_json(path, updated)
    return {
        "selected": sum(selected.values()),
        "terminal": sum(terminal.values()),
        "duplicate_selected": sum(value - 1 for value in selected.values() if value > 1),
        "duplicate_terminal": sum(value - 1 for value in terminal.values() if value > 1),
        "unmatched_selected": sum((selected - terminal).values()),
        "unmatched_terminal": sum((terminal - selected).values()),
        "terminal_outcomes": dict(outcomes),
    }


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        values[name.strip()] = value.strip()
    return values


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    os.chmod(temp, 0o600)
    os.replace(temp, path)


def append_json(path: Path, payload: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")


def routing_modes(config_text: str) -> tuple[str, str]:
    strategy = ""
    auto_mode = ""
    in_routing = False
    in_auto = False
    for raw_line in config_text.splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip())
        text = raw_line.strip()
        if indent == 0:
            in_routing = text == "routing:"
            in_auto = False
            continue
        if not in_routing:
            continue
        if indent == 2 and text.startswith("strategy:"):
            strategy = text.split(":", 1)[1].strip().strip('"\'')
        if indent == 2:
            in_auto = text == "auto:"
            continue
        if in_auto and indent == 4 and text.startswith("mode:"):
            auto_mode = text.split(":", 1)[1].strip().strip('"\'')
    return strategy, auto_mode


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-directory", type=Path, default=Path("/var/lib/cliproxy-smart-router-soak"))
    parser.add_argument("--log", type=Path, default=Path("/opt/crsproxy/logs/main.log"))
    parser.add_argument("--binary", type=Path, default=Path("/opt/crsproxy/cli-proxy-api"))
    parser.add_argument("--config", type=Path, default=Path("/opt/crsproxy/config.yaml"))
    args = parser.parse_args()

    args.state_directory.mkdir(parents=True, exist_ok=True)
    os.chmod(args.state_directory, 0o700)
    baseline_path = args.state_directory / "baseline.json"
    status_path = args.state_directory / "status.json"
    evidence_path = args.state_directory / "evidence.jsonl"
    offset_path = args.state_directory / "log-offset"
    lifecycle_path = args.state_directory / "lifecycle.json"

    now = time.time()
    binary_hash = sha256(args.binary)
    config_hash = sha256(args.config)
    config_text = args.config.read_text(encoding="utf-8", errors="replace")
    strategy, auto_mode = routing_modes(config_text)
    auto_active = auto_mode == "active"
    least_pressure = strategy == "least-pressure"

    if baseline_path.exists():
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    else:
        baseline = {
            "started_at_epoch": now,
            "expected_binary_sha256": binary_hash,
            "expected_config_sha256": config_hash,
            "expected_duration_seconds": 24 * 60 * 60,
        }
        atomic_json(baseline_path, baseline)
        log_stat = args.log.stat()
        atomic_json(offset_path, {"offset": log_stat.st_size, "inode": log_stat.st_ino})

    offset_state = json.loads(offset_path.read_text(encoding="utf-8"))
    events, next_offset, next_inode, invalid_events, sensitive_events, manual_toggles = read_events(
        args.log, int(offset_state.get("offset", 0)), int(offset_state.get("inode", 0))
    )
    atomic_json(offset_path, {"offset": next_offset, "inode": next_inode})

    management = load_env(Path("/etc/crsproxy/management-general.env"))["MANAGEMENT_PASSWORD"]
    reconciler = load_env(Path("/etc/crsproxy/account-reconciler.env"))["CLIPROXY_RECONCILER_API_KEY"]
    pressure = api_json("/v0/management/routing-pressure", management)
    reconcile = api_json("/v0/management/auth-files/reconcile-status", reconciler)["credentials"]

    states = Counter(str(row.get("state", "")) for row in reconcile)
    generation_mismatches = sum(row.get("generation") != row.get("runtime_generation") for row in reconcile)
    ready_mismatches = sum(
        row.get("state") == "ready"
        and (
            row.get("disabled") is True
            or row.get("durable_disabled") is True
            or row.get("unavailable") is True
            or row.get("credential_status") != "active"
        )
        for row in reconcile
    )
    pressure_rows = pressure.get("seats", [])
    pressure_consistent = (
        pressure.get("schema_version") == 1
        and pressure.get("selector") == "least_pressure"
        and pressure.get("active_seats") == len(pressure_rows)
        and pressure.get("active_leases") == sum(int(row.get("in_flight", 0)) for row in pressure_rows)
        and all(SEAT_BUCKET.fullmatch(str(row.get("seat_bucket", ""))) for row in pressure_rows)
    )
    event_summary = update_lifecycle(lifecycle_path, events)
    lifecycle_state = json.loads(lifecycle_path.read_text(encoding="utf-8"))
    lifecycle_state["manual_toggles"] = int(lifecycle_state.get("manual_toggles", 0)) + manual_toggles
    atomic_json(lifecycle_path, lifecycle_state)
    failures: list[str] = []
    reconciler_result = command("systemctl", "show", "cliproxy-account-reconciler.service", "-p", "Result", "--value")
    reconciler_status = int(
        command("systemctl", "show", "cliproxy-account-reconciler.service", "-p", "ExecMainStatus", "--value") or "0"
    )
    reconciler_completed = (reconciler_result, reconciler_status) in {("success", 0), ("exit-code", 1)}
    checks = {
        "binary_hash": binary_hash == baseline["expected_binary_sha256"],
        "config_hash": config_hash == baseline["expected_config_sha256"],
        "auto_active": auto_active,
        "least_pressure": least_pressure,
        "crsproxy_active": command("systemctl", "is-active", "crsproxy.service") == "active",
        "nginx_active": command("systemctl", "is-active", "nginx") == "active",
        "reconciler_timer_active": command("systemctl", "is-active", "cliproxy-account-reconciler.timer") == "active",
        "reconciler_timer_enabled": command("systemctl", "is-enabled", "cliproxy-account-reconciler.timer") == "enabled",
        "reconciler_controller_completed": reconciler_completed,
        "inventory_complete": len(reconcile) == 19,
        "generation_converged": generation_mismatches == 0,
        "ready_admission_converged": ready_mismatches == 0,
        "pressure_consistent": pressure_consistent,
        "pressure_protected": unauthenticated_status("/v0/management/routing-pressure") == 401,
        "telemetry_schema": invalid_events == 0,
        "telemetry_privacy": sensitive_events == 0,
        "no_duplicate_events": event_summary["duplicate_selected"] == 0 and event_summary["duplicate_terminal"] == 0,
        "no_manual_toggles": lifecycle_state["manual_toggles"] == 0,
    }
    for name, passed in checks.items():
        if not passed:
            failures.append(name)
    payload = {
        "schema_version": 1,
        "sampled_at_epoch": now,
        "elapsed_seconds": int(now - float(baseline["started_at_epoch"])),
        "complete": now - float(baseline["started_at_epoch"]) >= int(baseline["expected_duration_seconds"]),
        "healthy": not failures,
        "failures": failures,
        "checks": checks,
        "inventory": {
            "total": len(reconcile),
            "states": dict(states),
            "managed_degraded": sum(value for state, value in states.items() if state != "ready"),
            "generation_mismatches": generation_mismatches,
            "ready_mismatches": ready_mismatches,
        },
        "reconciler": {"result": reconciler_result, "exec_main_status": reconciler_status},
        "pressure": {"active_leases": pressure.get("active_leases"), "active_seats": pressure.get("active_seats")},
        "events": event_summary,
        "manual_toggles": lifecycle_state["manual_toggles"],
    }
    append_json(evidence_path, payload)
    atomic_json(status_path, payload)
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())

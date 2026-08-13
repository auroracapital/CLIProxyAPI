#!/usr/bin/env python3
"""Record privacy-safe, crash-consistent CLIProxy production-soak evidence.

The unkeyed sample chain detects corruption and divergence from the authoritative
root-owned state. It is not intended to resist a hostile root user.
"""

from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import json
import math
import os
import re
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 2
EXPECTED_DURATION_SECONDS = 24 * 60 * 60
EXPECTED_INTERVAL_SECONDS = 60
MAX_SAMPLE_GAP_SECONDS = 90
STARTUP_BOUNDARY_GRACE_SECONDS = 5 * 60
TERMINAL_GRACE_SECONDS = 15 * 60

ACCOUNT_STAGES = {"account_selection", "account_attempt"}
SLO_STAGES = {"model_decision", "model_attempt", "stream_attempt", "count_attempt"}
OBSERVED_STAGES = ACCOUNT_STAGES | SLO_STAGES
ATTEMPT_OUTCOMES = {"success", "failed", "canceled", "unavailable", "rejected"}
SELECTION_OUTCOMES = {"selected"}
INVENTORY_STATES = {"ready", "cooling", "auth_required", "refreshing", "probing", "quarantined"}
RECONCILER_RESULTS = {"success", "exit-code"}
SEAT_BUCKET = re.compile(r"^h1_[0-9a-f]{16}$")
REQUEST_BUCKET = re.compile(r"^r1_[0-9a-f]{16}$")
SAFE_ROUTE_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,127}$")
ATTEMPT = re.compile(r"^[1-9][0-9]{0,3}$")
NONNEGATIVE_INTEGER = re.compile(r"^(0|[1-9][0-9]{0,9})$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
RUN_ID = re.compile(r"^[0-9a-f]{32}$")
EVENT_ID = re.compile(r"^e1_[0-9a-f]{64}$")
TELEMETRY_FIELD = re.compile(r"\b(routing_[a-z_]+)=(\S*)")
FORBIDDEN_TELEMETRY = re.compile(
    r"(?i)(bearer\s+|authorization|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|"
    r"password|cookie|secret|credential|(?:^|[\s_=-])token(?:[\s_=-]|$)|(?:^|[\s_=-])key(?:[\s_=-]|$)|"
    r"@|/opt/crsproxy/auths|prompt|message|content)"
)
MANUAL_TOGGLE_PATH = "/v0/management/auth-files/status"
MANUAL_TOGGLE = re.compile(r'\b(PATCH|PUT|POST|DELETE)\s+"?' + re.escape(MANUAL_TOGGLE_PATH))

CHECK_NAMES = {
    "binary_hash",
    "config_hash",
    "verifier_hash",
    "auto_active",
    "least_pressure",
    "crsproxy_active",
    "nginx_active",
    "reconciler_timer_active",
    "reconciler_timer_enabled",
    "reconciler_controller_completed",
    "inventory_complete",
    "reconcile_schema",
    "routable_capacity",
    "generation_converged",
    "ready_admission_converged",
    "pressure_consistent",
    "pressure_protected",
    "telemetry_schema",
    "telemetry_privacy",
    "no_duplicate_events",
    "no_reused_seat_attempts",
    "no_orphan_terminal_events",
    "no_manual_toggles",
    "log_continuity",
}
INCIDENT_NAMES = {"verifier_execution", "artifact_integrity"}
FAILURE_NAMES = CHECK_NAMES | INCIDENT_NAMES
MIN_ELIGIBLE_REQUESTS = 100
MIN_DETERMINISTIC_DECISIONS = 100
TERMINAL_SUCCESS_PERMILLE = 999
FIRST_ATTEMPT_SUCCESS_PERCENT = 98
ROUTING_P95_LIMIT_MS = 25
PRESSURE_SKEW_RATIO_MILLI = 1500
PRESSURE_SKEW_MAX_SECONDS = 5 * 60


def canonical_json(payload: Any) -> bytes:
    return (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()


def object_hash(payload: Any) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def command(*args: str) -> str:
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout.strip()


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


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        values[name.strip()] = value.strip()
    return values


def secure_directory(path: Path) -> None:
    if path.is_symlink():
        raise RuntimeError("unsafe state directory")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.stat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
        raise RuntimeError("unsafe state directory")
    os.chmod(path, 0o700)


def open_lock(directory: Path) -> int:
    descriptor = os.open(directory / "lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
        os.close(descriptor)
        raise RuntimeError("unsafe state lock")
    os.fchmod(descriptor, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        raise RuntimeError("soak verifier already running") from None
    return descriptor


def secure_read(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise RuntimeError("unsafe state file")
        os.fchmod(descriptor, 0o600)
        with os.fdopen(os.dup(descriptor), "rb") as handle:
            return handle.read()
    finally:
        os.close(descriptor)


def secure_read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(secure_read(path))
    if not isinstance(payload, dict):
        raise RuntimeError("invalid state document")
    return payload


def atomic_write(path: Path, content: bytes) -> None:
    directory = path.parent
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = "." + path.name + "." + uuid.uuid4().hex + ".tmp"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory_fd,
        )
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.close(directory_fd)


def write_final_once(path: Path, content: bytes) -> None:
    if path.exists() or path.is_symlink():
        if secure_read(path) != content:
            raise RuntimeError("final artifact mismatch")
        return
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


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


def safe_event(fields: dict[str, str]) -> dict[str, str] | None:
    stage = fields.get("routing_stage", "")
    outcome = fields.get("routing_outcome", "")
    if stage not in OBSERVED_STAGES:
        return None
    if not REQUEST_BUCKET.fullmatch(fields.get("routing_request_bucket", "")):
        return None
    if stage in ACCOUNT_STAGES and not SEAT_BUCKET.fullmatch(fields.get("routing_seat_bucket", "")):
        return None
    if stage in ACCOUNT_STAGES and not ATTEMPT.fullmatch(fields.get("routing_attempt", "")):
        return None
    if stage in SLO_STAGES and not NONNEGATIVE_INTEGER.fullmatch(fields.get("routing_attempt", "")):
        return None
    if not SAFE_ROUTE_VALUE.fullmatch(fields.get("routing_provider", "")):
        return None
    if not SAFE_ROUTE_VALUE.fullmatch(fields.get("routing_model", "")):
        return None
    allowed_outcomes = SELECTION_OUTCOMES if stage in {"account_selection", "model_decision"} else (
        ATTEMPT_OUTCOMES | {"started", "committed"}
    )
    if outcome not in allowed_outcomes:
        return None
    result = {key: fields.get(key, "") for key in (
        "routing_stage",
        "routing_outcome",
        "routing_request_bucket",
        "routing_attempt",
        "routing_seat_bucket",
        "routing_provider",
        "routing_model",
    )}
    if stage == "model_decision":
        duration = fields.get("routing_duration_ms", "")
        if not NONNEGATIVE_INTEGER.fullmatch(duration) or int(duration) > 3_600_000:
            return None
        result["routing_duration_ms"] = duration
    return result


def read_events(log_path: Path, cursor: dict[str, int]) -> tuple[list[dict[str, str]], dict[str, int], dict[str, int]]:
    metadata = log_path.stat()
    offset = int(cursor["offset"])
    inode = int(cursor["inode"])
    discontinuity = metadata.st_ino != inode or metadata.st_size < offset
    if discontinuity:
        offset = 0
    with log_path.open("rb") as handle:
        handle.seek(offset)
        raw = handle.read()
    newline = raw.rfind(b"\n")
    complete = raw[: newline + 1] if newline >= 0 else b""
    lines = complete.decode("utf-8", errors="replace").splitlines()
    next_cursor = {"offset": offset + len(complete), "inode": metadata.st_ino}
    events: list[dict[str, str]] = []
    counters = {"invalid": 0, "sensitive": 0, "manual_toggles": 0, "discontinuity": int(discontinuity)}
    for line in lines:
        if MANUAL_TOGGLE_PATH in line and MANUAL_TOGGLE.search(line):
            counters["manual_toggles"] += 1
        if "routing decision" not in line:
            continue
        if FORBIDDEN_TELEMETRY.search(line):
            counters["sensitive"] += 1
            continue
        pairs = TELEMETRY_FIELD.findall(line)
        names = [name for name, _ in pairs]
        if len(names) != len(set(names)):
            counters["invalid"] += 1
            continue
        event = safe_event(dict(pairs))
        if event is None:
            counters["invalid"] += 1
            continue
        events.append(event)
    return events, next_cursor, counters


def event_key(event: dict[str, str]) -> str:
    material = "|".join(
        event[key]
        for key in (
            "routing_request_bucket",
            "routing_attempt",
            "routing_seat_bucket",
            "routing_provider",
            "routing_model",
        )
    )
    return "e1_" + hashlib.sha256(material.encode()).hexdigest()


def new_baseline(
    now: float,
    binary_hash: str,
    config_hash: str,
    verifier_hash: str,
    log_metadata: os.stat_result,
    pressure_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    allowance: dict[str, int] = {}
    for row in pressure_rows:
        seat = str(row.get("seat_bucket", ""))
        leases = int(row.get("in_flight", 0))
        if not SEAT_BUCKET.fullmatch(seat) or leases < 0:
            raise RuntimeError("invalid pressure snapshot")
        allowance[seat] = leases
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": uuid.uuid4().hex,
        "started_at_epoch": now,
        "soak_cutoff_epoch": now + EXPECTED_DURATION_SECONDS,
        "expected_binary_sha256": binary_hash,
        "expected_config_sha256": config_hash,
        "expected_verifier_sha256": verifier_hash,
        "expected_duration_seconds": EXPECTED_DURATION_SECONDS,
        "sample_interval_seconds": EXPECTED_INTERVAL_SECONDS,
        "max_sample_gap_seconds": MAX_SAMPLE_GAP_SECONDS,
        "startup_boundary_grace_seconds": STARTUP_BOUNDARY_GRACE_SECONDS,
        "terminal_grace_seconds": TERMINAL_GRACE_SECONDS,
        "initial_log_inode": int(log_metadata.st_ino),
        "initial_log_offset": int(log_metadata.st_size),
        "startup_allowance": allowance,
    }


def validate_baseline(baseline: dict[str, Any], now: float) -> None:
    exact = {
        "schema_version": SCHEMA_VERSION,
        "expected_duration_seconds": EXPECTED_DURATION_SECONDS,
        "sample_interval_seconds": EXPECTED_INTERVAL_SECONDS,
        "max_sample_gap_seconds": MAX_SAMPLE_GAP_SECONDS,
        "startup_boundary_grace_seconds": STARTUP_BOUNDARY_GRACE_SECONDS,
        "terminal_grace_seconds": TERMINAL_GRACE_SECONDS,
    }
    if any(baseline.get(key) != value for key, value in exact.items()):
        raise RuntimeError("invalid baseline contract")
    required = set(exact) | {
        "run_id", "started_at_epoch", "soak_cutoff_epoch", "expected_binary_sha256",
        "expected_config_sha256", "expected_verifier_sha256", "initial_log_inode",
        "initial_log_offset", "startup_allowance",
    }
    if set(baseline) != required:
        raise RuntimeError("invalid baseline fields")
    started = float(baseline["started_at_epoch"])
    cutoff = float(baseline["soak_cutoff_epoch"])
    if not math.isfinite(started) or not math.isfinite(cutoff) or started > now + 1:
        raise RuntimeError("invalid baseline time")
    if abs(cutoff - (started + EXPECTED_DURATION_SECONDS)) > 0.001:
        raise RuntimeError("invalid baseline cutoff")
    if not RUN_ID.fullmatch(str(baseline["run_id"])):
        raise RuntimeError("invalid baseline run")
    if not all(HEX_64.fullmatch(str(baseline[name])) for name in (
        "expected_binary_sha256", "expected_config_sha256", "expected_verifier_sha256"
    )):
        raise RuntimeError("invalid baseline hash")
    if int(baseline["initial_log_inode"]) < 0 or int(baseline["initial_log_offset"]) < 0:
        raise RuntimeError("invalid baseline cursor")
    allowance = baseline["startup_allowance"]
    if not isinstance(allowance, dict) or any(
        not SEAT_BUCKET.fullmatch(str(key)) or not isinstance(value, int) or value < 0
        for key, value in allowance.items()
    ):
        raise RuntimeError("invalid startup allowance")


def new_state(baseline: dict[str, Any]) -> dict[str, Any]:
    baseline_sha = object_hash(baseline)
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": baseline["run_id"],
        "baseline": baseline,
        "baseline_sha256": baseline_sha,
        "cursor": {"inode": baseline["initial_log_inode"], "offset": baseline["initial_log_offset"]},
        "lifecycle": {
            "selected": {}, "terminal": {}, "startup_terminal": {}, "outcomes": {},
            "startup_allowance": dict(baseline["startup_allowance"]),
            "request_seats": {}, "manual_toggles": 0, "reused_seat_attempts": 0,
            "cutoff": None,
        },
        "slo": {
            "terminal_requests": {}, "model_attempts": {}, "deterministic_latencies_ms": [],
            "selection_counts": {},
            "pressure_skew_violation_seconds": 0.0, "pressure_skew_last_sample_epoch": None,
        },
        "samples": [],
        "terminal": None,
    }


def validate_sample(sample: dict[str, Any], state: dict[str, Any], index: int, previous_hash: str) -> str:
    required = {
        "schema_version", "run_id", "baseline_sha256", "sample_seq", "sampled_at_epoch",
        "previous_sample_sha256", "verifier_sha256", "binary_sha256", "config_sha256",
        "healthy", "failures", "checks", "observations", "sample_sha256",
    }
    if set(sample) != required or sample.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError("invalid evidence schema")
    if sample.get("run_id") != state["run_id"] or sample.get("baseline_sha256") != state["baseline_sha256"]:
        raise RuntimeError("invalid evidence binding")
    if sample.get("sample_seq") != index + 1 or sample.get("previous_sample_sha256") != previous_hash:
        raise RuntimeError("invalid evidence chain")
    if not math.isfinite(float(sample.get("sampled_at_epoch", math.nan))):
        raise RuntimeError("invalid evidence time")
    if not all(HEX_64.fullmatch(str(sample.get(name, ""))) for name in (
        "verifier_sha256", "binary_sha256", "config_sha256"
    )):
        raise RuntimeError("invalid evidence identity")
    failures = sample.get("failures")
    checks = sample.get("checks")
    if not isinstance(failures, list) or len(failures) != len(set(failures)) or any(x not in FAILURE_NAMES for x in failures):
        raise RuntimeError("invalid evidence failures")
    if not isinstance(checks, dict) or any(key not in CHECK_NAMES or not isinstance(value, bool) for key, value in checks.items()):
        raise RuntimeError("invalid evidence checks")
    incidents = [x for x in failures if x in INCIDENT_NAMES]
    if incidents:
        if len(incidents) != 1 or checks or len(failures) != 1:
            raise RuntimeError("invalid incident evidence")
    elif set(checks) != CHECK_NAMES:
        raise RuntimeError("incomplete evidence checks")
    expected_failures = sorted([key for key, value in checks.items() if not value] + incidents)
    if sorted(failures) != expected_failures or sample.get("healthy") is not (not failures):
        raise RuntimeError("invalid evidence health")
    if not isinstance(sample.get("observations"), dict):
        raise RuntimeError("invalid evidence observations")
    unsigned = dict(sample)
    actual_hash = str(unsigned.pop("sample_sha256", ""))
    if not HEX_64.fullmatch(actual_hash) or object_hash(unsigned) != actual_hash:
        raise RuntimeError("invalid evidence hash")
    return actual_hash


def validate_state(state: dict[str, Any], now: float) -> None:
    required = {"schema_version", "run_id", "baseline", "baseline_sha256", "cursor", "lifecycle", "slo", "samples", "terminal"}
    if set(state) != required or state.get("schema_version") != SCHEMA_VERSION:
        raise RuntimeError("invalid authoritative state")
    baseline = state.get("baseline")
    if not isinstance(baseline, dict):
        raise RuntimeError("invalid baseline")
    validate_baseline(baseline, now)
    if state.get("run_id") != baseline["run_id"] or state.get("baseline_sha256") != object_hash(baseline):
        raise RuntimeError("invalid baseline binding")
    cursor = state.get("cursor")
    if not isinstance(cursor, dict) or set(cursor) != {"inode", "offset"} or int(cursor["inode"]) < 0 or int(cursor["offset"]) < 0:
        raise RuntimeError("invalid cursor")
    lifecycle = state.get("lifecycle")
    if not isinstance(lifecycle, dict) or not isinstance(state.get("samples"), list):
        raise RuntimeError("invalid state payload")
    validate_lifecycle(lifecycle, baseline)
    validate_slo_state(state["slo"])
    previous = "0" * 64
    last_time = None
    for index, sample in enumerate(state["samples"]):
        if not isinstance(sample, dict):
            raise RuntimeError("invalid evidence row")
        previous = validate_sample(sample, state, index, previous)
        sampled = float(sample["sampled_at_epoch"])
        if sampled < float(baseline["started_at_epoch"]) or sampled > now + 1:
            raise RuntimeError("evidence time outside run")
        if last_time is not None and sampled <= last_time:
            raise RuntimeError("nonmonotonic evidence")
        last_time = sampled
    terminal = state.get("terminal")
    if terminal is not None:
        required_terminal = {
            "schema_version", "run_id", "baseline_sha256", "state", "accepted",
            "finalized_at_epoch", "sample_count", "last_sample_sha256", "aggregate", "lifecycle", "slo",
        }
        if not isinstance(terminal, dict) or set(terminal) != required_terminal:
            raise RuntimeError("invalid terminal schema")
        if terminal.get("schema_version") != SCHEMA_VERSION or terminal.get("run_id") != state["run_id"] or terminal.get("baseline_sha256") != state["baseline_sha256"]:
            raise RuntimeError("invalid terminal binding")
        if terminal.get("state") not in {"accepted", "rejected"} or terminal.get("accepted") is not (terminal.get("state") == "accepted"):
            raise RuntimeError("invalid terminal state")
        if terminal.get("sample_count") != len(state["samples"]):
            raise RuntimeError("invalid terminal sample count")
        expected_last = state["samples"][-1]["sample_sha256"] if state["samples"] else None
        if terminal.get("last_sample_sha256") != expected_last:
            raise RuntimeError("invalid terminal evidence anchor")
        if (
            terminal.get("aggregate") != evidence_aggregate(state)
            or terminal.get("lifecycle") != lifecycle_summary(lifecycle)
            or terminal.get("slo") != slo_summary(state["slo"])
        ):
            raise RuntimeError("invalid terminal summary")
        finalized = float(terminal.get("finalized_at_epoch", math.nan))
        if not math.isfinite(finalized) or finalized > now + 1:
            raise RuntimeError("invalid terminal time")
        if state["samples"] and finalized < float(state["samples"][-1]["sampled_at_epoch"]):
            raise RuntimeError("invalid terminal time")
        candidate = copy.deepcopy(state)
        candidate["terminal"] = None
        if terminal_decision(candidate, finalized) != terminal:
            raise RuntimeError("invalid terminal decision")


def validate_count_map(value: Any, key_pattern: re.Pattern[str], name: str) -> None:
    if not isinstance(value, dict) or any(
        not key_pattern.fullmatch(str(key)) or not isinstance(count, int) or isinstance(count, bool) or count < 0
        for key, count in value.items()
    ):
        raise RuntimeError("invalid lifecycle " + name)


def validate_lifecycle(lifecycle: dict[str, Any], baseline: dict[str, Any]) -> None:
    required = {
        "selected", "terminal", "startup_terminal", "outcomes", "startup_allowance",
        "request_seats", "manual_toggles", "reused_seat_attempts", "cutoff",
    }
    if set(lifecycle) != required:
        raise RuntimeError("invalid lifecycle fields")
    validate_count_map(lifecycle["selected"], EVENT_ID, "selected")
    validate_count_map(lifecycle["terminal"], EVENT_ID, "terminal")
    validate_count_map(lifecycle["startup_terminal"], EVENT_ID, "startup terminal")
    validate_count_map(lifecycle["startup_allowance"], SEAT_BUCKET, "startup allowance")
    if any(
        int(count) > int(lifecycle["terminal"].get(key, 0))
        for key, count in lifecycle["startup_terminal"].items()
    ):
        raise RuntimeError("invalid lifecycle startup terminal")
    initial_allowance = baseline["startup_allowance"]
    if any(
        int(count) > int(initial_allowance.get(key, -1))
        for key, count in lifecycle["startup_allowance"].items()
    ) or set(lifecycle["startup_allowance"]) != set(initial_allowance):
        raise RuntimeError("invalid lifecycle startup allowance")
    outcomes = lifecycle["outcomes"]
    if not isinstance(outcomes, dict) or any(
        key not in ATTEMPT_OUTCOMES or not isinstance(count, int) or isinstance(count, bool) or count < 0
        for key, count in outcomes.items()
    ):
        raise RuntimeError("invalid lifecycle outcomes")
    seats = lifecycle["request_seats"]
    if not isinstance(seats, dict) or any(
        not REQUEST_BUCKET.fullmatch(str(request))
        or not isinstance(values, list)
        or values != sorted(set(values))
        or any(not SEAT_BUCKET.fullmatch(str(seat)) for seat in values)
        for request, values in seats.items()
    ):
        raise RuntimeError("invalid lifecycle seats")
    for name in ("manual_toggles", "reused_seat_attempts"):
        if not isinstance(lifecycle[name], int) or isinstance(lifecycle[name], bool) or lifecycle[name] < 0:
            raise RuntimeError("invalid lifecycle counter")
    cutoff = lifecycle["cutoff"]
    if cutoff is None:
        return
    if not isinstance(cutoff, dict) or set(cutoff) != {
        "frozen_at_epoch", "grace_deadline_epoch", "quiescence_started_at_epoch", "frozen"
    }:
        raise RuntimeError("invalid lifecycle cutoff")
    frozen_at = float(cutoff["frozen_at_epoch"])
    deadline = float(cutoff["grace_deadline_epoch"])
    quiescence = cutoff["quiescence_started_at_epoch"]
    if (
        not math.isfinite(frozen_at) or not math.isfinite(deadline)
        or frozen_at < float(baseline["soak_cutoff_epoch"])
        or abs(deadline - (float(baseline["soak_cutoff_epoch"]) + TERMINAL_GRACE_SECONDS)) > 0.001
        or frozen_at > deadline
    ):
        raise RuntimeError("invalid lifecycle cutoff time")
    if quiescence is not None and (
        not math.isfinite(float(quiescence)) or float(quiescence) < frozen_at or float(quiescence) > deadline
    ):
        raise RuntimeError("invalid lifecycle quiescence")
    validate_count_map(cutoff["frozen"], EVENT_ID, "frozen")
    if any(int(count) <= 0 for count in cutoff["frozen"].values()):
        raise RuntimeError("invalid lifecycle frozen count")
    if cutoff["frozen"] and quiescence is not None:
        raise RuntimeError("invalid lifecycle frozen quiescence")


def validate_slo_state(slo: Any) -> None:
    if not isinstance(slo, dict) or set(slo) != {
        "terminal_requests", "model_attempts", "deterministic_latencies_ms",
        "selection_counts", "pressure_skew_violation_seconds", "pressure_skew_last_sample_epoch",
    }:
        raise RuntimeError("invalid slo state")
    terminal_requests = slo["terminal_requests"]
    if not isinstance(terminal_requests, dict) or any(
        not REQUEST_BUCKET.fullmatch(str(key)) or value not in ATTEMPT_OUTCOMES
        for key, value in terminal_requests.items()
    ):
        raise RuntimeError("invalid slo requests")
    attempts = slo["model_attempts"]
    if not isinstance(attempts, dict) or any(
        not REQUEST_BUCKET.fullmatch(str(key))
        or not isinstance(value, dict)
        or any(not NONNEGATIVE_INTEGER.fullmatch(str(attempt)) or outcome not in ATTEMPT_OUTCOMES for attempt, outcome in value.items())
        for key, value in attempts.items()
    ):
        raise RuntimeError("invalid slo attempts")
    latencies = slo["deterministic_latencies_ms"]
    if not isinstance(latencies, list) or any(not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > 3_600_000 for value in latencies):
        raise RuntimeError("invalid slo latencies")
    selection_counts = slo["selection_counts"]
    if not isinstance(selection_counts, dict) or any(
        not SAFE_ROUTE_VALUE.fullmatch(str(group))
        or not isinstance(seats, dict)
        or any(not SEAT_BUCKET.fullmatch(str(seat)) or not isinstance(count, int) or count < 0 for seat, count in seats.items())
        for group, seats in selection_counts.items()
    ):
        raise RuntimeError("invalid slo selection counts")
    violation = slo["pressure_skew_violation_seconds"]
    last = slo["pressure_skew_last_sample_epoch"]
    if not isinstance(violation, (int, float)) or isinstance(violation, bool) or not math.isfinite(float(violation)) or violation < 0:
        raise RuntimeError("invalid slo pressure duration")
    if last is not None and (not isinstance(last, (int, float)) or isinstance(last, bool) or not math.isfinite(float(last))):
        raise RuntimeError("invalid slo pressure time")


def apply_events(lifecycle: dict[str, Any], events: list[dict[str, str]], now: float, baseline: dict[str, Any]) -> dict[str, Any]:
    selected = Counter({key: int(value) for key, value in lifecycle["selected"].items()})
    terminal = Counter({key: int(value) for key, value in lifecycle["terminal"].items()})
    startup_terminal = Counter({key: int(value) for key, value in lifecycle["startup_terminal"].items()})
    allowance = Counter({key: int(value) for key, value in lifecycle["startup_allowance"].items()})
    outcomes = Counter({key: int(value) for key, value in lifecycle["outcomes"].items()})
    request_seats = {key: set(value) for key, value in lifecycle["request_seats"].items()}
    reused = int(lifecycle["reused_seat_attempts"])
    cutoff = copy.deepcopy(lifecycle["cutoff"])
    frozen = Counter((cutoff or {}).get("frozen", {}))

    selections = [event for event in events if event["routing_stage"] == "account_selection"]
    terminals = [event for event in events if event["routing_stage"] == "account_attempt"]
    for event in selections:
        key = event_key(event)
        selected[key] += 1
        request = event["routing_request_bucket"]
        seat = event["routing_seat_bucket"]
        seats = request_seats.setdefault(request, set())
        if seat in seats:
            reused += 1
        seats.add(seat)
    for event in terminals:
        key = event_key(event)
        adjusted = terminal[key] - startup_terminal[key]
        if (
            selected[key] <= adjusted
            and now <= float(baseline["started_at_epoch"]) + STARTUP_BOUNDARY_GRACE_SECONDS
            and allowance[event["routing_seat_bucket"]] > 0
        ):
            startup_terminal[key] += 1
            allowance[event["routing_seat_bucket"]] -= 1
        terminal[key] += 1
        outcomes[event["routing_outcome"]] += 1
        if cutoff is not None and frozen[key] > 0:
            frozen[key] -= 1
            if frozen[key] <= 0:
                del frozen[key]

    adjusted_terminal = terminal - startup_terminal
    outstanding = selected - adjusted_terminal
    if cutoff is None and now >= float(baseline["soak_cutoff_epoch"]):
        frozen = Counter(outstanding)
        cutoff = {
            "frozen_at_epoch": now,
            "grace_deadline_epoch": float(baseline["soak_cutoff_epoch"]) + TERMINAL_GRACE_SECONDS,
            "quiescence_started_at_epoch": now if not frozen else None,
            "frozen": dict(frozen),
        }
    elif cutoff is not None:
        cutoff["frozen"] = {key: value for key, value in frozen.items() if value > 0}
        if not frozen and cutoff["quiescence_started_at_epoch"] is None:
            cutoff["quiescence_started_at_epoch"] = now

    lifecycle.update({
        "selected": dict(selected), "terminal": dict(terminal), "startup_terminal": dict(startup_terminal),
        "startup_allowance": dict(allowance), "outcomes": dict(outcomes),
        "request_seats": {key: sorted(value) for key, value in request_seats.items()},
        "reused_seat_attempts": reused, "cutoff": cutoff,
    })
    return lifecycle_summary(lifecycle)


def apply_slo_events(slo: dict[str, Any], events: list[dict[str, str]], pressure: dict[str, Any], now: float) -> None:
    terminal_requests = dict(slo["terminal_requests"])
    attempts = {key: dict(value) for key, value in slo["model_attempts"].items()}
    latencies = list(slo["deterministic_latencies_ms"])
    selection_counts = {group: dict(seats) for group, seats in slo["selection_counts"].items()}
    for item in events:
        stage = item["routing_stage"]
        request = item["routing_request_bucket"]
        outcome = item["routing_outcome"]
        terminal_outcome = "success" if outcome == "committed" else outcome
        if stage in {"model_attempt", "stream_attempt", "count_attempt"} and terminal_outcome in ATTEMPT_OUTCOMES:
            request_attempts = attempts.setdefault(request, {})
            request_attempts[item["routing_attempt"]] = terminal_outcome
            terminal_requests[request] = terminal_outcome
        elif stage == "model_decision":
            latencies.append(int(item["routing_duration_ms"]))
        elif stage == "account_selection":
            group = item["routing_provider"] + ":" + item["routing_model"]
            seats = selection_counts.setdefault(group, {})
            seat = item["routing_seat_bucket"]
            seats[seat] = int(seats.get(seat, 0)) + 1
    rows = pressure.get("seats", [])
    pressure_values = sorted(int(row.get("concurrency_pressure_milli", 0)) for row in rows)
    skewed = False
    if len(pressure_values) >= 2:
        midpoint = len(pressure_values) // 2
        median = pressure_values[midpoint] if len(pressure_values) % 2 else (
            pressure_values[midpoint - 1] + pressure_values[midpoint]
        ) / 2
        skewed = median > 0 and max(pressure_values) * 1000 > median * PRESSURE_SKEW_RATIO_MILLI
    last = slo["pressure_skew_last_sample_epoch"]
    if skewed and last is not None:
        slo["pressure_skew_violation_seconds"] += max(0.0, min(now - float(last), MAX_SAMPLE_GAP_SECONDS))
    slo["pressure_skew_last_sample_epoch"] = now
    slo["terminal_requests"] = terminal_requests
    slo["model_attempts"] = attempts
    slo["deterministic_latencies_ms"] = latencies
    slo["selection_counts"] = selection_counts


def percentile95(values: list[int]) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * 0.95) - 1)]


def slo_summary(slo: dict[str, Any]) -> dict[str, Any]:
    requests = slo["terminal_requests"]
    eligible = [outcome for outcome in requests.values() if outcome not in {"canceled", "rejected"}]
    terminal_successes = sum(outcome == "success" for outcome in eligible)
    first_attempt_eligible = 0
    first_attempt_successes = 0
    for attempts in slo["model_attempts"].values():
        outcome = attempts.get("0")
        if outcome is None or outcome in {"canceled", "rejected"}:
            continue
        first_attempt_eligible += 1
        first_attempt_successes += outcome == "success"
    latencies = slo["deterministic_latencies_ms"]
    p95 = percentile95(latencies)
    comparable_groups = []
    fairness_ok = True
    for group, seats in slo["selection_counts"].items():
        counts = sorted(int(value) for value in seats.values() if int(value) > 0)
        if len(counts) < 2:
            continue
        midpoint = len(counts) // 2
        median = counts[midpoint] if len(counts) % 2 else (counts[midpoint - 1] + counts[midpoint]) / 2
        ratio_milli = int(max(counts) * 1000 / median) if median else 2**31 - 1
        comparable_groups.append({"group": group, "seats": len(counts), "selections": sum(counts), "max_median_ratio_milli": ratio_milli})
        fairness_ok = fairness_ok and ratio_milli <= PRESSURE_SKEW_RATIO_MILLI
    checks = {
        "minimum_eligible_requests": len(eligible) >= MIN_ELIGIBLE_REQUESTS,
        "terminal_success_rate": len(eligible) > 0 and terminal_successes * 1000 >= len(eligible) * TERMINAL_SUCCESS_PERMILLE,
        "first_attempt_acceptance": first_attempt_eligible > 0 and first_attempt_successes * 100 >= first_attempt_eligible * FIRST_ATTEMPT_SUCCESS_PERCENT,
        "minimum_deterministic_decisions": len(latencies) >= MIN_DETERMINISTIC_DECISIONS,
        "routing_overhead_p95": p95 is not None and p95 <= ROUTING_P95_LIMIT_MS,
        "pressure_skew_duration": float(slo["pressure_skew_violation_seconds"]) <= PRESSURE_SKEW_MAX_SECONDS,
        "comparable_seat_coverage": bool(comparable_groups),
        "selection_balance": bool(comparable_groups) and fairness_ok,
    }
    return {
        "checks": checks,
        "sufficient_evidence": all(checks.values()),
        "eligible_requests": len(eligible),
        "terminal_successes": terminal_successes,
        "first_attempt_eligible": first_attempt_eligible,
        "first_attempt_successes": first_attempt_successes,
        "deterministic_decisions": len(latencies),
        "routing_overhead_p95_ms": p95,
        "pressure_skew_violation_seconds": round(float(slo["pressure_skew_violation_seconds"]), 3),
        "selection_balance_groups": comparable_groups,
        "thresholds": {
            "minimum_eligible_requests": MIN_ELIGIBLE_REQUESTS,
            "minimum_deterministic_decisions": MIN_DETERMINISTIC_DECISIONS,
            "terminal_success_permille": TERMINAL_SUCCESS_PERMILLE,
            "first_attempt_success_percent": FIRST_ATTEMPT_SUCCESS_PERCENT,
            "routing_p95_limit_ms": ROUTING_P95_LIMIT_MS,
            "pressure_skew_max_seconds": PRESSURE_SKEW_MAX_SECONDS,
        },
    }


def lifecycle_summary(lifecycle: dict[str, Any]) -> dict[str, Any]:
    selected = Counter(lifecycle["selected"])
    terminal = Counter(lifecycle["terminal"])
    startup = Counter(lifecycle["startup_terminal"])
    adjusted = terminal - startup
    cutoff = lifecycle["cutoff"]
    return {
        "selected": sum(selected.values()),
        "terminal": sum(terminal.values()),
        "duplicate_selected": sum(value - 1 for value in selected.values() if value > 1),
        "duplicate_terminal": sum(value - 1 for value in terminal.values() if value > 1),
        "unmatched_selected": sum((selected - adjusted).values()),
        "unmatched_terminal": sum((adjusted - selected).values()),
        "reused_seat_attempts": int(lifecycle["reused_seat_attempts"]),
        "startup_terminal_allowance_used": sum(startup.values()),
        "frozen_remaining": sum(int(value) for value in (cutoff or {}).get("frozen", {}).values()),
        "cutoff": copy.deepcopy(cutoff),
        "terminal_outcomes": dict(lifecycle["outcomes"]),
    }


def make_sample(
    state: dict[str, Any], now: float, verifier_hash: str, binary_hash: str, config_hash: str,
    checks: dict[str, bool], observations: dict[str, Any], incidents: list[str] | None = None,
) -> dict[str, Any]:
    failures = sorted([key for key, value in checks.items() if not value] + list(incidents or []))
    previous = state["samples"][-1]["sample_sha256"] if state["samples"] else "0" * 64
    sample = {
        "schema_version": SCHEMA_VERSION,
        "run_id": state["run_id"],
        "baseline_sha256": state["baseline_sha256"],
        "sample_seq": len(state["samples"]) + 1,
        "sampled_at_epoch": now,
        "previous_sample_sha256": previous,
        "verifier_sha256": verifier_hash,
        "binary_sha256": binary_hash,
        "config_sha256": config_hash,
        "healthy": not failures,
        "failures": failures,
        "checks": checks,
        "observations": observations,
    }
    sample["sample_sha256"] = object_hash(sample)
    return sample


def evidence_aggregate(state: dict[str, Any]) -> dict[str, Any]:
    rows = state["samples"]
    baseline = state["baseline"]
    times = [float(row["sampled_at_epoch"]) for row in rows]
    gaps = [times[0] - float(baseline["started_at_epoch"])] if times else [float("inf")]
    gaps.extend(right - left for left, right in zip(times, times[1:]))
    unhealthy = [row for row in rows if not row["healthy"]]
    counts = Counter(failure for row in rows for failure in row["failures"])
    return {
        "samples": len(rows),
        "healthy_samples": len(rows) - len(unhealthy),
        "unhealthy_samples": len(unhealthy),
        "window_healthy": not unhealthy,
        "continuity_healthy": max(gaps) <= MAX_SAMPLE_GAP_SECONDS,
        "max_gap_seconds": round(max(gaps), 3),
        "first_sampled_at_epoch": times[0] if times else None,
        "last_sampled_at_epoch": times[-1] if times else None,
        "first_failure_at_epoch": unhealthy[0]["sampled_at_epoch"] if unhealthy else None,
        "last_failure_at_epoch": unhealthy[-1]["sampled_at_epoch"] if unhealthy else None,
        "failure_counts": dict(counts),
        "last_sample_sha256": rows[-1]["sample_sha256"] if rows else None,
    }


def terminal_decision(state: dict[str, Any], now: float) -> dict[str, Any] | None:
    baseline = state["baseline"]
    if now < float(baseline["soak_cutoff_epoch"]):
        return None
    aggregate = evidence_aggregate(state)
    summary = lifecycle_summary(state["lifecycle"])
    slo = slo_summary(state["slo"])
    cutoff = summary["cutoff"]
    if cutoff is None:
        return None
    deadline = float(cutoff["grace_deadline_epoch"])
    quiescence = cutoff["quiescence_started_at_epoch"]
    quiescence_samples = [
        sample for sample in state["samples"]
        if quiescence is not None and float(sample["sampled_at_epoch"]) >= float(quiescence)
    ]
    pressure_quiet = bool(
        quiescence is not None
        and quiescence_samples
        and float(quiescence_samples[0]["sampled_at_epoch"]) <= float(quiescence) + MAX_SAMPLE_GAP_SECONDS
        and float(quiescence_samples[-1]["sampled_at_epoch"]) >= float(quiescence) + EXPECTED_INTERVAL_SECONDS
        and all(
            sample["observations"].get("pressure") == {"active_leases": 0, "active_seats": 0}
            for sample in quiescence_samples
        )
    )
    closed_in_time = (
        summary["frozen_remaining"] == 0
        and quiescence is not None
        and float(quiescence) + EXPECTED_INTERVAL_SECONDS <= deadline
        and now >= float(quiescence) + EXPECTED_INTERVAL_SECONDS
        and now <= deadline
        and pressure_quiet
    )
    accepted = bool(
        closed_in_time and aggregate["window_healthy"] and aggregate["continuity_healthy"]
        and slo["sufficient_evidence"]
    )
    if not accepted and now < deadline and aggregate["window_healthy"] and aggregate["continuity_healthy"]:
        return None
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": state["run_id"],
        "baseline_sha256": state["baseline_sha256"],
        "state": "accepted" if accepted else "rejected",
        "accepted": accepted,
        "finalized_at_epoch": now,
        "sample_count": aggregate["samples"],
        "last_sample_sha256": aggregate["last_sample_sha256"],
        "aggregate": aggregate,
        "lifecycle": summary,
        "slo": slo,
    }


def status_document(state: dict[str, Any]) -> dict[str, Any]:
    aggregate = evidence_aggregate(state)
    summary = lifecycle_summary(state["lifecycle"])
    terminal = state["terminal"]
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": state["run_id"],
        "baseline_sha256": state["baseline_sha256"],
        "terminal_state": terminal["state"] if terminal else (
            "draining" if summary["cutoff"] is not None else "running"
        ),
        "accepted": bool(terminal and terminal["accepted"]),
        "terminal_pending": terminal is None and summary["cutoff"] is not None,
        "aggregate": aggregate,
        "lifecycle": summary,
        "slo": slo_summary(state["slo"]),
        "latest_sample": state["samples"][-1] if state["samples"] else None,
    }


def evidence_bytes(state: dict[str, Any]) -> bytes:
    return b"".join(canonical_json(row) for row in state["samples"])


def export_artifacts(directory: Path, state: dict[str, Any]) -> None:
    atomic_write(directory / "evidence.jsonl", evidence_bytes(state))
    atomic_write(directory / "status.json", canonical_json(status_document(state)))
    if state["terminal"] is not None:
        write_final_once(directory / "final.json", canonical_json(state["terminal"]))


def artifact_integrity_ok(directory: Path, state: dict[str, Any]) -> bool:
    evidence_path = directory / "evidence.jsonl"
    status_path = directory / "status.json"
    final_path = directory / "final.json"
    if final_path.exists() or final_path.is_symlink():
        if state["terminal"] is None:
            return False
        try:
            if secure_read(final_path) != canonical_json(state["terminal"]):
                return False
        except (OSError, RuntimeError):
            return False
    if not state["samples"]:
        return not evidence_path.exists() and not status_path.exists()
    if not evidence_path.exists() or evidence_path.is_symlink():
        return False
    try:
        if secure_read(evidence_path) != evidence_bytes(state):
            return False
        if status_path.exists() or status_path.is_symlink():
            return secure_read(status_path) == canonical_json(status_document(state))
        return False
    except (OSError, RuntimeError):
        return False


def preflight_terminal(directory: Path, terminal: dict[str, Any]) -> None:
    final_path = directory / "final.json"
    if final_path.exists() or final_path.is_symlink():
        if secure_read(final_path) != canonical_json(terminal):
            raise RuntimeError("final artifact mismatch")


def snapshot(args: argparse.Namespace, state: dict[str, Any], now: float, verifier_hash: str, binary_hash: str, config_hash: str) -> tuple[dict[str, Any], dict[str, bool], dict[str, Any]]:
    events, next_cursor, telemetry = read_events(args.log, state["cursor"])
    management = load_env(args.management_env)["MANAGEMENT_PASSWORD"]
    reconciler = load_env(args.reconciler_env)["CLIPROXY_RECONCILER_API_KEY"]
    pressure = api_json("/v0/management/routing-pressure", management)
    reconcile = api_json("/v0/management/auth-files/reconcile-status", reconciler)["credentials"]
    pressure_rows = pressure.get("seats", [])
    pressure_consistent = (
        pressure.get("schema_version") == 1
        and pressure.get("selector") == "least_pressure"
        and pressure.get("active_seats") == len(pressure_rows)
        and pressure.get("active_leases") == sum(int(row.get("in_flight", 0)) for row in pressure_rows)
        and all(
            SEAT_BUCKET.fullmatch(str(row.get("seat_bucket", "")))
            and int(row.get("in_flight", -1)) > 0
            and int(row.get("capacity", -1)) > 0
            and int(row.get("concurrency_pressure_milli", -1)) >= 0
            for row in pressure_rows
        )
    )
    reconcile_schema = isinstance(reconcile, list) and all(valid_reconcile_row(row) for row in reconcile)
    safe_reconcile = reconcile if reconcile_schema else []
    states = Counter(str(row["state"]) for row in safe_reconcile)
    generation_mismatches = sum(row["generation"] != row["runtime_generation"] for row in safe_reconcile)
    ready_mismatches = sum(
        row.get("state") == "ready" and (
            row.get("disabled") is True or row.get("durable_disabled") is True
            or row.get("unavailable") is True or row.get("credential_status") != "active"
        ) for row in safe_reconcile
    )
    summary = apply_events(state["lifecycle"], events, now, state["baseline"])
    apply_slo_events(state["slo"], events, pressure, now)
    state["lifecycle"]["manual_toggles"] += telemetry["manual_toggles"]
    state["cursor"] = next_cursor
    reconciler_result = command("systemctl", "show", "cliproxy-account-reconciler.service", "-p", "Result", "--value")
    reconciler_status = int(command(
        "systemctl", "show", "cliproxy-account-reconciler.service", "-p", "ExecMainStatus", "--value"
    ) or "0")
    reconciler_result_observation = reconciler_result if reconciler_result in RECONCILER_RESULTS else "unknown"
    strategy, auto_mode = routing_modes(args.config.read_text(encoding="utf-8", errors="replace"))
    checks = {
        "binary_hash": binary_hash == state["baseline"]["expected_binary_sha256"],
        "config_hash": config_hash == state["baseline"]["expected_config_sha256"],
        "verifier_hash": verifier_hash == state["baseline"]["expected_verifier_sha256"],
        "auto_active": auto_mode == "active",
        "least_pressure": strategy == "least-pressure",
        "crsproxy_active": command("systemctl", "is-active", "crsproxy.service") == "active",
        "nginx_active": command("systemctl", "is-active", "nginx") == "active",
        "reconciler_timer_active": command("systemctl", "is-active", "cliproxy-account-reconciler.timer") == "active",
        "reconciler_timer_enabled": command("systemctl", "is-enabled", "cliproxy-account-reconciler.timer") == "enabled",
        "reconciler_controller_completed": (reconciler_result, reconciler_status) in {("success", 0), ("exit-code", 1)},
        "inventory_complete": len(reconcile) == 19,
        "reconcile_schema": reconcile_schema,
        "routable_capacity": states.get("ready", 0) > 0,
        "generation_converged": generation_mismatches == 0,
        "ready_admission_converged": ready_mismatches == 0,
        "pressure_consistent": pressure_consistent,
        "pressure_protected": unauthenticated_status("/v0/management/routing-pressure") == 401,
        "telemetry_schema": telemetry["invalid"] == 0,
        "telemetry_privacy": telemetry["sensitive"] == 0,
        "no_duplicate_events": summary["duplicate_selected"] == 0 and summary["duplicate_terminal"] == 0,
        "no_reused_seat_attempts": summary["reused_seat_attempts"] == 0,
        "no_orphan_terminal_events": summary["unmatched_terminal"] == 0,
        "no_manual_toggles": state["lifecycle"]["manual_toggles"] == 0,
        "log_continuity": telemetry["discontinuity"] == 0,
    }
    observations = {
        "inventory": {"total": len(reconcile), "states": dict(states), "generation_mismatches": generation_mismatches, "ready_mismatches": ready_mismatches},
        "pressure": {"active_leases": pressure.get("active_leases"), "active_seats": pressure.get("active_seats")},
        "events": summary,
        "reconciler": {"result": reconciler_result_observation, "exec_main_status": reconciler_status},
        "manual_toggles": state["lifecycle"]["manual_toggles"],
    }
    return state, checks, observations


def valid_reconcile_row(row: Any) -> bool:
    required = {
        "state", "generation", "runtime_generation", "credential_status",
        "disabled", "durable_disabled", "unavailable",
    }
    if not isinstance(row, dict) or not required.issubset(row):
        return False
    if row["state"] not in INVENTORY_STATES:
        return False
    if not all(
        isinstance(row[name], str) and bool(row[name]) and SAFE_ROUTE_VALUE.fullmatch(row[name])
        for name in ("generation", "runtime_generation", "credential_status")
    ):
        return False
    return all(isinstance(row[name], bool) for name in ("disabled", "durable_disabled", "unavailable"))


def initialise_state(args: argparse.Namespace, now: float, verifier_hash: str, binary_hash: str, config_hash: str) -> dict[str, Any]:
    log_metadata = args.log.stat()
    management = load_env(args.management_env)["MANAGEMENT_PASSWORD"]
    pressure = api_json("/v0/management/routing-pressure", management)
    baseline = new_baseline(now, binary_hash, config_hash, verifier_hash, log_metadata, pressure.get("seats", []))
    return new_state(baseline)


def append_incident(state: dict[str, Any], now: float, verifier_hash: str, binary_hash: str, config_hash: str, incident: str) -> None:
    last = float(state["samples"][-1]["sampled_at_epoch"]) if state["samples"] else float(state["baseline"]["started_at_epoch"])
    sampled_at = max(now, last + 0.000001)
    state["samples"].append(make_sample(
        state, sampled_at, verifier_hash, binary_hash, config_hash, {}, {"incident": incident}, [incident]
    ))


def execute_locked(args: argparse.Namespace, now: float) -> int:
    state_path = args.state_directory / "state.json"
    verifier_hash = sha256(Path(__file__).resolve())
    binary_hash = sha256(args.binary)
    config_hash = sha256(args.config)
    if state_path.exists():
        state = secure_read_json(state_path)
        validate_state(state, now)
    else:
        state = initialise_state(args, now, verifier_hash, binary_hash, config_hash)
        atomic_write(state_path, canonical_json(state))
    if state["terminal"] is not None:
        export_artifacts(args.state_directory, state)
        return 0 if state["terminal"]["accepted"] else 1

    working = copy.deepcopy(state)
    artifact_bad = not artifact_integrity_ok(args.state_directory, state)
    try:
        working, checks, observations = snapshot(args, working, now, verifier_hash, binary_hash, config_hash)
        if artifact_bad:
            append_incident(working, now, verifier_hash, binary_hash, config_hash, "artifact_integrity")
        else:
            working["samples"].append(make_sample(
                working, now, verifier_hash, binary_hash, config_hash, checks, observations
            ))
    except Exception:
        working = copy.deepcopy(state)
        append_incident(working, now, verifier_hash, binary_hash, config_hash, "verifier_execution")
    working["terminal"] = terminal_decision(working, now)
    validate_state(working, now)
    if working["terminal"] is not None:
        preflight_terminal(args.state_directory, working["terminal"])
    atomic_write(state_path, canonical_json(working))
    export_artifacts(args.state_directory, working)
    latest = working["samples"][-1]
    return 0 if latest["healthy"] and evidence_aggregate(working)["continuity_healthy"] else 1


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-directory", type=Path, default=Path("/var/lib/cliproxy-smart-router-soak"))
    parser.add_argument("--log", type=Path, default=Path("/opt/crsproxy/logs/main.log"))
    parser.add_argument("--binary", type=Path, default=Path("/opt/crsproxy/cli-proxy-api"))
    parser.add_argument("--config", type=Path, default=Path("/opt/crsproxy/config.yaml"))
    parser.add_argument("--management-env", type=Path, default=Path("/etc/crsproxy/management-general.env"))
    parser.add_argument("--reconciler-env", type=Path, default=Path("/etc/crsproxy/account-reconciler.env"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None, *, now: float | None = None) -> int:
    args = parse_args(argv)
    secure_directory(args.state_directory)
    lock = open_lock(args.state_directory)
    try:
        return execute_locked(args, time.time() if now is None else now)
    finally:
        os.close(lock)


if __name__ == "__main__":
    sys.exit(main())

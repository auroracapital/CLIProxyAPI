#!/usr/bin/env python3
"""Hub-only, privacy-safe desired-account reconciliation controller."""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as dt
import fcntl
import hashlib
import hmac
import json
import logging
import os
import random
import re
import shutil
import stat
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Iterator


ALLOWED_STATES = {
    "ready",
    "cooling",
    "refreshing",
    "probing",
    "auth_required",
    "misconfigured",
}
ALLOWED_CREDENTIAL_STATUSES = {
    "unknown",
    "active",
    "pending",
    "refreshing",
    "error",
    "disabled",
}
ALLOWED_REASONS = {
    "none",
    "attempt_budget_exhausted",
    "candidate_invalid",
    "candidate_promoted",
    "inventory_invalid",
    "locked",
    "not_due",
    "probe_auth_required",
    "probe_rejected",
    "probe_retryable",
    "refresh_failed",
    "refresh_succeeded",
    "rollback_completed",
    "rollback_failed",
}
SAFE_OUTCOMES = {
    "succeeded",
    "failed",
    "auth_required",
    "cooling",
    "retryable",
    "rejected",
    "admission_rejected",
    "skipped",
}
UTC = dt.timezone.utc


class ReconcileError(Exception):
    """A deliberately detail-free controller failure."""


class InventoryError(ReconcileError):
    pass


class APIError(ReconcileError):
    def __init__(self, status: int = 0, outcome: str = "", generation: str = ""):
        super().__init__("API request failed")
        self.status = status
        self.outcome = outcome if outcome in SAFE_OUTCOMES else ""
        self.generation = generation if re.fullmatch(r"[0-9a-f]{64}", generation) else ""


class CommittedTransition(APIError):
    """Durable lifecycle state committed but runtime publication is pending."""

    def __init__(self, status: int, generation: str):
        super().__init__(status, generation=generation)


class PromotionError(ReconcileError):
    pass


@dataclasses.dataclass(frozen=True)
class Seat:
    auth_index: str
    provider: str
    model: str
    canonical_path: Path | None = None
    candidate_path: Path | None = None
    required_keys: tuple[str, ...] = ()
    expected_fields: tuple[tuple[str, str], ...] = ()


@dataclasses.dataclass(frozen=True)
class Inventory:
    seats: tuple[Seat, ...]
    max_attempts_per_day: int = 6
    base_backoff_seconds: int = 300
    max_backoff_seconds: int = 21600
    probe_payload: dict[str, Any] = dataclasses.field(
        default_factory=lambda: {"messages": [{"role": "user", "content": "Reply OK."}]}
    )


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        data = {
            "event": getattr(record, "event", "controller"),
            "level": record.levelname.lower(),
        }
        for key in ("seat_key", "state", "outcome", "reason"):
            value = getattr(record, key, None)
            if value:
                data[key] = value
        return json.dumps(data, sort_keys=True, separators=(",", ":"))


def configure_logging(stream: Any = None) -> logging.Logger:
    logger = logging.getLogger("cliproxy-account-reconciler")
    logger.handlers.clear()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger


def log_event(logger: logging.Logger, event: str, **fields: str) -> None:
    safe = {"event": event}
    for key in ("seat_key", "state", "outcome", "reason"):
        value = fields.get(key, "")
        if value:
            safe[key] = value
    logger.info(event, extra=safe)


def _strict_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InventoryError(f"{label} must be an object")
    return value


def load_inventory(path: Path) -> Inventory:
    try:
        raw = _strict_object(json.loads(path.read_text(encoding="utf-8")), "inventory")
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InventoryError("inventory cannot be read") from exc
    allowed = {
        "version",
        "seats",
        "max_attempts_per_day",
        "base_backoff_seconds",
        "max_backoff_seconds",
        "probe_payload",
    }
    if set(raw) - allowed or raw.get("version") != 1:
        raise InventoryError("inventory version or fields are invalid")
    rows = raw.get("seats")
    if not isinstance(rows, list) or not rows:
        raise InventoryError("inventory seats must be a non-empty array")
    seats: list[Seat] = []
    seen_indexes: set[str] = set()
    seen_candidates: set[Path] = set()
    seen_canonicals: set[Path] = set()
    for row in rows:
        item = _strict_object(row, "seat")
        if set(item) - {
            "auth_index",
            "provider",
            "model",
            "canonical_path",
            "candidate_path",
            "required_keys",
            "expected_fields",
        }:
            raise InventoryError("seat contains unknown fields")
        auth_index = item.get("auth_index")
        provider = item.get("provider")
        model = item.get("model")
        if not all(isinstance(x, str) and x.strip() for x in (auth_index, provider, model)):
            raise InventoryError("seat target is incomplete")
        auth_index = auth_index.strip()
        provider = provider.strip().lower()
        model = model.strip()
        if auth_index in seen_indexes:
            raise InventoryError("duplicate auth index")
        seen_indexes.add(auth_index)
        canonical_raw = item.get("canonical_path")
        candidate_raw = item.get("candidate_path")
        if (canonical_raw is None) != (candidate_raw is None):
            raise InventoryError("candidate and canonical paths must be paired")
        canonical = Path(canonical_raw) if isinstance(canonical_raw, str) else None
        candidate = Path(candidate_raw) if isinstance(candidate_raw, str) else None
        if canonical is not None:
            if not canonical.is_absolute() or not candidate or not candidate.is_absolute():
                raise InventoryError("credential paths must be absolute")
            # Normalize dot segments without resolving the final component so a
            # staged symlink remains visible to lstat and is rejected later.
            canonical = Path(os.path.abspath(canonical))
            candidate = Path(os.path.abspath(candidate))
            if canonical == candidate or canonical in seen_canonicals or candidate in seen_candidates:
                raise InventoryError("ambiguous credential paths")
            if canonical in seen_candidates or candidate in seen_canonicals:
                raise InventoryError("overlapping credential paths")
            seen_canonicals.add(canonical)
            seen_candidates.add(candidate)
        required = item.get("required_keys", [])
        if not isinstance(required, list) or not all(isinstance(k, str) and k for k in required):
            raise InventoryError("required_keys must be strings")
        if len(set(required)) != len(required):
            raise InventoryError("required_keys contains duplicates")
        expected_raw = item.get("expected_fields", {})
        if not isinstance(expected_raw, dict) or not all(
            isinstance(key, str) and key and isinstance(value, str) and value
            for key, value in expected_raw.items()
        ):
            raise InventoryError("expected_fields must contain non-empty strings")
        if canonical is not None and not expected_raw:
            raise InventoryError("staged seats require expected identity fields")
        forbidden_expected = {
            "access_token",
            "refresh_token",
            "token",
            "disabled",
            "reconcile_state",
            "reconcile_reason",
            "reconcile_next_attempt",
        }
        if forbidden_expected.intersection(expected_raw):
            raise InventoryError("expected_fields contains mutable or secret fields")
        expected = tuple(sorted(expected_raw.items()))
        seats.append(Seat(auth_index, provider, model, canonical, candidate, tuple(required), expected))
    max_attempts = raw.get("max_attempts_per_day", 6)
    base_backoff = raw.get("base_backoff_seconds", 300)
    max_backoff = raw.get("max_backoff_seconds", 21600)
    if not isinstance(max_attempts, int) or not 1 <= max_attempts <= 100:
        raise InventoryError("max attempts is invalid")
    if not isinstance(base_backoff, int) or not isinstance(max_backoff, int):
        raise InventoryError("backoff is invalid")
    if not 1 <= base_backoff <= max_backoff <= 86400:
        raise InventoryError("backoff bounds are invalid")
    probe_payload = raw.get("probe_payload", {"messages": [{"role": "user", "content": "Reply OK."}]})
    if not isinstance(probe_payload, dict) or not probe_payload:
        raise InventoryError("probe payload must be a non-empty object")
    return Inventory(tuple(seats), max_attempts, base_backoff, max_backoff, probe_payload)


def validate_complete_inventory(inventory: Inventory, remote: list[dict[str, Any]]) -> None:
    indexed: dict[str, str] = {}
    for item in remote:
        if not isinstance(item, dict):
            raise InventoryError("remote inventory is malformed")
        index = item.get("auth_index")
        provider = item.get("provider")
        if not isinstance(index, str) or not index or not isinstance(provider, str) or not provider:
            raise InventoryError("remote inventory is incomplete")
        if item.get("state") not in ALLOWED_STATES:
            raise InventoryError("remote lifecycle state is invalid")
        if item.get("credential_status") not in ALLOWED_CREDENTIAL_STATUSES:
            raise InventoryError("remote credential status is invalid")
        if not isinstance(item.get("disabled"), bool) or not isinstance(item.get("unavailable"), bool):
            raise InventoryError("remote availability flags are invalid")
        for field in ("generation", "runtime_generation"):
            if not isinstance(item.get(field), str) or not re.fullmatch(r"[0-9a-f]{64}", item[field]):
                raise InventoryError("remote credential generation is invalid")
        if not isinstance(item.get("durable_disabled"), bool):
            raise InventoryError("remote durable admission flag is invalid")
        if index in indexed:
            raise InventoryError("remote inventory is ambiguous")
        indexed[index] = provider.strip().lower()
    desired = {seat.auth_index: seat.provider for seat in inventory.seats}
    if desired != indexed:
        raise InventoryError("desired and runtime inventories differ")


def opaque_key(secret: bytes, namespace: str, value: str) -> str:
    return hmac.new(secret, f"{namespace}\0{value}".encode(), hashlib.sha256).hexdigest()[:32]


def load_hmac_key(env_name: str = "CLIPROXY_RECONCILER_HMAC_KEY") -> bytes:
    value = os.environ.get(env_name, "").encode()
    if len(value) < 32:
        raise ReconcileError("HMAC key is missing or too short")
    return value


@contextlib.contextmanager
def file_lock(path: Path, blocking: bool = False) -> Iterator[bool]:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    acquired = False
    try:
        flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
        try:
            fcntl.flock(fd, flags)
            acquired = True
        except BlockingIOError:
            pass
        yield acquired
    finally:
        if acquired:
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def backoff_seconds(attempt: int, base: int, maximum: int, rng: random.Random) -> int:
    cap = min(maximum, base * (2 ** max(0, attempt - 1)))
    return max(1, int(rng.uniform(cap * 0.5, cap)))


def _atomic_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(data, out, sort_keys=True, separators=(",", ":"))
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp_name, path)
        dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp_name)


class StateStore:
    def __init__(self, directory: Path, now: Any = None):
        self.directory = directory
        self.now = now or (lambda: dt.datetime.now(UTC))

    def path(self, seat_key: str) -> Path:
        return self.directory / "seats" / f"{seat_key}.json"

    def read(self, seat_key: str) -> dict[str, Any]:
        today = self.now().date().isoformat()
        default = {
            "seat_key": seat_key,
            "state": "ready",
            "reason": "none",
            "outcome": "skipped",
            "attempt_day": today,
            "attempts": 0,
            "next_attempt": "",
        }
        try:
            value = json.loads(self.path(seat_key).read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            return default
        if not isinstance(value, dict) or value.get("seat_key") != seat_key:
            return default
        if value.get("attempt_day") != today:
            value["attempt_day"] = today
            value["attempts"] = 0
        return {**default, **{key: value.get(key, default[key]) for key in default}}

    def write(self, seat_key: str, state: str, reason: str, outcome: str, attempts: int, next_attempt: str) -> None:
        if state not in ALLOWED_STATES or reason not in ALLOWED_REASONS or outcome not in SAFE_OUTCOMES:
            raise ReconcileError("refusing unsafe state value")
        _atomic_json(
            self.path(seat_key),
            {
                "attempt_day": self.now().date().isoformat(),
                "attempts": int(attempts),
                "next_attempt": next_attempt,
                "outcome": outcome,
                "reason": reason,
                "seat_key": seat_key,
                "state": state,
                "updated_at": self.now().replace(microsecond=0).isoformat(),
            },
        )


class APIAdapter:
    def __init__(self, base_url: str, api_key: str = "", timeout: float = 20.0):
        if base_url not in {"http://127.0.0.1:8319", "http://[::1]:8319"}:
            raise ReconcileError("API endpoint must be the pinned loopback service")
        self.base_url = base_url
        self.api_key = api_key
        self.timeout = timeout

    def _request(self, method: str, endpoint: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = urllib.request.Request(self.base_url + endpoint, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                if response.status != 200:
                    raise APIError(response.status)
                value = json.load(response)
        except urllib.error.HTTPError as exc:
            # Extract only the documented categorical outcome. Never retain or
            # expose the response body itself.
            outcome = ""
            generation = ""
            try:
                value = json.load(exc)
                if isinstance(value, dict) and value.get("outcome") in SAFE_OUTCOMES:
                    outcome = value["outcome"]
                if isinstance(value, dict) and value.get("outcome") == "committed":
                    candidate_generation = value.get("generation")
                    if isinstance(candidate_generation, str) and re.fullmatch(r"[0-9a-f]{64}", candidate_generation):
                        generation = candidate_generation
            except (OSError, UnicodeError, json.JSONDecodeError):
                pass
            if generation:
                raise CommittedTransition(exc.code, generation) from None
            raise APIError(exc.code, outcome) from None
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
            raise APIError() from None
        if not isinstance(value, dict):
            raise APIError()
        return value

    def status(self) -> list[dict[str, Any]]:
        value = self._request("GET", "/v0/management/auth-files/reconcile-status")
        rows = value.get("credentials")
        if not isinstance(rows, list):
            raise APIError()
        return rows

    def set_state(
        self,
        auth_index: str,
        state: str,
        reason: str = "",
        next_attempt: str = "",
        generation: str = "",
        disabled: bool | None = None,
    ) -> dict[str, Any]:
        if not re.fullmatch(r"[0-9a-f]{64}", generation):
            raise APIError()
        payload: dict[str, Any] = {
            "auth_index": auth_index,
            "state": state,
            "reason": reason,
            "generation": generation,
        }
        if next_attempt:
            payload["next_attempt"] = next_attempt
        if disabled is not None:
            payload["disabled"] = disabled
        return self._request("POST", "/v0/management/auth-files/reconcile-state", payload)

    def refresh(self, auth_index: str) -> tuple[str, str, bool]:
        try:
            value = self._request("POST", "/v0/management/auth-files/refresh", {"auth_index": auth_index})
        except APIError as exc:
            if exc.outcome:
                return exc.outcome, "", False
            raise
        outcome = value.get("outcome") if value.get("outcome") in SAFE_OUTCOMES else "failed"
        generation = value.get("generation") if isinstance(value.get("generation"), str) else ""
        disabled = value.get("disabled") if isinstance(value.get("disabled"), bool) else False
        if outcome == "succeeded" and not re.fullmatch(r"[0-9a-f]{64}", generation):
            raise APIError()
        return outcome, generation, disabled

    def probe(self, seat: Seat, payload: dict[str, Any]) -> str:
        try:
            value = self._request(
                "POST",
                "/v0/management/auth-files/probe",
                {"auth_index": seat.auth_index, "model": seat.model, "payload": payload, "admit": False},
            )
        except APIError as exc:
            if exc.outcome:
                return exc.outcome
            raise
        return value.get("outcome") if value.get("outcome") in SAFE_OUTCOMES else "failed"


def read_candidate_snapshot(seat: Seat) -> tuple[dict[str, Any], str]:
    if seat.candidate_path is None or seat.canonical_path is None:
        raise PromotionError("candidate is not configured")
    try:
        parent_info = seat.canonical_path.parent.stat()
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(seat.candidate_path, flags)
    except OSError as exc:
        raise PromotionError("candidate is unavailable") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise PromotionError("candidate must be a regular file")
        if stat.S_IMODE(info.st_mode) != 0o600 or info.st_dev != parent_info.st_dev:
            raise PromotionError("candidate permissions or filesystem are invalid")
        with os.fdopen(fd, "rb", closefd=False) as incoming:
            raw = incoming.read()
    except OSError as exc:
        raise PromotionError("candidate cannot be read") from exc
    finally:
        os.close(fd)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PromotionError("candidate JSON is invalid") from exc
    if not isinstance(value, dict) or value.get("disabled") is True:
        raise PromotionError("candidate content is invalid")
    provider = value.get("provider", value.get("type"))
    if not isinstance(provider, str) or provider.strip().lower() != seat.provider:
        raise PromotionError("candidate provider does not match")
    if any(key not in value or value[key] in (None, "") for key in seat.required_keys):
        raise PromotionError("candidate is missing required fields")
    if any(str(value.get(key, "")) != expected for key, expected in seat.expected_fields):
        raise PromotionError("candidate identity does not match")
    return value, hashlib.sha256(raw).hexdigest()


def validate_candidate(seat: Seat) -> dict[str, Any]:
    value, _ = read_candidate_snapshot(seat)
    return value


def validate_canonical(seat: Seat) -> dict[str, Any]:
    """Read and validate a declared canonical credential without mutating it."""
    if seat.canonical_path is None:
        raise PromotionError("canonical is not configured")
    try:
        info = seat.canonical_path.lstat()
    except OSError as exc:
        raise PromotionError("canonical is unavailable") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise PromotionError("canonical must be a regular file")
    try:
        value = json.loads(seat.canonical_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PromotionError("canonical JSON is invalid") from exc
    if not isinstance(value, dict):
        raise PromotionError("canonical content is invalid")
    if "disabled" in value and not isinstance(value["disabled"], bool):
        raise PromotionError("canonical disabled flag is invalid")
    provider = value.get("provider", value.get("type"))
    if not isinstance(provider, str) or provider.strip().lower() != seat.provider:
        raise PromotionError("canonical provider does not match")
    if any(key not in value or value[key] in (None, "") for key in seat.required_keys):
        raise PromotionError("canonical is missing required fields")
    if any(str(value.get(key, "")) != expected for key, expected in seat.expected_fields):
        raise PromotionError("canonical identity does not match")
    return value


def _copy_fsync(source: Path, destination: Path, exclusive: bool = False) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_CLOEXEC | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(destination, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with source.open("rb") as incoming, os.fdopen(fd, "wb", closefd=False) as outgoing:
            shutil.copyfileobj(incoming, outgoing)
            outgoing.flush()
            os.fsync(outgoing.fileno())
    finally:
        os.close(fd)


def raw_file_generation(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise PromotionError("credential generation is unavailable") from exc


def file_generation(path: Path, hmac_key: bytes) -> str:
    digest = raw_file_generation(path)
    return hmac.new(
        hmac_key,
        b"reconcile-generation\0" + digest.encode(),
        hashlib.sha256,
    ).hexdigest()


@contextlib.contextmanager
def credential_file_lock(path: Path) -> Iterator[None]:
    lock_path = Path(str(path) + ".reconcile.lock")
    parent = lock_path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_info = parent.lstat()
    if not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode) or stat.S_IMODE(parent_info.st_mode) & 0o022:
        raise PromotionError("credential lock directory is unsafe")
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(lock_path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise PromotionError("credential lock is unsafe")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def archived_disabled(archive: Path | None) -> bool:
    if archive is None:
        return False
    try:
        value = json.loads(archive.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PromotionError("rollback archive is invalid") from exc
    if not isinstance(value, dict):
        raise PromotionError("rollback archive is invalid")
    disabled = value.get("disabled", False)
    if not isinstance(disabled, bool):
        raise PromotionError("rollback admission state is invalid")
    return disabled


def copy_atomic(source: Path, destination: Path) -> None:
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".reconcile-copy-", dir=destination.parent)
    os.close(fd)
    temp = Path(temp_name)
    try:
        _copy_fsync(source, temp)
        os.replace(temp, destination)
        directory_fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temp.unlink()


def promote_candidate(
    seat: Seat,
    archive_dir: Path,
    seat_key: str,
    now: dt.datetime,
    candidate: dict[str, Any] | None = None,
) -> Path | None:
    if candidate is None:
        candidate = validate_candidate(seat)
    assert seat.candidate_path is not None and seat.canonical_path is not None
    seat.canonical_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_info = seat.canonical_path.parent.stat()
    if not stat.S_ISDIR(parent_info.st_mode) or stat.S_IMODE(parent_info.st_mode) & 0o022:
        raise PromotionError("canonical directory permissions are unsafe")
    if seat.canonical_path.exists() and seat.canonical_path.stat().st_dev != seat.candidate_path.stat().st_dev:
        raise PromotionError("canonical and candidate filesystems differ")
    archive_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    archive: Path | None = None
    if seat.canonical_path.exists():
        canonical_info = seat.canonical_path.lstat()
        if not stat.S_ISREG(canonical_info.st_mode) or stat.S_ISLNK(canonical_info.st_mode):
            raise PromotionError("canonical must be a regular file")
        repair_canonical_access(seat.canonical_path)
        archive = archive_dir / f"{seat_key}-{now.strftime('%Y%m%dT%H%M%S%fZ')}.rollback"
        _copy_fsync(seat.canonical_path, archive, exclusive=True)
    fd, temp_name = tempfile.mkstemp(prefix=".candidate-", dir=seat.canonical_path.parent)
    os.close(fd)
    temp = Path(temp_name)
    replaced = False
    try:
        candidate["disabled"] = False
        candidate["reconcile_state"] = "probing"
        candidate.pop("reconcile_reason", None)
        candidate.pop("reconcile_next_attempt", None)
        with temp.open("w", encoding="utf-8") as outgoing:
            json.dump(candidate, outgoing, sort_keys=True, separators=(",", ":"))
            outgoing.write("\n")
            outgoing.flush()
            os.fsync(outgoing.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, seat.canonical_path)
        replaced = True
        repair_canonical_access(seat.canonical_path)
        directory_fd = os.open(seat.canonical_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except (OSError, PromotionError) as exc:
        if replaced:
            with contextlib.suppress(OSError, PromotionError):
                revert_promotion(seat, archive)
        raise PromotionError("candidate promotion failed") from exc
    finally:
        with contextlib.suppress(FileNotFoundError):
            temp.unlink()
    return archive


def normalize_canonical(seat: Seat, archive_dir: Path, seat_key: str, now: dt.datetime) -> Path:
    """Atomically make an existing desired credential probeable.

    The original bytes are archived first so watcher, refresh, probe, or
    admission failures can restore the exact pre-normalization credential.
    """
    canonical = validate_canonical(seat)
    assert seat.canonical_path is not None
    parent_info = seat.canonical_path.parent.stat()
    if not stat.S_ISDIR(parent_info.st_mode) or stat.S_IMODE(parent_info.st_mode) & 0o022:
        raise PromotionError("canonical directory permissions are unsafe")
    archive_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    archive = archive_dir / f"{seat_key}-{now.strftime('%Y%m%dT%H%M%S%fZ')}.rollback"
    _copy_fsync(seat.canonical_path, archive, exclusive=True)

    fd, temp_name = tempfile.mkstemp(prefix=".canonical-normalize-", dir=seat.canonical_path.parent)
    temp = Path(temp_name)
    replaced = False
    try:
        canonical["disabled"] = False
        canonical["reconcile_state"] = "probing"
        canonical.pop("reconcile_reason", None)
        canonical.pop("reconcile_next_attempt", None)
        os.fchmod(fd, 0o600)
        outgoing = os.fdopen(fd, "w", encoding="utf-8")
        fd = -1
        with outgoing:
            json.dump(canonical, outgoing, sort_keys=True, separators=(",", ":"))
            outgoing.write("\n")
            outgoing.flush()
            os.fsync(outgoing.fileno())
        os.replace(temp, seat.canonical_path)
        replaced = True
        repair_canonical_access(seat.canonical_path)
        directory_fd = os.open(seat.canonical_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except (OSError, PromotionError) as exc:
        if replaced:
            with contextlib.suppress(OSError, PromotionError):
                rollback(seat, archive)
        raise PromotionError("canonical normalization failed") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            temp.unlink()
    return archive


def rollback(seat: Seat, archive: Path | None) -> None:
    if archive is None or seat.canonical_path is None:
        raise PromotionError("rollback archive is unavailable")
    if stat.S_IMODE(archive.stat().st_mode) != 0o600:
        raise PromotionError("rollback archive permissions are invalid")
    fd, temp_name = tempfile.mkstemp(prefix=".rollback-", dir=seat.canonical_path.parent)
    os.close(fd)
    temp = Path(temp_name)
    try:
        _copy_fsync(archive, temp)
        os.replace(temp, seat.canonical_path)
        repair_canonical_access(seat.canonical_path)
        directory_fd = os.open(seat.canonical_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            temp.unlink()


def revert_promotion(seat: Seat, archive: Path | None) -> None:
    if archive is not None:
        rollback(seat, archive)
        return
    if seat.canonical_path is None:
        raise PromotionError("canonical path is unavailable")
    seat.canonical_path.unlink(missing_ok=True)
    directory_fd = os.open(seat.canonical_path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def repair_canonical_access(path: Path) -> bool:
    """Ensure canonical credentials stay private and owned by the service user."""
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise PromotionError("canonical must be a regular file")
    service_uid = os.geteuid()
    service_gid = os.getegid()
    if stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == service_uid and info.st_gid == service_gid:
        return False
    fd, temp_name = tempfile.mkstemp(prefix=".access-repair-", dir=path.parent)
    os.close(fd)
    temp = Path(temp_name)
    try:
        _copy_fsync(path, temp)
        os.replace(temp, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise PromotionError("canonical access repair failed") from exc
    finally:
        with contextlib.suppress(FileNotFoundError):
            temp.unlink()
    repaired = path.stat()
    if stat.S_IMODE(repaired.st_mode) != 0o600 or repaired.st_uid != service_uid or repaired.st_gid != service_gid:
        raise PromotionError("canonical access repair did not persist")
    return True


class Controller:
    def __init__(
        self,
        inventory: Inventory,
        api: APIAdapter,
        state_dir: Path,
        runtime_dir: Path,
        hmac_key: bytes,
        apply: bool = False,
        logger: logging.Logger | None = None,
        now: Any = None,
        rng: random.Random | None = None,
        max_seats: int = 0,
        only_healthy: bool = False,
        force_probe: bool = False,
        provider: str = "",
        seat_key: str = "",
    ):
        self.inventory = inventory
        self.api = api
        self.state_dir = state_dir
        self.runtime_dir = runtime_dir
        self.hmac_key = hmac_key
        self.apply = apply
        self.logger = logger or configure_logging()
        self.now = now or (lambda: dt.datetime.now(UTC))
        self.rng = rng or random.SystemRandom()
        self.store = StateStore(state_dir, self.now)
        self.max_seats = max_seats
        self.only_healthy = only_healthy
        self.force_probe = force_probe
        self.provider = provider.strip().lower()
        self.seat_key = seat_key.strip().lower()

    def run(self) -> int:
        with file_lock(self.runtime_dir / "locks" / "global.lock") as global_acquired:
            if not global_acquired:
                log_event(self.logger, "controller_skipped", reason="locked")
                return 0
            remote = self.api.status()
            validate_complete_inventory(self.inventory, remote)
            by_index = {row["auth_index"]: row for row in remote}
            seats = list(self.inventory.seats)
            if self.seat_key:
                seats = [
                    seat
                    for seat in seats
                    if opaque_key(self.hmac_key, "seat", seat.auth_index) == self.seat_key
                ]
            if self.provider:
                seats = [seat for seat in seats if seat.provider == self.provider]
            if self.only_healthy:
                seats = [seat for seat in seats if self._remote_credential_is_healthy(by_index[seat.auth_index])]
            if self.max_seats > 0:
                seats = seats[: self.max_seats]
            if not seats:
                raise InventoryError("canary selection is empty")
            failures = 0
            for seat in seats:
                if not self._reconcile_locked(seat, by_index[seat.auth_index]):
                    failures += 1
            return 1 if failures else 0

    def _reconcile_locked(self, seat: Seat, remote: dict[str, Any]) -> bool:
        seat_key = opaque_key(self.hmac_key, "seat", seat.auth_index)
        provider_key = opaque_key(self.hmac_key, "provider", seat.provider)
        with file_lock(self.runtime_dir / "locks" / f"provider-{provider_key}.lock") as provider_acquired:
            if not provider_acquired:
                log_event(self.logger, "seat_skipped", seat_key=seat_key, reason="locked")
                return True
            with file_lock(self.runtime_dir / "locks" / f"seat-{seat_key}.lock") as seat_acquired:
                if not seat_acquired:
                    log_event(self.logger, "seat_skipped", seat_key=seat_key, reason="locked")
                    return True
                return self._reconcile(seat, remote, seat_key)

    def _reconcile(self, seat: Seat, remote: dict[str, Any], seat_key: str) -> bool:
        persisted = self.store.read(seat_key)
        state = remote.get("state") if remote.get("state") in ALLOWED_STATES else "misconfigured"
        candidate_exists = bool(seat.candidate_path and seat.candidate_path.exists())
        if not self.apply:
            log_event(self.logger, "seat_dry_run", seat_key=seat_key, state=state, outcome="skipped")
            return True

        canonical_exists = bool(seat.canonical_path and seat.canonical_path.exists())
        canonical_needs_normalization = False
        if seat.canonical_path is not None and not candidate_exists:
            if not canonical_exists:
                return self._fail(
                    seat,
                    seat_key,
                    int(persisted.get("attempts", 0)),
                    "candidate_invalid",
                    "misconfigured",
                    "failed",
                )
            try:
                canonical = validate_canonical(seat)
                info = seat.canonical_path.lstat()
                canonical_needs_normalization = (
                    canonical.get("disabled") is True
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != os.geteuid()
                    or info.st_gid != os.getegid()
                    or state != "ready"
                    or not self._remote_credential_is_healthy(remote)
                    or self.force_probe
                )
            except (OSError, PromotionError):
                return self._fail(seat, seat_key, int(persisted.get("attempts", 0)), "candidate_invalid", "misconfigured", "failed")
        if state == "ready" and not candidate_exists and not canonical_needs_normalization:
            self._record(seat_key, "ready", "none", "skipped", persisted["attempts"], "")
            return True
        if state == "misconfigured" and not candidate_exists and seat.canonical_path is None:
            self._record(seat_key, state, "none", "skipped", persisted["attempts"], "")
            return False
        if state == "auth_required" and not candidate_exists and seat.canonical_path is None:
            self._record(seat_key, state, "none", "skipped", persisted["attempts"], "")
            return True
        next_attempt = _parse_time(persisted.get("next_attempt", ""))
        if next_attempt and self.now() < next_attempt and not candidate_exists:
            log_event(self.logger, "seat_skipped", seat_key=seat_key, state=state, reason="not_due")
            return True
        attempts = int(persisted.get("attempts", 0))
        if attempts >= self.inventory.max_attempts_per_day:
            try:
                self._transition(
                    seat.auth_index,
                    remote["generation"],
                    "auth_required",
                    "attempt_budget_exhausted",
                    disabled=remote["durable_disabled"],
                )
            except (APIError, PromotionError):
                return self._record_local_failure(
                    seat_key,
                    attempts,
                    "attempt_budget_exhausted",
                    "auth_required",
                    "failed",
                )
            self._record(seat_key, "auth_required", "attempt_budget_exhausted", "skipped", attempts, "")
            return True
        attempts += 1
        archive: Path | None = None
        promoted = False
        promoted_raw_generation = ""
        candidate_raw_generation = ""
        canonical_raw_generation = ""
        refresh_succeeded = False
        generation = remote["generation"]
        durable_disabled = remote["durable_disabled"]
        if candidate_exists:
            try:
                assert seat.canonical_path is not None
                assert seat.candidate_path is not None
                with credential_file_lock(seat.canonical_path), credential_file_lock(seat.candidate_path):
                    candidate, candidate_raw_generation = read_candidate_snapshot(seat)
                    archive = promote_candidate(
                        seat,
                        self.state_dir / "rollback",
                        seat_key,
                        self.now(),
                        candidate,
                    )
                    promoted_raw_generation = raw_file_generation(seat.canonical_path)
                    generation = file_generation(seat.canonical_path, self.api.api_key.encode())
                promoted = True
                self._wait_for_generation(seat.auth_index, generation, False)
                durable_disabled = False
            except (PromotionError, APIError):
                if promoted and self._restore_and_reload(seat, archive, promoted_raw_generation) is None:
                    return self._record_local_failure(
                        seat_key,
                        attempts,
                        "rollback_failed",
                        "misconfigured",
                        "failed",
                    )
                return self._fail(seat, seat_key, attempts, "candidate_invalid", "misconfigured", "failed")
        elif canonical_needs_normalization:
            try:
                assert seat.canonical_path is not None
                with credential_file_lock(seat.canonical_path):
                    archive = normalize_canonical(seat, self.state_dir / "rollback", seat_key, self.now())
                    promoted_raw_generation = raw_file_generation(seat.canonical_path)
                    generation = file_generation(seat.canonical_path, self.api.api_key.encode())
                promoted = True
                self._wait_for_generation(seat.auth_index, generation, False)
                durable_disabled = False
            except (PromotionError, APIError):
                if promoted and self._restore_and_reload(seat, archive, promoted_raw_generation) is None:
                    return self._record_local_failure(
                        seat_key,
                        attempts,
                        "rollback_failed",
                        "misconfigured",
                        "failed",
                    )
                return self._fail(seat, seat_key, attempts, "candidate_invalid", "misconfigured", "failed")
        try:
            generation = self._transition(
                seat.auth_index,
                generation,
                "refreshing",
                "candidate_promoted" if candidate_exists else "",
                disabled=False,
            )
            refresh_outcome, refreshed_generation, refreshed_disabled = self.api.refresh(seat.auth_index)
            if refresh_outcome != "succeeded":
                if promoted:
                    restored = self._restore_and_reload(seat, archive, promoted_raw_generation)
                    if restored is None:
                        return self._record_local_failure(seat_key, attempts, "rollback_failed", "misconfigured", "failed")
                    generation, durable_disabled = restored
                terminal = refresh_outcome == "auth_required" or attempts >= self.inventory.max_attempts_per_day
                return self._fail(
                    seat,
                    seat_key,
                    attempts,
                    "probe_auth_required" if terminal else "refresh_failed",
                    "auth_required" if terminal else "cooling",
                    refresh_outcome,
                    generation,
                    durable_disabled,
                )
            generation = refreshed_generation
            durable_disabled = refreshed_disabled
            refresh_succeeded = True
            if promoted and candidate_exists and seat.canonical_path is not None:
                with credential_file_lock(seat.canonical_path):
                    canonical_raw_generation = raw_file_generation(seat.canonical_path)
            generation = self._transition(
                seat.auth_index,
                generation,
                "probing",
                "refresh_succeeded",
                disabled=False,
            )
            durable_disabled = False
            if promoted and candidate_exists and seat.canonical_path is not None:
                with credential_file_lock(seat.canonical_path):
                    canonical_raw_generation = raw_file_generation(seat.canonical_path)
            probe_outcome = self.api.probe(seat, self.inventory.probe_payload)
            if probe_outcome == "succeeded":
                generation = self._transition(
                    seat.auth_index,
                    generation,
                    "ready",
                    "",
                    disabled=False,
                )
                self._record(seat_key, "ready", "none", "succeeded", attempts, "")
                if candidate_exists and seat.candidate_path:
                    with credential_file_lock(seat.candidate_path):
                        if seat.candidate_path.exists() and raw_file_generation(seat.candidate_path) == candidate_raw_generation:
                            seat.candidate_path.unlink()
                return True
            if promoted and candidate_exists:
                restored = self._restage_candidate_and_restore(
                    seat,
                    archive,
                    candidate_raw_generation,
                    canonical_raw_generation,
                )
                if restored is None:
                    return self._record_local_failure(seat_key, attempts, "rollback_failed", "misconfigured", "failed")
                generation, durable_disabled = restored
            elif promoted:
                # A successful refresh may rotate the refresh token. Keep that
                # newest credential generation, but restore the archived
                # admission flag while applying the failure lifecycle.
                durable_disabled = archived_disabled(archive)
            if probe_outcome == "auth_required":
                return self._fail(seat, seat_key, attempts, "probe_auth_required", "auth_required", probe_outcome, generation, durable_disabled)
            return self._fail(seat, seat_key, attempts, "probe_rejected" if probe_outcome == "rejected" else "probe_retryable", "cooling", probe_outcome, generation, durable_disabled)
        except (APIError, PromotionError):
            if promoted:
                if refresh_succeeded and candidate_exists:
                    restored = self._restage_candidate_and_restore(
                        seat,
                        archive,
                        candidate_raw_generation,
                        canonical_raw_generation,
                    )
                    if restored is None:
                        return self._record_local_failure(seat_key, attempts, "rollback_failed", "misconfigured", "failed")
                    generation, durable_disabled = restored
                elif refresh_succeeded:
                    durable_disabled = archived_disabled(archive)
                else:
                    restored = self._restore_and_reload(seat, archive, promoted_raw_generation)
                    if restored is None:
                        return self._record_local_failure(seat_key, attempts, "rollback_failed", "misconfigured", "failed")
                    generation, durable_disabled = restored
            return self._fail(seat, seat_key, attempts, "probe_retryable", "cooling", "retryable", generation, durable_disabled)

    def _restage_candidate_and_restore(
        self,
        seat: Seat,
        archive: Path | None,
        expected_candidate_generation: str,
        expected_canonical_generation: str,
    ) -> tuple[str, bool] | None:
        """Preserve a rotated candidate before restoring the prior canonical seat."""
        try:
            if seat.canonical_path is None or seat.candidate_path is None:
                return None
            with credential_file_lock(seat.canonical_path), credential_file_lock(seat.candidate_path):
                if not seat.canonical_path.exists():
                    return None
                if not seat.candidate_path.exists():
                    raise PromotionError("staged candidate disappeared")
                if raw_file_generation(seat.candidate_path) != expected_candidate_generation:
                    raise PromotionError("staged candidate generation changed")
                if raw_file_generation(seat.canonical_path) != expected_canonical_generation:
                    raise PromotionError("canonical generation changed before candidate restage")
                copy_atomic(seat.canonical_path, seat.candidate_path)
                expected_raw_generation = raw_file_generation(seat.canonical_path)
            return self._restore_and_reload(seat, archive, expected_raw_generation)
        except (OSError, PromotionError, APIError):
            return None

    @staticmethod
    def _remote_credential_is_healthy(remote: dict[str, Any]) -> bool:
        status = remote.get("credential_status")
        return (
            isinstance(status, str)
            and status.strip().lower() in {"active", "ready"}
            and remote.get("disabled") is False
            and remote.get("unavailable") is False
        )

    def _wait_for_generation(self, auth_index: str, generation: str, disabled: bool) -> None:
        """Wait for both runtime and disk to converge on an exact generation."""
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            rows = self.api.status()
            matches = [row for row in rows if row.get("auth_index") == auth_index]
            if len(matches) != 1:
                raise PromotionError("promoted credential identity changed")
            row = matches[0]
            if (
                row.get("generation") == generation
                and row.get("runtime_generation") == generation
                and row.get("durable_disabled") is disabled
                and row.get("disabled") is disabled
            ):
                return
            time.sleep(0.2)
        raise PromotionError("promoted credential was not reloaded")

    def _restore_and_reload(
        self,
        seat: Seat,
        archive: Path | None,
        expected_raw_generation: str,
    ) -> tuple[str, bool] | None:
        try:
            if seat.canonical_path is None:
                return None
            if archive is None:
                # A declared first-install seat must remain present so the next
                # complete-inventory validation can recover it. Keep the staged
                # credential durably disabled instead of deleting the runtime row.
                if not seat.canonical_path.exists():
                    return None
                generation = file_generation(seat.canonical_path, self.api.api_key.encode())
                generation = self._transition(
                    seat.auth_index,
                    generation,
                    "cooling",
                    "probe_retryable",
                    disabled=True,
                )
                return generation, True
            with credential_file_lock(seat.canonical_path):
                if seat.canonical_path.exists():
                    if not expected_raw_generation or raw_file_generation(seat.canonical_path) != expected_raw_generation:
                        raise PromotionError("rollback generation changed")
                elif expected_raw_generation:
                    raise PromotionError("rollback generation disappeared")
                revert_promotion(seat, archive)
            if seat.canonical_path is None or not seat.canonical_path.exists():
                return None
            generation = file_generation(seat.canonical_path, self.api.api_key.encode())
            disabled = archived_disabled(archive)
            self._wait_for_generation(seat.auth_index, generation, disabled)
            return generation, disabled
        except (OSError, PromotionError, APIError):
            return None

    def _transition(
        self,
        auth_index: str,
        generation: str,
        state: str,
        reason: str,
        next_attempt: str = "",
        disabled: bool | None = None,
    ) -> str:
        value: dict[str, Any] | None = None
        try:
            value = self.api.set_state(auth_index, state, reason, next_attempt, generation, disabled)
            new_generation = value.get("generation") if isinstance(value, dict) else ""
        except CommittedTransition as committed:
            new_generation = committed.generation
        except APIError as exc:
            # A transport failure may hide a successful durable commit. Recover
            # only from an exact authoritative lifecycle/admission convergence;
            # otherwise preserve the ambiguity and let generation fences stop
            # stale rollback or replay.
            if exc.status != 0:
                raise
            new_generation = self._discover_committed_transition(
                auth_index,
                generation,
                state,
                reason,
                next_attempt,
                disabled,
            )
            if not new_generation:
                raise
        if not re.fullmatch(r"[0-9a-f]{64}", new_generation):
            raise APIError()
        expected_disabled = disabled
        if expected_disabled is None:
            if value is None:
                raise APIError()
            actual = value.get("disabled")
            if not isinstance(actual, bool):
                raise APIError()
            expected_disabled = actual
        self._wait_for_generation(auth_index, new_generation, expected_disabled)
        return new_generation

    def _discover_committed_transition(
        self,
        auth_index: str,
        expected_generation: str,
        state: str,
        reason: str,
        next_attempt: str,
        disabled: bool | None,
    ) -> str:
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            try:
                rows = self.api.status()
            except APIError:
                time.sleep(0.2)
                continue
            matches = [row for row in rows if row.get("auth_index") == auth_index]
            if len(matches) != 1:
                return ""
            row = matches[0]
            generation = row.get("generation")
            if (
                isinstance(generation, str)
                and re.fullmatch(r"[0-9a-f]{64}", generation)
                and generation != expected_generation
                and row.get("runtime_generation") == generation
                and row.get("state") == state
                and row.get("reason", "") == reason
                and reconcile_times_equal(row.get("next_attempt", ""), next_attempt)
                and (
                    disabled is None
                    or (
                        row.get("durable_disabled") is disabled
                        and row.get("disabled") is disabled
                    )
                )
            ):
                return generation
            time.sleep(0.2)
        return ""
    def _fail(
        self,
        seat: Seat,
        seat_key: str,
        attempts: int,
        reason: str,
        state: str,
        outcome: str,
        generation: str = "",
        disabled: bool | None = None,
    ) -> bool:
        delay = backoff_seconds(attempts, self.inventory.base_backoff_seconds, self.inventory.max_backoff_seconds, self.rng)
        next_attempt = "" if state in {"auth_required", "misconfigured"} else (self.now() + dt.timedelta(seconds=delay)).replace(microsecond=0).isoformat()
        try:
            if not generation:
                rows = self.api.status()
                matches = [row for row in rows if row.get("auth_index") == seat.auth_index]
                if len(matches) != 1:
                    raise APIError()
                generation = matches[0].get("generation", "")
                disabled = matches[0].get("durable_disabled") if disabled is None else disabled
            self._transition(seat.auth_index, generation, state, reason, next_attempt, disabled)
        except (APIError, PromotionError):
            return self._record_local_failure(seat_key, attempts, reason, state, "failed", next_attempt)
        self._record(seat_key, state, reason, outcome if outcome in SAFE_OUTCOMES else "failed", attempts, next_attempt)
        return False

    def _record_local_failure(
        self,
        seat_key: str,
        attempts: int,
        reason: str,
        intended_state: str,
        outcome: str,
        next_attempt: str = "",
    ) -> bool:
        # The remote lifecycle did not commit. Preserve the last confirmed local
        # state and record only the failed outcome so a local file cannot falsely
        # claim that the scheduler transitioned the credential.
        previous = self.store.read(seat_key)
        state = previous.get("state") if previous.get("state") in ALLOWED_STATES else "misconfigured"
        self._record(seat_key, state, reason, outcome, attempts, next_attempt)
        log_event(
            self.logger,
            "remote_state_uncommitted",
            seat_key=seat_key,
            state=intended_state,
            outcome=outcome,
            reason=reason,
        )
        return False

    def _record(self, seat_key: str, state: str, reason: str, outcome: str, attempts: int, next_attempt: str) -> None:
        self.store.write(seat_key, state, reason, outcome, attempts, next_attempt)
        log_event(self.logger, "seat_reconciled", seat_key=seat_key, state=state, outcome=outcome, reason=reason)


def _parse_time(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def reconcile_times_equal(observed: Any, expected: str) -> bool:
    observed_time = _parse_time(observed if isinstance(observed, str) else "")
    expected_time = _parse_time(expected)
    if expected_time is None:
        return observed_time is None or observed_time.year == 1
    return observed_time == expected_time


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Reconcile the declared hub credential pool")
    parser.add_argument("--inventory", type=Path, default=Path("/etc/crsproxy/account-inventory.json"))
    parser.add_argument("--state-directory", type=Path, default=Path(os.environ.get("STATE_DIRECTORY", "/var/lib/cliproxy-account-reconciler")))
    parser.add_argument("--runtime-directory", type=Path, default=Path(os.environ.get("RUNTIME_DIRECTORY", "/run/cliproxy-account-reconciler")))
    parser.add_argument("--base-url", default="http://127.0.0.1:8319")
    parser.add_argument("--apply", action="store_true", help="perform mutations; the default is dry-run")
    parser.add_argument("--max-seats", type=int, default=0, help="after full validation, reconcile at most this many seats")
    parser.add_argument("--only-healthy", action="store_true", help="select canary seats from currently healthy runtime credentials")
    parser.add_argument("--force-probe", action="store_true", help="atomically normalize and exact-probe selected seats even when healthy")
    parser.add_argument("--provider", default="", help="after full validation, reconcile only this provider")
    parser.add_argument("--seat-key", default="", help="after full validation, reconcile only this opaque seat key")
    return parser.parse_args(argv)


def validate_seat_key_filter(value: str) -> str:
    seat_key = value.strip().lower()
    if seat_key and not re.fullmatch(r"[0-9a-f]{32}", seat_key):
        raise InventoryError("seat key filter is invalid")
    return seat_key


def main(argv: list[str] | None = None) -> int:
    logger = configure_logging()
    try:
        args = parse_args(argv)
        inventory = load_inventory(args.inventory)
        if args.max_seats < 0 or args.max_seats > len(inventory.seats):
            raise InventoryError("max seats is invalid")
        provider = args.provider.strip().lower()
        if provider and provider not in {seat.provider for seat in inventory.seats}:
            raise InventoryError("provider filter is invalid")
        seat_key = validate_seat_key_filter(args.seat_key)
        api = APIAdapter(args.base_url, os.environ.get("CLIPROXY_RECONCILER_API_KEY", ""))
        controller = Controller(
            inventory,
            api,
            args.state_directory,
            args.runtime_directory,
            load_hmac_key(),
            apply=args.apply,
            max_seats=args.max_seats,
            only_healthy=args.only_healthy,
            force_probe=args.force_probe,
            provider=provider,
            seat_key=seat_key,
            logger=logger,
        )
        return controller.run()
    except InventoryError:
        log_event(logger, "controller_failed", reason="inventory_invalid")
        return 2
    except ReconcileError:
        log_event(logger, "controller_failed", reason="probe_retryable")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Generate a complete protected CLIProxy account inventory on healify-hub."""

from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import pwd
import socket
import stat
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


BASE_URLS = {"http://127.0.0.1:8319", "http://[::1]:8319"}
PROBE_MODELS = {
    "antigravity": (
        "gemini-3.1-flash-lite",
        "gemini-2.5-flash-lite",
        "gemini-3-flash",
    ),
    "claude": (
        "claude-haiku-4-5-20251001",
        "claude-3-5-haiku-20241022",
    ),
    "codex": (
        "gpt-5.4-mini",
        "gpt-5.1-codex-mini",
    ),
    "gemini": (
        "gemini-3.1-flash-lite",
        "gemini-2.5-flash-lite",
        "gemini-3-flash",
    ),
    "gemini-cli": (
        "gemini-3.1-flash-lite",
        "gemini-2.5-flash-lite",
        "gemini-3-flash",
    ),
    "kimi": ("kimi-k2", "kimi-k2.5"),
    "xai": ("grok-3-mini-fast", "grok-3-mini"),
}
IDENTITY_FIELDS = {
    "antigravity": ("email", "project_id"),
    "claude": ("account_uuid", "email", "organization_uuid"),
    "codex": ("account_id", "email"),
    "gemini": ("project_id", "email"),
    "gemini-cli": ("project_id", "email"),
    "kimi": ("device_id",),
    "xai": ("sub", "email"),
}
TOKEN_FIELDS = ("refresh_token", "access_token")


class GenerationError(Exception):
    """A deliberately detail-free inventory generation failure."""


class APIClient:
    def __init__(self, base_url: str, api_key: str, timeout: float = 20.0):
        if base_url not in BASE_URLS:
            raise GenerationError("API endpoint must be the pinned loopback service")
        if not api_key:
            raise GenerationError("management API key is missing")
        self.base_url = base_url
        self.api_key = api_key
        self.timeout = timeout

    def get(self, endpoint: str) -> dict[str, Any]:
        request = urllib.request.Request(
            self.base_url + endpoint,
            headers={"Accept": "application/json", "Authorization": f"Bearer {self.api_key}"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                if response.status != 200:
                    raise GenerationError("management API request failed")
                value = json.load(response)
        except (urllib.error.URLError, TimeoutError, OSError, UnicodeError, json.JSONDecodeError):
            raise GenerationError("management API request failed") from None
        if not isinstance(value, dict):
            raise GenerationError("management API response is malformed")
        return value

    def reconcile_status(self) -> list[dict[str, Any]]:
        return _object_rows(self.get("/v0/management/auth-files/reconcile-status"), "credentials")

    def auth_files(self) -> list[dict[str, Any]]:
        return _object_rows(self.get("/v0/management/auth-files/reconcile-inventory"), "files")

    def models(self, _name: str, auth_index: str) -> list[dict[str, Any]]:
        query = urllib.parse.urlencode({"auth_index": auth_index})
        return _object_rows(self.get(f"/v0/management/auth-files/reconcile-models?{query}"), "models")


def _object_rows(value: dict[str, Any], key: str) -> list[dict[str, Any]]:
    rows = value.get(key)
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise GenerationError("management API response is malformed")
    return rows


def require_hub(hostname: str | None = None) -> None:
    host = (hostname or socket.gethostname()).strip().lower().split(".", 1)[0]
    if host != "healify-hub":
        raise GenerationError("inventory generation is restricted to healify-hub")


def _nonempty_string(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _load_canonical(path: Path, auth_dir: Path) -> dict[str, Any]:
    try:
        info = path.lstat()
        auth_info = auth_dir.stat()
    except OSError:
        raise GenerationError("canonical credential is unavailable") from None
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise GenerationError("canonical credential is not a regular file")
    if path.parent != auth_dir or info.st_dev != auth_info.st_dev or path.suffix.lower() != ".json":
        raise GenerationError("canonical credential path is outside the auth directory")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise GenerationError("canonical credential is not valid JSON") from None
    if not isinstance(value, dict):
        raise GenerationError("canonical credential is not a JSON object")
    return value


def _stable_auth_index(provider_type: str, path: Path) -> str:
    seed = f"{provider_type.lower()}:{path}"
    return hashlib.sha256(seed.encode()).hexdigest()[:16]


def _select_probe_model(provider: str, models: list[dict[str, Any]]) -> str:
    preferences = PROBE_MODELS.get(provider)
    if not preferences:
        raise GenerationError("provider has no approved probe-model policy")
    registered = {_nonempty_string(row.get("id")) for row in models}
    for model in preferences:
        if model in registered:
            return model
    raise GenerationError("credential has no approved registered probe model")


def _status_is_active(row: dict[str, Any]) -> bool:
    status = _nonempty_string(row.get("credential_status")).lower()
    if status not in {"unknown", "active", "pending", "refreshing", "error", "disabled"}:
        raise GenerationError("runtime credential status is invalid")
    disabled = row.get("disabled")
    unavailable = row.get("unavailable")
    if not isinstance(disabled, bool) or not isinstance(unavailable, bool):
        raise GenerationError("runtime credential status is incomplete")
    return status == "active" and not disabled and not unavailable


def _required_keys(value: dict[str, Any]) -> list[str]:
    keys = [key for key in TOKEN_FIELDS if _nonempty_string(value.get(key))]
    if "access_token" not in keys:
        raise GenerationError("canonical credential has no supported access token")
    return keys


def _expected_fields(provider: str, value: dict[str, Any]) -> dict[str, str]:
    fields = IDENTITY_FIELDS.get(provider)
    if not fields:
        raise GenerationError("provider has no approved identity policy")
    expected = {key: field for key in fields if (field := _nonempty_string(value.get(key)))}
    if not expected:
        raise GenerationError("canonical credential has no stable identity field")
    return expected


def generate_inventory(
    api: APIClient,
    auth_dir: Path,
    candidate_dir: Path,
    *,
    max_attempts_per_day: int = 6,
    base_backoff_seconds: int = 300,
    max_backoff_seconds: int = 21600,
) -> tuple[dict[str, Any], dict[str, int]]:
    auth_dir = Path(os.path.abspath(auth_dir))
    candidate_dir = Path(os.path.abspath(candidate_dir))
    status_rows = api.reconcile_status()
    file_rows = api.auth_files()
    if not status_rows:
        raise GenerationError("runtime desired-seat inventory is empty")

    by_index: dict[str, dict[str, Any]] = {}
    for row in file_rows:
        index = _nonempty_string(row.get("auth_index"))
        if not index:
            continue
        if index in by_index:
            raise GenerationError("runtime auth-file inventory is ambiguous")
        by_index[index] = row

    status_by_index: dict[str, dict[str, Any]] = {}
    models_by_index: dict[str, list[dict[str, Any]]] = {}
    provider_active_models: dict[str, set[str]] = {}
    for status in status_rows:
        auth_index = _nonempty_string(status.get("auth_index"))
        provider = _nonempty_string(status.get("provider")).lower()
        if not auth_index or not provider or auth_index in status_by_index:
            raise GenerationError("runtime desired-seat inventory is ambiguous")
        status_by_index[auth_index] = status
        row = by_index.get(auth_index)
        if row is None:
            raise GenerationError("runtime desired-seat inventory is incomplete")
        if _nonempty_string(row.get("provider")).lower() != provider or row.get("runtime_only") is True:
            raise GenerationError("runtime desired-seat metadata does not match")
        if _status_is_active(status):
            name = _nonempty_string(row.get("name"))
            if not name:
                raise GenerationError("runtime desired-seat path is ambiguous")
            models = api.models(name, auth_index)
            models_by_index[auth_index] = models
            registered = {_nonempty_string(model.get("id")) for model in models}
            provider_active_models.setdefault(provider, set()).update(registered - {""})
    if set(by_index) != set(status_by_index):
        raise GenerationError("runtime desired-seat inventories differ")

    seats: list[dict[str, Any]] = []
    provider_counts: dict[str, int] = {}
    seen_paths: set[Path] = set()
    seen_names: set[str] = set()
    for status in status_rows:
        auth_index = _nonempty_string(status.get("auth_index"))
        provider = _nonempty_string(status.get("provider")).lower()
        if not auth_index or not provider:
            raise GenerationError("runtime desired-seat inventory is ambiguous")
        row = by_index.get(auth_index)
        if row is None:
            raise GenerationError("runtime desired-seat inventory is incomplete")
        if _nonempty_string(row.get("provider")).lower() != provider or row.get("runtime_only") is True:
            raise GenerationError("runtime desired-seat metadata does not match")
        name = _nonempty_string(row.get("name"))
        raw_path = _nonempty_string(row.get("path"))
        if not name or not raw_path or name in seen_names:
            raise GenerationError("runtime desired-seat path is ambiguous")
        seen_names.add(name)
        canonical = Path(os.path.abspath(raw_path))
        if canonical in seen_paths:
            raise GenerationError("runtime desired-seat path is ambiguous")
        seen_paths.add(canonical)
        value = _load_canonical(canonical, auth_dir)
        file_provider = _nonempty_string(value.get("provider", value.get("type"))).lower()
        if file_provider != provider or _stable_auth_index(file_provider, canonical) != auth_index:
            raise GenerationError("canonical credential identity does not match runtime")
        if _status_is_active(status):
            model = _select_probe_model(provider, models_by_index[auth_index])
        else:
            peer_models = [{"id": model} for model in provider_active_models.get(provider, set())]
            model = _select_probe_model(provider, peer_models)
        seats.append(
            {
                "auth_index": auth_index,
                "provider": provider,
                "model": model,
                "canonical_path": str(canonical),
                "candidate_path": str(candidate_dir / canonical.name),
                "required_keys": _required_keys(value),
                "expected_fields": _expected_fields(provider, value),
            }
        )
        provider_counts[provider] = provider_counts.get(provider, 0) + 1

    if len(seats) != len(status_rows):
        raise GenerationError("runtime desired-seat inventory is incomplete")
    seats.sort(key=lambda seat: seat["auth_index"])
    return (
        {
            "version": 1,
            "max_attempts_per_day": max_attempts_per_day,
            "base_backoff_seconds": base_backoff_seconds,
            "max_backoff_seconds": max_backoff_seconds,
            "probe_payload": {"messages": [{"role": "user", "content": "Reply OK."}]},
            "seats": seats,
        },
        provider_counts,
    )


def resolve_owner(owner: str) -> tuple[int, int]:
    parts = owner.split(":", 1)
    if len(parts) != 2 or not all(parts):
        raise GenerationError("output owner must be user:group")
    try:
        return pwd.getpwnam(parts[0]).pw_uid, grp.getgrnam(parts[1]).gr_gid
    except KeyError:
        raise GenerationError("output owner does not exist") from None


def atomic_write_inventory(path: Path, inventory: dict[str, Any], uid: int, gid: int, mode: int) -> None:
    if mode != 0o640:
        raise GenerationError("inventory output mode must be 0640")
    path = Path(os.path.abspath(path))
    try:
        path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        parent_info = path.parent.lstat()
    except OSError:
        raise GenerationError("inventory output directory is unavailable") from None
    if not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode) or stat.S_IMODE(parent_info.st_mode) & 0o002:
        raise GenerationError("inventory output directory permissions are unsafe")
    try:
        current = path.lstat()
    except FileNotFoundError:
        current = None
    except OSError:
        raise GenerationError("existing inventory cannot be inspected") from None
    if current is not None:
        if not stat.S_ISREG(current.st_mode) or stat.S_ISLNK(current.st_mode):
            raise GenerationError("existing inventory is not a regular file")
    fd, temp_name = tempfile.mkstemp(prefix=".account-inventory-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        os.fchown(fd, uid, gid)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(inventory, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp_name, path)
        written = path.stat()
        if stat.S_IMODE(written.st_mode) != mode or written.st_uid != uid or written.st_gid != gid:
            raise GenerationError("inventory output protection did not persist")
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError:
        raise GenerationError("inventory output failed") from None
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def summary(mode: str, seats: int, provider_counts: dict[str, int]) -> str:
    if mode not in {"dry_run", "written"} or any(provider not in PROBE_MODELS for provider in provider_counts):
        raise GenerationError("summary contains an unsafe category")
    return json.dumps(
        {
            "event": "inventory_validated",
            "mode": mode,
            "providers": dict(sorted(provider_counts.items())),
            "seats": seats,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate the protected hub account inventory")
    parser.add_argument("--base-url", default="http://127.0.0.1:8319")
    parser.add_argument("--auth-dir", type=Path, default=Path("/opt/crsproxy/auths"))
    parser.add_argument("--candidate-dir", type=Path, default=Path("/opt/crsproxy/auth-candidates"))
    parser.add_argument("--output", type=Path, default=Path("/etc/crsproxy/account-inventory.json"))
    parser.add_argument("--owner", default="root:crsproxy")
    parser.add_argument("--mode", default="0640")
    parser.add_argument("--write", action="store_true", help="atomically write the inventory; default is dry-run")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        require_hub()
        args = parse_args(argv)
        if args.mode != "0640":
            raise GenerationError("inventory output mode must be 0640")
        api = APIClient(args.base_url, os.environ.get("CLIPROXY_RECONCILER_API_KEY", ""))
        inventory, providers = generate_inventory(api, args.auth_dir, args.candidate_dir)
        mode = "dry_run"
        if args.write:
            uid, gid = resolve_owner(args.owner)
            atomic_write_inventory(args.output, inventory, uid, gid, int(args.mode, 8))
            mode = "written"
        print(summary(mode, len(inventory["seats"]), providers))
        return 0
    except GenerationError:
        print('{"event":"inventory_failed","reason":"validation_failed"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

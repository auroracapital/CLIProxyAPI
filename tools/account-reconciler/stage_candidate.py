#!/usr/bin/env python3
"""Identity-match and atomically stage one externally authorized credential."""

from __future__ import annotations

import argparse
import importlib.machinery
import importlib.util
import json
import os
import pwd
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any


def load_reconciler():
    directory = Path(__file__).resolve().parent
    for name in ("reconciler.py", "account-reconciler"):
        path = directory / name
        if not path.is_file():
            continue
        loader = importlib.machinery.SourceFileLoader("cliproxy_account_reconciler", str(path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        if spec is None:
            continue
        module = importlib.util.module_from_spec(spec)
        sys.modules[loader.name] = module
        loader.exec_module(module)
        return module
    raise RuntimeError("account reconciler module is unavailable")


reconciler = load_reconciler()


MAX_CREDENTIAL_BYTES = 1024 * 1024


class StagingError(Exception):
    """A deliberately secret-free staging failure."""


def read_credential(path: Path, allowed_uids: set[int]) -> tuple[dict[str, Any], bytes]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise StagingError("credential cannot be read safely") from exc
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid not in allowed_uids
            or info.st_size <= 0
            or info.st_size > MAX_CREDENTIAL_BYTES
        ):
            raise StagingError("credential access or size is invalid")
        raw = b""
        while len(raw) <= MAX_CREDENTIAL_BYTES:
            chunk = os.read(fd, min(65536, MAX_CREDENTIAL_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
    except OSError as exc:
        raise StagingError("credential cannot be read safely") from exc
    finally:
        os.close(fd)
    if len(raw) > MAX_CREDENTIAL_BYTES:
        raise StagingError("credential access or size is invalid")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise StagingError("credential JSON is invalid") from exc
    if not isinstance(value, dict) or value.get("disabled") is True:
        raise StagingError("credential content is invalid")
    return value, raw


def matching_seat(inventory: reconciler.Inventory, credential: dict[str, Any]) -> reconciler.Seat:
    provider = credential.get("provider", credential.get("type"))
    if not isinstance(provider, str) or not provider.strip():
        raise StagingError("credential provider is missing")
    provider = provider.strip().lower()
    matches = [
        seat
        for seat in inventory.seats
        if seat.provider == provider
        and seat.canonical_path is not None
        and seat.candidate_path is not None
        and all(credential.get(key) not in (None, "") for key in seat.required_keys)
        and all(str(credential.get(key, "")) == expected for key, expected in seat.expected_fields)
    ]
    if len(matches) != 1:
        raise StagingError("credential identity does not uniquely match inventory")
    return matches[0]


def install_candidate(
    seat: reconciler.Seat,
    raw: bytes,
    uid: int,
    gid: int,
    replace_existing: bool = False,
) -> None:
    if seat.canonical_path is None or seat.candidate_path is None:
        raise StagingError("matched seat is not stageable")
    candidate = seat.candidate_path
    try:
        canonical_parent = seat.canonical_path.parent.stat()
        candidate_parent = candidate.parent.stat()
        if (
            not stat.S_ISDIR(canonical_parent.st_mode)
            or not stat.S_ISDIR(candidate_parent.st_mode)
            or stat.S_IMODE(canonical_parent.st_mode) & 0o022
            or stat.S_IMODE(candidate_parent.st_mode) & 0o022
            or canonical_parent.st_dev != candidate_parent.st_dev
        ):
            raise StagingError("credential directories are unsafe")
    except OSError as exc:
        raise StagingError("credential directories are unavailable") from exc

    try:
        with reconciler.credential_file_lock(candidate):
            exists = candidate.exists() or candidate.is_symlink()
            if exists:
                if not replace_existing:
                    raise StagingError("candidate already exists")
                try:
                    reconciler.validate_candidate(seat)
                except reconciler.PromotionError as exc:
                    raise StagingError("existing candidate is invalid") from exc

            fd, temp_name = tempfile.mkstemp(prefix=".staged-", dir=candidate.parent)
            temp = Path(temp_name)
            installed = False
            try:
                os.fchmod(fd, 0o600)
                os.fchown(fd, uid, gid)
                with os.fdopen(fd, "wb", closefd=False) as output:
                    output.write(raw)
                    output.flush()
                    os.fsync(output.fileno())
                os.close(fd)
                fd = -1
                if exists:
                    os.replace(temp, candidate)
                else:
                    os.link(temp, candidate, follow_symlinks=False)
                installed = True
                directory_fd = os.open(candidate.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            finally:
                if fd >= 0:
                    os.close(fd)
                if not installed or temp.exists():
                    try:
                        temp.unlink()
                    except FileNotFoundError:
                        pass
    except (OSError, StagingError, reconciler.PromotionError) as exc:
        if isinstance(exc, StagingError):
            raise
        raise StagingError("candidate installation failed") from exc


def stage(
    source: Path,
    inventory_path: Path,
    uid: int,
    gid: int,
    replace_existing: bool = False,
) -> None:
    inventory = reconciler.load_inventory(inventory_path)
    credential, raw = read_credential(source, {os.geteuid(), uid})
    seat = matching_seat(inventory, credential)
    install_candidate(seat, raw, uid, gid, replace_existing)
    # The source is intentionally retained as the recovery copy. Never emit
    # provider, identity, credential path, or candidate path.


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stage one identity-matched CLIProxy credential")
    parser.add_argument("source", type=Path)
    parser.add_argument("--inventory", type=Path, default=Path("/etc/crsproxy/account-inventory.json"))
    parser.add_argument("--service-user", default="crsproxy")
    parser.add_argument(
        "--replace-existing",
        action="store_true",
        help="replace only an existing candidate that validates as the same unique inventory seat",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        identity = pwd.getpwnam(args.service_user)
        stage(
            args.source,
            args.inventory,
            identity.pw_uid,
            identity.pw_gid,
            replace_existing=args.replace_existing,
        )
        print(json.dumps({"status": "staged"}, separators=(",", ":")))
        return 0
    except (KeyError, RuntimeError, reconciler.InventoryError, StagingError):
        print(json.dumps({"status": "rejected"}, separators=(",", ":")), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

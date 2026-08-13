#!/usr/bin/env python3
"""Send one privacy-safe deterministic request through the auto-router."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import urllib.error
import urllib.request
from pathlib import Path


ENDPOINT = "http://127.0.0.1:8320/v1/chat/completions"
EXPECTED_MODEL = "gpt-5.6-sol"
MAX_RESPONSE_BYTES = 1024 * 1024


class CanaryError(Exception):
    pass


def read_key(path: Path) -> str:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise CanaryError("client credential is unavailable") from exc
    try:
        info = os.fstat(fd)
        mode = stat.S_IMODE(info.st_mode)
        private_owned = info.st_uid == os.geteuid() and mode == 0o600
        systemd_credential = info.st_uid == 0 and mode in {0o400, 0o440}
        if (
            not stat.S_ISREG(info.st_mode)
            or not (private_owned or systemd_credential)
            or info.st_size <= 0
            or info.st_size > 8192
        ):
            raise CanaryError("client credential access is invalid")
        raw = os.read(fd, 8193)
    except OSError as exc:
        raise CanaryError("client credential cannot be read") from exc
    finally:
        os.close(fd)
    key = raw.decode("utf-8", errors="strict").strip()
    if not key or len(key) > 8192:
        raise CanaryError("client credential content is invalid")
    return key


def request_once(key: str, endpoint: str = ENDPOINT, timeout: float = 120.0) -> None:
    if endpoint != ENDPOINT:
        raise CanaryError("endpoint must be the pinned loopback auto-router")
    body = json.dumps(
        {
            "model": "auto",
            "messages": [
                {
                    "role": "user",
                    "content": "Implement a concurrency-safe Go router. Reply only with the word ready.",
                }
            ],
            "max_tokens": 8,
            "stream": False,
        },
        separators=(",", ":"),
    ).encode()
    request = urllib.request.Request(
        endpoint,
        data=body,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise CanaryError("auto-router request failed")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CanaryError("auto-router request failed") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise CanaryError("auto-router response is oversized")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CanaryError("auto-router response is malformed") from exc
    if not isinstance(value, dict) or value.get("model") != EXPECTED_MODEL:
        raise CanaryError("auto-router selected an unexpected model")
    choices = value.get("choices")
    if not isinstance(choices, list) or not choices:
        raise CanaryError("auto-router response is incomplete")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one CLIProxy smart-router soak canary")
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--endpoint", default=ENDPOINT)
    parser.add_argument("--timeout", type=float, default=120.0)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        if not 1 <= args.timeout <= 180:
            raise CanaryError("timeout is invalid")
        request_once(read_key(args.key_file), args.endpoint, args.timeout)
        print(json.dumps({"status": "success"}, separators=(",", ":")))
        return 0
    except (CanaryError, UnicodeError):
        print(json.dumps({"status": "failed"}, separators=(",", ":")), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

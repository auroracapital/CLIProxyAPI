#!/usr/bin/env python3
"""Render the auto-router runtime config from a secret-free JSON/YAML policy."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
MODEL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,127}$")
TASK_NAMES = {"code", "reasoning", "research", "agent", "multimodal", "writing", "general"}
OBJECTIVES = {"balanced", "quality", "cost", "latency"}
PROVIDER_STRATEGIES = {"health", "priority"}


def regular_secret(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("credential must be a regular file")
        with os.fdopen(os.dup(descriptor), "r", encoding="utf-8") as handle:
            value = handle.read().strip()
    finally:
        os.close(descriptor)
    if not value or "\n" in value or "\r" in value or len(value) > 4096:
        raise ValueError("credential must contain one non-empty bounded line")
    return value


def model_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{field} must be a non-empty list")
    models: list[str] = []
    for item in value:
        if not isinstance(item, str) or not MODEL_NAME.fullmatch(item):
            raise ValueError(f"{field} contains an invalid model")
        if item not in models:
            models.append(item)
    return models


def load_policy(path: Path) -> dict[str, Any]:
    # JSON is deliberately used as the constrained subset of YAML here. This
    # keeps the privileged renderer dependency-free and the policy auditable.
    policy = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(policy, dict) or policy.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported auto-router policy schema")
    if set(policy) != {"schema_version", "listen", "base", "routing"}:
        raise ValueError("unexpected auto-router policy fields")

    listen = policy["listen"]
    if not isinstance(listen, dict) or set(listen) != {"host", "port"}:
        raise ValueError("invalid listen policy")
    if listen.get("host") != "127.0.0.1" or listen.get("port") != 8320:
        raise ValueError("auto-router must listen only on 127.0.0.1:8320")

    base = policy["base"]
    if not isinstance(base, dict) or set(base) != {"url", "provider", "models"}:
        raise ValueError("invalid base policy")
    if base.get("url") != "http://127.0.0.1:8319/v1":
        raise ValueError("base must be the loopback explicit-model service on 8319")
    if not isinstance(base.get("provider"), str) or not MODEL_NAME.fullmatch(base["provider"]):
        raise ValueError("invalid base provider")
    base["models"] = model_list(base.get("models"), "base.models")

    routing = policy["routing"]
    required_routing = {"default_models", "task_models", "objective", "provider_strategy"}
    if not isinstance(routing, dict) or set(routing) != required_routing:
        raise ValueError("invalid routing policy")
    routing["default_models"] = model_list(routing.get("default_models"), "routing.default_models")
    task_models = routing.get("task_models")
    if not isinstance(task_models, dict) or any(task not in TASK_NAMES for task in task_models):
        raise ValueError("invalid routing.task_models")
    routing["task_models"] = {
        task: model_list(models, f"routing.task_models.{task}") for task, models in task_models.items()
    }
    if routing.get("objective") not in OBJECTIVES:
        raise ValueError("invalid routing objective")
    if routing.get("provider_strategy") not in PROVIDER_STRATEGIES:
        raise ValueError("invalid provider strategy")

    configured = set(base["models"])
    referenced = set(routing["default_models"])
    for models in routing["task_models"].values():
        referenced.update(models)
    if not referenced.issubset(configured):
        raise ValueError("routing policy references a model absent from base.models")
    return policy


def rendered_config(policy: dict[str, Any], client_key: str, base_key: str, state_dir: Path) -> dict[str, Any]:
    base = policy["base"]
    routing = policy["routing"]
    return {
        "host": "127.0.0.1",
        "port": 8320,
        "tls": {"enable": False, "cert": "", "key": ""},
        "remote-management": {"allow-remote": False, "secret-key": "", "disable-control-panel": True},
        "auth-dir": str(state_dir / "auths"),
        "api-keys": [client_key],
        "debug": False,
        "logging-to-file": False,
        "usage-statistics-enabled": False,
        "proxy-url": "",
        "request-retry": 2,
        "max-retry-credentials": 1,
        "max-retry-interval": 5,
        "disable-cooling": False,
        "routing": {
            "strategy": "least-pressure",
            "auto": {
                "mode": "exclusive",
                "max-fallbacks": 3,
                "default-models": routing["default_models"],
                "task-models": routing["task_models"],
                "policy": {
                    "objective": routing["objective"],
                    "provider-strategy": routing["provider_strategy"],
                },
            },
            "observability": {"enabled": True},
        },
        "openai-compatibility": [{
            "name": base["provider"],
            "base-url": base["url"],
            "api-key-entries": [{"api-key": base_key}],
            "models": [{"name": model, "alias": model} for model in base["models"]],
        }],
    }


def atomic_write(path: Path, payload: dict[str, Any]) -> None:
    if path.parent.is_symlink():
        raise ValueError("output directory must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o077:
        raise ValueError("output directory is unsafe")
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        written = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(written.st_mode) or written.st_uid != os.geteuid() or stat.S_IMODE(written.st_mode) != 0o600:
            raise ValueError("private runtime config did not persist")
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--client-key-file", type=Path, required=True)
    parser.add_argument("--base-api-key-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--state-directory", type=Path, default=Path("/var/lib/cliproxy-auto-router"))
    args = parser.parse_args()
    policy = load_policy(args.policy)
    config = rendered_config(
        policy,
        regular_secret(args.client_key_file),
        regular_secret(args.base_api_key_file),
        args.state_directory,
    )
    atomic_write(args.output, config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

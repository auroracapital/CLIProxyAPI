from __future__ import annotations

import contextlib
import datetime as dt
import importlib.util
import io
import json
import multiprocessing
import os
import random
import stat
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "reconciler.py"
SPEC = importlib.util.spec_from_file_location("account_reconciler", MODULE_PATH)
assert SPEC and SPEC.loader
reconciler = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = reconciler
SPEC.loader.exec_module(reconciler)


NOW = dt.datetime(2026, 8, 13, 12, 0, tzinfo=dt.timezone.utc)
HMAC_KEY = b"unit-test-key-that-is-at-least-32-bytes-long"


def write_json(path: Path, value: object, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(mode)


def inventory_dict(seats: list[dict] | None = None) -> dict:
    return {
        "version": 1,
        "max_attempts_per_day": 3,
        "base_backoff_seconds": 10,
        "max_backoff_seconds": 80,
        "probe_payload": {"messages": [{"role": "user", "content": "Reply OK."}]},
        "seats": seats
        or [
            {
                "auth_index": "index-alpha",
                "provider": "claude",
                "model": "probe-model",
            }
        ],
    }


class FakeAPI:
    def __init__(self, rows=None, refresh="succeeded", probe="succeeded"):
        self.rows = rows or [
            {
                "auth_index": "index-alpha",
                "provider": "claude",
                "state": "cooling",
                "credential_status": "error",
                "disabled": False,
                "unavailable": True,
            }
        ]
        self.refresh_outcome = refresh
        self.probe_outcome = probe
        self.calls = []

    def status(self):
        self.calls.append(("status",))
        return self.rows

    def set_state(self, auth_index, state, reason="", next_attempt=""):
        self.calls.append(("set_state", auth_index, state, reason, next_attempt))

    def refresh(self, auth_index):
        self.calls.append(("refresh", auth_index))
        return self.refresh_outcome

    def probe(self, seat, payload):
        self.calls.append(("probe", seat.auth_index, seat.model))
        return self.probe_outcome


def remote_row(**overrides):
    row = {
        "auth_index": "index-alpha",
        "provider": "claude",
        "state": "ready",
        "credential_status": "active",
        "disabled": False,
        "unavailable": False,
        "updated_at": "before",
    }
    row.update(overrides)
    return row


class FailingSetStateAPI(FakeAPI):
    def set_state(self, auth_index, state, reason="", next_attempt=""):
        self.calls.append(("set_state", auth_index, state, reason, next_attempt))
        raise reconciler.APIError(503, "retryable")


class PromotionReloadFailureController(reconciler.Controller):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.reload_calls = 0

    def _wait_for_reload(self, auth_index, previous_updated_at):
        self.reload_calls += 1
        if self.reload_calls == 1:
            raise reconciler.PromotionError("reload failed")
        return "rollback-reloaded"


class ImmediateReloadController(reconciler.Controller):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.reload_calls = []

    def _wait_for_reload(self, auth_index, previous_updated_at):
        self.reload_calls.append((auth_index, previous_updated_at))
        return f"reloaded-{len(self.reload_calls)}"


class InspectingAPI(FakeAPI):
    def __init__(self, canonical_path, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.canonical_path = canonical_path
        self.probed_canonical = None

    def probe(self, seat, payload):
        self.probed_canonical = json.loads(self.canonical_path.read_text(encoding="utf-8"))
        return super().probe(seat, payload)


class HTTPErrorAdapter(reconciler.APIAdapter):
    def _request(self, method, endpoint, payload=None):
        if endpoint.endswith("/probe"):
            raise reconciler.APIError(502, "auth_required")
        if endpoint.endswith("/refresh"):
            raise reconciler.APIError(502, "auth_required")
        return super()._request(method, endpoint, payload)


def lock_child(path: str, ready: multiprocessing.Event, release: multiprocessing.Event) -> None:
    with reconciler.file_lock(Path(path), blocking=True) as acquired:
        if acquired:
            ready.set()
            release.wait(5)


class InventoryTests(unittest.TestCase):
    def test_valid_inventory_and_exact_runtime_match(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.json"
            write_json(path, inventory_dict())
            inventory = reconciler.load_inventory(path)
            self.assertEqual(inventory.seats[0].provider, "claude")
            reconciler.validate_complete_inventory(
                inventory,
                [remote_row()],
            )

    def test_rejects_incomplete_duplicate_and_unknown_fields(self):
        bad_values = [
            {"version": 1, "seats": []},
            inventory_dict(
                [
                    {"auth_index": "same", "provider": "claude", "model": "m"},
                    {"auth_index": "same", "provider": "claude", "model": "m"},
                ]
            ),
            {**inventory_dict(), "identity": "must-not-exist"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            for number, value in enumerate(bad_values):
                path = Path(directory) / f"bad-{number}.json"
                write_json(path, value)
                with self.subTest(number=number), self.assertRaises(reconciler.InventoryError):
                    reconciler.load_inventory(path)

    def test_rejects_ambiguous_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            same = str(root / "same.json")
            value = inventory_dict(
                [
                    {
                        "auth_index": "index-alpha",
                        "provider": "claude",
                        "model": "m",
                        "canonical_path": same,
                        "candidate_path": same,
                    }
                ]
            )
            path = root / "inventory.json"
            write_json(path, value)
            with self.assertRaises(reconciler.InventoryError):
                reconciler.load_inventory(path)

    def test_rejects_missing_extra_duplicate_or_provider_mismatched_runtime_seats(self):
        inventory = reconciler.Inventory((reconciler.Seat("one", "claude", "m"),))
        cases = [
            [],
            [
                remote_row(auth_index="one"),
                remote_row(auth_index="two"),
            ],
            [
                remote_row(auth_index="one"),
                remote_row(auth_index="one"),
            ],
            [remote_row(auth_index="one", provider="gemini")],
        ]
        for rows in cases:
            with self.subTest(rows=rows), self.assertRaises(reconciler.InventoryError):
                reconciler.validate_complete_inventory(inventory, rows)


class LockAndBackoffTests(unittest.TestCase):
    def test_nonblocking_lock_reports_contention(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "locks" / "seat.lock")
            ready = multiprocessing.Event()
            release = multiprocessing.Event()
            process = multiprocessing.Process(target=lock_child, args=(path, ready, release))
            process.start()
            self.assertTrue(ready.wait(5))
            try:
                with reconciler.file_lock(Path(path)) as acquired:
                    self.assertFalse(acquired)
            finally:
                release.set()
                process.join(5)
            self.assertEqual(process.exitcode, 0)

    def test_backoff_is_exponential_bounded_and_jittered(self):
        rng = random.Random(7)
        first = reconciler.backoff_seconds(1, 10, 40, rng)
        second = reconciler.backoff_seconds(2, 10, 40, rng)
        capped = reconciler.backoff_seconds(20, 10, 40, rng)
        self.assertGreaterEqual(first, 5)
        self.assertLessEqual(first, 10)
        self.assertGreaterEqual(second, 10)
        self.assertLessEqual(second, 20)
        self.assertGreaterEqual(capped, 20)
        self.assertLessEqual(capped, 40)


class PromotionTests(unittest.TestCase):
    def make_seat(self, root: Path) -> reconciler.Seat:
        return reconciler.Seat(
            "index-alpha",
            "claude",
            "probe-model",
            root / "auths" / "canonical.json",
            root / "auths" / "candidate.json",
            ("refresh_token",),
        )

    def test_rejects_bad_mode_invalid_json_disabled_and_missing_key(self):
        invalid = [
            ({"provider": "claude", "refresh_token": "x"}, 0o644),
            ("not-json", 0o600),
            ({"provider": "claude", "refresh_token": "x", "disabled": True}, 0o600),
            ({"provider": "claude"}, 0o600),
            ({"provider": "gemini", "refresh_token": "x"}, 0o600),
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seat = self.make_seat(root)
            for number, (value, mode) in enumerate(invalid):
                if isinstance(value, str):
                    seat.candidate_path.parent.mkdir(parents=True, exist_ok=True)
                    seat.candidate_path.write_text(value, encoding="utf-8")
                    seat.candidate_path.chmod(mode)
                else:
                    write_json(seat.candidate_path, value, mode)
                with self.subTest(number=number), self.assertRaises(reconciler.PromotionError):
                    reconciler.validate_candidate(seat)

    def test_rejects_candidate_identity_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = self.make_seat(root)
            seat = reconciler.Seat(
                base.auth_index,
                base.provider,
                base.model,
                base.canonical_path,
                base.candidate_path,
                base.required_keys,
                (("account_id", "expected"),),
            )
            write_json(seat.candidate_path, {"provider": "claude", "refresh_token": "x", "account_id": "wrong"})
            with self.assertRaises(reconciler.PromotionError):
                reconciler.validate_candidate(seat)

    def test_promotes_atomically_archives_and_rolls_back_at_0600(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seat = self.make_seat(root)
            original = {"provider": "claude", "refresh_token": "old"}
            candidate = {"provider": "claude", "refresh_token": "new", "disabled": False}
            write_json(seat.canonical_path, original)
            write_json(seat.candidate_path, candidate)
            archive = reconciler.promote_candidate(seat, root / "state" / "rollback", "opaque-seat", NOW)
            promoted = json.loads(seat.canonical_path.read_text())
            self.assertEqual(promoted["refresh_token"], "new")
            self.assertFalse(promoted["disabled"])
            self.assertEqual(promoted["reconcile_state"], "probing")
            self.assertIsNotNone(archive)
            self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)
            self.assertNotIn("index-alpha", archive.name)
            reconciler.rollback(seat, archive)
            self.assertEqual(json.loads(seat.canonical_path.read_text()), original)
            self.assertEqual(stat.S_IMODE(seat.canonical_path.stat().st_mode), 0o600)

    def test_normalizes_disabled_canonical_and_archives_exact_original(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seat = self.make_seat(root)
            original = {
                "provider": "claude",
                "refresh_token": "old",
                "disabled": True,
                "reconcile_state": "auth_required",
                "reconcile_reason": "old",
                "reconcile_next_attempt": "later",
            }
            write_json(seat.canonical_path, original, 0o664)
            archive = reconciler.normalize_canonical(
                seat, root / "state" / "rollback", "opaque-seat", NOW
            )
            normalized = json.loads(seat.canonical_path.read_text())
            self.assertFalse(normalized["disabled"])
            self.assertEqual(normalized["reconcile_state"], "probing")
            self.assertNotIn("reconcile_reason", normalized)
            self.assertNotIn("reconcile_next_attempt", normalized)
            self.assertEqual(stat.S_IMODE(seat.canonical_path.stat().st_mode), 0o600)
            self.assertEqual(json.loads(archive.read_text()), original)
            self.assertEqual(stat.S_IMODE(archive.stat().st_mode), 0o600)

    def test_controller_repairs_access_normalizes_disabled_and_admits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seat = self.make_seat(root)
            write_json(
                seat.canonical_path,
                {"provider": "claude", "refresh_token": "old", "disabled": True},
                0o664,
            )
            api = InspectingAPI(
                seat.canonical_path,
                rows=[remote_row(credential_status="disabled", disabled=True)],
            )
            controller = ImmediateReloadController(
                reconciler.Inventory((seat,), 3, 10, 80),
                api,
                root / "state",
                root / "run",
                HMAC_KEY,
                apply=True,
                logger=reconciler.configure_logging(io.StringIO()),
                now=lambda: NOW,
                rng=random.Random(1),
            )
            self.assertEqual(controller.run(), 0)
            canonical = json.loads(seat.canonical_path.read_text())
            self.assertFalse(canonical["disabled"])
            self.assertEqual(canonical["reconcile_state"], "probing")
            self.assertEqual(stat.S_IMODE(seat.canonical_path.stat().st_mode), 0o600)
            self.assertEqual(api.probed_canonical, canonical)
            self.assertEqual(
                [call[2] for call in api.calls if call[0] == "set_state"],
                ["refreshing", "probing"],
            )
            self.assertEqual(len(controller.reload_calls), 1)
            seat_key = reconciler.opaque_key(HMAC_KEY, "seat", seat.auth_index)
            self.assertEqual(controller.store.read(seat_key)["state"], "ready")

    def test_controller_rolls_back_normalization_when_watcher_rejects_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seat = self.make_seat(root)
            original = {"provider": "claude", "refresh_token": "old", "disabled": True}
            write_json(seat.canonical_path, original, 0o664)
            controller = PromotionReloadFailureController(
                reconciler.Inventory((seat,), 3, 10, 80),
                FakeAPI(rows=[remote_row(credential_status="disabled", disabled=True)]),
                root / "state",
                root / "run",
                HMAC_KEY,
                apply=True,
                logger=reconciler.configure_logging(io.StringIO()),
                now=lambda: NOW,
                rng=random.Random(1),
            )
            self.assertEqual(controller.run(), 1)
            self.assertEqual(json.loads(seat.canonical_path.read_text()), original)
            self.assertEqual(stat.S_IMODE(seat.canonical_path.stat().st_mode), 0o600)
            self.assertEqual(controller.reload_calls, 2)

    def test_controller_rolls_back_normalization_when_probe_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seat = self.make_seat(root)
            original = {"provider": "claude", "refresh_token": "old", "disabled": True}
            write_json(seat.canonical_path, original, 0o664)
            controller = ImmediateReloadController(
                reconciler.Inventory((seat,), 3, 10, 80),
                FakeAPI(
                    rows=[remote_row(credential_status="disabled", disabled=True)],
                    probe="retryable",
                ),
                root / "state",
                root / "run",
                HMAC_KEY,
                apply=True,
                logger=reconciler.configure_logging(io.StringIO()),
                now=lambda: NOW,
                rng=random.Random(1),
            )
            self.assertEqual(controller.run(), 1)
            self.assertEqual(json.loads(seat.canonical_path.read_text()), original)
            self.assertEqual(stat.S_IMODE(seat.canonical_path.stat().st_mode), 0o600)
            self.assertEqual(len(controller.reload_calls), 2)

    def test_controller_rolls_back_when_pinned_probe_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seat = self.make_seat(root)
            original = {"provider": "claude", "refresh_token": "old"}
            write_json(seat.canonical_path, original)
            write_json(seat.candidate_path, {"provider": "claude", "refresh_token": "new"})
            inventory = reconciler.Inventory((seat,), 3, 10, 80)
            api = FakeAPI(probe="retryable")
            controller = ImmediateReloadController(
                inventory,
                api,
                root / "state",
                root / "run",
                HMAC_KEY,
                apply=True,
                logger=reconciler.configure_logging(io.StringIO()),
                now=lambda: NOW,
                rng=random.Random(1),
            )
            self.assertEqual(controller.run(), 1)
            self.assertEqual(json.loads(seat.canonical_path.read_text()), original)
            self.assertTrue(seat.candidate_path.exists())

    def test_controller_removes_new_canonical_when_first_candidate_probe_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seat = self.make_seat(root)
            write_json(seat.candidate_path, {"provider": "claude", "refresh_token": "new"})
            api = FakeAPI(probe="retryable")
            controller = reconciler.Controller(
                reconciler.Inventory((seat,), 3, 10, 80),
                api,
                root / "state",
                root / "run",
                HMAC_KEY,
                apply=True,
                logger=reconciler.configure_logging(io.StringIO()),
                now=lambda: NOW,
                rng=random.Random(1),
            )
            self.assertEqual(controller.run(), 1)
            self.assertFalse(seat.canonical_path.exists())
            self.assertTrue(seat.candidate_path.exists())

    def test_controller_rolls_back_when_promotion_reload_is_not_acknowledged(self):
        for existing in (True, False):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                seat = self.make_seat(root)
                original = {"provider": "claude", "refresh_token": "old"}
                if existing:
                    write_json(seat.canonical_path, original)
                write_json(seat.candidate_path, {"provider": "claude", "refresh_token": "new"})
                controller = PromotionReloadFailureController(
                    reconciler.Inventory((seat,), 3, 10, 80),
                    FakeAPI(),
                    root / "state",
                    root / "run",
                    HMAC_KEY,
                    apply=True,
                    logger=reconciler.configure_logging(io.StringIO()),
                    now=lambda: NOW,
                    rng=random.Random(1),
                )
                self.assertEqual(controller.run(), 1)
                if existing:
                    self.assertEqual(json.loads(seat.canonical_path.read_text()), original)
                else:
                    self.assertFalse(seat.canonical_path.exists())
                self.assertTrue(seat.candidate_path.exists())
                self.assertEqual(controller.reload_calls, 2)


class ControllerTests(unittest.TestCase):
    def test_exact_opaque_seat_key_selects_only_that_seat_after_full_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seats = (
                reconciler.Seat("index-alpha", "claude", "probe-model"),
                reconciler.Seat("index-beta", "codex", "probe-model"),
            )
            api = FakeAPI(
                rows=[
                    remote_row(auth_index="index-alpha", provider="claude"),
                    remote_row(auth_index="index-beta", provider="codex"),
                ]
            )
            target = reconciler.opaque_key(HMAC_KEY, "seat", "index-beta")
            controller = reconciler.Controller(
                reconciler.Inventory(seats),
                api,
                root / "state",
                root / "run",
                HMAC_KEY,
                seat_key=target,
                logger=reconciler.configure_logging(io.StringIO()),
                now=lambda: NOW,
            )
            self.assertEqual(controller.run(), 0)
            self.assertEqual(api.calls, [("status",)])
            self.assertFalse((root / "state").exists())

    def test_unknown_or_contradictory_opaque_seat_key_fails_before_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seat = reconciler.Seat("index-alpha", "claude", "probe-model")
            api = FakeAPI(rows=[remote_row()])
            for target, provider in [
                ("0" * 24, ""),
                (reconciler.opaque_key(HMAC_KEY, "seat", seat.auth_index), "codex"),
            ]:
                with self.subTest(target=target, provider=provider):
                    controller = reconciler.Controller(
                        reconciler.Inventory((seat,)),
                        api,
                        root / "state",
                        root / "run",
                        HMAC_KEY,
                        seat_key=target,
                        provider=provider,
                        logger=reconciler.configure_logging(io.StringIO()),
                        now=lambda: NOW,
                    )
                    with self.assertRaises(reconciler.InventoryError):
                        controller.run()
                    self.assertFalse((root / "state").exists())

    def test_seat_key_argument_accepts_only_opaque_hex(self):
        for value in ["raw-auth-index", "a" * 23, "g" * 24]:
            with self.assertRaises(reconciler.InventoryError):
                reconciler.validate_seat_key_filter(value)
        self.assertEqual(reconciler.validate_seat_key_filter(" A" + "b" * 23 + " "), "a" + "b" * 23)

    def test_apply_canary_validates_full_inventory_but_reconciles_one_healthy_seat(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canonical = root / "auths" / "healthy.json"
            candidate = root / "auths" / "healthy-candidate.json"
            write_json(canonical, {"provider": "claude", "refresh_token": "token", "account_id": "healthy"})
            seats = (
                reconciler.Seat("healthy", "claude", "probe-model", canonical, candidate, ("refresh_token",), (("account_id", "healthy"),)),
                reconciler.Seat("unhealthy", "claude", "probe-model"),
            )
            api = FakeAPI(rows=[
                remote_row(auth_index="healthy"),
                remote_row(auth_index="unhealthy", credential_status="error", unavailable=True),
            ])
            controller = ImmediateReloadController(
                reconciler.Inventory(seats), api, root / "state", root / "run", HMAC_KEY,
                apply=True, max_seats=1, only_healthy=True, force_probe=True,
                provider="claude",
                logger=reconciler.configure_logging(io.StringIO()), now=lambda: NOW,
            )
            self.assertEqual(controller.run(), 0)
            self.assertFalse(any("unhealthy" in call for call in api.calls))
            self.assertTrue(any(call[0] == "refresh" for call in api.calls))
            self.assertTrue(any(call[0] == "probe" for call in api.calls))

    def test_probe_preserves_categorical_outcome_from_non_2xx(self):
        adapter = HTTPErrorAdapter("http://127.0.0.1:8319")
        seat = reconciler.Seat("index-alpha", "claude", "probe-model")
        self.assertEqual(adapter.probe(seat, {"messages": []}), "auth_required")
        self.assertEqual(adapter.refresh(seat.auth_index), "auth_required")

    def test_dry_run_is_default_and_performs_no_mutating_api_or_state_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = FakeAPI()
            inventory = reconciler.Inventory((reconciler.Seat("index-alpha", "claude", "probe-model"),))
            controller = reconciler.Controller(
                inventory,
                api,
                root / "state",
                root / "run",
                HMAC_KEY,
                logger=reconciler.configure_logging(io.StringIO()),
                now=lambda: NOW,
            )
            self.assertFalse(controller.apply)
            self.assertEqual(controller.run(), 0)
            self.assertEqual(api.calls, [("status",)])
            self.assertFalse((root / "state").exists())

    def test_dry_run_does_not_persist_even_for_ready_seat(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = FakeAPI(rows=[remote_row()])
            inventory = reconciler.Inventory((reconciler.Seat("index-alpha", "claude", "probe-model"),))
            controller = reconciler.Controller(
                inventory,
                api,
                root / "state",
                root / "run",
                HMAC_KEY,
                logger=reconciler.configure_logging(io.StringIO()),
                now=lambda: NOW,
            )
            self.assertEqual(controller.run(), 0)
            self.assertFalse((root / "state").exists())

    def test_dry_run_does_not_normalize_or_repair_canonical_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canonical = root / "auths" / "canonical.json"
            candidate = root / "auths" / "candidate.json"
            original = {"provider": "claude", "refresh_token": "old", "disabled": True}
            write_json(canonical, original, 0o664)
            seat = reconciler.Seat(
                "index-alpha", "claude", "probe-model", canonical, candidate, ("refresh_token",)
            )
            api = FakeAPI(rows=[remote_row(credential_status="disabled", disabled=True)])
            controller = reconciler.Controller(
                reconciler.Inventory((seat,)),
                api,
                root / "state",
                root / "run",
                HMAC_KEY,
                logger=reconciler.configure_logging(io.StringIO()),
                now=lambda: NOW,
            )
            self.assertEqual(controller.run(), 0)
            self.assertEqual(json.loads(canonical.read_text()), original)
            self.assertEqual(stat.S_IMODE(canonical.stat().st_mode), 0o664)
            self.assertEqual(api.calls, [("status",)])
            self.assertFalse((root / "state").exists())

    def test_healthy_ready_canonical_seat_skips_without_file_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            canonical = root / "auths" / "canonical.json"
            candidate = root / "auths" / "candidate.json"
            original = {"provider": "claude", "refresh_token": "old", "disabled": False}
            write_json(canonical, original)
            seat = reconciler.Seat(
                "index-alpha", "claude", "probe-model", canonical, candidate, ("refresh_token",)
            )
            api = FakeAPI(rows=[remote_row()])
            controller = reconciler.Controller(
                reconciler.Inventory((seat,)),
                api,
                root / "state",
                root / "run",
                HMAC_KEY,
                apply=True,
                logger=reconciler.configure_logging(io.StringIO()),
                now=lambda: NOW,
            )
            self.assertEqual(controller.run(), 0)
            self.assertEqual(json.loads(canonical.read_text()), original)
            self.assertEqual(api.calls, [("status",)])

    def test_ready_but_unhealthy_runtime_status_triggers_reconciliation(self):
        cases = [
            {"credential_status": "error"},
            {"credential_status": "pending"},
            {"credential_status": "refreshing"},
            {"credential_status": "disabled", "disabled": True},
            {"credential_status": "active", "unavailable": True},
            {"credential_status": "unknown"},
        ]
        for remote_overrides in cases:
            with self.subTest(remote_overrides=remote_overrides), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                canonical = root / "auths" / "canonical.json"
                candidate = root / "auths" / "candidate.json"
                write_json(canonical, {"provider": "claude", "refresh_token": "old"})
                seat = reconciler.Seat(
                    "index-alpha", "claude", "probe-model", canonical, candidate, ("refresh_token",)
                )
                api = FakeAPI(rows=[remote_row(**remote_overrides)])
                controller = ImmediateReloadController(
                    reconciler.Inventory((seat,)),
                    api,
                    root / "state",
                    root / "run",
                    HMAC_KEY,
                    apply=True,
                    logger=reconciler.configure_logging(io.StringIO()),
                    now=lambda: NOW,
                )
                self.assertEqual(controller.run(), 0)
                self.assertIn(("refresh", "index-alpha"), api.calls)
                self.assertIn(("probe", "index-alpha", "probe-model"), api.calls)

    def test_attempt_budget_prevents_api_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = FakeAPI()
            seat = reconciler.Seat("index-alpha", "claude", "probe-model")
            inventory = reconciler.Inventory((seat,), max_attempts_per_day=1)
            controller = reconciler.Controller(
                inventory,
                api,
                root / "state",
                root / "run",
                HMAC_KEY,
                apply=True,
                logger=reconciler.configure_logging(io.StringIO()),
                now=lambda: NOW,
            )
            seat_key = reconciler.opaque_key(HMAC_KEY, "seat", seat.auth_index)
            controller.store.write(seat_key, "cooling", "probe_retryable", "retryable", 1, "")
            self.assertEqual(controller.run(), 0)
            self.assertEqual(api.calls[0], ("status",))
            self.assertEqual(api.calls[1][0:3], ("set_state", "index-alpha", "auth_required"))
            self.assertEqual(controller.store.read(seat_key)["state"], "auth_required")

    def test_failed_remote_state_write_preserves_last_confirmed_local_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = FailingSetStateAPI()
            seat = reconciler.Seat("index-alpha", "claude", "probe-model")
            controller = reconciler.Controller(
                reconciler.Inventory((seat,), max_attempts_per_day=1),
                api,
                root / "state",
                root / "run",
                HMAC_KEY,
                apply=True,
                logger=reconciler.configure_logging(io.StringIO()),
                now=lambda: NOW,
            )
            seat_key = reconciler.opaque_key(HMAC_KEY, "seat", seat.auth_index)
            controller.store.write(seat_key, "cooling", "probe_retryable", "retryable", 1, "")
            self.assertEqual(controller.run(), 1)
            persisted = controller.store.read(seat_key)
            self.assertEqual(persisted["state"], "cooling")
            self.assertEqual(persisted["reason"], "attempt_budget_exhausted")
            self.assertEqual(persisted["outcome"], "failed")

    def test_auth_failure_marks_auth_required_without_interactive_login(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            api = FakeAPI(probe="auth_required")
            seat = reconciler.Seat("index-alpha", "claude", "probe-model")
            controller = reconciler.Controller(
                reconciler.Inventory((seat,), 3, 10, 80),
                api,
                root / "state",
                root / "run",
                HMAC_KEY,
                apply=True,
                logger=reconciler.configure_logging(io.StringIO()),
                now=lambda: NOW,
                rng=random.Random(1),
            )
            self.assertEqual(controller.run(), 1)
            set_states = [call[2] for call in api.calls if call[0] == "set_state"]
            self.assertEqual(set_states, ["refreshing", "probing", "auth_required"])
            seat_key = reconciler.opaque_key(HMAC_KEY, "seat", seat.auth_index)
            self.assertEqual(controller.store.read(seat_key)["state"], "auth_required")

    def test_privacy_logs_and_state_contain_only_opaque_seat_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stream = io.StringIO()
            secret_index = "account-person@example.test-/private/auth.json-token"
            seat = reconciler.Seat(secret_index, "claude", "probe-model")
            api = FakeAPI(
                rows=[
                    remote_row(
                        auth_index=secret_index,
                        state="cooling",
                        credential_status="error",
                        unavailable=True,
                    )
                ]
            )
            controller = reconciler.Controller(
                reconciler.Inventory((seat,), 3, 10, 80),
                api,
                root / "state",
                root / "run",
                HMAC_KEY,
                logger=reconciler.configure_logging(stream),
                now=lambda: NOW,
            )
            self.assertEqual(controller.run(), 0)
            output = stream.getvalue()
            self.assertNotIn(secret_index, output)
            self.assertNotIn("example.test", output)
            self.assertIn(reconciler.opaque_key(HMAC_KEY, "seat", secret_index), output)
            self.assertFalse((root / "state").exists())
            lock_names = " ".join(path.name for path in (root / "run" / "locks").iterdir())
            self.assertNotIn(secret_index, lock_names)
            self.assertNotIn("claude", lock_names)


if __name__ == "__main__":
    unittest.main()

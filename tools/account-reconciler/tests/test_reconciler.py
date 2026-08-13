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
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "reconciler.py"
SPEC = importlib.util.spec_from_file_location("account_reconciler", MODULE_PATH)
assert SPEC and SPEC.loader
reconciler = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = reconciler
SPEC.loader.exec_module(reconciler)


NOW = dt.datetime(2026, 8, 13, 12, 0, tzinfo=dt.timezone.utc)
HMAC_KEY = b"unit-test-key-that-is-at-least-32-bytes-long"
GENERATION = "a" * 64


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
                "generation": GENERATION,
                "runtime_generation": GENERATION,
                "durable_disabled": False,
            }
        ]
        self.refresh_outcome = refresh
        self.probe_outcome = probe
        self.calls = []
        self.generation_counter = 0
        self.api_key = HMAC_KEY.decode()

    def status(self):
        self.calls.append(("status",))
        return self.rows

    def set_state(self, auth_index, state, reason="", next_attempt="", generation="", disabled=None):
        self.calls.append(("set_state", auth_index, state, reason, next_attempt, generation, disabled))
        self.generation_counter += 1
        new_generation = f"{self.generation_counter:064x}"
        for row in self.rows:
            if row["auth_index"] != auth_index:
                continue
            row["state"] = state
            row["generation"] = new_generation
            row["runtime_generation"] = new_generation
            if disabled is not None:
                row["disabled"] = disabled
                row["durable_disabled"] = disabled
            return {"generation": new_generation, "disabled": row["durable_disabled"]}
        raise reconciler.APIError(404)

    def refresh(self, auth_index):
        self.calls.append(("refresh", auth_index))
        row = next(row for row in self.rows if row["auth_index"] == auth_index)
        return self.refresh_outcome, row["generation"], row["durable_disabled"]

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
        "generation": GENERATION,
        "runtime_generation": GENERATION,
        "durable_disabled": False,
    }
    row.update(overrides)
    if "disabled" in overrides and "durable_disabled" not in overrides:
        row["durable_disabled"] = overrides["disabled"]
    return row


class FailingSetStateAPI(FakeAPI):
    def set_state(self, auth_index, state, reason="", next_attempt="", generation="", disabled=None):
        self.calls.append(("set_state", auth_index, state, reason, next_attempt, generation, disabled))
        raise reconciler.APIError(503, "retryable")


class PromotionReloadFailureController(reconciler.Controller):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.reload_calls = 0

    def _wait_for_generation(self, auth_index, generation, disabled):
        self.reload_calls += 1
        if self.reload_calls == 1 and not disabled:
            raise reconciler.PromotionError("reload failed")


class ImmediateReloadController(reconciler.Controller):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.reload_calls = []

    def _wait_for_generation(self, auth_index, generation, disabled):
        self.reload_calls.append((auth_index, generation, disabled))


class InspectingAPI(FakeAPI):
    def __init__(self, canonical_path, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.canonical_path = canonical_path
        self.probed_canonical = None

    def probe(self, seat, payload):
        self.probed_canonical = json.loads(self.canonical_path.read_text(encoding="utf-8"))
        return super().probe(seat, payload)

    def set_state(self, auth_index, state, reason="", next_attempt="", generation="", disabled=None):
        value = super().set_state(auth_index, state, reason, next_attempt, generation, disabled)
        canonical = json.loads(self.canonical_path.read_text(encoding="utf-8"))
        if disabled is not None:
            canonical["disabled"] = disabled
        canonical["reconcile_state"] = state
        if reason:
            canonical["reconcile_reason"] = reason
        else:
            canonical.pop("reconcile_reason", None)
        write_json(self.canonical_path, canonical)
        new_generation = reconciler.file_generation(self.canonical_path, self.api_key.encode())
        value["generation"] = new_generation
        for row in self.rows:
            if row["auth_index"] == auth_index:
                row["generation"] = new_generation
                row["runtime_generation"] = new_generation
        return value


class RotatingInspectingAPI(InspectingAPI):
    def refresh(self, auth_index):
        self.calls.append(("refresh", auth_index))
        canonical = json.loads(self.canonical_path.read_text(encoding="utf-8"))
        canonical["access_token"] = "rotated-access"
        canonical["refresh_token"] = "rotated-refresh"
        write_json(self.canonical_path, canonical)
        generation = reconciler.file_generation(self.canonical_path, self.api_key.encode())
        for row in self.rows:
            if row["auth_index"] == auth_index:
                row["generation"] = generation
                row["runtime_generation"] = generation
                row["durable_disabled"] = canonical.get("disabled", False)
        return "succeeded", generation, canonical.get("disabled", False)


class StatefulGenerationAPI:
    """Model durable file state and delayed watcher publication separately."""

    def __init__(
        self,
        canonical_path,
        *,
        row=None,
        probe_outcomes=("succeeded",),
        publish_delay=2,
        rotate_on_refresh=False,
        fail_transition_state="",
    ):
        self.canonical_path = canonical_path
        self.api_key = HMAC_KEY.decode()
        self.calls = []
        self.publish_delay = publish_delay
        self.rotate_on_refresh = rotate_on_refresh
        self.fail_transition_state = fail_transition_state
        self.probe_outcomes = list(probe_outcomes)
        self.pending_publication = None
        self.divergent_statuses = 0
        self.probe_snapshots = []
        self.refresh_count = 0
        self.row = remote_row(**(row or {}))
        if self.canonical_path.exists():
            canonical = self._canonical()
            generation = self._generation()
            disabled = canonical.get("disabled", False)
            self.row.update(
                {
                    "generation": generation,
                    "runtime_generation": generation,
                    "durable_disabled": disabled,
                    "disabled": disabled,
                    "state": canonical.get("reconcile_state", self.row["state"]),
                    "credential_status": "disabled" if disabled else "active",
                }
            )

    def _canonical(self):
        return json.loads(self.canonical_path.read_text(encoding="utf-8"))

    def _generation(self):
        return reconciler.file_generation(self.canonical_path, self.api_key.encode())

    def _queue_current_file(self):
        if not self.canonical_path.exists():
            return
        canonical = self._canonical()
        generation = self._generation()
        snapshot = {
            "generation": generation,
            "disabled": canonical.get("disabled", False),
            "state": canonical.get("reconcile_state", "ready"),
        }
        if self.pending_publication and self.pending_publication[1]["generation"] == generation:
            return
        if self.row["runtime_generation"] == generation:
            return
        self.pending_publication = [self.publish_delay, snapshot]

    def _advance_watcher(self):
        self._queue_current_file()
        if not self.pending_publication:
            return
        remaining, snapshot = self.pending_publication
        if remaining > 0:
            self.pending_publication[0] -= 1
            self.divergent_statuses += 1
            return
        self.row.update(
            {
                "runtime_generation": snapshot["generation"],
                "disabled": snapshot["disabled"],
                "state": snapshot["state"],
                "credential_status": "disabled" if snapshot["disabled"] else "active",
                "unavailable": False,
            }
        )
        self.pending_publication = None

    def status(self):
        self.calls.append(("status",))
        if self.canonical_path.exists():
            canonical = self._canonical()
            self.row["generation"] = self._generation()
            self.row["durable_disabled"] = canonical.get("disabled", False)
            self._advance_watcher()
        return [dict(self.row)]

    def set_state(self, auth_index, state, reason="", next_attempt="", generation="", disabled=None):
        self.calls.append(("set_state", auth_index, state, reason, next_attempt, generation, disabled))
        if state == self.fail_transition_state:
            self.fail_transition_state = ""
            raise reconciler.APIError(412, "retryable")
        if not self.canonical_path.exists() or generation != self._generation():
            raise reconciler.APIError(412)
        canonical = self._canonical()
        if disabled is not None:
            canonical["disabled"] = disabled
        canonical["reconcile_state"] = state
        if reason:
            canonical["reconcile_reason"] = reason
        else:
            canonical.pop("reconcile_reason", None)
        if next_attempt:
            canonical["reconcile_next_attempt"] = next_attempt
        else:
            canonical.pop("reconcile_next_attempt", None)
        write_json(self.canonical_path, canonical)
        new_generation = self._generation()
        self.row["generation"] = new_generation
        self.row["durable_disabled"] = canonical.get("disabled", False)
        self._queue_current_file()
        return {"generation": new_generation, "disabled": canonical.get("disabled", False)}

    def refresh(self, auth_index):
        self.calls.append(("refresh", auth_index))
        self.refresh_count += 1
        if self.rotate_on_refresh:
            canonical = self._canonical()
            canonical["access_token"] = f"rotated-access-{self.refresh_count}"
            canonical["refresh_token"] = f"rotated-refresh-{self.refresh_count}"
            write_json(self.canonical_path, canonical)
            self.row["generation"] = self._generation()
            self.row["durable_disabled"] = canonical.get("disabled", False)
            self._queue_current_file()
        return "succeeded", self._generation(), self._canonical().get("disabled", False)

    def probe(self, seat, payload):
        self.calls.append(("probe", seat.auth_index, seat.model))
        durable_generation = self._generation()
        snapshot = {
            "durable_generation": durable_generation,
            "runtime_generation": self.row["runtime_generation"],
            "state": self.row["state"],
            "disabled": self.row["disabled"],
        }
        self.probe_snapshots.append(snapshot)
        if snapshot != {
            "durable_generation": durable_generation,
            "runtime_generation": durable_generation,
            "state": "probing",
            "disabled": False,
        }:
            raise AssertionError(f"probe dispatched before runtime convergence: {snapshot}")
        return self.probe_outcomes.pop(0)


class AdvancingClock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        self.value += 0.1
        return self.value


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

    def run_with_stateful_watcher(self, controller):
        clock = AdvancingClock()
        with mock.patch.object(reconciler.time, "monotonic", side_effect=clock), mock.patch.object(
            reconciler.time, "sleep", return_value=None
        ):
            return controller.run()

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
            self.assertEqual(canonical["reconcile_state"], "ready")
            self.assertEqual(stat.S_IMODE(seat.canonical_path.stat().st_mode), 0o600)
            self.assertEqual(api.probed_canonical["reconcile_state"], "probing")
            self.assertEqual(api.probed_canonical["refresh_token"], canonical["refresh_token"])
            self.assertEqual(api.probed_canonical["disabled"], canonical["disabled"])
            self.assertEqual(
                [call[2] for call in api.calls if call[0] == "set_state"],
                ["refreshing", "probing", "ready"],
            )
            self.assertEqual(len(controller.reload_calls), 4)
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
            self.assertEqual(controller.reload_calls, 3)

    def test_controller_rolls_back_normalization_when_probe_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seat = self.make_seat(root)
            original = {"provider": "claude", "refresh_token": "old", "disabled": True}
            write_json(seat.canonical_path, original, 0o664)
            controller = ImmediateReloadController(
                reconciler.Inventory((seat,), 3, 10, 80),
                InspectingAPI(
                    seat.canonical_path,
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
            canonical = json.loads(seat.canonical_path.read_text())
            self.assertTrue(canonical["disabled"])
            self.assertEqual(canonical["refresh_token"], original["refresh_token"])
            self.assertEqual(canonical["reconcile_state"], "cooling")
            self.assertEqual(canonical["reconcile_reason"], "probe_retryable")
            self.assertEqual(stat.S_IMODE(seat.canonical_path.stat().st_mode), 0o600)
            self.assertGreaterEqual(len(controller.reload_calls), 2)

    def test_rejected_probe_preserves_rotated_tokens_but_restores_archived_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seat = self.make_seat(root)
            original = {
                "provider": "claude",
                "access_token": "old-access",
                "refresh_token": "old-refresh",
                "disabled": True,
            }
            write_json(seat.canonical_path, original, 0o600)
            api = RotatingInspectingAPI(
                seat.canonical_path,
                rows=[remote_row(credential_status="disabled", disabled=True)],
                probe="rejected",
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
            self.assertEqual(controller.run(), 1)
            canonical = json.loads(seat.canonical_path.read_text())
            self.assertEqual(canonical["access_token"], "rotated-access")
            self.assertEqual(canonical["refresh_token"], "rotated-refresh")
            self.assertTrue(canonical["disabled"])
            self.assertEqual(canonical["reconcile_state"], "cooling")
            self.assertEqual(canonical["reconcile_reason"], "probe_rejected")
            archives = list((root / "state" / "rollback").glob("*.rollback"))
            self.assertEqual(len(archives), 1)
            self.assertEqual(json.loads(archives[0].read_text()), original)

    def test_probe_waits_for_delayed_runtime_generation_and_probing_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seat = self.make_seat(root)
            write_json(
                seat.canonical_path,
                {"provider": "claude", "refresh_token": "old", "disabled": True},
            )
            api = StatefulGenerationAPI(
                seat.canonical_path,
                row={"credential_status": "disabled", "disabled": True},
                publish_delay=3,
            )
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
            self.assertEqual(self.run_with_stateful_watcher(controller), 0)
            self.assertGreaterEqual(api.divergent_statuses, 3)
            self.assertEqual(len(api.probe_snapshots), 1)
            snapshot = api.probe_snapshots[0]
            self.assertEqual(snapshot["runtime_generation"], snapshot["durable_generation"])
            self.assertEqual(snapshot["state"], "probing")
            self.assertFalse(snapshot["disabled"])

    def test_rejected_probe_cooling_preserves_archived_admission_and_newest_tokens(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seat = self.make_seat(root)
            write_json(
                seat.canonical_path,
                {
                    "provider": "claude",
                    "access_token": "old-access",
                    "refresh_token": "old-refresh",
                    "disabled": True,
                },
            )
            api = StatefulGenerationAPI(
                seat.canonical_path,
                row={"credential_status": "disabled", "disabled": True},
                probe_outcomes=("rejected",),
                publish_delay=2,
                rotate_on_refresh=True,
            )
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
            self.assertEqual(self.run_with_stateful_watcher(controller), 1)
            canonical = json.loads(seat.canonical_path.read_text())
            self.assertEqual(canonical["access_token"], "rotated-access-1")
            self.assertEqual(canonical["refresh_token"], "rotated-refresh-1")
            self.assertTrue(canonical["disabled"])
            self.assertEqual(canonical["reconcile_state"], "cooling")
            self.assertEqual(canonical["reconcile_reason"], "probe_rejected")
            self.assertEqual(api.row["runtime_generation"], api.row["generation"])
            self.assertTrue(api.row["disabled"])

    def test_candidate_probing_transition_error_restages_refresh_and_restores_canonical(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seat = self.make_seat(root)
            original = {
                "provider": "claude",
                "access_token": "canonical-access",
                "refresh_token": "canonical-refresh",
                "disabled": True,
            }
            candidate = {
                "provider": "claude",
                "access_token": "candidate-access",
                "refresh_token": "candidate-refresh",
                "disabled": False,
            }
            write_json(seat.canonical_path, original)
            write_json(seat.candidate_path, candidate)
            api = StatefulGenerationAPI(
                seat.canonical_path,
                row={"credential_status": "disabled", "disabled": True},
                publish_delay=1,
                rotate_on_refresh=True,
                fail_transition_state="probing",
            )
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
            self.assertEqual(self.run_with_stateful_watcher(controller), 1)
            canonical = json.loads(seat.canonical_path.read_text())
            staged = json.loads(seat.candidate_path.read_text())
            self.assertEqual(canonical["access_token"], original["access_token"])
            self.assertEqual(canonical["refresh_token"], original["refresh_token"])
            self.assertTrue(canonical["disabled"])
            self.assertEqual(canonical["reconcile_state"], "cooling")
            self.assertEqual(staged["access_token"], "rotated-access-1")
            self.assertEqual(staged["refresh_token"], "rotated-refresh-1")

    def test_first_install_probe_failure_recovers_on_second_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seat = self.make_seat(root)
            write_json(
                seat.candidate_path,
                {
                    "provider": "claude",
                    "access_token": "candidate-access",
                    "refresh_token": "candidate-refresh",
                },
            )
            api = StatefulGenerationAPI(
                seat.canonical_path,
                row={"credential_status": "error", "unavailable": True},
                probe_outcomes=("retryable", "succeeded"),
                publish_delay=1,
            )

            def make_controller():
                return reconciler.Controller(
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

            self.assertEqual(self.run_with_stateful_watcher(make_controller()), 1)
            failed = json.loads(seat.canonical_path.read_text())
            self.assertTrue(failed["disabled"])
            self.assertEqual(failed["reconcile_state"], "cooling")
            self.assertTrue(seat.candidate_path.exists())

            seat_key = reconciler.opaque_key(HMAC_KEY, "seat", seat.auth_index)
            state_path = root / "state" / "seats" / f"{seat_key}.json"
            persisted = json.loads(state_path.read_text())
            persisted["next_attempt"] = ""
            write_json(state_path, persisted)

            self.assertEqual(self.run_with_stateful_watcher(make_controller()), 0)
            admitted = json.loads(seat.canonical_path.read_text())
            self.assertFalse(admitted["disabled"])
            self.assertEqual(admitted["reconcile_state"], "ready")
            self.assertFalse(seat.candidate_path.exists())
            self.assertEqual(len(api.probe_snapshots), 2)

    def test_rejected_candidate_probe_restages_rotated_candidate_before_rollback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seat = self.make_seat(root)
            original = {
                "provider": "claude",
                "access_token": "canonical-access",
                "refresh_token": "canonical-refresh",
                "disabled": True,
            }
            candidate = {
                "provider": "claude",
                "access_token": "candidate-access",
                "refresh_token": "candidate-refresh",
                "disabled": False,
            }
            write_json(seat.canonical_path, original)
            write_json(seat.candidate_path, candidate)
            api = RotatingInspectingAPI(
                seat.canonical_path,
                rows=[remote_row(credential_status="disabled", disabled=True)],
                probe="rejected",
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
            self.assertEqual(controller.run(), 1)
            canonical = json.loads(seat.canonical_path.read_text())
            staged = json.loads(seat.candidate_path.read_text())
            self.assertEqual(canonical["refresh_token"], "canonical-refresh")
            self.assertTrue(canonical["disabled"])
            self.assertEqual(canonical["reconcile_state"], "cooling")
            self.assertEqual(staged["refresh_token"], "rotated-refresh")
            self.assertEqual(staged["access_token"], "rotated-access")

    def test_rollback_refuses_to_overwrite_newer_canonical_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seat = self.make_seat(root)
            original = {"provider": "claude", "refresh_token": "old", "disabled": True}
            write_json(seat.canonical_path, original)
            archive = reconciler.normalize_canonical(
                seat,
                root / "state" / "rollback",
                "opaque-seat",
                NOW,
            )
            promoted_generation = reconciler.raw_file_generation(seat.canonical_path)
            newer = {"provider": "claude", "refresh_token": "newer", "disabled": False}
            write_json(seat.canonical_path, newer)
            controller = ImmediateReloadController(
                reconciler.Inventory((seat,)),
                FakeAPI(),
                root / "state",
                root / "run",
                HMAC_KEY,
                apply=True,
                logger=reconciler.configure_logging(io.StringIO()),
                now=lambda: NOW,
            )
            self.assertIsNone(
                controller._restore_and_reload(seat, archive, promoted_generation)
            )
            self.assertEqual(json.loads(seat.canonical_path.read_text()), newer)

    def test_candidate_restage_refuses_changed_or_missing_staged_generation(self):
        for replacement in ({"provider": "claude", "refresh_token": "newer"}, None):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                seat = self.make_seat(root)
                original = {"provider": "claude", "refresh_token": "old", "disabled": True}
                staged = {"provider": "claude", "refresh_token": "candidate", "disabled": False}
                write_json(seat.canonical_path, original)
                write_json(seat.candidate_path, staged)
                archive = reconciler.promote_candidate(
                    seat,
                    root / "state" / "rollback",
                    "opaque-seat",
                    NOW,
                )
                expected_canonical = reconciler.raw_file_generation(seat.canonical_path)
                expected_candidate = reconciler.raw_file_generation(seat.candidate_path)
                if replacement is None:
                    seat.candidate_path.unlink()
                else:
                    write_json(seat.candidate_path, replacement)
                controller = ImmediateReloadController(
                    reconciler.Inventory((seat,)),
                    FakeAPI(),
                    root / "state",
                    root / "run",
                    HMAC_KEY,
                    apply=True,
                    logger=reconciler.configure_logging(io.StringIO()),
                    now=lambda: NOW,
                )
                self.assertIsNone(
                    controller._restage_candidate_and_restore(
                        seat,
                        archive,
                        expected_candidate,
                        expected_canonical,
                    )
                )
                self.assertNotEqual(json.loads(seat.canonical_path.read_text()), original)
                if replacement is None:
                    self.assertFalse(seat.candidate_path.exists())
                else:
                    self.assertEqual(json.loads(seat.candidate_path.read_text()), replacement)

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

    def test_controller_retains_disabled_canonical_when_first_candidate_probe_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            seat = self.make_seat(root)
            write_json(seat.candidate_path, {"provider": "claude", "refresh_token": "new"})
            api = InspectingAPI(seat.canonical_path, probe="retryable")
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
            self.assertEqual(controller.run(), 1)
            self.assertTrue(seat.canonical_path.exists())
            canonical = json.loads(seat.canonical_path.read_text())
            self.assertTrue(canonical["disabled"])
            self.assertEqual(canonical["reconcile_state"], "cooling")
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
                    InspectingAPI(seat.canonical_path) if not existing else FakeAPI(),
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
                    self.assertTrue(seat.canonical_path.exists())
                    self.assertTrue(json.loads(seat.canonical_path.read_text())["disabled"])
                self.assertTrue(seat.candidate_path.exists())
                self.assertGreaterEqual(controller.reload_calls, 1)


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
                ("0" * 32, ""),
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
        for value in ["raw-auth-index", "a" * 31, "g" * 32]:
            with self.assertRaises(reconciler.InventoryError):
                reconciler.validate_seat_key_filter(value)
        self.assertEqual(reconciler.validate_seat_key_filter(" A" + "b" * 31 + " "), "a" + "b" * 31)

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
        self.assertEqual(adapter.refresh(seat.auth_index), ("auth_required", "", False))

    def test_adapter_preserves_committed_generation_from_conflict(self):
        adapter = reconciler.APIAdapter("http://127.0.0.1:8319")
        body = io.BytesIO(
            json.dumps(
                {
                    "error": "reconcile state committed but runtime publication failed",
                    "outcome": "committed",
                    "generation": GENERATION,
                }
            ).encode()
        )
        conflict = reconciler.urllib.error.HTTPError(
            "http://127.0.0.1:8319/reconcile-state",
            409,
            "Conflict",
            {},
            body,
        )
        with mock.patch.object(reconciler.urllib.request, "urlopen", side_effect=conflict):
            with self.assertRaises(reconciler.CommittedTransition) as raised:
                adapter.set_state("index-alpha", "probing", generation=GENERATION, disabled=False)
        conflict.close()
        self.assertEqual(raised.exception.status, 409)
        self.assertEqual(raised.exception.generation, GENERATION)

    def test_transition_waits_for_committed_generation_without_replaying(self):
        class CommittedAPI(FakeAPI):
            def __init__(self):
                super().__init__(rows=[remote_row(state="refreshing")])
                self.set_calls = 0

            def set_state(self, auth_index, state, reason="", next_attempt="", generation="", disabled=None):
                self.set_calls += 1
                row = self.rows[0]
                row.update(
                    {
                        "state": state,
                        "reason": reason,
                        "next_attempt": next_attempt,
                        "generation": "b" * 64,
                        "runtime_generation": "b" * 64,
                        "disabled": disabled,
                        "durable_disabled": disabled,
                    }
                )
                raise reconciler.CommittedTransition(409, "b" * 64)

        api = CommittedAPI()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            controller = reconciler.Controller(
                reconciler.Inventory((reconciler.Seat("index-alpha", "claude", "probe-model"),)),
                api,
                root / "state",
                root / "run",
                HMAC_KEY,
                logger=reconciler.configure_logging(io.StringIO()),
                now=lambda: NOW,
            )
            generation = controller._transition(
                "index-alpha",
                GENERATION,
                "probing",
                "refresh_succeeded",
                disabled=False,
            )
        self.assertEqual(generation, "b" * 64)
        self.assertEqual(api.set_calls, 1)

    def test_transition_discovers_commit_after_response_loss(self):
        class LostResponseAPI(FakeAPI):
            def __init__(self):
                super().__init__(rows=[remote_row(state="refreshing")])
                self.set_calls = 0

            def set_state(self, auth_index, state, reason="", next_attempt="", generation="", disabled=None):
                self.set_calls += 1
                row = self.rows[0]
                row.update(
                    {
                        "state": state,
                        "reason": reason,
                        "next_attempt": next_attempt,
                        "generation": "c" * 64,
                        "runtime_generation": "c" * 64,
                        "disabled": disabled,
                        "durable_disabled": disabled,
                    }
                )
                raise reconciler.APIError()

        for state in ("probing", "ready"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                api = LostResponseAPI()
                controller = reconciler.Controller(
                    reconciler.Inventory((reconciler.Seat("index-alpha", "claude", "probe-model"),)),
                    api,
                    root / "state",
                    root / "run",
                    HMAC_KEY,
                    logger=reconciler.configure_logging(io.StringIO()),
                    now=lambda: NOW,
                )
                generation = controller._transition(
                    "index-alpha",
                    GENERATION,
                    state,
                    "refresh_succeeded" if state == "probing" else "",
                    disabled=False,
                )
                self.assertEqual(generation, "c" * 64)
                self.assertEqual(api.set_calls, 1)

    def test_transition_waits_for_delayed_commit_publication_after_response_loss(self):
        class DelayedLostResponseAPI(FakeAPI):
            def __init__(self):
                super().__init__(rows=[remote_row(state="refreshing")])
                self.status_calls = 0

            def set_state(self, auth_index, state, reason="", next_attempt="", generation="", disabled=None):
                self.target_state = state
                self.target_reason = reason
                self.target_next_attempt = next_attempt
                self.target_disabled = disabled
                self.rows[0]["generation"] = "d" * 64
                raise reconciler.APIError()

            def status(self):
                self.status_calls += 1
                if self.status_calls >= 3:
                    self.rows[0].update(
                        {
                            "state": self.target_state,
                            "reason": self.target_reason,
                            "next_attempt": self.target_next_attempt,
                            "runtime_generation": "d" * 64,
                            "disabled": self.target_disabled,
                            "durable_disabled": self.target_disabled,
                        }
                    )
                return super().status()

        for state in ("probing", "ready"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                api = DelayedLostResponseAPI()
                controller = reconciler.Controller(
                    reconciler.Inventory((reconciler.Seat("index-alpha", "claude", "probe-model"),)),
                    api,
                    root / "state",
                    root / "run",
                    HMAC_KEY,
                    logger=reconciler.configure_logging(io.StringIO()),
                    now=lambda: NOW,
                )
                clock = AdvancingClock()
                with mock.patch.object(reconciler.time, "monotonic", side_effect=clock), mock.patch.object(
                    reconciler.time, "sleep", return_value=None
                ):
                    generation = controller._transition(
                        "index-alpha",
                        GENERATION,
                        state,
                        "refresh_succeeded" if state == "probing" else "",
                        disabled=False,
                    )
                self.assertEqual(generation, "d" * 64)
                self.assertGreaterEqual(api.status_calls, 3)

    def test_transition_does_not_infer_unconverged_or_wrong_state_commit(self):
        for override in (
            {"generation": "c" * 64, "runtime_generation": GENERATION},
            {"state": "cooling"},
            {"disabled": True, "durable_disabled": True},
        ):
            with self.subTest(override=override), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                row = remote_row(state="probing")
                row.update(override)
                api = FakeAPI(rows=[row])
                api.set_state = mock.Mock(side_effect=reconciler.APIError())
                controller = reconciler.Controller(
                    reconciler.Inventory((reconciler.Seat("index-alpha", "claude", "probe-model"),)),
                    api,
                    root / "state",
                    root / "run",
                    HMAC_KEY,
                    logger=reconciler.configure_logging(io.StringIO()),
                    now=lambda: NOW,
                )
                clock = AdvancingClock()
                with mock.patch.object(reconciler.time, "monotonic", side_effect=clock), mock.patch.object(
                    reconciler.time, "sleep", return_value=None
                ):
                    with self.assertRaises(reconciler.APIError):
                        controller._transition(
                            "index-alpha",
                            GENERATION,
                            "probing",
                            "refresh_succeeded",
                        disabled=False,
                    )

    def test_transition_does_not_infer_unchanged_target_state_after_predispatch_loss(self):
        for state, reason, next_attempt in (
            ("probing", "refresh_succeeded", ""),
            ("ready", "", ""),
            ("cooling", "probe_retryable", (NOW + dt.timedelta(minutes=5)).isoformat()),
        ):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                row = remote_row(
                    state=state,
                    reason=reason,
                    next_attempt=next_attempt,
                    disabled=False,
                    durable_disabled=False,
                )
                api = FakeAPI(rows=[row])
                api.set_state = mock.Mock(side_effect=reconciler.APIError())
                controller = reconciler.Controller(
                    reconciler.Inventory((reconciler.Seat("index-alpha", "claude", "probe-model"),)),
                    api,
                    root / "state",
                    root / "run",
                    HMAC_KEY,
                    logger=reconciler.configure_logging(io.StringIO()),
                    now=lambda: NOW,
                )
                clock = AdvancingClock()
                with mock.patch.object(reconciler.time, "monotonic", side_effect=clock), mock.patch.object(
                    reconciler.time, "sleep", return_value=None
                ):
                    with self.assertRaises(reconciler.APIError):
                        controller._transition(
                            "index-alpha",
                            GENERATION,
                            state,
                            reason,
                            next_attempt,
                            disabled=False,
                        )

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

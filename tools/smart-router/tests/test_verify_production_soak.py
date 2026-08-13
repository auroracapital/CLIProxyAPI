from __future__ import annotations

import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).parents[1] / "verify_production_soak.py"
SPEC = importlib.util.spec_from_file_location("verify_production_soak", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
soak = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(soak)


def event(stage: str, outcome: str, *, request: str = "r1_0123456789abcdef", attempt: str = "1", seat: str = "h1_0123456789abcdef") -> dict[str, str]:
    return {
        "routing_stage": stage,
        "routing_outcome": outcome,
        "routing_request_bucket": request,
        "routing_attempt": attempt,
        "routing_seat_bucket": seat,
        "routing_provider": "codex",
        "routing_model": "gpt-5",
    }


class PureStateMachineTests(unittest.TestCase):
    def baseline(self, *, now: float = 1000, leases: int = 0) -> dict[str, object]:
        class Metadata:
            st_ino = 7
            st_size = 10

        return soak.new_baseline(
            now,
            "a" * 64,
            "b" * 64,
            "c" * 64,
            Metadata(),  # type: ignore[arg-type]
            [{"seat_bucket": "h1_0123456789abcdef", "in_flight": leases}],
        )

    def sample(self, state: dict[str, object], when: float, healthy: bool = True) -> None:
        checks = {name: True for name in soak.CHECK_NAMES}
        checks["binary_hash"] = healthy
        state["samples"].append(  # type: ignore[union-attr]
            soak.make_sample(
                state, when, "c" * 64, "a" * 64, "b" * 64, checks,
                {"pressure": {"active_leases": 0, "active_seats": 0}},
            )
        )

    def fill_slo(self, state: dict[str, object], count: int = soak.MIN_ELIGIBLE_REQUESTS) -> None:
        for index in range(count):
            request = f"r1_{index:016x}"
            state["slo"]["terminal_requests"][request] = "success"
            state["slo"]["model_attempts"][request] = {"0": "success"}
        state["slo"]["deterministic_latencies_ms"] = [10] * soak.MIN_DETERMINISTIC_DECISIONS
        state["slo"]["selection_counts"] = {
            "codex:gpt-5": {
                "h1_0123456789abcdef": count // 2,
                "h1_fedcba9876543210": count - count // 2,
            }
        }

    def test_baseline_contract_is_exact_and_hash_bound(self) -> None:
        baseline = self.baseline()
        soak.validate_baseline(baseline, 1000)
        self.assertEqual(baseline["soak_cutoff_epoch"], 1000 + soak.EXPECTED_DURATION_SECONDS)
        state = soak.new_state(baseline)
        soak.validate_state(state, 1000)
        state["baseline"]["max_sample_gap_seconds"] = 999
        with self.assertRaisesRegex(RuntimeError, "baseline contract"):
            soak.validate_state(state, 1000)

    def test_hash_chain_rejects_row_edit_and_truncation_break(self) -> None:
        state = soak.new_state(self.baseline())
        self.sample(state, 1001)
        self.sample(state, 1061)
        soak.validate_state(state, 1061)
        state["samples"][0]["observations"] = {"edited": True}
        with self.assertRaisesRegex(RuntimeError, "evidence hash"):
            soak.validate_state(state, 1061)

    def test_ordinary_sample_requires_complete_check_contract(self) -> None:
        state = soak.new_state(self.baseline())
        sample = soak.make_sample(state, 1001, "c" * 64, "a" * 64, "b" * 64, {"binary_hash": True}, {})
        state["samples"].append(sample)
        with self.assertRaisesRegex(RuntimeError, "incomplete evidence checks"):
            soak.validate_state(state, 1001)

        state = soak.new_state(self.baseline())
        self.sample(state, 1001)
        self.sample(state, 1061)
        state["samples"] = state["samples"][1:]
        with self.assertRaisesRegex(RuntimeError, "evidence chain"):
            soak.validate_state(state, 1061)

    def test_historical_failure_and_gap_are_cumulative(self) -> None:
        state = soak.new_state(self.baseline())
        self.sample(state, 1001, False)
        self.sample(state, 1061, True)
        aggregate = soak.evidence_aggregate(state)
        self.assertFalse(aggregate["window_healthy"])
        self.assertEqual(aggregate["failure_counts"], {"binary_hash": 1})

        state = soak.new_state(self.baseline())
        self.sample(state, 1001)
        self.sample(state, 1091.001)
        self.assertFalse(soak.evidence_aggregate(state)["continuity_healthy"])

    def test_sensitive_and_invalid_events_are_never_returned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "main.log"
            log.write_text(
                "routing decision routing_stage=account_selection routing_outcome=selected "
                "routing_request_bucket=r1_0123456789abcdef routing_attempt=1 "
                "routing_seat_bucket=h1_0123456789abcdef routing_provider=codex "
                "routing_model=secret@host\n"
                "routing decision routing_stage=account_selection routing_outcome=selected "
                "routing_request_bucket=r1_0123456789abcdef routing_attempt=1 "
                "routing_seat_bucket=h1_0123456789abcdef routing_provider=codex "
                "routing_model=gpt-5 prompt=do-not-persist\n",
                encoding="utf-8",
            )
            events, _, counters = soak.read_events(log, {"inode": log.stat().st_ino, "offset": 0})
            self.assertEqual(events, [])
            self.assertEqual(counters["sensitive"], 2)
            self.assertNotIn("do-not-persist", json.dumps(counters))

    def test_credential_shaped_telemetry_is_fail_closed_and_not_returned(self) -> None:
        names = [
            "api_key", "apikey", "authorization", "password", "cookie", "secret",
            "credential", "access_token", "refresh-token", "token", "key",
        ]
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "main.log"
            lines = []
            for index, name in enumerate(names):
                lines.append(
                    "routing decision routing_stage=account_selection routing_outcome=selected "
                    f"routing_request_bucket=r1_{index:016x} routing_attempt=1 "
                    "routing_seat_bucket=h1_0123456789abcdef routing_provider=codex "
                    f"routing_model=gpt-5 {name}=PRIVATE_{index}\n"
                )
            log.write_text("".join(lines), encoding="utf-8")
            events, _, counters = soak.read_events(log, {"inode": log.stat().st_ino, "offset": 0})
            self.assertEqual(events, [])
            self.assertEqual(counters["sensitive"], len(names))
            self.assertNotIn("PRIVATE", json.dumps(counters))

    def test_lifecycle_persists_only_hashed_event_keys(self) -> None:
        state = soak.new_state(self.baseline())
        soak.apply_events(state["lifecycle"], [event("account_selection", "selected"), event("account_attempt", "success")], 1001, state["baseline"])
        serialized = json.dumps(state["lifecycle"])
        self.assertNotIn("gpt-5", serialized)
        self.assertNotIn("codex", serialized)
        self.assertIn("e1_", serialized)

    def test_startup_allowance_is_bounded_and_same_batch_pairs_first(self) -> None:
        state = soak.new_state(self.baseline(leases=1))
        summary = soak.apply_events(
            state["lifecycle"],
            [event("account_attempt", "success"), event("account_selection", "selected")],
            1001,
            state["baseline"],
        )
        self.assertEqual(summary["startup_terminal_allowance_used"], 0)
        self.assertEqual(summary["unmatched_selected"], 0)
        self.assertEqual(summary["unmatched_terminal"], 0)

        second = event("account_attempt", "success", request="r1_1111111111111111")
        summary = soak.apply_events(state["lifecycle"], [second], 1002, state["baseline"])
        self.assertEqual(summary["startup_terminal_allowance_used"], 1)
        third = event("account_attempt", "success", request="r1_2222222222222222")
        summary = soak.apply_events(state["lifecycle"], [third], 1003, state["baseline"])
        self.assertEqual(summary["unmatched_terminal"], 1)

    def test_rotation_is_a_sticky_check_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "main.log"
            log.write_text("new\n", encoding="utf-8")
            _, cursor, counters = soak.read_events(log, {"inode": log.stat().st_ino + 1, "offset": 999})
            self.assertEqual(counters["discontinuity"], 1)
            self.assertEqual(cursor["inode"], log.stat().st_ino)

    def test_partial_line_is_not_consumed_and_duplicate_fields_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "main.log"
            prefix = (
                "routing decision routing_stage=account_selection routing_outcome=selected "
                "routing_request_bucket=r1_0123456789abcdef routing_attempt=1 "
                "routing_seat_bucket=h1_0123456789abcdef routing_provider=codex routing_model=gpt-5"
            )
            log.write_text(prefix, encoding="utf-8")
            events, cursor, counters = soak.read_events(log, {"inode": log.stat().st_ino, "offset": 0})
            self.assertEqual(events, [])
            self.assertEqual(cursor["offset"], 0)
            self.assertEqual(counters["invalid"], 0)
            with log.open("a", encoding="utf-8") as handle:
                handle.write(" routing_model=override\n")
            events, cursor, counters = soak.read_events(log, cursor)
            self.assertEqual(events, [])
            self.assertEqual(counters["invalid"], 1)
            self.assertEqual(cursor["offset"], log.stat().st_size)

    def test_slo_summary_requires_traffic_and_enforces_thresholds(self) -> None:
        state = soak.new_state(self.baseline())
        self.assertFalse(soak.slo_summary(state["slo"])["sufficient_evidence"])
        self.fill_slo(state)
        summary = soak.slo_summary(state["slo"])
        self.assertTrue(summary["sufficient_evidence"])
        state["slo"]["deterministic_latencies_ms"][-10:] = [30] * 10
        self.assertFalse(soak.slo_summary(state["slo"])["checks"]["routing_overhead_p95"])

    def test_cutoff_freezes_cohort_and_accepts_only_before_deadline(self) -> None:
        baseline = self.baseline(now=0)
        state = soak.new_state(baseline)
        selected = event("account_selection", "selected")
        terminal = event("account_attempt", "success")
        soak.apply_events(state["lifecycle"], [selected], soak.EXPECTED_DURATION_SECONDS, baseline)
        self.fill_slo(state)
        for when in range(60, soak.EXPECTED_DURATION_SECONDS + 1, 60):
            self.sample(state, when)
        self.assertIsNone(soak.terminal_decision(state, soak.EXPECTED_DURATION_SECONDS))
        soak.apply_events(state["lifecycle"], [terminal], soak.EXPECTED_DURATION_SECONDS + 30, baseline)
        self.sample(state, soak.EXPECTED_DURATION_SECONDS + 30)
        self.sample(state, soak.EXPECTED_DURATION_SECONDS + 90)
        decision = soak.terminal_decision(state, soak.EXPECTED_DURATION_SECONDS + 90)
        self.assertIsNotNone(decision)
        self.assertTrue(decision["accepted"])

        state = soak.new_state(baseline)
        soak.apply_events(state["lifecycle"], [selected], soak.EXPECTED_DURATION_SECONDS, baseline)
        self.fill_slo(state)
        for when in range(60, soak.EXPECTED_DURATION_SECONDS + 1, 60):
            self.sample(state, when)
        deadline = soak.EXPECTED_DURATION_SECONDS + soak.TERMINAL_GRACE_SECONDS
        for when in range(soak.EXPECTED_DURATION_SECONDS + 60, deadline + 1, 60):
            self.sample(state, when)
        decision = soak.terminal_decision(state, deadline)
        self.assertFalse(decision["accepted"])
        state["terminal"] = decision
        soak.apply_events(state["lifecycle"], [terminal], deadline + 1, baseline)
        self.assertFalse(state["terminal"]["accepted"])

    def test_active_pressure_prevents_terminal_acceptance(self) -> None:
        baseline = self.baseline(now=0)
        state = soak.new_state(baseline)
        soak.apply_events(state["lifecycle"], [], soak.EXPECTED_DURATION_SECONDS, baseline)
        for when in range(60, soak.EXPECTED_DURATION_SECONDS + 1, 60):
            self.sample(state, when)
        self.sample(state, soak.EXPECTED_DURATION_SECONDS + 60)
        state["samples"][-1]["observations"]["pressure"] = {"active_leases": 1, "active_seats": 1}
        unsigned = dict(state["samples"][-1])
        unsigned.pop("sample_sha256")
        state["samples"][-1]["sample_sha256"] = soak.object_hash(unsigned)
        decision = soak.terminal_decision(state, soak.EXPECTED_DURATION_SECONDS + 60)
        self.assertIsNone(decision)

    def test_cutoff_deadline_is_anchored_to_baseline_not_late_sample(self) -> None:
        baseline = self.baseline(now=0)
        state = soak.new_state(baseline)
        late = soak.EXPECTED_DURATION_SECONDS + 120
        soak.apply_events(state["lifecycle"], [], late, baseline)
        cutoff = state["lifecycle"]["cutoff"]
        self.assertEqual(
            cutoff["grace_deadline_epoch"],
            soak.EXPECTED_DURATION_SECONDS + soak.TERMINAL_GRACE_SECONDS,
        )

    def test_injected_terminal_is_recomputed_and_rejected(self) -> None:
        baseline = self.baseline(now=0)
        state = soak.new_state(baseline)
        self.sample(state, 60)
        fake = {
            "schema_version": soak.SCHEMA_VERSION,
            "run_id": state["run_id"],
            "baseline_sha256": state["baseline_sha256"],
            "state": "accepted",
            "accepted": True,
            "finalized_at_epoch": 60,
            "sample_count": 1,
            "last_sample_sha256": state["samples"][-1]["sample_sha256"],
            "aggregate": soak.evidence_aggregate(state),
            "lifecycle": soak.lifecycle_summary(state["lifecycle"]),
        }
        state["terminal"] = fake
        with self.assertRaisesRegex(RuntimeError, "terminal (schema|decision)"):
            soak.validate_state(state, 60)

    def test_real_zero_based_slo_attempt_log_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "main.log"
            log.write_text(
                "routing decision routing_stage=model_attempt routing_outcome=success "
                "routing_request_bucket=r1_0123456789abcdef routing_attempt=0 "
                "routing_seat_bucket= routing_provider=codex routing_model=gpt-5\n",
                encoding="utf-8",
            )
            events, _, counters = soak.read_events(log, {"inode": log.stat().st_ino, "offset": 0})
            self.assertEqual(counters["invalid"], 0)
            self.assertEqual(events[0]["routing_attempt"], "0")

    def test_post_cutoff_selection_does_not_enlarge_frozen_cohort(self) -> None:
        baseline = self.baseline(now=0)
        state = soak.new_state(baseline)
        soak.apply_events(state["lifecycle"], [], soak.EXPECTED_DURATION_SECONDS, baseline)
        self.assertEqual(soak.lifecycle_summary(state["lifecycle"])["frozen_remaining"], 0)
        late = event("account_selection", "selected", request="r1_1111111111111111")
        soak.apply_events(state["lifecycle"], [late], soak.EXPECTED_DURATION_SECONDS + 1, baseline)
        self.assertEqual(soak.lifecycle_summary(state["lifecycle"])["frozen_remaining"], 0)


class MainTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.state = root / "state"
        self.log = root / "main.log"
        self.binary = root / "binary"
        self.config = root / "config.yaml"
        self.management = root / "management.env"
        self.reconciler = root / "reconciler.env"
        self.log.write_text("", encoding="utf-8")
        self.binary.write_bytes(b"binary")
        self.config.write_text("routing:\n  strategy: least-pressure\n  auto:\n    mode: active\n", encoding="utf-8")
        self.management.write_text("MANAGEMENT_PASSWORD=x\n", encoding="utf-8")
        self.reconciler.write_text("CLIPROXY_RECONCILER_API_KEY=y\n", encoding="utf-8")
        self.argv = [
            "--state-directory", str(self.state), "--log", str(self.log),
            "--binary", str(self.binary), "--config", str(self.config),
            "--management-env", str(self.management), "--reconciler-env", str(self.reconciler),
        ]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def pressure(self) -> dict[str, object]:
        return {"schema_version": 1, "selector": "least_pressure", "active_seats": 0, "active_leases": 0, "seats": []}

    def reconcile(self) -> dict[str, object]:
        rows = [{
            "state": "ready", "generation": "gen", "runtime_generation": "gen",
            "credential_status": "active", "disabled": False,
            "durable_disabled": False, "unavailable": False,
        } for _ in range(19)]
        return {"credentials": rows}

    def api(self, path: str, _token: str) -> object:
        return self.pressure() if path.endswith("routing-pressure") else self.reconcile()

    def command(self, *args: str) -> str:
        if "ExecMainStatus" in args:
            return "0"
        if "Result" in args:
            return "success"
        return "enabled" if "is-enabled" in args else "active"

    def invoke(self, when: float) -> int:
        with mock.patch.object(soak, "api_json", side_effect=self.api), mock.patch.object(soak, "unauthenticated_status", return_value=401), mock.patch.object(soak, "command", side_effect=self.command):
            return soak.main(self.argv, now=when)

    def read_state(self) -> dict[str, object]:
        return json.loads((self.state / "state.json").read_text(encoding="utf-8"))

    def test_main_binds_artifacts_and_repairs_modes(self) -> None:
        self.assertEqual(self.invoke(1000), 0)
        state = self.read_state()
        self.assertEqual(len(state["samples"]), 1)
        for name in ("state.json", "status.json", "evidence.jsonl", "lock"):
            path = self.state / name
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        status = json.loads((self.state / "status.json").read_text(encoding="utf-8"))
        self.assertEqual(status["run_id"], state["run_id"])
        self.assertEqual(status["baseline_sha256"], state["baseline_sha256"])
        self.assertEqual(status["aggregate"]["last_sample_sha256"], state["samples"][-1]["sample_sha256"])

    def test_snapshot_failure_records_incident_without_advancing_cursor(self) -> None:
        self.assertEqual(self.invoke(1000), 0)
        before = self.read_state()
        self.log.write_text("routing decision incomplete\n", encoding="utf-8")
        with mock.patch.object(soak, "api_json", side_effect=RuntimeError("SECRET exception body")):
            self.assertEqual(soak.main(self.argv, now=1060), 1)
        after = self.read_state()
        self.assertEqual(after["cursor"], before["cursor"])
        self.assertEqual(after["samples"][-1]["failures"], ["verifier_execution"])
        self.assertNotIn("SECRET", json.dumps(after))

    def test_sensitive_log_marks_failure_without_persisting_value(self) -> None:
        self.assertEqual(self.invoke(1000), 0)
        with self.log.open("a", encoding="utf-8") as handle:
            handle.write(
                "routing decision routing_stage=account_selection routing_outcome=selected "
                "routing_request_bucket=r1_0123456789abcdef routing_attempt=1 "
                "routing_seat_bucket=h1_0123456789abcdef routing_provider=codex "
                "routing_model=gpt-5 prompt=VERY_PRIVATE_VALUE\n"
            )
        self.assertEqual(self.invoke(1060), 1)
        serialized = json.dumps(self.read_state())
        self.assertNotIn("VERY_PRIVATE_VALUE", serialized)
        self.assertIn("telemetry_privacy", serialized)

    def test_cursor_and_sample_commit_together(self) -> None:
        self.assertEqual(self.invoke(1000), 0)
        before = self.read_state()
        original = soak.atomic_write
        calls = 0

        def fail_state_once(path: Path, content: bytes) -> None:
            nonlocal calls
            if path.name == "state.json" and calls == 0:
                calls += 1
                raise OSError("simulated commit failure")
            original(path, content)

        with mock.patch.object(soak, "api_json", side_effect=self.api), mock.patch.object(soak, "unauthenticated_status", return_value=401), mock.patch.object(soak, "command", side_effect=self.command), mock.patch.object(soak, "atomic_write", side_effect=fail_state_once):
            with self.assertRaises(OSError):
                soak.main(self.argv, now=1060)
        self.assertEqual(self.read_state()["cursor"], before["cursor"])
        self.assertEqual(len(self.read_state()["samples"]), len(before["samples"]))

    def test_tampered_evidence_becomes_sticky_incident(self) -> None:
        self.assertEqual(self.invoke(1000), 0)
        (self.state / "evidence.jsonl").write_text("{}\n", encoding="utf-8")
        self.assertEqual(self.invoke(1060), 1)
        state = self.read_state()
        self.assertIn("artifact_integrity", state["samples"][-1]["failures"])
        self.assertEqual((self.state / "evidence.jsonl").read_bytes(), soak.evidence_bytes(state))

    def test_existing_terminal_is_authoritative_and_final_is_immutable(self) -> None:
        self.assertEqual(self.invoke(1000), 0)
        state = self.read_state()
        cutoff_time = float(state["baseline"]["soak_cutoff_epoch"])
        soak.apply_events(state["lifecycle"], [], cutoff_time, state["baseline"])
        deadline = cutoff_time + soak.TERMINAL_GRACE_SECONDS
        terminal = soak.terminal_decision(state, deadline)
        self.assertIsNotNone(terminal)
        state["terminal"] = terminal
        soak.atomic_write(self.state / "state.json", soak.canonical_json(state))
        soak.write_final_once(self.state / "final.json", soak.canonical_json(terminal))
        original = (self.state / "final.json").read_bytes()
        self.assertEqual(self.invoke(deadline + 1), 1)
        self.assertEqual((self.state / "final.json").read_bytes(), original)
        self.assertEqual(len(self.read_state()["samples"]), 1)

    def test_empty_reconcile_rows_cannot_green(self) -> None:
        def bad_api(path: str, _token: str) -> object:
            return self.pressure() if path.endswith("routing-pressure") else {"credentials": [{} for _ in range(19)]}

        with mock.patch.object(soak, "api_json", side_effect=bad_api), mock.patch.object(soak, "unauthenticated_status", return_value=401), mock.patch.object(soak, "command", side_effect=self.command):
            self.assertEqual(soak.main(self.argv, now=1000), 1)
        sample = self.read_state()["samples"][-1]
        self.assertFalse(sample["checks"]["reconcile_schema"])


if __name__ == "__main__":
    unittest.main()

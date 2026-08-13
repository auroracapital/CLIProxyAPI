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
    def test_routing_modes_supports_rendered_json_and_source_yaml(self) -> None:
        self.assertEqual(
            soak.routing_modes(json.dumps({"routing": {"strategy": "least-pressure", "auto": {"mode": "exclusive"}}})),
            ("least-pressure", "exclusive"),
        )
        self.assertEqual(
            soak.routing_modes("routing:\n  strategy: least-pressure\n  auto:\n    mode: reject\n"),
            ("least-pressure", "reject"),
        )

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
            {
                "seats": [{"seat_bucket": "h1_0123456789abcdef", "in_flight": leases}],
                "telemetry_instance": "p1_" + "a" * 32,
                "routing_events_dropped": 0,
                "routing_events_rejected": 0,
            },
        )

    def sample(self, state: dict[str, object], when: float, healthy: bool = True) -> None:
        checks = {name: True for name in soak.CHECK_NAMES}
        checks["binary_hash"] = healthy
        state["samples"].append(  # type: ignore[union-attr]
            soak.make_sample(
                state, when, "c" * 64, "a" * 64, "b" * 64, checks,
                self.observations(),
            )
        )

    def observations(self, telemetry: dict[str, object] | None = None) -> dict[str, object]:
        return {
            "inventory": {}, "pressure": {
                "active_leases": 0, "active_seats": 0, "frozen_active_leases": 0,
                "maximum_skew_streak_seconds": 0.0,
            },
            "events": {}, "reconciler": {}, "canary": {"result": "success", "exec_main_status": 0},
            "manual_toggles": 0,
            "telemetry": {
                "base": telemetry or {"instance": "p1_" + "a" * 32, "dropped": 0, "rejected": 0},
                "front": {"instance": "p1_" + "a" * 32, "dropped": 0, "rejected": 0},
            },
            "artifacts": {name: "0" * 64 for name in soak.ARTIFACT_ARGUMENTS},
        }

    def fill_slo(self, state: dict[str, object], count: int = soak.MIN_ELIGIBLE_REQUESTS) -> None:
        state["recovery"]["completed"] = 1
        for index in range(count):
            request = f"r1_{index:016x}"
            state["slo"]["terminal_requests"][request] = "success"
            state["slo"]["model_attempts"][request] = {"0": "success"}
        state["slo"]["deterministic_latencies_ms"] = [10] * soak.MIN_DETERMINISTIC_DECISIONS
        route = "g1_" + soak.hashlib.sha256(b"cliproxy-routing-route-v1\x00codex\x00gpt-5").hexdigest()[:16]
        state["slo"]["selection_counts"] = {
            route: {
                "h1_0123456789abcdef": count // 2,
                "h1_fedcba9876543210": count - count // 2,
            }
        }
        state["slo"]["eligible_routes"] = {route: {
            "last_sample_epoch": 1060,
            "last_seats": {"h1_0123456789abcdef": 1, "h1_fedcba9876543210": 1},
            "seats": {
                "h1_0123456789abcdef": {
                    "capacity": 1, "capacity_consistent": True, "mature": True,
                    "streak_seconds": 60.0, "eligible_seconds": 60.0,
                    "fair_selections": count // 2, "selection_cursor": count // 2,
                },
                "h1_fedcba9876543210": {
                    "capacity": 1, "capacity_consistent": True, "mature": True,
                    "streak_seconds": 60.0, "eligible_seconds": 60.0,
                    "fair_selections": count - count // 2, "selection_cursor": count - count // 2,
                },
            },
        }}

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

    def test_slo_fails_for_starved_historically_eligible_seat(self) -> None:
        state = soak.new_state(self.baseline())
        self.fill_slo(state)
        route = next(iter(state["slo"]["selection_counts"]))
        group = state["slo"]["selection_counts"][route]
        total = sum(group.values())
        group["h1_0123456789abcdef"] = total
        group["h1_fedcba9876543210"] = 0
        exposures = state["slo"]["eligible_routes"][route]["seats"]
        exposures["h1_0123456789abcdef"]["fair_selections"] = total
        exposures["h1_fedcba9876543210"]["fair_selections"] = 0
        self.assertFalse(soak.slo_summary(state["slo"])["checks"]["selection_balance"])

    def test_telemetry_restart_and_counter_changes_are_sample_failures(self) -> None:
        state = soak.new_state(self.baseline())
        baseline = soak.baseline_telemetry(state["baseline"])
        checks = {name: True for name in soak.CHECK_NAMES}
        for telemetry in (
            {**baseline, "dropped": 1},
            {**baseline, "rejected": 1},
            {**baseline, "instance": "p1_" + "b" * 32},
        ):
            candidate = dict(checks)
            candidate["telemetry_complete"] = False
            sample = soak.make_sample(
                state, 1001 + len(state["samples"]), "c" * 64, "a" * 64, "b" * 64,
                candidate, self.observations(telemetry),
            )
            state["samples"].append(sample)
        soak.validate_state(state, 1003)
        self.assertFalse(soak.evidence_aggregate(state)["window_healthy"])

    def test_telemetry_check_cannot_claim_green_after_restart(self) -> None:
        state = soak.new_state(self.baseline())
        checks = {name: True for name in soak.CHECK_NAMES}
        sample = soak.make_sample(
            state, 1001, "c" * 64, "a" * 64, "b" * 64, checks,
            self.observations({"instance": "p1_" + "b" * 32, "dropped": 0, "rejected": 0}),
        )
        state["samples"].append(sample)
        with self.assertRaisesRegex(RuntimeError, "telemetry check"):
            soak.validate_state(state, 1001)

    def test_telemetry_failure_cannot_heal_after_counter_reset(self) -> None:
        state = soak.new_state(self.baseline())
        checks = {name: True for name in soak.CHECK_NAMES}
        baseline = soak.baseline_telemetry(state["baseline"])
        failed = dict(checks)
        failed["telemetry_complete"] = False
        state["samples"].append(soak.make_sample(
            state, 1001, "c" * 64, "a" * 64, "b" * 64, failed,
            self.observations({**baseline, "dropped": 1}),
        ))
        state["samples"].append(soak.make_sample(
            state, 1061, "c" * 64, "a" * 64, "b" * 64, checks,
            self.observations(baseline),
        ))
        soak.validate_state(state, 1061)
        aggregate = soak.evidence_aggregate(state)
        self.assertFalse(aggregate["window_healthy"])
        self.assertEqual(aggregate["failure_counts"]["telemetry_complete"], 1)

    def test_fairness_requires_sustained_overlap_and_retains_mature_seats(self) -> None:
        state = soak.new_state(self.baseline())
        route = "g1_" + soak.hashlib.sha256(b"cliproxy-routing-route-v1\x00codex\x00gpt-5").hexdigest()[:16]
        a = {"seat_bucket": "h1_0123456789abcdef", "capacity": 1}
        b = {"seat_bucket": "h1_fedcba9876543210", "capacity": 1}
        c = {"seat_bucket": "h1_1111111111111111", "capacity": 1}

        soak.apply_slo_events(state["slo"], [], {"seats": [], "eligible_routes": [{"route_bucket": route, "seats": [a, b]}]}, 1000)
        soak.apply_slo_events(state["slo"], [], {"seats": [], "eligible_routes": []}, 1060)
        exposures = state["slo"]["eligible_routes"][route]["seats"]
        self.assertEqual(set(exposures), {a["seat_bucket"], b["seat_bucket"]})
        self.assertFalse(any(value["mature"] for value in exposures.values()))

        state = soak.new_state(self.baseline())
        soak.apply_slo_events(state["slo"], [], {"seats": [], "eligible_routes": [{"route_bucket": route, "seats": [a, b]}]}, 1000)
        soak.apply_slo_events(state["slo"], [], {"seats": [], "eligible_routes": [{"route_bucket": route, "seats": [a, c]}]}, 1060)
        self.assertFalse(any(value["mature"] for value in state["slo"]["eligible_routes"][route]["seats"].values()))

        state = soak.new_state(self.baseline())
        soak.apply_slo_events(state["slo"], [], {"seats": [], "eligible_routes": [{"route_bucket": route, "seats": [a, b]}]}, 1000)
        soak.apply_slo_events(state["slo"], [], {"seats": [], "eligible_routes": [{"route_bucket": route, "seats": [a, b]}]}, 1060)
        soak.apply_slo_events(state["slo"], [], {"seats": [], "eligible_routes": []}, 1120)
        exposures = state["slo"]["eligible_routes"][route]["seats"]
        self.assertTrue(exposures[a["seat_bucket"]]["mature"])
        self.assertTrue(exposures[b["seat_bucket"]]["mature"])

    def test_fairness_normalizes_capacity_and_catches_minority_starvation(self) -> None:
        state = soak.new_state(self.baseline())
        self.fill_slo(state, 300)
        route = next(iter(state["slo"]["eligible_routes"]))
        group = state["slo"]["selection_counts"][route]
        exposures = state["slo"]["eligible_routes"][route]["seats"]
        exposures["h1_0123456789abcdef"]["capacity"] = 2
        exposures["h1_0123456789abcdef"]["eligible_seconds"] = 60.0
        exposures["h1_fedcba9876543210"]["eligible_seconds"] = 60.0
        group["h1_0123456789abcdef"] = 200
        group["h1_fedcba9876543210"] = 100
        exposures["h1_0123456789abcdef"]["fair_selections"] = 200
        exposures["h1_fedcba9876543210"]["fair_selections"] = 100
        self.assertTrue(soak.slo_summary(state["slo"])["checks"]["selection_balance"])

        for index in range(15):
            seat = f"h1_{index + 2:016x}"
            exposures[seat] = {
                "capacity": 1, "capacity_consistent": True, "mature": True,
                "streak_seconds": 60.0, "eligible_seconds": 60.0,
                "fair_selections": 100, "selection_cursor": 100,
            }
            group[seat] = 100
        group["h1_fedcba9876543210"] = 0
        exposures["h1_fedcba9876543210"]["fair_selections"] = 0
        self.assertFalse(soak.slo_summary(state["slo"])["checks"]["selection_balance"])

    def test_fairness_requires_material_route_traffic_and_rejects_capacity_drift(self) -> None:
        state = soak.new_state(self.baseline())
        self.fill_slo(state)
        route = next(iter(state["slo"]["eligible_routes"]))
        group = state["slo"]["selection_counts"][route]
        group["h1_0123456789abcdef"] = 1
        group["h1_fedcba9876543210"] = 1
        for exposure in state["slo"]["eligible_routes"][route]["seats"].values():
            exposure["fair_selections"] = 1
        self.assertFalse(soak.slo_summary(state["slo"])["checks"]["comparable_seat_coverage"])

        group["h1_0123456789abcdef"] = 50
        group["h1_fedcba9876543210"] = 50
        for exposure in state["slo"]["eligible_routes"][route]["seats"].values():
            exposure["fair_selections"] = 50
        state["slo"]["eligible_routes"][route]["seats"]["h1_0123456789abcdef"]["capacity_consistent"] = False
        self.assertFalse(soak.slo_summary(state["slo"])["checks"]["selection_balance"])

    def test_pressure_schema_rejects_unknown_fields_bools_and_duplicates(self) -> None:
        valid = {
            "schema_version": 2, "selector": "least_pressure", "active_seats": 0,
            "active_leases": 0, "seats": [], "eligible_routes": [],
            "telemetry_instance": "p1_" + "a" * 32,
            "routing_events_dropped": 0, "routing_events_rejected": 0,
        }
        self.assertTrue(soak.valid_pressure_snapshot(valid))
        for mutation in (
            {**valid, "debug": "private"},
            {**valid, "routing_events_dropped": False},
            {**valid, "active_leases": True},
            {**valid, "telemetry_instance": "p1_short"},
            {**valid, "eligible_routes": [
                {"route_bucket": "g1_0123456789abcdef", "seats": []},
                {"route_bucket": "g1_0123456789abcdef", "seats": []},
            ]},
        ):
            self.assertFalse(soak.valid_pressure_snapshot(mutation))

    def test_route_pressure_streak_is_route_scoped_zero_filled_and_resets(self) -> None:
        route = "g1_0123456789abcdef"
        a = {"seat_bucket": "h1_0123456789abcdef", "capacity": 1}
        b = {"seat_bucket": "h1_fedcba9876543210", "capacity": 1}
        state = {"routes": {}, "maximum_skew_streak_seconds": 0.0}

        def pressure(active: int, seats: list[dict[str, object]]) -> dict[str, object]:
            rows = [] if active == 0 else [{
                "seat_bucket": a["seat_bucket"], "in_flight": 1, "capacity": 1,
                "concurrency_pressure_milli": active,
            }]
            return {"seats": rows, "eligible_routes": [{"route_bucket": route, "seats": seats}]}

        soak.apply_route_pressure(state, pressure(1000, [a, b]), 1000)
        for when in (1060, 1120, 1180, 1240, 1300, 1360):
            soak.apply_route_pressure(state, pressure(1000, [a, b]), when)
        self.assertEqual(state["routes"][route]["streak_seconds"], 360)
        self.assertGreater(state["maximum_skew_streak_seconds"], soak.PRESSURE_SKEW_MAX_SECONDS)
        soak.apply_route_pressure(state, pressure(0, [a, b]), 1420)
        self.assertEqual(state["routes"][route]["streak_seconds"], 0)
        soak.apply_route_pressure(state, pressure(1000, [a]), 1480)
        self.assertEqual(state["routes"][route]["streak_seconds"], 0)

    def test_journal_anchor_chain_recovery_and_prefix_mutation_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / "journal.jsonl"
            journal.write_bytes(b"")
            os.chmod(journal, 0o600)
            cursor = soak.journal_anchor(journal)
            previous = "0" * 64
            records = []
            specs = [
                ("refresh", "started", "ready", "refreshing", "none"),
                ("refresh", "succeeded", "refreshing", "probing", "refresh_succeeded"),
                ("probe_start", "started", "probing", "probing", "refresh_succeeded"),
                ("probe_result", "succeeded", "probing", "ready", "none"),
                ("readmission", "succeeded", "probing", "ready", "none"),
            ]
            for seq, (action, outcome, prior, result, reason) in enumerate(specs, 1):
                unsigned = {
                    "version": 1, "seq": seq, "timestamp": f"2026-08-13T00:0{seq}:00+00:00",
                    "seat_bucket": "a" * 32, "action": action, "outcome": outcome,
                    "prior": prior, "result": result, "reason": reason, "previous_hash": previous,
                }
                previous = soak.journal_record_hash(unsigned)
                records.append({**unsigned, "hash": previous})
            with journal.open("ab") as handle:
                handle.write(b"".join(soak.canonical_json(record) for record in records))
            events, next_cursor = soak.read_reconciler_journal(journal, cursor)
            recovery = {"journal_cursor": cursor, "seats": {}, "completed": 0, "events_sha256": "0" * 64}
            soak.apply_recovery_events(recovery, events)
            recovery["journal_cursor"] = next_cursor
            self.assertEqual(recovery["completed"], 1)

            replacement = Path(directory) / "replacement"
            replacement.write_bytes(journal.read_bytes())
            os.chmod(replacement, 0o600)
            os.replace(replacement, journal)
            with self.assertRaisesRegex(RuntimeError, "discontinuity"):
                soak.read_reconciler_journal(journal, next_cursor)

    def test_recovery_chain_is_same_seat_and_requires_readmission(self) -> None:
        recovery = {"journal_cursor": self.baseline()["reconciler_journal_cursor"], "seats": {}, "completed": 0, "events_sha256": "0" * 64}
        events = [
            {"seat_bucket": "a" * 32, "action": "refresh", "outcome": "started", "prior": "ready", "result": "refreshing", "reason": "none"},
            {"seat_bucket": "b" * 32, "action": "probe_result", "outcome": "succeeded", "prior": "probing", "result": "ready", "reason": "none"},
            {"seat_bucket": "a" * 32, "action": "readmission", "outcome": "succeeded", "prior": "probing", "result": "ready", "reason": "none"},
        ]
        soak.apply_recovery_events(recovery, events)
        self.assertEqual(recovery["completed"], 0)

    def test_journal_rejects_sequence_gap_and_partial_append(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            journal = Path(directory) / "journal.jsonl"
            journal.write_bytes(b"")
            os.chmod(journal, 0o600)
            cursor = soak.journal_anchor(journal)
            unsigned = {
                "version": 1, "seq": 2, "timestamp": "2026-08-13T00:01:00+00:00",
                "seat_bucket": "a" * 32, "action": "refresh", "outcome": "started",
                "prior": "ready", "result": "refreshing", "reason": "none",
                "previous_hash": "0" * 64,
            }
            journal.write_bytes(soak.canonical_json({**unsigned, "hash": soak.journal_record_hash(unsigned)}))
            with self.assertRaisesRegex(RuntimeError, "record"):
                soak.read_reconciler_journal(journal, cursor)

            journal.write_bytes(b'{"partial":')
            with self.assertRaisesRegex(RuntimeError, "mutation"):
                soak.read_reconciler_journal(journal, cursor)

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
                "routing decision routing_schema_version=1 routing_stage=model_attempt routing_mode=active "
                "routing_task=code routing_score_version=v2 routing_model=gpt-5 routing_provider=codex "
                "routing_reason= routing_outcome=success routing_attempt=0 routing_candidate_count=1 "
                "routing_duration_ms=0 routing_selector=least_pressure routing_shadow_match=false "
                "routing_seat_bucket= routing_predicted_seat_bucket= "
                "routing_request_bucket=r1_0123456789abcdef\n",
                encoding="utf-8",
            )
            events, _, counters = soak.read_events(log, {"inode": log.stat().st_ino, "offset": 0})
            self.assertEqual(counters["invalid"], 0)
            self.assertEqual(events[0]["routing_attempt"], "0")

    def test_unknown_routing_field_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "main.log"
            log.write_text(
                "routing decision routing_schema_version=1 routing_stage=account_selection routing_mode=active "
                "routing_task= routing_score_version= routing_model=gpt-5 routing_provider=codex "
                "routing_reason= routing_outcome=selected routing_attempt=1 routing_candidate_count=0 "
                "routing_duration_ms=0 routing_selector=least_pressure routing_shadow_match=false "
                "routing_seat_bucket=h1_0123456789abcdef routing_predicted_seat_bucket= "
                "routing_request_bucket=r1_0123456789abcdef routing_debug=sk-opaquevalue\n",
                encoding="utf-8",
            )
            events, _, counters = soak.read_events(log, {"inode": log.stat().st_ino, "offset": 0})
            self.assertEqual(events, [])
            self.assertEqual(counters["invalid"], 1)

    def test_post_cutoff_selection_does_not_enlarge_frozen_cohort(self) -> None:
        baseline = self.baseline(now=0)
        state = soak.new_state(baseline)
        soak.apply_events(state["lifecycle"], [], soak.EXPECTED_DURATION_SECONDS, baseline)
        self.assertEqual(soak.lifecycle_summary(state["lifecycle"])["frozen_remaining"], 0)
        late = event("account_selection", "selected", request="r1_1111111111111111")
        soak.apply_events(state["lifecycle"], [late], soak.EXPECTED_DURATION_SECONDS + 1, baseline)
        self.assertEqual(soak.lifecycle_summary(state["lifecycle"])["frozen_remaining"], 0)

    def test_post_cutoff_unrelated_pressure_does_not_block_frozen_drain(self) -> None:
        baseline = self.baseline(now=0)
        state = soak.new_state(baseline)
        selected = event("account_selection", "selected")
        terminal = event("account_attempt", "success")
        soak.apply_events(state["lifecycle"], [selected], soak.EXPECTED_DURATION_SECONDS, baseline)
        soak.apply_events(state["lifecycle"], [terminal], soak.EXPECTED_DURATION_SECONDS + 30, baseline)
        self.fill_slo(state)
        for when in range(60, soak.EXPECTED_DURATION_SECONDS + 1, 60):
            self.sample(state, when)
        self.sample(state, soak.EXPECTED_DURATION_SECONDS + 30)
        self.sample(state, soak.EXPECTED_DURATION_SECONDS + 90)
        for sample in state["samples"][-2:]:
            sample["observations"]["pressure"]["active_leases"] = 7
            sample["observations"]["pressure"]["active_seats"] = 3
            unsigned = dict(sample)
            unsigned.pop("sample_sha256")
            sample["sample_sha256"] = soak.object_hash(unsigned)
        state["samples"][-1]["previous_sample_sha256"] = state["samples"][-2]["sample_sha256"]
        unsigned = dict(state["samples"][-1])
        unsigned.pop("sample_sha256")
        state["samples"][-1]["sample_sha256"] = soak.object_hash(unsigned)
        decision = soak.terminal_decision(state, soak.EXPECTED_DURATION_SECONDS + 90)
        self.assertIsNotNone(decision)
        self.assertTrue(decision["accepted"])


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
        self.front_management = root / "front-management.env"
        self.front_log = root / "front-main.log"
        self.journal = root / "journal.jsonl"
        self.proc = root / "proc"
        self.proc.mkdir()
        self.artifacts = [root / f"artifact-{index}" for index in range(len(soak.ARTIFACT_ARGUMENTS))]
        self.log.write_text("", encoding="utf-8")
        self.front_log.write_text("", encoding="utf-8")
        self.binary.write_bytes(b"binary")
        self.config.write_text("routing:\n  strategy: least-pressure\n  auto:\n    mode: reject\n", encoding="utf-8")
        self.management.write_text("MANAGEMENT_PASSWORD=x\n", encoding="utf-8")
        self.reconciler.write_text("CLIPROXY_RECONCILER_API_KEY=y\n", encoding="utf-8")
        self.front_management.write_text("AUTO_ROUTER_MANAGEMENT_PASSWORD=z\n", encoding="utf-8")
        self.journal.write_bytes(b"")
        os.chmod(self.journal, 0o600)
        for artifact in self.artifacts:
            artifact.write_bytes(b"artifact")
        router_config = self.artifacts[list(soak.ARTIFACT_ARGUMENTS).index("router_config")]
        router_config.write_text(json.dumps({
            "schema_version": 1,
            "listen": {"host": "127.0.0.1", "port": 8320},
            "base": {"url": "http://127.0.0.1:8319/v1", "provider": "base", "models": ["model"]},
            "routing": {"default_models": ["model"], "task_models": {}, "objective": "balanced", "provider_strategy": "health"},
        }), encoding="utf-8")
        router_runtime_config = self.artifacts[list(soak.ARTIFACT_ARGUMENTS).index("router_runtime_config")]
        router_runtime_config.write_text("routing:\n  auto:\n    mode: exclusive\n", encoding="utf-8")
        artifact_args = []
        for (name, argument), path in zip(soak.ARTIFACT_ARGUMENTS.items(), self.artifacts):
            artifact_args.extend(["--" + argument.replace("_", "-"), str(path)])
        self.argv = [
            "--state-directory", str(self.state), "--log", str(self.log),
            "--binary", str(self.binary), "--config", str(self.config),
            "--management-env", str(self.management), "--reconciler-env", str(self.reconciler),
            "--front-log", str(self.front_log), "--front-management-env", str(self.front_management),
            "--reconciler-journal", str(self.journal), *artifact_args,
            "--proc-root", str(self.proc),
        ]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def pressure(self) -> dict[str, object]:
        return {
            "schema_version": 2, "selector": "least_pressure", "active_seats": 0,
            "active_leases": 0, "seats": [], "eligible_routes": [],
            "telemetry_instance": "p1_" + "a" * 32,
            "routing_events_dropped": 0, "routing_events_rejected": 0,
        }

    def reconcile(self) -> dict[str, object]:
        rows = [{
            "state": "ready", "generation": "gen", "runtime_generation": "gen",
            "credential_status": "active", "disabled": False,
            "durable_disabled": False, "unavailable": False,
        } for _ in range(20)]
        return {"credentials": rows}

    def api(self, path: str, _token: str, _base_url: str = "") -> object:
        return self.pressure() if path.endswith("routing-pressure") else self.reconcile()

    def command(self, *args: str) -> str:
        if "ConditionResult" in args:
            return "no"
        if "ActiveState" in args:
            return "inactive"
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

    def test_pinned_router_and_reconciler_artifact_drift_is_sticky(self) -> None:
        self.assertEqual(self.invoke(1000), 0)
        router = self.artifacts[list(soak.ARTIFACT_ARGUMENTS).index("router_binary")]
        original = router.read_bytes()
        router.write_bytes(b"drift")
        self.assertEqual(self.invoke(1060), 1)
        state = self.read_state()
        self.assertIn("router_binary_hash", state["samples"][-1]["failures"])
        router.write_bytes(original)
        self.assertEqual(self.invoke(1120), 0)
        self.assertFalse(soak.evidence_aggregate(self.read_state())["window_healthy"])

    def test_front_and_base_telemetry_are_independently_consumed(self) -> None:
        self.assertEqual(self.invoke(1000), 0)
        self.front_log.write_text(
            "routing decision routing_schema_version=1 routing_stage=model_decision routing_mode=active "
            "routing_task=code routing_score_version=v2 routing_model=gpt-5.6-sol routing_provider= "
            "routing_reason=keyword_code routing_outcome=selected routing_attempt=0 "
            "routing_candidate_count=1 routing_duration_ms=1 routing_selector= "
            "routing_shadow_match=false routing_seat_bucket= routing_predicted_seat_bucket= "
            "routing_request_bucket=r1_1111111111111111\n",
            encoding="utf-8",
        )
        self.log.write_text(
            "routing decision routing_schema_version=1 routing_stage=account_selection routing_mode=active "
            "routing_task= routing_score_version= routing_model=gpt-5.6-sol routing_provider=codex "
            "routing_reason= routing_outcome=selected routing_attempt=1 routing_candidate_count=0 "
            "routing_duration_ms=0 routing_selector=least_pressure routing_shadow_match=false "
            "routing_seat_bucket=h1_0123456789abcdef routing_predicted_seat_bucket= "
            "routing_request_bucket=r1_2222222222222222\n",
            encoding="utf-8",
        )
        self.assertEqual(self.invoke(1060), 0)
        state = self.read_state()
        self.assertEqual(len(state["slo"]["deterministic_latencies_ms"]), 1)
        self.assertEqual(sum(state["lifecycle"]["selected"].values()), 1)
        self.assertGreater(state["front_cursor"]["offset"], 0)
        self.assertGreater(state["cursor"]["offset"], 0)

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
        def bad_api(path: str, _token: str, _base_url: str = "") -> object:
            return self.pressure() if path.endswith("routing-pressure") else {"credentials": [{} for _ in range(20)]}

        with mock.patch.object(soak, "api_json", side_effect=bad_api), mock.patch.object(soak, "unauthenticated_status", return_value=401), mock.patch.object(soak, "command", side_effect=self.command):
            self.assertEqual(soak.main(self.argv, now=1000), 1)
        sample = self.read_state()["samples"][-1]
        self.assertFalse(sample["checks"]["reconcile_schema"])

    def test_not_all_desired_accounts_ready_cannot_green(self) -> None:
        def degraded_api(path: str, _token: str, _base_url: str = "") -> object:
            if path.endswith("routing-pressure"):
                return self.pressure()
            rows = self.reconcile()["credentials"]
            rows[0] = {**rows[0], "state": "auth_required"}
            return {"credentials": rows}

        with mock.patch.object(soak, "api_json", side_effect=degraded_api), mock.patch.object(soak, "unauthenticated_status", return_value=401), mock.patch.object(soak, "command", side_effect=self.command):
            self.assertEqual(soak.main(self.argv, now=1000), 1)
        sample = self.read_state()["samples"][-1]
        self.assertFalse(sample["checks"]["all_desired_accounts_ready"])

    def test_competing_reauth_process_fails_closed(self) -> None:
        process = self.proc / "123"
        process.mkdir()
        (process / "cmdline").write_bytes(b"python\0/opt/crsproxy/auto_reauth.py\0")
        self.assertEqual(self.invoke(1000), 1)
        sample = self.read_state()["samples"][-1]
        self.assertFalse(sample["checks"]["no_competing_reauth_processes"])

    def test_unfenced_legacy_reauth_unit_fails_closed(self) -> None:
        def command(*args: str) -> str:
            if "ConditionResult" in args:
                return "yes"
            return self.command(*args)

        with mock.patch.object(soak, "api_json", side_effect=self.api), mock.patch.object(soak, "unauthenticated_status", return_value=401), mock.patch.object(soak, "command", side_effect=command):
            self.assertEqual(soak.main(self.argv, now=1000), 1)
        sample = self.read_state()["samples"][-1]
        self.assertFalse(sample["checks"]["single_reauth_owner"])


if __name__ == "__main__":
    unittest.main()

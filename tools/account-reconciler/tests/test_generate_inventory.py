import contextlib
import importlib.util
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "generate_inventory.py"
SPEC = importlib.util.spec_from_file_location("generate_inventory", MODULE_PATH)
generator = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(generator)


class FakeAPI:
    def __init__(self, status, files, models):
        self.status_rows = status
        self.file_rows = files
        self.models_by_index = models
        self.model_calls = []

    def reconcile_status(self):
        return self.status_rows

    def auth_files(self):
        return self.file_rows

    def models(self, name, auth_index):
        self.model_calls.append((name, auth_index))
        return self.models_by_index[auth_index]


def auth_index(provider, path):
    return generator._stable_auth_index(provider, path)


class GenerateInventoryTests(unittest.TestCase):
    def build_pool(self, root, count=19):
        auth_dir = root / "auths"
        candidate_dir = root / "candidates"
        auth_dir.mkdir(mode=0o700)
        status = []
        files = []
        models = {}
        tokens = []
        identities = []
        providers = ("claude", "codex", "xai", "antigravity", "kimi")
        preferred = {
            "claude": "claude-haiku-4-5-20251001",
            "codex": "gpt-5.4-mini",
            "xai": "grok-3-mini-fast",
            "antigravity": "gemini-3.1-flash-lite",
            "kimi": "kimi-k2",
        }
        for number in range(count):
            provider = providers[number % len(providers)]
            path = auth_dir / f"seat-{number:02d}.json"
            token = f"secret-token-{number}"
            identity = f"private-identity-{number}"
            value = {"type": provider, "access_token": token, "refresh_token": f"refresh-{number}"}
            if provider == "claude":
                value["account_uuid"] = identity
            elif provider == "codex":
                value["account_id"] = identity
            elif provider == "xai":
                value["sub"] = identity
            elif provider == "antigravity":
                value["project_id"] = identity
            else:
                value["device_id"] = identity
            path.write_text(json.dumps(value), encoding="utf-8")
            os.chmod(path, 0o600)
            index = auth_index(provider, path)
            status.append({"auth_index": index, "provider": provider, "credential_status": "active", "disabled": False, "unavailable": False, "state": "ready"})
            files.append({"auth_index": index, "provider": provider, "name": path.name, "path": str(path), "runtime_only": False})
            models[index] = [{"id": "expensive-model"}, {"id": preferred[provider]}]
            tokens.append(token)
            identities.append(identity)
        return auth_dir, candidate_dir, FakeAPI(status, files, models), tokens, identities

    def test_generates_exact_file_pool_and_deterministic_models(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            auth_dir, candidate_dir, api, _, _ = self.build_pool(root)
            inventory, providers = generator.generate_inventory(api, auth_dir, candidate_dir)
            self.assertEqual(len(inventory["seats"]), 19)
            self.assertEqual(sum(providers.values()), 19)
            self.assertEqual(len(api.model_calls), 19)
            for seat in inventory["seats"]:
                self.assertEqual(Path(seat["canonical_path"]).parent, auth_dir)
                self.assertEqual(Path(seat["candidate_path"]).parent, candidate_dir)
                self.assertIn("access_token", seat["required_keys"])
                self.assertTrue(seat["expected_fields"])

    def test_fails_closed_on_incomplete_mismatch_unknown_model_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            auth_dir, candidate_dir, api, _, _ = self.build_pool(root, count=1)
            cases = []
            cases.append(FakeAPI(api.status_rows + [{"auth_index": "missing", "provider": "claude"}], api.file_rows, api.models_by_index))
            mismatched = [dict(api.file_rows[0], provider="codex")]
            cases.append(FakeAPI(api.status_rows, mismatched, api.models_by_index))
            cases.append(FakeAPI(api.status_rows, api.file_rows + [{"auth_index": "extra", "provider": "claude"}], api.models_by_index))
            cases.append(FakeAPI(api.status_rows, api.file_rows, {api.status_rows[0]["auth_index"]: [{"id": "unapproved"}]}))
            for candidate in cases:
                with self.subTest(candidate=candidate), self.assertRaises(generator.GenerationError):
                    generator.generate_inventory(candidate, auth_dir, candidate_dir)
            path = Path(api.file_rows[0]["path"])
            target = root / "target.json"
            target.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
            path.unlink()
            path.symlink_to(target)
            with self.assertRaises(generator.GenerationError):
                generator.generate_inventory(api, auth_dir, candidate_dir)

    def test_fails_closed_without_tokens_or_stable_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            auth_dir, candidate_dir, api, _, _ = self.build_pool(root, count=1)
            path = Path(api.file_rows[0]["path"])
            path.write_text(json.dumps({"type": "claude", "account_uuid": "identity"}), encoding="utf-8")
            with self.assertRaises(generator.GenerationError):
                generator.generate_inventory(api, auth_dir, candidate_dir)
            path.write_text(json.dumps({"type": "claude", "access_token": "token"}), encoding="utf-8")
            with self.assertRaises(generator.GenerationError):
                generator.generate_inventory(api, auth_dir, candidate_dir)

    def test_disabled_seat_uses_registered_same_provider_model(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            auth_dir, candidate_dir, api, _, _ = self.build_pool(root, count=2)
            disabled = api.status_rows[1]
            disabled["provider"] = "claude"
            disabled["credential_status"] = "disabled"
            disabled["disabled"] = True
            disabled_path = Path(api.file_rows[1]["path"])
            disabled_value = json.loads(disabled_path.read_text(encoding="utf-8"))
            disabled_value["type"] = "claude"
            disabled_value["account_uuid"] = disabled_value.pop("account_id")
            disabled_path.write_text(json.dumps(disabled_value), encoding="utf-8")
            new_index = auth_index("claude", disabled_path)
            disabled["auth_index"] = new_index
            api.file_rows[1]["auth_index"] = new_index
            api.file_rows[1]["provider"] = "claude"
            api.models_by_index[new_index] = []
            inventory, _ = generator.generate_inventory(api, auth_dir, candidate_dir)
            by_index = {seat["auth_index"]: seat for seat in inventory["seats"]}
            self.assertEqual(by_index[new_index]["model"], "claude-haiku-4-5-20251001")

    def test_disabled_seat_without_registered_same_provider_model_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            auth_dir, candidate_dir, api, _, _ = self.build_pool(root, count=1)
            api.status_rows[0]["credential_status"] = "disabled"
            api.status_rows[0]["disabled"] = True
            api.models_by_index[api.status_rows[0]["auth_index"]] = []
            with self.assertRaises(generator.GenerationError):
                generator.generate_inventory(api, auth_dir, candidate_dir)

    def test_atomic_write_enforces_mode_and_replaces_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "account-inventory.json"
            inventory = {"version": 1, "seats": []}
            generator.atomic_write_inventory(output, inventory, os.getuid(), os.getgid(), 0o640)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), inventory)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o640)
            generator.atomic_write_inventory(output, {"version": 1, "seats": [1]}, os.getuid(), os.getgid(), 0o640)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["seats"], [1])
            with self.assertRaises(generator.GenerationError):
                generator.atomic_write_inventory(output, inventory, os.getuid(), os.getgid(), 0o600)
            output.unlink()
            output.symlink_to(Path(directory) / "missing-target")
            with self.assertRaises(generator.GenerationError):
                generator.atomic_write_inventory(output, inventory, os.getuid(), os.getgid(), 0o640)

    def test_main_dry_run_writes_nothing_and_output_is_secret_free(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            auth_dir, candidate_dir, api, tokens, identities = self.build_pool(root, count=1)
            output = root / "account-inventory.json"
            stream = io.StringIO()
            with (
                mock.patch.object(generator, "require_hub"),
                mock.patch.object(generator, "APIClient", return_value=api),
                mock.patch.dict(os.environ, {"CLIPROXY_RECONCILER_API_KEY": "management-secret"}),
                contextlib.redirect_stdout(stream),
            ):
                result = generator.main(["--auth-dir", str(auth_dir), "--candidate-dir", str(candidate_dir), "--output", str(output)])
            self.assertEqual(result, 0)
            self.assertFalse(output.exists())
            rendered = stream.getvalue()
            self.assertEqual(json.loads(rendered)["mode"], "dry_run")
            for secret in tokens + identities + ["management-secret", str(auth_dir)]:
                self.assertNotIn(secret, rendered)

    def test_host_and_loopback_guards(self):
        generator.require_hub("healify-hub.tail6aeed8.ts.net")
        with self.assertRaises(generator.GenerationError):
            generator.require_hub("sams-mac-max")
        with self.assertRaises(generator.GenerationError):
            generator.APIClient("http://100.127.244.3:8319", "key")
        with self.assertRaises(generator.GenerationError):
            generator.APIClient("http://127.0.0.1:8319", "")


if __name__ == "__main__":
    unittest.main()

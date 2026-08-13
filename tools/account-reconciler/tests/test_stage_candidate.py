import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "stage_candidate.py"
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("stage_candidate", MODULE_PATH)
stage_candidate = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(stage_candidate)


class StageCandidateTests(unittest.TestCase):
    def fixture(self, root: Path):
        auths = root / "auths"
        candidates = root / "candidates"
        auths.mkdir(mode=0o700)
        candidates.mkdir(mode=0o700)
        inventory = root / "inventory.json"
        inventory.write_text(json.dumps({
            "version": 1,
            "seats": [
                {
                    "auth_index": "claude-seat",
                    "provider": "claude",
                    "model": "probe-model",
                    "canonical_path": str(auths / "claude.json"),
                    "candidate_path": str(candidates / "claude.json"),
                    "required_keys": ["access_token", "refresh_token"],
                    "expected_fields": {"account_uuid": "account-a", "email": "a@example.test"},
                },
                {
                    "auth_index": "xai-seat",
                    "provider": "xai",
                    "model": "probe-model",
                    "canonical_path": str(auths / "xai.json"),
                    "candidate_path": str(candidates / "xai.json"),
                    "required_keys": ["access_token", "refresh_token"],
                    "expected_fields": {"sub": "subject-b", "email": "b@example.test"},
                },
            ],
        }), encoding="utf-8")
        source = root / "fresh.json"
        return inventory, source, candidates

    def write_source(self, source: Path, value: dict, mode: int = 0o600):
        source.write_text(json.dumps(value), encoding="utf-8")
        source.chmod(mode)

    def test_uniquely_matches_and_atomically_installs_exact_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, source, candidates = self.fixture(root)
            value = {
                "type": "claude", "account_uuid": "account-a", "email": "a@example.test",
                "access_token": "access", "refresh_token": "refresh",
            }
            self.write_source(source, value)

            stage_candidate.stage(source, inventory, os.getuid(), os.getgid())

            candidate = candidates / "claude.json"
            self.assertEqual(json.loads(candidate.read_text(encoding="utf-8")), value)
            self.assertEqual(stat.S_IMODE(candidate.stat().st_mode), 0o600)
            self.assertTrue(source.exists())
            self.assertFalse((candidates / "xai.json").exists())

    def test_rejects_identity_provider_required_key_mode_and_existing_candidate(self):
        cases = (
            ({"type": "claude", "account_uuid": "wrong", "email": "a@example.test", "access_token": "a", "refresh_token": "r"}, 0o600),
            ({"type": "codex", "account_uuid": "account-a", "email": "a@example.test", "access_token": "a", "refresh_token": "r"}, 0o600),
            ({"type": "claude", "account_uuid": "account-a", "email": "a@example.test", "access_token": "a"}, 0o600),
            ({"type": "claude", "account_uuid": "account-a", "email": "a@example.test", "access_token": "a", "refresh_token": "r"}, 0o644),
        )
        for value, mode in cases:
            with self.subTest(value=value, mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                inventory, source, candidates = self.fixture(root)
                self.write_source(source, value, mode)
                with self.assertRaises(stage_candidate.StagingError):
                    stage_candidate.stage(source, inventory, os.getuid(), os.getgid())
                self.assertEqual(list(candidates.iterdir()), [])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, source, candidates = self.fixture(root)
            value = {
                "type": "claude", "account_uuid": "account-a", "email": "a@example.test",
                "access_token": "a", "refresh_token": "r",
            }
            self.write_source(source, value)
            (candidates / "claude.json").write_text("existing", encoding="utf-8")
            with self.assertRaises(stage_candidate.StagingError):
                stage_candidate.stage(source, inventory, os.getuid(), os.getgid())
            self.assertEqual((candidates / "claude.json").read_text(encoding="utf-8"), "existing")

    def test_rejects_symlink_source_and_ambiguous_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, source, candidates = self.fixture(root)
            target = root / "target.json"
            self.write_source(target, {
                "type": "claude", "account_uuid": "account-a", "email": "a@example.test",
                "access_token": "a", "refresh_token": "r",
            })
            source.symlink_to(target)
            with self.assertRaises(stage_candidate.StagingError):
                stage_candidate.stage(source, inventory, os.getuid(), os.getgid())
            self.assertEqual(list(candidates.iterdir()), [])

            data = json.loads(inventory.read_text(encoding="utf-8"))
            duplicate = dict(data["seats"][0])
            duplicate["auth_index"] = "duplicate"
            duplicate["canonical_path"] = str(root / "auths" / "duplicate.json")
            duplicate["candidate_path"] = str(candidates / "duplicate.json")
            data["seats"].append(duplicate)
            inventory.write_text(json.dumps(data), encoding="utf-8")
            source.unlink()
            self.write_source(source, json.loads(target.read_text(encoding="utf-8")))
            with self.assertRaises(stage_candidate.StagingError):
                stage_candidate.stage(source, inventory, os.getuid(), os.getgid())
            self.assertEqual(list(candidates.iterdir()), [])


if __name__ == "__main__":
    unittest.main()

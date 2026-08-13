from __future__ import annotations

import importlib.util
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("soak_canary", ROOT / "soak_canary.py")
assert SPEC and SPEC.loader
canary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(canary)


class Response(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


class SoakCanaryTests(unittest.TestCase):
    def test_request_is_auto_code_and_requires_expected_model(self):
        captured = {}

        def open_request(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return Response(json.dumps({"model": "gpt-5.6-sol", "choices": [{}]}).encode())

        with mock.patch.object(canary.urllib.request, "urlopen", side_effect=open_request):
            canary.request_once("secret-key", timeout=12)

        request = captured["request"]
        body = json.loads(request.data)
        self.assertEqual(body["model"], "auto")
        self.assertIn("Go router", body["messages"][0]["content"])
        self.assertFalse(body["stream"])
        self.assertEqual(captured["timeout"], 12)
        self.assertEqual(request.get_header("Authorization"), "Bearer secret-key")

        with mock.patch.object(
            canary.urllib.request, "urlopen",
            return_value=Response(json.dumps({"model": "unexpected", "choices": [{}]}).encode()),
        ):
            with self.assertRaises(canary.CanaryError):
                canary.request_once("secret-key")

    def test_key_requires_private_regular_owned_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / "key"
            key.write_text("secret\n", encoding="utf-8")
            key.chmod(0o600)
            self.assertEqual(canary.read_key(key), "secret")
            key.chmod(0o640)
            with self.assertRaises(canary.CanaryError):
                canary.read_key(key)
            if os.geteuid() == 0:
                key.chmod(0o440)
                self.assertEqual(canary.read_key(key), "secret")
            target = root / "target"
            target.write_text("secret", encoding="utf-8")
            target.chmod(0o600)
            key.unlink()
            key.symlink_to(target)
            with self.assertRaises(canary.CanaryError):
                canary.read_key(key)

    def test_units_are_hardened_disabled_by_default_and_five_minute(self):
        service = (ROOT / "systemd" / "cliproxy-smart-router-canary.service").read_text(encoding="utf-8")
        timer = (ROOT / "systemd" / "cliproxy-smart-router-canary.timer").read_text(encoding="utf-8")
        self.assertIn("DynamicUser=yes", service)
        self.assertIn("LoadCredential=client-key:/etc/crsproxy/auto-router-client-key", service)
        self.assertIn("IPAddressAllow=localhost", service)
        self.assertNotIn("Environment=", service)
        self.assertIn("OnUnitInactiveSec=5min", timer)
        self.assertIn("Persistent=true", timer)
        self.assertNotIn("WantedBy=timers.target", service)


if __name__ == "__main__":
    unittest.main()

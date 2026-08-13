from __future__ import annotations

import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location("render_config", ROOT / "render_config.py")
assert SPEC is not None and SPEC.loader is not None
renderer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(renderer)


class AutoRouterArtifactTests(unittest.TestCase):
    def policy(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "listen": {"host": "127.0.0.1", "port": 8320},
            "base": {
                "url": "http://127.0.0.1:8319/v1",
                "provider": "cliproxy-base",
                "models": ["model-fast", "model-strong"],
            },
            "routing": {
                "default_models": ["model-fast", "model-strong"],
                "task_models": {"code": ["model-strong"], "general": ["model-fast"]},
                "objective": "balanced",
                "provider_strategy": "health",
            },
        }

    def test_rendered_config_is_loopback_only_and_forwards_explicit_models(self) -> None:
        policy = self.policy()
        config = renderer.rendered_config(policy, "front-secret", "base-secret", Path("/var/lib/cliproxy-auto-router"))
        self.assertEqual((config["host"], config["port"]), ("127.0.0.1", 8320))
        self.assertTrue(config["commercial-mode"])
        self.assertFalse(config["logging-to-file"])
        self.assertEqual(config["routing"]["auto"]["mode"], "exclusive")
        provider = config["openai-compatibility"][0]
        self.assertEqual(provider["base-url"], "http://127.0.0.1:8319/v1")
        self.assertEqual(provider["api-key-entries"], [{"api-key": "base-secret"}])
        self.assertEqual(
            provider["models"],
            [{"name": "model-fast", "alias": "model-fast"}, {"name": "model-strong", "alias": "model-strong"}],
        )
        self.assertNotIn(8317, json.loads(json.dumps(config)).values())

    def test_renderer_writes_private_runtime_config_and_no_secret_in_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_path = root / "auto-router.yaml"
            policy_path.write_text(json.dumps(self.policy()), encoding="utf-8")
            client_key = root / "client-key"
            base_key = root / "base-key"
            client_key.write_text("front-secret\n", encoding="utf-8")
            base_key.write_text("base-secret\n", encoding="utf-8")
            policy = renderer.load_policy(policy_path)
            output = root / "run" / "config.yaml"
            renderer.atomic_write(
                output,
                renderer.rendered_config(
                    policy,
                    renderer.regular_secret(client_key),
                    renderer.regular_secret(base_key),
                    root / "state",
                ),
            )
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertNotIn("front-secret", policy_path.read_text(encoding="utf-8"))
            self.assertNotIn("base-secret", policy_path.read_text(encoding="utf-8"))
            rendered = output.read_text(encoding="utf-8")
            self.assertIn("front-secret", rendered)
            self.assertIn("base-secret", rendered)

    def test_renderer_rejects_symlinked_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir(mode=0o700)
            linked = root / "linked"
            linked.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink"):
                renderer.atomic_write(linked / "config.yaml", {"safe": True})

    def test_policy_rejects_wrong_ports_and_unknown_models(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.yaml"
            policy = self.policy()
            policy["listen"]["port"] = 8317
            path.write_text(json.dumps(policy), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "8320"):
                renderer.load_policy(path)
            policy = self.policy()
            policy["routing"]["default_models"] = ["not-configured"]
            path.write_text(json.dumps(policy), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "absent"):
                renderer.load_policy(path)

    def test_systemd_unit_uses_credentials_and_has_no_secret_environment(self) -> None:
        unit = (ROOT / "systemd" / "cliproxy-auto-router.service").read_text(encoding="utf-8")
        self.assertIn("DynamicUser=yes", unit)
        self.assertIn("SupplementaryGroups=crsproxy", unit)
        self.assertIn("LoadCredential=client-key:/etc/crsproxy/auto-router-client-key", unit)
        self.assertIn("LoadCredential=base-api-key:/etc/crsproxy/auto-router-base-api-key", unit)
        self.assertIn("IPAddressAllow=localhost", unit)
        self.assertIn("-config /run/cliproxy-auto-router/config.yaml --local-model", unit)
        self.assertNotIn("Environment=", unit)
        self.assertNotIn("8317", unit)
        self.assertNotIn("listen 8321", unit)

    def test_nginx_ingress_is_separate_from_canonical_explicit_port(self) -> None:
        nginx = (ROOT / "nginx" / "cliproxy-auto-router.conf").read_text(encoding="utf-8")
        directives = [line.strip() for line in nginx.splitlines() if line.strip() and not line.lstrip().startswith("#")]
        self.assertIn("listen 8321;", directives)
        self.assertIn("listen [::]:8321;", directives)
        self.assertIn("proxy_pass http://127.0.0.1:8320;", directives)
        self.assertFalse(any(line.startswith("listen 8317") for line in directives))
        self.assertNotIn("proxy_pass http://127.0.0.1:8319;", directives)

    def test_documentation_preserves_explicit_endpoint_contract(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("nginx :8317 -> base CLIProxyAPI 127.0.0.1:8319", readme)
        self.assertIn("nginx :8321 -> front router 127.0.0.1:8320", readme)
        self.assertIn("bypass the front process entirely", readme)
        self.assertIn("routing.auto.mode: reject", readme)
        self.assertIn("routing.auto.mode: exclusive", readme)


if __name__ == "__main__":
    unittest.main()

"""Tests for PodSpec and PodInfo models."""

from __future__ import annotations

import json
import unittest

from nucleus_sdk.models import PodInfo, PodSpec


class TestPodSpecCredentials(unittest.TestCase):
    def test_credentials_env_default_none(self):
        spec = PodSpec()
        self.assertIsNone(spec.credentials_env)

    def test_credentials_env_in_to_dict(self):
        spec = PodSpec(
            credentials_env={"LLM_API_TOKEN": "test-token", "DB_PASSWORD": "secret"},
        )
        d = spec.to_dict()
        inner = d["spec"]
        self.assertIn("credentials", inner)
        creds = inner["credentials"]
        self.assertEqual(creds["env"]["LLM_API_TOKEN"], "test-token")
        self.assertEqual(creds["env"]["DB_PASSWORD"], "secret")

    def test_credentials_env_omitted_when_none(self):
        spec = PodSpec()
        d = spec.to_dict()
        inner = d["spec"]
        self.assertNotIn("credentials", inner)

    def test_credentials_env_omitted_when_empty(self):
        spec = PodSpec(credentials_env={})
        d = spec.to_dict()
        inner = d["spec"]
        self.assertNotIn("credentials", inner)

    def test_credentials_redacted_in_repr(self):
        spec = PodSpec(
            credentials_env={"LLM_API_TOKEN": "super-secret-value-12345"},
        )
        r = repr(spec)
        self.assertNotIn("super-secret-value-12345", r)
        self.assertIn("[REDACTED]", r)
        self.assertIn("LLM_API_TOKEN", r)

    def test_repr_without_credentials(self):
        spec = PodSpec(profile="codegen")
        r = repr(spec)
        self.assertNotIn("credentials_env", r)
        self.assertIn("profile='codegen'", r)

    def test_to_dict_serializable(self):
        """to_dict output must be JSON-serializable (for API calls)."""
        spec = PodSpec(
            profile="codegen",
            credentials_env={"TOKEN": "value"},
            budget_max_usd=5.0,
            network_allow=["https://api.example.com"],
        )
        d = spec.to_dict()
        serialized = json.dumps(d)
        self.assertIn('"TOKEN"', serialized)
        self.assertIn('"value"', serialized)

    def test_credentials_env_matches_rust_spec_shape(self):
        """Credentials in to_dict must match Rust CredentialsSpec: {env: {k: v}}."""
        spec = PodSpec(credentials_env={"KEY": "val"})
        d = spec.to_dict()
        creds = d["spec"]["credentials"]
        # Must have 'env' key wrapping the dict (matches Rust CredentialsSpec)
        self.assertIn("env", creds)
        self.assertEqual(creds["env"], {"KEY": "val"})
        # Must not have flat keys at top level
        self.assertNotIn("KEY", creds)


class TestPodSpecToDict(unittest.TestCase):
    def test_minimal_spec(self):
        spec = PodSpec()
        d = spec.to_dict()
        self.assertEqual(d["apiVersion"], "nucleus/v1")
        self.assertEqual(d["kind"], "Pod")
        self.assertEqual(d["spec"]["work_dir"], ".")
        self.assertEqual(d["spec"]["timeout_seconds"], 3600)
        self.assertEqual(d["spec"]["policy"], {"type": "profile", "name": "default"})

    def test_full_spec(self):
        spec = PodSpec(
            work_dir="/app",
            timeout_seconds=600,
            profile="codegen",
            network_allow=["https://api.example.com"],
            dns_allow=["api.example.com"],
            cpu_cores=2,
            memory_mib=512,
            labels={"team": "backend"},
            task="Fix the login bug",
            budget_max_usd=10.0,
            credentials_env={"LLM_API_TOKEN": "tok123"},
        )
        d = spec.to_dict()
        inner = d["spec"]
        self.assertEqual(inner["work_dir"], "/app")
        self.assertEqual(inner["timeout_seconds"], 600)
        self.assertEqual(inner["policy"]["name"], "codegen")
        self.assertEqual(inner["network"]["allow"], ["https://api.example.com"])
        self.assertEqual(inner["network"]["dns_allow"], ["api.example.com"])
        self.assertEqual(inner["resources"]["cpu_cores"], 2)
        self.assertEqual(inner["resources"]["memory_mib"], 512)
        self.assertEqual(inner["task"], "Fix the login bug")
        self.assertEqual(inner["budget"]["max_usd"], 10.0)
        self.assertEqual(inner["credentials"]["env"]["LLM_API_TOKEN"], "tok123")
        self.assertEqual(d["metadata"]["labels"]["team"], "backend")


class TestPodInfo(unittest.TestCase):
    def test_from_dict_running(self):
        info = PodInfo.from_dict({
            "id": "pod-123",
            "created_at_unix": 1710000000,
            "state": "running",
            "proxy_addr": "http://localhost:9090",
        })
        self.assertEqual(info.id, "pod-123")
        self.assertEqual(info.state, "running")
        self.assertEqual(info.proxy_addr, "http://localhost:9090")
        self.assertIsNone(info.exit_code)

    def test_from_dict_exited(self):
        info = PodInfo.from_dict({
            "id": "pod-456",
            "created_at_unix": 1710000000,
            "state": {"exited": {"code": 0}},
        })
        self.assertEqual(info.state, "exited")
        self.assertEqual(info.exit_code, 0)

    def test_from_dict_error(self):
        info = PodInfo.from_dict({
            "id": "pod-789",
            "created_at_unix": 1710000000,
            "state": {"error": {"message": "OOM killed"}},
        })
        self.assertEqual(info.state, "error")
        self.assertEqual(info.error, "OOM killed")


if __name__ == "__main__":
    unittest.main()

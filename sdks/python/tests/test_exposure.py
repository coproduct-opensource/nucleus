"""Tests for the exposure tracking module and uninhabitable state gate integration."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from nucleus_sdk import (
    Session,
    exposureGuard,
    ExposureLabel,
    ExposureSet,
    StateBlocked,
    AccessDenied,
    NucleusError,
)
from nucleus_sdk.client import ProxyClient
from nucleus_sdk.errors import from_error_payload
from nucleus_sdk.exposure import (
    classify_operation,
    project_exposure,
    should_deny,
    apply_record,
)
from nucleus_sdk.tools.fs import FileHandle
from nucleus_sdk.tools.net import NetHandle
from nucleus_sdk.tools.git import GitHandle
from nucleus_sdk.trace import Trace


# --- ExposureSet unit tests ---


class TestExposureSet(unittest.TestCase):
    def test_empty(self):
        t = ExposureSet.empty()
        self.assertEqual(t.summary(), "clean")
        self.assertFalse(t.is_uninhabitable())

    def test_with_label(self):
        t = ExposureSet.empty().with_label(ExposureLabel.PRIVATE_DATA)
        self.assertTrue(t.contains(ExposureLabel.PRIVATE_DATA))
        self.assertFalse(t.contains(ExposureLabel.UNTRUSTED_CONTENT))
        self.assertEqual(t.summary(), "private_data")

    def test_union(self):
        a = ExposureSet.empty().with_label(ExposureLabel.PRIVATE_DATA)
        b = ExposureSet.empty().with_label(ExposureLabel.UNTRUSTED_CONTENT)
        c = a.union(b)
        self.assertTrue(c.contains(ExposureLabel.PRIVATE_DATA))
        self.assertTrue(c.contains(ExposureLabel.UNTRUSTED_CONTENT))

    def test_uninhabitable_complete(self):
        t = (
            ExposureSet.empty()
            .with_label(ExposureLabel.PRIVATE_DATA)
            .with_label(ExposureLabel.UNTRUSTED_CONTENT)
            .with_label(ExposureLabel.EXFIL_VECTOR)
        )
        self.assertTrue(t.is_uninhabitable())

    def test_uninhabitable_incomplete(self):
        t = (
            ExposureSet.empty()
            .with_label(ExposureLabel.PRIVATE_DATA)
            .with_label(ExposureLabel.UNTRUSTED_CONTENT)
        )
        self.assertFalse(t.is_uninhabitable())

    def test_equality(self):
        a = ExposureSet.empty().with_label(ExposureLabel.PRIVATE_DATA)
        b = ExposureSet.empty().with_label(ExposureLabel.PRIVATE_DATA)
        self.assertEqual(a, b)

    def test_idempotent_union(self):
        t = ExposureSet.empty().with_label(ExposureLabel.PRIVATE_DATA)
        t2 = t.with_label(ExposureLabel.PRIVATE_DATA)
        self.assertEqual(t, t2)


# --- Pure function tests (mirror Verus-verified exposure_core) ---


class TestClassifyOperation(unittest.TestCase):
    def test_private_data_ops(self):
        for op in ("fs.read", "fs.glob", "fs.grep"):
            self.assertEqual(classify_operation(op), ExposureLabel.PRIVATE_DATA, op)

    def test_untrusted_content_ops(self):
        for op in ("net.fetch", "net.search"):
            self.assertEqual(
                classify_operation(op), ExposureLabel.UNTRUSTED_CONTENT, op
            )

    def test_exfil_ops(self):
        for op in ("git.push", "git.create_pr", "run"):
            self.assertEqual(classify_operation(op), ExposureLabel.EXFIL_VECTOR, op)

    def test_neutral_ops(self):
        for op in ("fs.write", "git.commit", "git.add"):
            self.assertIsNone(classify_operation(op), op)

    def test_unknown_op(self):
        self.assertIsNone(classify_operation("unknown.op"))


class TestProjectexposure(unittest.TestCase):
    def test_normal_op(self):
        empty = ExposureSet.empty()
        projected = project_exposure(empty, "fs.read")
        self.assertTrue(projected.contains(ExposureLabel.PRIVATE_DATA))

    def test_neutral_op(self):
        t = ExposureSet.empty().with_label(ExposureLabel.PRIVATE_DATA)
        projected = project_exposure(t, "fs.write")
        self.assertEqual(projected, t)

    def test_omnibus_run(self):
        empty = ExposureSet.empty()
        projected = project_exposure(empty, "run")
        self.assertTrue(projected.contains(ExposureLabel.PRIVATE_DATA))
        self.assertTrue(projected.contains(ExposureLabel.EXFIL_VECTOR))
        self.assertFalse(projected.contains(ExposureLabel.UNTRUSTED_CONTENT))


class TestShouldDeny(unittest.TestCase):
    def test_uninhabitable_blocks_exfil(self):
        t = (
            ExposureSet.empty()
            .with_label(ExposureLabel.PRIVATE_DATA)
            .with_label(ExposureLabel.UNTRUSTED_CONTENT)
        )
        self.assertTrue(should_deny(t, "git.push"))
        self.assertTrue(should_deny(t, "run"))
        self.assertTrue(should_deny(t, "git.create_pr"))

    def test_no_block_without_uninhabitable(self):
        t = ExposureSet.empty().with_label(ExposureLabel.PRIVATE_DATA)
        self.assertFalse(should_deny(t, "git.push"))

    def test_no_block_for_non_exfil(self):
        t = (
            ExposureSet.empty()
            .with_label(ExposureLabel.PRIVATE_DATA)
            .with_label(ExposureLabel.UNTRUSTED_CONTENT)
        )
        self.assertFalse(should_deny(t, "fs.read"))

    def test_disabled(self):
        t = (
            ExposureSet.empty()
            .with_label(ExposureLabel.PRIVATE_DATA)
            .with_label(ExposureLabel.UNTRUSTED_CONTENT)
        )
        self.assertFalse(should_deny(t, "git.push", uninhabitable_state_enabled=False))

    def test_omnibus_with_untrusted(self):
        t = ExposureSet.empty().with_label(ExposureLabel.UNTRUSTED_CONTENT)
        # run is omnibus: projects private_data + exfil_vector
        # with untrusted already present, uninhabitable state completes
        self.assertTrue(should_deny(t, "run"))


class TestApplyRecord(unittest.TestCase):
    def test_records_label(self):
        empty = ExposureSet.empty()
        after = apply_record(empty, "fs.read")
        self.assertTrue(after.contains(ExposureLabel.PRIVATE_DATA))

    def test_neutral_no_change(self):
        t = ExposureSet.empty().with_label(ExposureLabel.PRIVATE_DATA)
        after = apply_record(t, "fs.write")
        self.assertEqual(after, t)

    def test_run_records_exfil_only(self):
        # Unlike project_exposure, apply_record does NOT use omnibus
        empty = ExposureSet.empty()
        after = apply_record(empty, "run")
        self.assertTrue(after.contains(ExposureLabel.EXFIL_VECTOR))
        self.assertFalse(after.contains(ExposureLabel.PRIVATE_DATA))


# --- exposureGuard tests ---


class TestexposureGuard(unittest.TestCase):
    def test_starts_clean(self):
        guard = exposureGuard()
        self.assertEqual(guard.summary(), "clean")

    def test_record_accumulates(self):
        guard = exposureGuard()
        guard.record("fs.read")
        self.assertEqual(guard.summary(), "private_data")
        guard.record("net.fetch")
        self.assertEqual(guard.summary(), "private_data+untrusted_content")

    def test_check_blocks_uninhabitable(self):
        guard = exposureGuard()
        guard.record("fs.read")
        guard.record("net.fetch")
        with self.assertRaises(StateBlocked) as ctx:
            guard.check("git.push")
        self.assertIn("uninhabitable state blocked", str(ctx.exception))
        self.assertEqual(ctx.exception.kind, "uninhabitable_blocked")

    def test_check_allows_non_exfil(self):
        guard = exposureGuard()
        guard.record("fs.read")
        guard.record("net.fetch")
        guard.check("fs.read")  # should not raise
        guard.check("fs.write")  # should not raise

    def test_check_allows_when_disabled(self):
        guard = exposureGuard(uninhabitable_state_enabled=False)
        guard.record("fs.read")
        guard.record("net.fetch")
        guard.check("git.push")  # should not raise


# --- StateBlocked exception tests ---


class TestStateBlocked(unittest.TestCase):
    def test_is_subclass_of_access_denied(self):
        self.assertTrue(issubclass(StateBlocked, AccessDenied))

    def test_is_subclass_of_nucleus_error(self):
        self.assertTrue(issubclass(StateBlocked, NucleusError))

    def test_from_error_payload(self):
        payload = {"error": "uninhabitable state blocked", "kind": "uninhabitable_blocked"}
        err = from_error_payload(payload, 403)
        self.assertIsInstance(err, StateBlocked)
        self.assertEqual(err.status, 403)


# --- Integration tests: Session + exposure tracking ---


class TestSessionexposureIntegration(unittest.TestCase):
    def _make_session(self, uninhabitable_state_enabled=True):
        mock_proxy = MagicMock(spec=ProxyClient)
        mock_proxy.read.return_value = "file contents"
        mock_proxy.web_fetch.return_value = {"status": 200, "body": "ok"}
        mock_proxy.web_search.return_value = {"results": []}
        mock_proxy.run.return_value = {"exit_code": 0, "stdout": ""}
        mock_proxy.glob.return_value = {"files": ["a.py"]}
        mock_proxy.grep.return_value = {"matches": []}
        return Session(
            profile="test",
            proxy=mock_proxy,
            uninhabitable_state_enabled=uninhabitable_state_enabled,
        )

    def test_exposure_summary_clean_on_start(self):
        s = self._make_session()
        with s as session:
            self.assertEqual(session.exposure_summary, "clean")

    def test_read_adds_private_data(self):
        s = self._make_session()
        with s as session:
            session.fs.read("file.txt")
            self.assertEqual(session.exposure_summary, "private_data")

    def test_fetch_adds_untrusted_content(self):
        s = self._make_session()
        with s as session:
            session.net.fetch("https://example.com")
            self.assertEqual(session.exposure_summary, "untrusted_content")

    def test_uninhabitable_blocks_push_after_read_and_fetch(self):
        s = self._make_session()
        with s as session:
            session.fs.read("secrets.txt")
            session.net.fetch("https://evil.com")
            with self.assertRaises(StateBlocked):
                session.git.push("origin", "main")

    def test_uninhabitable_blocks_run_after_grep_and_search(self):
        s = self._make_session()
        with s as session:
            session.fs.grep("password")
            session.net.search("how to exfiltrate")
            with self.assertRaises(StateBlocked):
                session.git.push("origin")

    def test_write_is_neutral(self):
        s = self._make_session()
        with s as session:
            session.fs.write("out.txt", "data")
            self.assertEqual(session.exposure_summary, "clean")

    def test_commit_is_neutral(self):
        s = self._make_session()
        with s as session:
            session.git.commit("msg")
            self.assertEqual(session.exposure_summary, "clean")

    def test_uninhabitable_disabled_allows_everything(self):
        s = self._make_session(uninhabitable_state_enabled=False)
        with s as session:
            session.fs.read("secrets.txt")
            session.net.fetch("https://evil.com")
            session.git.push("origin", "main")  # should NOT raise

    def test_glob_adds_private_data(self):
        s = self._make_session()
        with s as session:
            session.fs.glob("**/*.py")
            self.assertEqual(session.exposure_summary, "private_data")

    def test_exposure_survives_after_context_exit(self):
        s = self._make_session()
        with s as session:
            session.fs.read("a.txt")
            session.net.fetch("https://example.com")
        self.assertEqual(s.exposure_summary, "private_data+untrusted_content")

    def test_uninhabitable_trace_records_deny(self):
        s = self._make_session()
        try:
            with s as session:
                session.fs.read("data.txt")
                session.net.fetch("https://evil.com")
                session.git.push("origin")
        except StateBlocked:
            pass
        # The session exit should have recorded the StateBlocked
        exit_entries = [
            e for e in s.trace.entries if e.operation == "session.exit"
        ]
        self.assertEqual(len(exit_entries), 1)
        self.assertEqual(exit_entries[0].policy_decision, "deny")
        self.assertIn("StateBlocked", exit_entries[0].result_summary)


# --- Tool handle backward compatibility (no guard) ---


class TestToolHandlesWithoutGuard(unittest.TestCase):
    """Verify tool handles work without a exposureGuard (backward compat)."""

    def test_file_handle_no_guard(self):
        proxy = MagicMock(spec=ProxyClient)
        proxy.read.return_value = "content"
        fh = FileHandle(proxy, Trace())
        result = fh.read("test.txt")
        self.assertEqual(result, "content")

    def test_net_handle_no_guard(self):
        proxy = MagicMock(spec=ProxyClient)
        proxy.web_fetch.return_value = {"status": 200, "body": "ok"}
        nh = NetHandle(proxy, Trace())
        result = nh.fetch("https://example.com")
        self.assertEqual(result.status, 200)

    def test_git_handle_no_guard(self):
        proxy = MagicMock(spec=ProxyClient)
        proxy.run.return_value = {
            "status": 0,
            "success": True,
            "stdout": "",
            "stderr": "",
        }
        gh = GitHandle(proxy, Trace())
        gh.push("origin")
        proxy.run.assert_called_once()


if __name__ == "__main__":
    unittest.main()

"""Unit tests for Session, Trace, typed tool handles, and new error types."""

from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock, patch

from nucleus_sdk import (
    Session,
    Trace,
    TraceEntry,
    PolicyDenied,
    BudgetExceeded,
    AccessDenied,
    NucleusError,
)
from nucleus_sdk.client import ProxyClient
from nucleus_sdk.errors import from_error_payload
from nucleus_sdk.tools.fs import FileHandle
from nucleus_sdk.tools.net import NetHandle
from nucleus_sdk.tools.git import GitHandle


class TestPolicyDenied(unittest.TestCase):
    def test_is_subclass_of_access_denied(self):
        self.assertTrue(issubclass(PolicyDenied, AccessDenied))

    def test_is_subclass_of_nucleus_error(self):
        self.assertTrue(issubclass(PolicyDenied, NucleusError))

    def test_raise_and_catch(self):
        with self.assertRaises(AccessDenied):
            raise PolicyDenied("git push denied by policy", kind="policy_denied")

    def test_from_error_payload(self):
        payload = {"error": "push denied", "kind": "policy_denied"}
        err = from_error_payload(payload, 403)
        self.assertIsInstance(err, PolicyDenied)
        self.assertEqual(err.message, "push denied")
        self.assertEqual(err.status, 403)


class TestBudgetExceeded(unittest.TestCase):
    def test_is_subclass_of_nucleus_error(self):
        self.assertTrue(issubclass(BudgetExceeded, NucleusError))

    def test_not_subclass_of_access_denied(self):
        self.assertFalse(issubclass(BudgetExceeded, AccessDenied))

    def test_raise_and_catch(self):
        with self.assertRaises(NucleusError):
            raise BudgetExceeded("$5.00 limit reached", kind="budget_exceeded")

    def test_from_error_payload(self):
        payload = {"error": "budget limit", "kind": "budget_exceeded"}
        err = from_error_payload(payload, 402)
        self.assertIsInstance(err, BudgetExceeded)
        self.assertEqual(err.status, 402)


class TestTrace(unittest.TestCase):
    def test_empty_trace(self):
        t = Trace()
        self.assertEqual(len(t), 0)
        self.assertEqual(t.entries, [])
        self.assertEqual(t.export_dict(), [])
        self.assertEqual(t.export_jsonl(), "")

    def test_record_and_entries(self):
        t = Trace()
        entry = t.record(
            operation="fs.read",
            args={"path": "README.md"},
            result_summary="1024 bytes",
            duration_ms=1.5,
        )
        self.assertEqual(len(t), 1)
        self.assertIsInstance(entry, TraceEntry)
        self.assertEqual(entry.operation, "fs.read")
        self.assertEqual(entry.policy_decision, "allow")

    def test_entries_are_copies(self):
        t = Trace()
        t.record(operation="op", args={}, result_summary="ok", duration_ms=0)
        entries = t.entries
        entries.clear()
        self.assertEqual(len(t), 1)

    def test_record_deny(self):
        t = Trace()
        entry = t.record(
            operation="git.push",
            args={},
            result_summary="denied",
            duration_ms=0,
            policy_decision="deny",
        )
        self.assertEqual(entry.policy_decision, "deny")

    def test_export_dict(self):
        t = Trace()
        t.record(operation="a", args={"k": 1}, result_summary="ok", duration_ms=2.0)
        t.record(operation="b", args={}, result_summary="ok", duration_ms=3.0)
        exported = t.export_dict()
        self.assertEqual(len(exported), 2)
        self.assertIsInstance(exported[0], dict)
        self.assertEqual(exported[0]["operation"], "a")
        self.assertIn("timestamp", exported[0])

    def test_export_jsonl(self):
        t = Trace()
        t.record(operation="x", args={}, result_summary="ok", duration_ms=1.0)
        t.record(operation="y", args={}, result_summary="ok", duration_ms=2.0)
        jsonl = t.export_jsonl()
        lines = jsonl.strip().split("\n")
        self.assertEqual(len(lines), 2)
        first = json.loads(lines[0])
        self.assertEqual(first["operation"], "x")
        second = json.loads(lines[1])
        self.assertEqual(second["operation"], "y")


class TestSessionCreation(unittest.TestCase):
    def test_requires_proxy_url(self):
        """Session raises ValueError if no proxy_url and env not set."""
        with patch.dict("os.environ", {}, clear=True):
            s = Session(profile="test")
            with self.assertRaises(ValueError):
                s.__enter__()

    def test_creates_with_explicit_proxy_url(self):
        """Session can be created with explicit proxy_url (won't connect)."""
        s = Session(profile="codegen", proxy_url="http://localhost:9999")
        with s as session:
            self.assertEqual(session.profile, "codegen")

    def test_creates_with_env_proxy_url(self):
        """Session reads NUCLEUS_PROXY_URL from env."""
        with patch.dict("os.environ", {"NUCLEUS_PROXY_URL": "http://localhost:8888"}):
            s = Session(profile="test")
            with s as session:
                self.assertEqual(session.profile, "test")

    def test_creates_with_injected_proxy(self):
        """Session accepts an external ProxyClient instance."""
        mock_proxy = MagicMock(spec=ProxyClient)
        s = Session(profile="test", proxy=mock_proxy)
        with s as session:
            self.assertIsNotNone(session.fs)
            self.assertIsNotNone(session.net)
            self.assertIsNotNone(session.git)

    def test_tool_accessors_outside_context(self):
        """Accessing tool handles outside 'with' block raises RuntimeError."""
        s = Session(profile="test", proxy_url="http://localhost:9999")
        with self.assertRaises(RuntimeError):
            _ = s.fs
        with self.assertRaises(RuntimeError):
            _ = s.net
        with self.assertRaises(RuntimeError):
            _ = s.git


class TestSessionTrace(unittest.TestCase):
    def test_trace_accessible_during_session(self):
        mock_proxy = MagicMock(spec=ProxyClient)
        s = Session(profile="test", proxy=mock_proxy)
        with s as session:
            self.assertIsInstance(session.trace, Trace)
            self.assertEqual(len(session.trace), 0)

    def test_trace_records_exit_exception(self):
        mock_proxy = MagicMock(spec=ProxyClient)
        s = Session(profile="test", proxy=mock_proxy)
        try:
            with s as session:
                raise PolicyDenied("not allowed", kind="policy_denied")
        except PolicyDenied:
            pass
        # Should have recorded the exit exception
        entries = s.trace.entries
        self.assertTrue(len(entries) >= 1)
        exit_entry = entries[-1]
        self.assertEqual(exit_entry.operation, "session.exit")
        self.assertEqual(exit_entry.policy_decision, "deny")
        self.assertIn("PolicyDenied", exit_entry.result_summary)

    def test_trace_survives_after_exit(self):
        mock_proxy = MagicMock(spec=ProxyClient)
        mock_proxy.read.return_value = "hello"
        s = Session(profile="test", proxy=mock_proxy)
        with s as session:
            session.fs.read("a.txt")
        # Trace is still accessible after the context exits
        self.assertEqual(len(s.trace), 1)
        self.assertEqual(s.trace.entries[0].operation, "fs.read")


class TestFileHandleDelegation(unittest.TestCase):
    def setUp(self):
        self.mock_proxy = MagicMock(spec=ProxyClient)
        self.trace = Trace()
        self.fh = FileHandle(self.mock_proxy, self.trace)

    def test_read_delegates(self):
        self.mock_proxy.read.return_value = "file contents"
        result = self.fh.read("/path/to/file")
        self.mock_proxy.read.assert_called_once_with("/path/to/file")
        self.assertEqual(result, "file contents")
        self.assertEqual(len(self.trace), 1)
        self.assertEqual(self.trace.entries[0].operation, "fs.read")

    def test_write_delegates(self):
        self.fh.write("/path/to/file", "data")
        self.mock_proxy.write.assert_called_once_with("/path/to/file", "data")
        self.assertEqual(len(self.trace), 1)
        self.assertEqual(self.trace.entries[0].operation, "fs.write")

    def test_glob_delegates(self):
        self.mock_proxy.glob.return_value = {"matches": ["a.py", "b.py"]}
        result = self.fh.glob("*.py")
        self.mock_proxy.glob.assert_called_once_with(
            pattern="*.py", directory=None, max_results=None
        )
        self.assertEqual(len(result.matches), 2)
        self.assertEqual(self.trace.entries[0].operation, "fs.glob")

    def test_grep_delegates(self):
        self.mock_proxy.grep.return_value = {
            "matches": [{"file": "a.py", "line": 1, "content": "foo"}]
        }
        result = self.fh.grep("foo", path="/src")
        self.mock_proxy.grep.assert_called_once_with(
            pattern="foo",
            path="/src",
            file_glob=None,
            context_lines=None,
            max_matches=None,
            case_insensitive=None,
        )
        self.assertEqual(len(result.matches), 1)
        self.assertEqual(result.matches[0].content, "foo")
        self.assertEqual(self.trace.entries[0].operation, "fs.grep")


class TestNetHandleDelegation(unittest.TestCase):
    def setUp(self):
        self.mock_proxy = MagicMock(spec=ProxyClient)
        self.trace = Trace()
        self.nh = NetHandle(self.mock_proxy, self.trace)

    def test_fetch_delegates(self):
        self.mock_proxy.web_fetch.return_value = {"status": 200, "body": "ok"}
        result = self.nh.fetch("https://example.com")
        self.mock_proxy.web_fetch.assert_called_once_with(
            url="https://example.com", method=None, headers=None, body=None
        )
        self.assertEqual(result.status, 200)
        self.assertEqual(result.body, "ok")
        self.assertEqual(self.trace.entries[0].operation, "net.fetch")

    def test_search_delegates(self):
        self.mock_proxy.web_search.return_value = {
            "results": [{"title": "a", "url": "https://example.com"}]
        }
        result = self.nh.search("test query", max_results=5)
        self.mock_proxy.web_search.assert_called_once_with(
            query="test query", max_results=5
        )
        self.assertEqual(len(result.results), 1)
        self.assertEqual(result.results[0].title, "a")
        self.assertEqual(self.trace.entries[0].operation, "net.search")


class TestGitHandleDelegation(unittest.TestCase):
    def setUp(self):
        self.mock_proxy = MagicMock(spec=ProxyClient)
        self.mock_proxy.run.return_value = {
            "status": 0,
            "success": True,
            "stdout": "",
            "stderr": "",
        }
        self.trace = Trace()
        self.gh = GitHandle(self.mock_proxy, self.trace)

    def test_commit_delegates(self):
        self.gh.commit("initial commit", paths=["file.py"])
        # Should have called git add then git commit
        calls = self.mock_proxy.run.call_args_list
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0].kwargs["args"], ["git", "add", "file.py"])
        self.assertEqual(
            calls[1].kwargs["args"], ["git", "commit", "-m", "initial commit"]
        )
        self.assertEqual(len(self.trace), 2)

    def test_commit_no_paths(self):
        self.gh.commit("msg")
        calls = self.mock_proxy.run.call_args_list
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].kwargs["args"], ["git", "commit", "-m", "msg"])

    def test_push_delegates(self):
        self.gh.push("origin", "main")
        self.mock_proxy.run.assert_called_once_with(
            args=["git", "push", "origin", "main"], directory=None
        )
        self.assertEqual(self.trace.entries[0].operation, "git.push")

    def test_push_no_branch(self):
        self.gh.push("origin")
        self.mock_proxy.run.assert_called_once_with(
            args=["git", "push", "origin"], directory=None
        )

    def test_create_pr_delegates(self):
        self.gh.create_pr("my pr", body="description", base="main")
        self.mock_proxy.run.assert_called_once_with(
            args=[
                "git",
                "pr",
                "create",
                "--title",
                "my pr",
                "--body",
                "description",
                "--base",
                "main",
            ],
            directory=None,
        )
        self.assertEqual(self.trace.entries[0].operation, "git.create_pr")


class TestSessionApprove(unittest.TestCase):
    def test_approve_calls_proxy_and_action(self):
        mock_proxy = MagicMock(spec=ProxyClient)
        mock_proxy.approve.return_value = {"approved": True}
        mock_proxy.web_fetch.return_value = {"status": 200, "body": "ok"}

        s = Session(profile="test", proxy=mock_proxy)
        with s as session:
            result = session.approve(
                "fetch", lambda: session.net.fetch("https://example.com")
            )
        self.assertEqual(result.status, 200)
        mock_proxy.approve.assert_called_once_with("fetch")
        # Should have trace entries for net.fetch and approve:fetch
        ops = [e.operation for e in s.trace.entries]
        self.assertIn("net.fetch", ops)
        self.assertIn("approve:fetch", ops)

    def test_approve_outside_context_raises(self):
        s = Session(profile="test", proxy_url="http://localhost:9999")
        with self.assertRaises(RuntimeError):
            s.approve("op", lambda: None)


class TestSessionIntegration(unittest.TestCase):
    """Integration-style test using a mock ProxyClient for a multi-step workflow."""

    def test_full_workflow_trace(self):
        mock_proxy = MagicMock(spec=ProxyClient)
        mock_proxy.read.return_value = "# README\n"
        mock_proxy.run.return_value = {
            "status": 0,
            "success": True,
            "stdout": "",
            "stderr": "",
        }
        mock_proxy.web_fetch.return_value = {"status": 200, "body": "<html>"}
        mock_proxy.approve.return_value = {"approved": True}

        s = Session(profile="safe_pr_fixer", proxy=mock_proxy)
        with s as session:
            readme = session.fs.read("README.md")
            session.fs.write("README.md", readme + "\nUpdated.")
            session.approve(
                "fetch", lambda: session.net.fetch("https://example.com")
            )
            session.git.commit("update readme", paths=["README.md"])

        trace = s.trace
        self.assertTrue(len(trace) >= 5)

        ops = [e.operation for e in trace.entries]
        self.assertIn("fs.read", ops)
        self.assertIn("fs.write", ops)
        self.assertIn("net.fetch", ops)
        self.assertIn("approve:fetch", ops)
        self.assertIn("git.add", ops)
        self.assertIn("git.commit", ops)

        # All entries should have allow policy (no denials in this workflow)
        for entry in trace.entries:
            self.assertEqual(entry.policy_decision, "allow")

        # Trace export should produce valid JSONL
        jsonl = trace.export_jsonl()
        lines = jsonl.strip().split("\n")
        for line in lines:
            parsed = json.loads(line)
            self.assertIn("operation", parsed)
            self.assertIn("timestamp", parsed)
            self.assertIn("duration_ms", parsed)


if __name__ == "__main__":
    unittest.main()

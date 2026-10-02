"""Tests for typed response objects in nucleus_sdk.types."""

from __future__ import annotations

import unittest

from nucleus_sdk.types import (
    CommandOutput,
    FetchResponse,
    GlobResult,
    GrepMatch,
    GrepResult,
    SearchResult,
    SearchResultItem,
)


class TestGlobResult(unittest.TestCase):
    def test_from_dict_basic(self):
        r = GlobResult.from_dict({"matches": ["a.py", "b.py"]})
        self.assertEqual(r.matches, ["a.py", "b.py"])
        self.assertFalse(r.truncated)

    def test_from_dict_truncated(self):
        r = GlobResult.from_dict({"matches": ["x"], "truncated": True})
        self.assertTrue(r.truncated)

    def test_from_dict_empty(self):
        r = GlobResult.from_dict({})
        self.assertEqual(r.matches, [])
        self.assertFalse(r.truncated)

    def test_frozen(self):
        r = GlobResult.from_dict({"matches": ["a"]})
        with self.assertRaises(AttributeError):
            r.matches = []  # type: ignore[misc]


class TestGrepMatch(unittest.TestCase):
    def test_from_dict_full(self):
        m = GrepMatch.from_dict({
            "file": "src/main.rs",
            "line": 42,
            "content": "fn main() {",
            "context_before": ["// entry point"],
            "context_after": ["    println!(\"hello\");"],
        })
        self.assertEqual(m.file, "src/main.rs")
        self.assertEqual(m.line, 42)
        self.assertEqual(m.content, "fn main() {")
        self.assertEqual(len(m.context_before), 1)
        self.assertEqual(len(m.context_after), 1)

    def test_from_dict_minimal(self):
        m = GrepMatch.from_dict({"file": "a.py", "line": 1, "content": "x"})
        self.assertEqual(m.context_before, [])
        self.assertEqual(m.context_after, [])

    def test_from_dict_null_context(self):
        m = GrepMatch.from_dict({
            "file": "a.py",
            "line": 1,
            "content": "x",
            "context_before": None,
            "context_after": None,
        })
        self.assertEqual(m.context_before, [])
        self.assertEqual(m.context_after, [])


class TestGrepResult(unittest.TestCase):
    def test_from_dict_with_matches(self):
        r = GrepResult.from_dict({
            "matches": [
                {"file": "a.py", "line": 1, "content": "foo"},
                {"file": "b.py", "line": 5, "content": "bar"},
            ],
        })
        self.assertEqual(len(r.matches), 2)
        self.assertIsInstance(r.matches[0], GrepMatch)
        self.assertEqual(r.matches[0].file, "a.py")
        self.assertEqual(r.matches[1].line, 5)
        self.assertFalse(r.truncated)

    def test_from_dict_truncated(self):
        r = GrepResult.from_dict({"matches": [], "truncated": True})
        self.assertTrue(r.truncated)

    def test_from_dict_empty(self):
        r = GrepResult.from_dict({})
        self.assertEqual(r.matches, [])


class TestFetchResponse(unittest.TestCase):
    def test_from_dict_full(self):
        r = FetchResponse.from_dict({
            "status": 200,
            "headers": {"content-type": "text/html"},
            "body": "<html>hello</html>",
        })
        self.assertEqual(r.status, 200)
        self.assertEqual(r.headers["content-type"], "text/html")
        self.assertEqual(r.body, "<html>hello</html>")
        self.assertFalse(r.truncated)

    def test_from_dict_truncated(self):
        r = FetchResponse.from_dict({
            "status": 200,
            "headers": {},
            "body": "...",
            "truncated": True,
        })
        self.assertTrue(r.truncated)

    def test_from_dict_missing_fields(self):
        r = FetchResponse.from_dict({})
        self.assertEqual(r.status, 0)
        self.assertEqual(r.headers, {})
        self.assertEqual(r.body, "")

    def test_frozen(self):
        r = FetchResponse.from_dict({"status": 200, "body": "x"})
        with self.assertRaises(AttributeError):
            r.status = 500  # type: ignore[misc]


class TestSearchResultItem(unittest.TestCase):
    def test_from_dict_full(self):
        item = SearchResultItem.from_dict({
            "title": "Rust docs",
            "url": "https://doc.rust-lang.org",
            "snippet": "The Rust programming language",
        })
        self.assertEqual(item.title, "Rust docs")
        self.assertEqual(item.url, "https://doc.rust-lang.org")
        self.assertEqual(item.snippet, "The Rust programming language")

    def test_from_dict_no_snippet(self):
        item = SearchResultItem.from_dict({
            "title": "Example",
            "url": "https://example.com",
        })
        self.assertIsNone(item.snippet)


class TestSearchResult(unittest.TestCase):
    def test_from_dict_with_results(self):
        r = SearchResult.from_dict({
            "results": [
                {"title": "A", "url": "https://a.com"},
                {"title": "B", "url": "https://b.com", "snippet": "B site"},
            ]
        })
        self.assertEqual(len(r.results), 2)
        self.assertIsInstance(r.results[0], SearchResultItem)
        self.assertEqual(r.results[1].snippet, "B site")

    def test_from_dict_empty(self):
        r = SearchResult.from_dict({})
        self.assertEqual(r.results, [])


class TestCommandOutput(unittest.TestCase):
    def test_from_dict_success(self):
        r = CommandOutput.from_dict({
            "status": 0,
            "success": True,
            "stdout": "hello\n",
            "stderr": "",
        })
        self.assertEqual(r.status, 0)
        self.assertTrue(r.success)
        self.assertEqual(r.stdout, "hello\n")
        self.assertEqual(r.stderr, "")

    def test_from_dict_failure(self):
        r = CommandOutput.from_dict({
            "status": 1,
            "success": False,
            "stdout": "",
            "stderr": "error: not found\n",
        })
        self.assertEqual(r.status, 1)
        self.assertFalse(r.success)
        self.assertEqual(r.stderr, "error: not found\n")

    def test_from_dict_defaults(self):
        r = CommandOutput.from_dict({})
        self.assertEqual(r.status, -1)
        self.assertFalse(r.success)
        self.assertEqual(r.stdout, "")
        self.assertEqual(r.stderr, "")

    def test_frozen(self):
        r = CommandOutput.from_dict({"status": 0, "success": True})
        with self.assertRaises(AttributeError):
            r.status = 1  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()

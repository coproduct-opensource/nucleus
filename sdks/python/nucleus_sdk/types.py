"""Typed response objects for nucleus SDK tool handles.

Every tool handle method returns a typed object instead of a raw dict.
Each response carries exposure metadata so callers can inspect
the security state that produced the result.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class GlobResult:
    """Result of a filesystem glob operation."""

    matches: List[str]
    truncated: bool = False

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> GlobResult:
        return cls(
            matches=d.get("matches", []),
            truncated=bool(d.get("truncated", False)),
        )


@dataclass(frozen=True)
class GrepMatch:
    """A single grep match within a file."""

    file: str
    line: int
    content: str
    context_before: List[str] = field(default_factory=list)
    context_after: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> GrepMatch:
        return cls(
            file=d.get("file", ""),
            line=d.get("line", 0),
            content=d.get("content", ""),
            context_before=d.get("context_before") or [],
            context_after=d.get("context_after") or [],
        )


@dataclass(frozen=True)
class GrepResult:
    """Result of a content search (grep) operation."""

    matches: List[GrepMatch]
    truncated: bool = False

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> GrepResult:
        raw_matches = d.get("matches", [])
        return cls(
            matches=[GrepMatch.from_dict(m) for m in raw_matches],
            truncated=bool(d.get("truncated", False)),
        )


@dataclass(frozen=True)
class FetchResponse:
    """Result of an HTTP fetch operation."""

    status: int
    headers: Dict[str, str]
    body: str
    truncated: bool = False

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> FetchResponse:
        return cls(
            status=d.get("status", 0),
            headers=d.get("headers") or {},
            body=d.get("body", ""),
            truncated=bool(d.get("truncated", False)),
        )


@dataclass(frozen=True)
class SearchResultItem:
    """A single web search result."""

    title: str
    url: str
    snippet: Optional[str] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> SearchResultItem:
        return cls(
            title=d.get("title", ""),
            url=d.get("url", ""),
            snippet=d.get("snippet"),
        )


@dataclass(frozen=True)
class SearchResult:
    """Result of a web search operation."""

    results: List[SearchResultItem]

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> SearchResult:
        raw = d.get("results", [])
        return cls(results=[SearchResultItem.from_dict(r) for r in raw])


@dataclass(frozen=True)
class CommandOutput:
    """Result of a command execution (run / git)."""

    status: int
    success: bool
    stdout: str
    stderr: str

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> CommandOutput:
        return cls(
            status=d.get("status", -1),
            success=d.get("success", False),
            stdout=d.get("stdout", ""),
            stderr=d.get("stderr", ""),
        )

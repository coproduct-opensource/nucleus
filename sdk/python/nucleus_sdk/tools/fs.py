from __future__ import annotations

import time
from typing import Optional, TYPE_CHECKING

from ..types import GlobResult, GrepResult

if TYPE_CHECKING:
    from ..client import ProxyClient
    from ..taint import TaintGuard
    from ..trace import Trace


class FileHandle:
    """Typed accessor for filesystem operations.

    All calls delegate to a ProxyClient and record each operation
    in the session trace. An optional TaintGuard enforces the
    trifecta gate before each operation.
    """

    def __init__(
        self,
        proxy: ProxyClient,
        trace: Trace,
        taint_guard: Optional[TaintGuard] = None,
    ) -> None:
        self._proxy = proxy
        self._trace = trace
        self._guard = taint_guard

    def read(self, path: str) -> str:
        """Read a file and return its contents."""
        if self._guard:
            self._guard.check("fs.read")
        start = time.monotonic()
        result = self._proxy.read(path)
        elapsed = (time.monotonic() - start) * 1000
        self._trace.record(
            operation="fs.read",
            args={"path": path},
            result_summary=f"{len(result)} bytes",
            duration_ms=round(elapsed, 2),
        )
        if self._guard:
            self._guard.record("fs.read")
        return result

    def write(self, path: str, contents: str) -> None:
        """Write contents to a file."""
        if self._guard:
            self._guard.check("fs.write")
        start = time.monotonic()
        self._proxy.write(path, contents)
        elapsed = (time.monotonic() - start) * 1000
        self._trace.record(
            operation="fs.write",
            args={"path": path},
            result_summary=f"{len(contents)} bytes written",
            duration_ms=round(elapsed, 2),
        )
        if self._guard:
            self._guard.record("fs.write")

    def glob(
        self,
        pattern: str,
        directory: Optional[str] = None,
        max_results: Optional[int] = None,
    ) -> GlobResult:
        """Search for files matching a glob pattern."""
        if self._guard:
            self._guard.check("fs.glob")
        start = time.monotonic()
        raw = self._proxy.glob(
            pattern=pattern, directory=directory, max_results=max_results
        )
        elapsed = (time.monotonic() - start) * 1000
        result = GlobResult.from_dict(raw)
        self._trace.record(
            operation="fs.glob",
            args={"pattern": pattern},
            result_summary=f"{len(result.matches)} matches",
            duration_ms=round(elapsed, 2),
        )
        if self._guard:
            self._guard.record("fs.glob")
        return result

    def grep(
        self,
        pattern: str,
        path: Optional[str] = None,
        file_glob: Optional[str] = None,
        context_lines: Optional[int] = None,
        max_matches: Optional[int] = None,
        case_insensitive: Optional[bool] = None,
    ) -> GrepResult:
        """Search file contents with a regex pattern."""
        if self._guard:
            self._guard.check("fs.grep")
        start = time.monotonic()
        raw = self._proxy.grep(
            pattern=pattern,
            path=path,
            file_glob=file_glob,
            context_lines=context_lines,
            max_matches=max_matches,
            case_insensitive=case_insensitive,
        )
        elapsed = (time.monotonic() - start) * 1000
        result = GrepResult.from_dict(raw)
        self._trace.record(
            operation="fs.grep",
            args={"pattern": pattern},
            result_summary=f"{len(result.matches)} matches",
            duration_ms=round(elapsed, 2),
        )
        if self._guard:
            self._guard.record("fs.grep")
        return result

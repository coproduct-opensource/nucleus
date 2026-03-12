from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..client import ProxyClient
    from ..trace import Trace


class FileHandle:
    """Typed accessor for filesystem operations.

    All calls delegate to a ProxyClient and record each operation
    in the session trace.
    """

    def __init__(self, proxy: ProxyClient, trace: Trace) -> None:
        self._proxy = proxy
        self._trace = trace

    def read(self, path: str) -> str:
        """Read a file and return its contents."""
        start = time.monotonic()
        result = self._proxy.read(path)
        elapsed = (time.monotonic() - start) * 1000
        self._trace.record(
            operation="fs.read",
            args={"path": path},
            result_summary=f"{len(result)} bytes",
            duration_ms=round(elapsed, 2),
        )
        return result

    def write(self, path: str, contents: str) -> None:
        """Write contents to a file."""
        start = time.monotonic()
        self._proxy.write(path, contents)
        elapsed = (time.monotonic() - start) * 1000
        self._trace.record(
            operation="fs.write",
            args={"path": path},
            result_summary=f"{len(contents)} bytes written",
            duration_ms=round(elapsed, 2),
        )

    def glob(
        self,
        pattern: str,
        directory: Optional[str] = None,
        max_results: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Search for files matching a glob pattern."""
        start = time.monotonic()
        result = self._proxy.glob(
            pattern=pattern, directory=directory, max_results=max_results
        )
        elapsed = (time.monotonic() - start) * 1000
        matches = result.get("files", [])
        self._trace.record(
            operation="fs.glob",
            args={"pattern": pattern},
            result_summary=f"{len(matches)} matches",
            duration_ms=round(elapsed, 2),
        )
        return result

    def grep(
        self,
        pattern: str,
        path: Optional[str] = None,
        file_glob: Optional[str] = None,
        context_lines: Optional[int] = None,
        max_matches: Optional[int] = None,
        case_insensitive: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Search file contents with a regex pattern."""
        start = time.monotonic()
        result = self._proxy.grep(
            pattern=pattern,
            path=path,
            file_glob=file_glob,
            context_lines=context_lines,
            max_matches=max_matches,
            case_insensitive=case_insensitive,
        )
        elapsed = (time.monotonic() - start) * 1000
        matches = result.get("matches", [])
        self._trace.record(
            operation="fs.grep",
            args={"pattern": pattern},
            result_summary=f"{len(matches)} matches",
            duration_ms=round(elapsed, 2),
        )
        return result

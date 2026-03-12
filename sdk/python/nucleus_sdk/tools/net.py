from __future__ import annotations

import time
from typing import Dict, Optional, TYPE_CHECKING

from ..types import FetchResponse, SearchResult

if TYPE_CHECKING:
    from ..client import ProxyClient
    from ..taint import TaintGuard
    from ..trace import Trace


class NetHandle:
    """Typed accessor for network operations.

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

    def fetch(
        self,
        url: str,
        method: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> FetchResponse:
        """Fetch a URL through the proxy."""
        if self._guard:
            self._guard.check("net.fetch")
        start = time.monotonic()
        raw = self._proxy.web_fetch(
            url=url, method=method, headers=headers, body=body
        )
        elapsed = (time.monotonic() - start) * 1000
        result = FetchResponse.from_dict(raw)
        self._trace.record(
            operation="net.fetch",
            args={"url": url, "method": method or "GET"},
            result_summary=f"status={result.status}",
            duration_ms=round(elapsed, 2),
        )
        if self._guard:
            self._guard.record("net.fetch")
        return result

    def search(
        self,
        query: str,
        max_results: Optional[int] = None,
    ) -> SearchResult:
        """Perform a web search through the proxy."""
        if self._guard:
            self._guard.check("net.search")
        start = time.monotonic()
        raw = self._proxy.web_search(query=query, max_results=max_results)
        elapsed = (time.monotonic() - start) * 1000
        result = SearchResult.from_dict(raw)
        self._trace.record(
            operation="net.search",
            args={"query": query},
            result_summary=f"{len(result.results)} results",
            duration_ms=round(elapsed, 2),
        )
        if self._guard:
            self._guard.record("net.search")
        return result

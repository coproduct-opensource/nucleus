from __future__ import annotations

import time
from typing import Any, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..client import ProxyClient
    from ..trace import Trace


class NetHandle:
    """Typed accessor for network operations.

    All calls delegate to a ProxyClient and record each operation
    in the session trace.
    """

    def __init__(self, proxy: ProxyClient, trace: Trace) -> None:
        self._proxy = proxy
        self._trace = trace

    def fetch(
        self,
        url: str,
        method: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Fetch a URL through the proxy."""
        start = time.monotonic()
        result = self._proxy.web_fetch(
            url=url, method=method, headers=headers, body=body
        )
        elapsed = (time.monotonic() - start) * 1000
        status = result.get("status", "unknown")
        self._trace.record(
            operation="net.fetch",
            args={"url": url, "method": method or "GET"},
            result_summary=f"status={status}",
            duration_ms=round(elapsed, 2),
        )
        return result

    def search(
        self,
        query: str,
        max_results: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Perform a web search through the proxy."""
        start = time.monotonic()
        result = self._proxy.web_search(query=query, max_results=max_results)
        elapsed = (time.monotonic() - start) * 1000
        results_count = len(result.get("results", []))
        self._trace.record(
            operation="net.search",
            args={"query": query},
            result_summary=f"{results_count} results",
            duration_ms=round(elapsed, 2),
        )
        return result

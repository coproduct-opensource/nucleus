from __future__ import annotations

import os
import time
from typing import Any, Callable, Dict, Optional, TypeVar

from .client import ProxyClient
from .errors import AccessDenied, ApprovalRequired
from .profiles import ProfileRegistry, ProfileSpec
from .exposure import exposureGuard
from .trace import Trace
from .tools.fs import FileHandle
from .tools.net import NetHandle
from .tools.git import GitHandle

T = TypeVar("T")


class Session:
    """High-level session that wraps a ProxyClient with typed tool handles,
    automatic trace recording, and exposure tracking.

    The session tracks exposure across tool calls using a monotone 3-bool
    semilattice. When all three exposure labels co-occur (the "uninhabitable state"),
    exfiltration-capable operations raise ``StateBlocked`` unless
    explicitly approved.

    Usage::

        with Session(profile="codegen") as s:
            readme = s.fs.read("README.md")          # adds private_datan exposure
            s.fs.write("out.txt", readme.upper())     # neutral
            result = s.approve("fetch", lambda: s.net.fetch("https://example.com"))

    On exit the session exports its trace.  The trace is available
    via :attr:`trace` during and after the session lifetime.
    """

    _canonical_registry: Optional[ProfileRegistry] = None

    def __init__(
        self,
        profile: str = "default",
        proxy_url: Optional[str] = None,
        proxy: Optional[ProxyClient] = None,
        timeout: float = 30.0,
        uninhabitable_state_enabled: bool = True,
        validate_profile: bool = False,
    ) -> None:
        self.profile = profile
        self._proxy_url = proxy_url or os.environ.get("NUCLEUS_PROXY_URL", "")
        self._timeout = timeout
        self._trace = Trace()
        self._external_proxy = proxy
        self._exposure_guard = exposureGuard(uninhabitable_state_enabled=uninhabitable_state_enabled)

        # Resolve profile spec from canonical registry.
        if Session._canonical_registry is None:
            Session._canonical_registry = ProfileRegistry.canonical()
        self._profile_spec: Optional[ProfileSpec] = (
            Session._canonical_registry.get(profile)
        )
        if validate_profile and self._profile_spec is None:
            Session._canonical_registry.resolve(profile)  # raises KeyError

        # These are initialised lazily in __enter__
        self._proxy: Optional[ProxyClient] = None
        self._fs: Optional[FileHandle] = None
        self._net: Optional[NetHandle] = None
        self._git: Optional[GitHandle] = None

    # -- context manager protocol ------------------------------------------

    def __enter__(self) -> Session:
        if self._external_proxy is not None:
            self._proxy = self._external_proxy
        else:
            if not self._proxy_url:
                raise ValueError(
                    "proxy_url must be provided or set via NUCLEUS_PROXY_URL"
                )
            self._proxy = ProxyClient(self._proxy_url, timeout=self._timeout)

        self._fs = FileHandle(self._proxy, self._trace, self._exposure_guard)
        self._net = NetHandle(self._proxy, self._trace, self._exposure_guard)
        self._git = GitHandle(self._proxy, self._trace, self._exposure_guard)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        # Record any exception that caused exit
        if exc_type is not None:
            self._trace.record(
                operation="session.exit",
                args={},
                result_summary=f"exception: {exc_type.__name__}: {exc_val}",
                duration_ms=0,
                policy_decision="deny" if issubclass(exc_type, AccessDenied) else "allow",
            )
        # The trace remains available via self.trace after exit.
        return None  # Do not suppress exceptions

    # -- typed tool accessors ----------------------------------------------

    @property
    def fs(self) -> FileHandle:
        if self._fs is None:
            raise RuntimeError("Session not entered; use 'with Session(...) as s:'")
        return self._fs

    @property
    def net(self) -> NetHandle:
        if self._net is None:
            raise RuntimeError("Session not entered; use 'with Session(...) as s:'")
        return self._net

    @property
    def git(self) -> GitHandle:
        if self._git is None:
            raise RuntimeError("Session not entered; use 'with Session(...) as s:'")
        return self._git

    @property
    def trace(self) -> Trace:
        return self._trace

    @property
    def profile_spec(self) -> Optional[ProfileSpec]:
        """The resolved profile spec, or ``None`` for custom profiles."""
        return self._profile_spec

    @property
    def exposure_summary(self) -> str:
        """Human-readable summary of the current session exposure state."""
        return self._exposure_guard.summary()

    # -- approval helper ---------------------------------------------------

    def approve(self, operation: str, action: Callable[[], T]) -> T:
        """Request approval for *operation* then execute *action*.

        This makes unsafe actions impossible to express without explicit
        approval: the caller must name the operation and provide the
        action as a callable, so both sides of the approval are visible
        in source code.
        """
        if self._proxy is None:
            raise RuntimeError("Session not entered; use 'with Session(...) as s:'")

        start = time.monotonic()
        self._proxy.approve(operation)
        result = action()
        elapsed = (time.monotonic() - start) * 1000
        self._trace.record(
            operation=f"approve:{operation}",
            args={"operation": operation},
            result_summary="approved",
            duration_ms=round(elapsed, 2),
            policy_decision="allow",
        )
        return result

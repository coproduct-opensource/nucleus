from __future__ import annotations

import time
from typing import List, Optional, TYPE_CHECKING

from ..types import CommandOutput

if TYPE_CHECKING:
    from ..client import ProxyClient
    from ..taint import TaintGuard
    from ..trace import Trace


class GitHandle:
    """Typed accessor for git operations.

    Git commands are executed via ProxyClient.run() with appropriate
    arguments.  All calls are recorded in the session trace. An optional
    TaintGuard enforces the trifecta gate before each operation.
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

    def _run_git(
        self,
        args: List[str],
        operation_name: str,
        directory: Optional[str] = None,
    ) -> CommandOutput:
        """Run a git subcommand and record it in the trace."""
        op = f"git.{operation_name}"
        if self._guard:
            self._guard.check(op)
        full_args = ["git"] + args
        start = time.monotonic()
        raw = self._proxy.run(args=full_args, directory=directory)
        elapsed = (time.monotonic() - start) * 1000
        result = CommandOutput.from_dict(raw)
        self._trace.record(
            operation=op,
            args={"git_args": args},
            result_summary=f"exit_code={result.status}",
            duration_ms=round(elapsed, 2),
        )
        if self._guard:
            self._guard.record(op)
        return result

    def commit(
        self,
        message: str,
        paths: Optional[List[str]] = None,
        directory: Optional[str] = None,
    ) -> CommandOutput:
        """Stage files and create a git commit."""
        if paths:
            self._run_git(["add"] + paths, "add", directory=directory)
        return self._run_git(
            ["commit", "-m", message], "commit", directory=directory
        )

    def push(
        self,
        remote: str = "origin",
        branch: Optional[str] = None,
        directory: Optional[str] = None,
    ) -> CommandOutput:
        """Push commits to a remote."""
        args = ["push", remote]
        if branch:
            args.append(branch)
        return self._run_git(args, "push", directory=directory)

    def create_pr(
        self,
        title: str,
        body: str = "",
        base: Optional[str] = None,
        directory: Optional[str] = None,
    ) -> CommandOutput:
        """Create a pull request (delegates to a generic PR creation command)."""
        # Uses a generic 'pr create' pattern that maps to the proxy's run endpoint.
        # The orchestrator is responsible for translating this to the appropriate
        # hosting platform command (e.g. gh, glab, etc.).
        args = ["pr", "create", "--title", title, "--body", body]
        if base:
            args.extend(["--base", base])
        return self._run_git(args, "create_pr", directory=directory)

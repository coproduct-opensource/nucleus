"""AgentDojo pipeline element implementing Portcullis exposure-lattice defense.

Wraps the FunctionsRuntime to intercept tool execution. When a tool call would
complete the uninhabitable triangle, the wrapped runtime returns an error
instead of executing the tool.

Usage:
    from portcullis_defense import PortcullisDefense

    pipeline = AgentPipeline([
        InitQuery(),
        ToolsExecutionLoop([
            PortcullisDefense(),
            ToolsExecutor(),
            llm_element,
        ]),
    ])
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import (
    EmptyEnv,
    FunctionCallArgTypes,
    FunctionReturnType,
    FunctionsRuntime,
    TaskEnvironment,
)
from agentdojo.types import ChatMessage

logger = logging.getLogger("portcullis")

_MIRROR_REMOVED = """\
The pure-Python exposure mirror this defense used has been REMOVED, and is not
coming back. It reimplemented `exposure_core::should_deny`, a function with no
live-path callers — the production IFC gate is `ifc_egress_denial`, reached via
`Kernel::decide_term_with_flow` — and its policy did not match that function
either. Measured over a 430-decision corpus it disagreed with the real kernel on
4.2% of decisions, in both directions: it allowed a destructive write in a
tainted session 15 times, and blocked reads the kernel permits 3 times.

Numbers produced through it would describe a policy nucleus does not run.

To run this benchmark, route tool calls through the `nucleus-flow-replay` crate,
which drives the real kernel decision path. See
`crates/nucleus-flow-replay/tests/kernel_vs_mirror.rs` for the divergence
evidence and `corpus/mirror-verdicts.json` for what the mirror used to decide.
"""


@dataclass
class PortcullisStats:
    """Tracks defense decisions for reporting."""
    allowed: int = 0
    blocked: int = 0
    blocked_tools: list[str] = field(default_factory=list)
    exposure_trajectory: list[str] = field(default_factory=list)


class GuardedRuntime(FunctionsRuntime):
    """FunctionsRuntime wrapper that gates tool execution via exposure tracking.

    Before each tool call, checks if execution would complete the uninhabitable
    triangle. If so, returns an error. Otherwise delegates to the real runtime.
    """

    def __init__(self, inner: FunctionsRuntime, stats: PortcullisStats, exposure: object):
        # Copy the functions registry from the inner runtime
        super().__init__(inner.functions.values())
        self._inner = inner
        self._stats = stats
        self._exposure = exposure

    @property
    def exposure(self) -> object:
        return self._exposure

    def run_function(
        self,
        env: TaskEnvironment | None,
        function: str,
        kwargs: Mapping[str, FunctionCallArgTypes],
        raise_on_error: bool = False,
    ) -> tuple[FunctionReturnType, str | None]:
        # Fail loudly rather than degrade to "allow everything". A defense
        # that silently stops defending is the worst outcome available here:
        # the benchmark would report a security score for a pipeline that has
        # no gate in it at all.
        raise NotImplementedError(_MIRROR_REMOVED)


class PortcullisDefense(BasePipelineElement):
    """Exposure-lattice defense that wraps the FunctionsRuntime.

    Placed BEFORE ToolsExecutor in the pipeline. Replaces the runtime with
    a GuardedRuntime that blocks tool calls completing the uninhabitable state.
    ToolsExecutor then operates on the guarded runtime transparently.
    """

    def __init__(self) -> None:
        # Refuse at construction, not at the first tool call: a pipeline that
        # builds successfully and then dies mid-episode wastes a benchmark run
        # and produces a partial result that looks like data.
        raise NotImplementedError(_MIRROR_REMOVED)

    @property
    def stats(self) -> PortcullisStats:
        return self._stats

    @property
    def exposure(self) -> object:
        return self._guarded.exposure if self._guarded is not None else None

    def reset(self) -> None:
        self._stats = PortcullisStats()
        self._guarded = None

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: TaskEnvironment = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict[str, Any] = {},
    ) -> tuple[str, FunctionsRuntime, TaskEnvironment, Sequence[ChatMessage], dict[str, Any]]:
        """Replace the runtime with a guarded version."""
        if self._guarded is None or self._guarded._inner is not runtime:
            self._guarded = GuardedRuntime(runtime, self._stats, self._exposure)
        # Sync exposure state (in case it was updated by a previous iteration)
        self._exposure = self._guarded.exposure
        return query, self._guarded, env, messages, extra_args

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

from .exposure import ExposureSet, apply_record, should_deny

logger = logging.getLogger("portcullis")


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

    def __init__(self, inner: FunctionsRuntime, stats: PortcullisStats, exposure: ExposureSet):
        # Copy the functions registry from the inner runtime
        super().__init__(inner.functions.values())
        self._inner = inner
        self._stats = stats
        self._exposure = exposure

    @property
    def exposure(self) -> ExposureSet:
        return self._exposure

    def run_function(
        self,
        env: TaskEnvironment | None,
        function: str,
        kwargs: Mapping[str, FunctionCallArgTypes],
        raise_on_error: bool = False,
    ) -> tuple[FunctionReturnType, str | None]:
        if should_deny(self._exposure, function):
            self._stats.blocked += 1
            self._stats.blocked_tools.append(function)
            logger.info("BLOCKED %s (exposure: %s)", function, self._exposure)
            error_msg = (
                f"SecurityError: tool '{function}' was blocked by Portcullis security policy. "
                f"The current exposure state would become uninhabitable."
            )
            if raise_on_error:
                raise RuntimeError(error_msg)
            return "", error_msg

        # Allow — execute and record exposure
        result, error = self._inner.run_function(env, function, kwargs, raise_on_error)
        if error is None:
            self._stats.allowed += 1
            self._exposure = apply_record(self._exposure, function)
            self._stats.exposure_trajectory.append(repr(self._exposure))
        return result, error


class PortcullisDefense(BasePipelineElement):
    """Exposure-lattice defense that wraps the FunctionsRuntime.

    Placed BEFORE ToolsExecutor in the pipeline. Replaces the runtime with
    a GuardedRuntime that blocks tool calls completing the uninhabitable state.
    ToolsExecutor then operates on the guarded runtime transparently.
    """

    def __init__(self) -> None:
        self._stats = PortcullisStats()
        self._exposure = ExposureSet.empty()
        self._guarded: GuardedRuntime | None = None

    @property
    def stats(self) -> PortcullisStats:
        return self._stats

    @property
    def exposure(self) -> ExposureSet:
        if self._guarded is not None:
            return self._guarded.exposure
        return self._exposure

    def reset(self) -> None:
        self._stats = PortcullisStats()
        self._exposure = ExposureSet.empty()
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

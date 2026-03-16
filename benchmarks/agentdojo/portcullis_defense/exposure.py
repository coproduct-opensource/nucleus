"""Pure-Python mirror of portcullis/src/exposure_core.rs.

This module faithfully reimplements the exposure decision kernel from the
Rust crate. The Rust version is verified by 28 Kani bounded model-checking
harnesses; this Python port is tested for parity in test_exposure.py.

Three exposure labels form a lattice:
  - PrivateData: agent has seen private/sensitive data
  - UntrustedContent: agent has ingested untrusted external content
  - ExfilVector: agent has access to an exfiltration channel

When ALL THREE are present simultaneously, the state is "uninhabitable" —
the agent could be tricked (via untrusted content) into exfiltrating
private data. The policy engine blocks tool calls that would complete the
uninhabitable triangle.
"""

from __future__ import annotations

from typing import Optional

from .tool_map import TOOL_MAP, ExposureLabel


class ExposureSet:
    """Immutable set of exposure labels (max 3 elements)."""

    __slots__ = ("_labels",)

    def __init__(self, labels: frozenset[ExposureLabel] | None = None):
        self._labels: frozenset[ExposureLabel] = labels or frozenset()

    @classmethod
    def empty(cls) -> ExposureSet:
        return cls()

    @classmethod
    def singleton(cls, label: ExposureLabel) -> ExposureSet:
        return cls(frozenset({label}))

    def union(self, other: ExposureSet) -> ExposureSet:
        return ExposureSet(self._labels | other._labels)

    def contains(self, label: ExposureLabel) -> bool:
        return label in self._labels

    def is_uninhabitable(self) -> bool:
        return len(self._labels) >= 3

    def count(self) -> int:
        return len(self._labels)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ExposureSet):
            return self._labels == other._labels
        return NotImplemented

    def __repr__(self) -> str:
        names = sorted(l.name for l in self._labels)
        return f"ExposureSet({{{', '.join(names)}}})"


def classify_tool(tool_name: str) -> Optional[ExposureLabel]:
    """Map an AgentDojo tool name to its exposure label.

    Returns None for neutral operations (no exposure contribution)
    or unknown tools (fail-open for utility).
    """
    entry = TOOL_MAP.get(tool_name)
    if entry is None:
        return None
    return entry


def project_exposure(current: ExposureSet, tool_name: str) -> ExposureSet:
    """Project what the exposure set WOULD be if this tool executes.

    Mirror of portcullis::exposure_core::project_exposure.
    """
    label = classify_tool(tool_name)
    if label is None:
        return current
    return current.union(ExposureSet.singleton(label))


def should_deny(current: ExposureSet, tool_name: str) -> bool:
    """Should this tool call be denied?

    Two policies are enforced (analogous to FIDES P-T and P-F):

    1. **Trusted Action (P-T / integrity)**: Any consequential action
       (ExfilVector tool) is blocked when the context contains
       UntrustedContent. The decision to act must not be influenced
       by attacker-controllable data.

    2. **Uninhabitable State (P-F / exfiltration)**: Any tool call that
       would complete the uninhabitable triangle (all 3 labels present)
       is blocked, preventing data exfiltration chains.

    Reading data and ingesting content are always allowed — the agent
    needs to do its job. Only consequential outbound actions are gated.
    """
    label = classify_tool(tool_name)
    if label is None:
        return False

    # P-T: Block consequential actions in untrusted context
    # If the agent has ingested untrusted content, it must not perform
    # consequential actions (ExfilVector tools) — the decision may have
    # been influenced by a prompt injection in the untrusted data.
    if label == ExposureLabel.ExfilVector and current.contains(ExposureLabel.UntrustedContent):
        return True

    # P-F: Block uninhabitable state completion
    # If executing this tool would result in all 3 exposure labels being
    # present, block it to prevent exfiltration chains.
    projected = project_exposure(current, tool_name)
    if projected.is_uninhabitable():
        return True

    return False


def apply_record(current: ExposureSet, tool_name: str) -> ExposureSet:
    """Record a successful tool execution in the exposure accumulator.

    Mirror of portcullis::exposure_core::apply_record.
    """
    label = classify_tool(tool_name)
    if label is None:
        return current
    return current.union(ExposureSet.singleton(label))

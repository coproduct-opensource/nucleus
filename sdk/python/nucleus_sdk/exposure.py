"""Session-scoped exposure tracking with uninhabitable state gate.

Mirrors the Verus-verified exposure_core decision kernel from portcullis.
The three exposure labels form a 3-bool semilattice — exposure can only increase
(monotone union), never decrease within a session.

When all three labels co-occur (the "uninhabitable state"), exfiltration-capable
operations require explicit approval before proceeding.
"""

from __future__ import annotations

from enum import Enum, auto
from typing import FrozenSet, Optional


class ExposureLabel(Enum):
    """The three legs of the exposure uninhabitable state."""

    PRIVATE_DATA = auto()
    """Private data was accessed (read, glob, grep)."""

    UNTRUSTED_CONTENT = auto()
    """Untrusted external content was ingested (web_fetch, web_search)."""

    EXFIL_VECTOR = auto()
    """An exfiltration-capable operation was performed (run, git_push, create_pr)."""


# Map SDK operation names to their exposure contribution.
# None means the operation is exposure-neutral (no contribution).
_OPERATION_exposure: dict[str, Optional[ExposureLabel]] = {
    "fs.read": ExposureLabel.PRIVATE_DATA,
    "fs.write": None,
    "fs.glob": ExposureLabel.PRIVATE_DATA,
    "fs.grep": ExposureLabel.PRIVATE_DATA,
    "net.fetch": ExposureLabel.UNTRUSTED_CONTENT,
    "net.search": ExposureLabel.UNTRUSTED_CONTENT,
    "git.push": ExposureLabel.EXFIL_VECTOR,
    "git.create_pr": ExposureLabel.EXFIL_VECTOR,
    "git.commit": None,
    "git.add": None,
    "run": ExposureLabel.EXFIL_VECTOR,
}

# Operations where RunBash-style omnibus projection applies.
# These conservatively project PRIVATE_DATA + EXFIL_VECTOR because
# a shell command can both read files and exfiltrate data.
_OMNIBUS_OPERATIONS = frozenset({"run"})

# Operations that require approval when uninhabitable state would complete.
_EXFIL_OPERATIONS = frozenset({"run", "git.push", "git.create_pr"})


class ExposureSet:
    """Monotone 3-bool exposure accumulator.

    Mirrors portcullis::guard::ExposureSet. The set can only grow via union —
    there is no way to remove a label once added.
    """

    __slots__ = ("_labels",)

    def __init__(self, labels: Optional[FrozenSet[ExposureLabel]] = None) -> None:
        self._labels: FrozenSet[ExposureLabel] = labels or frozenset()

    @classmethod
    def empty(cls) -> ExposureSet:
        return cls()

    def union(self, other: ExposureSet) -> ExposureSet:
        return ExposureSet(self._labels | other._labels)

    def with_label(self, label: ExposureLabel) -> ExposureSet:
        return ExposureSet(self._labels | {label})

    def contains(self, label: ExposureLabel) -> bool:
        return label in self._labels

    def is_uninhabitable(self) -> bool:
        return (
            ExposureLabel.PRIVATE_DATA in self._labels
            and ExposureLabel.UNTRUSTED_CONTENT in self._labels
            and ExposureLabel.EXFIL_VECTOR in self._labels
        )

    @property
    def labels(self) -> FrozenSet[ExposureLabel]:
        return self._labels

    def summary(self) -> str:
        if not self._labels:
            return "clean"
        parts = []
        if ExposureLabel.PRIVATE_DATA in self._labels:
            parts.append("private_data")
        if ExposureLabel.UNTRUSTED_CONTENT in self._labels:
            parts.append("untrusted_content")
        if ExposureLabel.EXFIL_VECTOR in self._labels:
            parts.append("exfil_vector")
        return "+".join(parts)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ExposureSet):
            return NotImplemented
        return self._labels == other._labels

    def __repr__(self) -> str:
        return f"ExposureSet({self.summary()})"


def classify_operation(operation: str) -> Optional[ExposureLabel]:
    """Map an operation name to its exposure label.

    Mirrors portcullis::exposure_core::classify_operation.
    """
    return _OPERATION_exposure.get(operation)


def project_exposure(current: ExposureSet, operation: str) -> ExposureSet:
    """Project what the exposure set WOULD be if this operation executes.

    Mirrors portcullis::exposure_core::project_exposure. RunBash-style operations
    are treated as omnibus (conservatively project both PRIVATE_DATA and
    EXFIL_VECTOR).
    """
    if operation in _OMNIBUS_OPERATIONS:
        return (
            current.with_label(ExposureLabel.PRIVATE_DATA).with_label(
                ExposureLabel.EXFIL_VECTOR
            )
        )
    label = classify_operation(operation)
    if label is not None:
        return current.with_label(label)
    return current


def should_deny(
    current: ExposureSet,
    operation: str,
    uninhabitable_state_enabled: bool = True,
) -> bool:
    """Pure denial decision: should this operation be blocked?

    Mirrors portcullis::exposure_core::should_deny.
    Returns True if the operation would complete the uninhabitable state and
    the operation is exfiltration-capable.
    """
    if not uninhabitable_state_enabled:
        return False
    requires_approval = operation in _EXFIL_OPERATIONS
    if not requires_approval:
        return False
    projected = project_exposure(current, operation)
    return projected.is_uninhabitable()


def apply_record(current: ExposureSet, operation: str) -> ExposureSet:
    """Record a successful operation's exposure contribution.

    Mirrors portcullis::exposure_core::apply_record. Unlike project_exposure,
    this does NOT use omnibus projection — it records what actually happened.
    """
    label = classify_operation(operation)
    if label is not None:
        return current.with_label(label)
    return current


class exposureGuard:
    """Session-scoped exposure guard that tool handles call before/after operations.

    This is the Python equivalent of Sessionexposure in nucleus-mcp's Rust code.
    Tool handles call ``check()`` before executing and ``record()`` after
    a successful execution.
    """

    def __init__(self, uninhabitable_state_enabled: bool = True) -> None:
        self._exposure = ExposureSet.empty()
        self._uninhabitable_enabled = uninhabitable_state_enabled

    @property
    def exposure(self) -> ExposureSet:
        return self._exposure

    def check(self, operation: str) -> None:
        """Raise StateBlocked if the operation would complete the uninhabitable state.

        Must be called BEFORE the operation executes. This is the pre-call
        gate that blocks exfiltration when private data and untrusted content
        have both been accessed.
        """
        if should_deny(self._exposure, operation, self._uninhabitable_enabled):
            from .errors import StateBlocked

            raise StateBlocked(
                f"uninhabitable state blocked: {operation} would complete exposure uninhabitable state "
                f"({self._exposure.summary()}). The session has accessed private data "
                f"and untrusted content -- this exfiltration-capable operation "
                f"requires explicit approval.",
                kind="uninhabitable_blocked",
                operation=operation,
            )

    def record(self, operation: str) -> None:
        """Record a successful operation's exposure contribution.

        Must be called AFTER the operation succeeds. Exposure accumulation
        is monotone — it can only increase.
        """
        self._exposure = apply_record(self._exposure, operation)

    def summary(self) -> str:
        return self._exposure.summary()

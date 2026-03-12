"""Canonical profile registry mirroring portcullis ProfileRegistry.

Provides the 10 built-in profiles from the Rust ``portcullis`` crate as
Python dataclasses, with name normalization and lookup.  This lets Python
SDK users validate and inspect profile names before sending them to the
tool-proxy.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, List, Optional


class CapabilityLevel(str, Enum):
    """Three-level capability state matching Rust ``CapabilityLevel``."""

    NEVER = "never"
    LOW_RISK = "low_risk"
    ALWAYS = "always"


@dataclass(frozen=True)
class Capabilities:
    """Capability levels for all 12 operations."""

    read_files: CapabilityLevel = CapabilityLevel.ALWAYS
    write_files: CapabilityLevel = CapabilityLevel.LOW_RISK
    edit_files: CapabilityLevel = CapabilityLevel.LOW_RISK
    run_bash: CapabilityLevel = CapabilityLevel.NEVER
    glob_search: CapabilityLevel = CapabilityLevel.ALWAYS
    grep_search: CapabilityLevel = CapabilityLevel.ALWAYS
    web_search: CapabilityLevel = CapabilityLevel.LOW_RISK
    web_fetch: CapabilityLevel = CapabilityLevel.LOW_RISK
    git_commit: CapabilityLevel = CapabilityLevel.LOW_RISK
    git_push: CapabilityLevel = CapabilityLevel.NEVER
    create_pr: CapabilityLevel = CapabilityLevel.LOW_RISK
    manage_pods: CapabilityLevel = CapabilityLevel.NEVER

    def allowed_operations(self) -> List[str]:
        """Return operations that are not ``NEVER``."""
        ops = []
        for op in (
            "read_files",
            "write_files",
            "edit_files",
            "run_bash",
            "glob_search",
            "grep_search",
            "web_search",
            "web_fetch",
            "git_commit",
            "git_push",
            "create_pr",
            "manage_pods",
        ):
            if getattr(self, op) != CapabilityLevel.NEVER:
                ops.append(op)
        return ops

    def denied_operations(self) -> List[str]:
        """Return operations that are ``NEVER``."""
        ops = []
        for op in (
            "read_files",
            "write_files",
            "edit_files",
            "run_bash",
            "glob_search",
            "grep_search",
            "web_search",
            "web_fetch",
            "git_commit",
            "git_push",
            "create_pr",
            "manage_pods",
        ):
            if getattr(self, op) == CapabilityLevel.NEVER:
                ops.append(op)
        return ops


@dataclass(frozen=True)
class BudgetSpec:
    """Budget limits for a profile."""

    max_cost_usd: str = "5.00"
    max_input_tokens: int = 100000
    max_output_tokens: int = 10000


@dataclass(frozen=True)
class TimeSpec:
    """Time bounds for a profile."""

    duration_minutes: Optional[int] = None
    duration_hours: Optional[int] = None


@dataclass(frozen=True)
class ProfileSpec:
    """A complete profile specification mirroring the Rust ``ProfileSpec``.

    Each profile fully declares capability levels, blocked paths, budget
    limits, and time bounds.
    """

    name: str
    description: str
    capabilities: Capabilities
    obligations: FrozenSet[str] = frozenset()
    blocked_paths: FrozenSet[str] = frozenset()
    budget: Optional[BudgetSpec] = None
    time: Optional[TimeSpec] = None

    @property
    def trifecta_components(self) -> int:
        """Count how many trifecta components are present.

        - private_data: read_files != NEVER
        - untrusted_content: web_search or web_fetch != NEVER
        - exfil_vector: git_push, create_pr, or run_bash != NEVER

        Returns 0-3.
        """
        count = 0
        if self.capabilities.read_files != CapabilityLevel.NEVER:
            count += 1
        if (
            self.capabilities.web_search != CapabilityLevel.NEVER
            or self.capabilities.web_fetch != CapabilityLevel.NEVER
        ):
            count += 1
        if (
            self.capabilities.git_push != CapabilityLevel.NEVER
            or self.capabilities.create_pr != CapabilityLevel.NEVER
            or self.capabilities.run_bash != CapabilityLevel.NEVER
        ):
            count += 1
        return count

    @property
    def trifecta_safe(self) -> bool:
        """True if the trifecta can never fire (< 3 components present)."""
        return self.trifecta_components < 3


# Standard blocked paths shared by all canonical profiles.
_STANDARD_BLOCKED: FrozenSet[str] = frozenset(
    [
        "**/.ssh/**",
        "**/.aws/**",
        "**/.env",
        "**/.env.*",
        "**/credentials*",
        "/etc/shadow",
        "/etc/passwd",
    ]
)

_STANDARD_BLOCKED_SHORT: FrozenSet[str] = frozenset(
    [
        "**/.ssh/**",
        "**/.aws/**",
        "**/.env",
        "**/.env.*",
        "**/credentials*",
    ]
)

# -- Canonical profiles -------------------------------------------------------

SAFE_PR_FIXER = ProfileSpec(
    name="safe-pr-fixer",
    description="Safe PR fixer \u2014 no push, no PR creation. CI wrapper pushes.",
    capabilities=Capabilities(
        read_files=CapabilityLevel.ALWAYS,
        write_files=CapabilityLevel.LOW_RISK,
        edit_files=CapabilityLevel.LOW_RISK,
        run_bash=CapabilityLevel.LOW_RISK,
        glob_search=CapabilityLevel.ALWAYS,
        grep_search=CapabilityLevel.ALWAYS,
        web_search=CapabilityLevel.NEVER,
        web_fetch=CapabilityLevel.LOW_RISK,
        git_commit=CapabilityLevel.LOW_RISK,
        git_push=CapabilityLevel.NEVER,
        create_pr=CapabilityLevel.NEVER,
        manage_pods=CapabilityLevel.NEVER,
    ),
    blocked_paths=_STANDARD_BLOCKED,
    budget=BudgetSpec(max_cost_usd="5.00", max_input_tokens=100000, max_output_tokens=10000),
    time=TimeSpec(duration_hours=2),
)

DOC_EDITOR = ProfileSpec(
    name="doc-editor",
    description="Documentation editor \u2014 read all, write docs only, no network",
    capabilities=Capabilities(
        read_files=CapabilityLevel.ALWAYS,
        write_files=CapabilityLevel.LOW_RISK,
        edit_files=CapabilityLevel.LOW_RISK,
        run_bash=CapabilityLevel.NEVER,
        glob_search=CapabilityLevel.ALWAYS,
        grep_search=CapabilityLevel.ALWAYS,
        web_search=CapabilityLevel.NEVER,
        web_fetch=CapabilityLevel.NEVER,
        git_commit=CapabilityLevel.LOW_RISK,
        git_push=CapabilityLevel.NEVER,
        create_pr=CapabilityLevel.NEVER,
        manage_pods=CapabilityLevel.NEVER,
    ),
    blocked_paths=frozenset(
        ["**/.ssh/**", "**/.aws/**", "**/.env", "**/.env.*", "**/credentials*", "/etc/shadow"]
    ),
    budget=BudgetSpec(max_cost_usd="2.00", max_input_tokens=50000, max_output_tokens=10000),
    time=TimeSpec(duration_hours=1),
)

TEST_RUNNER = ProfileSpec(
    name="test-runner",
    description="Test runner \u2014 read source, execute tests, no source writes",
    capabilities=Capabilities(
        read_files=CapabilityLevel.ALWAYS,
        write_files=CapabilityLevel.NEVER,
        edit_files=CapabilityLevel.NEVER,
        run_bash=CapabilityLevel.LOW_RISK,
        glob_search=CapabilityLevel.ALWAYS,
        grep_search=CapabilityLevel.ALWAYS,
        web_search=CapabilityLevel.NEVER,
        web_fetch=CapabilityLevel.NEVER,
        git_commit=CapabilityLevel.NEVER,
        git_push=CapabilityLevel.NEVER,
        create_pr=CapabilityLevel.NEVER,
        manage_pods=CapabilityLevel.NEVER,
    ),
    blocked_paths=_STANDARD_BLOCKED_SHORT,
    budget=BudgetSpec(max_cost_usd="1.00", max_input_tokens=50000, max_output_tokens=5000),
    time=TimeSpec(duration_minutes=30),
)

TRIAGE_BOT = ProfileSpec(
    name="triage-bot",
    description="Triage bot \u2014 read, search, fetch context. No code changes.",
    capabilities=Capabilities(
        read_files=CapabilityLevel.ALWAYS,
        write_files=CapabilityLevel.NEVER,
        edit_files=CapabilityLevel.NEVER,
        run_bash=CapabilityLevel.NEVER,
        glob_search=CapabilityLevel.ALWAYS,
        grep_search=CapabilityLevel.ALWAYS,
        web_search=CapabilityLevel.LOW_RISK,
        web_fetch=CapabilityLevel.LOW_RISK,
        git_commit=CapabilityLevel.NEVER,
        git_push=CapabilityLevel.NEVER,
        create_pr=CapabilityLevel.NEVER,
        manage_pods=CapabilityLevel.NEVER,
    ),
    blocked_paths=_STANDARD_BLOCKED_SHORT,
    budget=BudgetSpec(max_cost_usd="1.00", max_input_tokens=50000, max_output_tokens=5000),
    time=TimeSpec(duration_minutes=30),
)

CODE_REVIEW = ProfileSpec(
    name="code-review",
    description="Code review \u2014 read source, search web for context, no modifications",
    capabilities=Capabilities(
        read_files=CapabilityLevel.ALWAYS,
        write_files=CapabilityLevel.NEVER,
        edit_files=CapabilityLevel.NEVER,
        run_bash=CapabilityLevel.NEVER,
        glob_search=CapabilityLevel.ALWAYS,
        grep_search=CapabilityLevel.ALWAYS,
        web_search=CapabilityLevel.LOW_RISK,
        web_fetch=CapabilityLevel.NEVER,
        git_commit=CapabilityLevel.NEVER,
        git_push=CapabilityLevel.NEVER,
        create_pr=CapabilityLevel.NEVER,
        manage_pods=CapabilityLevel.NEVER,
    ),
    obligations=frozenset(["web_search"]),
    blocked_paths=_STANDARD_BLOCKED,
    budget=BudgetSpec(max_cost_usd="1.00", max_input_tokens=50000, max_output_tokens=5000),
    time=TimeSpec(duration_minutes=30),
)

CODEGEN = ProfileSpec(
    name="codegen",
    description="Code generation \u2014 read/write/edit/run, network-isolated, no push",
    capabilities=Capabilities(
        read_files=CapabilityLevel.ALWAYS,
        write_files=CapabilityLevel.LOW_RISK,
        edit_files=CapabilityLevel.LOW_RISK,
        run_bash=CapabilityLevel.LOW_RISK,
        glob_search=CapabilityLevel.ALWAYS,
        grep_search=CapabilityLevel.ALWAYS,
        web_search=CapabilityLevel.NEVER,
        web_fetch=CapabilityLevel.NEVER,
        git_commit=CapabilityLevel.LOW_RISK,
        git_push=CapabilityLevel.NEVER,
        create_pr=CapabilityLevel.NEVER,
        manage_pods=CapabilityLevel.NEVER,
    ),
    blocked_paths=_STANDARD_BLOCKED,
    budget=BudgetSpec(max_cost_usd="5.00", max_input_tokens=100000, max_output_tokens=10000),
    time=TimeSpec(duration_hours=1),
)

RELEASE = ProfileSpec(
    name="release",
    description="Release \u2014 full capabilities, approval required for push and PR",
    capabilities=Capabilities(
        read_files=CapabilityLevel.ALWAYS,
        write_files=CapabilityLevel.LOW_RISK,
        edit_files=CapabilityLevel.LOW_RISK,
        run_bash=CapabilityLevel.LOW_RISK,
        glob_search=CapabilityLevel.ALWAYS,
        grep_search=CapabilityLevel.ALWAYS,
        web_search=CapabilityLevel.LOW_RISK,
        web_fetch=CapabilityLevel.LOW_RISK,
        git_commit=CapabilityLevel.LOW_RISK,
        git_push=CapabilityLevel.LOW_RISK,
        create_pr=CapabilityLevel.LOW_RISK,
        manage_pods=CapabilityLevel.NEVER,
    ),
    obligations=frozenset(["git_push", "create_pr"]),
    blocked_paths=_STANDARD_BLOCKED,
    budget=BudgetSpec(max_cost_usd="5.00", max_input_tokens=100000, max_output_tokens=10000),
    time=TimeSpec(duration_hours=2),
)

RESEARCH_WEB = ProfileSpec(
    name="research-web",
    description="Web research \u2014 read files, search/fetch web, no writes or execution",
    capabilities=Capabilities(
        read_files=CapabilityLevel.LOW_RISK,
        write_files=CapabilityLevel.NEVER,
        edit_files=CapabilityLevel.NEVER,
        run_bash=CapabilityLevel.NEVER,
        glob_search=CapabilityLevel.ALWAYS,
        grep_search=CapabilityLevel.ALWAYS,
        web_search=CapabilityLevel.LOW_RISK,
        web_fetch=CapabilityLevel.LOW_RISK,
        git_commit=CapabilityLevel.NEVER,
        git_push=CapabilityLevel.NEVER,
        create_pr=CapabilityLevel.NEVER,
        manage_pods=CapabilityLevel.NEVER,
    ),
    blocked_paths=_STANDARD_BLOCKED,
    budget=BudgetSpec(max_cost_usd="1.50", max_input_tokens=50000, max_output_tokens=5000),
    time=TimeSpec(duration_minutes=45),
)

READ_ONLY = ProfileSpec(
    name="read-only",
    description="Read only \u2014 read files and search, no writes or network",
    capabilities=Capabilities(
        read_files=CapabilityLevel.ALWAYS,
        write_files=CapabilityLevel.NEVER,
        edit_files=CapabilityLevel.NEVER,
        run_bash=CapabilityLevel.NEVER,
        glob_search=CapabilityLevel.ALWAYS,
        grep_search=CapabilityLevel.ALWAYS,
        web_search=CapabilityLevel.NEVER,
        web_fetch=CapabilityLevel.NEVER,
        git_commit=CapabilityLevel.NEVER,
        git_push=CapabilityLevel.NEVER,
        create_pr=CapabilityLevel.NEVER,
        manage_pods=CapabilityLevel.NEVER,
    ),
    blocked_paths=_STANDARD_BLOCKED,
    budget=BudgetSpec(max_cost_usd="1.00", max_input_tokens=50000, max_output_tokens=5000),
    time=TimeSpec(duration_minutes=30),
)

LOCAL_DEV = ProfileSpec(
    name="local-dev",
    description="Local dev \u2014 read/write/edit/run/commit, no network, no push",
    capabilities=Capabilities(
        read_files=CapabilityLevel.ALWAYS,
        write_files=CapabilityLevel.LOW_RISK,
        edit_files=CapabilityLevel.LOW_RISK,
        run_bash=CapabilityLevel.LOW_RISK,
        glob_search=CapabilityLevel.ALWAYS,
        grep_search=CapabilityLevel.ALWAYS,
        web_search=CapabilityLevel.NEVER,
        web_fetch=CapabilityLevel.NEVER,
        git_commit=CapabilityLevel.LOW_RISK,
        git_push=CapabilityLevel.NEVER,
        create_pr=CapabilityLevel.NEVER,
        manage_pods=CapabilityLevel.NEVER,
    ),
    blocked_paths=_STANDARD_BLOCKED,
    budget=BudgetSpec(max_cost_usd="3.00", max_input_tokens=100000, max_output_tokens=10000),
    time=TimeSpec(duration_hours=2),
)


class ProfileRegistry:
    """Registry of named profiles, mirroring the Rust ``ProfileRegistry``.

    Provides lookup by name with case-insensitive, hyphen/underscore-
    normalized matching.
    """

    def __init__(self) -> None:
        self._profiles: Dict[str, ProfileSpec] = {}

    def register(self, spec: ProfileSpec) -> None:
        """Add or replace a profile."""
        self._profiles[self._normalize(spec.name)] = spec

    def resolve(self, name: str) -> ProfileSpec:
        """Look up a profile by name.

        Raises ``KeyError`` if not found.
        """
        normalized = self._normalize(name)
        if normalized not in self._profiles:
            available = ", ".join(sorted(self.names()))
            raise KeyError(f"unknown profile {name!r}; available: {available}")
        return self._profiles[normalized]

    def names(self) -> List[str]:
        """Return all registered profile names (original casing)."""
        return [p.name for p in self._profiles.values()]

    def get(self, name: str) -> Optional[ProfileSpec]:
        """Look up a profile, returning ``None`` if not found."""
        return self._profiles.get(self._normalize(name))

    def __contains__(self, name: str) -> bool:
        return self._normalize(name) in self._profiles

    def __len__(self) -> int:
        return len(self._profiles)

    @staticmethod
    def _normalize(name: str) -> str:
        return name.lower().replace("_", "-")

    @classmethod
    def canonical(cls) -> ProfileRegistry:
        """Create a registry with the 10 built-in canonical profiles."""
        registry = cls()
        for profile in _CANONICAL_PROFILES:
            registry.register(profile)
        return registry


_CANONICAL_PROFILES: List[ProfileSpec] = [
    SAFE_PR_FIXER,
    DOC_EDITOR,
    TEST_RUNNER,
    TRIAGE_BOT,
    CODE_REVIEW,
    CODEGEN,
    RELEASE,
    RESEARCH_WEB,
    READ_ONLY,
    LOCAL_DEV,
]

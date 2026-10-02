"""Pure-Python nucleus kernel for tool call gating.

This is a lightweight reimplementation of the core decision logic
from portcullis. It does NOT require the Rust binary — it runs
entirely in Python for easy integration with agent frameworks.

For production use with full IFC enforcement, use the Rust
nucleus-claude-hook binary instead.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Operation(Enum):
    """Tool operations that can be gated by the kernel."""

    READ_FILES = "read_files"
    WRITE_FILES = "write_files"
    EDIT_FILES = "edit_files"
    RUN_BASH = "run_bash"
    GLOB_SEARCH = "glob_search"
    GREP_SEARCH = "grep_search"
    WEB_SEARCH = "web_search"
    WEB_FETCH = "web_fetch"
    GIT_COMMIT = "git_commit"
    GIT_PUSH = "git_push"
    CREATE_PR = "create_pr"
    MANAGE_PODS = "manage_pods"
    SPAWN_AGENT = "spawn_agent"


class CapabilityLevel(Enum):
    """Permission level for an operation."""

    NEVER = 0
    LOW_RISK = 1
    ALWAYS = 2


class Profile(Enum):
    """Built-in permission profiles."""

    READ_ONLY = "read_only"
    CODE_REVIEW = "code_review"
    EDIT_ONLY = "edit_only"
    FIX_ISSUE = "fix_issue"
    SAFE_PR_FIXER = "safe_pr_fixer"
    RELEASE = "release"
    PERMISSIVE = "permissive"


# Exposure labels for the uninhabitable state detector
class ExposureLabel(Enum):
    PRIVATE_DATA = "private_data"
    UNTRUSTED_CONTENT = "untrusted_content"
    EXFIL_VECTOR = "exfil_vector"


@dataclass
class Decision:
    """Result of a kernel decision."""

    allowed: bool
    operation: Operation
    reason: Optional[str] = None
    exposure_count: int = 0
    web_tainted: bool = False

    @property
    def denied(self) -> bool:
        return not self.allowed


# Profile capability definitions
PROFILES: dict[str, dict[Operation, CapabilityLevel]] = {
    "read_only": {
        Operation.READ_FILES: CapabilityLevel.ALWAYS,
        Operation.GLOB_SEARCH: CapabilityLevel.ALWAYS,
        Operation.GREP_SEARCH: CapabilityLevel.ALWAYS,
    },
    "safe_pr_fixer": {
        Operation.READ_FILES: CapabilityLevel.ALWAYS,
        Operation.WRITE_FILES: CapabilityLevel.LOW_RISK,
        Operation.EDIT_FILES: CapabilityLevel.LOW_RISK,
        Operation.RUN_BASH: CapabilityLevel.LOW_RISK,
        Operation.GLOB_SEARCH: CapabilityLevel.ALWAYS,
        Operation.GREP_SEARCH: CapabilityLevel.ALWAYS,
        Operation.WEB_SEARCH: CapabilityLevel.LOW_RISK,
        Operation.WEB_FETCH: CapabilityLevel.LOW_RISK,
        Operation.GIT_COMMIT: CapabilityLevel.LOW_RISK,
        Operation.SPAWN_AGENT: CapabilityLevel.LOW_RISK,
    },
    "permissive": {op: CapabilityLevel.ALWAYS for op in Operation},
}

# Tool name → Operation mapping (matches Rust classify_tool)
TOOL_MAP: dict[str, Operation] = {
    "Bash": Operation.RUN_BASH,
    "Read": Operation.READ_FILES,
    "Write": Operation.WRITE_FILES,
    "Edit": Operation.EDIT_FILES,
    "Glob": Operation.GLOB_SEARCH,
    "Grep": Operation.GREP_SEARCH,
    "WebFetch": Operation.WEB_FETCH,
    "WebSearch": Operation.WEB_SEARCH,
    "Agent": Operation.SPAWN_AGENT,
}

# Exposure classification
EXPOSURE_MAP: dict[Operation, ExposureLabel] = {
    Operation.READ_FILES: ExposureLabel.PRIVATE_DATA,
    Operation.GLOB_SEARCH: ExposureLabel.PRIVATE_DATA,
    Operation.GREP_SEARCH: ExposureLabel.PRIVATE_DATA,
    Operation.WEB_FETCH: ExposureLabel.UNTRUSTED_CONTENT,
    Operation.WEB_SEARCH: ExposureLabel.UNTRUSTED_CONTENT,
    Operation.RUN_BASH: ExposureLabel.EXFIL_VECTOR,
    Operation.GIT_PUSH: ExposureLabel.EXFIL_VECTOR,
    Operation.CREATE_PR: ExposureLabel.EXFIL_VECTOR,
    Operation.SPAWN_AGENT: ExposureLabel.EXFIL_VECTOR,
}


class Kernel:
    """Pure-Python nucleus kernel for tool call gating.

    Tracks capabilities, exposure accumulation, and web taint.

    Args:
        profile: Permission profile name (default: "safe_pr_fixer")
    """

    def __init__(self, profile: str = "safe_pr_fixer"):
        self.profile_name = profile
        caps = PROFILES.get(profile, PROFILES["safe_pr_fixer"])
        self._capabilities: dict[Operation, CapabilityLevel] = {
            op: caps.get(op, CapabilityLevel.NEVER) for op in Operation
        }
        self._exposure: set[ExposureLabel] = set()
        self._web_tainted: bool = False
        self._decisions: list[dict] = []

    def classify_tool(self, tool_name: str) -> Operation:
        """Map a tool name to an Operation."""
        if tool_name in TOOL_MAP:
            return TOOL_MAP[tool_name]
        if tool_name.startswith("mcp__"):
            return self._classify_mcp(tool_name)
        return Operation.RUN_BASH  # fail-closed

    def _classify_mcp(self, name: str) -> Operation:
        parts = name.split("__")
        tool = parts[2] if len(parts) > 2 else name
        if any(k in tool for k in ("run", "exec", "shell", "command")):
            return Operation.RUN_BASH
        if any(k in tool for k in ("fetch", "download", "http", "browse")):
            return Operation.WEB_FETCH
        if any(k in tool for k in ("write", "create", "update", "delete")):
            return Operation.WRITE_FILES
        if any(k in tool for k in ("read", "get", "list", "search", "query")):
            return Operation.READ_FILES
        if any(k in tool for k in ("push", "commit", "merge")):
            return Operation.GIT_PUSH
        return Operation.RUN_BASH  # fail-closed

    def decide(self, tool_name: str, subject: str = "") -> Decision:
        """Make a permission decision for a tool call.

        Args:
            tool_name: The tool name (e.g., "Bash", "Read", "WebFetch")
            subject: Human-readable subject (file path, URL, command)

        Returns:
            Decision with allowed/denied status and reason
        """
        op = self.classify_tool(tool_name)

        # 1. Capability check
        cap = self._capabilities.get(op, CapabilityLevel.NEVER)
        if cap == CapabilityLevel.NEVER:
            return Decision(
                allowed=False,
                operation=op,
                reason=f"capability {op.value} is Never",
                exposure_count=len(self._exposure),
                web_tainted=self._web_tainted,
            )

        # 2. Flow taint check — web-tainted sessions can't write
        if self._web_tainted and op in (
            Operation.WRITE_FILES,
            Operation.EDIT_FILES,
            Operation.RUN_BASH,
            Operation.GIT_COMMIT,
            Operation.GIT_PUSH,
            Operation.CREATE_PR,
            Operation.SPAWN_AGENT,
        ):
            return Decision(
                allowed=False,
                operation=op,
                reason="session tainted by web content — write/exec blocked",
                exposure_count=len(self._exposure),
                web_tainted=True,
            )

        # 3. Exposure tracking
        if op in EXPOSURE_MAP:
            self._exposure.add(EXPOSURE_MAP[op])

        # 4. Track web taint
        if op in (Operation.WEB_FETCH, Operation.WEB_SEARCH):
            self._web_tainted = True

        # 5. Uninhabitable state check (all 3 legs present)
        if len(self._exposure) >= 3 and op in (
            Operation.RUN_BASH,
            Operation.GIT_PUSH,
            Operation.CREATE_PR,
            Operation.SPAWN_AGENT,
        ):
            return Decision(
                allowed=False,
                operation=op,
                reason="uninhabitable state — all 3 exposure legs present, exfil blocked",
                exposure_count=len(self._exposure),
                web_tainted=self._web_tainted,
            )

        # Record decision
        self._decisions.append(
            {
                "timestamp": time.time(),
                "operation": op.value,
                "subject": subject,
                "allowed": True,
            }
        )

        return Decision(
            allowed=True,
            operation=op,
            exposure_count=len(self._exposure),
            web_tainted=self._web_tainted,
        )

    @property
    def exposure_count(self) -> int:
        """Number of distinct exposure labels accumulated."""
        return len(self._exposure)

    @property
    def web_tainted(self) -> bool:
        """Whether the session has been tainted by web content."""
        return self._web_tainted

    @property
    def decisions(self) -> list[dict]:
        """List of decisions made in this session."""
        return list(self._decisions)

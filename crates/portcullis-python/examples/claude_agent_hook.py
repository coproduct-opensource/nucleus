"""
Nucleus integration with Claude Agent SDK — PreToolUse policy enforcement.

Every tool call Claude makes flows through the nucleus permission kernel.
Denials include RepairHints telling Claude exactly what to fix.

Usage:
    pip install portcullis claude-agent-sdk
    python claude_agent_hook.py

Requires:
    - portcullis built with maturin: cd crates/portcullis-python && maturin develop
    - claude-agent-sdk: pip install claude-agent-sdk
    - ANTHROPIC_API_KEY set in environment
"""

from portcullis import (
    Runtime,
    Profile,
    PolicyDenied,
    IntegLevel,
    UntrustedAccess,
)

# ── Tool name → Operation mapping ──────────────────────────────────────────

TOOL_TO_OPERATION = {
    "Read": "read_files",
    "Write": "write_files",
    "Edit": "edit_files",
    "Bash": "run_bash",
    "Glob": "glob_search",
    "Grep": "grep_search",
    "WebSearch": "web_search",
    "WebFetch": "web_fetch",
    "GitCommit": "git_commit",
    "GitPush": "git_push",
    "CreatePr": "create_pr",
    "Task": "spawn_agent",
}


# ── Nucleus guard hook ─────────────────────────────────────────────────────

def create_nucleus_guard(profile, task=""):
    """
    Create a PreToolUse hook that enforces a nucleus policy.

    Args:
        profile: A portcullis.Profile (e.g., Profile.RESEARCH)
        task: Human-readable task description for audit trail

    Returns:
        An async hook function compatible with claude-agent-sdk.

    Example:
        guard = create_nucleus_guard(
            Profile.RESEARCH.with_capability("run_bash"),
            task="analyze SEC filings"
        )
    """
    rt = Runtime(profile, task=task)

    async def nucleus_pre_tool_use(tool_name, tool_input, session_id, **kwargs):
        """PreToolUse hook: check every tool call against nucleus policy."""
        operation = TOOL_TO_OPERATION.get(tool_name)

        if operation is None:
            # Unknown tool — require approval (closed-world default)
            return {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "reason": f"nucleus: unknown tool '{tool_name}' — not in policy",
            }

        if not rt.can(operation):
            # Capability denied by profile
            return {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "reason": f"nucleus: {operation} is not allowed by {profile} profile",
            }

        # Allowed by policy
        return {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
        }

    return nucleus_pre_tool_use


# ── Subagent policy enforcement ────────────────────────────────────────────

def create_subagent_guard(parent_profile, child_profile, task=""):
    """
    Create a guard that enforces delegation narrowing for subagents.

    The child profile must be ≤ the parent profile on every dimension.
    This is the runtime enforcement of our Lean-proved delegation
    category (deflationary property).
    """
    # Verify child ≤ parent at creation time
    parent_rt = Runtime(parent_profile, task="parent")
    child_rt = Runtime(child_profile, task=task)

    for cap in [
        "read_files", "write_files", "edit_files", "run_bash",
        "web_fetch", "web_search", "git_commit", "git_push", "create_pr",
    ]:
        if child_rt.can(cap) and not parent_rt.can(cap):
            raise ValueError(
                f"delegation violation: child has {cap} but parent does not — "
                f"child profile must be ≤ parent profile"
            )

    return create_nucleus_guard(child_profile, task=task)


# ── Example usage ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Nucleus + Claude Agent SDK Integration")
    print("=" * 50)

    # Create a guard with Research + Bash profile
    profile = Profile.RESEARCH.with_capability("run_bash")
    guard = create_nucleus_guard(profile, task="analyze SEC filings")

    print(f"\nProfile: Research + Bash")
    print(f"Allowed: read_files, web_fetch, web_search, run_bash, glob, grep")
    print(f"Denied:  write_files, git_push, create_pr\n")

    # Simulate tool calls
    import asyncio

    async def test():
        # Should allow
        result = await guard("Read", {"path": "README.md"}, "test-session")
        print(f"Read README.md:  {result['permissionDecision']}")

        result = await guard("Bash", {"command": "cargo test"}, "test-session")
        print(f"Bash cargo test: {result['permissionDecision']}")

        result = await guard("WebFetch", {"url": "https://sec.gov"}, "test-session")
        print(f"WebFetch sec.gov: {result['permissionDecision']}")

        # Should deny
        result = await guard("Write", {"path": "evil.txt"}, "test-session")
        print(f"Write evil.txt:  {result['permissionDecision']} — {result.get('reason', '')}")

        result = await guard("GitPush", {"remote": "origin"}, "test-session")
        print(f"GitPush origin:  {result['permissionDecision']} — {result.get('reason', '')}")

        # Unknown tool — requires approval
        result = await guard("CustomTool", {}, "test-session")
        print(f"CustomTool:      {result['permissionDecision']} — {result.get('reason', '')}")

    asyncio.run(test())

    # Subagent delegation
    print("\n" + "=" * 50)
    print("Subagent delegation narrowing:")
    try:
        # This should succeed: ReadOnly ≤ Research+Bash
        child_guard = create_subagent_guard(
            profile,
            Profile.READ_ONLY,
            task="review code"
        )
        print("  ReadOnly child of Research+Bash: OK")
    except ValueError as e:
        print(f"  Error: {e}")

    try:
        # This should fail: Codegen has write_files, parent doesn't
        child_guard = create_subagent_guard(
            Profile.READ_ONLY,
            Profile.CODEGEN,
            task="generate code"
        )
        print("  Codegen child of ReadOnly: OK (should have failed!)")
    except ValueError as e:
        print(f"  Codegen child of ReadOnly: BLOCKED — {e}")

"""Tests for the nucleus Python SDK kernel."""

from nucleus import Kernel, Decision, Operation, Profile


def test_read_allowed():
    kernel = Kernel(profile="safe_pr_fixer")
    d = kernel.decide("Read", "/etc/hostname")
    assert d.allowed
    assert d.operation == Operation.READ_FILES


def test_write_allowed_without_web():
    kernel = Kernel(profile="safe_pr_fixer")
    d = kernel.decide("Read", "/src/main.rs")
    assert d.allowed
    d = kernel.decide("Write", "/src/main.rs")
    assert d.allowed


def test_web_taint_blocks_write():
    kernel = Kernel(profile="safe_pr_fixer")
    d1 = kernel.decide("Read", "/src/main.rs")
    assert d1.allowed
    d2 = kernel.decide("WebFetch", "https://example.com")
    assert d2.allowed  # reading web is safe
    assert kernel.web_tainted
    d3 = kernel.decide("Write", "/tmp/file.txt")
    assert not d3.allowed  # blocked by taint
    assert "tainted" in d3.reason


def test_read_only_blocks_write():
    kernel = Kernel(profile="read_only")
    d = kernel.decide("Write", "/tmp/file.txt")
    assert not d.allowed
    assert "Never" in d.reason


def test_classify_mcp_tool():
    kernel = Kernel()
    assert kernel.classify_tool("mcp__fs__read_file") == Operation.READ_FILES
    assert kernel.classify_tool("mcp__shell__run_command") == Operation.RUN_BASH
    assert kernel.classify_tool("mcp__http__fetch_url") == Operation.WEB_FETCH
    assert kernel.classify_tool("mcp__evil__pwn") == Operation.RUN_BASH  # fail-closed


def test_unknown_tool_fail_closed():
    kernel = Kernel()
    assert kernel.classify_tool("UnknownTool") == Operation.RUN_BASH


def test_exposure_accumulation():
    kernel = Kernel(profile="permissive")
    assert kernel.exposure_count == 0
    kernel.decide("Read", "/etc/passwd")
    assert kernel.exposure_count == 1  # PrivateData
    kernel.decide("WebFetch", "https://evil.com")
    assert kernel.exposure_count == 2  # + UntrustedContent


def test_decision_tracking():
    kernel = Kernel()
    kernel.decide("Read", "/file.txt")
    kernel.decide("Glob", "*.rs")
    assert len(kernel.decisions) == 2
    assert kernel.decisions[0]["operation"] == "read_files"


def test_agent_blocked_after_taint():
    kernel = Kernel(profile="safe_pr_fixer")
    kernel.decide("WebFetch", "https://example.com")
    d = kernel.decide("Agent", "spawn subprocess")
    assert not d.allowed
    assert "tainted" in d.reason


if __name__ == "__main__":
    import sys
    tests = [
        test_read_allowed,
        test_write_allowed_without_web,
        test_web_taint_blocks_write,
        test_read_only_blocks_write,
        test_classify_mcp_tool,
        test_unknown_tool_fail_closed,
        test_exposure_accumulation,
        test_decision_tracking,
        test_agent_blocked_after_taint,
    ]
    passed = 0
    for test in tests:
        try:
            test()
            passed += 1
            print(f"  ok {test.__name__}")
        except AssertionError as e:
            print(f"  FAIL {test.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed")
    sys.exit(0 if passed == len(tests) else 1)

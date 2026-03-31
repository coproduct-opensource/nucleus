"""Nucleus Python SDK — information flow control for AI agent tool calls.

Provides Python bindings to the nucleus permission kernel for:
- Classifying tool calls and checking permissions
- Managing capability profiles
- Tracking information flow (taint propagation)
- Verifying receipt chains

Usage:
    from nucleus import Kernel, Operation, Profile

    kernel = Kernel(profile="safe_pr_fixer")
    decision = kernel.decide("Read", "/etc/hostname")
    assert decision.allowed

    decision = kernel.decide("WebFetch", "https://example.com")
    assert decision.allowed  # reading is safe

    decision = kernel.decide("Write", "/tmp/file.txt")
    assert not decision.allowed  # blocked: web content tainted the session
"""

from nucleus.kernel import Kernel, Decision, Operation, Profile

__version__ = "0.1.0"
__all__ = ["Kernel", "Decision", "Operation", "Profile"]

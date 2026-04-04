"""
Integration tests for the portcullis Python bindings.

Run with: maturin develop && python -m pytest test_portcullis.py -v
"""
import pytest


def test_import():
    import portcullis
    assert portcullis is not None


def test_verdict_values():
    from portcullis import Verdict
    assert Verdict.ALLOW != Verdict.DENY
    assert Verdict.UNKNOWN != Verdict.CONFLICT


def test_verdict_truth_meet():
    from portcullis import Verdict
    assert Verdict.ALLOW.truth_meet(Verdict.DENY) == Verdict.DENY
    assert Verdict.ALLOW.truth_meet(Verdict.ALLOW) == Verdict.ALLOW
    assert Verdict.DENY.truth_meet(Verdict.DENY) == Verdict.DENY


def test_verdict_truth_join():
    from portcullis import Verdict
    assert Verdict.ALLOW.truth_join(Verdict.DENY) == Verdict.ALLOW
    assert Verdict.DENY.truth_join(Verdict.DENY) == Verdict.DENY


def test_verdict_negate():
    from portcullis import Verdict
    assert Verdict.ALLOW.negate() == Verdict.DENY
    assert Verdict.DENY.negate() == Verdict.ALLOW
    assert Verdict.UNKNOWN.negate() == Verdict.UNKNOWN
    assert Verdict.CONFLICT.negate() == Verdict.CONFLICT


def test_verdict_info_join_detects_contradiction():
    from portcullis import Verdict
    assert Verdict.ALLOW.info_join(Verdict.DENY) == Verdict.CONFLICT


def test_verdict_de_morgan():
    from portcullis import Verdict
    a, b = Verdict.ALLOW, Verdict.DENY
    # De Morgan: (a AND b)' = a' OR b'
    assert a.truth_meet(b).negate() == a.negate().truth_join(b.negate())


def test_verdict_predicates():
    from portcullis import Verdict
    assert Verdict.ALLOW.is_allow()
    assert not Verdict.DENY.is_allow()
    assert Verdict.DENY.is_deny()
    assert Verdict.CONFLICT.is_conflict()
    assert Verdict.ALLOW.is_decided()
    assert Verdict.DENY.is_decided()
    assert not Verdict.UNKNOWN.is_decided()
    assert not Verdict.CONFLICT.is_decided()


def test_capability_level_ordering():
    from portcullis import CapabilityLevel
    assert CapabilityLevel.NEVER < CapabilityLevel.LOW_RISK
    assert CapabilityLevel.LOW_RISK < CapabilityLevel.ALWAYS
    assert CapabilityLevel.NEVER < CapabilityLevel.ALWAYS


def test_policy_request_creation():
    from portcullis import PolicyRequest, CapabilityLevel
    req = PolicyRequest("read_files", CapabilityLevel.LOW_RISK)
    assert req.operation == "read_files"
    assert req.required_level == CapabilityLevel.LOW_RISK


def test_policy_request_with_context():
    from portcullis import PolicyRequest, CapabilityLevel
    req = PolicyRequest("web_fetch", CapabilityLevel.LOW_RISK)
    req2 = req.with_context("taint", "adversarial")
    assert req2.operation == "web_fetch"


def test_read_only_allows_reads():
    from portcullis import Pipeline, PolicyRequest, CapabilityLevel, read_only
    policy = Pipeline([read_only()])
    req = PolicyRequest("read_files", CapabilityLevel.LOW_RISK)
    result = policy.check(req)
    assert result.is_allow()


def test_read_only_denies_exec():
    from portcullis import Pipeline, PolicyRequest, CapabilityLevel, read_only
    policy = Pipeline([read_only()])
    req = PolicyRequest("run_bash", CapabilityLevel.ALWAYS)
    result = policy.check(req)
    assert result.is_deny()
    assert "run_bash" in result.reason


def test_deny_disabled():
    from portcullis import Pipeline, PolicyRequest, CapabilityLevel, deny_disabled
    policy = Pipeline([deny_disabled()])
    req = PolicyRequest("git_push", CapabilityLevel.NEVER)
    result = policy.check(req)
    assert result.is_deny()


def test_deny_disabled_abstains_for_enabled():
    from portcullis import Pipeline, PolicyRequest, CapabilityLevel, deny_disabled
    policy = Pipeline([deny_disabled()])
    req = PolicyRequest("git_push", CapabilityLevel.ALWAYS)
    result = policy.check(req)
    assert result.is_abstain()


def test_require_approval_for():
    from portcullis import Pipeline, PolicyRequest, CapabilityLevel, require_approval_for
    policy = Pipeline([require_approval_for(["git_push", "create_pr"])])
    req = PolicyRequest("git_push", CapabilityLevel.ALWAYS)
    result = policy.check(req)
    assert result.is_requires_approval()
    assert result.reason is not None


def test_require_approval_abstains_for_other_ops():
    from portcullis import Pipeline, PolicyRequest, CapabilityLevel, require_approval_for
    policy = Pipeline([require_approval_for(["git_push"])])
    req = PolicyRequest("read_files", CapabilityLevel.LOW_RISK)
    result = policy.check(req)
    assert result.is_abstain()


def test_deny_operations():
    from portcullis import Pipeline, PolicyRequest, CapabilityLevel, deny_operations
    policy = Pipeline([deny_operations(["run_bash"], "shell not permitted in this env")])
    req = PolicyRequest("run_bash", CapabilityLevel.ALWAYS)
    result = policy.check(req)
    assert result.is_deny()
    assert "shell not permitted" in result.reason


def test_deny_adversarial_taint():
    from portcullis import (
        Pipeline, PolicyRequest, CapabilityLevel, deny_adversarial_taint
    )
    policy = Pipeline([deny_adversarial_taint()])
    req = (
        PolicyRequest("web_fetch", CapabilityLevel.LOW_RISK)
        .with_context("taint", "adversarial")
    )
    result = policy.check(req)
    assert result.is_deny()


def test_deny_adversarial_taint_clean_request():
    from portcullis import (
        Pipeline, PolicyRequest, CapabilityLevel, deny_adversarial_taint
    )
    policy = Pipeline([deny_adversarial_taint()])
    req = PolicyRequest("web_fetch", CapabilityLevel.LOW_RISK)
    result = policy.check(req)
    assert result.is_abstain()


def test_deny_when_context_matches():
    from portcullis import (
        Pipeline, PolicyRequest, CapabilityLevel, deny_when_context_matches
    )
    policy = Pipeline([
        deny_when_context_matches("mode", "offline", ["web_fetch", "web_search"])
    ])
    req = (
        PolicyRequest("web_fetch", CapabilityLevel.LOW_RISK)
        .with_context("mode", "offline")
    )
    result = policy.check(req)
    assert result.is_deny()


def test_require_min_capability():
    from portcullis import (
        Pipeline, PolicyRequest, CapabilityLevel, require_min_capability
    )
    policy = Pipeline([require_min_capability(CapabilityLevel.LOW_RISK)])
    req = PolicyRequest("read_files", CapabilityLevel.NEVER)
    result = policy.check(req)
    assert result.is_deny()


def test_pipeline_first_match_stops_at_first_decision():
    from portcullis import (
        Pipeline, PolicyRequest, CapabilityLevel,
        deny_disabled, require_approval_for, read_only,
    )
    # deny_disabled fires first for NEVER-level ops
    policy = Pipeline([
        deny_disabled(),
        require_approval_for(["git_push"]),
        read_only(),
    ])
    req = PolicyRequest("git_push", CapabilityLevel.NEVER)
    result = policy.check(req)
    assert result.is_deny()  # deny_disabled fires, not require_approval_for


def test_pipeline_all_of():
    from portcullis import (
        Pipeline, PolicyRequest, CapabilityLevel,
        deny_disabled, read_only,
    )
    policy = Pipeline.all_of([deny_disabled(), read_only()])
    # read_only allows LOW_RISK; deny_disabled abstains for LOW_RISK
    req = PolicyRequest("read_files", CapabilityLevel.LOW_RISK)
    result = policy.check(req)
    assert result.is_allow()


def test_pipeline_any_of():
    from portcullis import (
        Pipeline, PolicyRequest, CapabilityLevel,
        require_approval_for, read_only,
    )
    policy = Pipeline.any_of([require_approval_for(["git_push"]), read_only()])
    # read_only allows LOW_RISK reads
    req = PolicyRequest("read_files", CapabilityLevel.LOW_RISK)
    result = policy.check(req)
    assert result.is_allow()


def test_check_result_reason_none_for_allow():
    from portcullis import Pipeline, PolicyRequest, CapabilityLevel, read_only
    policy = Pipeline([read_only()])
    req = PolicyRequest("read_files", CapabilityLevel.LOW_RISK)
    result = policy.check(req)
    assert result.reason is None


def test_comprehensive_security_pipeline():
    """Realistic pipeline: deny disabled + deny taint + require approval for dangerous ops + read-only fallback."""
    from portcullis import (
        Pipeline, PolicyRequest, CapabilityLevel,
        deny_disabled, deny_adversarial_taint,
        require_approval_for, read_only,
    )
    policy = Pipeline([
        deny_disabled(),
        deny_adversarial_taint(),
        require_approval_for(["git_push", "create_pr", "spawn_agent", "manage_pods"]),
        read_only(),
    ])

    # Read is allowed
    assert policy.check(PolicyRequest("read_files", CapabilityLevel.LOW_RISK)).is_allow()

    # Exec is denied by read_only
    assert policy.check(PolicyRequest("run_bash", CapabilityLevel.ALWAYS)).is_deny()

    # Disabled ops are denied immediately
    assert policy.check(PolicyRequest("git_push", CapabilityLevel.NEVER)).is_deny()

    # Tainted requests are denied
    tainted = (
        PolicyRequest("web_fetch", CapabilityLevel.LOW_RISK)
        .with_context("taint", "adversarial")
    )
    assert policy.check(tainted).is_deny()

    # Dangerous ops require approval when enabled
    approval_req = PolicyRequest("git_push", CapabilityLevel.ALWAYS)
    assert policy.check(approval_req).is_requires_approval()

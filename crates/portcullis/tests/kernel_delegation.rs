//! Delegation constraint enforcement tests (#779) — extracted from kernel.rs.
//!
//! These tests verify that the kernel enforces delegation constraints on
//! `SpawnAgent` operations: expiry, depth limits, sink scope, and that
//! non-spawn operations remain unaffected.

use portcullis::kernel::{DenyReason, Kernel, Verdict};
use portcullis::{Operation, PermissionLattice};
use portcullis_core::delegation::{DelegationConstraints, DelegationScope};
use portcullis_core::SinkClass;

/// Helper: a permissive PermissionLattice that allows SpawnAgent.
fn spawn_allowed_perms() -> PermissionLattice {
    PermissionLattice::permissive()
}

fn future_expiry() -> u64 {
    (chrono::Utc::now().timestamp() as u64) + 3600
}

fn past_expiry() -> u64 {
    // Well in the past
    1_000_000
}

#[test]
fn spawn_allowed_when_delegation_permits() {
    let mut kernel = Kernel::capability_only(spawn_allowed_perms());
    kernel.set_delegation(DelegationConstraints {
        scope: DelegationScope {
            allowed_paths: vec!["**".to_string()],
            allowed_sinks: vec![SinkClass::AgentSpawn],
            allowed_repos: vec!["*".to_string()],
        },
        max_delegation_depth: 2,
        expires_at: future_expiry(),
    });

    let (d, token) = kernel.decide(Operation::SpawnAgent, "child-agent");
    assert!(d.verdict.is_allowed(), "SpawnAgent should be allowed");
    assert!(token.is_some());
    assert_eq!(kernel.delegation_depth(), 1);
}

#[test]
fn spawn_denied_when_delegation_expired() {
    let mut kernel = Kernel::capability_only(spawn_allowed_perms());
    kernel.set_delegation(DelegationConstraints {
        scope: DelegationScope::unrestricted(),
        max_delegation_depth: 5,
        expires_at: past_expiry(),
    });

    let (d, _token) = kernel.decide(Operation::SpawnAgent, "child-agent");
    assert!(
        d.verdict.is_denied(),
        "expired delegation must deny SpawnAgent"
    );
    match &d.verdict {
        Verdict::Deny(DenyReason::DelegationDenied { detail }) => {
            assert!(
                detail.contains("expired"),
                "detail should mention expiry: {detail}"
            );
        }
        other => panic!("expected DelegationDenied, got {other:?}"),
    }
}

#[test]
fn spawn_denied_when_depth_exhausted() {
    let mut kernel = Kernel::capability_only(spawn_allowed_perms());
    kernel.set_delegation(DelegationConstraints {
        scope: DelegationScope {
            allowed_paths: vec!["**".to_string()],
            allowed_sinks: vec![SinkClass::AgentSpawn],
            allowed_repos: vec!["*".to_string()],
        },
        max_delegation_depth: 1,
        expires_at: future_expiry(),
    });

    // First spawn succeeds — depth goes from 0 to 1
    let (d1, token1) = kernel.decide(Operation::SpawnAgent, "child-1");
    assert!(d1.verdict.is_allowed(), "first spawn should succeed");
    assert!(token1.is_some());
    assert_eq!(kernel.delegation_depth(), 1);

    // Second spawn denied — depth 1 >= max 1
    let (d2, token2) = kernel.decide(Operation::SpawnAgent, "child-2");
    assert!(
        d2.verdict.is_denied(),
        "second spawn should be denied (depth exhausted)"
    );
    assert!(token2.is_none());
    match &d2.verdict {
        Verdict::Deny(DenyReason::DelegationDenied { detail }) => {
            assert!(detail.contains("depth exhausted"), "detail: {detail}");
        }
        other => panic!("expected DelegationDenied, got {other:?}"),
    }
}

#[test]
fn spawn_denied_when_sink_not_in_scope() {
    let mut kernel = Kernel::capability_only(spawn_allowed_perms());
    // Scope allows writes but NOT AgentSpawn
    kernel.set_delegation(DelegationConstraints {
        scope: DelegationScope {
            allowed_paths: vec!["**".to_string()],
            allowed_sinks: vec![SinkClass::WorkspaceWrite, SinkClass::GitCommit],
            allowed_repos: vec!["*".to_string()],
        },
        max_delegation_depth: 5,
        expires_at: future_expiry(),
    });

    let (d, token) = kernel.decide(Operation::SpawnAgent, "child-agent");
    assert!(
        d.verdict.is_denied(),
        "SpawnAgent should be denied (sink not in scope)"
    );
    assert!(token.is_none());
    match &d.verdict {
        Verdict::Deny(DenyReason::DelegationDenied { detail }) => {
            assert!(
                detail.contains("AgentSpawn not in delegation scope"),
                "detail: {detail}"
            );
        }
        other => panic!("expected DelegationDenied, got {other:?}"),
    }
}

#[test]
fn non_spawn_ops_unaffected_by_delegation() {
    let mut kernel = Kernel::capability_only(spawn_allowed_perms());
    // Set a delegation with empty sinks — should NOT block ReadFiles
    kernel.set_delegation(DelegationConstraints {
        scope: DelegationScope::empty(),
        max_delegation_depth: 0,
        expires_at: past_expiry(),
    });

    let (d, token) = kernel.decide(Operation::ReadFiles, "/workspace/foo.rs");
    assert!(
        d.verdict.is_allowed(),
        "ReadFiles should be unaffected by delegation constraints"
    );
    assert!(token.is_some());
}

#[test]
fn no_delegation_means_no_constraint() {
    let mut kernel = Kernel::capability_only(spawn_allowed_perms());
    // No set_delegation() call — SpawnAgent should pass through to
    // normal capability checks
    let (d, token) = kernel.decide(Operation::SpawnAgent, "child-agent");
    assert!(
        d.verdict.is_allowed(),
        "without delegation constraints, SpawnAgent is governed by capabilities alone"
    );
    assert!(token.is_some());
    // Depth should NOT increment when no delegation is set
    assert_eq!(kernel.delegation_depth(), 0);
}

#[test]
fn depth_increments_only_on_allowed_spawn() {
    let mut kernel = Kernel::capability_only(spawn_allowed_perms());
    kernel.set_delegation(DelegationConstraints {
        scope: DelegationScope {
            allowed_paths: vec!["**".to_string()],
            allowed_sinks: vec![SinkClass::AgentSpawn],
            allowed_repos: vec!["*".to_string()],
        },
        max_delegation_depth: 3,
        expires_at: future_expiry(),
    });

    assert_eq!(kernel.delegation_depth(), 0);

    // Allow first
    let (d1, _) = kernel.decide(Operation::SpawnAgent, "a");
    assert!(d1.verdict.is_allowed());
    assert_eq!(kernel.delegation_depth(), 1);

    // Allow second
    let (d2, _) = kernel.decide(Operation::SpawnAgent, "b");
    assert!(d2.verdict.is_allowed());
    assert_eq!(kernel.delegation_depth(), 2);

    // Allow third
    let (d3, _) = kernel.decide(Operation::SpawnAgent, "c");
    assert!(d3.verdict.is_allowed());
    assert_eq!(kernel.delegation_depth(), 3);

    // Deny fourth — depth 3 >= max 3
    let (d4, _) = kernel.decide(Operation::SpawnAgent, "d");
    assert!(d4.verdict.is_denied());
    // Depth stays at 3 since the spawn was denied
    assert_eq!(kernel.delegation_depth(), 3);
}

#[test]
fn delegation_accessors() {
    let mut kernel = Kernel::capability_only(spawn_allowed_perms());
    assert!(kernel.delegation().is_none());
    assert_eq!(kernel.delegation_depth(), 0);

    let constraints = DelegationConstraints {
        scope: DelegationScope::unrestricted(),
        max_delegation_depth: 5,
        expires_at: future_expiry(),
    };
    kernel.set_delegation(constraints.clone());
    assert!(kernel.delegation().is_some());
    assert_eq!(kernel.delegation().unwrap().max_delegation_depth, 5);
}

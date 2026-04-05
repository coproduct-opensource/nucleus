#![allow(deprecated)]
//! Sink scope enforcement tests (#809) — extracted from kernel.rs (#825).
//!
//! These tests verify that the kernel enforces SinkScope constraints
//! from verified permission certificates (path, host, and git ref scoping).

use portcullis::certificate::{SinkScope, VerifiedPermissions};
use portcullis::kernel::{DenyReason, Kernel, Verdict};
use portcullis::{
    BudgetLattice, CapabilityLattice, IsolationLattice, Obligations, Operation, PermissionLattice,
};

/// Build a fully permissive lattice with NO obligations and NO
/// uninhabitable constraint — purely for testing sink scope checks
/// without RequiresApproval noise.
fn permissive_no_obligations() -> PermissionLattice {
    PermissionLattice {
        capabilities: CapabilityLattice::permissive(),
        obligations: Obligations::default(),
        budget: BudgetLattice {
            max_cost_usd: rust_decimal::Decimal::from(100),
            ..Default::default()
        },
        ..PermissionLattice::permissive().as_ceiling()
    }
}

/// Helper: create a VerifiedPermissions with the given SinkScope.
fn verified_with_scope(scope: SinkScope) -> VerifiedPermissions {
    VerifiedPermissions::new(
        permissive_no_obligations(),
        1,
        "root".to_string(),
        "leaf".to_string(),
        scope,
    )
}

#[test]
fn write_outside_allowed_paths_denied() {
    let scope = SinkScope {
        allowed_paths: vec!["/workspace/output/".to_string()],
        allowed_hosts: vec![],
        allowed_git_refs: vec![],
    };
    let verified = verified_with_scope(scope);
    let mut kernel = Kernel::from_certificate(verified, [0u8; 32]);

    // Write inside scope — allowed
    let (d, token) = kernel.decide(Operation::WriteFiles, "/workspace/output/result.txt");
    assert!(
        d.verdict.is_allowed(),
        "write inside scope should be allowed"
    );
    assert!(token.is_some());

    // Write outside scope — denied
    let (d, token) = kernel.decide(Operation::WriteFiles, "/etc/passwd");
    assert!(
        d.verdict.is_denied(),
        "write outside scope should be denied"
    );
    assert!(token.is_none());
    match &d.verdict {
        Verdict::Deny(DenyReason::SinkScopeDenied { dimension, detail }) => {
            assert_eq!(dimension, "path");
            assert!(detail.contains("/etc/passwd"), "detail: {detail}");
        }
        other => panic!("expected SinkScopeDenied, got {other:?}"),
    }
}

#[test]
fn edit_outside_allowed_paths_denied() {
    let scope = SinkScope {
        allowed_paths: vec!["/workspace/src/**/*.rs".to_string()],
        allowed_hosts: vec![],
        allowed_git_refs: vec![],
    };
    let verified = verified_with_scope(scope);
    let mut kernel = Kernel::from_certificate(verified, [0u8; 32]);

    // Edit matching glob — allowed
    let (d, _) = kernel.decide(Operation::EditFiles, "/workspace/src/lib.rs");
    assert!(
        d.verdict.is_allowed(),
        "edit matching glob should be allowed"
    );

    // Edit not matching glob — denied
    let (d, _) = kernel.decide(Operation::EditFiles, "/workspace/Cargo.toml");
    assert!(d.verdict.is_denied(), "edit outside glob should be denied");
    match &d.verdict {
        Verdict::Deny(DenyReason::SinkScopeDenied { dimension, .. }) => {
            assert_eq!(dimension, "path");
        }
        other => panic!("expected SinkScopeDenied, got {other:?}"),
    }
}

#[test]
fn network_outside_allowed_hosts_denied() {
    let scope = SinkScope {
        allowed_paths: vec![],
        allowed_hosts: vec!["api.example.com".to_string()],
        allowed_git_refs: vec![],
    };
    let verified = verified_with_scope(scope);
    let mut kernel = Kernel::from_certificate(verified, [0u8; 32]);

    // Fetch allowed host — allowed
    let (d, _) = kernel.decide(Operation::WebFetch, "https://api.example.com/data");
    assert!(d.verdict.is_allowed(), "fetch to allowed host should pass");

    // Fetch disallowed host — denied
    let (d, token) = kernel.decide(Operation::WebFetch, "https://evil.com/exfil");
    assert!(
        d.verdict.is_denied(),
        "fetch to disallowed host should be denied"
    );
    assert!(token.is_none());
    match &d.verdict {
        Verdict::Deny(DenyReason::SinkScopeDenied { dimension, detail }) => {
            assert_eq!(dimension, "host");
            assert!(detail.contains("evil.com"), "detail: {detail}");
        }
        other => panic!("expected SinkScopeDenied, got {other:?}"),
    }
}

#[test]
fn subdomain_of_allowed_host_permitted() {
    let scope = SinkScope {
        allowed_paths: vec![],
        allowed_hosts: vec!["example.com".to_string()],
        allowed_git_refs: vec![],
    };
    let verified = verified_with_scope(scope);
    let mut kernel = Kernel::from_certificate(verified, [0u8; 32]);

    let (d, _) = kernel.decide(Operation::WebFetch, "https://api.example.com/data");
    assert!(
        d.verdict.is_allowed(),
        "subdomain of allowed host should pass"
    );
}

#[test]
fn git_ref_outside_allowed_refs_denied() {
    let scope = SinkScope {
        allowed_paths: vec![],
        allowed_hosts: vec![],
        allowed_git_refs: vec!["origin/feature-*".to_string()],
    };
    let verified = verified_with_scope(scope);
    let mut kernel = Kernel::from_certificate(verified, [0u8; 32]);

    // Push to allowed ref — allowed
    let (d, _) = kernel.decide(Operation::GitPush, "origin/feature-xyz");
    assert!(
        d.verdict.is_allowed(),
        "push to allowed ref should pass, got: {:?}",
        d.verdict
    );

    // Push to disallowed ref — denied
    let (d, token) = kernel.decide(Operation::GitPush, "origin/main");
    assert!(
        d.verdict.is_denied(),
        "push to disallowed ref should be denied"
    );
    assert!(token.is_none());
    match &d.verdict {
        Verdict::Deny(DenyReason::SinkScopeDenied { dimension, detail }) => {
            assert_eq!(dimension, "git_ref");
            assert!(detail.contains("origin/main"), "detail: {detail}");
        }
        other => panic!("expected SinkScopeDenied, got {other:?}"),
    }
}

#[test]
fn no_scope_means_unrestricted() {
    // Unrestricted scope (all empty) = None stored on kernel
    let scope = SinkScope::unrestricted();
    let verified = verified_with_scope(scope);
    let kernel = Kernel::from_certificate(verified, [0u8; 32]);

    assert!(
        kernel.sink_scope().is_none(),
        "unrestricted scope should be None"
    );

    // Each operation tested in its own kernel to avoid IFC taint accumulation
    let scope = SinkScope::unrestricted();
    let mut k1 = Kernel::from_certificate(verified_with_scope(scope.clone()), [0u8; 32]);
    let (d, _) = k1.decide(Operation::WriteFiles, "/anywhere/file.txt");
    assert!(d.verdict.is_allowed(), "write should pass without scope");

    let mut k2 =
        Kernel::from_certificate(verified_with_scope(SinkScope::unrestricted()), [0u8; 32]);
    let (d, _) = k2.decide(Operation::WebFetch, "https://any-host.com/");
    assert!(d.verdict.is_allowed(), "fetch should pass without scope");

    let mut k3 =
        Kernel::from_certificate(verified_with_scope(SinkScope::unrestricted()), [0u8; 32]);
    let (d, _) = k3.decide(Operation::GitPush, "origin/main");
    assert!(d.verdict.is_allowed(), "push should pass without scope");
}

#[test]
fn read_operations_unaffected_by_path_scope() {
    // Path scope should only gate write operations, not reads
    let scope = SinkScope {
        allowed_paths: vec!["/workspace/output/".to_string()],
        allowed_hosts: vec![],
        allowed_git_refs: vec![],
    };
    let verified = verified_with_scope(scope);
    let mut kernel = Kernel::from_certificate(verified, [0u8; 32]);

    // ReadFiles outside scope — should still be allowed
    let (d, _) = kernel.decide(Operation::ReadFiles, "/etc/hosts");
    assert!(
        d.verdict.is_allowed(),
        "read operations should not be gated by sink scope"
    );
}

#[test]
fn sink_scope_accessor_returns_scope() {
    let scope = SinkScope {
        allowed_paths: vec!["/out/".to_string()],
        allowed_hosts: vec!["host.com".to_string()],
        allowed_git_refs: vec![],
    };
    let verified = verified_with_scope(scope);
    let kernel = Kernel::from_certificate(verified, [0u8; 32]);

    let s = kernel.sink_scope().expect("scope should be Some");
    assert_eq!(s.allowed_paths, vec!["/out/"]);
    assert_eq!(s.allowed_hosts, vec!["host.com"]);
    assert!(s.allowed_git_refs.is_empty());
}

#[test]
fn from_certificate_with_isolation_also_stores_scope() {
    let scope = SinkScope {
        allowed_paths: vec!["/restricted/".to_string()],
        allowed_hosts: vec![],
        allowed_git_refs: vec![],
    };
    let verified = verified_with_scope(scope);
    let mut kernel =
        Kernel::from_certificate_with_isolation(verified, [0u8; 32], IsolationLattice::localhost());

    assert!(kernel.sink_scope().is_some());

    let (d, _) = kernel.decide(Operation::WriteFiles, "/other/file.txt");
    assert!(d.verdict.is_denied());
    match &d.verdict {
        Verdict::Deny(DenyReason::SinkScopeDenied { dimension, .. }) => {
            assert_eq!(dimension, "path");
        }
        other => panic!("expected SinkScopeDenied, got {other:?}"),
    }
}

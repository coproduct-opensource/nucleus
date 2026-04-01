//! Receipt chain integration tests — extracted from kernel.rs (#825).
//!
//! These tests verify that the kernel correctly produces an append-only
//! receipt chain when enabled, with hash-linked contiguous receipts.

use portcullis::kernel::Kernel;
use portcullis::{Operation, PermissionLattice};

#[test]
fn decide_produces_receipt_when_enabled() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);
    kernel.enable_receipt_chain();

    let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
    assert!(d.verdict.is_allowed());

    let chain = kernel.receipt_chain().expect("chain should be enabled");
    assert_eq!(chain.len(), 1);
    assert!(chain.verify().is_ok());

    let receipt = &chain.receipts()[0];
    assert_eq!(receipt.operation, "ReadFiles");
    assert_eq!(receipt.subject, "/workspace/main.rs");
}

#[test]
fn deny_produces_receipt() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);
    kernel.enable_receipt_chain();

    // safe_pr_fixer has git_push=Never
    let (d, _token) = kernel.decide(Operation::GitPush, "origin/main");
    assert!(d.verdict.is_denied());

    let chain = kernel.receipt_chain().unwrap();
    assert_eq!(chain.len(), 1);
    assert!(chain.verify().is_ok());

    let receipt = &chain.receipts()[0];
    assert!(matches!(
        receipt.verdict,
        portcullis_core::flow::FlowVerdict::Deny(_)
    ));
}

#[test]
fn chain_valid_after_multiple_decisions() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);
    kernel.enable_receipt_chain();

    // Mix of allows and denies
    kernel.decide(Operation::ReadFiles, "/workspace/a.rs");
    kernel.decide(Operation::WriteFiles, "/workspace/b.rs");
    kernel.decide(Operation::GitPush, "origin/main"); // denied
    kernel.decide(Operation::GlobSearch, "/workspace/**");
    kernel.decide(Operation::ReadFiles, "/workspace/c.rs");

    let chain = kernel.receipt_chain().unwrap();
    assert_eq!(chain.len(), 5);
    assert!(
        chain.verify().is_ok(),
        "chain should verify after 5 decisions"
    );

    // Head hash should not be zeros
    assert_ne!(chain.head_hash(), &[0u8; 32]);
}

#[test]
fn receipt_chain_disabled_by_default() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);

    kernel.decide(Operation::ReadFiles, "/workspace/main.rs");

    assert!(
        kernel.receipt_chain().is_none(),
        "chain should be None when not enabled"
    );
}

#[test]
fn receipt_links_are_contiguous() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);
    kernel.enable_receipt_chain();

    kernel.decide(Operation::ReadFiles, "/a");
    kernel.decide(Operation::ReadFiles, "/b");
    kernel.decide(Operation::ReadFiles, "/c");

    let chain = kernel.receipt_chain().unwrap();
    let receipts = chain.receipts();

    // First receipt links to genesis (all zeros)
    assert_eq!(receipts[0].prev_hash, [0u8; 32]);

    // Each subsequent receipt's prev_hash == predecessor's receipt_hash
    for i in 1..receipts.len() {
        assert_eq!(
            receipts[i].prev_hash,
            receipts[i - 1].receipt_hash,
            "receipt {} should link to receipt {}",
            i,
            i - 1
        );
    }
}

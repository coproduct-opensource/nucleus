//! Kernel-level DLC-D verified-admission tests (feature `dlc`) — the bites on the LIVE path.
//!
//! These prove the `says_admission` consult in `Kernel::decide_term_with_flow` actually gates:
//! an unprovisioned kernel is unchanged (inert-by-default), a valid issuer-signed credential
//! admits, and every failure mode — missing credential, credential minted for a different
//! operation, unknown issuer — denies with `DenyReason::DlcAdmissionDenied` (the right reason
//! at the right layer: the DLC gate runs before the lattice, so the deny reason itself proves
//! WHICH check fired).
#![cfg(feature = "dlc")]

use dlc_core::judgment::KeyRing;
use dlc_core::principal::{KeyRecord, Principal, PrincipalId};
use dlc_core::syntax::Signature;
use dlc_d::admission::cap_atom;
use portcullis::kernel::{DenyReason, Kernel, Verdict};
use portcullis::says_admission::DlcAdmission;
use portcullis::{ActionTerm, Operation, PermissionLattice};

const SEED: [u8; 32] = [7u8; 32];

fn issuer_and_keyring() -> (KeyRing, Principal) {
    let pk = dlc_crypto::ed25519::public_key(&SEED);
    let issuer = Principal::Atom(PrincipalId(pk));
    let keyring = KeyRing {
        entries: vec![KeyRecord {
            principal: PrincipalId(pk),
            alg: 0,
            public_key: pk.to_vec(),
        }],
    };
    (keyring, issuer)
}

/// Mint an issuer-signed credential for one operation name. Mirrors dlc-d's v1 cap-invoke
/// message layout (domain tag + LE cap atom); the layout is an implementation detail of the
/// REV-PINNED dlc-d dependency, so a layout change surfaces here as a red test at pin-bump.
fn credential(operation: &str) -> Signature {
    let mut msg = b"dlc-d/cap-invoke:".to_vec();
    msg.extend_from_slice(&cap_atom(operation).to_le_bytes());
    Signature {
        alg: 0,
        bytes: dlc_crypto::ed25519::sign(&SEED, &msg).to_vec(),
    }
}

fn read_term() -> ActionTerm {
    ActionTerm::from_operation(Operation::ReadFiles, "README.md")
}

fn deny_reason(kernel: &mut Kernel, term: ActionTerm) -> Option<DenyReason> {
    let (decision, _token) = kernel.decide_term_with_flow(term, None);
    match decision.verdict {
        Verdict::Deny(reason) => Some(reason),
        _ => None,
    }
}

#[test]
fn unprovisioned_kernel_is_unchanged() {
    // Inert-by-default: no set_dlc_admission ⇒ the gate never fires.
    let mut kernel = Kernel::new(PermissionLattice::safe_pr_fixer());
    let (decision, _) = kernel.decide_term_with_flow(read_term(), None);
    assert!(
        decision.verdict.is_allowed(),
        "baseline lattice must allow the read, got {:?}",
        decision.verdict
    );
}

#[test]
fn valid_credential_admits() {
    let (keyring, issuer) = issuer_and_keyring();
    let mut kernel = Kernel::new(PermissionLattice::safe_pr_fixer());
    kernel.set_dlc_admission(
        DlcAdmission::new(keyring, issuer).with_credential("read_files", credential("read_files")),
    );
    let (decision, _) = kernel.decide_term_with_flow(read_term(), None);
    assert!(
        decision.verdict.is_allowed(),
        "a genuine issuer-signed credential for read_files must admit, got {:?}",
        decision.verdict
    );
}

#[test]
fn missing_credential_denies_fail_closed() {
    // Provisioned, but no credential presented for this operation ⇒ deny — and the reason
    // proves the DLC gate (not the lattice) is what fired.
    let (keyring, issuer) = issuer_and_keyring();
    let mut kernel = Kernel::new(PermissionLattice::safe_pr_fixer());
    kernel.set_dlc_admission(DlcAdmission::new(keyring, issuer));
    match deny_reason(&mut kernel, read_term()) {
        Some(DenyReason::DlcAdmissionDenied { .. }) => {}
        other => panic!("expected DlcAdmissionDenied, got {other:?}"),
    }
}

#[test]
fn wrong_operation_credential_denies() {
    // The cryptographic bite: a credential MINTED for web_fetch, presented under read_files.
    // The map lookup succeeds — the Ed25519 signature is what refuses (it covers web_fetch's
    // cap atom, not read_files'), so this cannot be faked by registry bookkeeping.
    let (keyring, issuer) = issuer_and_keyring();
    let mut kernel = Kernel::new(PermissionLattice::safe_pr_fixer());
    kernel.set_dlc_admission(
        DlcAdmission::new(keyring, issuer).with_credential("read_files", credential("web_fetch")),
    );
    match deny_reason(&mut kernel, read_term()) {
        Some(DenyReason::DlcAdmissionDenied { .. }) => {}
        other => panic!("expected DlcAdmissionDenied, got {other:?}"),
    }
}

#[test]
fn unknown_issuer_denies() {
    let (_keyring, issuer) = issuer_and_keyring();
    let empty = KeyRing { entries: vec![] };
    let mut kernel = Kernel::new(PermissionLattice::safe_pr_fixer());
    kernel.set_dlc_admission(
        DlcAdmission::new(empty, issuer).with_credential("read_files", credential("read_files")),
    );
    match deny_reason(&mut kernel, read_term()) {
        Some(DenyReason::DlcAdmissionDenied { .. }) => {}
        other => panic!("expected DlcAdmissionDenied, got {other:?}"),
    }
}

#[test]
fn deny_narrowing_only() {
    // The gate can only NARROW: an operation the lattice would deny anyway stays denied
    // (with the earlier gate's reason), and providing a valid credential for it does not
    // widen the lattice's verdict.
    let (keyring, issuer) = issuer_and_keyring();
    let mut kernel = Kernel::new(PermissionLattice::safe_pr_fixer());
    kernel.set_dlc_admission(
        DlcAdmission::new(keyring, issuer)
            .with_credential("manage_pods", credential("manage_pods")),
    );
    let term = ActionTerm::from_operation(Operation::ManagePods, "pod-1");
    let (decision, _) = kernel.decide_term_with_flow(term, None);
    assert!(
        !decision.verdict.is_allowed(),
        "a valid credential must not widen what the lattice denies, got {:?}",
        decision.verdict
    );
}

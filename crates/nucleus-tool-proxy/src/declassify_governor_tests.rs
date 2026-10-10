//! ADR 0013 rule 8: an eval cell's guest holds no declassification governor key.
//!
//! The kernel here is built the way both construction sites build it (`main.rs`, `mcp.rs`):
//! the keys [`GovernorKeys::keys`] returns, set only when there are any. The attempt is the
//! token endpoint's order: [`GovernorKeys::admit`], then the kernel's verify-and-apply.

use super::{EVAL_CELL_REFUSAL, GovernorKeys};
use portcullis::kernel::Kernel;
use portcullis::token_sign;
use portcullis::{Operation, PermissionLattice};
use portcullis_core::declassify::{
    DeclassificationRule, DeclassificationToken, DeclassifyAction, TokenApplyResult,
};
use portcullis_core::flow::NodeKind;
use portcullis_core::{ContentHash, IntegLevel};
use ring::signature::{Ed25519KeyPair, KeyPair};

const VALUE_ID: [u8; 32] = [0x5A; 32];

fn governor() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[7; 32]).expect("a 32-byte seed is a key")
}

/// The node's `NUCLEUS_DECLASSIFY_TRUSTED_KEYS`, naming the governor.
fn env_naming_the_governor() -> String {
    hex::encode(governor().public_key().as_ref())
}

fn pod(labels: &str) -> nucleus_spec::PodSpec {
    serde_yaml::from_str(&format!(
        "apiVersion: nucleus/v1\nkind: Pod\nmetadata:\n  name: p\n{labels}spec:\n  \
         timeout_seconds: 60\n"
    ))
    .expect("spec parses")
}

fn eval_cell() -> nucleus_spec::PodSpec {
    pod("  labels:\n    isolation.coproduct.one/profile: eval-cell\n")
}

fn kernel_as_constructed(keys: &GovernorKeys) -> Kernel {
    let mut k = Kernel::new(PermissionLattice::safe_pr_fixer());
    if !keys.keys().is_empty() {
        k.set_trusted_keys(keys.keys().to_vec());
    }
    k
}

/// A governor-signed token releasing a web read in `kernel` into `write_files`.
fn governor_token(kernel: &mut Kernel) -> DeclassificationToken {
    let node = kernel
        .observe_with_content_hash(NodeKind::WebContent, &[], ContentHash::from_bytes(VALUE_ID))
        .expect("observe");
    let mut token = DeclassificationToken::new(
        node,
        DeclassificationRule {
            action: DeclassifyAction::RaiseIntegrity {
                from: IntegLevel::Adversarial,
                to: IntegLevel::Untrusted,
            },
            justification: "validated".to_string(),
        },
        vec![Operation::WriteFiles],
        u64::MAX,
        "governor".to_string(),
    )
    .with_content_commitment(VALUE_ID);
    token_sign::sign_token(&mut token, &governor());
    token
}

/// The attempt to apply a governor-signed token.
fn attempt(keys: &GovernorKeys) -> Result<TokenApplyResult, String> {
    let mut kernel = kernel_as_constructed(keys);
    let token = governor_token(&mut kernel);
    keys.admit().map_err(|e| e.to_string())?;
    kernel
        .apply_declassification_token(&token)
        .map_err(|e| format!("{e:?}"))
}

/// A-19 row 2: the node's env names a governor, and the pod is an eval cell. The guest holds no
/// key and refuses the governor's own token by name. Red when `for_pod` hands an eval cell the
/// env's keys (the behaviour on main): the token applies.
#[test]
fn an_eval_cell_refuses_a_governor_signed_token_even_with_keys_in_its_env() {
    let keys = GovernorKeys::for_pod(&eval_cell(), Some(&env_naming_the_governor()));
    assert_eq!(keys, GovernorKeys::WithheldFromEvalCell);
    assert!(keys.keys().is_empty(), "an eval cell's guest holds no key");
    let refused = attempt(&keys).expect_err("an eval cell cannot declassify");
    assert!(
        refused.contains(EVAL_CELL_REFUSAL) && refused.contains("eval cell"),
        "refused by name, not as a bad signature: {refused}"
    );
}

/// The kernel an eval cell builds refuses on its own, too: without the by-name check it holds no
/// trusted key, so verification fails closed (the guest already treated "no keys" as refusal).
#[test]
fn an_eval_cells_kernel_has_no_trusted_key_to_verify_with() {
    let keys = GovernorKeys::for_pod(&eval_cell(), Some(&env_naming_the_governor()));
    let mut kernel = kernel_as_constructed(&keys);
    let token = governor_token(&mut kernel);
    assert!(kernel.apply_declassification_token(&token).is_err());
}

/// An unknown profile label is read as the stricter profile: the node refuses it at create, so
/// in the guest it can only be a rewrite (ADR 0007 B-3).
#[test]
fn an_unknown_profile_holds_no_key() {
    let spec = pod("  labels:\n    isolation.coproduct.one/profile: eval-cel\n");
    let keys = GovernorKeys::for_pod(&spec, Some(&env_naming_the_governor()));
    assert_eq!(keys, GovernorKeys::WithheldFromEvalCell);
}

/// A-19 row 3, non-vacuity: a standard pod given the same env declassifies with the governor's
/// token, so the refusal above is the profile's and not a broken token.
#[test]
fn a_standard_pod_still_declassifies_with_the_nodes_governor_key() {
    let keys = GovernorKeys::for_pod(&pod(""), Some(&env_naming_the_governor()));
    assert_eq!(keys.keys().len(), 1);
    match attempt(&keys) {
        Ok(TokenApplyResult::Applied { new_label, .. }) => {
            assert_eq!(new_label.integrity, IntegLevel::Untrusted);
        }
        other => panic!("a standard pod's governor token applies, got {other:?}"),
    }
}

/// A standard pod the node gave no key still refuses every token (fail-closed on main).
#[test]
fn a_standard_pod_without_keys_refuses() {
    let keys = GovernorKeys::for_pod(&pod(""), None);
    assert!(attempt(&keys).is_err());
}

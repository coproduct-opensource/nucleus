//! `verify_ifc_flow` tests. Moved out of `lib.rs` to keep it under its line
//! ceiling; they were the last code in that file, so no line above them moved
//! (the verifier wasm records panic locations by line).

use super::*;

#[test]
fn non_egress_hop_is_not_gated() {
    assert_eq!(verify_ifc_flow(None), IfcFlowOutcome::NotGated);
    assert!(verify_ifc_flow(None).is_consistent());
}

#[test]
fn allowed_clean_egress_is_consistent() {
    // anti-vacuity: the verifier must ACCEPT legitimate allowed egress, not
    // reject everything.
    assert_eq!(verify_ifc_flow(Some("trusted")), IfcFlowOutcome::Allow);
    assert_eq!(verify_ifc_flow(Some("untrusted")), IfcFlowOutcome::Allow);
}

#[test]
fn allowed_adversarial_egress_is_inconsistent() {
    // A signed edge claiming an allowed egress under adversarial integrity is
    // self-inconsistent — the gateway would have denied before signing.
    match verify_ifc_flow(Some("adversarial")) {
        IfcFlowOutcome::Inconsistent {
            effective_integrity,
        } => {
            assert_eq!(effective_integrity, "adversarial");
        }
        other => panic!("expected Inconsistent, got {other:?}"),
    }
    assert!(!verify_ifc_flow(Some("adversarial")).is_consistent());
}

#[test]
fn unrecognized_token_is_inconsistent_fail_closed() {
    assert!(!verify_ifc_flow(Some("garbage_token")).is_consistent());
    assert!(!verify_ifc_flow(Some("")).is_consistent());
}

#[test]
fn matches_the_single_source_predicate() {
    // verify_ifc_flow's Allow/Inconsistent split is EXACTLY the gateway's
    // predicate — proving producer and verifier share one rule.
    for tok in ["trusted", "untrusted", "adversarial", "secret", "weird"] {
        let blocked = nucleus_ifc::egress_blocked_by_integrity(tok);
        let consistent = verify_ifc_flow(Some(tok)).is_consistent();
        assert_eq!(consistent, !blocked, "drift for token {tok:?}");
    }
}

// ── cross-check: gate output (child) vs runner-signed input (parent) ──

#[test]
fn cross_check_non_egress_child_is_not_gated() {
    assert_eq!(
        verify_ifc_flow_consistent(None, Some("trusted")),
        IfcFlowOutcome::NotGated
    );
}

#[test]
fn cross_check_matching_signed_input_is_allow() {
    // anti-vacuity: an honest hop (gate allowed "trusted", parent signed
    // "trusted") must be accepted.
    assert_eq!(
        verify_ifc_flow_consistent(Some("trusted"), Some("trusted")),
        IfcFlowOutcome::Allow
    );
}

#[test]
fn cross_check_rejects_input_output_mismatch() {
    // The gate co-committed "trusted" but the runner signed "adversarial"
    // upstream — the gate evaluated a downgraded value. Reject.
    match verify_ifc_flow_consistent(Some("trusted"), Some("adversarial")) {
        IfcFlowOutcome::Inconsistent {
            effective_integrity,
        } => {
            assert_eq!(effective_integrity, "trusted");
        }
        other => panic!("expected Inconsistent, got {other:?}"),
    }
    // Also reject when the parent didn't sign an effective integrity at all
    // (can't confirm the gate input).
    assert!(!verify_ifc_flow_consistent(Some("trusted"), None).is_consistent());
}

#[test]
fn cross_check_inherits_allow_rule() {
    // A child gated on "adversarial" is rejected by the allow-rule before the
    // input/output comparison even matters.
    assert!(!verify_ifc_flow_consistent(Some("adversarial"), Some("adversarial")).is_consistent());
}

//! Sink scope + one-shot burn — the slice the **declassification** theorems are
//! proven over after Charon→Aeneas→Lean extraction.
//!
//! # What this is
//!
//! A `DeclassificationToken` (portcullis-core `declassify.rs`) is signed over a
//! target node, a label rule, and a list of `allowed_sinks`. Two decisions give
//! the token its meaning, and both are restated here `String`-free so their
//! reachable dependency subgraph stays inside Aeneas's supported subset:
//!
//! * **Sink scope** — a declassified node contributes its *released*
//!   confidentiality only to operations inside the token's signed sink mask;
//!   every other operation keeps seeing the *strict* label. [`mask_admits`] is
//!   the bit test, [`effective_conf`] the shadow pick, [`declass_release_ok`]
//!   the composed release decision at a sink ceiling (composing [`cflows_to`]
//!   exactly as `extracted::identity` composes it).
//! * **One-shot burn** — a token authorizes at most one application, forever.
//!   [`declass_step`] is the 2-state ABSORBING machine: applying burns, a
//!   refusal preserves, and a burned token admits nothing ever again. This is
//!   deliberately NOT the mediation machine (`extracted::mediation::med_step`),
//!   whose `Discharge` re-arms the authority — re-arming is exactly what a
//!   one-shot token must never do.
//!
//! # Why the mask is a `u16`
//!
//! `Operation` is `#[repr(u8)]` with 13 variants whose discriminants are pinned
//! 0..=12 by compile-time asserts (ifc_ops.rs). `1 << discriminant` therefore
//! fits a `u16` with three bits to spare, and bit arithmetic extracts cleanly
//! (precedent: `extracted::egress`'s netmask). The mask is derived from the
//! signed `allowed_sinks` list by `DeclassificationToken::sink_mask()`, and the
//! parity of that derivation with [`mask_admits`] is checked exhaustively over
//! the whole 2^13 × 13 domain in portcullis-core — for a finite domain an
//! exhaustive check is a complete equivalence proof, not a sample.
//!
//! # Faithfulness
//!
//! [`MedOperation`]'s discriminants ARE the production `Operation`
//! discriminants (bound in `extracted::mediation`). The graph-level binding —
//! that `FlowGraph` verdicts actually route through these functions — is the
//! pointwise binding test in `portcullis/tests/declassify_scope.rs`, the same
//! layer FM-5 uses for its spawn binding.

use super::ifc_confidentiality::{ConfLevel, cflows_to};
use super::mediation::{MedOperation, opcode};

/// Bit test: does the signed sink mask admit operation `op`?
///
/// An empty mask (0) admits nothing — a token with no allowed sinks is inert,
/// matching `allowed_sinks: Empty = no sinks allowed` in the token's docs.
pub fn mask_admits(mask: u16, op: MedOperation) -> bool {
    let bit: u16 = 1 << opcode(op);
    (mask & bit) != 0
}

/// The shadow pick: the confidentiality a declassified node contributes when
/// operation `op` consumes it.
///
/// Inside the mask the node contributes its released level; outside it, the
/// strict (pre-declassification) level. The node's stored label is never
/// mutated — release is a per-operation VIEW, which is what makes a token
/// scoped to one sink unable to clear its node for any other.
pub fn effective_conf(
    strict: ConfLevel,
    released: ConfLevel,
    mask: u16,
    op: MedOperation,
) -> ConfLevel {
    if mask_admits(mask, op) {
        released
    } else {
        strict
    }
}

/// The composed release decision: may data with strict level `strict`,
/// declassified to `released` for the sinks in `mask`, flow to a sink for
/// operation `op` whose confidentiality ceiling is `sink_cap`?
pub fn declass_release_ok(
    strict: ConfLevel,
    released: ConfLevel,
    mask: u16,
    op: MedOperation,
    sink_cap: ConfLevel,
) -> bool {
    cflows_to(effective_conf(strict, released, mask, op), sink_cap)
}

// ═══════════════════════════════════════════════════════════════════════════
// The one-shot machine — the slice the burn theorems are proven over
// ═══════════════════════════════════════════════════════════════════════════

/// Whether the token's single authorization has been spent.
///
/// Flat struct rather than an enum for the same reason as
/// `extracted::mediation::MedState`: no discriminated union on the proof's
/// critical path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclassState {
    /// Has the token been applied? Absorbing: once true, forever true.
    pub burned: bool,
}

/// The fresh state: authorization unspent.
pub fn declass_fresh() -> DeclassState {
    DeclassState { burned: false }
}

/// The result of one application attempt: whether it applied, and the state
/// after.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeclassStepResult {
    /// Did the token apply?
    pub ok: bool,
    /// The state afterwards. A refusal leaves the state unchanged — an
    /// expired or precondition-unmet token did not exercise its authority
    /// and stays usable once the obstacle clears (`runD` semantics: spend on
    /// release, never on refusal).
    pub next: DeclassState,
}

/// One application attempt.
///
/// * Applies iff the token is unburned AND its signature verified AND the
///   rule's precondition matched — and applying burns it, forever. There is
///   no re-arming action: unlike the mediation machine's `Discharge`, nothing
///   in this machine can take `burned` back to false.
/// * Any refusal (bad signature, unmet precondition, or already burned)
///   leaves the state exactly as it was.
pub fn declass_step(state: DeclassState, sig_ok: bool, precond_ok: bool) -> DeclassStepResult {
    if !state.burned && sig_ok && precond_ok {
        DeclassStepResult {
            ok: true,
            next: DeclassState { burned: true },
        }
    } else {
        DeclassStepResult {
            ok: false,
            next: state,
        }
    }
}

// ═══ Value binding — the slice the value-non-steering theorem is proven over ═══

/// **Value binding (Phase 3): is a declassification release authorized for the
/// *specific* value the governor committed to?**
///
/// A signed `DeclassificationToken` carries a `content_commitment` — the
/// SHA-256 identity of the exact bytes the governor authorized releasing. The
/// target node carries a `content_hash` the monitor recomputed at ingest (never
/// an agent-supplied field). A release is authorized for the value ONLY when the
/// token is BOUND to a value, the node HAS a recorded value, and the two
/// identities are EQUAL — a pure equality over the value identity. This is what
/// denies an adversary the ability to steer WHICH value a governor's release
/// clears: the signature fixes the identity, and any substituted value has a
/// different identity and is refused.
///
/// Fail-closed: an unbound token (`committed_bound == false`) or a node with no
/// recorded identity (`recorded_present == false`) is NOT authorized.
///
/// # Representation of the value identity
///
/// The production identity is a 32-byte SHA-256 (`ContentHash([u8; 32])`).
/// Modeled here as an opaque `u64` tag with decidable equality: the decision
/// — bound ∧ present ∧ equal — is independent of the identity's *width*, and no
/// other extracted decision function in this corpus uses a byte array, so a
/// `u64` tag keeps the reachable subgraph inside the pipeline's proven-
/// extractable subset (a full `[u8; 32]` array is unproven in this extractor).
/// The runtime↔model parity test (`portcullis/tests/declassify_scope.rs`) binds
/// the real 32-byte `ContentHash` comparison to this scalar decision: equal
/// bytes map to an equal tag, unequal bytes to an unequal tag.
pub fn value_authorized(
    committed_bound: bool,
    recorded_present: bool,
    committed: u64,
    recorded: u64,
) -> bool {
    committed_bound && recorded_present && committed == recorded
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_OPS: [MedOperation; 13] = [
        MedOperation::ReadFiles,
        MedOperation::WriteFiles,
        MedOperation::EditFiles,
        MedOperation::RunBash,
        MedOperation::GlobSearch,
        MedOperation::GrepSearch,
        MedOperation::WebSearch,
        MedOperation::WebFetch,
        MedOperation::GitCommit,
        MedOperation::GitPush,
        MedOperation::CreatePr,
        MedOperation::ManagePods,
        MedOperation::SpawnAgent,
    ];

    /// Every operation is admitted exactly by the masks with its bit set —
    /// the full 2^13 × 13 domain, so this is an equivalence check of the bit
    /// test against its specification, not a sample.
    #[test]
    fn mask_admits_is_exactly_the_bit_test() {
        for mask in 0u16..(1 << 13) {
            for op in ALL_OPS {
                let expected = mask & (1u16 << opcode(op)) != 0;
                assert_eq!(
                    mask_admits(mask, op),
                    expected,
                    "mask_admits diverged for mask={mask:#06x}, op={op:?}"
                );
            }
        }
    }

    /// The empty mask admits nothing; the full mask admits everything.
    #[test]
    fn empty_mask_is_inert_and_full_mask_is_total() {
        for op in ALL_OPS {
            assert!(!mask_admits(0, op), "empty mask admitted {op:?}");
            assert!(mask_admits((1 << 13) - 1, op), "full mask refused {op:?}");
        }
    }

    /// Outside the mask the strict level governs: a Secret node declassified
    /// to Public for one sink stays Secret for every other.
    #[test]
    fn outside_the_mask_the_strict_level_governs() {
        for granted in ALL_OPS {
            let mask = 1u16 << opcode(granted);
            for attempted in ALL_OPS {
                let eff = effective_conf(ConfLevel::Secret, ConfLevel::Public, mask, attempted);
                if opcode(attempted) == opcode(granted) {
                    assert_eq!(eff, ConfLevel::Public);
                } else {
                    assert_eq!(
                        eff,
                        ConfLevel::Secret,
                        "release leaked from {granted:?} to {attempted:?}"
                    );
                }
            }
        }
    }

    /// The composed decision: released-Secret data reaches a Public-ceiling
    /// sink only through an in-mask operation.
    #[test]
    fn release_reaches_a_low_sink_only_in_mask() {
        for granted in ALL_OPS {
            let mask = 1u16 << opcode(granted);
            for attempted in ALL_OPS {
                let ok = declass_release_ok(
                    ConfLevel::Secret,
                    ConfLevel::Public,
                    mask,
                    attempted,
                    ConfLevel::Public,
                );
                assert_eq!(
                    ok,
                    opcode(attempted) == opcode(granted),
                    "declass_release_ok wrong for granted={granted:?}, attempted={attempted:?}"
                );
            }
        }
    }

    /// One-shot: applying burns; a second apply is refused; the machine is
    /// absorbing — no input sequence unburns it.
    #[test]
    fn apply_burns_and_nothing_unburns() {
        let first = declass_step(declass_fresh(), true, true);
        assert!(first.ok);
        assert!(first.next.burned);

        let second = declass_step(first.next, true, true);
        assert!(!second.ok, "a burned token applied again");
        assert!(second.next.burned);

        // Exhaust the input alphabet from the burned state: still burned.
        for sig_ok in [false, true] {
            for precond_ok in [false, true] {
                let r = declass_step(first.next, sig_ok, precond_ok);
                assert!(!r.ok);
                assert!(r.next.burned, "the machine un-burned itself");
            }
        }
    }

    /// A refusal preserves the token: bad signature or unmet precondition
    /// leaves it fresh and a later valid apply still succeeds.
    #[test]
    fn refusal_preserves_the_token() {
        for (sig_ok, precond_ok) in [(false, false), (false, true), (true, false)] {
            let refused = declass_step(declass_fresh(), sig_ok, precond_ok);
            assert!(!refused.ok);
            assert!(!refused.next.burned, "a refusal burned the token");
            let later = declass_step(refused.next, true, true);
            assert!(later.ok, "the token was not usable after a refusal");
        }
    }

    // ── Value binding ──

    /// The matching value is released; a substituted value is refused.
    #[test]
    fn value_binding_gates_release_on_identity_equality() {
        // Committed identity == recorded identity ⇒ authorized.
        assert!(value_authorized(true, true, 0xABCD, 0xABCD));
        // A DIFFERENT recorded identity (the substitution attack) ⇒ refused.
        assert!(!value_authorized(true, true, 0xABCD, 0x1234));
    }

    /// Fail-closed: an unbound token and a node with no recorded identity are
    /// both refused, whatever the tags.
    #[test]
    fn value_binding_fails_closed_on_unbound_or_missing() {
        // Unbound token: even a matching tag is refused.
        assert!(!value_authorized(false, true, 7, 7));
        // Missing recorded hash: even a matching tag is refused.
        assert!(!value_authorized(true, false, 7, 7));
        // Both absent.
        assert!(!value_authorized(false, false, 7, 7));
    }
}

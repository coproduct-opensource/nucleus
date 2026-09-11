//! `nucleus-rest-pattern-lint` — the `rest_pattern_on_policy_path` pass.
//!
//! ADR 0007 E-1: **no `..` in a record pattern on a delegation or policy path.**
//!
//! # What this closes
//!
//! `create_sub_pod` decides four of `PodSpecInner`'s fourteen fields. The other
//! ten, and all four of `Metadata`'s, reached the serialized child spec exactly
//! as the requester wrote them. That enumeration IS the security boundary, and
//! it was maintained by hand — the handler's own comment said authority "must be
//! made deliberately, not inherited from a field being added", and nothing made
//! it so. A fifteenth field would have been granted to children by default.
//!
//! The remedy was an exhaustive destructure: binding every field by name makes a
//! new one an `E0027` at the delegation boundary, so the build breaks until
//! someone writes down what it means. This pass is what keeps that true. Without
//! it, one `..` restores the old behaviour and nothing objects — and `..` is the
//! natural thing to type when a pattern gets long.
//!
//! # Why this is scoped by TYPE, not by crate
//!
//! Measured 2026-09-11: the policy crates carry **284** production rest-patterns
//! (`portcullis` 145, `portcullis-core` 61, `nucleus-tool-proxy` 42). A
//! crate-scoped ban would be hundreds of allow-listed exceptions, which is
//! theatre — a lint suppressed everywhere teaches people to suppress it.
//!
//! Almost all of those are correct. `..` is the right thing to write when you
//! need two fields of a struct whose other twenty are irrelevant. What E-1 is
//! about is narrower and nameable: records whose invariant must hold over *all*
//! fields, because the fields ARE the authority being delegated.
//!
//! So [`POLICY_RECORDS`] names those records, and the pass says nothing about
//! any other struct. Measured over the whole workspace, those six types have
//! **zero** rest-patterns today, production and test — so this gates at zero
//! with no allowlist, and an allowlist would be the first sign the scope is
//! wrong.
//!
//! # What a clean pass does NOT establish
//!
//! * **That the bound fields are handled.** Exhaustive destructuring forces a
//!   DECISION per field; it does not check the decision. `create_sub_pod` binds
//!   ten fields to `_`-prefixed names with a reason each, and that is a standing
//!   choice to forward them unclamped, not a clamp. The pass cannot tell those
//!   apart and does not try.
//! * **That every delegation path is covered.** [`POLICY_RECORDS`] is a list.
//!   A new record that carries authority is not on it until someone adds it,
//!   which is the same hand-maintained-enumeration problem one level up. The
//!   list is short and load-bearing on purpose.
//! * **Anything about `..` in expressions.** Struct-update syntax
//!   (`Foo { a, ..base }`) is a different construct and is not touched.

#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_hir;
extern crate rustc_middle;

use clippy_utils::diagnostics::span_lint_and_help;
use rustc_hir::{Pat, PatKind};
use rustc_lint::{LateContext, LateLintPass};
use rustc_middle::ty;

/// Records whose patterns must name every field.
///
/// Each is a record where the fields ARE the authority: destructuring one
/// incompletely is how a field added later gets delegated by default.
///
/// Short on purpose. Adding a name here tightens the boundary and is cheap;
/// REMOVING one loosens it and should be a visible, argued diff.
const POLICY_RECORDS: &[&str] = &[
    // The sub-pod spec. Fourteen fields, four decided at the delegation
    // boundary; the enumeration of the other ten is the security property.
    "PodSpecInner",
    // `PodSpec`'s sibling of `spec`, and the half ADR 0006 C4.2's own prose
    // under-counted: it names `labels` and `task_grant_id`, while `name` and
    // `namespace` ride through too.
    "Metadata",
    "PodSpec",
    // The permission lattice and its capability half — what a delegation
    // narrows. A `..` here is a dimension silently inherited.
    "PermissionLattice",
    "CapabilityLattice",
    "PolicySpec",
];

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Flags `..` in a pattern that destructures one of a named set of policy
    /// and delegation records.
    ///
    /// ### Why is this bad?
    ///
    /// For these records the field list is the authority. A `..` means a field
    /// added later is handled by nobody — in `create_sub_pod` that is a child
    /// pod inheriting a capability its parent never decided to grant. Naming
    /// every field turns that into `E0027`: the build breaks until someone says
    /// what the new field means.
    ///
    /// ### Known problems
    ///
    /// Scoped to a hand-maintained list of record names, resolved through the
    /// type rather than the written path — so `Self { .. }` inside an `impl` and
    /// aliases are caught, but a record that carries authority and is not on the
    /// list is invisible.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// let PodSpecInner { policy, workload, .. } = &spec.spec;
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// let PodSpecInner {
    ///     policy: _policy,       // narrowed to this pod's ceiling
    ///     workload: _workload,   // stripped
    ///     // … every remaining field, each with a reason
    /// } = &spec.spec;
    /// ```
    pub REST_PATTERN_ON_POLICY_PATH,
    Warn,
    "a `..` in a record pattern on a delegation or policy path"
}

impl<'tcx> LateLintPass<'tcx> for RestPatternOnPolicyPath {
    fn check_pat(&mut self, cx: &LateContext<'tcx>, pat: &'tcx Pat<'tcx>) {
        // The third field of `PatKind::Struct` is the span of the `..`, present
        // only when the pattern has one. `None` is an already-exhaustive
        // pattern, which is the state this pass exists to keep — and the span
        // lets the diagnostic point at the `..` rather than at the whole
        // pattern, which for a fourteen-field record is most of a screen.
        let PatKind::Struct(_, _, Some(rest_span)) = pat.kind else {
            return;
        };

        // Resolved through the TYPE rather than the written path. A pattern may
        // spell the record as `Self`, as an alias, or fully qualified; matching
        // the text would miss all three, and a miss is indistinguishable from
        // "no policy record here" — the failure mode this pass exists to
        // prevent, pointed at itself.
        let ty::Adt(adt, _) = cx.typeck_results().pat_ty(pat).kind() else {
            return;
        };
        let name = cx.tcx.item_name(adt.did());
        if !POLICY_RECORDS.contains(&name.as_str()) {
            return;
        }

        span_lint_and_help(
            cx,
            REST_PATTERN_ON_POLICY_PATH,
            rest_span,
            format!("`..` in a pattern over `{name}`, whose fields are the authority"),
            None,
            "name every field. A field this pattern does not mention is one \
             nobody decided about, and on a delegation path that is a capability \
             granted by default — bind it to `_name` with a reason if forwarding \
             it unclamped is the standing decision",
        );
    }
}

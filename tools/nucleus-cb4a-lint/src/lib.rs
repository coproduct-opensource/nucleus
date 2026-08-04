//! `nucleus-cb4a-lint` — the `cb4a_separation` pass.
//!
//! Mechanises the two normative MUSTs of the IETF draft **Credential Broker for
//! Agents** (`draft-hartman-credential-broker-4-agents-00`):
//!
//! > The component that decides "yes" (**PDP**) MUST never touch credential
//! > material. The component that dispenses credentials (**CDP**) MUST never
//! > make policy decisions.
//!
//! Both are stated in the draft as prose about components. This pass states them
//! as **reachability over the call graph**: nothing reachable from a PDP root
//! may name credential material, and nothing reachable from a CDP root may name
//! a policy type. As far as we know nobody has mechanised these before.
//!
//! # Why this closes FORWARD, unlike its sibling
//!
//! `nucleus-mediation-lint` closes **backward**: it starts at I/O primitives and
//! propagates up to public entry points, because the question is "can anything
//! reach an effect without a token". Here the question is inverted — "can *this
//! designated function* reach a forbidden thing" — so the closure runs forward
//! from named roots. The fixpoint machinery is the same shape; the direction and
//! the seed are not.
//!
//! That difference has a consequence worth stating: a backward closure that
//! stops at a crate boundary still catches the defect in the callee's own crate,
//! because every crate gets its own pass. A **forward** closure that stops at a
//! crate boundary genuinely stops. See "What a clean pass does not establish".
//!
//! # Why a lint, when the type signatures already say this
//!
//! `pdp_decide` takes no `CredentialStore` and `cdp_fetch` takes no
//! `PermissionLattice`, which closes the *direct* case at the signature. But a
//! signature says nothing about what a function does two hops down. A PDP that
//! called a logging helper that called a store accessor would satisfy every
//! signature in sight and violate the MUST — and that is exactly the shape
//! separation-of-duty failures take in practice, because nobody adds
//! `CredentialStore` to the PDP's own arguments.
//!
//! # This is a SUFFICIENT condition over the scanned crate
//!
//! Like `mediated` and unlike `aeneas_eligible`, a clean pass is meant to assert
//! something. For that to hold, two things must be true:
//!
//! 1. **The forbidden sets are complete** for the crate being scanned. A missing
//!    entry means a violating path reports clean. See [`CREDENTIAL_MATERIAL`] and
//!    [`POLICY_MATERIAL`].
//! 2. **The call-graph closure is sound.** Calls that defeat static resolution —
//!    `dyn` dispatch, function pointers, inline `asm!` — are reported when
//!    reachable from a root, never skipped.
//!
//! # What a clean pass does NOT establish
//!
//! * **Anything past a crate boundary.** The closure follows locally-resolvable
//!   callees only. That is covered by the OTHER half of the FM-2 argument rather
//!   than by this pass: `deny.toml` lists `nucleus-cred-broker` with `wrappers`,
//!   so only the composition root may link credential material at all. Inside
//!   that crate this lint applies; outside it, the ban does. The two halves
//!   compose, and neither is sufficient alone — which is why both exist.
//! * **That the roots are the real PDP and CDP.** [`PDP_ROOTS`] and
//!   [`CDP_ROOTS`] are matched by name. Renaming `pdp_decide` without updating
//!   this list silently removes the check, so the root lists are themselves
//!   load-bearing configuration.
//! * **Anything about data flow.** "Does not name" is a syntactic property. A
//!   PDP handed a credential as an opaque `&[u8]` through three layers of
//!   generics would pass. Closing that needs the information-flow work
//!   (FM-1), not a lint.

#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_data_structures;
extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use rustc_data_structures::fx::{FxHashMap, FxHashSet};
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_hir::intravisit::{FnKind, Visitor, walk_expr};
use rustc_hir::{Expr, ExprKind, FnDecl};
use rustc_lint::{LateContext, LateLintPass};
use rustc_middle::ty::TyKind;
use rustc_span::Span;
use std::cell::RefCell;

dylint_linting::impl_late_lint! {
    /// ### What it does
    ///
    /// Flags any function reachable from a PDP root that names credential
    /// material, and any function reachable from a CDP root that names a policy
    /// type. Closed under the call graph.
    ///
    /// ### Why is this bad?
    ///
    /// It is CB4A's separation of duties. If the decider can also reach the
    /// secrets, compromising it yields both; the whole point of splitting them
    /// is that compromise of one does not give you the other.
    ///
    /// ### Known problems
    ///
    /// The closure does not cross crate boundaries — that case is covered by the
    /// `deny.toml` dependency ban instead. "Names" is syntactic: a credential
    /// laundered through an opaque byte slice would not be caught.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// fn pdp_decide(env: &Envelope, policy: &PermissionLattice) -> Verdict {
    ///     audit(env)          // and `audit` reads the CredentialStore
    /// }
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// fn pdp_decide(env: &Envelope, policy: &PermissionLattice) -> Verdict {
    ///     audit_without_credentials(env)
    /// }
    /// ```
    pub CB4A_SEPARATION,
    Warn,
    "a PDP path reaches credential material, or a CDP path reaches policy",
    Cb4ASeparation::new()
}

/// Function paths that are PDP entry points, matched by suffix.
///
/// **Load-bearing configuration.** Renaming the decider without updating this
/// list removes the check silently rather than failing loudly, which is the one
/// way a root list can be worse than no root list.
const PDP_ROOTS: &[&str] = &["::pdp_decide", "::decide_identity_grant"];

/// Function paths that are CDP entry points, matched by suffix.
const CDP_ROOTS: &[&str] = &["::cdp_fetch", "::for_request"];

/// Paths naming credential material. A PDP path that mentions any of these
/// violates CB4A's first MUST.
///
/// Completeness is load-bearing in the same way `mediated`'s deny-set is: a
/// missing entry makes a violating path report clean.
const CREDENTIAL_MATERIAL: &[&str] = &[
    "Credential",
    "CredentialStore",
    "::expose",
    "credentials::env",
    "secret",
];

/// Paths naming policy material. A CDP path that mentions any of these violates
/// CB4A's second MUST.
///
/// `Operation` is deliberately ABSENT. The CDP is told which operation was
/// approved — that is the decision being communicated to it, not the CDP making
/// one. Including it would flag the correct design, and a lint that fires on the
/// intended shape gets suppressed rather than obeyed.
const POLICY_MATERIAL: &[&str] = &[
    "PermissionLattice",
    "CapabilityLevel",
    "resolve_policy",
    "PolicyProfile",
    "portcullis_core::policy",
];

/// Which MUST a root stands for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    /// Decides. Must not touch credential material.
    Pdp,
    /// Dispenses. Must not decide policy.
    Cdp,
}

impl Role {
    fn forbidden(self) -> &'static [&'static str] {
        match self {
            Role::Pdp => CREDENTIAL_MATERIAL,
            Role::Cdp => POLICY_MATERIAL,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Role::Pdp => "PDP",
            Role::Cdp => "CDP",
        }
    }

    fn must(self) -> &'static str {
        match self {
            Role::Pdp => "the component that decides MUST never touch credential material",
            Role::Cdp => "the component that dispenses credentials MUST never decide policy",
        }
    }
}

/// What we learned about one function before the closure runs.
struct FnFacts {
    span: Span,
    path: String,
    /// Every path this function names, in its signature or its body.
    names: Vec<String>,
    /// Locally-resolvable callees.
    callees: FxHashSet<LocalDefId>,
    /// Calls this pass could not resolve. Reported when reachable from a root.
    unresolved: Vec<(Span, String)>,
}

impl FnFacts {
    /// The first forbidden path this function names, if any.
    fn touches(&self, forbidden: &[&str]) -> Option<String> {
        self.names.iter().find_map(|n| {
            forbidden
                .iter()
                .find(|f| n.contains(**f))
                .map(|f| format!("`{n}` (matches `{f}`)"))
        })
    }
}

pub struct Cb4ASeparation {
    facts: RefCell<FxHashMap<LocalDefId, FnFacts>>,
}

impl Cb4ASeparation {
    pub fn new() -> Self {
        Self {
            facts: RefCell::new(FxHashMap::default()),
        }
    }
}

impl Default for Cb4ASeparation {
    fn default() -> Self {
        Self::new()
    }
}

/// Walks a body collecting callees, named paths, and unresolvable calls.
struct Scan<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    callees: FxHashSet<LocalDefId>,
    names: Vec<String>,
    unresolved: Vec<(Span, String)>,
}

impl<'a, 'tcx> Scan<'a, 'tcx> {
    fn record(&mut self, did: DefId) {
        self.names.push(self.cx.tcx.def_path_str(did));
        if let Some(local) = did.as_local() {
            self.callees.insert(local);
        }
        // Cross-crate callees are recorded by NAME above but not followed. The
        // dependency ban is what covers past the boundary — see the module docs.
    }
}

impl<'a, 'tcx> Visitor<'tcx> for Scan<'a, 'tcx> {
    fn visit_expr(&mut self, ex: &'tcx Expr<'tcx>) {
        // The TYPE of every expression counts as a name, not just called
        // functions. A function that merely holds a `Credential` in a local
        // never calls anything named `Credential`, and a call-only scan would
        // miss it entirely.
        if let Some(ty) = self.cx.typeck_results().expr_ty_opt(ex)
            && let TyKind::Adt(adt, _) = ty.kind()
        {
            self.names.push(self.cx.tcx.def_path_str(adt.did()));
        }

        match ex.kind {
            ExprKind::Call(callee, _) => {
                if let ExprKind::Path(ref qpath) = callee.kind {
                    match self.cx.qpath_res(qpath, callee.hir_id) {
                        rustc_hir::def::Res::Def(_, did) => self.record(did),
                        _ => self
                            .unresolved
                            .push((ex.span, "call through an unresolved path".to_string())),
                    }
                } else {
                    self.unresolved
                        .push((ex.span, "call through a function pointer or value".to_string()));
                }
            }
            ExprKind::MethodCall(..) => {
                match self.cx.typeck_results().type_dependent_def_id(ex.hir_id) {
                    Some(did) => self.record(did),
                    None => self
                        .unresolved
                        .push((ex.span, "unresolved method call".to_string())),
                }
            }
            ExprKind::InlineAsm(_) => self
                .unresolved
                .push((ex.span, "inline `asm!` — opaque to the call graph".to_string())),
            _ => {}
        }
        walk_expr(self, ex);
    }
}

/// Every ADT named in a function's signature.
fn signature_names(cx: &LateContext<'_>, def_id: LocalDefId) -> Vec<String> {
    let sig = cx.tcx.fn_sig(def_id.to_def_id()).skip_binder();
    let inputs_and_output = sig.inputs_and_output().skip_binder();
    inputs_and_output
        .iter()
        .filter_map(|ty| {
            // Peel references so `&CredentialStore` is seen as `CredentialStore`.
            let mut ty = ty;
            while let TyKind::Ref(_, inner, _) = ty.kind() {
                ty = *inner;
            }
            match ty.kind() {
                TyKind::Adt(adt, args) => {
                    let mut names = vec![cx.tcx.def_path_str(adt.did())];
                    // Generic arguments count: `Result<&Credential, _>` names a
                    // credential even though the outer type is `Result`.
                    for arg in args.types() {
                        if let TyKind::Adt(inner, _) = arg.kind() {
                            names.push(cx.tcx.def_path_str(inner.did()));
                        }
                    }
                    Some(names)
                }
                _ => None,
            }
        })
        .flatten()
        .collect()
}

impl<'tcx> LateLintPass<'tcx> for Cb4ASeparation {
    fn check_fn(
        &mut self,
        cx: &LateContext<'tcx>,
        kind: FnKind<'tcx>,
        _decl: &'tcx FnDecl<'tcx>,
        body: &'tcx rustc_hir::Body<'tcx>,
        span: Span,
        def_id: LocalDefId,
    ) {
        if matches!(kind, FnKind::Closure) {
            return;
        }

        let mut scan = Scan {
            cx,
            callees: FxHashSet::default(),
            names: Vec::new(),
            unresolved: Vec::new(),
        };
        scan.visit_body(body);

        let mut names = scan.names;
        names.extend(signature_names(cx, def_id));

        self.facts.borrow_mut().insert(
            def_id,
            FnFacts {
                span,
                path: cx.tcx.def_path_str(def_id.to_def_id()),
                names,
                callees: scan.callees,
                unresolved: scan.unresolved,
            },
        );
    }

    /// The forward closure and the report.
    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        let facts = self.facts.borrow();

        for role in [Role::Pdp, Role::Cdp] {
            let roots = match role {
                Role::Pdp => PDP_ROOTS,
                Role::Cdp => CDP_ROOTS,
            };

            // Seed: the roots themselves.
            let mut reachable: FxHashSet<LocalDefId> = facts
                .iter()
                .filter(|(_, f)| roots.iter().any(|r| f.path.ends_with(*r)))
                .map(|(d, _)| *d)
                .collect();

            if reachable.is_empty() {
                // No root in this crate. Silence is correct — most crates have
                // neither a PDP nor a CDP — and is why the root list being wrong
                // is a silent failure rather than a loud one.
                continue;
            }

            // Least fixpoint of "reachable from a root".
            loop {
                let mut grew = false;
                let frontier: Vec<LocalDefId> = reachable
                    .iter()
                    .filter_map(|d| facts.get(d))
                    .flat_map(|f| f.callees.iter().copied())
                    .collect();
                for callee in frontier {
                    if reachable.insert(callee) {
                        grew = true;
                    }
                }
                if !grew {
                    break;
                }
            }

            for did in &reachable {
                let Some(f) = facts.get(did) else { continue };

                if let Some(hit) = f.touches(role.forbidden()) {
                    span_lint_and_help(
                        cx,
                        CB4A_SEPARATION,
                        f.span,
                        format!(
                            "`{}` is reachable from a {} entry point and names {hit}",
                            f.path,
                            role.name()
                        ),
                        None,
                        format!(
                            "CB4A: {}. Move this out of the {} call graph, or pass the \
                             already-decided result rather than the thing that decides it",
                            role.must(),
                            role.name()
                        ),
                    );
                }

                // Unresolvable calls are reported when reachable from a root:
                // they are where the closure stops being sound, and a clean pass
                // over a graph with holes in it is the one lie this must not tell.
                for (span, why) in &f.unresolved {
                    span_lint_and_help(
                        cx,
                        CB4A_SEPARATION,
                        *span,
                        format!(
                            "{why} — reachable from a {} entry point, so the separation \
                             cannot be established past it",
                            role.name()
                        ),
                        None,
                        "make the callee statically resolvable, or keep it out of the \
                         PDP/CDP call graphs",
                    );
                }
            }
        }
    }
}

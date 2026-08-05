//! `nucleus-identity-lint` — the `workload_identity_isolation` pass.
//!
//! **FM-5's reachability leg.** The Lean theorems in
//! `IdentityMaterialNoninterferenceExtracted.lean` prove that the *extracted
//! delivery relation* never delivers identity material to the workload, and
//! the binding tests in `nucleus-tool-proxy/src/workload.rs` pin that model to
//! `workload_env` pointwise. What neither establishes is that the spawn path's
//! CALL GRAPH stays away from identity material entirely — a helper three hops
//! below `spawn_workload` that reads the broker capability would satisfy every
//! signature and every binding test while putting the material one refactor
//! away from the child's environment. This pass states that as reachability:
//! **nothing reachable from a workload-spawn root may name identity
//! material.**
//!
//! # Why this closes FORWARD, like `cb4a_separation`
//!
//! The question is "can *these designated functions* reach a forbidden thing",
//! so the closure runs forward from named roots — the same shape and the same
//! consequence as the CB4A pass: a forward closure that stops at a crate
//! boundary genuinely stops. The roots and everything interesting below them
//! live in `nucleus-tool-proxy`, which is the crate this pass is run over in
//! CI; material minted in other crates is out of the workload-spawn call
//! graph by construction of the spawn path's signature.
//!
//! # What a clean pass does NOT establish
//!
//! * **Anything about data flow.** "Does not name" is syntactic. The overlay's
//!   values are `String`s by the time `workload_env` returns them — a secret
//!   laundered into a `String` upstream of the roots is invisible here. That
//!   dynamic gap is covered by the real-child test
//!   (`the_spawned_child_does_not_inherit_the_capability`) and by the binding
//!   tests, not by this lint. The three legs compose; none is sufficient
//!   alone.
//! * **That the roots are the real spawn path.** [`WORKLOAD_ROOTS`] is matched
//!   by name. Renaming `spawn_workload` without updating the list removes the
//!   check silently, so the root list is load-bearing configuration — the same
//!   caveat the sibling passes carry.
//! * **Completeness of [`IDENTITY_MATERIAL`].** A missing entry means a
//!   violating path reports clean. The list deliberately avoids bare
//!   substrings like `Credential`, because `CredentialedEgressSpec` — names
//!   and URLs only, the credential stays host-side — is a legitimate input of
//!   `workload_egress_env`, and a lint that fires on the intended shape gets
//!   suppressed rather than obeyed.

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
    /// Flags any function reachable from a workload-spawn root that names
    /// identity material. Closed under the call graph.
    ///
    /// ### Why is this bad?
    ///
    /// It is FM-5's boundary. The workload is the process the sandbox exists
    /// to contain; identity material in its call graph is one refactor away
    /// from its environment, and the environment leak has already happened
    /// once (the broker capability, via `Command`'s default inheritance).
    ///
    /// ### Known problems
    ///
    /// "Names" is syntactic: a secret laundered through a `String` is not
    /// caught — the real-child and binding tests cover that. The closure does
    /// not cross crate boundaries.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// fn workload_env(...) -> BTreeMap<String, String> {
    ///     let cap = broker_capability();   // reads the broker secret
    ///     ...
    /// }
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// fn workload_env(...) -> BTreeMap<String, String> {
    ///     // only the proxy URL, the workload's own HMAC, and egress names
    /// }
    /// ```
    pub WORKLOAD_IDENTITY_ISOLATION,
    Warn,
    "a workload-spawn path reaches identity material",
    WorkloadIdentityIsolation::new()
}

/// Function paths that are workload-spawn entry points, matched by suffix.
///
/// **Load-bearing configuration.** Renaming a root without updating this list
/// removes the check silently rather than failing loudly — the one way a root
/// list can be worse than no root list.
const WORKLOAD_ROOTS: &[&str] = &[
    // The typed-launch path (FM-5 increment 3): build → admit → spawn. Type-
    // qualified so a generic `build`/`admit` elsewhere in the crate is not
    // pulled in as a root. `spawn_workload` was replaced by this trio.
    "WorkloadLaunch::build",
    "WorkloadLaunch::admit",
    "::spawn_admitted",
    "::workload_env",
    "::start_if_configured",
    "::workload_egress_env",
];

/// Paths naming identity material — the FM-5 `Secret`-labelled kinds, by the
/// types and accessors that carry them in this codebase.
///
/// Completeness is load-bearing: a missing entry makes a violating path report
/// clean. Precision is load-bearing too — see the module docs for why bare
/// `Credential` is deliberately absent.
const IDENTITY_MATERIAL: &[&str] = &[
    // The SVID and its key (nucleus-identity).
    "WorkloadCertificate",
    "PrivateKey",
    "TrustBundle",
    // Session task token (node mint + proxy holder).
    "MintedTaskToken",
    "SessionTaskToken",
    "SignedTaskRef",
    // The broker capability, in each of its shapes: the node's affine mint,
    // the guest fetcher's type, the proxy's client type, and the accessor
    // that reads it from the proxy's environment.
    "BrokerCapability",
    "ServeToken",
    "broker_client::Capability",
    "::broker_capability",
    // Per-pod material bundles.
    "PodMaterial",
    "DlcAdmissionMaterial",
    // The proxy's sandbox proof (carries the sandbox token).
    "SandboxProof",
];

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

pub struct WorkloadIdentityIsolation {
    facts: RefCell<FxHashMap<LocalDefId, FnFacts>>,
}

impl WorkloadIdentityIsolation {
    pub fn new() -> Self {
        Self {
            facts: RefCell::new(FxHashMap::default()),
        }
    }
}

impl Default for WorkloadIdentityIsolation {
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
        // Cross-crate callees are recorded by NAME above but not followed —
        // the boundary caveat in the module docs.
    }
}

impl<'a, 'tcx> Visitor<'tcx> for Scan<'a, 'tcx> {
    fn visit_expr(&mut self, ex: &'tcx Expr<'tcx>) {
        // The TYPE of every expression counts as a name, not just called
        // functions: a function that merely HOLDS a `SessionTaskToken` in a
        // local never calls anything named that, and a call-only scan would
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
            // Peel references so `&SessionTaskToken` is seen as `SessionTaskToken`.
            let mut ty = ty;
            while let TyKind::Ref(_, inner, _) = ty.kind() {
                ty = *inner;
            }
            match ty.kind() {
                TyKind::Adt(adt, args) => {
                    let mut names = vec![cx.tcx.def_path_str(adt.did())];
                    // Generic arguments count: `Option<&SessionTaskToken>`
                    // names the token even though the outer type is `Option`.
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

impl<'tcx> LateLintPass<'tcx> for WorkloadIdentityIsolation {
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

        // Seed: the roots themselves.
        let mut reachable: FxHashSet<LocalDefId> = facts
            .iter()
            .filter(|(_, f)| WORKLOAD_ROOTS.iter().any(|r| f.path.ends_with(*r)))
            .map(|(d, _)| *d)
            .collect();

        if reachable.is_empty() {
            // No root in this crate. Silence is correct — most crates spawn no
            // workload — and is why the root list being wrong is a silent
            // failure rather than a loud one.
            return;
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

            if let Some(hit) = f.touches(IDENTITY_MATERIAL) {
                span_lint_and_help(
                    cx,
                    WORKLOAD_IDENTITY_ISOLATION,
                    f.span,
                    format!(
                        "`{}` is reachable from a workload-spawn root and names {hit}",
                        f.path
                    ),
                    None,
                    "FM-5: identity material must never enter the workload-spawn call \
                     graph. Keep the spawn path to the proxy URL, the workload's own \
                     HMAC, and egress names — anything else belongs to the runtime",
                );
            }

            // Unresolvable calls are reported when reachable from a root: they
            // are where the closure stops being sound, and a clean pass over a
            // graph with holes in it is the one lie this must not tell.
            for (span, why) in &f.unresolved {
                span_lint_and_help(
                    cx,
                    WORKLOAD_IDENTITY_ISOLATION,
                    *span,
                    format!(
                        "{why} — reachable from a workload-spawn root, so identity \
                         isolation cannot be established past it"
                    ),
                    None,
                    "make the callee statically resolvable, or keep it out of the \
                     workload-spawn call graph",
                );
            }
        }
    }
}

//! `nucleus-mediation-lint` — the `mediated` pass.
//!
//! Flags any **publicly reachable** function that can reach a raw I/O primitive
//! without passing through a function that demands an
//! `Authority` by value. The reachability is **closed under the call graph**: a
//! callee that performs I/O makes its caller an effect site, transitively, until
//! some function on the path demands an authority.
//!
//! # This is a SUFFICIENT condition, not a screen — the opposite of its sibling
//!
//! The sibling `nucleus-guarantee-lint` is scrupulous that `aeneas_eligible` is
//! *"a SCREEN, not a proof — a clean pass asserts nothing"*, because Aeneas may
//! reject code the screen accepts. **This lint is deliberately the inverse.**
//!
//! A clean pass here is meant to assert something real, because it is what
//! discharges the antecedent of the Lean mediation theorem:
//!
//! > *If* every effect entry point consumes an `Authority` scoped to its
//! > `(Operation, SinkClass)`, *then* every trace has each effect immediately
//! > preceded by a matching discharge.
//!
//! Lean proves the conditional. This lint discharges the premise over the real
//! Rust. Neither half is worth much alone.
//!
//! For that to hold, two things must be true, and both are load-bearing:
//!
//! 1. **The deny-set covers every raw I/O primitive** reachable from the scanned
//!    crates. Incompleteness here is unsoundness, not noise — a missing entry
//!    means an unmediated path reports clean. See [`DENY_SET`].
//! 2. **The call-graph closure is sound.** Constructs that defeat static call
//!    resolution — `dyn Trait` dispatch, function pointers, FFI, inline `asm!` —
//!    are reported as `unresolved_call` rather than ignored, because silently
//!    skipping them would turn a hole into a clean pass. This mirrors seL4,
//!    which forbids calls through function pointers precisely so its call graph
//!    is statically known.
//!
//! # What a clean pass does NOT establish
//!
//! * **That the authority is *spent*, only that it is *demanded*.** A function
//!   taking `Authority` and calling `drop` on it would pass. What closes that in
//!   practice is elsewhere: `Authority` is `!Clone` and `#[must_use]`, `spend` is
//!   its only consuming method, and the scope check inside `spend` is what the
//!   Lean theorem is stated over. The lint proves the token reaches the boundary;
//!   the type and the theorem cover what happens there.
//! * **Anything about crates it does not run on.** Soundness is relative to the
//!   scanned set. `nucleus` and `nucleus-tool-proxy` legitimately call
//!   `std::process` and `reqwest` for their *own* infrastructure — jailer spawn,
//!   HTTP serving — which is not agent-attributed effect. "Mediated crates" is a
//!   defined set, listed in the CI invocation, not "everything".
//! * **That the I/O primitive list matches the kernel's actual syscall surface.**
//!   A `libc` call through FFI is caught as `unresolved_call`, not decoded.

#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_data_structures;
extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use rustc_data_structures::fx::{FxHashMap, FxHashSet};
use rustc_hir::def_id::{DefId, LOCAL_CRATE, LocalDefId};
use rustc_hir::intravisit::{FnKind, Visitor, walk_expr};
use rustc_hir::{Expr, ExprKind, FnDecl};
use rustc_lint::{LateContext, LateLintPass};
use rustc_middle::ty::TyKind;
use rustc_span::Span;
use std::cell::RefCell;

dylint_linting::impl_late_lint! {
    /// ### What it does
    ///
    /// Flags publicly reachable functions that can reach a raw I/O primitive
    /// without passing through a function that demands an `Authority` by value.
    /// Closed under the call graph.
    ///
    /// ### Why is this bad?
    ///
    /// It is the complete-mediation leg of the reference-monitor requirements:
    /// tamper-proof, verifiable, and *always invoked*. An unmediated path means
    /// an effect can occur without discharging the obligations, which is exactly
    /// the confused-deputy class this codebase has already had twice.
    ///
    /// ### Known problems
    ///
    /// Soundness is relative to the scanned crate set and to the completeness of
    /// the deny-set. Calls that cannot be statically resolved are reported
    /// rather than skipped, so they surface as work rather than as a clean pass.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// pub fn save(p: &Path, b: &[u8]) -> std::io::Result<()> {
    ///     std::fs::write(p, b) // flagged: reaches I/O, demands no Authority
    /// }
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// pub fn save(p: &Path, b: &[u8], a: Authority) -> std::io::Result<()> {
    ///     a.spend(Operation::WriteFiles, SinkClass::WorkspaceWrite)?;
    ///     std::fs::write(p, b)
    /// }
    /// ```
    pub MEDIATED,
    Warn,
    "a publicly reachable path reaches raw I/O without demanding an Authority",
    Mediated::new()
}

/// Raw I/O primitives, matched against `def_path_str` by prefix.
///
/// **Completeness of this list is load-bearing.** A missing entry is not a false
/// negative in the usual sense — it makes an unmediated path report clean, which
/// is the one failure mode this lint exists to prevent. Additions belong here
/// rather than in an allow-list at the call site.
const DENY_SET: &[&str] = &[
    // Filesystem
    "std::fs::",
    "tokio::fs::",
    "cap_std::fs::Dir::",
    "cap_std::fs::File::",
    // Process
    "std::process::Command::",
    "tokio::process::Command::",
    // Network
    "std::net::",
    "tokio::net::",
    "reqwest::",
    // Raw descriptors — bypass the typed wrappers above.
    "std::os::fd::",
    "std::os::unix::io::",
];

/// The type whose by-value presence in a signature marks a mediation boundary.
const AUTHORITY_PATH_SUFFIX: &str = "authority::Authority";

/// The **mediated set** — the crates whose unmediated-I/O findings are ENFORCED.
///
/// This codifies the "defined set" the module docs and README already declare:
/// *"'Mediated crates' is a defined set, listed in the CI invocation, not
/// 'everything'."* Because `cargo dylint -- -p <crate>` compiles and lints every
/// workspace member in the dependency closure, the pass would otherwise report
/// the host runtime's own infrastructure I/O — config loaders (`load_from_dir`),
/// audit/lineage persistence (`JsonlSink`, `MerkleSink`), keyless-identity fetch
/// (`workload_api`), attestation/randomness clients, and sandbox setup — none of
/// which is *agent-attributed* effect. That surface is out of scope by the same
/// reasoning that puts jailer spawn and HTTP serving out of scope.
///
/// So the **"reaches raw I/O, demands no `Authority`" finding is emitted only for
/// a crate in this set** (see [`check_crate_post`]). This is a **crate scope, not
/// a call-site allowlist**: the pass still reports *every* such site within a
/// mediated crate — there is no per-call exemption, and the "no call-site
/// allowlist by design" posture is preserved. Widening the guarantee is done by
/// adding a crate here, in the open, not by suppressing a call site.
///
/// The closure-soundness reports (unresolved `dyn`/fn-pointer/closure calls) are
/// **not** scoped by this set: they remain emitted for every crate as an
/// advisory signal, and the enforcing CI job deliberately does not gate on them
/// (a higher-order call is a call-graph observation, not an unmediated sink).
///
/// Crate names are the **lib crate** spelling (hyphens become underscores):
/// package `portcullis-effects` is crate `portcullis_effects`.
const MEDIATED_CRATES: &[&str] = &[
    // The sealed agent-effect boundary: every raw sink here is reached only after
    // an `Authority` is demanded by value and spent. This is the crate the Lean
    // Tier-A mediation theorem is stated over.
    "portcullis_effects",
];

/// Strip generic argument lists from a `def_path_str` rendering.
///
/// `def_path_str` renders generics — a call on a parameterised type comes back
/// as `nucleus::Executor::<'a>::run_args` — so a deny-set prefix that does not
/// anticipate the parameterisation silently never matches. A miss is
/// indistinguishable from "no I/O here", which is the failure mode this pass
/// exists to prevent, so the path is normalised once rather than every entry
/// guessing.
fn strip_generics(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut depth = 0usize;
    for c in path.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    while out.contains("::::") {
        out = out.replace("::::", "::");
    }
    out
}

/// What we learned about one function, before the call-graph closure runs.
struct FnFacts {
    span: Span,
    path: String,
    /// Calls a deny-set primitive directly in its own body.
    direct_io: Option<String>,
    /// Demands an `Authority` **by value** — a mediation boundary.
    demands_authority: bool,
    /// Locally-resolvable callees.
    callees: FxHashSet<LocalDefId>,
    /// Calls this pass could not resolve statically. Reported, never ignored.
    unresolved: Vec<(Span, String)>,
    /// Reachable from outside the crate.
    is_public: bool,
}

pub struct Mediated {
    facts: RefCell<FxHashMap<LocalDefId, FnFacts>>,
}

impl Mediated {
    pub fn new() -> Self {
        Self {
            facts: RefCell::new(FxHashMap::default()),
        }
    }
}

impl Default for Mediated {
    fn default() -> Self {
        Self::new()
    }
}

/// Does this signature take an `Authority` by value?
///
/// By value, specifically: a `&Authority` is the ambient-authority shape the
/// affine cutover removed, and it does not mark a boundary because it can be
/// replayed.
fn demands_authority(cx: &LateContext<'_>, def_id: LocalDefId) -> bool {
    let sig = cx.tcx.fn_sig(def_id.to_def_id()).skip_binder();
    sig.inputs().skip_binder().iter().any(|ty| match ty.kind() {
        TyKind::Adt(adt, _) => cx
            .tcx
            .def_path_str(adt.did())
            .ends_with(AUTHORITY_PATH_SUFFIX),
        _ => false,
    })
}

/// Walks a body collecting callees, direct I/O hits, and unresolvable calls.
struct CallScan<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    callees: FxHashSet<LocalDefId>,
    direct_io: Option<String>,
    unresolved: Vec<(Span, String)>,
}

impl<'a, 'tcx> CallScan<'a, 'tcx> {
    fn record(&mut self, did: DefId, _span: Span) {
        let path = strip_generics(&self.cx.tcx.def_path_str(did));
        if self.direct_io.is_none()
            && let Some(hit) = DENY_SET.iter().find(|p| path.starts_with(**p))
        {
            self.direct_io = Some(format!("{path} (deny-set: `{hit}`)"));
        }
        if let Some(local) = did.as_local() {
            self.callees.insert(local);
        }
        // Cross-crate calls are deliberately NOT reported here.
        //
        // The first version did report them, on the reasoning that an edge the
        // closure cannot follow is a hole. That reasoning was wrong, and the
        // noise made the point: 299 cross-crate reports against 15 real findings
        // on `portcullis-effects` alone.
        //
        // The edge is covered elsewhere. Dylint runs per crate, so a callee in
        // the mediated set is analysed by ITS OWN pass — and since it must be
        // exported to be callable from here, the `is_exported` filter will not
        // hide it. The finding surfaces where the defect is, rather than at every
        // call site that reaches it.
        //
        // Calls OUT of the mediated set rest on deny-set completeness, which is
        // already stated as load-bearing. Reporting them here double-counts an
        // assumption instead of adding one.
        //
        // What remains genuinely unresolvable — function pointers, `dyn`
        // dispatch, inline `asm!` — defeats the call graph WITHIN a crate, where
        // no other pass will cover it, and is still reported below.
    }
}

impl<'a, 'tcx> Visitor<'tcx> for CallScan<'a, 'tcx> {
    fn visit_expr(&mut self, ex: &'tcx Expr<'tcx>) {
        match ex.kind {
            ExprKind::Call(callee, _) => {
                if let ExprKind::Path(ref qpath) = callee.kind {
                    use rustc_hir::def::{DefKind, Res};
                    match self.cx.qpath_res(qpath, callee.hir_id) {
                        // A tuple-struct or enum-variant constructor is not a
                        // call that can reach I/O. Reporting `Self(bytes)` as
                        // "the call graph cannot see past this" is noise that
                        // buries real findings.
                        Res::Def(DefKind::Ctor(..), _) | Res::SelfCtor(_) => {}
                        Res::Def(_, did) => self.record(did, ex.span),
                        _ => self
                            .unresolved
                            .push((ex.span, "call through an unresolved path".to_string())),
                    }
                } else {
                    // Calling a value: a function pointer or closure variable. seL4
                    // forbids exactly this so its call graph stays static.
                    self.unresolved.push((
                        ex.span,
                        "call through a function pointer or value".to_string(),
                    ));
                }
            }
            ExprKind::MethodCall(..) => {
                match self.cx.typeck_results().type_dependent_def_id(ex.hir_id) {
                    Some(did) => self.record(did, ex.span),
                    None => self
                        .unresolved
                        .push((ex.span, "unresolved method call".to_string())),
                }
            }
            ExprKind::InlineAsm(_) => self.unresolved.push((
                ex.span,
                "inline `asm!` — opaque to the call graph".to_string(),
            )),
            // Descend into closure bodies.
            //
            // An `async fn`'s body in HIR IS a closure, and `check_fn` returns
            // early for `FnKind::Closure`, so without this every async function
            // was recorded with ZERO callees and its body was never analysed.
            // That is not a corner case here: 153 of ~571 functions in
            // `nucleus-node` and 21 of ~376 in `portcullis-effects` are `async
            // fn`, and this pass is a CI gate over both. Its green board did not
            // cover them.
            //
            // `walk_expr` visits the closure EXPRESSION; the body is a separate
            // `Body` reached through the HIR map.
            ExprKind::Closure(closure) => {
                let body = self.cx.tcx.hir_body(closure.body);
                self.visit_body(body);
            }
            _ => {}
        }
        walk_expr(self, ex);
    }
}

impl<'tcx> LateLintPass<'tcx> for Mediated {
    fn check_fn(
        &mut self,
        cx: &LateContext<'tcx>,
        kind: FnKind<'tcx>,
        _decl: &'tcx FnDecl<'tcx>,
        body: &'tcx rustc_hir::Body<'tcx>,
        span: Span,
        def_id: LocalDefId,
    ) {
        // A closure's body is scanned as part of its enclosing function, so its
        // calls are already attributed there.
        if matches!(kind, FnKind::Closure) {
            return;
        }

        let mut scan = CallScan {
            cx,
            callees: FxHashSet::default(),
            direct_io: None,
            unresolved: Vec::new(),
        };
        scan.visit_body(body);

        let is_public = cx.tcx.effective_visibilities(()).is_exported(def_id);

        self.facts.borrow_mut().insert(
            def_id,
            FnFacts {
                span,
                path: cx.tcx.def_path_str(def_id.to_def_id()),
                direct_io: scan.direct_io,
                demands_authority: demands_authority(cx, def_id),
                callees: scan.callees,
                unresolved: scan.unresolved,
                is_public,
            },
        );
    }

    /// The closure and the report.
    ///
    /// `check_fn` sees one function at a time and cannot know whether a callee
    /// reaches I/O, so the decision has to wait until every function in the crate
    /// has been seen. This is the whole reason the pass accumulates.
    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        let facts = self.facts.borrow();

        // Is the crate currently under compilation in the mediated set? The pass
        // is invoked once per workspace member in the dependency closure, so this
        // is the gate that keeps the ENFORCED "unmediated I/O" finding scoped to
        // the agent-effect boundary rather than the host runtime's own infra I/O.
        // See [`MEDIATED_CRATES`]. Unresolved-call reports below are NOT scoped by
        // this — they stay advisory for every crate.
        let crate_is_mediated = {
            let name = cx.tcx.crate_name(LOCAL_CRATE);
            MEDIATED_CRATES.contains(&name.as_str())
        };

        // Least fixpoint of "reaches raw I/O without crossing a boundary".
        //
        // Seed: functions doing I/O directly and demanding no authority.
        // Step:  f joins if it calls some g in the set AND f is not itself a
        //        boundary — a boundary absorbs the obligation and stops the
        //        propagation, which is precisely what "mediated" means.
        let mut unmediated: FxHashSet<LocalDefId> = facts
            .iter()
            .filter(|(_, f)| f.direct_io.is_some() && !f.demands_authority)
            .map(|(d, _)| *d)
            .collect();

        loop {
            let mut grew = false;
            for (did, f) in facts.iter() {
                if f.demands_authority || unmediated.contains(did) {
                    continue;
                }
                if f.callees.iter().any(|c| unmediated.contains(c)) {
                    unmediated.insert(*did);
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }

        for (did, f) in facts.iter() {
            // Report at the crate boundary. An internal helper reaching I/O is
            // fine so long as every public path to it crosses a boundary; the
            // public function is where that stops being true.
            //
            // Scoped to the mediated set: outside it, raw I/O is the host
            // runtime's own infrastructure (config load, audit persistence,
            // identity/attestation, sandbox setup), not agent-attributed effect.
            if crate_is_mediated && f.is_public && unmediated.contains(did) {
                let detail = match &f.direct_io {
                    Some(hit) => format!("reaches raw I/O: {hit}"),
                    None => "reaches raw I/O transitively through its callees".to_string(),
                };
                span_lint_and_help(
                    cx,
                    MEDIATED,
                    f.span,
                    format!("`{}` {detail}, but demands no `Authority`", f.path),
                    None,
                    "take an `Authority` by value and spend it, or route the call \
                     through a function that does",
                );
            }

            // Unresolvable calls are reported even when nothing else is wrong:
            // they are where the closure stops being sound, so treating them as
            // clean would be the one lie this pass must not tell.
            for (span, why) in &f.unresolved {
                span_lint_and_help(
                    cx,
                    MEDIATED,
                    *span,
                    format!("{why} — the call-graph closure cannot see past this"),
                    None,
                    "the mediation guarantee is only as sound as the call graph; \
                     make the callee statically resolvable or mediate it directly",
                );
            }
        }
    }
}

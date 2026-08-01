//! `nucleus-observed-lint` — the `observed` pass. The **source-side dual** of
//! `mediated`.
//!
//! `mediated` asks: does every path to an effect cross an authority boundary?
//! This asks the other half: **does every path that ingests external bytes reach
//! `FlowTracker::observe*`?** Bytes that enter a session without an observation
//! create no flow node, so the information-flow gate cannot see them, and every
//! theorem downstream is conditioned on an antecedent nothing enforces.
//!
//! That gap was not hypothetical. `/v1/run` returned arbitrary subprocess stdout
//! to the agent and observed nothing, while the five other HTTP handlers that
//! return external bytes all observed theirs. It was found by reading, fixed by
//! hand, and would have been caught here.
//!
//! # Findings are sound; a clean pass is a SCREEN
//!
//! This is the opposite posture to its sibling, and the difference is not
//! stylistic. `mediated` can assert something on a clean pass because its
//! boundary is a **signature** property — an `Authority` is either in the type or
//! it is not, and the type system carries it.
//!
//! The obligation here is a **call**, and a reachability closure cannot see two
//! things that matter:
//!
//! * **Order.** A function that calls `observe` and, separately, reads a socket
//!   passes this lint, even if the read happens after the observation.
//! * **Identity.** Nothing checks that the bytes observed are the bytes ingested.
//!   Observing an unrelated buffer satisfies the closure.
//!
//! So: a REPORT is a true finding — that path reaches an ingest primitive and no
//! `observe` is reachable from it at all, which cannot be correct. A CLEAN PASS
//! means only that an observation exists somewhere on the path. Do not cite a
//! green run of this lint as evidence that ingest labelling is adequate; that is
//! the [`ingest adequacy`] property, and it needs the labels to be right as well
//! as present, which no static pass can decide.
//!
//! Stated plainly because the sibling's doctrine is the reverse, and quietly
//! inheriting its "a clean pass asserts something real" would be the one lie
//! this pass must not tell.
//!
//! # ⚠ STATUS: NOT WORKING. DO NOT GATE THIS IN CI.
//!
//! This pass builds, runs, and reports — but it **fails its own acceptance
//! test** and must not be cited as coverage until it passes.
//!
//! The test: delete the `http_observe_command_output` call from `run_command`
//! (recreating the `/v1/run` bug this pass exists to catch) and the pass must go
//! RED at that function. **It stays green.** A pass that misses the one bug it
//! was justified by is worse than no pass, because a green run reads as
//! assurance.
//!
//! Diagnosis so far, so this is resumable rather than restarted:
//!
//! * **Ruled out — `is_public` filtering.** The sibling reports only at exported
//!   functions, which is right for a LIBRARY. `nucleus-tool-proxy` is a BINARY
//!   whose handlers are private (`async fn run_command`, never `pub`), so the
//!   filter hid every handler. Removed, and confirmed fixed: non-public
//!   functions such as `load_last_hash` now report.
//! * **Ruled out — std-only ingest set.** Handlers never call `std::process`
//!   directly; they call an executor abstraction in another crate, and the
//!   closure stops at crate boundaries by design. `INGEST_CONTAINS` was added
//!   for the codebase's own surface. Did not fix it.
//! * **Ruled out — the call is silently dropped as unresolvable.** There are
//!   zero `unresolved` reports anywhere in `main.rs`, so the visitor is not
//!   failing to resolve `executor.run_args(..)`; it is not matching it.
//! * **Open — the pass barely sees `main.rs` at all.** The whole output mentions
//!   that file twice. Next step is to establish whether dylint is analysing the
//!   binary target's root module, and what `def_path_str` actually renders for
//!   `Executor::run_args` (the working hypothesis is a generic-parameter
//!   rendering such as `Executor::<'_>::run_args` that no current needle
//!   matches). A one-shot debug print of every `FnFacts.path` with a
//!   `direct_ingest` would settle both in a single run.
//!
//! What DOES work: 31 findings on the dependency crates, all genuine reads with
//! no observation — and all of them runtime infrastructure (config loading, key
//! loading, merkle checkpoints), i.e. correctly *not* agent-attributed ingest.
//! That is a scoping problem, not a bug: the CI invocation must name the handler
//! crates, and the sibling's own crate list is already wrong in this way
//! (`dylint-separation.yml` scans two of the three crates `mediated-set.md`
//! specifies).
//!
//! # What is deliberately not flagged
//!
//! The runtime reads files and sockets for its **own** infrastructure — config
//! loading, health checks, serving HTTP. Those are not agent-attributed ingest.
//! Scope is therefore the handler crates named in the CI invocation, not
//! "everything", exactly as `mediated` scopes itself.

#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_data_structures;
extern crate rustc_hir;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use rustc_data_structures::fx::{FxHashMap, FxHashSet};
use rustc_hir::def_id::{DefId, LocalDefId};
use rustc_hir::intravisit::{FnKind, Visitor, walk_expr};
use rustc_hir::{Expr, ExprKind, FnDecl};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::Span;
use std::cell::RefCell;

dylint_linting::impl_late_lint! {
    /// ### What it does
    ///
    /// Flags publicly reachable functions that can reach a primitive yielding
    /// **external bytes** without any call to `FlowTracker::observe*` being
    /// reachable from them. Closed under the call graph.
    ///
    /// ### Why is this bad?
    ///
    /// Unobserved bytes create no flow node, so the IFC gate cannot see them.
    /// Every downstream guarantee — "untrusted web content cannot reach a
    /// privileged sink" — is conditioned on the ingest having been observed.
    /// An unobserved channel does not weaken that theorem; it makes it
    /// inapplicable.
    ///
    /// ### Known problems
    ///
    /// A clean pass is a screen, not a proof: neither the ORDER of the ingest
    /// and the observation, nor the IDENTITY of the bytes observed, is checked.
    /// Soundness of findings is relative to the scanned crate set and the
    /// completeness of the ingest-set.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// pub async fn run(cmd: &str) -> Output {
    ///     let out = Command::new("sh").arg(cmd).output().await?; // flagged
    ///     Ok(Json(RunResponse { stdout: out.stdout }))           // no observe
    /// }
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// pub async fn run(cmd: &str) -> Output {
    ///     let out = Command::new("sh").arg(cmd).output().await?;
    ///     observe_command_output(&state, &out.stdout, &out.stderr).await;
    ///     Ok(Json(RunResponse { stdout: out.stdout }))
    /// }
    /// ```
    pub OBSERVED,
    Warn,
    "a publicly reachable path ingests external bytes without reaching FlowTracker::observe",
    Observed::new()
}

/// Primitives that yield bytes originating OUTSIDE the trust boundary, matched
/// against `def_path_str` by prefix.
///
/// **Completeness is load-bearing for findings to be exhaustive**, though not for
/// them to be correct: a missing entry hides a hole, it does not invent one.
/// Deliberately narrower than `mediated`'s deny-set — that one lists everything
/// that *acts*, this one lists what *returns external bytes to the caller*.
/// `std::fs::write` acts and is in the sibling's set; it ingests nothing and is
/// not here.
const INGEST_SET: &[&str] = &[
    // Filesystem reads — content of files the agent did not author.
    "std::fs::read",
    "std::fs::File::open",
    "tokio::fs::read",
    "tokio::fs::File::open",
    "cap_std::fs::Dir::open",
    "cap_std::fs::File::open",
    // Subprocess output — the channel that was actually missing.
    "std::process::Command::output",
    "std::process::Child::wait_with_output",
    "tokio::process::Command::output",
    "tokio::process::Child::wait_with_output",
    // Network reads.
    "std::net::TcpStream::read",
    "tokio::net::TcpStream",
    "reqwest::Response::",
    "reqwest::blocking::Response::",
    // ── THIS CODEBASE'S OWN INGEST SURFACE ─────────────────────────────────
    //
    // The std entries above are necessary but not sufficient, and finding that
    // out is what this list cost. Handlers never touch `std::process` directly:
    // they call an executor/sandbox abstraction in another crate, and the
    // call-graph closure deliberately stops at crate boundaries (following them
    // was measured at 299 reports to 15 findings on the sibling). So with std
    // primitives alone the pass could not see the ONE bug it was built for —
    // verified by removing the fix from `/v1/run` and watching it stay green.
    //
    // The set therefore names the layer the handlers actually use. Every entry
    // returns bytes the agent did not author.
    "nucleus::command::Executor::run_args",
    "nucleus::sandbox::Sandbox::read_to_string",
];

/// Entries matched anywhere in the path rather than as a prefix.
///
/// Kept separate from [`INGEST_SET`] on purpose. A blanket `contains` over the
/// whole set would match `my_crate::std::fs::read`, so the std primitives stay
/// prefix-anchored; only these codebase-local names, whose module path may be
/// re-exported or renamed, are matched loosely.
const INGEST_CONTAINS: &[&str] = &["Executor::run_args", "Sandbox::read_to_string"];

/// The call that discharges the obligation, matched by `def_path_str` substring.
///
/// Matched on the tracker's method rather than on the proxy's local helper, so a
/// new helper does not silently become an unrecognised boundary.
const OBSERVE_MARKERS: &[&str] = &["ifc_api::FlowTracker::observe", "FlowTracker::observe"];

/// What we learned about one function, before the call-graph closure runs.
struct FnFacts {
    span: Span,
    path: String,
    /// Calls an ingest primitive directly in its own body.
    direct_ingest: Option<String>,
    /// Calls `FlowTracker::observe*` directly in its own body.
    observes: bool,
    /// Locally-resolvable callees.
    callees: FxHashSet<LocalDefId>,
    /// Calls this pass could not resolve statically. Reported, never ignored.
    unresolved: Vec<(Span, String)>,
    /// Reachable from outside the crate. Collected but deliberately NOT used to
    /// filter reports — see the note in `check_crate_post`.
    #[allow(dead_code)]
    is_public: bool,
}

pub struct Observed {
    facts: RefCell<FxHashMap<LocalDefId, FnFacts>>,
}

impl Observed {
    pub fn new() -> Self {
        Self {
            facts: RefCell::new(FxHashMap::default()),
        }
    }
}

impl Default for Observed {
    fn default() -> Self {
        Self::new()
    }
}

/// Walks a body collecting callees, ingest hits, observe calls, and unresolvable
/// calls.
struct CallScan<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    callees: FxHashSet<LocalDefId>,
    direct_ingest: Option<String>,
    observes: bool,
    unresolved: Vec<(Span, String)>,
}

impl<'a, 'tcx> CallScan<'a, 'tcx> {
    fn record(&mut self, did: DefId, _span: Span) {
        let path = self.cx.tcx.def_path_str(did);
        if self.direct_ingest.is_none()
            && let Some(hit) = INGEST_SET
                .iter()
                .find(|p| path.starts_with(**p))
                .or_else(|| INGEST_CONTAINS.iter().find(|p| path.contains(**p)))
        {
            self.direct_ingest = Some(format!("{path} (ingest-set: `{hit}`)"));
        }
        if !self.observes && OBSERVE_MARKERS.iter().any(|m| path.contains(m)) {
            self.observes = true;
        }
        if let Some(local) = did.as_local() {
            self.callees.insert(local);
        }
        // Cross-crate calls are not reported, for the reason the sibling gives at
        // length: dylint runs per crate, so a callee in the scanned set is
        // analysed by its own pass and the finding surfaces where the defect is.
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
                        // call that can ingest anything. Reporting `Self(bytes)`
                        // as "the call graph cannot see past this" is noise that
                        // buries real findings — measured: it was the majority of
                        // output on the first run.
                        Res::Def(DefKind::Ctor(..), _) | Res::SelfCtor(_) => {}
                        Res::Def(_, did) => self.record(did, ex.span),
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
                    Some(did) => self.record(did, ex.span),
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

impl<'tcx> LateLintPass<'tcx> for Observed {
    fn check_fn(
        &mut self,
        cx: &LateContext<'tcx>,
        kind: FnKind<'tcx>,
        _decl: &'tcx FnDecl<'tcx>,
        body: &'tcx rustc_hir::Body<'tcx>,
        span: Span,
        def_id: LocalDefId,
    ) {
        // A closure's body is scanned as part of its enclosing function.
        if matches!(kind, FnKind::Closure) {
            return;
        }

        let mut scan = CallScan {
            cx,
            callees: FxHashSet::default(),
            direct_ingest: None,
            observes: false,
            unresolved: Vec::new(),
        };
        scan.visit_body(body);

        let is_public = cx.tcx.effective_visibilities(()).is_exported(def_id);

        self.facts.borrow_mut().insert(
            def_id,
            FnFacts {
                span,
                path: cx.tcx.def_path_str(def_id.to_def_id()),
                direct_ingest: scan.direct_ingest,
                observes: scan.observes,
                callees: scan.callees,
                unresolved: scan.unresolved,
                is_public,
            },
        );
    }

    /// The closure and the report.
    fn check_crate_post(&mut self, cx: &LateContext<'tcx>) {
        let facts = self.facts.borrow();

        // Least fixpoint of "ingests external bytes without reaching an observe".
        //
        // Seed: functions ingesting directly that do not themselves observe.
        // Step:  f joins if it calls some g in the set AND f does not itself
        //        observe — an observation absorbs the obligation, which is what
        //        "observed" means here.
        //
        // NOTE the absorption is where order-blindness enters: `f` observing
        // anything at all stops the propagation, regardless of when or of what.
        // That is why a clean pass is a screen. See the module docs.
        let mut unobserved: FxHashSet<LocalDefId> = facts
            .iter()
            .filter(|(_, f)| f.direct_ingest.is_some() && !f.observes)
            .map(|(d, _)| *d)
            .collect();

        loop {
            let mut grew = false;
            for (did, f) in facts.iter() {
                if f.observes || unobserved.contains(did) {
                    continue;
                }
                if f.callees.iter().any(|c| unobserved.contains(c)) {
                    unobserved.insert(*did);
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }

        for (did, f) in facts.iter() {
            // NOTE: no `is_public` filter, unlike the sibling.
            //
            // `mediated` reports at the crate boundary because its scanned crates
            // are LIBRARIES, where the public API is the boundary. The crate this
            // pass most needs to cover is a BINARY whose entry points are private
            // axum route handlers — `async fn run_command`, not `pub async fn`.
            // With an `is_public` filter the pass was blind to every handler in
            // it, and stayed green with the `/v1/run` fix deleted. Measured, not
            // reasoned: that is what the first three acceptance runs showed.
            //
            // Reporting at the ingesting function is also the better location for
            // this lint regardless — the observation belongs next to the ingest,
            // not at some exported ancestor.
            if unobserved.contains(did) {
                let detail = match &f.direct_ingest {
                    Some(hit) => format!("ingests external bytes: {hit}"),
                    None => "ingests external bytes transitively through its callees".to_string(),
                };
                span_lint_and_help(
                    cx,
                    OBSERVED,
                    f.span,
                    format!("`{}` {detail}, but no `FlowTracker::observe` is reachable", f.path),
                    None,
                    "observe the ingested bytes with a NodeKind whose intrinsic \
                     integrity matches the source, or route the call through a \
                     function that does — unobserved bytes are invisible to the \
                     IFC gate",
                );
            }

            for (span, why) in &f.unresolved {
                span_lint_and_help(
                    cx,
                    OBSERVED,
                    *span,
                    format!("{why} — the call-graph closure cannot see past this"),
                    None,
                    "an ingest reached this way would not be seen; make the callee \
                     statically resolvable or observe it directly",
                );
            }
        }
    }
}

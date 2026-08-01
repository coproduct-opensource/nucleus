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
//! # Acceptance test, and the four bugs it took to pass it
//!
//! The test: delete the `http_observe_command_output` call from `run_command`,
//! recreating the `/v1/run` bug this pass exists to catch, and it must go RED
//! there. It does, naming the function and the ingest primitive; with the call
//! restored, zero handlers are flagged.
//!
//! Getting there took four fixes, each of which made the pass report GREEN while
//! being blind — worth recording because three of them apply to any lint of this
//! shape, and two apply to the sibling as it stands:
//!
//! 1. **`async fn` bodies are closures and were never walked.** `check_fn`
//!    returns early for `FnKind::Closure`, and `walk_expr` visits a closure
//!    EXPRESSION without its body. Every handler in this codebase is `async fn`,
//!    so the pass recorded them with **zero callees** — measured — and could not
//!    see a single line of the code it targets, while sync helpers reported
//!    normally and made it look healthy. Fixed by descending through
//!    `ExprKind::Closure` into `tcx.hir_body`.
//! 2. **`def_path_str` renders generics.** The executor call comes back as
//!    `nucleus::Executor::<'a>::run_args`, so a needle of `Executor::run_args`
//!    silently never matches — and a miss is indistinguishable from "no ingest
//!    here". Fixed by normalising generics out of the path before matching
//!    rather than making needles anticipate parameterisation.
//! 3. **The obligation is transitive.** `read_file` calls `http_observe_flow`,
//!    which calls the tracker. Direct-only absorption reported it as unobserved
//!    — a false positive on a handler doing exactly the right thing. `observes`
//!    is now closed under the call graph, like the ingest side.
//! 4. **`is_public` filtering.** The sibling reports only at exported functions,
//!    correct for a LIBRARY. This target is a BINARY whose handlers are private
//!    (`async fn run_command`, never `pub`), so the filter hid all of them.
//!
//! **Bugs 1 and 2 are present in `nucleus-mediation-lint` today**, which is a
//! CI gate. It skips closures and has no `ExprKind::Closure` handling at all, so
//! it cannot see any `async fn` body: 153 of ~571 functions in `nucleus-node`
//! and 21 of ~376 in `portcullis-effects` are invisible to it. Its green board
//! is not evidence over that code. Fixing it is a separate change.
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

/// Strip generic argument lists from a `def_path_str` rendering.
///
/// `def_path_str` renders generics: the executor call comes back as
/// `nucleus::Executor::<'a>::run_args`, so a needle of `Executor::run_args`
/// never matches. Rather than make every needle anticipate how a type is
/// parameterised — which silently fails open, since a miss looks identical to
/// "no ingest here" — the path is normalised once before matching.
///
/// Diagnosed by dumping callee paths after the pass reported `ingest=None` on a
/// handler that plainly ingests.
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
    // `A::<'a>::b` leaves `A::::b`.
    while out.contains("::::") {
        out = out.replace("::::", "::");
    }
    out
}

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
        let path = strip_generics(&self.cx.tcx.def_path_str(did));
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
            // Descend into closure bodies.
            //
            // THIS IS WHY THE PASS SAW NOTHING. An `async fn`'s body in HIR is a
            // closure, and `check_fn` returns early for `FnKind::Closure`, so
            // every async function was recorded with ZERO callees — measured:
            // `run_command`, `read_file` and `web_fetch` all showed
            // `ingest=None observes=false callees=0`, which is impossible for a
            // 200-line handler. Every handler in this codebase is `async fn`, so
            // the pass was structurally blind to exactly the code it targets,
            // while sync helpers like `load_last_hash` reported normally and made
            // it look like it was working.
            //
            // `walk_expr` visits the closure EXPRESSION but not its body, which
            // is a separate `Body` reached through the HIR map.
            ExprKind::Closure(closure) => {
                let body = self.cx.tcx.hir_body(closure.body);
                self.visit_body(body);
            }
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
        // `observes` is a DIRECT fact; the obligation is discharged transitively.
        // `read_file` calls `http_observe_flow`, which calls the tracker — so
        // direct-only absorption reported it as unobserved, a false positive on
        // a handler that does exactly the right thing.
        let mut reaches_observe: FxHashSet<LocalDefId> = facts
            .iter()
            .filter(|(_, f)| f.observes)
            .map(|(d, _)| *d)
            .collect();
        loop {
            let mut grew = false;
            for (did, f) in facts.iter() {
                if reaches_observe.contains(did) {
                    continue;
                }
                if f.callees.iter().any(|c| reaches_observe.contains(c)) {
                    reaches_observe.insert(*did);
                    grew = true;
                }
            }
            if !grew {
                break;
            }
        }

        let mut unobserved: FxHashSet<LocalDefId> = facts
            .iter()
            .filter(|(d, f)| f.direct_ingest.is_some() && !reaches_observe.contains(d))
            .map(|(d, _)| *d)
            .collect();

        loop {
            let mut grew = false;
            for (did, f) in facts.iter() {
                if reaches_observe.contains(did) || unobserved.contains(did) {
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

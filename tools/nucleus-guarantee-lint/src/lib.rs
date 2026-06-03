#![feature(rustc_private)]
#![warn(unused_extern_crates)]

//! # `aeneas_eligible` — an Aeneas-extraction *screen*
//!
//! ## HONESTY (read this first)
//!
//! This lint computes a **necessary condition** — a *screen* — for whether a Rust
//! function *could* be eligible for [Aeneas](https://github.com/AeneasVerif/aeneas)
//! extraction into a pure functional model (Lean/F*/Coq/HOL4). It is **NOT**:
//!
//! * a proof that the function *is* extractable;
//! * a proof that the extracted model is *correct*;
//! * a guarantee of anything.
//!
//! A function that passes this screen may still fail Aeneas's borrow-checked
//! symbolic interpreter (e.g. AeneasVerif/aeneas#802, "borrow checking error on
//! valid Rust code"). The screen only ever asserts **ineligibility** on a hit; a
//! clean pass asserts nothing. Aeneas is alpha software and its supported subset is
//! a moving target, so this screen is deliberately biased toward DENY when uncertain
//! (Research Report 3, "Caveats on the screen itself").
//!
//! ## What it screens for (the deny-set)
//!
//! Per the Aeneas/Charon subset analysis (Research Report 3), a function is flagged
//! ineligible if its body or signature contains ANY of:
//!
//! * `unsafe` fn or any user-written `unsafe { }` block  (aeneas#743)
//! * `async` fn or an `async { }` block / `.await`        (charon#609 — unsupported even at the Charon lowering layer)
//! * a closure                                            (aeneas#924 — default-deny, fragile)
//! * `dyn Trait` anywhere in the signature                (no functional model for dynamic dispatch)
//! * a raw pointer `*const T` / `*mut T` in the signature (aeneas#743 — borrows-only model)
//! * a call to an FFI / `extern` foreign item             (charon limitations.md — opaque bodies)
//! * inline assembly (`asm!`)                             (no functional model)
//!
//! NOTE: this scaffold screens the constructs that are decidable at the HIR level with
//! high confidence. Several deny-set rows from Research 3 (floats, nested loops /
//! break-to-outer-label / return-in-loop, non-`Vec` std collections, iterator-combinator
//! chains) are intentionally NOT yet implemented here — see the `// TODO(deny-set)`
//! markers below. They are flagged for the verifier rather than implemented half-heartedly.

// A list of available compiler crates: https://doc.rust-lang.org/nightly/nightly-rustc/
// NOTE: `TraitObjectSyntax` lives in `rustc_ast` (re-exported into HIR usage), so
// `rustc_ast` IS load-bearing here despite the "unused extern crate" lint's first guess.
extern crate rustc_ast;
extern crate rustc_hir;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use clippy_utils::fn_def_id;
use rustc_ast::TraitObjectSyntax;
// `visit_ty_unambig` is provided by the `VisitorExt` extension trait, not `Visitor`
// itself (Research 2 drift point: the AmbigArg split). It must be in scope to call it.
use rustc_hir::intravisit::{FnKind, Visitor, VisitorExt, walk_expr, walk_ty};
use rustc_hir::{
    AmbigArg, BlockCheckMode, ClosureKind, CoroutineDesugaring, CoroutineKind, Expr, ExprKind,
    FnDecl, Safety, Ty, TyKind, UnsafeSource,
};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::Span;
use rustc_span::def_id::LocalDefId;

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Screens each function for constructs that make it **ineligible** for
    /// [Aeneas](https://github.com/AeneasVerif/aeneas) extraction into a pure
    /// functional model. This is a *necessary condition* (a screen), **not** a proof
    /// of extractability or correctness — see the crate-level docs.
    ///
    /// ### Why is this bad?
    ///
    /// If a function is meant to be verified via the Charon → Aeneas pipeline, using
    /// an out-of-subset construct (`unsafe`, `async`, closures, `dyn`, raw pointers,
    /// FFI, inline asm) silently removes it from the verifiable surface. Flagging it
    /// at lint time keeps the "verifiable" claim honest.
    ///
    /// ### Known problems
    ///
    /// The screen is a NECESSARY, not SUFFICIENT, condition. A clean pass does not
    /// imply the function actually extracts (Aeneas may still reject valid Rust).
    /// Several deny-set rows are not yet implemented (floats, nested-loop control
    /// flow, non-`Vec` collections, iterator combinators) — see `TODO(deny-set)`.
    ///
    /// ### Example
    ///
    /// ```rust
    /// async fn f() {} // flagged: `async`
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust
    /// fn add(a: u64, b: u64) -> u64 { a + b } // passes the screen
    /// ```
    pub AENEAS_ELIGIBLE,
    Warn,
    "function uses a construct outside the Aeneas-extractable subset (screen, not a proof)"
}

impl<'tcx> LateLintPass<'tcx> for AeneasEligible {
    // `check_fn` is the per-function unit (Research Report 2, "Hooks to register").
    // It fires for free fns, methods, AND closures (FnKind::Closure). We handle the
    // closure case via the body visitor on the *enclosing* fn, so here we only act on
    // ItemFn/Method to avoid double-reporting; a closure seen as its own check_fn is
    // skipped because the enclosing fn already reported "closure".
    fn check_fn(
        &mut self,
        cx: &LateContext<'tcx>,
        kind: FnKind<'tcx>,
        decl: &'tcx FnDecl<'tcx>,
        body: &'tcx rustc_hir::Body<'tcx>,
        span: Span,
        _def_id: LocalDefId,
    ) {
        // Skip closures-as-fn (the enclosing fn's visitor reports them).
        if matches!(kind, FnKind::Closure) {
            return;
        }

        // --- (a) signature unsafety -------------------------------------------------
        // FnHeader.safety is HeaderSafety post-refactor; prefer header.is_unsafe(),
        // which correctly treats SafeTargetFeatures as NOT unsafe (Research 2, §a).
        if let Some(header) = kind.header()
            && header.is_unsafe()
        {
            report(cx, span, "an `unsafe` function signature");
            // keep scanning the body for additional, more specific hits
        }

        // --- (b) async fn -----------------------------------------------------------
        if let Some(header) = kind.header()
            && header.is_async()
        {
            report(cx, span, "an `async` function signature");
        }

        // --- (d) `dyn Trait` / (f) raw pointers in the SIGNATURE --------------------
        // Walk every Ty in inputs + output. We use a Ty-only visitor so we descend
        // into nested generic positions (e.g. `Box<dyn Trait>`, `&*const T`).
        for input in decl.inputs {
            check_signature_ty(cx, input);
        }
        if let rustc_hir::FnRetTy::Return(ret) = decl.output {
            check_signature_ty(cx, ret);
        }

        // --- body walk: (a) unsafe blocks, (b) async blocks, (c) closures,
        //                 (e) FFI calls, (f) inline asm ----------------------------
        let mut v = BodyScreen { cx };
        v.visit_body(body);
    }
}

/// Walk a single signature `Ty` for `dyn` and raw pointers (Research 2, §d, §f).
fn check_signature_ty<'tcx>(cx: &LateContext<'tcx>, ty: &'tcx Ty<'tcx>) {
    let mut v = SigTyScreen { cx };
    v.visit_ty_unambig(ty);
}

struct SigTyScreen<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
}

impl<'a, 'tcx> Visitor<'tcx> for SigTyScreen<'a, 'tcx> {
    fn visit_ty(&mut self, ty: &'tcx Ty<'tcx, AmbigArg>) {
        match ty.kind {
            // TyKind::TraitObject second field is now a TaggedRef<Lifetime,
            // TraitObjectSyntax> (Research 2, §d). We only report `dyn` syntax.
            TyKind::TraitObject(_bounds, tagged) => {
                // On nightly-2026-04-16, TraitObjectSyntax = { Dyn, None } (no DynStar;
                // Research 2 listed DynStar but it is absent on this pinned channel).
                if matches!(tagged.tag(), TraitObjectSyntax::Dyn) {
                    report(self.cx, ty.span, "a `dyn Trait` trait object in the signature");
                }
            }
            // Raw pointer: TyKind::Ptr(MutTy) — distinct from TyKind::Ref (Research 2, §f).
            TyKind::Ptr(_) => {
                report(self.cx, ty.span, "a raw pointer (`*const`/`*mut`) in the signature");
            }
            _ => {}
        }
        walk_ty(self, ty);
    }
}

struct BodyScreen<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
}

impl<'a, 'tcx> Visitor<'tcx> for BodyScreen<'a, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        match expr.kind {
            // (a) user-written unsafe block (exclude compiler-generated desugarings).
            ExprKind::Block(block, _) => {
                if matches!(
                    block.rules,
                    BlockCheckMode::UnsafeBlock(UnsafeSource::UserProvided)
                ) {
                    report(self.cx, expr.span, "a user-written `unsafe { }` block");
                }
            }
            // (b)/(c) closures share ExprKind::Closure; ClosureKind distinguishes
            // plain closures from async/gen-block desugarings (Research 2, §b, §c).
            ExprKind::Closure(closure) => match closure.kind {
                ClosureKind::Closure => {
                    report(self.cx, expr.span, "a closure");
                }
                ClosureKind::Coroutine(CoroutineKind::Desugared(
                    CoroutineDesugaring::Async,
                    _,
                )) => {
                    report(self.cx, expr.span, "an `async` block");
                }
                ClosureKind::CoroutineClosure(CoroutineDesugaring::Async) => {
                    report(self.cx, expr.span, "an `async` closure");
                }
                // Other coroutines (gen / async-gen) — default-deny as out-of-subset.
                _ => {
                    report(self.cx, expr.span, "a coroutine (gen/async block or closure)");
                }
            },
            // (f) inline assembly — no functional model (Research 2, §f).
            ExprKind::InlineAsm(_) => {
                report(self.cx, expr.span, "inline assembly (`asm!`)");
            }
            // (e) FFI / extern call: resolve callee DefId and test is_foreign_item.
            // fn_def_id covers both Call and MethodCall (Research 2, §e).
            ExprKind::Call(..) | ExprKind::MethodCall(..) => {
                if let Some(did) = fn_def_id(self.cx, expr)
                    && self.cx.tcx.is_foreign_item(did)
                {
                    report(self.cx, expr.span, "a call to an FFI / `extern` foreign item");
                }
            }
            _ => {}
        }
        // Recurse — for_each_expr-style descent INTO closures is intentional so the
        // enclosing fn owns the report for everything lexically inside it.
        walk_expr(self, expr);
    }
}

/// Resolve the genuine `unsafe fn` distinction without the helper, for reference:
/// `HeaderSafety::Normal(Safety::Unsafe)` is a real `unsafe fn`; `SafeTargetFeatures`
/// is type-system-unsafe but safety-check-safe and must NOT be flagged. We rely on
/// `header.is_unsafe()` above, which encodes exactly this. (Kept to document intent.)
#[allow(dead_code)]
fn is_genuine_unsafe(safety: Safety) -> bool {
    matches!(safety, Safety::Unsafe)
}

fn report(cx: &LateContext<'_>, span: Span, what: &str) {
    span_lint_and_help(
        cx,
        AENEAS_ELIGIBLE,
        span,
        format!("not Aeneas-extractable: this function contains {what}"),
        None,
        "this is a NECESSARY-CONDITION screen, not a proof of extractability or correctness; \
         rewrite within the Aeneas subset, or accept that this item is outside the verified surface",
    );
}

// ============================================================================
// TODO(guarantee-receipt): future-pass hook — SCREEN ONLY for now.
//
// This scaffold is the SCREEN. A future LateLintPass (or a post-build StableMIR
// pass) would, for each function that PASSES the screen, compute a stable digest
// and emit a *signed per-hash guarantee receipt*:
//
//     receipt = sign(
//         body_hash   = hash(StableMIR body  OR  rustfmt-normalized source),
//         toolchain   = "nightly-2026-04-16",          // from rust-toolchain.toml
//         profile     = <aeneas/charon commit + backend + flags>,
//         screen      = "aeneas_eligible@<this-crate-version>",
//     )
//
// The receipt must record that it certifies ONLY "passed the screen under <toolchain,
// profile>", NOT "is extractable" and NOT "is correct". Hashing options (Research 2,
// "Span + snippet for hashing"): SpanRangeExt::with_source_text for source hashing, or
// clippy_utils::hash_expr / SpanlessHash for a reformat-robust structural hash; prefer
// StableMIR for toolchain-stable semantics once that hook is wired.
// ============================================================================

// TODO(deny-set): the following Research-3 deny-set rows are NOT yet screened and are
// flagged for the verifier (do not assume a clean pass covers them):
//   * floats (f32/f64) anywhere                          (aeneas#828)
//   * nested loops / break-to-outer-label / return-in-loop (aeneas#964, #822)
//   * non-`Vec` std collections (HashMap/BTreeMap/…)     (charon limitations.md)
//   * iterator-combinator chains (.map/.filter/.collect) (aeneas#1053/#1043/#464)

// NOTE: the UI test entry point lives in `tests/ui.rs` (the dylint_testing harness),
// not here, to avoid running the same `ui/` snapshot twice. (Template normally puts
// `#[test] fn ui()` in lib.rs; we relocated it per the task's tests/ harness ask.)

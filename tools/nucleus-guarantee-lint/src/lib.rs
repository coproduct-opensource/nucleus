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

// The per-hash guarantee receipt (hash / canonicalize / sign / verify) lives in the PURE
// sibling crate `nucleus_guarantee_receipt` (NO rustc dependency — unit-testable without
// the compiler, and rlib/bin-buildable, which a rustc_private cdylib is NOT). See its
// docs for the honesty boundary (a receipt is a SCREEN result, NOT a proof).
use clippy_utils::diagnostics::span_lint_and_help;
use clippy_utils::fn_def_id;
use clippy_utils::source::snippet_opt;
use nucleus_guarantee_receipt::{PROFILE_ID, Receipt, load_signing_key};
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
use std::cell::RefCell;
use std::path::PathBuf;

dylint_linting::impl_late_lint! {
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
    "function uses a construct outside the Aeneas-extractable subset (screen, not a proof)",
    AeneasEligible::new()
}

/// Configuration, read from `dylint.toml` under the key `nucleus_guarantee_lint`
/// (the crate name). Absent ⇒ `Default` ⇒ receipts disabled (the screen still runs).
///
/// ```toml
/// [nucleus_guarantee_lint]
/// emit_receipts = true
/// receipt_dir = "target/guarantee-receipts"
/// signing_key_path = "secrets/guarantee-witness.key"   # 32-byte ed25519, raw OR hex
/// ```
///
/// HONESTY / fail-loud: if `emit_receipts = true` but `signing_key_path` is empty or the
/// key cannot be loaded as a valid 32-byte ed25519 secret (raw or hex), the lint pass
/// ABORTS with a hard error. It NEVER substitutes a zero / fake key — an unsigned or
/// fake-signed receipt would be a dishonest attestation.
#[derive(Debug, Default, serde::Deserialize)]
struct Config {
    #[serde(default)]
    emit_receipts: bool,
    #[serde(default)]
    receipt_dir: String,
    #[serde(default)]
    signing_key_path: String,
}

/// The lint pass. Holds config + a `RefCell` accumulator of receipts gathered during
/// `check_fn`, flushed (written + signed) once at `check_crate_post`.
pub struct AeneasEligible {
    config: Config,
    pending: RefCell<Vec<Receipt>>,
}

impl AeneasEligible {
    pub fn new() -> Self {
        Self {
            config: dylint_linting::config_or_default(env!("CARGO_PKG_NAME")),
            pending: RefCell::new(Vec::new()),
        }
    }
}

impl Default for AeneasEligible {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve the toolchain string the screen is running under. The receipt is
/// TOOLCHAIN-RELATIVE: the guarantee only holds for this exact rustc. Prefer the
/// `RUSTUP_TOOLCHAIN` env (set by rustup when a `+toolchain` / `rust-toolchain.toml`
/// is active); fall back to `nightly-2026-04-16` (this crate's pinned channel) so the
/// receipt is never silently toolchain-less.
fn resolve_toolchain() -> String {
    std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "nightly-2026-04-16".to_string())
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
        def_id: LocalDefId,
    ) {
        // Skip closures-as-fn (the enclosing fn's visitor reports them).
        if matches!(kind, FnKind::Closure) {
            return;
        }

        // Per-fn hit collector. Every `report_and_record` both emits the diagnostic
        // (unchanged behaviour, so the UI snapshot stays green) AND records the canonical
        // rule name + reason here, which the receipt then summarizes.
        let hits: RefCell<Vec<Hit>> = RefCell::new(Vec::new());

        // --- (a) signature unsafety -------------------------------------------------
        // FnHeader.safety is HeaderSafety post-refactor; prefer header.is_unsafe(),
        // which correctly treats SafeTargetFeatures as NOT unsafe (Research 2, §a).
        if let Some(header) = kind.header()
            && header.is_unsafe()
        {
            report_and_record(cx, &hits, span, "no_unsafe", "an `unsafe` function signature");
            // keep scanning the body for additional, more specific hits
        }

        // --- (b) async fn -----------------------------------------------------------
        if let Some(header) = kind.header()
            && header.is_async()
        {
            report_and_record(cx, &hits, span, "no_async", "an `async` function signature");
        }

        // --- (d) `dyn Trait` / (f) raw pointers in the SIGNATURE --------------------
        // Walk every Ty in inputs + output. We use a Ty-only visitor so we descend
        // into nested generic positions (e.g. `Box<dyn Trait>`, `&*const T`).
        for input in decl.inputs {
            check_signature_ty(cx, &hits, input);
        }
        if let rustc_hir::FnRetTy::Return(ret) = decl.output {
            check_signature_ty(cx, &hits, ret);
        }

        // --- body walk: (a) unsafe blocks, (b) async blocks, (c) closures,
        //                 (e) FFI calls, (f) inline asm ----------------------------
        let mut v = BodyScreen { cx, hits: &hits };
        v.visit_body(body);

        // --- receipt emission (only when configured) --------------------------------
        if self.config.emit_receipts {
            self.record_receipt(cx, def_id, span, hits.into_inner());
        }
    }

    // Crate-end hook: flush all accumulated receipts to disk, signed. LateLintPass
    // provides `check_crate_post` as the post-traversal crate-end hook.
    fn check_crate_post(&mut self, _cx: &LateContext<'tcx>) {
        if !self.config.emit_receipts {
            return;
        }
        if let Err(e) = self.flush_receipts() {
            // Fail LOUD: a misconfigured signer must not silently drop receipts.
            panic!("nucleus_guarantee_lint: failed to flush guarantee receipts: {e}");
        }
    }
}

impl AeneasEligible {
    /// Build a receipt for one screened function and stash it in `pending`. Reads the
    /// v0 `normalized_source` from the function's HIR span (whitespace-sensitive; see
    /// `receipt` module docs for the v1 TODO).
    fn record_receipt(
        &self,
        cx: &LateContext<'_>,
        def_id: LocalDefId,
        span: Span,
        hits: Vec<Hit>,
    ) {
        let item_path = cx.tcx.def_path_str(def_id.to_def_id());
        let item_kind = cx.tcx.def_descr(def_id.to_def_id()).to_string();

        // v0 normalized_source = the raw source snippet of the fn from its HIR span.
        // If the snippet is unavailable (macro-generated, no source map), skip the
        // receipt rather than hash an empty/placeholder string (no fake anchors).
        let Some(normalized_source) = snippet_opt(cx, span) else {
            return;
        };

        let toolchain = resolve_toolchain();
        let failed_rules: Vec<&str> = {
            let mut v: Vec<&str> = hits.iter().map(|h| h.rule).collect();
            v.sort_unstable();
            v.dedup();
            v
        };
        let reasons: Vec<String> = hits.iter().map(|h| h.reason.clone()).collect();

        let receipt = Receipt::build(
            item_path,
            item_kind,
            &normalized_source,
            &toolchain,
            PROFILE_ID,
            &failed_rules,
            reasons,
        );
        self.pending.borrow_mut().push(receipt);
    }

    /// Load the signing key (fail-loud on a bad/missing key — NEVER a zero key), then
    /// write `<receipt_dir>/<anchor_hash>.{json,sig}` for each pending receipt.
    fn flush_receipts(&self) -> Result<(), String> {
        let pending = self.pending.borrow();
        if pending.is_empty() {
            return Ok(());
        }

        if self.config.signing_key_path.trim().is_empty() {
            return Err(
                "emit_receipts = true but signing_key_path is empty; refusing to emit \
                 unsigned receipts (set a 32-byte ed25519 key path)"
                    .to_string(),
            );
        }
        let key_bytes = std::fs::read(&self.config.signing_key_path).map_err(|e| {
            format!("could not read signing_key_path '{}': {e}", self.config.signing_key_path)
        })?;
        let key = load_signing_key(&key_bytes)
            .map_err(|e| format!("invalid signing key at '{}': {e}", self.config.signing_key_path))?;

        let dir = if self.config.receipt_dir.trim().is_empty() {
            PathBuf::from("target/guarantee-receipts")
        } else {
            PathBuf::from(&self.config.receipt_dir)
        };
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("could not create receipt_dir '{}': {e}", dir.display()))?;

        for receipt in pending.iter() {
            let (json, sig) = receipt
                .sign(&key)
                .map_err(|e| format!("failed to sign receipt {}: {e}", receipt.anchor_hash))?;
            let base = dir.join(&receipt.anchor_hash);
            std::fs::write(base.with_extension("json"), &json)
                .map_err(|e| format!("write receipt json failed: {e}"))?;
            // Signature as lowercase hex (matches the hex anchor_hash convention).
            std::fs::write(base.with_extension("sig"), hex::encode(sig.to_bytes()))
                .map_err(|e| format!("write receipt sig failed: {e}"))?;
        }
        Ok(())
    }
}

/// One screen hit: the canonical rule name (one of `receipt::SCREENED_RULES`) plus the
/// human-readable reason that is also shown in the diagnostic.
struct Hit {
    rule: &'static str,
    reason: String,
}

/// Walk a single signature `Ty` for `dyn` and raw pointers (Research 2, §d, §f).
fn check_signature_ty<'tcx>(cx: &LateContext<'tcx>, hits: &RefCell<Vec<Hit>>, ty: &'tcx Ty<'tcx>) {
    let mut v = SigTyScreen { cx, hits };
    v.visit_ty_unambig(ty);
}

struct SigTyScreen<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    hits: &'a RefCell<Vec<Hit>>,
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
                    report_and_record(
                        self.cx,
                        self.hits,
                        ty.span,
                        "no_dyn_in_sig",
                        "a `dyn Trait` trait object in the signature",
                    );
                }
            }
            // Raw pointer: TyKind::Ptr(MutTy) — distinct from TyKind::Ref (Research 2, §f).
            TyKind::Ptr(_) => {
                report_and_record(
                    self.cx,
                    self.hits,
                    ty.span,
                    "no_raw_ptr",
                    "a raw pointer (`*const`/`*mut`) in the signature",
                );
            }
            _ => {}
        }
        walk_ty(self, ty);
    }
}

struct BodyScreen<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    hits: &'a RefCell<Vec<Hit>>,
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
                    report_and_record(
                        self.cx,
                        self.hits,
                        expr.span,
                        "no_unsafe",
                        "a user-written `unsafe { }` block",
                    );
                }
            }
            // (b)/(c) closures share ExprKind::Closure; ClosureKind distinguishes
            // plain closures from async/gen-block desugarings (Research 2, §b, §c).
            ExprKind::Closure(closure) => match closure.kind {
                ClosureKind::Closure => {
                    report_and_record(self.cx, self.hits, expr.span, "no_closures", "a closure");
                }
                ClosureKind::Coroutine(CoroutineKind::Desugared(
                    CoroutineDesugaring::Async,
                    _,
                )) => {
                    report_and_record(self.cx, self.hits, expr.span, "no_async", "an `async` block");
                }
                ClosureKind::CoroutineClosure(CoroutineDesugaring::Async) => {
                    report_and_record(
                        self.cx,
                        self.hits,
                        expr.span,
                        "no_async",
                        "an `async` closure",
                    );
                }
                // Other coroutines (gen / async-gen) — default-deny as out-of-subset.
                _ => {
                    report_and_record(
                        self.cx,
                        self.hits,
                        expr.span,
                        "no_closures",
                        "a coroutine (gen/async block or closure)",
                    );
                }
            },
            // (f) inline assembly — no functional model (Research 2, §f).
            ExprKind::InlineAsm(_) => {
                report_and_record(
                    self.cx,
                    self.hits,
                    expr.span,
                    "no_inline_asm",
                    "inline assembly (`asm!`)",
                );
            }
            // (e) FFI / extern call: resolve callee DefId and test is_foreign_item.
            // fn_def_id covers both Call and MethodCall (Research 2, §e).
            ExprKind::Call(..) | ExprKind::MethodCall(..) => {
                if let Some(did) = fn_def_id(self.cx, expr)
                    && self.cx.tcx.is_foreign_item(did)
                {
                    report_and_record(
                        self.cx,
                        self.hits,
                        expr.span,
                        "no_ffi_call",
                        "a call to an FFI / `extern` foreign item",
                    );
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

/// Emit the diagnostic AND record the canonical `rule` + `reason` for the enclosing fn's
/// receipt. The diagnostic text is unchanged from `report`, so the UI snapshot stays
/// byte-identical whether or not receipts are enabled.
fn report_and_record(
    cx: &LateContext<'_>,
    hits: &RefCell<Vec<Hit>>,
    span: Span,
    rule: &'static str,
    what: &str,
) {
    report(cx, span, what);
    hits.borrow_mut().push(Hit {
        rule,
        reason: what.to_string(),
    });
}

// ============================================================================
// guarantee-receipt: IMPLEMENTED (v0). See the `receipt` module + `check_fn`/
// `check_crate_post` above. When `emit_receipts = true` in dylint.toml, each screened
// fn yields a signed per-hash receipt at `<receipt_dir>/<anchor_hash>.{json,sig}`.
//
//     anchor_hash = SHA-256( b"nucleus.guarantee-receipt.v0"
//                            ‖ normalized_source ‖ toolchain ‖ profile_id )
//
// The receipt certifies ONLY "the screen returned this result for this (source,
// toolchain, profile) hash" — NOT "is extractable" and NOT "is correct" (see the
// `receipt` module-level HONESTY docs).
//
// v0 `normalized_source` = the raw HIR-span source snippet (clippy_utils::source::
// snippet_opt) — WHITESPACE-SENSITIVE. v1 TODO: switch to a reformat-robust anchor
// (rustfmt-normalized source, or a StableMIR-body hash) for toolchain-stable semantics.
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

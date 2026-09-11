//! `debug_format_in_preimage` — a value formatted for humans must not reach a
//! hash or signature preimage.
//!
//! # The defect this was built from
//!
//! `crates/portcullis/src/audit.rs:184`:
//!
//! ```ignore
//! hasher.update(format!("{:?}", self.event).as_bytes());
//! ```
//!
//! That is `PermissionAuditEvent::content_hash`, the link in the audit log's
//! hash chain, which `executor_sig` then signs. Derived `Debug` is **not a
//! stability contract**: renaming a variant forks the chain and every prior
//! entry fails to verify, and a `Debug` impl that elides a field makes two
//! distinct events hash identically. `crates/portcullis-core/src/provenance_node.rs:65`
//! does the same with a node kind, inside a content address.
//!
//! The tree already has the right answer and does not enforce it.
//! `crates/nucleus-ifc-kernel/src/flow.rs:598` is a stable two-byte tag whose
//! doc says *"not Debug format"*, pinned by two tests, and there are 34
//! `canonical_bytes` / `canonical_tag` definitions across the workspace. The
//! discipline exists; nothing stops the next author skipping it.
//!
//! # Why this fires on `Display` too, not only `Debug`
//!
//! The obvious rule is "no `{:?}` into a hasher". The rule here is wider: **no
//! format macro of any kind**. `Display` is no more a stability contract than
//! `Debug` for a preimage — a `Display` impl can be changed for readability by
//! someone who has no idea a digest depends on it, and neither impl is covered
//! by semver. Narrowing to `{:?}` would also make the pass depend on reading the
//! format string, which is a much more expensive question (see below).
//!
//! A format macro reaching a digest is *always* worth a human deciding, so the
//! lint asks for that decision rather than guessing which specifier is safe.
//!
//! # How it sees a `format!` without reading the format string
//!
//! `format_args!` is an **AST** node (`ast::ExprKind::FormatArgs`) lowered
//! during AST→HIR, so a late pass cannot match on it. Clippy's own format lints
//! reach it through a `FormatArgsStorage` filled by an early pass, which is
//! plumbing none of the sibling passes here have.
//!
//! None of that is needed. The question is not *what the format string says*,
//! it is *did this value come from a format macro*, and that is answerable from
//! the expression's macro backtrace: `root_macro_call_first_node` plus
//! `is_format_macro`. HIR only, one pass, no storage.
//!
//! # What a clean pass does NOT establish
//!
//! * **That the non-format preimages are canonical.** A hand-rolled byte string
//!   with no length prefixes and no domain tag is a collision waiting to happen
//!   and is invisible here. This closes one door.
//! * **That the value did not arrive by another hop.**
//!   `crates/nucleus-tool-proxy/src/workload.rs:692` stores a `format!` result
//!   into a struct field that later reaches a preimage; a local pass cannot see
//!   that. The unit of enforcement is the expression handed to the sink, and the
//!   one-hop case (`let s = format!(..); hasher.update(s.as_bytes())`) is caught
//!   because the local binding is followed. Two hops are not.
//! * **That every sink is listed.** [`SINKS`] is a closed vocabulary, like the
//!   sibling passes' — an FFI digest, or a hasher reached through a trait object
//!   whose method is named differently, is outside it.

#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use clippy_utils::macros::{is_format_macro, macro_backtrace};
use rustc_hir::{Expr, ExprKind};
use rustc_lint::{LateContext, LateLintPass};

dylint_linting::declare_late_lint! {
    /// ### What it does
    /// Refuses a value produced by a format macro as an argument to a hash or
    /// signature preimage.
    ///
    /// ### Why is this bad?
    /// `Debug` and `Display` are presentation, not encoding. Neither is covered
    /// by semver, both change for readability, and a digest that depends on one
    /// forks the moment someone improves a message.
    ///
    /// ### Example
    /// ```ignore
    /// hasher.update(format!("{:?}", event).as_bytes());   // forks on a rename
    /// ```
    /// Use instead:
    /// ```ignore
    /// hasher.update(event.canonical_tag());               // a pinned encoding
    /// ```
    pub DEBUG_FORMAT_IN_PREIMAGE,
    Warn,
    "a value formatted for humans reaches a hash or signature preimage"
}

/// Method names that consume preimage bytes.
///
/// A closed vocabulary for the reason every sibling pass keeps one: this is a
/// name match, not a resolution of the `Digest` trait, so widening it is a
/// visible diff rather than an accident. `update` carries the RustCrypto
/// streaming API (`Sha256`, `Blake3`, `Hmac`); `digest`, `finalize_fixed` and
/// `sign` carry the one-shot forms.
const SINKS: &[&str] = &["update", "digest", "sign", "finalize_fixed", "chain_update"];

/// Peel the conversions a preimage argument is normally wrapped in.
///
/// `format!(..).as_bytes()`, `.as_str()`, `.into_bytes()` and a borrow all sit
/// between the macro and the sink, and the macro backtrace belongs to the
/// expression underneath them.
fn peel<'tcx>(mut e: &'tcx Expr<'tcx>) -> &'tcx Expr<'tcx> {
    loop {
        e = match &e.kind {
            ExprKind::MethodCall(seg, recv, [], _)
                if matches!(
                    seg.ident.name.as_str(),
                    "as_bytes" | "as_str" | "into_bytes" | "as_ref" | "to_string" | "as_slice"
                ) =>
            {
                recv
            }
            ExprKind::AddrOf(_, _, inner) | ExprKind::Unary(rustc_hir::UnOp::Deref, inner) => inner,
            _ => return e,
        };
    }
}

/// Did this expression come from a format macro?
fn is_formatted(cx: &LateContext<'_>, e: &Expr<'_>) -> bool {
    macro_backtrace(e.span).any(|mac| is_format_macro(cx, mac.def_id))
}

impl<'tcx> LateLintPass<'tcx> for DebugFormatInPreimage {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        let ExprKind::MethodCall(seg, _recv, args, _) = &expr.kind else {
            return;
        };
        if !SINKS.contains(&seg.ident.name.as_str()) {
            return;
        }
        for arg in *args {
            let inner = peel(arg);
            if !is_formatted(cx, inner) {
                continue;
            }
            span_lint_and_help(
                cx,
                DEBUG_FORMAT_IN_PREIMAGE,
                // The SINK's span, not the argument's. A diagnostic whose span
                // lies inside a macro expansion is suppressed by rustc and
                // never reaches the user — which is exactly what happened here:
                // the pass fired on `format!(..)` and nothing was printed, while
                // the four ordinary `update` calls around it reported fine.
                expr.span,
                "a value formatted for humans reaches a hash or signature preimage",
                None,
                "`Debug` and `Display` are presentation, not encoding: neither is covered by \
                 semver, both change for readability, and a digest that depends on one forks the \
                 moment someone improves a message. Give the type a pinned encoding — \
                 `nucleus-ifc-kernel/src/flow.rs`'s two-byte tag is the model, and there are 34 \
                 `canonical_bytes`/`canonical_tag` definitions in this workspace to copy.",
            );
        }
    }
}

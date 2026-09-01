//! `nucleus-egress-lint` — the `unpoliced_http_client` pass.
//!
//! # What this closes
//!
//! A pod runs under default-deny egress. The audit log nonetheless fetched
//! `https://api.drand.sh/public/latest` on every boot with a 5-second timeout —
//! a request the pod's own network policy forbids, so it could not succeed.
//! Measured on an M5 Pro, that one call was **5044 ms of a 5497 ms tool-proxy
//! startup**, paid by every pod before it served anything.
//!
//! Nothing was broken and nothing logged. It compiled because
//! `reqwest::Client` is **ambient authority**: nothing in its type says where it
//! may connect, so any function anywhere could mint one.
//!
//! `nucleus_client::egress::Admitted` gave the beacon fetch a proof obligation.
//! That is the type; this pass is what makes the type the only door. Without
//! it, the next `reqwest::Client::builder()` reintroduces exactly the same
//! defect and nothing objects.
//!
//! # Why this pass is deliberately NARROW
//!
//! There are ~24 `reqwest::Client` construction sites across ~15 crates, and
//! most are legitimate: the node, the CLI and the SDK are **host** processes,
//! not sandboxed pods, and default-deny egress is not their constraint. A
//! workspace-wide ban would be twenty allow-listed exceptions, which is theatre
//! — a lint suppressed everywhere teaches people to suppress it.
//!
//! So the property is stated where it is actually true: **inside the guest**,
//! network I/O goes through a policy-aware constructor. CI runs this pass over
//! `nucleus-tool-proxy` and `nucleus-client` only. Run it over `nucleus-node`
//! and it will fire on correct code.
//!
//! # What a clean pass does NOT establish
//!
//! * **That the blessed constructors are correct.** [`BLESSED`] names functions
//!   that are *allowed* to build a client; whether they consult the allowlist
//!   properly is the job of `web_fetch_policy`'s own tests and the `Admitted`
//!   witness, not of a syntactic pass.
//! * **That no other transport exists.** A raw `TcpStream`, a `hyper` client, or
//!   an FFI call are all invisible here. This closes the door that was actually
//!   walked through, not every door.
//! * **Completeness of [`BLESSED`].** It is matched by function name. Renaming
//!   a blessed constructor without updating the list turns a legitimate call
//!   into a violation — noisy, and the safe direction. Adding a name to the
//!   list is the dangerous direction, so the list is load-bearing configuration
//!   and short on purpose.

#![feature(rustc_private)]
#![warn(unused_extern_crates)]

extern crate rustc_hir;
extern crate rustc_span;

use clippy_utils::diagnostics::span_lint_and_help;
use rustc_hir::def_id::LocalDefId;
use rustc_hir::intravisit::FnKind;
use rustc_hir::{Body, Expr, ExprKind, FnDecl};
use rustc_lint::{LateContext, LateLintPass};
use rustc_span::Span;

/// Functions permitted to construct an HTTP client inside the guest.
///
/// Each is policy-aware: it takes the resolved allowlists, or it takes an
/// [`Admitted`] proof. Everything else must route through one of them.
///
/// Short on purpose — adding a name here is how the boundary gets widened, so
/// it should be a visible, argued diff.
const BLESSED: &[&str] = &[
    // Takes `dns_allow` / `url_allow` and re-checks every redirect hop.
    "build_web_fetch_client",
];

/// The type whose presence in a signature licenses building a client.
///
/// `nucleus_client::egress::Admitted` is unforgeable outside its module, so a
/// function that has one was handed a decision the policy already made.
const ADMISSION_PROOF: &str = "Admitted";

/// Does this signature carry an egress admission proof?
///
/// Matched on the type's last path segment. A local alias named `Admitted`
/// would fool it — noted rather than solved, because the alternative (resolving
/// the type through `LateContext`) buys little against a threat model where the
/// author is trying to defeat their own lint.
fn takes_admission_proof(decl: &FnDecl<'_>) -> bool {
    decl.inputs.iter().any(|ty| {
        if let rustc_hir::TyKind::Path(rustc_hir::QPath::Resolved(_, path)) = &ty.kind {
            path.segments
                .last()
                .is_some_and(|s| s.ident.name.as_str() == ADMISSION_PROOF)
        } else {
            false
        }
    })
}

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Flags `reqwest::Client::new` / `reqwest::Client::builder` constructed
    /// anywhere in the guest except a blessed, policy-aware constructor.
    ///
    /// ### Why is this bad?
    ///
    /// `reqwest::Client` is ambient authority: its type says nothing about
    /// where it may connect. A pod under default-deny egress spent five
    /// seconds of every boot on a fetch its own policy forbade, and the code
    /// was well-typed. The `Admitted` witness gives the call a proof
    /// obligation; this pass is what stops the next call from skipping it.
    ///
    /// ### Known problems
    ///
    /// Syntactic and narrow: only `reqwest`, only the guest crates, only by
    /// function name. A raw socket is invisible to it.
    ///
    /// ### Example
    ///
    /// ```rust,ignore
    /// let client = reqwest::Client::builder().timeout(t).build()?;
    /// ```
    ///
    /// Use instead:
    ///
    /// ```rust,ignore
    /// let client = web_fetch_policy::build_web_fetch_client(t, dns_allow, url_allow)?;
    /// ```
    pub UNPOLICED_HTTP_CLIENT,
    Warn,
    "an HTTP client built in the guest outside a policy-aware constructor"
}

impl<'tcx> LateLintPass<'tcx> for UnpolicedHttpClient {
    fn check_fn(
        &mut self,
        cx: &LateContext<'tcx>,
        kind: FnKind<'tcx>,
        _decl: &'tcx FnDecl<'tcx>,
        body: &'tcx Body<'tcx>,
        span: Span,
        _def_id: LocalDefId,
    ) {
        // A function that already HOLDS the egress proof may build a client:
        // that is the whole point of the witness. This is the rule the pass
        // really wants, and it is a property of the signature rather than a
        // name someone remembered to add to a list.
        if takes_admission_proof(_decl) {
            return;
        }
        // The remaining exception is a constructor that takes the allowlists
        // directly and re-checks every redirect hop. Matched by name because it
        // predates the witness; short on purpose.
        if let FnKind::ItemFn(ident, ..) | FnKind::Method(ident, ..) = kind {
            if BLESSED.contains(&ident.name.as_str()) {
                return;
            }
        }
        // `#[cfg(test)]` code is not in a normal build, so `cargo dylint -p <crate>`
        // never sees it — tests may build clients freely, and the property this
        // states is about the shipped path.
        let _ = span;

        let mut finder = ClientFinder { cx, hits: Vec::new() };
        rustc_hir::intravisit::Visitor::visit_body(&mut finder, body);

        for hit in finder.hits {
            span_lint_and_help(
                cx,
                UNPOLICED_HTTP_CLIENT,
                hit,
                "HTTP client constructed outside a policy-aware constructor",
                None,
                "a pod runs under default-deny egress, so a client built here can \
                 target a host its own policy forbids — and will spend the full \
                 timeout discovering that on every boot. Build it through \
                 `web_fetch_policy::build_web_fetch_client`, or take an \
                 `egress::Admitted` proof.",
            );
        }
    }
}

struct ClientFinder<'a, 'tcx> {
    cx: &'a LateContext<'tcx>,
    hits: Vec<Span>,
}

impl<'a, 'tcx> rustc_hir::intravisit::Visitor<'tcx> for ClientFinder<'a, 'tcx> {
    fn visit_expr(&mut self, expr: &'tcx Expr<'tcx>) {
        if let ExprKind::Call(callee, _) = expr.kind {
            if let ExprKind::Path(ref qpath) = callee.kind {
                if let Some(def_id) = self.cx.qpath_res(qpath, callee.hir_id).opt_def_id() {
                    let path = self.cx.get_def_path(def_id);
                    let segments: Vec<String> =
                        path.iter().map(|s| s.to_string()).collect();
                    let is_client_ctor = segments.len() >= 3
                        && segments[0] == "reqwest"
                        && segments[segments.len() - 2] == "Client"
                        && matches!(segments[segments.len() - 1].as_str(), "new" | "builder");
                    if is_client_ctor {
                        self.hits.push(expr.span);
                    }
                }
            }
        }
        rustc_hir::intravisit::walk_expr(self, expr);
    }
}

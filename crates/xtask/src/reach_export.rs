//! `reach-export` — the call-graph **reach relation**, exported as CSV.
//!
//! # Why this exists
//!
//! Four gates in this repository already answer reachability questions, each
//! with its own file format and its own hand-maintained ledger:
//!
//! | gate | question | ledger |
//! |---|---|---|
//! | `mediated` (Dylint) | does a public fn reach a raw I/O primitive without crossing an `Authority`? | `DENY_SET`, in Rust |
//! | `cargo xtask law-mechanisms` | is a declared mechanism reached by *nothing* live? | `scripts/law-mechanisms-manifest.txt` |
//! | `cargo xtask inert-authority` | is a mechanism reached, handed its witness, and drops it? | `scripts/inert-authority-manifest.txt` |
//! | `scripts/check-extracted-callsites.sh` | is a proven predicate reached from a shipping path? | `scripts/extracted-callsites-manifest.txt` |
//!
//! They are four queries over one relation. `law-mechanisms`' own header states
//! the shared predicate in prose — *"a predicate proven about a function nobody
//! calls is a proof about dead code"* — and then each gate re-derives it by
//! grepping for a string anchor. This subcommand exports the relation itself so
//! it can be queried once instead of grepped four times.
//!
//! # This is an INDEX, not a gate — and the distinction is load-bearing
//!
//! Nothing here decides anything. No required context consumes this output, and
//! [`run`] returns `0` unless the export itself failed. That is deliberate:
//! `mediated` derives its call graph inside `rustc` with full type information
//! and reports `unresolved_call` rather than skipping what it cannot resolve,
//! which is what lets a clean pass there *assert* something. This exporter reads
//! `syn` ASTs with no type information at all. It is strictly weaker, and it must
//! never be mistaken for the thing it indexes.
//!
//! Concretely, what the weakness costs:
//!
//! * **Call resolution is by name.** A call is matched against declared function
//!   names, preferring the calling crate. Every edge therefore carries a
//!   [`Resolution`] class, and a consumer that wants a precise graph filters to
//!   [`Resolution::UniqueWorkspace`] / [`Resolution::SameCrate`]. The classes
//!   form a chain of sub-quivers, so reach is monotone along the inclusion: an
//!   answer computed over the precise classes is a *lower* bound on reach, and
//!   one computed over all classes is an *upper* bound. Neither is the truth;
//!   both bracket it, and the report prints the width of the bracket.
//! * **Sink detection is path-form only.** `std::fs::read(..)` and a `use
//!   std::process::Command;` + `Command::new(..)` are both caught (this resolves
//!   `use` aliases per file); a sink reached through a method on a value whose
//!   type is not written at the call site is not. `mediated` has the types and
//!   this does not.
//! * **Dynamic calls are recorded, never dropped.** A call through a closure
//!   binding, a field, or a name that resolves to no declared function becomes an
//!   [`Unresolved`] row, for `mediated`'s reason: silently skipping what defeats
//!   static resolution turns a hole into a clean pass.
//!
//! # `#[cfg(test)]` handling deliberately differs from the grep gates
//!
//! [`law_mechanisms::production_region`] strips test code by counting braces,
//! because a grep gate has no parser. This walks `syn` items and skips any item
//! carrying `#[cfg(test)]`, which is exact. The two therefore disagree on
//! pathological input, and where they do, this one is right. File-level scope is
//! shared: [`law_mechanisms::is_production_path`] and
//! [`law_mechanisms::tracked`], so the file domain still comes from `git
//! ls-files` rather than a directory walk.

use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use crate::law_mechanisms::{self, is_production_path, tracked};

/// Raw I/O primitives, mirrored from `tools/nucleus-mediation-lint`'s `DENY_SET`.
///
/// Mirrored, not imported: the lint is a `dylint` crate built against
/// `rustc_private` on a pinned nightly and cannot be a dependency of a stable
/// `xtask`. [`check_sink_parity`] asserts the two lists agree by reading the
/// lint's source, so the copy cannot drift silently — the same discipline
/// `law-mechanisms` applies to its own manifest.
const SINKS: &[(&str, &str)] = &[
    ("std::fs::", "filesystem"),
    ("tokio::fs::", "filesystem"),
    ("cap_std::fs::Dir::", "filesystem"),
    ("cap_std::fs::File::", "filesystem"),
    ("std::process::Command::", "process"),
    ("tokio::process::Command::", "process"),
    ("std::net::", "network"),
    ("tokio::net::", "network"),
    ("reqwest::", "network"),
    ("std::os::fd::", "raw_fd"),
    ("std::os::unix::io::", "raw_fd"),
];

/// The crates whose unmediated-I/O findings `mediated` ENFORCES. Mirrored from
/// that lint's `MEDIATED_CRATES` and parity-checked by [`check_sink_parity`].
const MEDIATED_CRATES: &[&str] = &["portcullis_effects"];

/// Where the mirrored constants are read back from, for the parity check.
const LINT_SRC: &str = "tools/nucleus-mediation-lint/src/lib.rs";

/// How confidently a call edge was resolved. Ordered weakest-precision-last;
/// the variants partition the edge set into sub-quivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Resolution {
    /// Exactly one declared function in the workspace bears this name.
    UniqueWorkspace,
    /// Several bear it, but exactly one is in the calling crate, which is taken.
    SameCrate,
    /// Several bear it and none disambiguates. Every candidate gets an edge, so
    /// reach over this class is an over-approximation.
    Ambiguous,
}

impl Resolution {
    fn as_str(self) -> &'static str {
        match self {
            Resolution::UniqueWorkspace => "unique_workspace",
            Resolution::SameCrate => "same_crate",
            Resolution::Ambiguous => "ambiguous",
        }
    }

    /// The precise classes — those whose edges are backed by a unique callee.
    /// Reach restricted to these is a lower bound on true reach.
    pub fn is_precise(self) -> bool {
        matches!(self, Resolution::UniqueWorkspace | Resolution::SameCrate)
    }
}

/// A function declared in the production region of a tracked crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FnNode {
    pub id: String,
    /// `crate::module::Type::name` — the display name and the olog row name.
    pub qualified: String,
    /// The bare identifier, which is what name resolution matches on.
    pub name: String,
    pub krate: String,
    pub file: String,
    pub line: usize,
    pub public: bool,
}

/// One resolved call, caller → callee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEdge {
    pub caller: String,
    pub callee: String,
    pub resolution: Resolution,
    pub file: String,
    pub line: usize,
}

/// A path-form call into a raw I/O primitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkUse {
    pub fn_id: String,
    pub sink: String,
    pub path: String,
    pub file: String,
    pub line: usize,
}

/// A witness type appearing in a function signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessDemand {
    pub fn_id: String,
    pub witness: String,
    /// `by_value` | `by_ref`. Only `by_value` marks a mediation boundary for
    /// `mediated`; `by_ref` is recorded because `inert-authority` cares about it
    /// (a `SessionCleanseToken` taken by reference is not single-use).
    pub binding: String,
    /// `true` when the parameter is `_`-bound — the shape `inert-authority`
    /// counts. A demanded-and-unread witness bounds nothing.
    pub inert: bool,
    pub file: String,
    pub line: usize,
}

/// A call that defeated static resolution. Recorded, never dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unresolved {
    pub fn_id: String,
    /// `dynamic_call` (callee is an expression, not a path) or `no_declaration`
    /// (a name matching no declared function: an external crate, or a trait
    /// method dispatched dynamically — this cannot tell which).
    pub form: String,
    pub detail: String,
    pub file: String,
    pub line: usize,
}

/// Everything one export run learned.
#[derive(Debug, Default)]
pub struct Graph {
    pub fns: Vec<FnNode>,
    pub edges: Vec<CallEdge>,
    pub sink_uses: Vec<SinkUse>,
    pub demands: Vec<WitnessDemand>,
    pub unresolved: Vec<Unresolved>,
    /// Files `syn` could not parse. Non-empty is a finding, not a warning: an
    /// unparsed file contributes no edges, which silently shrinks reach.
    pub unparsed: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Declaration pass — walk the item tree, collecting functions
// ═══════════════════════════════════════════════════════════════════════════

fn has_cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| {
        if !a.path().is_ident("cfg") {
            return false;
        }
        let mut found = false;
        // `parse_nested_meta` walks `cfg(test)`, `cfg(all(test, ..))`, etc.
        let _ = a.parse_nested_meta(|meta| {
            if meta.path.is_ident("test") {
                found = true;
            }
            // Descend into `all(..)` / `any(..)` / `not(..)`.
            let _ = meta.parse_nested_meta(|inner| {
                if inner.path.is_ident("test") {
                    found = true;
                }
                Ok(())
            });
            Ok(())
        });
        found
    })
}

/// Render a `syn::Path` as `a::b::c`, dropping generic arguments.
fn path_str(p: &syn::Path) -> String {
    let mut out = String::new();
    if p.leading_colon.is_some() {
        // `::std::fs::read` and `std::fs::read` name the same thing; normalising
        // here means the deny-set does not need both spellings.
    }
    for (i, seg) in p.segments.iter().enumerate() {
        if i > 0 {
            out.push_str("::");
        }
        out.push_str(&seg.ident.to_string());
    }
    out
}

/// The bare name of a type, looking through references, boxes and options — the
/// spelling a witness type is recognised by.
fn type_head(t: &syn::Type) -> Option<(String, bool)> {
    match t {
        syn::Type::Path(tp) => tp
            .path
            .segments
            .last()
            .map(|s| (s.ident.to_string(), false)),
        syn::Type::Reference(r) => type_head(&r.elem).map(|(n, _)| (n, true)),
        syn::Type::Paren(p) => type_head(&p.elem),
        syn::Type::Group(g) => type_head(&g.elem),
        _ => None,
    }
}

/// Per-file `use` map: last segment → full path, so `Command::new` can be
/// expanded to `std::process::Command::new` and matched against the deny-set.
fn use_map(file: &syn::File) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for item in &file.items {
        if let syn::Item::Use(u) = item {
            walk_use(&u.tree, &mut String::new(), &mut map);
        }
    }
    map
}

fn walk_use(tree: &syn::UseTree, prefix: &mut String, out: &mut BTreeMap<String, String>) {
    match tree {
        syn::UseTree::Path(p) => {
            let saved = prefix.len();
            if !prefix.is_empty() {
                prefix.push_str("::");
            }
            prefix.push_str(&p.ident.to_string());
            walk_use(&p.tree, prefix, out);
            prefix.truncate(saved);
        }
        syn::UseTree::Name(n) => {
            let name = n.ident.to_string();
            let full = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}::{name}")
            };
            out.insert(name, full);
        }
        syn::UseTree::Rename(r) => {
            let orig = r.ident.to_string();
            let full = if prefix.is_empty() {
                orig
            } else {
                format!("{prefix}::{orig}")
            };
            out.insert(r.rename.to_string(), full);
        }
        syn::UseTree::Group(g) => {
            for t in &g.items {
                walk_use(t, prefix, out);
            }
        }
        // A glob import hides which names it brings in. It is not recorded, so a
        // sink reached through one is missed — one more reason this is an index.
        syn::UseTree::Glob(_) => {}
    }
}

/// The crate name for a tracked path: `crates/<pkg>/src/..` → `<pkg>` with
/// hyphens as underscores, matching the lib-crate spelling `mediated` uses.
pub fn crate_of(path: &str) -> Option<String> {
    path.strip_prefix("crates/")
        .and_then(|r| r.split('/').next())
        .map(|p| p.replace('-', "_"))
}

/// A function body, paired with the context needed to name and attribute it.
struct Decl<'a> {
    name: String,
    qualified: String,
    line: usize,
    public: bool,
    sig: &'a syn::Signature,
    block: Option<&'a syn::Block>,
}

/// Collect every production function declared in one parsed file.
fn declarations<'a>(file: &'a syn::File, krate: &str) -> Vec<Decl<'a>> {
    let mut out = Vec::new();
    let mut scope = krate.to_string();
    collect_items(&file.items, &mut scope, &mut out);
    out
}

fn collect_items<'a>(items: &'a [syn::Item], scope: &mut String, out: &mut Vec<Decl<'a>>) {
    for item in items {
        match item {
            syn::Item::Fn(f) if !has_cfg_test(&f.attrs) => out.push(Decl {
                name: f.sig.ident.to_string(),
                qualified: format!("{scope}::{}", f.sig.ident),
                line: line_of(&f.sig.ident),
                public: matches!(f.vis, syn::Visibility::Public(_)),
                sig: &f.sig,
                block: Some(&f.block),
            }),
            syn::Item::Mod(m) if !has_cfg_test(&m.attrs) => {
                if let Some((_, inner)) = &m.content {
                    let saved = scope.len();
                    let _ = write!(scope, "::{}", m.ident);
                    collect_items(inner, scope, out);
                    scope.truncate(saved);
                }
            }
            syn::Item::Impl(i) if !has_cfg_test(&i.attrs) => {
                let ty = type_head(&i.self_ty)
                    .map(|(n, _)| n)
                    .unwrap_or_else(|| "impl".to_string());
                for ii in &i.items {
                    if let syn::ImplItem::Fn(f) = ii {
                        if has_cfg_test(&f.attrs) {
                            continue;
                        }
                        out.push(Decl {
                            name: f.sig.ident.to_string(),
                            qualified: format!("{scope}::{ty}::{}", f.sig.ident),
                            line: line_of(&f.sig.ident),
                            public: matches!(f.vis, syn::Visibility::Public(_)),
                            sig: &f.sig,
                            block: Some(&f.block),
                        });
                    }
                }
            }
            syn::Item::Trait(t) if !has_cfg_test(&t.attrs) => {
                for ti in &t.items {
                    if let syn::TraitItem::Fn(f) = ti {
                        if has_cfg_test(&f.attrs) {
                            continue;
                        }
                        // A trait method with no default body still declares a
                        // signature, so its witness demands count — that is
                        // exactly where `inert-authority` finds `_`-bound
                        // parameters in `trait ShellEffect` and friends.
                        out.push(Decl {
                            name: f.sig.ident.to_string(),
                            qualified: format!("{scope}::{}::{}", t.ident, f.sig.ident),
                            line: line_of(&f.sig.ident),
                            public: matches!(t.vis, syn::Visibility::Public(_)),
                            sig: &f.sig,
                            block: f.default.as_ref(),
                        });
                    }
                }
            }
            _ => {}
        }
    }
}

/// The 1-based source line of an identifier.
///
/// `proc-macro2`'s `span-locations` feature is enabled in this crate's
/// manifest for exactly this: without it every span reports line 0 and the
/// exported CSV cannot be navigated back to source.
fn line_of(ident: &syn::Ident) -> usize {
    ident.span().start().line
}

// ═══════════════════════════════════════════════════════════════════════════
// Body pass — calls, sinks, dynamic dispatch
// ═══════════════════════════════════════════════════════════════════════════

/// What one function body calls, before resolution.
#[derive(Default)]
struct BodyFacts {
    /// Bare callee names with their call-site line, from path calls and method
    /// calls alike.
    called: Vec<(String, usize)>,
    /// Fully-qualified path-form calls, for deny-set matching.
    paths: Vec<(String, usize)>,
    /// Callees that are expressions rather than paths.
    dynamic: Vec<(String, usize)>,
}

struct BodyVisitor<'a> {
    uses: &'a BTreeMap<String, String>,
    facts: BodyFacts,
}

impl<'a> syn::visit::Visit<'a> for BodyVisitor<'a> {
    fn visit_expr_call(&mut self, node: &'a syn::ExprCall) {
        match &*node.func {
            syn::Expr::Path(p) => {
                let raw = path_str(&p.path);
                let line = p
                    .path
                    .segments
                    .first()
                    .map(|s| s.ident.span().start().line)
                    .unwrap_or(0);
                self.facts.paths.push((self.expand(&raw), line));
                if let Some(last) = p.path.segments.last() {
                    self.facts.called.push((last.ident.to_string(), line));
                }
            }
            other => self
                .facts
                .dynamic
                .push((expr_shape(other), node.paren_token.span.open().start().line)),
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'a syn::ExprMethodCall) {
        self.facts
            .called
            .push((node.method.to_string(), node.method.span().start().line));
        syn::visit::visit_expr_method_call(self, node);
    }
}

impl BodyVisitor<'_> {
    /// Expand a written path through the file's `use` map, so `Command::new`
    /// becomes `std::process::Command::new`.
    fn expand(&self, raw: &str) -> String {
        let Some((head, rest)) = raw.split_once("::") else {
            return self
                .uses
                .get(raw)
                .cloned()
                .unwrap_or_else(|| raw.to_string());
        };
        match self.uses.get(head) {
            Some(full) => format!("{full}::{rest}"),
            None => raw.to_string(),
        }
    }
}

/// A short, stable description of a non-path callee, for the unresolved row.
fn expr_shape(e: &syn::Expr) -> String {
    match e {
        syn::Expr::Field(_) => "field",
        syn::Expr::MethodCall(_) => "method_result",
        syn::Expr::Paren(_) | syn::Expr::Group(_) => "parenthesised",
        syn::Expr::Closure(_) => "closure_literal",
        syn::Expr::Call(_) => "call_result",
        syn::Expr::Index(_) => "index",
        syn::Expr::Unary(_) => "deref",
        _ => "expression",
    }
    .to_string()
}

// ═══════════════════════════════════════════════════════════════════════════
// Build
// ═══════════════════════════════════════════════════════════════════════════

/// Witness types, mirrored from `scripts/inert-authority-manifest.txt`'s
/// `WITNESS` block, which is parsed at run time rather than copied — the
/// manifest stays the single declaration.
fn witness_types(root: &Path) -> Result<Vec<String>> {
    let p = root.join("scripts/inert-authority-manifest.txt");
    let text = std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
    let mut out = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim();
        if line == "WITNESS = [" {
            inside = true;
            continue;
        }
        if inside {
            if line == "]" {
                break;
            }
            let name = line.trim_end_matches(',').trim().trim_matches('"');
            if !name.is_empty() {
                out.push(name.to_string());
            }
        }
    }
    if out.is_empty() {
        bail!(
            "no WITNESS types parsed from {}; the demand scan would be vacuous",
            p.display()
        );
    }
    Ok(out)
}

/// Build the graph from a corpus of `path -> source`.
pub fn build(corpus: &BTreeMap<String, String>, witnesses: &[String]) -> Graph {
    let witness_set: BTreeSet<&str> = witnesses.iter().map(String::as_str).collect();
    let mut g = Graph::default();

    // Pass 1 — declarations. Ids must be stable across runs, so they are the
    // qualified name plus a disambiguating index for genuine duplicates (two
    // `impl` blocks for the same type in one crate can declare the same path).
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    // Keep each file's parse so pass 2 does not re-parse.
    let mut parsed: Vec<(String, String, syn::File)> = Vec::new();

    for (path, src) in corpus {
        let Some(krate) = crate_of(path) else {
            continue;
        };
        match syn::parse_file(src) {
            Ok(f) => parsed.push((path.clone(), krate, f)),
            Err(_) => g.unparsed.push(path.clone()),
        }
    }

    for (path, krate, file) in &parsed {
        for d in declarations(file, krate) {
            let n = seen.entry(d.qualified.clone()).or_insert(0);
            let id = if *n == 0 {
                d.qualified.clone()
            } else {
                format!("{}#{}", d.qualified, n)
            };
            *n += 1;
            g.fns.push(FnNode {
                id,
                qualified: d.qualified,
                name: d.name,
                krate: krate.clone(),
                file: path.clone(),
                line: d.line,
                public: d.public,
            });
        }
    }

    // Name → candidate ids, and the same restricted per crate.
    let mut by_name: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (i, f) in g.fns.iter().enumerate() {
        by_name.entry(f.name.as_str()).or_default().push(i);
    }

    // Pass 2 — bodies. Indices into `g.fns` are assigned in the same order as
    // pass 1 walked, so they line up without a second lookup.
    let mut idx = 0usize;
    let mut edges = Vec::new();
    let mut sink_uses = Vec::new();
    let mut demands = Vec::new();
    let mut unresolved = Vec::new();

    for (path, krate, file) in &parsed {
        let uses = use_map(file);
        for d in declarations(file, krate) {
            let fn_id = g.fns[idx].id.clone();
            idx += 1;

            // Signature — witness demands.
            for arg in &d.sig.inputs {
                let syn::FnArg::Typed(pt) = arg else { continue };
                let Some((head, by_ref)) = type_head(&pt.ty) else {
                    continue;
                };
                if !witness_set.contains(head.as_str()) {
                    continue;
                }
                let inert = match &*pt.pat {
                    syn::Pat::Ident(pi) => pi.ident.to_string().starts_with('_'),
                    syn::Pat::Wild(_) => true,
                    _ => false,
                };
                demands.push(WitnessDemand {
                    fn_id: fn_id.clone(),
                    witness: head,
                    binding: if by_ref { "by_ref" } else { "by_value" }.to_string(),
                    inert,
                    file: path.clone(),
                    line: d.line,
                });
            }

            let Some(block) = d.block else { continue };
            let mut v = BodyVisitor {
                uses: &uses,
                facts: BodyFacts::default(),
            };
            syn::visit::Visit::visit_block(&mut v, block);

            for (p, line) in &v.facts.paths {
                for (prefix, kind) in SINKS {
                    if p.starts_with(prefix) {
                        sink_uses.push(SinkUse {
                            fn_id: fn_id.clone(),
                            sink: (*kind).to_string(),
                            path: p.clone(),
                            file: path.clone(),
                            line: *line,
                        });
                        break;
                    }
                }
            }

            for (shape, line) in &v.facts.dynamic {
                unresolved.push(Unresolved {
                    fn_id: fn_id.clone(),
                    form: "dynamic_call".to_string(),
                    detail: shape.clone(),
                    file: path.clone(),
                    line: *line,
                });
            }

            let mut emitted: BTreeSet<(String, Resolution)> = BTreeSet::new();
            for (name, line) in &v.facts.called {
                let Some(cands) = by_name.get(name.as_str()) else {
                    unresolved.push(Unresolved {
                        fn_id: fn_id.clone(),
                        form: "no_declaration".to_string(),
                        detail: name.clone(),
                        file: path.clone(),
                        line: *line,
                    });
                    continue;
                };
                let same: Vec<usize> = cands
                    .iter()
                    .copied()
                    .filter(|&c| g.fns[c].krate == *krate)
                    .collect();
                let (chosen, res): (Vec<usize>, Resolution) = if cands.len() == 1 {
                    (cands.clone(), Resolution::UniqueWorkspace)
                } else if same.len() == 1 {
                    (same, Resolution::SameCrate)
                } else {
                    (cands.clone(), Resolution::Ambiguous)
                };
                for c in chosen {
                    let callee = g.fns[c].id.clone();
                    if emitted.insert((callee.clone(), res)) {
                        edges.push(CallEdge {
                            caller: fn_id.clone(),
                            callee,
                            resolution: res,
                            file: path.clone(),
                            line: *line,
                        });
                    }
                }
            }
        }
    }

    g.edges = edges;
    g.sink_uses = sink_uses;
    g.demands = demands;
    g.unresolved = unresolved;
    g
}

/// A publicly reachable function in a mediated crate that can reach a raw I/O
/// primitive without any function on the path demanding an `Authority` by value.
///
/// This is `mediated`'s finding, at `mediated`'s granularity (the offending
/// FUNCTION, not the path), recomputed over the exported graph so the claim
/// "there are none" becomes a row count rather than a lint's exit status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnmediatedPath {
    /// The public entry point that should not have been able to get there.
    pub entry: String,
    /// The function on the far end that performs the I/O.
    pub via: String,
    /// Which class of primitive it reaches.
    pub sink: String,
    /// `precise` when the witnessing path uses only unique-callee edges;
    /// `ambiguous` when it needs a name-resolved guess. A finding in the
    /// `precise` class is worth a human look; one that exists only in the
    /// `ambiguous` class is probably this index's imprecision, and separating
    /// them is the difference between a report and a pile.
    pub class: &'static str,
    /// Edges from `entry` to `via`. Zero means `entry` performs the I/O itself.
    pub depth: usize,
}

/// Does this function discharge the mediation obligation?
///
/// `mediated`'s rule exactly: an `Authority` demanded BY VALUE. A by-reference
/// binding does not count (the lint keys on the type appearing by value in the
/// signature), and neither does any other witness type — `Authority` is the one
/// the Lean mediation theorem is stated over.
fn is_mediating(demands: &[WitnessDemand], fn_id: &str) -> bool {
    demands
        .iter()
        .any(|d| d.fn_id == fn_id && d.witness == "Authority" && d.binding == "by_value")
}

/// Compute the unmediated-path witnesses.
///
/// The traversal never enters a mediating node, which is what "some function on
/// the path demands an authority" means operationally: once the obligation is
/// discharged, everything downstream is inside the boundary and is not this
/// question's business. A sink performer that is itself mediating is therefore
/// unreachable here, correctly.
///
/// Seeds are PUBLIC functions in a crate `mediated` enforces. That scope is not
/// a softening — it is the lint's own: "'Mediated crates' is a defined set,
/// listed in the CI invocation, not 'everything'". Widening it means adding a
/// crate, in the open, in both places.
pub fn unmediated_paths(g: &Graph) -> Vec<UnmediatedPath> {
    let sink_of: BTreeMap<&str, &str> = g
        .sink_uses
        .iter()
        .map(|s| (s.fn_id.as_str(), s.sink.as_str()))
        .collect();

    let mut out = Vec::new();
    // `precise` first, so a finding that exists in both classes is reported as
    // precise: the stronger statement wins, and the dedup below keeps one row.
    for (class, precise_only) in [("precise", true), ("ambiguous", false)] {
        let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for e in &g.edges {
            if precise_only && !e.resolution.is_precise() {
                continue;
            }
            // Never traverse INTO a mediating node.
            if is_mediating(&g.demands, &e.callee) {
                continue;
            }
            adj.entry(e.caller.as_str())
                .or_default()
                .push(e.callee.as_str());
        }

        for f in &g.fns {
            if !f.public || !MEDIATED_CRATES.contains(&f.krate.as_str()) {
                continue;
            }
            if is_mediating(&g.demands, &f.id) {
                continue;
            }
            // BFS to saturation, recording the first (shortest) witness per sink.
            let mut seen: BTreeSet<&str> = [f.id.as_str()].into_iter().collect();
            let mut frontier: Vec<&str> = vec![f.id.as_str()];
            let mut depth = 0usize;
            let mut hit: BTreeMap<&str, (&str, usize)> = BTreeMap::new();
            while !frontier.is_empty() {
                for n in &frontier {
                    if let Some(sink) = sink_of.get(*n) {
                        hit.entry(sink).or_insert((*n, depth));
                    }
                }
                let mut next = Vec::new();
                for n in &frontier {
                    for c in adj.get(*n).map(Vec::as_slice).unwrap_or(&[]) {
                        if seen.insert(c) {
                            next.push(*c);
                        }
                    }
                }
                frontier = next;
                depth += 1;
            }
            for (sink, (via, d)) in hit {
                out.push(UnmediatedPath {
                    entry: f.id.clone(),
                    via: via.to_string(),
                    sink: sink.to_string(),
                    class,
                    depth: d,
                });
            }
        }
    }

    // One row per (entry, sink); the precise pass ran first, so it wins.
    let mut keep: BTreeSet<(String, String)> = BTreeSet::new();
    out.retain(|u| keep.insert((u.entry.clone(), u.sink.clone())));
    out.sort_by(|a, b| (a.class, &a.entry, &a.sink).cmp(&(b.class, &b.entry, &b.sink)));
    out
}

// ═══════════════════════════════════════════════════════════════════════════
// Reach
// ═══════════════════════════════════════════════════════════════════════════

/// Forward reach from `seeds` over the edges admitted by `admit`, iterated to
/// **saturation**. Returns the reached set and the number of rounds it took.
///
/// Saturation, not a depth cap, is the whole point. A truncated closure
/// *under-approximates* reach, and for "nothing unmediated reaches a sink" an
/// under-approximation yields a false clean. The round count is returned so a
/// consumer that must cap (a SQL `WITH RECURSIVE ... WHERE depth < N`) can check
/// its `N` exceeds the measured diameter.
pub fn reach(
    edges: &[CallEdge],
    seeds: &BTreeSet<String>,
    admit: impl Fn(&CallEdge) -> bool,
) -> (BTreeSet<String>, usize) {
    let mut adj: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for e in edges.iter().filter(|e| admit(e)) {
        adj.entry(e.caller.as_str())
            .or_default()
            .push(e.callee.as_str());
    }
    let mut seen: BTreeSet<String> = seeds.clone();
    let mut frontier: Vec<String> = seeds.iter().cloned().collect();
    let mut rounds = 0usize;
    while !frontier.is_empty() {
        rounds += 1;
        let mut next = Vec::new();
        for f in &frontier {
            for &c in adj.get(f.as_str()).map(Vec::as_slice).unwrap_or(&[]) {
                if seen.insert(c.to_string()) {
                    next.push(c.to_string());
                }
            }
        }
        frontier = next;
    }
    (seen, rounds)
}

// ═══════════════════════════════════════════════════════════════════════════
// CSV emission
// ═══════════════════════════════════════════════════════════════════════════

/// Quote one CSV field. `olog`'s reader is a plain split, so a field carrying a
/// comma or a quote must be escaped here; a note copied from a manifest does.
fn csv(field: &str) -> String {
    let needs = field.contains([',', '"', '\n', '\r']);
    if !needs {
        return field.to_string();
    }
    format!("\"{}\"", field.replace('"', "\"\""))
}

fn row(fields: &[&str]) -> String {
    let mut s = String::new();
    for (i, f) in fields.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&csv(f));
    }
    s.push('\n');
    s
}

/// Write every table. Column order is the contract the olog's `mapping = {..}`
/// indices are written against; changing it is a breaking change to
/// `ologs/nucleus_reach.toml` and must be made in both repositories.
///
/// # Ids are integers, and they are EXPORT-LOCAL
///
/// Olog's CSV importer parses the id column as `i64` and skips any row whose id
/// does not parse or is zero (`src/bin/import-crates.rs`), so a qualified-name
/// id imports as nothing at all — silently, since a skipped row is not an
/// error. Every table therefore gets a 1-based integer surrogate.
///
/// Those integers are assigned in emission order and are NOT stable across
/// exports: adding one function shifts every id after it. The stable identity
/// is the qualified name, carried in `name`. Anything that must survive a
/// re-export — a saved query, a cross-repo reference — keys on the name.
pub fn emit(g: &Graph, mechanisms: &[MechanismRow], out: &Path) -> Result<Vec<(String, usize)>> {
    std::fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;

    let mut written = Vec::new();
    let mut write = |name: &str, header: &str, body: String, rows: usize| -> Result<()> {
        let p = out.join(name);
        std::fs::write(&p, format!("{header}\n{body}"))
            .with_context(|| format!("writing {}", p.display()))?;
        written.push((name.to_string(), rows));
        Ok(())
    };

    // ── surrogate id tables ──────────────────────────────────────────
    let mut krates: BTreeSet<&str> = BTreeSet::new();
    for f in &g.fns {
        krates.insert(f.krate.as_str());
    }
    let krate_id: BTreeMap<&str, usize> = krates
        .iter()
        .enumerate()
        .map(|(i, k)| (*k, i + 1))
        .collect();

    let fn_id: BTreeMap<&str, usize> = g
        .fns
        .iter()
        .enumerate()
        .map(|(i, f)| (f.id.as_str(), i + 1))
        .collect();

    let mut kinds: BTreeSet<&str> = BTreeSet::new();
    for (_, kind) in SINKS {
        kinds.insert(kind);
    }
    let sink_id: BTreeMap<&str, usize> =
        kinds.iter().enumerate().map(|(i, k)| (*k, i + 1)).collect();

    let mut ws: BTreeSet<&str> = BTreeSet::new();
    for d in &g.demands {
        ws.insert(d.witness.as_str());
    }
    let witness_id: BTreeMap<&str, usize> =
        ws.iter().enumerate().map(|(i, w)| (*w, i + 1)).collect();

    // A reference that cannot be resolved is written as 0, which the importer
    // treats as absent and the arrow's pullback filter then deletes. Better a
    // visibly dropped row than a dangling one.
    let fk = |m: &BTreeMap<&str, usize>, k: &str| m.get(k).copied().unwrap_or(0).to_string();

    // crates.csv — 0:id 1:name 2:mediated
    let mut body = String::new();
    for k in &krates {
        body.push_str(&row(&[
            &fk(&krate_id, k),
            k,
            &MEDIATED_CRATES.contains(k).to_string(),
        ]));
    }
    write("crates.csv", "id,name,mediated", body, krates.len())?;

    // rust_fns.csv — 0:id 1:name 2:self_ref 3:crate_id 4:file 5:line 6:public
    //
    // `self_ref` repeats the id. It materialises the identity morphism
    // `id_RustFn`, which the olog needs as a real column because its
    // composition machinery derives an edge table from a span of two arrows and
    // has no other way to project the caller side. See the olog's comment.
    let mut body = String::new();
    for f in &g.fns {
        let id = fk(&fn_id, &f.id);
        body.push_str(&row(&[
            &id,
            &f.qualified,
            &id,
            &fk(&krate_id, &f.krate),
            &f.file,
            &f.line.to_string(),
            &f.public.to_string(),
        ]));
    }
    write(
        "rust_fns.csv",
        "id,name,self_ref,crate_id,file,line,public",
        body,
        g.fns.len(),
    )?;

    // call_sites.csv — 0:id 1:name 2:caller_id 3:callee_id 4:resolution 5:file 6:line
    let mut body = String::new();
    for (i, e) in g.edges.iter().enumerate() {
        body.push_str(&row(&[
            &(i + 1).to_string(),
            &format!("{} \u{2192} {}", e.caller, e.callee),
            &fk(&fn_id, &e.caller),
            &fk(&fn_id, &e.callee),
            e.resolution.as_str(),
            &e.file,
            &e.line.to_string(),
        ]));
    }
    write(
        "call_sites.csv",
        "id,name,caller_id,callee_id,resolution,file,line",
        body,
        g.edges.len(),
    )?;

    // sinks.csv — 0:id 1:name 2:kind
    let mut body = String::new();
    for k in &kinds {
        body.push_str(&row(&[&fk(&sink_id, k), k, k]));
    }
    write("sinks.csv", "id,name,kind", body, kinds.len())?;

    // sink_uses.csv — 0:id 1:name 2:fn_id 3:sink_id 4:file 5:line
    let mut body = String::new();
    for (i, s) in g.sink_uses.iter().enumerate() {
        body.push_str(&row(&[
            &(i + 1).to_string(),
            &s.path,
            &fk(&fn_id, &s.fn_id),
            &fk(&sink_id, &s.sink),
            &s.file,
            &s.line.to_string(),
        ]));
    }
    write(
        "sink_uses.csv",
        "id,name,fn_id,sink_id,file,line",
        body,
        g.sink_uses.len(),
    )?;

    // witnesses.csv — 0:id 1:name
    let mut body = String::new();
    for w in &ws {
        body.push_str(&row(&[&fk(&witness_id, w), w]));
    }
    write("witnesses.csv", "id,name", body, ws.len())?;

    // witness_demands.csv — 0:id 1:name 2:fn_id 3:witness_id 4:binding 5:inert 6:file 7:line
    let mut body = String::new();
    for (i, d) in g.demands.iter().enumerate() {
        body.push_str(&row(&[
            &(i + 1).to_string(),
            &format!("{}:{}", d.witness, d.binding),
            &fk(&fn_id, &d.fn_id),
            &fk(&witness_id, &d.witness),
            &d.binding,
            &d.inert.to_string(),
            &d.file,
            &d.line.to_string(),
        ]));
    }
    write(
        "witness_demands.csv",
        "id,name,fn_id,witness_id,binding,inert,file,line",
        body,
        g.demands.len(),
    )?;

    // unresolved_calls.csv — 0:id 1:name 2:fn_id 3:form 4:file 5:line
    let mut body = String::new();
    for (i, u) in g.unresolved.iter().enumerate() {
        body.push_str(&row(&[
            &(i + 1).to_string(),
            &u.detail,
            &fk(&fn_id, &u.fn_id),
            &u.form,
            &u.file,
            &u.line.to_string(),
        ]));
    }
    write(
        "unresolved_calls.csv",
        "id,name,fn_id,form,file,line",
        body,
        g.unresolved.len(),
    )?;

    // The mediation witnesses, split by class into TWO files, because they are
    // two different claims and merging them would destroy both.
    //
    //   unmediated_paths.csv  precise class — every edge on the witnessing path
    //                         has a unique callee. The olog declares this object
    //                         INITIAL: a row here is a finding worth stopping
    //                         for. Empty is a RATCHET over a known-incomplete
    //                         index, never a proof of mediation: the precise
    //                         sub-quiver UNDER-approximates reach, so an empty
    //                         precise class cannot establish that no path
    //                         exists. `mediated` makes that claim; this does not.
    //
    //   mediation_suspicions.csv  ambiguous class — the witness needs a
    //                         name-resolved guess somewhere. A work queue, not a
    //                         verdict, and emphatically NOT declared initial.
    //
    // Putting the 159 ambiguous rows into the initial object would make the
    // invariant permanently red and teach everyone to ignore it, which is the
    // failure mode this whole exercise is about.
    let witnesses = unmediated_paths(g);
    let (precise, suspicions): (Vec<_>, Vec<_>) =
        witnesses.iter().partition(|u| u.class == "precise");

    let emit_witnesses = |rows: &[&UnmediatedPath]| -> String {
        let mut body = String::new();
        for (i, u) in rows.iter().enumerate() {
            body.push_str(&row(&[
                &(i + 1).to_string(),
                &format!("{} \u{2192} {} ({})", u.entry, u.via, u.sink),
                &fk(&fn_id, &u.entry),
                &fk(&fn_id, &u.via),
                &fk(&sink_id, &u.sink),
                u.class,
                &u.depth.to_string(),
            ]));
        }
        body
    };

    // unmediated_paths.csv — 0:id 1:name 2:fn_id 3:via_fn_id 4:sink_id 5:class 6:depth
    let body = emit_witnesses(&precise);
    write(
        "unmediated_paths.csv",
        "id,name,fn_id,via_fn_id,sink_id,class,depth",
        body,
        precise.len(),
    )?;

    // mediation_suspicions.csv — same columns, deliberately a separate table.
    let body = emit_witnesses(&suspicions);
    write(
        "mediation_suspicions.csv",
        "id,name,fn_id,via_fn_id,sink_id,class,depth",
        body,
        suspicions.len(),
    )?;

    // mechanisms.csv — 0:id 1:name 2:law 3:class 4:file 5:decl_anchor 6:use_anchor 7:manifest 8:note
    let mut body = String::new();
    for (i, m) in mechanisms.iter().enumerate() {
        body.push_str(&row(&[
            &(i + 1).to_string(),
            &m.name,
            &m.law,
            &m.class,
            &m.file,
            &m.decl_anchor,
            &m.use_anchor,
            &m.manifest,
            &m.note,
        ]));
    }
    write(
        "mechanisms.csv",
        "id,name,law,class,file,decl_anchor,use_anchor,manifest,note",
        body,
        mechanisms.len(),
    )?;

    Ok(written)
}

/// A row from one of the three hand-maintained reach ledgers, normalised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MechanismRow {
    pub id: String,
    pub name: String,
    pub law: String,
    pub class: String,
    pub file: String,
    pub decl_anchor: String,
    pub use_anchor: String,
    pub manifest: String,
    pub note: String,
}

/// Read `scripts/law-mechanisms-manifest.txt` through that gate's own parser, so
/// the export cannot disagree with the gate about what a row means.
pub fn mechanisms(root: &Path) -> Result<Vec<MechanismRow>> {
    let p = root.join("scripts/law-mechanisms-manifest.txt");
    let text = std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
    let manifest = law_mechanisms::parse(&text)?;
    Ok(manifest
        .rows
        .iter()
        .map(|r| MechanismRow {
            id: r.mechanism.clone(),
            name: r.mechanism.clone(),
            law: r.law.clone(),
            class: r.class.to_string(),
            file: r.file.clone(),
            decl_anchor: r.decl_anchor.clone(),
            use_anchor: r.use_anchor.clone(),
            manifest: "law-mechanisms".to_string(),
            note: r.note.clone(),
        })
        .collect())
}

/// Assert the mirrored [`SINKS`] and [`MEDIATED_CRATES`] still match the lint.
///
/// A mirror that drifts is worse than no mirror: the olog would show a reach
/// picture over a deny-set the enforcing gate no longer uses. This reads the
/// lint source and compares literals, which is why the mirror is allowed to
/// exist at all.
pub fn check_sink_parity(root: &Path) -> Result<()> {
    let p = root.join(LINT_SRC);
    let src = std::fs::read_to_string(&p)
        .with_context(|| format!("reading {} for deny-set parity", p.display()))?;
    let mut missing = Vec::new();
    for (prefix, _) in SINKS {
        if !src.contains(&format!("\"{prefix}\"")) {
            missing.push((*prefix).to_string());
        }
    }
    for k in MEDIATED_CRATES {
        if !src.contains(&format!("\"{k}\"")) {
            missing.push((*k).to_string());
        }
    }
    if !missing.is_empty() {
        bail!(
            "deny-set mirror has drifted from {LINT_SRC}: {} no longer appears there. \
             The export would index a reach picture the enforcing gate does not use.",
            missing.join(", ")
        );
    }
    // The reverse direction: a prefix the lint gained and this did not.
    let lint_entries = extract_list(&src, "const DENY_SET: &[&str] = &[");
    for e in &lint_entries {
        if !SINKS.iter().any(|(p, _)| p == e) {
            bail!(
                "{LINT_SRC} declares deny-set entry {e:?} that this exporter's SINKS lacks. \
                 A sink the index cannot see is a sink whose reach it under-reports."
            );
        }
    }
    Ok(())
}

/// Pull the string literals out of a `const NAME: &[&str] = &[ .. ];` block.
fn extract_list(src: &str, opener: &str) -> Vec<String> {
    let Some(start) = src.find(opener) else {
        return Vec::new();
    };
    let rest = &src[start + opener.len()..];
    let Some(end) = rest.find("];") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut chars = rest[..end].chars().peekable();
    while let Some(c) = chars.next() {
        if c != '"' {
            continue;
        }
        let mut lit = String::new();
        for c in chars.by_ref() {
            if c == '"' {
                break;
            }
            lit.push(c);
        }
        out.push(lit);
    }
    out
}

// ═══════════════════════════════════════════════════════════════════════════
// Entry point
// ═══════════════════════════════════════════════════════════════════════════

/// Run the export. Returns `0` unless the export itself failed — this indexes,
/// it does not decide.
pub fn run(out_dir: &str, report: bool) -> Result<i32> {
    let root = std::env::current_dir()?;
    check_sink_parity(&root)?;

    let witnesses = witness_types(&root)?;
    let corpus = tracked(is_production_path)?;
    let g = build(&corpus, &witnesses);
    let mechs = mechanisms(&root)?;

    let out = root.join(out_dir);
    let written = emit(&g, &mechs, &out)?;

    println!("reach-export → {}", out.display());
    for (name, n) in &written {
        println!("  {name:<22} {n:>7} rows");
    }

    if !g.unparsed.is_empty() {
        println!(
            "\n  {} file(s) syn could not parse — each contributes no edges, \
             so reach is under-reported by whatever they call:",
            g.unparsed.len()
        );
        for p in &g.unparsed {
            println!("    {p}");
        }
    }

    if report {
        print_report(&g, &mechs);
    }
    Ok(0)
}

fn print_report(g: &Graph, mechs: &[MechanismRow]) {
    println!("\n── resolution classes ──");
    let mut per: BTreeMap<&str, usize> = BTreeMap::new();
    for e in &g.edges {
        *per.entry(e.resolution.as_str()).or_default() += 1;
    }
    for (k, v) in &per {
        println!("  {k:<18} {v:>7}");
    }
    let mut forms: BTreeMap<&str, usize> = BTreeMap::new();
    for u in &g.unresolved {
        *forms.entry(u.form.as_str()).or_default() += 1;
    }
    for (k, v) in &forms {
        println!("  {k:<18} {v:>7}  (unresolved — recorded, not dropped)");
    }

    // The bracket: reach over precise edges only vs. reach over every edge.
    let sink_fns: BTreeSet<String> = g.sink_uses.iter().map(|s| s.fn_id.clone()).collect();
    let entry: BTreeSet<String> = g
        .fns
        .iter()
        .filter(|f| f.public)
        .map(|f| f.id.clone())
        .collect();
    let (lo, lo_rounds) = reach(&g.edges, &entry, |e| e.resolution.is_precise());
    let (hi, hi_rounds) = reach(&g.edges, &entry, |_| true);
    let lo_hits = lo.intersection(&sink_fns).count();
    let hi_hits = hi.intersection(&sink_fns).count();

    println!("\n── reach from public functions ──");
    println!(
        "  precise edges only : {:>7} fns, {lo_rounds} rounds to saturation",
        lo.len()
    );
    println!(
        "  every edge         : {:>7} fns, {hi_rounds} rounds to saturation",
        hi.len()
    );
    println!(
        "  sink-performing fns reached: {lo_hits} (lower bound) .. {hi_hits} (upper bound) \
         of {} that perform one",
        sink_fns.len()
    );
    println!(
        "\n  A SQL `WITH RECURSIVE .. WHERE depth < N` over this edge table must use \
         N > {hi_rounds}, or it under-reports reach — which for a containment question \
         is a false clean."
    );

    println!("\n── complete mediation, as a row count ──");
    let um = unmediated_paths(g);
    let mediating = g
        .demands
        .iter()
        .filter(|d| d.witness == "Authority" && d.binding == "by_value")
        .count();
    println!(
        "  {} by-value Authority demand(s) discharge the obligation; seeds are public fns in {:?}",
        mediating, MEDIATED_CRATES
    );
    if um.is_empty() {
        println!(
            "  0 unmediated witnesses. That is THIS INDEX finding none, not a proof: `mediated` \
             has the types and this does not."
        );
    } else {
        let precise = um.iter().filter(|u| u.class == "precise").count();
        println!(
            "  {} unmediated witness(es) — {precise} in the precise class, {} only via \
             ambiguous name resolution:",
            um.len(),
            um.len() - precise
        );
        for u in um.iter().take(12) {
            println!(
                "    [{}] {} → {} ({}, depth {})",
                u.class, u.entry, u.via, u.sink, u.depth
            );
        }
        if um.len() > 12 {
            println!("    .. and {} more", um.len() - 12);
        }
    }

    println!("\n── the hand-maintained ledgers, as queries ──");

    // A law-mechanism row names either a function or a type. This index is a
    // CALL graph, so it can answer the reach question for the former and not
    // the latter — a type's "use" is a construction or a trait impl, not a
    // call. Reporting both under one number would look like a disagreement
    // with the gate when it is a scope boundary, so they are split.
    let mut fn_rows = 0usize;
    let mut fn_rows_wired = 0usize;
    let mut fn_rows_unseen = Vec::new();
    let mut type_rows = 0usize;
    for m in mechs {
        if !m.decl_anchor.contains("fn ") {
            type_rows += 1;
            continue;
        }
        fn_rows += 1;
        let declared: Vec<&FnNode> = g
            .fns
            .iter()
            .filter(|f| f.file == m.file && m.decl_anchor.ends_with(&f.name))
            .collect();
        if declared.is_empty() {
            fn_rows_unseen.push(m.name.as_str());
            continue;
        }
        if declared
            .iter()
            .any(|d| g.edges.iter().any(|e| e.callee == d.id))
        {
            fn_rows_wired += 1;
        }
    }
    println!(
        "  law-mechanisms: {} rows declared dead — {type_rows} name a TYPE (out of a call \
         graph's scope: a type is constructed, not called) and {fn_rows} name a function.",
        mechs.len()
    );
    println!(
        "  Of the {fn_rows} function rows, this index finds an inbound production call edge \
         for {fn_rows_wired}. The gate says zero, by construction — a row only exists while \
         its use-anchor appears nowhere."
    );
    if !fn_rows_unseen.is_empty() {
        println!(
            "  {} function row(s) whose declaring fn this index could not locate: {}. \
             That is this index failing, not the gate.",
            fn_rows_unseen.len(),
            fn_rows_unseen.join(", ")
        );
    }
    if fn_rows_wired > 0 {
        println!(
            "  A non-zero count above is exactly what read-only mode is for: either a \
             name-resolved edge is spurious (ambiguity picked the wrong callee) or the \
             gate's string anchor misses a real call. Reconcile by hand before wiring."
        );
    }

    let inert = g.demands.iter().filter(|d| d.inert).count();
    println!(
        "\n  witness demands: {} total, {inert} `_`-bound. \
         `scripts/inert-authority-manifest.txt` pins INERT_TOTAL; a different number here \
         means the two scans disagree about scope, not that the tree changed. That gate \
         counts per (file, impl target) and excludes the `Seal` family on purpose.",
        g.demands.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-crate corpus, so the whole build is testable without a checkout —
    /// `law_mechanisms::decide`'s reason for taking its corpus as an argument.
    fn corpus(files: &[(&str, &str)]) -> BTreeMap<String, String> {
        files
            .iter()
            .map(|(p, s)| ((*p).to_string(), (*s).to_string()))
            .collect()
    }

    fn ws() -> Vec<String> {
        ["Authority", "SessionCleanseToken"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn cfg_test_items_are_excluded_exactly() {
        let g = build(
            &corpus(&[(
                "crates/demo/src/lib.rs",
                r#"
                pub fn live() {}
                #[cfg(test)]
                mod tests { pub fn dead() {} }
                #[cfg(all(test, feature = "x"))]
                pub fn also_dead() {}
                "#,
            )]),
            &ws(),
        );
        let names: BTreeSet<&str> = g.fns.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains("live"));
        assert!(!names.contains("dead"), "#[cfg(test)] mod must be skipped");
        assert!(
            !names.contains("also_dead"),
            "cfg(all(test, ..)) must be skipped: brace-counting missed this shape"
        );
    }

    #[test]
    fn sink_is_seen_through_a_use_alias() {
        let g = build(
            &corpus(&[(
                "crates/demo/src/lib.rs",
                r#"
                use std::process::Command;
                pub fn spawn() { let _ = Command::new("sh"); }
                "#,
            )]),
            &ws(),
        );
        assert_eq!(g.sink_uses.len(), 1, "the use alias must be expanded");
        assert_eq!(g.sink_uses[0].sink, "process");
        assert_eq!(g.sink_uses[0].path, "std::process::Command::new");
    }

    #[test]
    fn a_glob_import_hides_its_sink_and_that_is_recorded_as_a_limit() {
        // Not an aspiration — an assertion that the known hole behaves as the
        // module docs say, so a future change that silently "fixes" it by
        // guessing is caught.
        let g = build(
            &corpus(&[(
                "crates/demo/src/lib.rs",
                r#"
                use std::process::*;
                pub fn spawn() { let _ = Command::new("sh"); }
                "#,
            )]),
            &ws(),
        );
        assert!(
            g.sink_uses.is_empty(),
            "a glob import is not recorded, so this sink is missed — documented, not fixed"
        );
    }

    #[test]
    fn self_qualified_calls_produce_an_edge() {
        // THE REGRESSION THIS WHOLE EXPORT EARNED ITS KEEP ON.
        //
        // `scripts/law-mechanisms-manifest.txt` declares `Kernel::with_isolation`
        // dead with use-anchor `Kernel::with_isolation(`, and the gate agrees —
        // but `crates/portcullis/src/kernel.rs:590` calls it as
        // `Self::with_isolation(..)` from `Kernel::new`, which the anchor cannot
        // match. A call graph sees the edge the string does not.
        let g = build(
            &corpus(&[(
                "crates/demo/src/lib.rs",
                r#"
                pub struct Kernel;
                impl Kernel {
                    pub fn new() -> Self { Self::with_isolation() }
                    pub fn with_isolation() -> Self { Kernel }
                }
                "#,
            )]),
            &ws(),
        );
        let target = g
            .fns
            .iter()
            .find(|f| f.name == "with_isolation")
            .expect("declaration");
        assert!(
            g.edges.iter().any(|e| e.callee == target.id),
            "`Self::with_isolation()` must yield an inbound edge; a string anchor \
             spelled `Kernel::with_isolation(` does not see this call"
        );
    }

    #[test]
    fn resolution_classes_partition_by_precision() {
        let g = build(
            &corpus(&[
                (
                    "crates/a/src/lib.rs",
                    r#"
                    pub fn only_one_of_these() {}
                    pub fn shared() {}
                    pub fn caller() { only_one_of_these(); shared(); }
                    "#,
                ),
                ("crates/b/src/lib.rs", "pub fn shared() {}"),
            ]),
            &ws(),
        );
        let by = |n: &str| {
            g.edges
                .iter()
                .find(|e| e.callee.ends_with(n))
                .map(|e| e.resolution)
        };
        assert_eq!(by("only_one_of_these"), Some(Resolution::UniqueWorkspace));
        // `shared` exists in both crates; the caller's crate disambiguates.
        assert_eq!(by("shared"), Some(Resolution::SameCrate));
    }

    #[test]
    fn ambiguity_over_approximates_rather_than_dropping_edges() {
        // Two same-crate candidates and no disambiguator: EVERY candidate gets
        // an edge. Dropping one would under-report reach, which for a
        // containment question is the unsound direction.
        let g = build(
            &corpus(&[(
                "crates/a/src/lib.rs",
                r#"
                pub struct X; pub struct Y;
                impl X { pub fn go() {} }
                impl Y { pub fn go() {} }
                pub fn caller(v: X) { v.go(); }
                "#,
            )]),
            &ws(),
        );
        let n = g
            .edges
            .iter()
            .filter(|e| e.callee.ends_with("::go") && e.resolution == Resolution::Ambiguous)
            .count();
        assert_eq!(n, 2, "both candidates must get an edge, not one or neither");
    }

    #[test]
    fn a_name_matching_nothing_is_recorded_not_dropped() {
        let g = build(
            &corpus(&[(
                "crates/a/src/lib.rs",
                "pub fn caller() { some_external_thing(); }",
            )]),
            &ws(),
        );
        assert!(g.edges.is_empty());
        assert_eq!(g.unresolved.len(), 1);
        assert_eq!(g.unresolved[0].form, "no_declaration");
        assert_eq!(g.unresolved[0].detail, "some_external_thing");
    }

    #[test]
    fn a_dynamic_callee_is_recorded_not_dropped() {
        let g = build(
            &corpus(&[("crates/a/src/lib.rs", "pub fn caller(f: fn()) { (f)(); }")]),
            &ws(),
        );
        assert!(
            g.unresolved.iter().any(|u| u.form == "dynamic_call"),
            "a call through a binding defeats static resolution and must surface as work"
        );
    }

    #[test]
    fn witness_binding_and_inertness_are_distinguished() {
        let g = build(
            &corpus(&[(
                "crates/a/src/lib.rs",
                r#"
                pub fn spends(a: Authority) { let _ = a; }
                pub fn drops(_a: Authority) {}
                pub fn borrows(_t: &SessionCleanseToken) {}
                "#,
            )]),
            &ws(),
        );
        let find = |n: &str| g.demands.iter().find(|d| d.fn_id.ends_with(n)).unwrap();
        assert_eq!(find("spends").binding, "by_value");
        assert!(!find("spends").inert);
        assert!(
            find("drops").inert,
            "`_`-bound is the inert-authority shape"
        );
        assert_eq!(find("borrows").binding, "by_ref");
        assert!(find("borrows").inert);
    }

    #[test]
    fn trait_method_signatures_count_even_with_no_body() {
        // `inert-authority` finds `_`-bound parameters in bodyless trait
        // declarations (`trait ShellEffect`, `NetEffect`), so they must be here.
        let g = build(
            &corpus(&[(
                "crates/a/src/lib.rs",
                "pub trait ShellEffect { fn run(&self, _a: Authority); }",
            )]),
            &ws(),
        );
        assert_eq!(g.demands.len(), 1);
        assert!(g.demands[0].inert);
    }

    #[test]
    fn reach_saturates_and_is_monotone_in_the_admitted_edges() {
        let e = |c: &str, d: &str, r: Resolution| CallEdge {
            caller: c.to_string(),
            callee: d.to_string(),
            resolution: r,
            file: "f".into(),
            line: 1,
        };
        let edges = vec![
            e("a", "b", Resolution::UniqueWorkspace),
            e("b", "c", Resolution::UniqueWorkspace),
            e("c", "d", Resolution::Ambiguous),
            // A cycle: saturation must terminate regardless.
            e("d", "a", Resolution::Ambiguous),
        ];
        let seeds: BTreeSet<String> = ["a".to_string()].into_iter().collect();
        let (lo, lo_rounds) = reach(&edges, &seeds, |e| e.resolution.is_precise());
        let (hi, _) = reach(&edges, &seeds, |_| true);
        assert_eq!(lo.len(), 3, "precise edges reach a,b,c");
        assert_eq!(hi.len(), 4, "every edge reaches a,b,c,d");
        assert!(
            lo.is_subset(&hi),
            "reach must be monotone along the sub-quiver inclusion — the bracket \
             claim in the module docs depends on it"
        );
        assert!(lo_rounds >= 1);
    }

    #[test]
    fn reach_over_a_cycle_terminates() {
        let e = |c: &str, d: &str| CallEdge {
            caller: c.to_string(),
            callee: d.to_string(),
            resolution: Resolution::UniqueWorkspace,
            file: "f".into(),
            line: 1,
        };
        let edges = vec![e("a", "b"), e("b", "a")];
        let seeds: BTreeSet<String> = ["a".to_string()].into_iter().collect();
        let (seen, _) = reach(&edges, &seeds, |_| true);
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn csv_escapes_the_fields_a_manifest_note_actually_contains() {
        assert_eq!(csv("plain"), "plain");
        assert_eq!(csv("a,b"), "\"a,b\"");
        assert_eq!(csv("say \"hi\""), "\"say \"\"hi\"\"\"");
        // Manifest notes are prose with commas; an unescaped one would shift
        // every later column in the olog's positional `mapping = {..}`.
        assert!(csv("the sandbox root. All 11 callers are tests, three of them").starts_with('"'));
    }

    #[test]
    fn extract_list_reads_the_deny_set_form() {
        let src =
            "const DENY_SET: &[&str] = &[\n  \"std::fs::\",\n  // comment\n  \"reqwest::\",\n];\n";
        assert_eq!(
            extract_list(src, "const DENY_SET: &[&str] = &["),
            vec!["std::fs::".to_string(), "reqwest::".to_string()]
        );
    }

    #[test]
    fn crate_name_uses_the_lib_crate_spelling() {
        assert_eq!(
            crate_of("crates/portcullis-effects/src/lib.rs").as_deref(),
            Some("portcullis_effects")
        );
        assert_eq!(crate_of("tools/x/src/lib.rs"), None);
    }

    #[test]
    fn the_mirrored_deny_set_matches_the_lint() {
        // The mirror's whole licence to exist. Run from the repo root, which is
        // where `cargo test` puts a workspace member's CWD via CARGO_MANIFEST_DIR.
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root")
            .to_path_buf();
        check_sink_parity(&root).expect("SINKS must agree with the mediation lint");
    }

    #[test]
    fn a_file_that_does_not_parse_is_a_finding_not_a_silence() {
        let g = build(
            &corpus(&[("crates/a/src/lib.rs", "pub fn broken( {")]),
            &ws(),
        );
        assert_eq!(g.unparsed, vec!["crates/a/src/lib.rs".to_string()]);
    }

    #[test]
    fn declaration_lines_are_real() {
        let g = build(
            &corpus(&[("crates/a/src/lib.rs", "\n\npub fn third_line() {}")]),
            &ws(),
        );
        assert_eq!(
            g.fns[0].line, 3,
            "span-locations must be on, or the CSV cannot be navigated to source"
        );
    }

    #[test]
    fn every_emitted_id_is_an_integer_the_importer_will_accept() {
        // olog's CSV importer parses the id column as i64 and SKIPS any row it
        // cannot parse, or whose id is 0 — silently, because a skipped row is
        // not an error. The first version of this exporter emitted qualified
        // names as ids and every single table imported as empty, through a
        // pipeline that reported success at every phase. Hence this test.
        let g = build(
            &corpus(&[(
                "crates/demo/src/lib.rs",
                r#"
                use std::process::Command;
                pub fn a(_x: Authority) { b(); let _ = Command::new("sh"); }
                pub fn b() {}
                "#,
            )]),
            &ws(),
        );
        let dir = std::env::temp_dir().join(format!("reach-export-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        emit(&g, &[], &dir).expect("emit");

        for file in [
            "crates.csv",
            "rust_fns.csv",
            "call_sites.csv",
            "sinks.csv",
            "sink_uses.csv",
            "witnesses.csv",
            "witness_demands.csv",
            "unresolved_calls.csv",
        ] {
            let text = std::fs::read_to_string(dir.join(file)).expect(file);
            let mut rows = 0;
            for line in text.lines().skip(1).filter(|l| !l.is_empty()) {
                let id = line.split(',').next().unwrap();
                let n: i64 = id
                    .parse()
                    .unwrap_or_else(|_| panic!("{file}: id {id:?} does not parse as i64"));
                assert!(n > 0, "{file}: id {n} is zero, which the importer drops");
                rows += 1;
            }
            assert!(
                rows > 0,
                "{file} emitted no rows; the test would be vacuous"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn foreign_keys_point_at_ids_that_exist() {
        // The join `v.id = d.caller_id` is the whole edge table. A FK that
        // names no row makes the composition silently smaller, which reads as
        // "less reach" — the unsound direction.
        let g = build(
            &corpus(&[(
                "crates/demo/src/lib.rs",
                "pub fn a() { b(); }\npub fn b() {}",
            )]),
            &ws(),
        );
        let dir = std::env::temp_dir().join(format!("reach-fk-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        emit(&g, &[], &dir).expect("emit");

        let fns = std::fs::read_to_string(dir.join("rust_fns.csv")).unwrap();
        let ids: BTreeSet<&str> = fns
            .lines()
            .skip(1)
            .filter(|l| !l.is_empty())
            .map(|l| l.split(',').next().unwrap())
            .collect();
        let calls = std::fs::read_to_string(dir.join("call_sites.csv")).unwrap();
        let mut checked = 0;
        for line in calls.lines().skip(1).filter(|l| !l.is_empty()) {
            let c: Vec<&str> = line.split(',').collect();
            assert!(ids.contains(c[2]), "caller_id {:?} names no rust_fn", c[2]);
            assert!(ids.contains(c[3]), "callee_id {:?} names no rust_fn", c[3]);
            checked += 1;
        }
        assert!(checked > 0, "no edges emitted; the test would be vacuous");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_identity_column_equals_the_id() {
        // `self_ref` IS id_RustFn. If the two ever diverge, the `calls_*`
        // compositions project the wrong caller and every edge is wrong in a
        // way no count would reveal.
        let g = build(
            &corpus(&[("crates/demo/src/lib.rs", "pub fn a() {}")]),
            &ws(),
        );
        let dir = std::env::temp_dir().join(format!("reach-self-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        emit(&g, &[], &dir).expect("emit");
        let fns = std::fs::read_to_string(dir.join("rust_fns.csv")).unwrap();
        for line in fns.lines().skip(1).filter(|l| !l.is_empty()) {
            let c: Vec<&str> = line.split(',').collect();
            assert_eq!(c[0], c[2], "self_ref must equal id");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ─── Complete mediation, as a row count ────────────────────────
    //
    // These pin `mediated`'s rule as this index reimplements it. Where the two
    // disagree, `mediated` is right — it has the types — but a silent
    // disagreement is worthless, so each rule gets a test.

    fn effects(src: &str) -> BTreeMap<String, String> {
        corpus(&[("crates/portcullis-effects/src/lib.rs", src)])
    }

    #[test]
    fn a_public_fn_reaching_a_sink_with_no_authority_is_a_witness() {
        let g = build(
            &effects(
                r#"
                use std::process::Command;
                pub fn run() { let _ = Command::new("sh"); }
                "#,
            ),
            &ws(),
        );
        let um = unmediated_paths(&g);
        assert_eq!(um.len(), 1, "got {um:?}");
        assert_eq!(um[0].sink, "process");
        assert_eq!(um[0].depth, 0, "the entry performs the I/O itself");
        assert_eq!(um[0].class, "precise");
    }

    #[test]
    fn a_by_value_authority_discharges_the_obligation() {
        let g = build(
            &effects(
                r#"
                use std::process::Command;
                pub fn run(a: Authority) { let _ = a; let _ = Command::new("sh"); }
                "#,
            ),
            &ws(),
        );
        assert!(
            unmediated_paths(&g).is_empty(),
            "an Authority demanded by value is exactly what mediation means"
        );
    }

    #[test]
    fn a_by_reference_authority_does_not_discharge_it() {
        // `mediated` keys on the type appearing BY VALUE. A reference is not a
        // spent witness, and the inert-authority gate exists because that
        // distinction has already cost this tree a real defect.
        let g = build(
            &effects(
                r#"
                use std::process::Command;
                pub fn run(a: &Authority) { let _ = a; let _ = Command::new("sh"); }
                "#,
            ),
            &ws(),
        );
        assert_eq!(
            unmediated_paths(&g).len(),
            1,
            "a by-ref Authority must NOT count as mediation"
        );
    }

    #[test]
    fn a_mediating_node_on_the_path_blocks_the_witness() {
        // `do_io` is deliberately PRIVATE. A public function that performs I/O
        // is its own seed and its own witness at depth 0 — which is correct, and
        // which would mask what this test is actually about.
        let g = build(
            &effects(
                r#"
                use std::process::Command;
                pub fn entry() { gate(make()); }
                pub fn make() -> Authority { todo!() }
                pub fn gate(a: Authority) { let _ = a; do_io(); }
                fn do_io() { let _ = Command::new("sh"); }
                "#,
            ),
            &ws(),
        );
        assert!(
            unmediated_paths(&g).is_empty(),
            "traversal must not pass THROUGH a node that demands an authority; got {:?}",
            unmediated_paths(&g)
        );
    }

    #[test]
    fn a_public_sink_performer_is_its_own_witness_even_behind_a_gate() {
        // The companion to the test above, because the reason that fixture had
        // to use a private function is itself a rule worth asserting: `mediated`
        // reports a PUBLICLY REACHABLE function that reaches a sink, and a
        // public one reaches itself. Gating its only caller does not help.
        let g = build(
            &effects(
                r#"
                use std::process::Command;
                pub fn entry() { gate(); }
                pub fn gate(a: Authority) { let _ = a; do_io(); }
                pub fn do_io() { let _ = Command::new("sh"); }
                "#,
            ),
            &ws(),
        );
        let um = unmediated_paths(&g);
        assert_eq!(um.len(), 1, "got {um:?}");
        assert!(um[0].entry.ends_with("::do_io"));
        assert_eq!(um[0].depth, 0);
    }

    #[test]
    fn a_non_mediating_hop_does_not_block_it() {
        // The mirror of the test above: same shape, no Authority, so the
        // witness must appear. Without this, the blocking test would pass on a
        // function that simply never finds anything.
        let g = build(
            &effects(
                r#"
                use std::process::Command;
                pub fn entry() { hop(); }
                fn hop() { do_io(); }
                fn do_io() { let _ = Command::new("sh"); }
                "#,
            ),
            &ws(),
        );
        let um = unmediated_paths(&g);
        assert!(
            um.iter()
                .any(|u| u.entry.ends_with("::entry") && u.depth == 2),
            "expected an entry→hop→sink witness at depth 2, got {um:?}"
        );
    }

    #[test]
    fn the_seed_scope_is_public_fns_in_a_mediated_crate() {
        // Two halves of one rule, so neither can be dropped silently.
        let private = build(
            &effects(
                r#"
                use std::process::Command;
                fn run() { let _ = Command::new("sh"); }
                "#,
            ),
            &ws(),
        );
        assert!(
            unmediated_paths(&private).is_empty(),
            "a private fn is not a public entry point"
        );

        let elsewhere = build(
            &corpus(&[(
                "crates/nucleus-audit/src/lib.rs",
                r#"
                use std::process::Command;
                pub fn run() { let _ = Command::new("sh"); }
                "#,
            )]),
            &ws(),
        );
        assert!(
            unmediated_paths(&elsewhere).is_empty(),
            "`mediated` enforces a DEFINED crate set; widening it means adding a \
             crate in the open, in both places, not finding one here"
        );
    }

    #[test]
    fn each_entry_and_sink_pair_yields_one_row_and_precise_wins() {
        // The precise pass runs first so a witness present in both classes is
        // reported as precise. Reporting it twice, or as ambiguous, would make
        // the initial object red for a finding the strict graph already has.
        let g = build(
            &effects(
                r#"
                use std::process::Command;
                pub fn entry() { sink(); }
                pub fn sink() { let _ = Command::new("sh"); let _ = Command::new("ls"); }
                "#,
            ),
            &ws(),
        );
        let um = unmediated_paths(&g);
        let procs: Vec<_> = um
            .iter()
            .filter(|u| u.entry.ends_with("::entry") && u.sink == "process")
            .collect();
        assert_eq!(procs.len(), 1, "one row per (entry, sink), got {procs:?}");
        assert_eq!(procs[0].class, "precise");
    }

    #[test]
    fn the_two_witness_files_are_disjoint_and_the_initial_one_holds_only_precise() {
        // The whole split. Merging them would make the invariant permanently
        // red and teach everyone to ignore it.
        let g = build(
            &effects(
                r#"
                use std::process::Command;
                pub fn entry() { let _ = Command::new("sh"); }
                "#,
            ),
            &ws(),
        );
        let dir = std::env::temp_dir().join(format!("reach-med-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        emit(&g, &[], &dir).expect("emit");

        let read = |f: &str| -> Vec<String> {
            std::fs::read_to_string(dir.join(f))
                .unwrap()
                .lines()
                .skip(1)
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect()
        };
        let init = read("unmediated_paths.csv");
        let susp = read("mediation_suspicions.csv");
        assert!(
            !init.is_empty(),
            "the fixture must produce a precise witness"
        );
        for line in &init {
            assert!(
                line.contains(",precise,"),
                "the initial object may hold ONLY precise-class rows: {line}"
            );
        }
        for line in &susp {
            assert!(
                line.contains(",ambiguous,"),
                "the suspicion queue may hold ONLY ambiguous-class rows: {line}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

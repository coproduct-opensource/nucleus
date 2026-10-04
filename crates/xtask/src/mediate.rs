//! The `mediate` family — how much of what an agent can call is SEALED.
//!
//! # The claim this counts
//!
//! "Complete mediation": every operation an agent can invoke passes a decision
//! before it acts. `portcullis_effects` makes the strongest version of that a
//! type: its effect methods take an `Authority` **by value**, and an `Authority`
//! is minted only from the `DischargedBundle` a `run_gate::preflight_*` returns.
//! A handler holding one reached the effect through the decision; there is no
//! other way to call the method.
//!
//! Not every agent-reachable operation is built that way. Some reach their
//! effect after a runtime decision that returns nothing the effect needs — the
//! kernel said yes, and the code that acts could have run without asking. That
//! is mediation that holds today and is one refactor from not holding. Some
//! reach no decision at all.
//!
//! # The unit
//!
//! One **agent-reachable entry point**: an HTTP route on the tool-proxy router,
//! or an MCP tool (`#[tool]` in `mcp.rs`). Not a raw effect call: measured
//! 2026-09-27, every production `std::fs`/`tokio::fs` call in the tool-proxy is
//! the proxy's own configuration and state (certs, policy file, socket URLs),
//! none directed by the agent, so a sink count would be large and meaningless.
//!
//! Each entry point is classified by its handler body into a [`Tier`]:
//!
//! * **Sealed** — the handler mints an `Authority`, so its effect is reached
//!   through a preflight by construction.
//! * **Checked** — a runtime decision is on the path (a kernel decider or a
//!   `run_gate::preflight_*` in the body, the auth middleware's
//!   `run_gate::endpoint_operation` ceiling, or a declared authority of its own
//!   such as a verified signature), but nothing it returns is needed to act.
//! * **Unchecked** — none of those.
//!
//! **discharged** = Sealed. **population** = every entry point except those
//! declared [`NOT_AN_EFFECT`], which are reported as **undeclared**: shape
//! without obligation, printed so the exclusion is visible rather than silent.
//!
//! # What this does not measure
//!
//! Wiring, not correctness: whether the decision is RIGHT is the kernel's
//! proofs' and tests' business. Nor the guest-isolation leg — that the pod can
//! reach the world only through this proxy is a property of the VM and its
//! network namespace, evidenced by the live `nucleus-perf agency` harness, not
//! by source. And the body scan is one level deep: a handler that delegates its
//! whole decision to a helper reads as the helper's absence. Every current
//! handler decides inline; a delegating one would read LOW, which is the safe
//! direction.

use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use syn::visit::Visit;

use crate::scorecard::{Census, Family};

const SRC: &str = "crates/nucleus-tool-proxy/src";
/// The router is built here.
const ROUTER: &str = "crates/nucleus-tool-proxy/src/main.rs";
/// The MCP tools are declared here.
const MCP: &str = "crates/nucleus-tool-proxy/src/mcp.rs";
/// `endpoint_operation` — the auth middleware's per-route ceiling — lives here.
const RUN_GATE: &str = "crates/nucleus-tool-proxy/src/run_gate.rs";

/// The dedicated badge. The scorecard's flagless run keeps it fresh.
pub const BADGE: &str = "ci/badges/mediation.json";

/// Entry points that are not agent-directed effects: `(entry, why)`.
///
/// Excluded from the population by name, with the reason on the record. A row
/// naming an entry the router no longer has is refused, so this cannot rot into
/// a list of exemptions for routes that are gone.
pub const NOT_AN_EFFECT: &[(&str, &str)] = &[
    (
        "http /v1/health",
        "liveness probe: names no path, host or command",
    ),
    (
        "http /v1/workload/result",
        "the pod's own workload outcome, written by the supervisor; takes no agent-named resource",
    ),
    (
        "http /v1/workload/logs/stdout",
        "the pod's own workload output, written by the supervisor; takes no agent-named resource",
    ),
    (
        "http /v1/workload/logs/stderr",
        "the pod's own workload output, written by the supervisor; takes no agent-named resource",
    ),
];

/// Entry points whose authority is not the kernel ceiling but a check of their
/// own: `(entry, file, evidence, why)`.
///
/// Counted Checked only while `evidence` still appears in `file` — the
/// anti-over-claim rule `typed` applies to its registry: a row cannot buy a tier
/// without the mechanism behind it.
pub const OWN_AUTHORITY: &[(&str, &str, &str, &str)] = &[
    (
        "http /v1/approve",
        ROUTER,
        "AuthTier::ApprovalEd25519Drand",
        "the auth middleware sends this path to the approval-signature tier",
    ),
    (
        "http /v1/declassify",
        "crates/nucleus-tool-proxy/src/declassify.rs",
        "verify_declassification",
        "the kernel verifies the governor's signed declassification token and mints the witness the graph spends",
    ),
    (
        "http /v1/escalate",
        "crates/nucleus-tool-proxy/src/escalate.rs",
        "verify_detailed",
        "the approver's SPIFFE trace chain is verified before anything is granted",
    ),
];

/// Functions whose call in a handler body is a runtime decision.
const DECIDERS: &[&str] = &["http_kernel_decide", "kernel_decide", "decide"];

/// How an entry point reaches its effect. Three values, not a bool: "decided at
/// runtime" and "sealed by a type" need opposite follow-ups (ADR 0007 A).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Sealed,
    Checked,
    Unchecked,
}

impl Tier {
    fn label(self) -> &'static str {
        match self {
            Tier::Sealed => "sealed",
            Tier::Checked => "checked",
            Tier::Unchecked => "UNCHECKED",
        }
    }
}

/// One agent-reachable entry point and what its handler was found to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// `http <path>` or `mcp <tool>`.
    pub name: String,
    /// `file::fn` of the handler.
    pub handler: String,
    pub tier: Tier,
    /// Why it has that tier.
    pub because: String,
}

/// The calls a function body makes: every path segment chain of a call
/// expression, and every method name.
#[derive(Default)]
struct Calls {
    paths: Vec<Vec<String>>,
    methods: BTreeSet<String>,
    /// The token text of every macro in the body. syn does not parse a macro's
    /// body, and `/v1/read` mints its `Authority` inside a `macro_rules!` the
    /// handler defines -- read without this, a sealed handler reads Checked.
    macros: Vec<String>,
}

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = &*c.func {
            self.paths.push(
                p.path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect(),
            );
        }
        syn::visit::visit_expr_call(self, c);
    }
    fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
        self.methods.insert(m.method.to_string());
        syn::visit::visit_expr_method_call(self, m);
    }
    fn visit_macro(&mut self, m: &'ast syn::Macro) {
        self.macros.push(m.tokens.to_string());
        syn::visit::visit_macro(self, m);
    }
}

/// Is `name` a call to a decision in this macro text? A call is the name
/// followed by `(`, so a mention in a string or a path is not counted.
fn macro_calls(text: &str, name: &str) -> bool {
    text.split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '('))
        .any(|w| w.strip_suffix('(').is_some_and(|n| n == name))
        || text.contains(&format!("{name} ("))
}

impl Calls {
    fn of(block: &syn::Block) -> Self {
        let mut c = Calls::default();
        c.visit_block(block);
        c
    }

    fn mints_authority(&self) -> bool {
        self.paths
            .iter()
            .any(|p| p.len() >= 2 && p[p.len() - 2] == "Authority" && p[p.len() - 1] == "new")
            || self.macros.iter().any(|m| m.contains("Authority :: new ("))
    }

    /// The first decision this body makes, by name.
    fn decider(&self) -> Option<String> {
        let last = |p: &Vec<String>| p.last().cloned().unwrap_or_default();
        let direct = self
            .paths
            .iter()
            .map(last)
            .chain(self.methods.iter().cloned())
            .find(|n| DECIDERS.contains(&n.as_str()) || n.starts_with("preflight_"));
        direct.or_else(|| {
            DECIDERS
                .iter()
                .find(|d| self.macros.iter().any(|m| macro_calls(m, d)))
                .map(|d| (*d).to_string())
        })
    }
}

/// `(path, handler path segments)` for every `.route("<path>", verb(<handler>))`
/// in the router file.
pub fn routes(src: &str) -> Result<Vec<(String, Vec<String>)>> {
    struct V(Vec<(String, Vec<String>)>);
    impl<'ast> Visit<'ast> for V {
        fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
            if m.method == "route"
                && m.args.len() == 2
                && let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(path),
                    ..
                }) = &m.args[0]
                && let syn::Expr::Call(verb) = &m.args[1]
                && let Some(syn::Expr::Path(h)) = verb.args.first()
            {
                self.0.push((
                    path.value(),
                    h.path
                        .segments
                        .iter()
                        .map(|s| s.ident.to_string())
                        .collect(),
                ));
            }
            syn::visit::visit_expr_method_call(self, m);
        }
    }
    let file: syn::File = syn::parse_str(src).context("parsing the router")?;
    let mut v = V(Vec::new());
    // Top-level functions only: a `#[cfg(test)] mod` building a router for a
    // test is not the router an agent reaches.
    for item in &file.items {
        if let syn::Item::Fn(f) = item {
            v.visit_item_fn(f);
        }
    }
    // A method chain is visited outermost-first; sort so the order is the
    // path's and not the visitor's.
    v.0.sort();
    Ok(v.0)
}

/// The top-level function (or impl method) `name` in `src`, outside any `mod`.
fn find_fn(src: &str, name: &str) -> Result<Option<syn::Block>> {
    let file: syn::File = syn::parse_str(src).context("parsing a handler file")?;
    for item in &file.items {
        match item {
            syn::Item::Fn(f) if f.sig.ident == name => return Ok(Some((*f.block).clone())),
            syn::Item::Impl(i) => {
                for it in &i.items {
                    if let syn::ImplItem::Fn(f) = it
                        && f.sig.ident == name
                    {
                        return Ok(Some(f.block.clone()));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(None)
}

/// `(tool name, body)` for every `#[tool]` method in the MCP file.
pub fn mcp_tools(src: &str) -> Result<Vec<(String, syn::Block)>> {
    let file: syn::File = syn::parse_str(src).context("parsing the MCP server")?;
    let mut out = Vec::new();
    for item in &file.items {
        if let syn::Item::Impl(i) = item {
            for it in &i.items {
                if let syn::ImplItem::Fn(f) = it
                    && f.attrs.iter().any(|a| a.path().is_ident("tool"))
                {
                    out.push((f.sig.ident.to_string(), f.block.clone()));
                }
            }
        }
    }
    Ok(out)
}

/// The string literals in `run_gate::endpoint_operation`'s body: the routes the
/// auth middleware holds to a certificate ceiling. A literal ending in `/` is a
/// prefix (`starts_with`), the rest are exact.
pub fn ceiling_routes(src: &str) -> Result<Vec<String>> {
    struct Lits(Vec<String>);
    impl<'ast> Visit<'ast> for Lits {
        fn visit_lit_str(&mut self, l: &'ast syn::LitStr) {
            self.0.push(l.value());
        }
    }
    let Some(block) = find_fn(src, "endpoint_operation")? else {
        bail!(
            "{RUN_GATE} has no `endpoint_operation`. The middleware ceiling moved, and every \
             route that relied on it would read UNCHECKED."
        );
    };
    let mut l = Lits(Vec::new());
    l.visit_block(&block);
    Ok(l.0)
}

/// The module a bare handler name was imported from by `src`'s top-level `use` items, as a path
/// of module names (`use approval::{approve_operation, ..}` gives `["approval"]`). A router names
/// a handler bare once it moves into a module and is imported, so the census follows the import
/// the compiler follows instead of guessing by name. `None` when no import names it.
fn imported_from(src: &str, name: &str) -> Result<Option<Vec<String>>> {
    fn walk(tree: &syn::UseTree, prefix: &mut Vec<String>, name: &str) -> Option<Vec<String>> {
        match tree {
            syn::UseTree::Path(p) => {
                prefix.push(p.ident.to_string());
                let found = walk(&p.tree, prefix, name);
                prefix.pop();
                found
            }
            syn::UseTree::Name(n) if n.ident == name => Some(prefix.clone()),
            syn::UseTree::Rename(r) if r.rename == name => Some(prefix.clone()),
            syn::UseTree::Group(g) => g.items.iter().find_map(|t| walk(t, prefix, name)),
            _ => None,
        }
    }
    let file: syn::File = syn::parse_str(src).context("parsing the router")?;
    Ok(file.items.iter().find_map(|item| match item {
        syn::Item::Use(u) => walk(&u.tree, &mut Vec::new(), name),
        _ => None,
    }))
}

fn under_ceiling(path: &str, ceiling: &[String]) -> bool {
    ceiling
        .iter()
        .any(|c| c == path || (c.ends_with('/') && path.starts_with(c.as_str())))
}

fn source<'a>(corpus: &'a BTreeMap<String, String>, path: &str) -> Result<&'a str> {
    corpus
        .get(path)
        .map(String::as_str)
        .ok_or_else(|| anyhow::anyhow!("{path} is not in the production corpus"))
}

/// Classify every agent-reachable entry point.
pub fn entries(corpus: &BTreeMap<String, String>) -> Result<Vec<Entry>> {
    let router = source(corpus, ROUTER)?;
    let ceiling = ceiling_routes(source(corpus, RUN_GATE)?)?;
    let own: BTreeMap<&str, (&str, &str)> = OWN_AUTHORITY
        .iter()
        .map(|(e, f, ev, _)| (*e, (*f, *ev)))
        .collect();

    let tier_of = |name: &str, calls: &Calls, path: Option<&str>| -> Result<(Tier, String)> {
        if calls.mints_authority() {
            return Ok((Tier::Sealed, "mints an Authority".into()));
        }
        if let Some(d) = calls.decider() {
            return Ok((
                Tier::Checked,
                format!("decides via `{d}`, acts without its witness"),
            ));
        }
        if let Some(p) = path
            && under_ceiling(p, &ceiling)
        {
            return Ok((
                Tier::Checked,
                "middleware ceiling (`endpoint_operation`)".into(),
            ));
        }
        if let Some((file, evidence)) = own.get(name) {
            if !source(corpus, file)?.contains(evidence) {
                bail!(
                    "OWN_AUTHORITY says {name} is authorized by `{evidence}` in {file}, and \
                     {file} no longer contains it. A row cannot buy a tier without the mechanism \
                     behind it."
                );
            }
            return Ok((Tier::Checked, format!("own authority: `{evidence}`")));
        }
        Ok((Tier::Unchecked, "no decision on the path".into()))
    };

    let mut out = Vec::new();
    let routes = routes(router)?;
    if routes.is_empty() {
        bail!(
            "no `.route(..)` calls found in {ROUTER}. The population would be zero and the ratio \
             meaningless — the router moved."
        );
    }
    for (path, handler) in routes {
        let name = format!("http {path}");
        let (file, func) = match handler.as_slice() {
            // A bare name is the router's own function, or one it imports from a crate module.
            [f] => match imported_from(router, f)?.as_deref() {
                Some([m]) if m != "crate" && m != "self" && m != "super" => {
                    (format!("{SRC}/{m}.rs"), f.clone())
                }
                Some(other) if !other.is_empty() => bail!(
                    "{name}: handler `{f}` is imported from `{}`, a path the census does not \
                     resolve. Teach it the path rather than let the route read as a missing fn.",
                    other.join("::")
                ),
                _ => (ROUTER.to_string(), f.clone()),
            },
            [.., m, f] => (format!("{SRC}/{m}.rs"), f.clone()),
            [] => bail!("{name}: a route with no handler path"),
        };
        let Some(body) = find_fn(source(corpus, &file)?, &func)? else {
            bail!("{name}: handler `{func}` not found at the top level of {file}");
        };
        let (tier, because) = tier_of(&name, &Calls::of(&body), Some(&path))?;
        out.push(Entry {
            name,
            handler: format!("{file}::{func}"),
            tier,
            because,
        });
    }

    let tools = mcp_tools(source(corpus, MCP)?)?;
    if tools.is_empty() {
        bail!(
            "no `#[tool]` methods found in {MCP}. The MCP surface would silently leave the count."
        );
    }
    for (tool, body) in tools {
        let name = format!("mcp {tool}");
        let (tier, because) = tier_of(&name, &Calls::of(&body), None)?;
        out.push(Entry {
            name,
            handler: format!("{MCP}::{tool}"),
            tier,
            because,
        });
    }

    let names: BTreeSet<&str> = out.iter().map(|e| e.name.as_str()).collect();
    for (entry, _) in NOT_AN_EFFECT {
        if !names.contains(entry) {
            bail!("NOT_AN_EFFECT names {entry}, which is not an entry point. Delete the row.");
        }
    }
    for (entry, ..) in OWN_AUTHORITY {
        if !names.contains(entry) {
            bail!("OWN_AUTHORITY names {entry}, which is not an entry point. Delete the row.");
        }
    }
    out.sort_by(|a, b| (a.tier, &a.name).cmp(&(b.tier, &b.name)));
    Ok(out)
}

fn is_effect(e: &Entry) -> bool {
    !NOT_AN_EFFECT.iter().any(|(n, _)| *n == e.name)
}

/// The census over classified entries.
pub fn census_of(entries: &[Entry]) -> Census {
    let effects: Vec<&Entry> = entries.iter().filter(|e| is_effect(e)).collect();
    Census {
        population: effects.len(),
        discharged: effects.iter().filter(|e| e.tier == Tier::Sealed).count(),
        undeclared: entries.len() - effects.len(),
    }
}

pub struct Mediate;

impl Family for Mediate {
    fn name(&self) -> &'static str {
        "mediate"
    }

    fn unit(&self) -> &'static str {
        "agent-reachable entry point"
    }

    fn census(&self, corpus: &BTreeMap<String, String>) -> Result<Census> {
        Ok(census_of(&entries(corpus)?))
    }
}

/// shields.io endpoint JSON for the dedicated badge.
pub fn badge_json(c: Census) -> String {
    let bp = c.basis_points();
    let colour = if bp >= 9_900 {
        "brightgreen"
    } else if bp >= 7_500 {
        "yellow"
    } else {
        "orange"
    };
    format!(
        r#"{{"schemaVersion":1,"label":"sealed mediation","message":"{}/{} ({})","color":"{colour}"}}"#,
        c.discharged,
        c.population,
        crate::scorecard::pct(bp)
    )
}

/// `cargo xtask mediation`: the per-entry table, or `--badge` for the JSON.
/// A report, not a gate — the scorecard gates the number and the badge.
pub fn run(badge: bool) -> Result<i32> {
    let corpus = crate::law_mechanisms::tracked(crate::law_mechanisms::is_production_path)?;
    let entries = entries(&corpus)?;
    let c = census_of(&entries);
    if badge {
        println!("{}", badge_json(c));
        return Ok(0);
    }
    println!(
        "  sealed mediation | {}/{} agent-reachable effects ({})\n",
        c.discharged,
        c.population,
        crate::scorecard::pct(c.basis_points())
    );
    for e in &entries {
        let note = if is_effect(e) {
            ""
        } else {
            "  [not an effect]"
        };
        println!(
            "  {:<10} {:<32} {}{note}\n  {:<10} {:<32} {}",
            e.tier.label(),
            e.name,
            e.because,
            "",
            "",
            e.handler
        );
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(src: &str) -> syn::Block {
        syn::parse_str(src).expect("a block")
    }

    #[test]
    fn minting_an_authority_is_sealed_and_a_bare_decision_is_not() {
        let sealed = Calls::of(&block(
            "{ let b = preflight_fs(x); portcullis_effects::authority::Authority::new(b); }",
        ));
        assert!(sealed.mints_authority());
        let checked = Calls::of(&block(
            "{ let _dt = http_kernel_decide(&s, op).await?; act(); }",
        ));
        assert!(!checked.mints_authority());
        assert_eq!(checked.decider().as_deref(), Some("http_kernel_decide"));
        let method = Calls::of(&block("{ self.kernel_decide(op, s).await; }"));
        assert_eq!(method.decider().as_deref(), Some("kernel_decide"));
        let bare = Calls::of(&block("{ std::fs::write(p, b); }"));
        assert!(!bare.mints_authority() && bare.decider().is_none());
    }

    /// `/v1/read` mints its `Authority` inside a `macro_rules!` it defines.
    /// syn does not parse a macro body, so without the token scan a sealed
    /// handler reads Checked -- the census under-counting its own subject.
    #[test]
    fn an_authority_minted_inside_a_macro_is_still_sealed() {
        let c = Calls::of(&block(
            "{ macro_rules! a { () => {{ match r { Ok(b) => portcullis_effects::authority::Authority::new(b), _ => return } }} } let x = a!(); }",
        ));
        assert!(c.mints_authority());
        let mention = Calls::of(&block("{ tracing::info!(\"no Authority::new here\"); }"));
        assert!(!mention.mints_authority(), "a string is not a mint");
    }

    #[test]
    fn routes_are_read_from_top_level_functions_only() {
        let src = r#"
            fn main() { Router::new().route("/v1/a", post(a)).route("/v1/b", get(m::b)); }
            #[cfg(test)] mod tests { fn t() { Router::new().route("/v1/test", post(t)); } }
        "#;
        assert_eq!(
            routes(src).unwrap(),
            vec![
                ("/v1/a".to_string(), vec!["a".to_string()]),
                ("/v1/b".to_string(), vec!["m".to_string(), "b".to_string()]),
            ]
        );
    }

    #[test]
    fn only_tool_attributed_methods_are_mcp_tools() {
        let src =
            "impl S { #[tool(description = \"r\")] async fn read(&self) {} fn helper(&self) {} }";
        let names: Vec<String> = mcp_tools(src).unwrap().into_iter().map(|t| t.0).collect();
        assert_eq!(names, vec!["read"]);
    }

    #[test]
    fn the_middleware_ceiling_is_exact_or_a_trailing_slash_prefix() {
        let ceiling = vec!["/v1/read".to_string(), "/v1/egress/".to_string()];
        assert!(under_ceiling("/v1/read", &ceiling));
        assert!(under_ceiling("/v1/egress/{name}/{*path}", &ceiling));
        assert!(!under_ceiling("/v1/readme", &ceiling));
        assert!(!under_ceiling("/v1/memory/write", &ceiling));
    }

    /// A tool-proxy in miniature, one entry per tier plus a declared non-effect.
    fn mini() -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                ROUTER.to_string(),
                r#"
                fn main() {
                    Router::new()
                        .route("/v1/health", get(health))
                        .route("/v1/read", post(read_file))
                        .route("/v1/glob", post(glob_search))
                        .route("/v1/memory/write", post(memory_write))
                        .route("/v1/workload/result", get(result))
                        .route("/v1/workload/logs/stdout", get(result))
                        .route("/v1/workload/logs/stderr", get(result))
                        .route("/v1/approve", post(approve))
                        .route("/v1/declassify", post(approve))
                        .route("/v1/escalate", post(approve))
                        .route("/v1/raw", post(raw));
                }
                async fn health() {}
                async fn result() {}
                async fn approve() {}
                const T: &str = "AuthTier::ApprovalEd25519Drand";
                async fn read_file() { let b = preflight_read_fs(x); Authority::new(b); }
                async fn glob_search() { glob(p); }
                async fn memory_write() { let _dt = http_kernel_decide(s).await?; }
                async fn raw() { std::fs::write(p, b); }
                "#
                .to_string(),
            ),
            (
                RUN_GATE.to_string(),
                r#"fn endpoint_operation(p: &str) -> Option<Operation> {
                    match p { "/v1/read" => Some(R), "/v1/glob" => Some(G), _ => None } }"#
                    .to_string(),
            ),
            (
                MCP.to_string(),
                "impl S { #[tool(description = \"r\")] async fn read(&self) { Authority::new(b); } }"
                    .to_string(),
            ),
            (
                "crates/nucleus-tool-proxy/src/declassify.rs".to_string(),
                "fn f() { verify_declassification(); }".to_string(),
            ),
            (
                "crates/nucleus-tool-proxy/src/escalate.rs".to_string(),
                "fn f() { verify_detailed(); }".to_string(),
            ),
        ])
    }

    #[test]
    fn every_tier_is_found_and_non_effects_leave_the_denominator() {
        let es = entries(&mini()).unwrap();
        let tier = |n: &str| es.iter().find(|e| e.name == n).unwrap().tier;
        assert_eq!(tier("http /v1/read"), Tier::Sealed);
        assert_eq!(tier("mcp read"), Tier::Sealed);
        assert_eq!(tier("http /v1/glob"), Tier::Checked, "middleware ceiling");
        assert_eq!(
            tier("http /v1/memory/write"),
            Tier::Checked,
            "a bare decision"
        );
        assert_eq!(tier("http /v1/approve"), Tier::Checked, "own authority");
        assert_eq!(tier("http /v1/raw"), Tier::Unchecked);
        let c = census_of(&es);
        // 12 entries, 4 declared not-an-effect, 2 sealed.
        assert_eq!((c.population, c.discharged, c.undeclared), (8, 2, 4));
    }

    /// The anti-over-claim rule: an own-authority row whose evidence is gone
    /// is refused, not silently counted.
    #[test]
    fn an_own_authority_row_without_its_mechanism_is_refused() {
        let mut c = mini();
        c.insert(
            "crates/nucleus-tool-proxy/src/escalate.rs".to_string(),
            "fn f() {}".to_string(),
        );
        let err = entries(&c).expect_err("no mechanism, no tier").to_string();
        assert!(err.contains("verify_detailed"), "{err}");
    }

    #[test]
    fn an_empty_router_is_refused_rather_than_scored() {
        let mut c = mini();
        c.insert(ROUTER.to_string(), "fn main() {}".to_string());
        let err = entries(&c).expect_err("no population").to_string();
        assert!(err.contains("population would be zero"), "{err}");
    }

    #[test]
    fn a_stale_exemption_is_refused() {
        let mut c = mini();
        let router = c[ROUTER].replace(".route(\"/v1/health\", get(health))", "");
        c.insert(ROUTER.to_string(), router);
        let err = entries(&c).expect_err("stale row").to_string();
        assert!(err.contains("NOT_AN_EFFECT names http /v1/health"), "{err}");
    }

    #[test]
    fn the_badge_reads_sealed_over_population() {
        let c = Census {
            population: 8,
            discharged: 2,
            undeclared: 4,
        };
        assert_eq!(
            badge_json(c),
            r#"{"schemaVersion":1,"label":"sealed mediation","message":"2/8 (25.00%)","color":"orange"}"#
        );
    }
}

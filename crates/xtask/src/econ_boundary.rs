//! `cargo xtask econ-boundary` — economics never widens authority.
//!
//! Every economics epic (#2498–#2503) carries the same governing constraint,
//! and until now nothing enforced it structurally (#2514):
//!
//! > The deny-by-default capability boundary (`Kernel::decide`,
//! > `LatticeCertificate`, `run_gate`) decides *whether*; the economic layer
//! > decides only price, collateral, allocation among already-authorized
//! > requests, and payout/rebate/slash. The single lattice touchpoint is
//! > `cert_bridge::intersect_grant_with_certificate` (a **meet** — narrowing
//! > only).
//!
//! The defect this refuses is the one that would be easiest to write: a
//! reputation score, a bid, or a price reaching into the code that decides
//! what an agent may do, and moving the answer. `docs/econ-layer-boundary.md`
//! is the prose; this is the gate.
//!
//! # Three checks, one question each
//!
//! 1. **The authority crates do not depend on the economic crates.** Asked of
//!    `cargo metadata`'s resolved graph, transitively: `nucleus-ifc-kernel`,
//!    `portcullis-core` and `ck-policy` reach none of
//!    `nucleus-creditworthiness`, `nucleus-permission-market`,
//!    `nucleus-econ-kernels`, `nucleus-externality`. A dependency edge is the
//!    only way an import can exist, so this is the structural half.
//! 2. **The decision functions in `run_gate.rs` name no economic type.**
//!    `nucleus-tool-proxy` legitimately depends on the market — it renders a
//!    402 from a `PermissionGrant` — so a crate-level rule would be red on
//!    day one and a file-level rule would be too. The rule is per function:
//!    each named decision function's *body* is parsed with `syn` and may
//!    contain no path rooted at an economic crate. The function names are
//!    pinned, and a name that is no longer found fails the gate: a renamed
//!    decision function is one this gate silently stopped watching.
//! 3. **`pod_authority.rs` names no economic type anywhere.** It is the host's
//!    admission path and holds the root signing key; there is no legitimate
//!    reason for a price to appear in it.
//!
//! And one non-vacuity anchor: `cert_bridge.rs` must still contain the meet
//! the constraint names as the *only* permitted touchpoint. If that function
//! moves, the sentence in six epics is pointing at nothing, and this gate says
//! so rather than passing.
//!
//! # What this does not check
//!
//! That the meet in `cert_bridge.rs` *is* a meet. A function named
//! `intersect_grant_with_certificate` that joined would pass. The Kani harness
//! `effective ≤ verified.effective()` (#2513) is the check on that, and it is
//! a different gate. This one decides reachability, not semantics.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use syn::visit::Visit;

/// The economic crates, as cargo names them.
const ECON_CRATES: [&str; 4] = [
    "nucleus-creditworthiness",
    "nucleus-permission-market",
    "nucleus-econ-kernels",
    "nucleus-externality",
];

/// The same crates as Rust paths root them.
const ECON_ROOTS: [&str; 4] = [
    "nucleus_creditworthiness",
    "nucleus_permission_market",
    "nucleus_econ_kernels",
    "nucleus_externality",
];

/// Crates that decide authority and may reach no economic crate, transitively.
const AUTHORITY_CRATES: [&str; 3] = ["nucleus-ifc-kernel", "portcullis-core", "ck-policy"];

/// The decision functions in `run_gate.rs`. Pinned by name; a name not found
/// fails the gate.
const RUN_GATE_DECISION_FNS: [&str; 8] = [
    "certificate_denies_endpoint",
    "levels_for",
    "preflight_runbash",
    "preflight_web",
    "preflight_fs",
    "preflight_read_fs",
    "preflight_grep_fs",
    "discharge_witness",
];

const RUN_GATE: &str = "crates/nucleus-tool-proxy/src/run_gate.rs";
const POD_AUTHORITY: &str = "crates/nucleus-node/src/pod_authority.rs";
const CERT_BRIDGE: &str = "crates/nucleus-tool-proxy/src/cert_bridge.rs";
const TOUCHPOINT: &str = "intersect_grant_with_certificate";

/// Collects every path whose first segment is an economic crate root.
struct EconPaths {
    hits: Vec<String>,
}

impl EconPaths {
    fn note(&mut self, first: &str, rendered: String) {
        if ECON_ROOTS.contains(&first) {
            self.hits.push(rendered);
        }
    }
}

impl<'ast> Visit<'ast> for EconPaths {
    fn visit_path(&mut self, p: &'ast syn::Path) {
        if let Some(first) = p.segments.first() {
            let rendered = p
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect::<Vec<_>>()
                .join("::");
            self.note(&first.ident.to_string(), rendered);
        }
        syn::visit::visit_path(self, p);
    }

    fn visit_use_tree(&mut self, t: &'ast syn::UseTree) {
        if let syn::UseTree::Path(p) = t {
            self.note(&p.ident.to_string(), format!("use {}", p.ident));
        }
        syn::visit::visit_use_tree(self, t);
    }
}

/// Economic paths reachable from the bodies of the named functions in `src`.
/// Returns `(hits, missing function names)`.
pub fn econ_paths_in_fns(src: &str, fns: &[&str]) -> Result<(Vec<String>, Vec<String>)> {
    let file: syn::File = syn::parse_str(src).context("parsing Rust source")?;
    let mut found: BTreeSet<String> = BTreeSet::new();
    let mut hits = Vec::new();
    for item in &file.items {
        if let syn::Item::Fn(f) = item {
            let name = f.sig.ident.to_string();
            if fns.contains(&name.as_str()) {
                found.insert(name.clone());
                let mut v = EconPaths { hits: Vec::new() };
                v.visit_block(&f.block);
                hits.extend(v.hits.into_iter().map(|h| format!("{name}: {h}")));
            }
        }
    }
    let missing: Vec<String> = fns
        .iter()
        .filter(|n| !found.contains(**n))
        .map(|n| (*n).to_string())
        .collect();
    Ok((hits, missing))
}

/// Economic paths anywhere in `src`.
pub fn econ_paths_in_file(src: &str) -> Result<Vec<String>> {
    let file: syn::File = syn::parse_str(src).context("parsing Rust source")?;
    let mut v = EconPaths { hits: Vec::new() };
    v.visit_file(&file);
    Ok(v.hits)
}

/// For each authority crate, the economic crates it reaches transitively,
/// per `cargo metadata`'s resolved graph.
fn graph_reaches(root: &Path) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let out = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(root)
        .output()
        .context("running cargo metadata")?;
    if !out.status.success() {
        bail!(
            "cargo metadata failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .take(3)
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    let meta: serde_json::Value =
        serde_json::from_slice(&out.stdout).context("parsing cargo metadata JSON")?;

    let mut name_of: BTreeMap<String, String> = BTreeMap::new();
    for p in meta
        .get("packages")
        .and_then(serde_json::Value::as_array)
        .context("no `packages`")?
    {
        if let (Some(id), Some(name)) = (
            p.get("id").and_then(serde_json::Value::as_str),
            p.get("name").and_then(serde_json::Value::as_str),
        ) {
            name_of.insert(id.to_string(), name.to_string());
        }
    }
    let mut deps_of: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for n in meta
        .pointer("/resolve/nodes")
        .and_then(serde_json::Value::as_array)
        .context("no `resolve.nodes`")?
    {
        let Some(id) = n.get("id").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let deps = n
            .get("deps")
            .and_then(serde_json::Value::as_array)
            .map(|ds| {
                ds.iter()
                    .filter_map(|d| d.get("pkg").and_then(serde_json::Value::as_str))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        deps_of.insert(id.to_string(), deps);
    }

    let mut result = BTreeMap::new();
    for auth in AUTHORITY_CRATES {
        let Some(start) = name_of
            .iter()
            .find(|(_, n)| n.as_str() == auth)
            .map(|(id, _)| id)
        else {
            bail!("authority crate {auth} is not in the resolved graph — the gate cannot look");
        };
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut queue: VecDeque<String> = VecDeque::from([start.clone()]);
        let mut reached: BTreeSet<String> = BTreeSet::new();
        while let Some(id) = queue.pop_front() {
            if !seen.insert(id.clone()) {
                continue;
            }
            if let Some(name) = name_of.get(&id)
                && ECON_CRATES.contains(&name.as_str())
            {
                reached.insert(name.clone());
            }
            for d in deps_of.get(&id).into_iter().flatten() {
                queue.push_back(d.clone());
            }
        }
        result.insert(auth.to_string(), reached);
    }
    Ok(result)
}

/// Every boundary violation implied by the four inputs, as strings.
///
/// Extracted from `check` so each rule is reachable from a test. `check` reads
/// the graph and three files; this decides. Before the split the only way to
/// exercise any rule was to run the gate on the whole repository, which can
/// only ever show the clean case — and a gate that has only been observed
/// passing is the thing A-19 exists to forbid.
pub fn findings(
    graph: &BTreeMap<String, BTreeSet<String>>,
    run_gate_src: &str,
    pod_authority_src: &str,
    bridge_src: &str,
) -> Result<Vec<String>> {
    let mut out = Vec::new();

    for (auth, reached) in graph {
        for econ in reached {
            out.push(format!(
                "{auth} reaches {econ} in the resolved dependency graph. An authority crate \
                 that can name a price can be moved by one."
            ));
        }
    }

    let (hits, missing) = econ_paths_in_fns(run_gate_src, &RUN_GATE_DECISION_FNS)?;
    for m in &missing {
        out.push(format!(
            "{RUN_GATE}: decision function `{m}` not found. A renamed decision function is one \
             this gate silently stopped watching — update RUN_GATE_DECISION_FNS."
        ));
    }
    for h in &hits {
        out.push(format!(
            "{RUN_GATE}: decision function names an economic type — {h}"
        ));
    }

    for h in econ_paths_in_file(pod_authority_src)? {
        out.push(format!("{POD_AUTHORITY}: names an economic type — {h}"));
    }

    if !bridge_src.contains(&format!("fn {TOUCHPOINT}")) {
        out.push(format!(
            "{CERT_BRIDGE} no longer defines `{TOUCHPOINT}`, the single lattice touchpoint the \
             boundary names. Either the meet moved — update this gate and \
             docs/econ-layer-boundary.md — or it is gone, and the boundary has no touchpoint."
        ));
    }

    Ok(out)
}

pub fn check(root: &Path) -> Result<()> {
    let graph = graph_reaches(root)?;
    let run_gate = fs::read_to_string(root.join(RUN_GATE)).context("reading run_gate.rs")?;
    let pod_auth =
        fs::read_to_string(root.join(POD_AUTHORITY)).context("reading pod_authority.rs")?;
    let bridge = fs::read_to_string(root.join(CERT_BRIDGE)).context("reading cert_bridge.rs")?;

    let found = findings(&graph, &run_gate, &pod_auth, &bridge)?;
    for f in &found {
        println!("  FAIL  {f}");
    }
    if !found.is_empty() {
        bail!(
            "{} boundary violation(s): economics reached authority",
            found.len()
        );
    }
    println!(
        "ok: {} authority crate(s) reach no economic crate; {} decision function(s) in run_gate.rs \
         and all of pod_authority.rs name none; the meet in cert_bridge.rs is where the boundary \
         says it is",
        AUTHORITY_CRATES.len(),
        RUN_GATE_DECISION_FNS.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defect this gate exists for, in the shape it would arrive: a price
    /// consulted inside a decision.
    #[test]
    fn a_planted_economic_path_in_a_decision_function_is_found() {
        let src = r#"
            pub(crate) fn levels_for(x: u8) -> u8 {
                let bid = nucleus_permission_market::PermissionBid::default();
                if bid.value_estimate() > 0 { 1 } else { x }
            }
            pub(crate) fn certificate_denies_endpoint() -> bool { false }
        "#;
        let (hits, missing) =
            econ_paths_in_fns(src, &["levels_for", "certificate_denies_endpoint"]).unwrap();
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert!(hits[0].starts_with("levels_for: nucleus_permission_market"));
        assert!(missing.is_empty());
    }

    /// A `use` inside the function body is the other way in.
    #[test]
    fn a_planted_use_inside_a_decision_function_is_found() {
        let src = r#"
            fn levels_for() {
                use nucleus_econ_kernels::run_vcg;
                let _ = run_vcg;
            }
        "#;
        let (hits, _) = econ_paths_in_fns(src, &["levels_for"]).unwrap();
        assert!(!hits.is_empty(), "{hits:?}");
    }

    /// Non-vacuity: a decision function that disappears is reported, not
    /// silently unguarded.
    #[test]
    fn a_missing_decision_function_is_reported() {
        let (hits, missing) = econ_paths_in_fns("fn other() {}", &["levels_for"]).unwrap();
        assert!(hits.is_empty());
        assert_eq!(missing, vec!["levels_for".to_string()]);
    }

    /// Economic paths OUTSIDE the decision functions are allowed — that is the
    /// whole reason the rule is per function and not per file.
    #[test]
    fn economic_paths_outside_decision_functions_are_not_hits() {
        let src = r#"
            fn levels_for() -> u8 { 1 }
            fn payment_required(g: &nucleus_permission_market::PermissionGrant) -> u8 { 2 }
        "#;
        let (hits, _) = econ_paths_in_fns(src, &["levels_for"]).unwrap();
        assert!(hits.is_empty(), "{hits:?}");
        assert_eq!(econ_paths_in_file(src).unwrap().len(), 1);
    }

    /// The shipped files, read the way the gate reads them.
    #[test]
    fn the_shipped_decision_functions_are_all_present_and_clean() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let src = fs::read_to_string(root.join(RUN_GATE)).expect("run_gate.rs");
        let (hits, missing) = econ_paths_in_fns(&src, &RUN_GATE_DECISION_FNS).expect("parses");
        assert!(missing.is_empty(), "renamed decision fn(s): {missing:?}");
        assert!(hits.is_empty(), "{hits:?}");
        let pa = fs::read_to_string(root.join(POD_AUTHORITY)).expect("pod_authority.rs");
        assert!(econ_paths_in_file(&pa).expect("parses").is_empty());
        let bridge = fs::read_to_string(root.join(CERT_BRIDGE)).expect("cert_bridge.rs");
        assert!(bridge.contains(&format!("fn {TOUCHPOINT}")));
    }

    fn graph(pairs: &[(&str, &[&str])]) -> BTreeMap<String, BTreeSet<String>> {
        pairs
            .iter()
            .map(|(a, es)| {
                (
                    (*a).to_string(),
                    es.iter().map(|e| (*e).to_string()).collect(),
                )
            })
            .collect()
    }

    /// The four inputs that must yield NOTHING, so each test below departs from
    /// a known-clean baseline rather than from nothing at all.
    fn clean() -> (BTreeMap<String, BTreeSet<String>>, String, String, String) {
        let fns = RUN_GATE_DECISION_FNS
            .iter()
            .map(|n| format!("fn {n}() {{ let _ = 1; }}\n"))
            .collect::<String>();
        (
            BTreeMap::new(),
            fns,
            "fn unrelated() {}\n".to_string(),
            format!("fn {TOUCHPOINT}() {{}}\n"),
        )
    }

    #[test]
    fn the_clean_shape_reports_nothing() {
        let (g, rg, pa, br) = clean();
        let f = findings(&g, &rg, &pa, &br).expect("parses");
        assert!(f.is_empty(), "{f:?}");
    }

    /// Rule 1: the resolved graph. This is the violation the gate exists for —
    /// an authority crate that can name a price can be moved by one.
    #[test]
    fn an_authority_crate_reaching_an_economic_one_is_reported() {
        let (_, rg, pa, br) = clean();
        let g = graph(&[(AUTHORITY_CRATES[0], &[ECON_CRATES[0]])]);
        let f = findings(&g, &rg, &pa, &br).expect("parses");
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].contains(AUTHORITY_CRATES[0]) && f[0].contains(ECON_CRATES[0]));
        assert!(f[0].contains("resolved dependency graph"));
    }

    /// Rule 2a: a renamed decision function. Absence of a hit must not read as
    /// absence of a problem — the gate stops watching a function it cannot find.
    #[test]
    fn a_decision_function_that_is_gone_is_reported_not_skipped() {
        let (g, _, pa, br) = clean();
        let f = findings(&g, "fn something_else() {}\n", &pa, &br).expect("parses");
        assert_eq!(
            f.len(),
            RUN_GATE_DECISION_FNS.len(),
            "every missing decision function must be named: {f:?}"
        );
        assert!(f.iter().all(|m| m.contains("not found")));
    }

    /// Rule 2b: an economic path inside a decision function.
    #[test]
    fn an_economic_path_in_a_decision_function_is_reported() {
        let (g, _, pa, br) = clean();
        let mut rg = String::new();
        for (i, n) in RUN_GATE_DECISION_FNS.iter().enumerate() {
            if i == 0 {
                rg.push_str(&format!(
                    "fn {n}() {{ let _ = {}::PermissionGrant::default(); }}\n",
                    ECON_ROOTS[0]
                ));
            } else {
                rg.push_str(&format!("fn {n}() {{}}\n"));
            }
        }
        let f = findings(&g, &rg, &pa, &br).expect("parses");
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].contains("names an economic type"));
    }

    /// Rule 3: pod_authority.rs, whole file — not just its decision functions,
    /// because the authority file may not name economics anywhere.
    #[test]
    fn an_economic_path_anywhere_in_pod_authority_is_reported() {
        let (g, rg, _, br) = clean();
        let pa = format!("fn helper() {{ let _ = {}::Thing; }}\n", ECON_ROOTS[0]);
        let f = findings(&g, &rg, &pa, &br).expect("parses");
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].contains("pod_authority.rs"));
    }

    /// Rule 4: the anchor. If the one permitted touchpoint is gone, the gate
    /// must say so rather than pass — a boundary with no touchpoint is not a
    /// boundary that holds, it is one nobody is checking.
    #[test]
    fn the_missing_touchpoint_is_reported() {
        let (g, rg, pa, _) = clean();
        let f = findings(&g, &rg, &pa, "fn nothing_like_it() {}\n").expect("parses");
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].contains(TOUCHPOINT) && f[0].contains("no longer defines"));
    }

    #[test]
    fn malformed_rust_is_an_error_not_a_pass() {
        let (g, _, pa, br) = clean();
        assert!(
            findings(&g, "fn (((", &pa, &br).is_err(),
            "unparseable source must not read as clean"
        );
    }
}

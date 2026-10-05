//! `cargo xtask test-shards` — the test suite as two scope shards, generated rather than kept by
//! hand.
//!
//! `.gatehouse/test-shards.toml` says which packages form `test-node` and what the tests read
//! outside their dependency closure; this generates `.gatehouse/shards/test-node.json` and
//! `.gatehouse/shards/test-libs.json` from it, from `cargo metadata`, from the tracked files, and
//! from `.gatehouse/gates/test.json` (env, pins, seed, tools, resources — one definition, not
//! three). `--check` regenerates in memory and refuses a committed generation that differs.
//!
//! # The shape of `test-libs`'s scope, and why
//!
//! `crates/**` minus the `test-node` crates' entries, plus the workspace inputs, the measured
//! fixtures and the SDK's inputs. Not one `crates/<c>/**` per crate in the closure: that form says
//! the same thing and is refused by the writ kernel at its derivation caps (gatehouse F-182: 112
//! patterns over 1,159 leaves, `error[Capacity]` at every tree), and a scope whose hash cannot be
//! DERIVED never lets a receipt cross a tree — which is the only reason to shard.
//!
//! The excludes are each excluded crate's entries except its `Cargo.toml` (cargo loads every
//! member's manifest) and any fixture `test-libs` reads inside it. They are the smallest subtrees
//! holding nothing kept, so a stub's path always lands inside one.
//!
//! # The stubs
//!
//! A member whose sources the selection excludes has no target files, and cargo refuses to load
//! such a workspace. `tools/test-shard` writes an empty stub at each target path before the run.
//! The paths are computed HERE, from `cargo metadata`'s targets, and they appear twice in the
//! generation: as the runner's `--stub` arguments and as the gate's declared writes, one path per
//! file. A wildcard such as `crates/*/src/lib.rs` also names `test-libs`'s own crates, and
//! `writesOutsideScope_b` refuses it under `crates/**` (gatehouse F-186).
//!
//! # What it refuses to generate
//!
//! * a `test-libs` package whose build reaches a `test-node` package: that crate is an empty stub
//!   in `test-libs`'s pod, so the build would fail — the layout is wrong, not the run;
//! * a stub path that no exclude carves out: it would be a write into the scope;
//! * a package named in the layout that the workspace does not have.

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

const LAYOUT: &str = ".gatehouse/test-shards.toml";
const BASE: &str = ".gatehouse/gates/test.json";
// NOT `.gatehouse/gates/` yet. Every file there must have a plan gate of the same name
// (`cargo xtask gate-defs`), and the plan cannot declare these until it imports a gatehouse
// prelude whose `Gate` carries `exclude` (gatehouse#261). The files move, and `test` is retired,
// in the change that adds the two plan gates.
const NODE_OUT: &str = ".gatehouse/shards/test-node.json";
const LIBS_OUT: &str = ".gatehouse/shards/test-libs.json";
/// The crate whose build script embeds the verifier SDK. A shard whose closure reaches it runs
/// the SDK step first.
const SDK_CRATE: &str = "nucleus-verifier-service";

#[derive(Debug, Deserialize)]
struct Layout {
    runner: Vec<String>,
    nextest: Vec<String>,
    global: Vec<String>,
    sdk_reads: Vec<String>,
    writes: Vec<String>,
    node: NodeShard,
    libs: Shard,
    fixtures: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct NodeShard {
    packages: Vec<String>,
    whole_repository: Vec<String>,
    timeout_s: u64,
    measured_ms: u64,
}

#[derive(Debug, Deserialize)]
struct Shard {
    timeout_s: u64,
    measured_ms: u64,
}

/// A workspace member, as `cargo metadata --no-deps` reports it.
#[derive(Debug, Clone)]
pub struct Member {
    pub name: String,
    /// Relative to the workspace root.
    pub dir: String,
    /// `(kind, path relative to dir)` for every target.
    pub targets: Vec<(String, String)>,
    /// Workspace members this one depends on: `(name, kind)`, kind `normal`/`dev`/`build`.
    pub deps: Vec<(String, String)>,
}

/// What a stub must contain for cargo to build that target kind.
fn needs_main(kind: &str) -> bool {
    !matches!(
        kind,
        "lib" | "rlib" | "dylib" | "cdylib" | "staticlib" | "proc-macro"
    )
}

pub fn members_from_metadata(meta: &Value, root: &Path) -> Result<Vec<Member>> {
    let root = root
        .canonicalize()
        .with_context(|| format!("canonicalizing {}", root.display()))?;
    let pkgs = meta["packages"]
        .as_array()
        .context("metadata has no packages")?;
    let ws: BTreeSet<&str> = meta["workspace_members"]
        .as_array()
        .context("metadata has no workspace_members")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let names: BTreeSet<String> = pkgs
        .iter()
        .filter(|p| p["id"].as_str().is_some_and(|id| ws.contains(id)))
        .filter_map(|p| p["name"].as_str().map(str::to_string))
        .collect();
    let mut out = Vec::new();
    for p in pkgs {
        if !p["id"].as_str().is_some_and(|id| ws.contains(id)) {
            continue;
        }
        let name = p["name"]
            .as_str()
            .context("package without a name")?
            .to_string();
        let manifest = Path::new(p["manifest_path"].as_str().context("no manifest_path")?);
        let dir_abs = manifest.parent().context("manifest without a parent")?;
        let dir = dir_abs
            .strip_prefix(&root)
            .with_context(|| format!("{name} lives outside the workspace root"))?
            .to_string_lossy()
            .into_owned();
        let mut targets = Vec::new();
        for t in p["targets"].as_array().context("no targets")? {
            let src = Path::new(t["src_path"].as_str().context("target without src_path")?);
            let rel = src
                .strip_prefix(dir_abs)
                .with_context(|| format!("{name}: target {} outside its member", src.display()))?
                .to_string_lossy()
                .into_owned();
            for k in t["kind"].as_array().context("target without kind")? {
                targets.push((k.as_str().unwrap_or_default().to_string(), rel.clone()));
            }
        }
        let mut deps = Vec::new();
        for d in p["dependencies"].as_array().context("no dependencies")? {
            let dn = d["name"].as_str().unwrap_or_default();
            if d["path"].is_string() && names.contains(dn) {
                let kind = d["kind"].as_str().unwrap_or("normal").to_string();
                deps.push((dn.to_string(), kind));
            }
        }
        out.push(Member {
            name,
            dir,
            targets,
            deps,
        });
    }
    Ok(out)
}

/// What building `root`'s tests compiles: dev-dependencies at the root, normal and build edges
/// transitively (a dependency's dev-dependencies are never built).
fn closure(by_name: &BTreeMap<&str, &Member>, root: &str) -> BTreeSet<String> {
    let mut seen = BTreeSet::from([root.to_string()]);
    let mut stack: Vec<String> = by_name[root].deps.iter().map(|(n, _)| n.clone()).collect();
    while let Some(n) = stack.pop() {
        if !seen.insert(n.clone()) {
            continue;
        }
        if let Some(m) = by_name.get(n.as_str()) {
            stack.extend(
                m.deps
                    .iter()
                    .filter(|(_, k)| k != "dev")
                    .map(|(d, _)| d.clone()),
            );
        }
    }
    seen
}

/// What to exclude of an excluded crate `dir`: everything but `keep`, in as few patterns as the
/// writ kernel can afford to derive.
///
/// The pattern count is the derivation's cost (gatehouse F-182: 65-69 patterns derive, 74 are
/// refused), and the first generation of this file hit it: one exclude per top-level entry of
/// each crate was 46 excludes and 74 patterns, refused `error[Capacity]` at nucleus 0462daae.
/// So a crate holding nothing kept below its top level is ONE pattern for every subdirectory,
/// `dir/*/*/**`, plus its top-level files other than the kept ones. Not `dir/*/**`: `**` matches
/// zero segments, so that pattern also matches `dir/Cargo.toml`, and an exclude always wins.
fn exclude_crate(dir: &str, files: &[String], keep: &BTreeSet<String>) -> Vec<String> {
    let prefix = format!("{dir}/");
    let kept_below = keep.iter().any(|k| {
        k.strip_prefix(&prefix)
            .is_some_and(|rest| rest.contains('/'))
    });
    if kept_below {
        return carve(dir, files, keep);
    }
    let mut out = vec![format!("{dir}/*/*/**")];
    out.extend(
        files
            .iter()
            .filter(|f| {
                f.strip_prefix(&prefix)
                    .is_some_and(|rest| !rest.contains('/'))
            })
            .filter(|f| !keep.contains(*f))
            .cloned(),
    );
    out
}

/// The smallest subtrees under `dir` that hold no `keep` path, as scope patterns (`x/**` for a
/// directory, `x` for a file). `files` are tracked paths relative to the repository root.
fn carve(dir: &str, files: &[String], keep: &BTreeSet<String>) -> Vec<String> {
    let prefix = format!("{dir}/");
    let mut children: BTreeMap<String, bool> = BTreeMap::new(); // name -> is a directory
    for f in files {
        if let Some(rest) = f.strip_prefix(&prefix) {
            match rest.split_once('/') {
                Some((d, _)) => {
                    children.insert(d.to_string(), true);
                }
                None => {
                    children.entry(rest.to_string()).or_insert(false);
                }
            }
        }
    }
    let mut out = Vec::new();
    for (name, is_dir) in children {
        let path = format!("{prefix}{name}");
        if !is_dir {
            if !keep.contains(&path) {
                out.push(path);
            }
        } else if keep.iter().any(|k| k.starts_with(&format!("{path}/"))) {
            out.extend(carve(&path, files, keep));
        } else {
            out.push(format!("{path}/**"));
        }
    }
    out
}

/// `gatehouse_scope::matches` over `/`-split components: a literal, `*` (one component), `**`
/// (zero or more) and `*suffix`. The scope engine is gatehouse's; this is the subset of its
/// grammar the generator emits, used only to refuse a generation, never to admit a run.
fn glob_match(pat: &str, path: &str) -> bool {
    fn go(p: &[&str], s: &[&str]) -> bool {
        match p.split_first() {
            None => s.is_empty(),
            Some((&"**", rest)) => go(rest, s) || (!s.is_empty() && go(p, &s[1..])),
            Some((seg, rest)) => match s.split_first() {
                None => false,
                Some((head, tail)) => {
                    let ok = if *seg == "*" {
                        true
                    } else if let Some(suffix) = seg.strip_prefix('*') {
                        head.ends_with(suffix)
                    } else {
                        seg == head
                    };
                    ok && go(rest, tail)
                }
            },
        }
    }
    let p: Vec<&str> = pat.split('/').collect();
    let s: Vec<&str> = path.split('/').collect();
    go(&p, &s)
}

/// Is `path` inside one of `excludes`?
fn excluded(path: &str, excludes: &[String]) -> bool {
    excludes.iter().any(|e| glob_match(e, path))
}

fn step(
    program: &str,
    args: &[String],
    reads: &[String],
    writes: &[String],
    base: &Value,
) -> Value {
    let mut s = base.clone();
    s["program"] = json!(program);
    if args.is_empty() {
        s.as_object_mut()
            .expect("a step is an object")
            .remove("args");
    } else {
        s["args"] = json!(args);
    }
    s["reads"] = json!(reads);
    s["writes"] = json!(writes);
    s
}

/// The two gate definitions, as JSON values.
pub fn generate(
    layout_text: &str,
    base: &Value,
    members: &[Member],
    files: &[String],
) -> Result<(Value, Value)> {
    let layout: Layout = toml::from_str(layout_text).context("parsing the shard layout")?;
    let by_name: BTreeMap<&str, &Member> = members.iter().map(|m| (m.name.as_str(), m)).collect();
    for p in &layout.node.packages {
        ensure!(
            by_name.contains_key(p.as_str()),
            "{LAYOUT}: test-node names {p}, which is not a workspace member"
        );
    }
    let node: BTreeSet<&str> = layout.node.packages.iter().map(String::as_str).collect();
    let libs: Vec<&Member> = members
        .iter()
        .filter(|m| !node.contains(m.name.as_str()))
        .collect();

    // A test-libs build must not reach a test-node crate: in test-libs's pod that crate is a stub.
    let mut reaches = Vec::new();
    for m in &libs {
        let c = closure(&by_name, &m.name);
        for n in &node {
            if c.contains(*n) {
                reaches.push(format!("{} -> {n}", m.name));
            }
        }
    }
    ensure!(
        reaches.is_empty(),
        "test-libs packages whose tests build a test-node crate, which is an empty stub in test-libs's \
         pod -- move them to test-node or change the layout: {reaches:?}"
    );

    let libs_names: BTreeSet<&str> = libs.iter().map(|m| m.name.as_str()).collect();
    let fixtures: BTreeSet<String> = layout
        .fixtures
        .iter()
        .filter(|(c, _)| libs_names.contains(c.as_str()))
        .flat_map(|(_, f)| f.iter().cloned())
        .collect();
    let libs_sdk = libs
        .iter()
        .any(|m| closure(&by_name, &m.name).contains(SDK_CRATE));
    let node_sdk = node
        .iter()
        .any(|n| closure(&by_name, n).contains(SDK_CRATE));

    // Excludes: each test-node crate minus its manifest and the fixtures test-libs reads inside it.
    let mut excludes = Vec::new();
    let mut stubs: Vec<(String, String, bool)> = Vec::new(); // (member dir, rel path, needs main)
    for n in &layout.node.packages {
        let m = by_name[n.as_str()];
        let mut keep: BTreeSet<String> = fixtures
            .iter()
            .filter(|f| f.starts_with(&format!("{}/", m.dir)))
            .cloned()
            .collect();
        keep.insert(format!("{}/Cargo.toml", m.dir));
        excludes.extend(exclude_crate(&m.dir, files, &keep));
        for (kind, rel) in &m.targets {
            let entry = (m.dir.clone(), rel.clone(), needs_main(kind));
            if !stubs.iter().any(|(d, r, _)| *d == entry.0 && *r == entry.1) {
                stubs.push(entry);
            }
        }
    }
    excludes.sort();
    excludes.dedup();
    stubs.sort();
    let stray: Vec<String> = stubs
        .iter()
        .map(|(d, r, _)| format!("{d}/{r}"))
        .filter(|p| !excluded(p, &excludes))
        .collect();
    ensure!(
        stray.is_empty(),
        "stub paths no exclude carves out, which would be writes into test-libs's scope: {stray:?}"
    );

    // test-libs's scope and capability.
    let mut include: Vec<String> = layout.global.clone();
    include.push("crates/**".into());
    include.extend(
        fixtures
            .iter()
            .filter(|f| !f.starts_with("crates/"))
            .cloned(),
    );
    if libs_sdk {
        include.extend(layout.sdk_reads.iter().cloned());
    }
    dedup_keep_order(&mut include);
    // A declared write under an include is carved out of the selection, so it lands outside the
    // scope (`writesOutsideScope_b`, gatehouse F-182): `sdks/verifier-js/**` is one include where
    // its inputs were ten, and its two output directories are excludes.
    for w in &layout.writes {
        let under = include.iter().any(|i| {
            i.strip_suffix("/**")
                .is_some_and(|d| w.starts_with(&format!("{d}/")))
        });
        if under && !excludes.contains(w) {
            excludes.push(w.clone());
        }
    }
    let overlap: Vec<&String> = layout
        .writes
        .iter()
        .filter(|w| {
            include
                .iter()
                .any(|i| glob_match(i, w.trim_end_matches("/**")))
        })
        .filter(|w| !excludes.contains(*w))
        .collect();
    ensure!(
        overlap.is_empty(),
        "declared writes inside test-libs's scope: {overlap:?}"
    );
    let mut libs_writes = layout.writes.clone();
    libs_writes.extend(stubs.iter().map(|(d, r, _)| format!("{d}/{r}")));

    let base_steps = base["steps"].as_array().context("test.json has no steps")?;
    let (sdk_step, run_step) = match base_steps.as_slice() {
        [sdk, run] => (sdk, run),
        other => bail!(
            "{BASE}: expected the SDK step and the run step, found {} step(s)",
            other.len()
        ),
    };
    let sdk_program = sdk_step["program"]
        .as_str()
        .context("SDK step without a program")?;

    let filter_out: Vec<String> = layout
        .node
        .whole_repository
        .iter()
        .map(|b| format!("binary_id({b})"))
        .collect();
    let repo_pkgs: BTreeSet<String> = layout
        .node
        .whole_repository
        .iter()
        .map(|b| b.split("::").next().unwrap_or(b).to_string())
        .collect();

    // test-libs: everything but test-node's packages, minus the whole-repository binaries.
    let mut libs_run: Vec<String> = layout.runner[1..].to_vec();
    libs_run.push("--workspace-features".into());
    for (d, r, main) in &stubs {
        libs_run.push(if *main { "--stub-main" } else { "--stub" }.into());
        libs_run.push(format!("{d}:{r}"));
    }
    libs_run.push("--".into());
    libs_run.extend(layout.nextest.iter().cloned());
    libs_run.push("--workspace".into());
    for n in &layout.node.packages {
        libs_run.extend(["--exclude".to_string(), n.clone()]);
    }
    if !filter_out.is_empty() {
        libs_run.extend([
            "-E".to_string(),
            format!("not ({})", filter_out.join(" | ")),
        ]);
    }

    // test-node: its packages, plus the packages holding the whole-repository binaries, filtered
    // to only those binaries from the latter.
    let mut node_run: Vec<String> = layout.runner[1..].to_vec();
    node_run.push("--workspace-features".into());
    node_run.push("--".into());
    node_run.extend(layout.nextest.iter().cloned());
    for n in layout.node.packages.iter().chain(repo_pkgs.iter()) {
        node_run.extend(["-p".to_string(), n.clone()]);
    }
    if !repo_pkgs.is_empty() {
        let pk: Vec<String> = repo_pkgs.iter().map(|p| format!("package({p})")).collect();
        node_run.extend([
            "-E".to_string(),
            format!("not ({}) | {}", pk.join(" | "), filter_out.join(" | ")),
        ]);
    }

    let runner = layout.runner.first().context("the runner is an argv")?;
    let base_scope = &base["scope"];
    let node_reads: Vec<String> = base_scope["include"]
        .as_array()
        .context("test.json scope has no include")?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();

    let mut node_gate = base.clone();
    node_gate["scope"] = json!({
        "include": node_reads, "exclude": [], "external": [], "git_history": false, "git_checkout": true,
    });
    node_gate["cap"]["fs_read"] = json!(node_reads);
    node_gate["cap"]["fs_write"] = json!(layout.writes);
    node_gate["timeout_s"] = json!(layout.node.timeout_s);
    let mut node_steps = Vec::new();
    if node_sdk {
        node_steps.push(step(
            sdk_program,
            &[],
            &node_reads,
            &layout.writes,
            sdk_step,
        ));
    }
    node_steps.push(step(
        runner,
        &node_run,
        &node_reads,
        &layout.writes,
        run_step,
    ));
    node_gate["steps"] = json!(node_steps);

    let mut libs_gate = base.clone();
    libs_gate["scope"] = json!({
        "include": include, "exclude": excludes, "external": [], "git_history": false,
    });
    libs_gate["cap"]["fs_read"] = json!(include);
    libs_gate["cap"]["fs_write"] = json!(libs_writes);
    libs_gate["timeout_s"] = json!(layout.libs.timeout_s);
    let mut libs_steps = Vec::new();
    if libs_sdk {
        libs_steps.push(step(sdk_program, &[], &include, &libs_writes, sdk_step));
    }
    libs_steps.push(step(runner, &libs_run, &include, &libs_writes, run_step));
    libs_gate["steps"] = json!(libs_steps);
    // `git` is only for the checkout test-node keeps.
    if let Some(tools) = libs_gate["tools"].as_array_mut() {
        tools.retain(|t| !t.as_str().is_some_and(|s| s.starts_with("git@")));
    }
    // The measured duration lives in the plan (`measuredMs`), not in the executor definition; the
    // layout keeps it so the plan half of the generation has one source.
    let _ = (layout.node.measured_ms, layout.libs.measured_ms);
    Ok((node_gate, libs_gate))
}

fn dedup_keep_order(v: &mut Vec<String>) {
    let mut seen = BTreeSet::new();
    v.retain(|x| seen.insert(x.clone()));
}

fn metadata(root: &Path) -> Result<Value> {
    let out = Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(root)
        .output()
        .context("running cargo metadata")?;
    ensure!(
        out.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&out.stderr)
            .lines()
            .take(3)
            .collect::<Vec<_>>()
            .join(" ")
    );
    serde_json::from_slice(&out.stdout).context("cargo metadata is not json")
}

fn tracked(root: &Path) -> Result<Vec<String>> {
    let out = Command::new("git")
        .args(["ls-files", "-z"])
        .current_dir(root)
        .output()
        .context("running git ls-files")?;
    ensure!(out.status.success(), "git ls-files failed");
    Ok(String::from_utf8(out.stdout)
        .context("a tracked path is not UTF-8")?
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect())
}

fn render(v: &Value) -> Result<String> {
    let mut s = serde_json::to_string_pretty(v)?;
    s.push('\n');
    Ok(s)
}

/// Ask gatehouse's `gate` whether the writ kernel derives this gate's scope hash at `HEAD` — the
/// derivation `POST /scopes` runs. A scope that does not derive stays ASSERTED, and an asserted
/// hash never lets a receipt cross a tree, so a shard whose scope stopped deriving costs a whole
/// attempt on every tree and saves nothing. Nothing else would say so: the gate still runs and
/// still goes green. The first generation of this file was such a scope (74 patterns, refused
/// `error[Capacity]`), and a few new crates can push a derivable one over the edge again.
fn derives(gate: &Path, root: &Path, def: &str) -> Result<()> {
    let out = Command::new(gate)
        .args([
            "scope", "witness", def, "--repo", ".", "--tree", "HEAD", "--check",
        ])
        .current_dir(root)
        .output()
        .with_context(|| format!("running {}", gate.display()))?;
    match out.status.code() {
        Some(0) => {
            let v: Value = serde_json::from_slice(&out.stdout).context("gate printed no json")?;
            ensure!(
                v["derived"].is_string(),
                "{def}: gate exited 0 without a derived hash -- is it older than `scope witness --check`?"
            );
            println!(
                "{def}: derives at HEAD ({})",
                v["derived"].as_str().unwrap_or_default()
            );
            Ok(())
        }
        Some(1) => bail!(
            "{def}: the writ kernel does not derive this scope at HEAD, so it can never be reused across \
             trees: {}",
            String::from_utf8_lossy(&out.stdout).trim()
        ),
        // 2 is "could not look", which is never a pass.
        _ => bail!(
            "{def}: gate could not look: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ),
    }
}

/// Generate, and either write the two gate files or (with `check`) refuse if they differ. With
/// `gate`, also refuse a scope the writ kernel does not derive.
pub fn run(root: &Path, check: bool, gate: Option<&Path>) -> Result<()> {
    let layout =
        fs::read_to_string(root.join(LAYOUT)).with_context(|| format!("reading {LAYOUT}"))?;
    let base: Value = serde_json::from_str(
        &fs::read_to_string(root.join(BASE)).with_context(|| format!("reading {BASE}"))?,
    )
    .with_context(|| format!("parsing {BASE}"))?;
    let members = members_from_metadata(&metadata(root)?, root)?;
    let files = tracked(root)?;
    let (node, libs) = generate(&layout, &base, &members, &files)?;
    let mut stale = Vec::new();
    for (path, v) in [(NODE_OUT, &node), (LIBS_OUT, &libs)] {
        let want = render(v)?;
        if check {
            if fs::read_to_string(root.join(path)).ok().as_deref() != Some(want.as_str()) {
                stale.push(path);
            }
        } else {
            fs::write(root.join(path), want).with_context(|| format!("writing {path}"))?;
        }
    }
    if !stale.is_empty() {
        bail!(
            "{stale:?} differ from what `cargo xtask test-shards` generates from {LAYOUT}, the workspace and {BASE}; regenerate"
        );
    }
    if let Some(g) = gate {
        for def in [NODE_OUT, LIBS_OUT] {
            derives(g, root, def)?;
        }
    }
    let n_ex = libs["scope"]["exclude"].as_array().map_or(0, Vec::len);
    let n_in = libs["scope"]["include"].as_array().map_or(0, Vec::len);
    println!(
        "{}: test-libs scope {n_in} include(s) + {n_ex} exclude(s) = {} patterns",
        if check { "OK" } else { "generated" },
        n_in + n_ex
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(name: &str, targets: &[(&str, &str)], deps: &[(&str, &str)]) -> Member {
        Member {
            name: name.into(),
            dir: format!("crates/{name}"),
            targets: targets
                .iter()
                .map(|(k, p)| ((*k).into(), (*p).into()))
                .collect(),
            deps: deps
                .iter()
                .map(|(n, k)| ((*n).into(), (*k).into()))
                .collect(),
        }
    }

    const LAYOUT_TEXT: &str = r#"
runner = ["cargo", "run", "--manifest-path", "tools/test-shard/Cargo.toml", "--"]
nextest = ["cargo", "nextest", "run"]
global = ["Cargo.toml", "Cargo.lock"]
sdk_reads = ["sdks/x/**"]
writes = ["target/**"]
[node]
packages = ["node"]
whole_repository = ["lib-a::walks_everything"]
timeout_s = 1800
measured_ms = 1
[libs]
timeout_s = 1800
measured_ms = 1
[fixtures]
lib-a = ["crates/node/proto/x.proto", "docs/fixture.md"]
"#;

    fn base() -> Value {
        json!({
            "scope": {"include": ["**"], "exclude": [], "external": [], "git_history": true},
            "cap": {"fs_read": ["**"], "fs_write": ["target/**"]},
            "steps": [
                {"program": "scripts/sdk.sh", "reads": ["**"], "writes": ["target/**"]},
                {"program": "cargo", "args": ["nextest", "run"], "reads": ["**"], "writes": ["target/**"], "loopback": true, "uid": 1001}
            ],
            "tools": ["cargo@1", "git@2"],
            "timeout_s": 3600
        })
    }

    fn files() -> Vec<String> {
        [
            "crates/node/Cargo.toml",
            "crates/node/src/main.rs",
            "crates/node/src/pod.rs",
            "crates/node/proto/x.proto",
            "crates/node/proto/y.proto",
            "crates/node/build.rs",
            "crates/lib-a/Cargo.toml",
            "crates/lib-a/src/lib.rs",
            "docs/fixture.md",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
    }

    fn strs(v: &Value) -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn libs_scope_is_crates_minus_the_node_crate_and_keeps_its_manifest_and_fixture() {
        let members = vec![
            member(
                "node",
                &[("bin", "src/main.rs"), ("custom-build", "build.rs")],
                &[("lib-a", "normal")],
            ),
            member("lib-a", &[("lib", "src/lib.rs")], &[]),
        ];
        let (node, libs) = generate(LAYOUT_TEXT, &base(), &members, &files()).unwrap();
        let ex = strs(&libs["scope"]["exclude"]);
        assert_eq!(
            ex,
            vec![
                "crates/node/build.rs",
                "crates/node/proto/y.proto",
                "crates/node/src/**"
            ]
        );
        assert!(
            !ex.contains(&"sdks/x/out/**".to_string()),
            "a write under no include is not excluded"
        );
        let inc = strs(&libs["scope"]["include"]);
        assert!(
            inc.contains(&"crates/**".to_string()) && inc.contains(&"docs/fixture.md".to_string()),
            "{inc:?}"
        );
        // Every stub is declared as a write, one path per file, and each lies in an exclude.
        let w = strs(&libs["cap"]["fs_write"]);
        assert!(
            w.contains(&"crates/node/src/main.rs".into())
                && w.contains(&"crates/node/build.rs".into()),
            "{w:?}"
        );
        assert!(
            !w.iter()
                .any(|p| p.contains('*') && p.starts_with("crates/")),
            "no wildcard stub: {w:?}"
        );
        // The runner gets the same stubs, with `main` where cargo links an executable.
        let args = strs(&libs["steps"][0]["args"]);
        assert!(
            args.windows(2)
                .any(|w| w == ["--stub-main", "crates/node:src/main.rs"]),
            "{args:?}"
        );
        assert!(
            args.windows(2).any(|w| w == ["--exclude", "node"]),
            "{args:?}"
        );
        assert!(
            args.contains(&"not (binary_id(lib-a::walks_everything))".to_string()),
            "{args:?}"
        );
        // test-node keeps the whole tree and a checkout, and no history.
        assert_eq!(node["scope"]["git_checkout"], json!(true));
        assert_eq!(node["scope"]["git_history"], json!(false));
        let nargs = strs(&node["steps"][0]["args"]);
        assert!(
            nargs.windows(2).any(|w| w == ["-p", "lib-a"]),
            "the whole-repository binary's package: {nargs:?}"
        );
        // git is a test-node tool only.
        assert_eq!(strs(&libs["tools"]), vec!["cargo@1"]);
    }

    #[test]
    fn a_libs_package_that_builds_a_node_crate_is_refused() {
        let members = vec![
            member("node", &[("lib", "src/lib.rs")], &[]),
            member("lib-a", &[("lib", "src/lib.rs")], &[("node", "normal")]),
        ];
        let err = generate(LAYOUT_TEXT, &base(), &members, &files()).unwrap_err();
        assert!(err.to_string().contains("lib-a -> node"), "{err}");
    }

    #[test]
    fn a_dev_dependency_of_a_dependency_is_not_built_and_does_not_count() {
        // lib-a dev-depends on lib-b, which dev-depends on node: building lib-a's tests never
        // builds node, so the layout stands.
        let members = vec![
            member("node", &[("lib", "src/lib.rs")], &[]),
            member("lib-a", &[("lib", "src/lib.rs")], &[("lib-b", "dev")]),
            member("lib-b", &[("lib", "src/lib.rs")], &[("node", "dev")]),
        ];
        let mut f = files();
        f.push("crates/lib-b/src/lib.rs".into());
        // lib-b's OWN tests do build node, so lib-b must move: refused, naming lib-b only.
        let err = generate(LAYOUT_TEXT, &base(), &members, &f)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("lib-b -> node") && !err.contains("lib-a -> node"),
            "{err}"
        );
    }

    #[test]
    fn a_layout_naming_a_crate_the_workspace_lacks_is_refused() {
        let members = vec![member("lib-a", &[("lib", "src/lib.rs")], &[])];
        assert!(generate(LAYOUT_TEXT, &base(), &members, &files()).is_err());
    }

    #[test]
    fn a_crate_with_nothing_kept_below_its_top_level_is_one_pattern_and_its_loose_files() {
        let keep: BTreeSet<String> = ["crates/lib-a/Cargo.toml".to_string()].into();
        let mut f = files();
        f.push("crates/lib-a/README.md".into());
        assert_eq!(
            exclude_crate("crates/lib-a", &f, &keep),
            vec!["crates/lib-a/*/*/**", "crates/lib-a/README.md"]
        );
        // The one pattern never reaches the manifest: `*/**` would have.
        assert!(!glob_match(
            "crates/lib-a/*/*/**",
            "crates/lib-a/Cargo.toml"
        ));
        assert!(glob_match("crates/lib-a/*/**", "crates/lib-a/Cargo.toml"));
        assert!(glob_match("crates/lib-a/*/*/**", "crates/lib-a/src/lib.rs"));
        assert!(glob_match(
            "crates/lib-a/*/*/**",
            "crates/lib-a/src/bin/x.rs"
        ));
    }

    #[test]
    fn carve_keeps_kept_paths_and_carves_the_largest_subtrees_without_them() {
        let keep: BTreeSet<String> = ["crates/node/Cargo.toml", "crates/node/proto/x.proto"]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let got = carve("crates/node", &files(), &keep);
        assert_eq!(
            got,
            vec![
                "crates/node/build.rs",
                "crates/node/proto/y.proto",
                "crates/node/src/**"
            ]
        );
    }
}

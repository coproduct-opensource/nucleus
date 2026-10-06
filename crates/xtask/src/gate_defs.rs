//! Compare the fields shared by the elaborated plan and executor definitions.
//! The pinned gatehouse workflow separately re-elaborates the writ snapshot.
//! This preserves the existing checker boundary: capability, command/list
//! fields, scope inclusion AND exclusion, timeout, platform, and platform image
//! pins. Step contents are not part of this comparison.
//!
//! Exclusions joined 2026-10-05, with the first gate to have any (`test-libs`,
//! docs/findings/test-scope-shards.md §4). Until then this said exclusions were
//! out of scope and no gate had one, so nothing was missing; a shard scope is
//! `crates/**` minus 35 excludes, and those excludes are exactly what makes its
//! hash derivable. A definition whose excludes the plan does not state selects
//! something other than what the kernel admitted. A plan elaborated by a
//! gatehouse whose `Gate` has no `exclude` reads as excluding nothing, which is
//! what that plan meant.
use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct Pin {
    platform: String,
    image: String,
}
#[derive(Debug, Deserialize, PartialEq, Eq)]
struct Cap {
    wall_ms: u64,
    cpu_ms: u64,
    mem_mb: u64,
    net: String,
    exec: String,
    fs_read: Vec<String>,
    fs_write: Vec<String>,
    secrets: Vec<String>,
}
#[derive(Debug, Deserialize)]
struct Common {
    #[serde(default)]
    cmd: Vec<Value>,
    #[serde(default)]
    steps: Vec<Value>,
    #[serde(default)]
    tools: Vec<Value>,
    #[serde(default)]
    seeds: Vec<Value>,
    #[serde(default)]
    outputs: Vec<Value>,
    cap: Cap,
}
#[derive(Debug, Deserialize)]
struct PlanGate {
    name: String,
    #[serde(flatten)]
    common: Common,
    platform: String,
    #[serde(default)]
    pins: Vec<Pin>,
    scope: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
    timeout_ms: u64,
}
#[derive(Debug, Deserialize)]
struct Env {
    platform: String,
    image: String,
    #[serde(default)]
    pins: Vec<Pin>,
}
#[derive(Debug, Deserialize)]
struct Scope {
    include: Vec<String>,
    #[serde(default)]
    exclude: Vec<String>,
}
#[derive(Debug, Deserialize)]
struct Gate {
    #[serde(flatten)]
    common: Common,
    env: Env,
    scope: Scope,
    timeout_s: u64,
}

fn compare(plan: &PlanGate, gate: &Gate) -> Vec<String> {
    let mut bad = Vec::new();
    let want = &plan.common;
    let got = &gate.common;
    if got.cmd.is_empty() == got.steps.is_empty() {
        bad.push("exactly one of cmd or steps must be nonempty".into());
    }
    if want.cmd.is_empty() == want.steps.is_empty() {
        bad.push("plan must declare exactly one of cmd or steps".into());
    }
    for (name, a, b) in [
        ("cmd", &want.cmd, &got.cmd),
        ("tools", &want.tools, &got.tools),
        ("seeds", &want.seeds, &got.seeds),
        ("outputs", &want.outputs, &got.outputs),
    ] {
        if a != b {
            bad.push(format!("{name} differs from the plan"));
        }
    }
    if gate.timeout_s.checked_mul(1000) != Some(plan.timeout_ms) {
        bad.push("timeout_s does not equal the plan's timeout_ms".into());
    }
    if want.cap != got.cap {
        bad.push("capability differs from the plan".into());
    }
    if plan.scope != gate.scope.include {
        bad.push("scope.include differs from the plan".into());
    }
    if plan.exclude != gate.scope.exclude {
        bad.push("scope.exclude differs from the plan".into());
    }
    if plan.platform != gate.env.platform {
        bad.push("env.platform differs from the plan".into());
    }
    if plan.pins != gate.env.pins {
        bad.push("env.pins differs from the plan".into());
    }
    let mut platforms = BTreeSet::new();
    for pin in &plan.pins {
        if !platforms.insert(&pin.platform) {
            bad.push("plan repeats an image platform pin".into());
        }
    }
    if !plan.pins.is_empty() {
        match plan.pins.iter().find(|p| p.platform == plan.platform) {
            Some(pin) if pin.image == gate.env.image => {}
            Some(_) => bad.push("env.image does not match this platform's pin".into()),
            None => bad.push("plan has no image pin for its platform".into()),
        }
    }
    bad
}

pub(crate) fn check(root: &Path, elaborated: Option<&Path>) -> Result<()> {
    let source = elaborated
        .map(|p| root.join(p))
        .unwrap_or_else(|| root.join(".gatehouse/plan-gates.json"));
    let plans: Vec<PlanGate> = serde_json::from_slice(
        &fs::read(&source).with_context(|| format!("read {}", source.display()))?,
    )
    .with_context(|| format!("parse {}", source.display()))?;
    ensure!(!plans.is_empty(), "elaborated plan contains no gates");
    let mut indexed = BTreeMap::new();
    for plan in plans {
        ensure!(!plan.name.is_empty(), "plan gate has no name");
        let name = plan.name.clone();
        ensure!(
            indexed.insert(name.clone(), plan).is_none(),
            "duplicate plan gate {name}"
        );
    }
    let mut seen = BTreeSet::new();
    let mut bad = Vec::new();
    for entry in fs::read_dir(root.join(".gatehouse/gates"))? {
        let path = entry?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .context("non-UTF8 gate name")?;
        seen.insert(name.to_string());
        let Some(plan) = indexed.get(name) else {
            bad.push(format!("{name}: definition has no plan gate"));
            continue;
        };
        let gate: Gate = serde_json::from_slice(&fs::read(&path)?)
            .with_context(|| format!("parse {}", path.display()))?;
        bad.extend(
            compare(plan, &gate)
                .into_iter()
                .map(|why| format!("{name}: {why}")),
        );
    }
    for name in indexed.keys() {
        if !seen.contains(name) {
            bad.push(format!("{name}: gate definition is missing"));
        }
    }
    if !bad.is_empty() {
        bad.sort();
        bail!(
            "gate definitions disagree with the plan:\n{}",
            bad.join("\n")
        );
    }
    println!(
        "OK: {} gate(s) agree on command, tools, seeds, outputs, capability, scope inclusion and exclusion, timeout, platform and pins",
        indexed.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        fs::create_dir_all(dir.path().join(".gatehouse/gates")).unwrap();
        fs::copy(
            source.join(".gatehouse/plan-gates.json"),
            dir.path().join(".gatehouse/plan-gates.json"),
        )
        .unwrap();
        for entry in fs::read_dir(source.join(".gatehouse/gates")).unwrap() {
            let path = entry.unwrap().path();
            fs::copy(
                &path,
                dir.path()
                    .join(".gatehouse/gates")
                    .join(path.file_name().unwrap()),
            )
            .unwrap();
        }
        dir
    }
    #[test]
    fn the_committed_pair_agrees() {
        let dir = tree();
        check(dir.path(), None).unwrap();
    }
    #[test]
    fn moving_the_machine_or_image_without_the_plan_is_refused() {
        for field in ["platform", "image"] {
            let dir = tree();
            let path = dir.path().join(".gatehouse/gates/fmt.json");
            let original = fs::read(&path).unwrap();
            let mut gate: Value = serde_json::from_slice(&original).unwrap();
            gate["env"][field] = Value::String("wrong-platform-or-image".into());
            fs::write(&path, serde_json::to_vec(&gate).unwrap()).unwrap();
            assert!(check(dir.path(), None).is_err(), "{field}");
            fs::write(&path, original).unwrap();
            check(dir.path(), None).unwrap();
        }
    }
    #[test]
    fn duplicate_names_missing_definitions_and_empty_plans_are_not_success() {
        for case in ["duplicate", "missing", "empty"] {
            let dir = tree();
            let path = dir.path().join(".gatehouse/plan-gates.json");
            let mut plans: Vec<Value> = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            match case {
                "duplicate" => plans.push(plans[0].clone()),
                "missing" => {
                    fs::remove_file(dir.path().join(".gatehouse/gates/fmt.json")).unwrap();
                }
                "empty" => plans.clear(),
                _ => unreachable!(),
            }
            fs::write(&path, serde_json::to_vec(&plans).unwrap()).unwrap();
            assert!(check(dir.path(), None).is_err(), "{case}");
        }
    }
    #[test]
    fn an_exclude_the_plan_does_not_state_is_refused_either_way_round() {
        // On the definition only.
        let dir = tree();
        let path = dir.path().join(".gatehouse/gates/fmt.json");
        let mut gate: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        gate["scope"]["exclude"] = serde_json::json!(["crates/xtask/**"]);
        fs::write(&path, serde_json::to_vec(&gate).unwrap()).unwrap();
        let err = check(dir.path(), None).unwrap_err().to_string();
        assert!(err.contains("fmt: scope.exclude differs"), "{err}");
        // On the plan only.
        let dir = tree();
        let path = dir.path().join(".gatehouse/plan-gates.json");
        let mut plans: Vec<Value> = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let fmt = plans.iter_mut().find(|p| p["name"] == "fmt").unwrap();
        fmt["exclude"] = serde_json::json!(["crates/xtask/**"]);
        fs::write(&path, serde_json::to_vec(&plans).unwrap()).unwrap();
        let err = check(dir.path(), None).unwrap_err().to_string();
        assert!(err.contains("fmt: scope.exclude differs"), "{err}");
    }
    #[test]
    fn a_capability_change_or_timeout_overflow_is_refused() {
        for (pointer, value) in [
            ("/cap/net", Value::String("any".into())),
            ("/timeout_s", Value::from(u64::MAX)),
        ] {
            let dir = tree();
            let path = dir.path().join(".gatehouse/gates/fmt.json");
            let mut gate: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            *gate.pointer_mut(pointer).unwrap() = value;
            fs::write(path, serde_json::to_vec(&gate).unwrap()).unwrap();
            assert!(check(dir.path(), None).is_err(), "{pointer}");
        }
    }
}

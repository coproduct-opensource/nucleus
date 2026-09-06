//! From files to [`Model`].
//!
//! The YAML is hand-walked rather than deserialised into a schema: workflow
//! files carry keys this tool has no model for, and a partial `#[derive]`
//! would drop steps it did not anticipate — which for a checker means silently
//! examining less than it reports. Line numbers are recovered by searching the
//! raw text, since `serde_yaml` drops spans.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_yaml::Value;

use crate::model::{
    Allowlist, Concurrency, InlineGates, Job, Ledger, Model, PathFilter, QueueConfig, Step,
    Triggers, Workflow,
};

/// Look a key up in a mapping, tolerating YAML 1.1's reading of `on` as a
/// boolean. Whether `on:` parses as the string `"on"` or as `true` depends on
/// the YAML library's schema; a loader that only tried one of them would read
/// every workflow as trigger-less.
fn get<'a>(map: &'a Value, key: &str) -> Option<&'a Value> {
    let m = map.as_mapping()?;
    if let Some(v) = m.get(Value::String(key.to_string())) {
        return Some(v);
    }
    if key == "on" {
        return m.get(Value::Bool(true));
    }
    None
}

fn as_str_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Sequence(s)) => s
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

fn scalar_string(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn path_filter(v: &Value) -> PathFilter {
    PathFilter {
        paths: as_str_list(get(v, "paths")),
        paths_ignore: as_str_list(get(v, "paths-ignore")),
        types: as_str_list(get(v, "types")),
    }
}

fn triggers(on: Option<&Value>) -> Triggers {
    let mut t = Triggers::default();
    let Some(on) = on else { return t };
    let mut mark = |name: &str, body: Option<&Value>| match name {
        "push" => t.push = Some(body.map(path_filter).unwrap_or_default()),
        "pull_request" => t.pull_request = Some(body.map(path_filter).unwrap_or_default()),
        "merge_group" => t.merge_group = true,
        "schedule" => t.schedule = true,
        "workflow_dispatch" => t.workflow_dispatch = true,
        other => t.other.push(other.to_string()),
    };
    match on {
        Value::String(s) => mark(s, None),
        Value::Sequence(seq) => {
            for e in seq {
                if let Some(s) = e.as_str() {
                    mark(s, None);
                }
            }
        }
        Value::Mapping(m) => {
            for (k, v) in m {
                if let Some(s) = k.as_str() {
                    let body = if v.is_null() { None } else { Some(v) };
                    mark(s, body);
                }
            }
        }
        _ => {}
    }
    t
}

/// First 1-indexed line at or after `from` (0-indexed) containing `needle`.
fn find_line(raw: &[&str], needle: &str, from: usize) -> Option<usize> {
    raw.iter()
        .enumerate()
        .skip(from)
        .find(|(_, l)| l.contains(needle))
        .map(|(i, _)| i + 1)
}

/// Parse one workflow file.
pub fn parse_workflow(path: &str, text: &str) -> Result<Workflow> {
    let doc: Value =
        serde_yaml::from_str(text).with_context(|| format!("{path}: not valid YAML"))?;
    let raw: Vec<&str> = text.lines().collect();

    let name = scalar_string(get(&doc, "name")).unwrap_or_else(|| path.to_string());
    let t = triggers(get(&doc, "on"));

    let concurrency = get(&doc, "concurrency").and_then(|c| {
        let group = scalar_string(get(c, "group"))?;
        let cancel_in_progress =
            scalar_string(get(c, "cancel-in-progress")).unwrap_or_else(|| "false".into());
        let line = find_line(&raw, "concurrency:", 0).unwrap_or(1);
        Some(Concurrency {
            group,
            cancel_in_progress,
            line,
        })
    });

    let default_shell = get(&doc, "defaults")
        .and_then(|d| get(d, "run"))
        .and_then(|r| get(r, "shell"))
        .and_then(|s| s.as_str())
        .map(str::to_string);

    let mut jobs = Vec::new();
    if let Some(Value::Mapping(jm)) = get(&doc, "jobs") {
        let mut cursor = 0usize;
        for (k, jv) in jm {
            let id = k.as_str().unwrap_or("<job>").to_string();
            let line = find_line(&raw, &format!("  {id}:"), cursor).unwrap_or(1);
            cursor = line;
            let job_shell = get(jv, "defaults")
                .and_then(|d| get(d, "run"))
                .and_then(|r| get(r, "shell"))
                .and_then(|s| s.as_str())
                .map(str::to_string)
                .or_else(|| default_shell.clone());
            let job_workdir = get(jv, "defaults")
                .and_then(|d| get(d, "run"))
                .and_then(|r| get(r, "working-directory"))
                .and_then(|s| s.as_str())
                .map(str::to_string);
            let needs = as_str_list(get(jv, "needs"));
            let timeout_minutes = get(jv, "timeout-minutes").and_then(Value::as_u64);
            let continue_on_error = get(jv, "continue-on-error")
                .and_then(Value::as_bool)
                .unwrap_or(false);

            let mut steps = Vec::new();
            let mut scursor = line;
            if let Some(Value::Sequence(sv)) = get(jv, "steps") {
                for st in sv {
                    let sname = scalar_string(get(st, "name"))
                        .or_else(|| scalar_string(get(st, "uses")).map(|u| format!("uses {u}")))
                        .unwrap_or_else(|| "<unnamed>".into());
                    let run = get(st, "run").and_then(|r| r.as_str()).map(str::to_string);
                    let shell = get(st, "shell")
                        .and_then(|s| s.as_str())
                        .map(str::to_string)
                        .or_else(|| job_shell.clone());
                    let mut env = BTreeMap::new();
                    if let Some(Value::Mapping(em)) = get(st, "env") {
                        for (ek, ev) in em {
                            if let (Some(k), Some(v)) = (ek.as_str(), scalar_string(Some(ev))) {
                                env.insert(k.to_string(), v);
                            }
                        }
                    }
                    // The step's own line: its `- name:` if named, else the
                    // first line of its script.
                    let sline = if let Some(uses) = sname.strip_prefix("uses ") {
                        find_line(&raw, uses, scursor)
                    } else if sname != "<unnamed>" {
                        find_line(&raw, &format!("name: {sname}"), scursor)
                    } else {
                        run.as_deref()
                            .and_then(|r| r.lines().next())
                            .map(str::trim)
                            .filter(|f| !f.is_empty())
                            .and_then(|f| find_line(&raw, f, scursor))
                    }
                    .unwrap_or(scursor);
                    scursor = sline;
                    steps.push(Step {
                        name: sname,
                        id: scalar_string(get(st, "id")),
                        run,
                        shell,
                        if_expr: scalar_string(get(st, "if")),
                        continue_on_error: get(st, "continue-on-error")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        env,
                        working_directory: get(st, "working-directory")
                            .and_then(|s| s.as_str())
                            .map(str::to_string)
                            .or_else(|| job_workdir.clone()),
                        line: sline,
                    });
                }
            }
            // strategy.matrix: cartesian product of the list-valued keys, in
            // declaration order (GitHub's check-run naming order).
            let mut matrix: Vec<Vec<(String, String)>> = Vec::new();
            let mut matrix_opaque = false;
            if let Some(Value::Mapping(mm)) = get(jv, "strategy").and_then(|s| get(s, "matrix")) {
                let mut dims: Vec<(String, Vec<String>)> = Vec::new();
                for (mk, mv) in mm {
                    let Some(k) = mk.as_str() else { continue };
                    if k == "include" || k == "exclude" {
                        matrix_opaque = true;
                        continue;
                    }
                    let vals: Vec<String> = match mv {
                        Value::Sequence(s) => {
                            s.iter().filter_map(|x| scalar_string(Some(x))).collect()
                        }
                        other => scalar_string(Some(other)).into_iter().collect(),
                    };
                    if !vals.is_empty() {
                        dims.push((k.to_string(), vals));
                    }
                }
                if !dims.is_empty() {
                    matrix.push(Vec::new());
                    for (k, vals) in dims {
                        let mut next = Vec::new();
                        for combo in &matrix {
                            for v in &vals {
                                let mut c = combo.clone();
                                c.push((k.clone(), v.clone()));
                                next.push(c);
                            }
                        }
                        matrix = next;
                    }
                }
            }
            jobs.push(Job {
                matrix,
                matrix_opaque,
                id,
                name: scalar_string(get(jv, "name")),
                runs_on: scalar_string(get(jv, "runs-on")).unwrap_or_default(),
                if_expr: scalar_string(get(jv, "if")),
                needs,
                timeout_minutes,
                continue_on_error,
                line,
                steps,
            });
        }
    }

    Ok(Workflow {
        path: path.to_string(),
        name,
        triggers: t,
        concurrency,
        default_shell,
        jobs,
        raw: text.to_string(),
    })
}

/// Parse the required-check ledger: one context per line, `#` comments,
/// `# PINNED = N` header.
pub fn parse_ledger(text: &str) -> Ledger {
    let mut l = Ledger::default();
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix('#') {
            let r = rest.trim();
            if let Some(n) = r.strip_prefix("PINNED") {
                if let Ok(v) = n.trim().trim_start_matches('=').trim().parse::<usize>() {
                    l.pinned = Some(v);
                }
            }
            continue;
        }
        if !t.is_empty() {
            l.contexts.push(t.to_string());
        }
    }
    l
}

/// Parse the inline-gate inventory: `key | falsifier` lines, `#` comments,
/// `# UNCOVERED_CEILING = N` header.
pub fn parse_inline_gates(text: &str) -> InlineGates {
    let mut g = InlineGates::default();
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix('#') {
            let r = rest.trim();
            if let Some(n) = r.strip_prefix("UNCOVERED_CEILING") {
                if let Ok(v) = n.trim().trim_start_matches('=').trim().parse::<usize>() {
                    g.uncovered_ceiling = Some(v);
                }
            }
            continue;
        }
        if t.is_empty() {
            continue;
        }
        let (k, v) = t.split_once(" | ").unwrap_or((t, ""));
        g.entries.insert(k.trim().to_string(), v.trim().to_string());
    }
    g
}

/// Parse the gate-integrity allowlist: `RULE workflow::step | reason`.
pub fn parse_allowlist(text: &str) -> Allowlist {
    let mut a = Allowlist::default();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let (k, v) = t.split_once(" | ").unwrap_or((t, ""));
        a.entries.insert(k.trim().to_string(), v.trim().to_string());
    }
    a
}

/// Build the model from an in-memory set of files (what the tests use).
///
/// `workflows` are `(path, text)`; `gate_scripts` are the on-disk gate
/// script paths.
pub fn from_parts(
    workflows: &[(String, String)],
    ledger: &str,
    queue_toml: &str,
    inline_gates: &str,
    allowlist: &str,
    gate_scripts: Vec<String>,
) -> Result<Model> {
    let mut wfs = Vec::new();
    for (p, t) in workflows {
        wfs.push(parse_workflow(p, t)?);
    }
    let queue: QueueConfig = toml::from_str(queue_toml).context("ci/merge-queue.toml")?;
    Ok(Model {
        workflows: wfs,
        ledger: parse_ledger(ledger),
        queue,
        inline_gates: parse_inline_gates(inline_gates),
        allowlist: parse_allowlist(allowlist),
        gate_scripts,
    })
}

/// Build the model from a repository checkout.
pub fn from_repo(root: &Path) -> Result<Model> {
    let wf_dir = root.join(".github/workflows");
    let mut workflows = Vec::new();
    let mut names: Vec<_> = std::fs::read_dir(&wf_dir)
        .with_context(|| format!("reading {}", wf_dir.display()))?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "yml" || e == "yaml"))
        .collect();
    names.sort();
    for p in names {
        let rel = format!(
            ".github/workflows/{}",
            p.file_name().and_then(|f| f.to_str()).unwrap_or("?")
        );
        let text = std::fs::read_to_string(&p).with_context(|| format!("reading {rel}"))?;
        workflows.push((rel, text));
    }
    let read = |rel: &str| -> Result<String> {
        std::fs::read_to_string(root.join(rel)).with_context(|| format!("reading {rel}"))
    };
    let ledger = read("ci/required-checks.txt")?;
    let queue = read("ci/merge-queue.toml")?;
    let inline = read("ci/inline-gates.txt")?;
    let allow = read("ci/gate-integrity-allowlist.txt").unwrap_or_default();

    let mut gate_scripts = Vec::new();
    for (dir, prefix) in [("scripts", "check-"), ("ci", "")] {
        let d = root.join(dir);
        if !d.is_dir() {
            bail!("{} is not a directory", d.display());
        }
        for e in std::fs::read_dir(&d)?.filter_map(Result::ok) {
            let f = e.file_name();
            let f = f.to_string_lossy();
            if f.starts_with(prefix) && f.ends_with(".sh") {
                gate_scripts.push(format!("{dir}/{f}"));
            }
        }
    }
    gate_scripts.sort();
    from_parts(&workflows, &ledger, &queue, &inline, &allow, gate_scripts)
}

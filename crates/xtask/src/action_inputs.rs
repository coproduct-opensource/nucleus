//! `cargo xtask action-inputs` — a `with:` key an action does not declare is silently dropped.
//!
//! GitHub does not fail a step that passes an input the action never declared. It writes
//!
//! ```text
//! ##[warning]Unexpected input(s) 'targets', valid inputs are ['toolchain', 'target', …]
//! ```
//!
//! into the log and carries on, so the step runs *without* whatever that input was meant to
//! do. `actionlint` does not catch it either (measured 2026-09-12: clean on a file with three
//! such keys).
//!
//! # The three that paid for this gate
//!
//! `ci.yml` passed `targets:` to `actions-rust-lang/setup-rust-toolchain` at three sites. The
//! action declares `target`, singular — read from its `action.yml` at the pinned SHA, whose
//! inputs are `toolchain target components cache …` with no `targets` among them. So the
//! toolchain action installed no target at any of the three.
//!
//! **None of the three jobs was broken**, and that is the point rather than a mitigation: the
//! musl job runs `rustup target add` on its own line, and the wasm jobs use `wasm-pack --target
//! web`, which installs what it needs. So the keys were dead config that read as live, and the
//! same typo in a job without a second route would have failed in the build, far from the
//! `with:` block that caused it.
//!
//! # What decides this, and what needs the network
//!
//! An action's inputs live in its `action.yml`. For `./.github/actions/*` that file is in this
//! repository and the verdict is decidable from a checkout. For a third-party action it is in
//! *their* repository at the pinned SHA, so that half needs the GitHub API — and is REPORTED
//! as unchecked rather than passed when no token is available, on the same argument
//! `gatehouse-pin` makes about its third operand: a conjunct that could not be evaluated is not
//! a conjunct that held.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

/// One `uses:` step with the keys its `with:` block passes.
#[derive(Debug, PartialEq, Eq)]
pub struct Step {
    pub file: String,
    pub line: usize,
    /// `owner/repo@sha`, `owner/repo/path@sha`, or `./.github/actions/name`.
    pub uses: String,
    pub with: Vec<String>,
}

fn indent(l: &str) -> usize {
    l.len() - l.trim_start().len()
}

/// Keys GitHub accepts on any step, which no action declares.
const UNIVERSAL: &[&str] = &["args", "entrypoint"];

/// Every `uses:` step under `.github/`, with the `with:` keys it passes.
///
/// `with:` is a SIBLING of `uses:`, and its keys sit one level deeper. The block ends at the
/// first line indented no deeper than the `with:` key itself — reading to the end of the step
/// instead would swallow the next step's keys and blame this action for them.
pub fn steps(root: &Path) -> Result<Vec<Step>> {
    let mut out = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();
    for d in [".github/workflows", ".github/actions"] {
        collect(&root.join(d), &mut files);
    }
    files.sort();
    for path in files {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let text = fs::read_to_string(&path).with_context(|| format!("reading {rel}"))?;
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim_start();
            let Some(v) = t
                .strip_prefix("- uses:")
                .or_else(|| t.strip_prefix("uses:"))
            else {
                continue;
            };
            // `uses: owner/repo@sha # v2.9.1` and `… # zizmor: ignore[…]` are both live in
            // this tree; the trailing comment is not part of the ref, and carrying it into a
            // fetch asks the API for a tag that does not exist.
            let uses = v.split('#').next().unwrap_or(v).trim().to_string();
            if uses.is_empty() || uses.starts_with("${{") {
                continue; // computed at run time; nothing static to check against
            }
            let key_indent = indent(line) + if t.starts_with("- ") { 2 } else { 0 };
            let mut with = Vec::new();
            let mut in_with = false;
            let mut with_indent = 0usize;
            for l in &lines[i + 1..] {
                if l.trim().is_empty() {
                    continue;
                }
                if indent(l) < key_indent {
                    break;
                }
                let lt = l.trim_start();
                if indent(l) == key_indent {
                    if lt.starts_with("- ") {
                        break; // the next step
                    }
                    in_with = lt.starts_with("with:");
                    if in_with {
                        with_indent = indent(l);
                    }
                    continue;
                }
                if in_with && indent(l) > with_indent {
                    // A COMMENT is not a key. `gatehouse-shadow.yml` carries a twenty-line
                    // comment inside its `with:` explaining the timeout arithmetic, and every
                    // `#` line in it holds a colon -- so reading them as keys reported the
                    // prose as undeclared inputs. Same shape as the `case a|b)` and
                    // line-continuation traps: a parser meeting a syntax the tree really uses.
                    if lt.starts_with('#') {
                        continue;
                    }
                    // Only the block's OWN keys, at exactly one level in. Anything deeper is
                    // a value belonging to the key above it.
                    if indent(l) == with_indent + 2
                        && let Some((k, _)) = lt.split_once(':')
                        && !k.trim().is_empty()
                    {
                        with.push(k.trim().to_string());
                    }
                }
            }
            out.push(Step {
                file: rel.clone(),
                line: i + 1,
                uses,
                with,
            });
        }
    }
    Ok(out)
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut paths: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
    paths.sort();
    for p in paths {
        if p.is_dir() {
            collect(&p, out);
        } else if p.extension().is_some_and(|x| x == "yml" || x == "yaml") {
            out.push(p);
        }
    }
}

/// The `inputs:` an `action.yml` declares, from its text.
pub fn declared_inputs(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut in_inputs = false;
    let mut inputs_indent = 0usize;
    for line in src.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let t = line.trim_start();
        let ind = indent(line);
        if t.starts_with("inputs:") {
            in_inputs = true;
            inputs_indent = ind;
            continue;
        }
        if in_inputs {
            if ind <= inputs_indent {
                in_inputs = false;
                continue;
            }
            if ind == inputs_indent + 2
                && let Some((k, _)) = t.split_once(':')
            {
                out.insert(k.trim().to_string());
            }
        }
    }
    out
}

/// `action.yml` for a third-party `owner/repo[/path]@ref`, via the API at the pinned ref.
fn fetch_action_yml(uses: &str) -> Option<String> {
    let (path_part, at) = uses.split_once('@')?;
    let mut seg = path_part.splitn(3, '/');
    let owner = seg.next()?;
    let repo = seg.next()?;
    let sub = seg.next().unwrap_or("");
    for name in ["action.yml", "action.yaml"] {
        let p = if sub.is_empty() {
            name.to_string()
        } else {
            format!("{sub}/{name}")
        };
        let url = format!("repos/{owner}/{repo}/contents/{p}?ref={at}");
        let out = Command::new("gh")
            .args(["api", &url, "--jq", ".content"])
            .output()
            .ok()?;
        if !out.status.success() {
            continue;
        }
        let b64: String = String::from_utf8_lossy(&out.stdout)
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if b64.is_empty() {
            continue;
        }
        let dec = Command::new("base64")
            .arg("-d")
            .arg("-i")
            .env("B64", &b64)
            .output();
        let decoded = match dec {
            Ok(_) => base64_decode(&b64),
            Err(_) => base64_decode(&b64),
        };
        if let Some(s) = decoded {
            return Some(s);
        }
    }
    None
}

/// Minimal base64, so the gate does not take a dependency for one call.
fn base64_decode(s: &str) -> Option<String> {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut buf = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for c in s.bytes() {
        if c == b'=' {
            break;
        }
        let v = T.iter().position(|&t| t == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            buf.push((acc >> bits) as u8);
        }
    }
    String::from_utf8(buf).ok()
}

/// Measured 2026-09-12: 269 `uses:` sites across `.github/`. A scan finding far fewer has
/// stopped reading the tree, and a clean verdict would then be about nothing.
const MIN_STEPS: usize = 150;

pub fn check(root: &Path, network: bool) -> Result<()> {
    let steps = steps(root)?;
    if steps.len() < MIN_STEPS {
        bail!(
            "found {} `uses:` step(s), floor {MIN_STEPS} — the scan is wrong",
            steps.len()
        );
    }

    let mut failures = 0usize;
    let mut local_checked = 0usize;
    let mut remote_checked = 0usize;
    let mut unchecked: BTreeSet<String> = BTreeSet::new();

    for s in &steps {
        if s.with.is_empty() {
            continue;
        }
        let declared = if let Some(rel) = s.uses.strip_prefix("./") {
            // In this repository: always decidable.
            let mut p = root.join(rel);
            if p.is_dir() {
                p = p.join("action.yml");
            }
            let Ok(src) = fs::read_to_string(&p) else {
                println!(
                    "  FAIL  {}:{} uses {} and no action.yml is there",
                    s.file, s.line, s.uses
                );
                failures += 1;
                continue;
            };
            local_checked += 1;
            declared_inputs(&src)
        } else if network {
            match fetch_action_yml(&s.uses) {
                Some(src) => {
                    remote_checked += 1;
                    declared_inputs(&src)
                }
                None => {
                    unchecked.insert(s.uses.clone());
                    continue;
                }
            }
        } else {
            unchecked.insert(s.uses.clone());
            continue;
        };
        if declared.is_empty() {
            unchecked.insert(s.uses.clone());
            continue;
        }
        for k in &s.with {
            if declared.contains(k) || UNIVERSAL.contains(&k.as_str()) {
                continue;
            }
            println!(
                "  FAIL  {}:{} passes `{k}:` to {}, which declares no such input.",
                s.file, s.line, s.uses
            );
            println!(
                "        GitHub warns and DROPS it, so the step runs without whatever that key\n\
                 \x20       was for. Declared: {}",
                declared.iter().cloned().collect::<Vec<_>>().join(" ")
            );
            failures += 1;
        }
    }

    println!(
        "{} `uses:` step(s); {local_checked} against an action.yml in this repository, \
         {remote_checked} against one fetched at its pinned ref",
        steps.len()
    );
    if !unchecked.is_empty() {
        println!(
            "  not checked ({}): {}",
            unchecked.len(),
            unchecked.iter().cloned().collect::<Vec<_>>().join(", ")
        );
        println!(
            "  Their action.yml lives in another repository. Reported rather than passed: a \
             conjunct that could not be evaluated is not one that held."
        );
    }
    if failures > 0 {
        bail!("{failures} `with:` key(s) no action declares");
    }
    println!("ok: every `with:` key checked is one its action declares");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inputs_are_read_from_an_action_yml() {
        let src = "name: x\ninputs:\n  run:\n    required: true\n  bin-dir:\n    default: ''\nruns:\n  using: composite\n";
        let d = declared_inputs(src);
        assert!(d.contains("run"), "{d:?}");
        assert!(d.contains("bin-dir"), "{d:?}");
        // `required`/`default` are one level deeper and are NOT inputs.
        assert!(!d.contains("required"), "{d:?}");
        assert_eq!(d.len(), 2, "{d:?}");
    }

    #[test]
    fn a_with_block_is_read_from_the_sibling_of_uses() {
        let wf = "jobs:\n  j:\n    steps:\n      - uses: ./.github/actions/gatehouse\n        with:\n          run: cargo test\n          timeout: \"1200\"\n      - uses: other/x@abc\n        with:\n          k: v\n";
        let d = std::env::temp_dir().join("nucleus-ai-test");
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join(".github/workflows")).unwrap();
        fs::write(d.join(".github/workflows/w.yml"), wf).unwrap();
        let s = steps(&d).expect("parses");
        assert_eq!(s.len(), 2, "{s:?}");
        assert_eq!(s[0].with, vec!["run", "timeout"], "{s:?}");
        assert_eq!(s[1].with, vec!["k"], "the next step's keys leaked: {s:?}");
    }

    /// The shipped tree, read the way the gate reads it — and the local action's own caller
    /// must be among what it finds, or the offline conjunct covers nothing.
    #[test]
    fn the_scan_reaches_the_workflows_and_the_local_action() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let s = steps(&root).expect("the workflows parse");
        assert!(s.len() >= MIN_STEPS, "found {} step(s)", s.len());
        assert!(
            s.iter().any(|x| x.uses.starts_with("./.github/actions/")),
            "no caller of a local action found"
        );
    }

    /// Every `with:` key on the LOCAL action is one it declares. This is the conjunct that
    /// needs no network, and it must hold on the shipped tree.
    #[test]
    fn the_local_action_callers_pass_only_declared_inputs() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let declared = declared_inputs(
            &fs::read_to_string(root.join(".github/actions/gatehouse/action.yml")).unwrap(),
        );
        assert!(!declared.is_empty());
        for s in steps(&root).expect("parses") {
            if !s.uses.starts_with("./.github/actions/gatehouse") {
                continue;
            }
            for k in &s.with {
                assert!(
                    declared.contains(k) || UNIVERSAL.contains(&k.as_str()),
                    "{}:{} passes `{k}` which the action does not declare",
                    s.file,
                    s.line
                );
            }
        }
    }
}

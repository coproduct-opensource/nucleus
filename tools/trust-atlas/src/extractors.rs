//! The two LIVE extractors. Everything else in this spike is fixture-driven
//! (see README.md "honest scope").
//!
//! 1. `live_required_checks` / `live_workflows`: shell out to `gh api` for the
//!    branch-protection required checks + workflow list of
//!    coproduct-opensource/nucleus. On any failure the caller falls back to
//!    the fixture and MUST mark the output `[fixture]`.
//! 2. `extract_kani_harnesses`: grep a `--repo` path for `#[kani::proof]`,
//!    producing harness facts with file:line provenance.

use anyhow::Result;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const NUCLEUS_REPO_SLUG: &str = "coproduct-opensource/nucleus";

/// Where a datum came from — printed next to every fact that rests on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Live,
    Fixture,
}

impl Source {
    pub fn marker(self) -> &'static str {
        match self {
            Self::Live => "[live]",
            Self::Fixture => "[fixture]",
        }
    }
}

fn gh_api(path: &str) -> Result<String> {
    let out = Command::new("gh").args(["api", path]).output()?;
    if !out.status.success() {
        anyhow::bail!(
            "gh api {path} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8(out.stdout)?)
}

#[derive(Deserialize)]
struct RequiredStatusChecks {
    contexts: Vec<String>,
}

/// LIVE extractor 1a: required status-check contexts on `main`.
pub fn live_required_checks(slug: &str) -> Result<Vec<String>> {
    let raw = gh_api(&format!(
        "repos/{slug}/branches/main/protection/required_status_checks"
    ))?;
    let parsed: RequiredStatusChecks = serde_json::from_str(&raw)?;
    Ok(parsed.contexts)
}

#[derive(Deserialize)]
struct WorkflowList {
    workflows: Vec<WorkflowEntry>,
}

#[derive(Deserialize)]
pub struct WorkflowEntry {
    pub name: String,
    pub path: String,
    pub state: String,
}

/// LIVE extractor 1b: the repo's workflow list (names + paths).
/// NOTE: the workflows API does not expose job-level contexts, so the
/// workflow->job mapping still comes from the fixture even on the live path.
pub fn live_workflows(slug: &str) -> Result<Vec<WorkflowEntry>> {
    let raw = gh_api(&format!("repos/{slug}/actions/workflows?per_page=100"))?;
    let parsed: WorkflowList = serde_json::from_str(&raw)?;
    Ok(parsed.workflows)
}

/// A `#[kani::proof]` harness fact with checkable provenance.
pub struct KaniFact {
    pub name: String,
    pub file: PathBuf,
    /// 1-based line of the `#[kani::proof]` attribute.
    pub line: usize,
}

impl KaniFact {
    pub fn citation(&self) -> String {
        format!("{}:{}", self.file.display(), self.line)
    }
}

/// LIVE extractor 2: walk `repo` for `#[kani::proof]` attributes.
///
/// Only lines whose trimmed text STARTS with the attribute count — this
/// deliberately excludes string-literal mentions such as the
/// `content.matches("#[kani::proof]")` counter in nucleus-audit
/// (crates/nucleus-audit/src/main.rs:1172), matching the fixture's honesty
/// note (raw grep = 114, real harnesses = 113).
pub fn extract_kani_harnesses(repo: &Path) -> Result<Vec<KaniFact>> {
    let mut facts = Vec::new();
    walk(repo, &mut facts)?;
    facts.sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));
    Ok(facts)
}

fn walk(dir: &Path, facts: &mut Vec<KaniFact>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if matches!(
                name.as_ref(),
                ".git" | "target" | "node_modules" | "pkg" | ".lake" | "vendor"
            ) {
                continue;
            }
            walk(&path, facts)?;
        } else if name.ends_with(".rs") {
            scan_file(&path, facts)?;
        }
    }
    Ok(())
}

fn scan_file(path: &Path, facts: &mut Vec<KaniFact>) -> Result<()> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Ok(()); // non-UTF8: not a harness file
    };
    let lines: Vec<&str> = content.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        if !line.trim_start().starts_with("#[kani::proof]") {
            continue;
        }
        // Harness name: the next `fn NAME` within a few lines (further
        // attributes like #[kani::unwind] may sit in between).
        let name = lines[idx + 1..]
            .iter()
            .take(4)
            .find_map(|l| {
                let l = l.trim_start();
                let rest = l
                    .strip_prefix("pub fn ")
                    .or_else(|| l.strip_prefix("fn "))?;
                Some(
                    rest.split(|c: char| c == '(' || c.is_whitespace())
                        .next()
                        .unwrap_or("?")
                        .to_string(),
                )
            })
            .unwrap_or_else(|| "?".to_string());
        facts.push(KaniFact {
            name,
            file: path.to_path_buf(),
            line: idx + 1,
        });
    }
    Ok(())
}

//! `cargo xtask ci-spec` — the thin I/O shell around the `ci-spec` crate.
//!
//! The decision (are the merge-queue invariants satisfied by this tree?)
//! lives in `crates/ci-spec` as pure functions over a typed model, tested
//! from in-memory fixtures. This module only reads the checkout and prints.

use std::path::PathBuf;

use anyhow::Result;

/// `ci-spec check`: exit 0 clean, 1 violation, 2 could not look.
pub fn check(repo: Option<String>, json: bool) -> Result<()> {
    let root = repo_root(repo)?;
    let model = ci_spec::loader::from_repo(&root)?;
    let report = ci_spec::check(&model);
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", report.render());
    }
    let code = report.exit_code();
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

/// `ci-spec inline-gates`: print the inline-gate inventory in
/// `ci/inline-gates.txt` shape, carrying forward any falsifier already on
/// record so regenerating never loses an annotation.
pub fn inline_gates(repo: Option<String>) -> Result<()> {
    let root = repo_root(repo)?;
    let model = ci_spec::loader::from_repo(&root)?;
    let gates = ci_spec::invariants::wired::inline_gates(&model);
    let mut uncovered = 0usize;
    let mut lines = Vec::new();
    for (key, _line, _path) in &gates {
        let existing = model
            .inline_gates
            .entries
            .get(key)
            .cloned()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "UNCOVERED: no falsifier yet".to_string());
        if existing.starts_with("UNCOVERED") {
            uncovered += 1;
        }
        lines.push(format!("{key} | {existing}"));
    }
    println!(
        "# Every inline gate step (a `run:` containing `exit 1` or `::error::`) and what\n\
         # FALSIFIES it — a `*-falsifier` job, a check-gates-can-fail.sh probe, or a\n\
         # `--self-test` mode — or `UNCOVERED: <reason>`.\n\
         #\n\
         # WHY: scripts/check-gates-can-fail.sh covers scripts/check-*.sh only. Every\n\
         # required gate the 2026-09-05 inventory found green-by-construction (the proof\n\
         # count ratchet, the llvm-cov thresholds) was an INLINE step, outside that\n\
         # domain. This file puts them in one. The domain is derived by ci-spec (I8):\n\
         # an unlisted gate is red, a stale entry is red, and UNCOVERED only shrinks.\n\
         #\n\
         # Regenerate with `cargo xtask ci-spec inline-gates > ci/inline-gates.txt`\n\
         # (annotations are carried forward).\n\
         #\n\
         # UNCOVERED_CEILING = {uncovered}\n"
    );
    for l in lines {
        println!("{l}");
    }
    Ok(())
}

fn repo_root(repo: Option<String>) -> Result<PathBuf> {
    if let Some(r) = repo {
        return Ok(PathBuf::from(r));
    }
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()?;
    if out.status.success() {
        Ok(PathBuf::from(String::from_utf8(out.stdout)?.trim()))
    } else {
        Ok(std::env::current_dir()?)
    }
}

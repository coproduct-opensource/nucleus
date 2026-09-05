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

/// `ci-spec live-parity`: the ledgers against GitHub. Exit 0 in lockstep,
/// 1 drift, 2 could not look (no token, API error, partial response).
pub fn live_parity(repo: Option<String>, github: &str, json: bool) -> Result<()> {
    let root = repo_root(repo)?;
    let model = ci_spec::loader::from_repo(&root)?;

    let fetch = |path: &str| -> Result<String, String> {
        let out = std::process::Command::new("gh")
            .args(["api", path])
            .output()
            .map_err(|e| format!("run gh api {path}: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "gh api {path} failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        String::from_utf8(out.stdout).map_err(|e| e.to_string())
    };

    let looked =
        (|| -> Result<(ci_spec::live::LiveProtection, ci_spec::live::LiveQueue), String> {
            let prot = fetch(&format!("repos/{github}/branches/main/protection"))?;
            let rs = fetch(&format!(
                "repos/{github}/rulesets/{}",
                model.queue.ruleset_id
            ))?;
            Ok((
                ci_spec::live::parse_protection(&prot)?,
                ci_spec::live::parse_ruleset(&rs, model.queue.ruleset_id)?,
            ))
        })();

    let (live, queue) = match looked {
        Ok(v) => v,
        Err(e) => {
            // "Could not look" is exit 2 and a red job — reporting it as a
            // pass would be the exact vacuity the parity check exists to find.
            eprintln!("::error::live-parity could not look: {e}");
            eprintln!(
                "  (reading branch protection needs a token with repository Administration: \
                 read — set CI_ASSURANCE_TOKEN; GITHUB_TOKEN cannot)"
            );
            std::process::exit(2);
        }
    };

    let findings = ci_spec::live::parity(&model, &live, &queue);
    let report = ci_spec::Report {
        workflows: model.workflows.len(),
        jobs: model.workflows.iter().map(|w| w.jobs.len()).sum(),
        gates: 0,
        required_contexts: model.ledger.contexts.len(),
        findings,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "live-parity: ledger {} contexts, GitHub {} contexts, strict pinned={} live={}",
            model.ledger.contexts.len(),
            live.contexts.len(),
            model.queue.strict,
            live.strict
        );
        print!("{}", report.render());
    }
    let code = report.exit_code();
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

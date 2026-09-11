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

/// `ci-spec advisory`: every check context a workflow produces that the
/// required-check ledger does not list.
///
/// A required check blocks a merge; everything else is advisory, and an advisory
/// gate can be red on `main` indefinitely with nothing to notice. That is not a
/// hypothetical here: `a real nucleus pod boots and is enforced (x86_64)` --
/// the only lane that boots a real microVM and proves the enforcement end to end
/// -- went red on `main` on 2026-09-11 and a PR was enqueued past it.
///
/// This does NOT say every context should be required. Release jobs, nightly
/// lanes, the explicitly "informational" shadow gates and scheduled workflows are
/// advisory on purpose. It says what the set IS, so the ones that are advisory by
/// accident can be told from the ones that are advisory by decision -- the same
/// thing `ci/inline-gates.txt` does for gate steps, and the same reason ADR 0007
/// gives for naming an enforcement tier on every rule: so a gap reads as a gap
/// rather than as coverage.
///
/// Contexts still carrying an unexpanded `${{ ... }}` are reported separately.
/// They are matrix jobs the model could not expand (`matrix_opaque`), so their
/// real context names are unknown -- and "unknown" is not "unrequired" (A-2).
pub fn advisory(repo: Option<String>) -> Result<()> {
    let root = repo_root(repo)?;
    let model = ci_spec::loader::from_repo(&root)?;
    let required: std::collections::BTreeSet<&str> =
        model.ledger.contexts.iter().map(String::as_str).collect();

    let mut produced = std::collections::BTreeSet::new();
    for w in &model.workflows {
        for j in &w.jobs {
            for c in j.contexts() {
                produced.insert(c);
            }
        }
    }

    let (opaque, concrete): (Vec<&String>, Vec<&String>) = produced
        .iter()
        .filter(|c| !required.contains(c.as_str()))
        .partition(|c| c.contains("${{"));

    println!(
        "# Check contexts produced by a workflow and NOT listed in\n\
         # ci/required-checks.txt. Advisory: nothing blocks a merge on them.\n\
         #\n\
         # Not a to-do list. Release, nightly and shadow lanes belong here. The\n\
         # point is that the set is visible, so advisory-by-accident can be told\n\
         # from advisory-by-decision."
    );
    println!(
        "#\n# produced={} required={} advisory={} unexpanded={}",
        produced.len(),
        required.len(),
        concrete.len(),
        opaque.len()
    );
    for c in &concrete {
        println!("{c}");
    }
    if !opaque.is_empty() {
        println!(
            "\n# Unexpanded matrix contexts -- the model could not resolve these names,\n\
             # so whether they are required is UNKNOWN, which is not the same as no."
        );
        for c in &opaque {
            println!("# ?  {c}");
        }
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

    let looked = (|| -> Result<
        (
            ci_spec::live::LiveProtection,
            Option<ci_spec::live::LiveQueue>,
        ),
        String,
    > {
        let prot = fetch(&format!("repos/{github}/branches/main/protection"))?;
        let protection = ci_spec::live::parse_protection(&prot)?;
        if model.queue.owner == "gatehouse" {
            // The claim is about EVERY ruleset, not one pinned id: a queue re-enabled under a
            // new ruleset would merge this branch while gatehouse thought it owned the merge.
            let listing = fetch(&format!("repos/{github}/rulesets"))?;
            for id in ci_spec::live::parse_ruleset_ids(&listing)? {
                let rs = fetch(&format!("repos/{github}/rulesets/{id}"))?;
                if ci_spec::live::ruleset_has_merge_queue(&rs)? {
                    // Parsed as GitHub's queue so parity reports the owner conflict with the
                    // ruleset's own numbers rather than a bare "it exists".
                    return Ok((protection, Some(ci_spec::live::parse_ruleset(&rs, id)?)));
                }
            }
            return Ok((protection, None));
        }
        let rs = fetch(&format!(
            "repos/{github}/rulesets/{}",
            model.queue.ruleset_id
        ))?;
        Ok((
            protection,
            Some(ci_spec::live::parse_ruleset(&rs, model.queue.ruleset_id)?),
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

    let findings = ci_spec::live::parity(&model, &live, queue.as_ref());
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

/// `ci-spec gen-golden`: render crates/ci-spec/tests/golden/queue_traces.json
/// as ci/lean/CiSpec/Golden.lean on stdout.
pub fn gen_golden(repo: Option<String>) -> Result<()> {
    let root = repo_root(repo)?;
    let json = std::fs::read_to_string(root.join("crates/ci-spec/tests/golden/queue_traces.json"))?;
    let g = ci_spec::golden::parse(&json).map_err(|e| anyhow::anyhow!(e))?;
    // Never render vectors the Rust mirror itself does not reproduce.
    ci_spec::golden::check_rust(&g)
        .map_err(|e| anyhow::anyhow!("golden vector fails in Rust: {e}"))?;
    print!(
        "{}",
        ci_spec::golden::render_lean(&g).map_err(|e| anyhow::anyhow!(e))?
    );
    Ok(())
}

/// `ci-spec trace-check`: replay the last `since_hours` of merge-queue
/// history (PR timeline events, via `gh api graphql`) through the queue
/// model. Exit 0 clean, 1 a transition the model rejects, 2 vacuous window
/// or could not look.
pub fn trace_check(github: &str, since_hours: u64, json: bool) -> Result<()> {
    let (owner, name) = github
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("--github must be owner/name"))?;
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        .saturating_sub(since_hours * 3600);
    // PRs updated in the window carry every merge-queue event of the window.
    let query = format!(
        "{{repository(owner:\"{owner}\",name:\"{name}\"){{pullRequests(last:60, orderBy:{{field:UPDATED_AT, direction:ASC}}, states:[OPEN, MERGED, CLOSED]){{nodes{{number updatedAt \
         timelineItems(last:30, itemTypes:[ADDED_TO_MERGE_QUEUE_EVENT, REMOVED_FROM_MERGE_QUEUE_EVENT, MERGED_EVENT]){{nodes{{__typename \
         ... on AddedToMergeQueueEvent{{createdAt}} ... on RemovedFromMergeQueueEvent{{createdAt reason}} ... on MergedEvent{{createdAt}}}}}}}}}}}}}}"
    );
    let out = std::process::Command::new("gh")
        .args(["api", "graphql", "-f", &format!("query={query}")])
        .output()?;
    if !out.status.success() {
        eprintln!(
            "::error::trace-check could not look: gh api graphql failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        std::process::exit(2);
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    let mut events: Vec<ci_spec::trace::TraceEvent> = Vec::new();
    let since_rfc = ci_timings_rfc3339(since);
    for pr in v["data"]["repository"]["pullRequests"]["nodes"]
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        let number = u32::try_from(pr["number"].as_u64().unwrap_or(0)).unwrap_or(0);
        for it in pr["timelineItems"]["nodes"]
            .as_array()
            .cloned()
            .unwrap_or_default()
        {
            let at = it["createdAt"].as_str().unwrap_or("").to_string();
            if at.as_str() < since_rfc.as_str() {
                continue;
            }
            let kind = match it["__typename"].as_str().unwrap_or("") {
                "AddedToMergeQueueEvent" => ci_spec::trace::Kind::Added,
                "MergedEvent" => ci_spec::trace::Kind::Merged,
                "RemovedFromMergeQueueEvent" => ci_spec::trace::Kind::Removed {
                    reason: it["reason"].as_str().unwrap_or("").to_string(),
                },
                _ => continue,
            };
            events.push(ci_spec::trace::TraceEvent {
                at,
                pr: number,
                kind,
            });
        }
    }
    let r = ci_spec::trace::replay(&events);
    if json {
        println!("{}", serde_json::to_string_pretty(&r)?);
    } else {
        println!(
            "trace-check: {} timeline events in the last {since_hours}h — {} enqueues, {} merges, {} ejections",
            r.events, r.enqueues, r.merges, r.ejections
        );
        for v in &r.violations {
            println!("  VIOLATION: {v}");
        }
        if let Some(v) = &r.vacuous {
            println!("  UNDECIDED: {v}");
        }
        if r.exit_code() == 0 {
            println!("ok: the model accepts every transition GitHub performed");
        }
    }
    let code = r.exit_code();
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

fn ci_timings_rfc3339(secs: u64) -> String {
    // Days since epoch → civil date (Howard Hinnant's algorithm), UTC.
    let days = secs / 86400;
    let rem = secs % 86400;
    let z = i64::try_from(days).expect("day count fits i64") + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

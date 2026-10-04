//! The selection is only worth what it has been shown to select. Fixtures, run through the same
//! decision the scoped modes take (`decide`), with nothing executed:
//!
//! * a diff touching ONE gate script selects exactly that gate's probes;
//! * a diff touching the engine selects every probe;
//! * a gate-code path no probe names -- an undeclared input -- selects none on a pull request
//!   and every probe in the merge-queue backstop;
//! * a base nobody can read selects every probe and says why, and `--for-event pull_request ''`
//!   (exactly the call ci.yml makes) parses and decides;
//! * an empty diff selects none, with a reason per probe -- and `--vacuity-only` stays its own
//!   unscoped step in ci.yml (read from the workflow, not assumed).
//!
//! Plus non-vacuity of the derivation: every probed shell gate's input set contains its own
//! script, every xtask probe's contains crates/xtask/, and no probed gate names a repo path the
//! resolver cannot find -- an input nobody would see change.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use super::inputs::{ENGINE, Index};
use super::table::{self, Family};
use super::{Decision, Request, ScopeKind, decide, fixture_scope, parse, scope_for};

fn count_runs(idx: &Index, scope: &super::Scope, probes: &[table::Probe]) -> (usize, usize) {
    let mut run = 0;
    let mut skip = 0;
    for p in probes {
        match decide(idx, scope, p) {
            Decision::Run(_) => run += 1,
            Decision::Skip(_) => skip += 1,
        }
    }
    (run, skip)
}

pub fn run(root: &Path, idx: &Index) -> bool {
    let probes = table::probes();
    let total = probes.len();
    let mut fails = 0;
    let mut say = |ok: bool, line: String| {
        println!("{line}");
        if !ok {
            fails += 1;
        }
    };

    let gates: BTreeSet<&str> = table::probed_shell_gates();
    let subs: BTreeSet<&str> = probes
        .iter()
        .filter_map(|p| match p.family {
            Family::Script { .. } => None,
            Family::Xtask { sub }
            | Family::XtaskFlagged { sub, .. }
            | Family::XtaskPartial { sub, .. }
            | Family::XtaskGenerated { sub, .. } => Some(sub),
        })
        .collect();
    if gates.len() < 10 || subs.len() < 5 {
        println!(
            "  FAIL  self-test: read too few probes from the table; the fixtures would be vacuous"
        );
        return false;
    }

    // 1. One gate script selects exactly that gate's probes. Named rather than searched for, so
    //    the assertion is about this table.
    let pick = "check-kani-divergence.sh";
    let want = probes
        .iter()
        .filter(|p| matches!(p.family, Family::Script { gate, .. } if gate == pick))
        .count();
    let changed = format!("scripts/{pick}");
    let scope = fixture_scope(ScopeKind::Scoped, "the base of the given diff", &[&changed]);
    let mut got = 0;
    let mut extra = Vec::new();
    for p in &probes {
        if let Decision::Run(_) = decide(idx, &scope, p) {
            if p.label().starts_with(&format!("{pick} ")) {
                got += 1;
            } else {
                extra.push(p.label());
            }
        }
    }
    if want < 1 {
        say(
            false,
            format!("  FAIL  self-test: {pick} is no longer probed; name another fixture gate"),
        );
    } else if got != want || !extra.is_empty() {
        say(
            false,
            format!(
                "  FAIL  self-test: a diff touching scripts/{pick} selected {got} of its {want} probe(s), plus:"
            ),
        );
        for e in extra {
            println!("        {e}");
        }
    } else {
        say(
            true,
            format!("  ok    self-test: scripts/{pick} alone selects exactly its {want} probe(s)"),
        );
    }

    // 2. The engine: everything.
    for e in ENGINE {
        let path = if e.ends_with('/') {
            format!("{e}mod.rs")
        } else {
            (*e).to_string()
        };
        let scope = fixture_scope(ScopeKind::Scoped, "the base of the given diff", &[&path]);
        let (run, skip) = count_runs(idx, &scope, &probes);
        if run != total || skip != 0 {
            say(
                false,
                format!(
                    "  FAIL  self-test: a diff touching {path} selected {run} of {total} probes; the engine must select all"
                ),
            );
        } else {
            say(
                true,
                format!("  ok    self-test: {path} selects all {total} probes"),
            );
        }
    }

    // 2b. The backstop: a gate-code path no probe's derivation names is skipped by the
    //     pull-request scope and runs everything in the merge queue.
    let undeclared = "scripts/demo.sh";
    let (scoped, _) = count_runs(
        idx,
        &fixture_scope(ScopeKind::Scoped, "fixture", &[undeclared]),
        &probes,
    );
    let (backstop, _) = count_runs(
        idx,
        &fixture_scope(ScopeKind::Backstop, "fixture", &[undeclared]),
        &probes,
    );
    if !root.join(undeclared).is_file() || scoped != 0 || backstop != total {
        say(
            false,
            format!(
                "  FAIL  self-test: {undeclared} (no probe's input) selected {scoped} scoped and {backstop} of {total} in the backstop;"
            ),
        );
        println!(
            "        want 0 and all -- the backstop is what catches an input the derivation missed"
        );
    } else {
        say(
            true,
            format!(
                "  ok    self-test: {undeclared} is no probe's input: 0 scoped, all {total} in the merge-queue backstop"
            ),
        );
    }

    // 2c. A base nobody can read is every probe, with the reason printed -- never an error.
    let calls: [&[&str]; 5] = [
        &["--for-event", "merge_group", ""],
        &["--changed-from", ""],
        &["--backstop-from", ""],
        &["--changed-from", "no-such-revision-xyz"],
        &["--for-event", "pull_request", ""],
    ];
    for call in calls {
        let shown = call
            .iter()
            .map(|a| {
                if a.is_empty() {
                    "''".to_string()
                } else {
                    (*a).to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
        let mut argv = vec!["--plan".to_string()];
        argv.extend(call.iter().map(|a| (*a).to_string()));
        let opts = match parse(&argv) {
            Ok(Request::Run(o)) => o,
            Ok(_) | Err(_) => {
                say(
                    false,
                    format!("  FAIL  self-test: --plan {shown} did not parse"),
                );
                continue;
            }
        };
        let (scope, _) = scope_for(root, &opts);
        let (run, _) = count_runs(idx, &scope, &probes);
        let pr = call.first() == Some(&"--for-event") && call.get(1) == Some(&"pull_request");
        if pr {
            say(
                true,
                format!(
                    "  ok    self-test: --plan {shown} parses and decides ({run} probe(s) selected)"
                ),
            );
        } else if run != total
            || !scope
                .all
                .as_deref()
                .is_some_and(|w| w.contains("cannot be read"))
        {
            say(
                false,
                format!(
                    "  FAIL  self-test: --plan {shown} selected {run} of {total}, or did not say why"
                ),
            );
        } else {
            say(
                true,
                format!(
                    "  ok    self-test: --plan {shown} runs all {total} and says why: {}",
                    scope.all.unwrap_or_default()
                ),
            );
        }
    }

    // 3. Empty: nothing, each skip with its reason, and the cheap half unaffected.
    let (run, skip) = count_runs(
        idx,
        &fixture_scope(ScopeKind::Scoped, "the base of the given diff", &[]),
        &probes,
    );
    if run != 0 || skip != total {
        say(
            false,
            format!(
                "  FAIL  self-test: an empty diff selected {run} probe(s), or skipped one without a reason"
            ),
        );
    } else {
        say(
            true,
            format!(
                "  ok    self-test: an empty diff selects none, and says why for each of {total}"
            ),
        );
    }
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap_or_default();
    let vacuity_step = regex::Regex::new(
        r"(?m)^[[:space:]]*run: scripts/check-gates-can-fail\.sh --vacuity-only$",
    )
    .is_ok_and(|re| re.is_match(&ci));
    if !vacuity_step {
        say(
            false,
            "  FAIL  self-test: ci.yml no longer runs --vacuity-only as its own unscoped step"
                .into(),
        );
    }

    // 4. The derivation is not vacuous, and sees every path a probed gate names.
    for g in &gates {
        let script = format!("scripts/{g}");
        if !idx.script_inputs(&script).contains(&script) {
            say(
                false,
                format!("  FAIL  self-test: the input set of {g} does not contain its own script"),
            );
        }
        let unres = idx.unresolved(&script);
        if !unres.is_empty() {
            say(
                false,
                format!(
                    "  FAIL  self-test: {g} names path(s) the tree does not have: {} ",
                    unres.join(" ")
                ),
            );
            println!(
                "        Either the gate reads something this cannot resolve -- an input nobody"
            );
            println!("        would see change -- or the reference is stale. Fix whichever it is.");
        }
    }
    for s in &subs {
        if !idx.xtask_inputs(s).contains("crates/xtask/") {
            say(
                false,
                format!(
                    "  FAIL  self-test: the input set of xtask {s} does not contain crates/xtask/"
                ),
            );
        }
    }
    fails == 0
}

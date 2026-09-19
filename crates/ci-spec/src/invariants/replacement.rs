//! CI-RP — a gate that replaces a required context must run what that context ran.
//!
//! # The founding defect
//!
//! On 2026-09-17 four required contexts were retired in one change: `Rustfmt`, `Clippy`, `Tests`
//! and the ci-spec context left `ci/required-checks.txt` and the GitHub ruleset, and
//! `gatehouse/required` took their place. Both edits are subtractions. Nothing anywhere said
//! which gate now does `cargo fmt --all -- --check`, and nothing could have noticed if the answer
//! were "none of them" — the ledger's population pin counts contexts, and one context replacing
//! four is a legal count. A cutover was therefore a claim made in a commit message.
//!
//! Forty-six contexts remain on GitHub. Doing that forty-six more times on review alone is the
//! defect, not the risk.
//!
//! # What is decided here
//!
//! `ci/gatehouse-replacements.txt` declares `<context> <- <gate>`. For each line:
//!
//! * **CI-RP-1** the gate exists — `.gatehouse/gates/<gate>.json` defining a command, as
//!   either `cmd` or `steps`. A converted gate carries steps and no `cmd`, and the loader reads
//!   its argv out of them.
//! * **CI-RP-2** every command the replaced job runs is a command the gate runs.
//! * **CI-RP-3** the replaced job is still in the tree. When the workflow is finally deleted the
//!   parity becomes uncheckable, and the line should go with it; this says so rather than passing
//!   in silence, which is what an unfalsifiable row does.
//! * **CI-RP-4** a context produced by a RELAY resolves to the step it reports.
//!
//! # Relays, and why ignoring them would make this vacuous
//!
//! nucleus consolidated eleven one-script jobs into one pod and kept eleven status contexts, each
//! produced by a tiny job whose only command is
//!
//! ```text
//! case "$STEP" in success|skipped) exit 0;; *) echo "::error::…"; exit 1;; esac
//! ```
//!
//! with `STEP: ${{ needs.text-gates.outputs.verify_strict }}`. That job runs no gate: comparing a
//! replacement against ITS commands would find nothing to cover and pass every time. Eleven of the
//! contexts still on GitHub have this shape, so a parity rule that stopped at the producer would
//! wave the entire next wave through.
//!
//! So a producer with no verdict-deciding command of its own is followed: `needs.<job>.outputs.<n>`
//! resolves through that job's `outputs:` to `steps.<id>.outcome`, and the parity is computed
//! against that step's `run:`. A relay that cannot be resolved is CI-RP-4, never a pass.
//!
//! # What "every command" means, exactly
//!
//! Not string equality: the gate runs `cargo clippy --offline --locked` where CI ran
//! `cargo clippy`, and demanding the flags match would refuse every honest cutover. An invocation
//! is reduced to what decides a verdict:
//!
//! * the program and, for a multi-call tool, its subcommand — `cargo clippy`, `cargo fmt`,
//!   `wasm-pack build`;
//! * the packages it is scoped to, `-p <name>`, because `cargo clippy -p portcullis` and
//!   `cargo clippy` are different gates and nucleus runs both on purpose;
//! * the denials, `-D <lint>`, because `cargo clippy` without `-D warnings` is not the check that
//!   was retired — it is the same command with the verdict removed.
//!
//! Setup is skipped by an explicit list (`set`, `cd`, `echo`, `export`, `git`, `rustup`, …): a
//! step that fetches a ref or writes a summary is not what the context decided.
//!
//! The gate's side is read through one level of indirection: a repository script named in the
//! gate's argv is expanded, so `scripts/gatehouse-verifier-sdk.sh` counts as running the
//! `wasm-pack build` inside it. Two levels are not followed, because a wrapper calling a wrapper
//! is a gate nobody reviews either.

use std::collections::BTreeSet;

use super::finding;
use crate::model::Model;
use crate::{Finding, Severity};

const LEDGER: &str = "ci/gatehouse-replacements.txt";

/// Commands that set a job up rather than decide it.
const SETUP: &[&str] = &[
    "set", "cd", "echo", "printf", "export", "source", ".", "if", "fi", "then", "else", "elif",
    "for", "while", "do", "done", "case", "esac", "exit", "true", "false", "read", "mkdir", "rm",
    "cp", "mv", "ln", "touch", "chmod", "test", "[", "git", "rustup", "curl", "sudo", "tee",
    "shift", "local", "declare", "eval", "trap", "sleep", "wait", "npm", "unset",
];

/// Words that stand in front of the real program: `exec wasm-pack build …` runs wasm-pack, and
/// `sh -c "cargo clippy …"` runs cargo. A gate's argv is almost always `["sh", "-c", "…"]`,
/// so without the shells here every gate would read as running nothing but `sh`.
const PREFIX: &[&str] = &[
    "exec", "time", "command", "nice", "env", "nohup", "stdbuf", "sh", "bash", "dash", "zsh",
];

/// Tools whose first non-flag word is a subcommand rather than an argument.
const MULTICALL: &[&str] = &[
    "cargo",
    "wasm-pack",
    "rustup",
    "lake",
    "elan",
    "docker",
    "uv",
];

/// The part of one command line that decides a verdict: program, subcommand, `-p` scopes and
/// `-D` denials. Returns `None` for setup and for anything with no program.
fn invocation(line: &str) -> Option<String> {
    let line = line.trim().trim_start_matches('(');
    let mut words = line.split_whitespace().peekable();
    let mut program = words.next()?;
    // A `case` arm's label is not a program: splitting `case "$STEP" in success) exit 0;; *) …`
    // on `;` leaves `success) exit 0` and `*) echo …`. Left unhandled, a relay job reads as
    // running the commands `success)` and `skipped)`, which is worse than reading as running
    // nothing — it makes the job look like a gate and stops the relay from being followed.
    while program.ends_with(')') {
        program = words.next()?;
    }
    loop {
        // `FOO=bar cmd …`: the assignment is not the program, and neither is `exec` or `nice -n 15`.
        if program.contains('=') || PREFIX.contains(&program) {
            while words.peek().is_some_and(|w| w.starts_with('-')) {
                words.next();
                // `nice -n 15`: the flag takes a value that is not a flag.
                if words.peek().is_some_and(|w| w.parse::<i64>().is_ok()) {
                    words.next();
                }
            }
            program = words.next()?;
            continue;
        }
        break;
    }
    // Shell punctuation is not a program: `cargo fmt --check || { echo …; exit 1; }` splits into
    // a command and a brace group, and a `{` the gate does not "run" is not a missing check.
    if SETUP.contains(&program)
        || program.starts_with('#')
        || program.contains('=')
        || !program.chars().any(char::is_alphanumeric)
    {
        return None;
    }
    let mut key = program.to_string();
    if MULTICALL.contains(&program)
        && let Some(sub) = words.peek()
        && !sub.starts_with('-')
    {
        key.push(' ');
        key.push_str(words.next()?);
    }
    let rest: Vec<&str> = words.collect();
    let mut scopes = BTreeSet::new();
    let mut denials = BTreeSet::new();
    let mut i = 0;
    while i < rest.len() {
        match rest[i] {
            "-p" | "--package" => {
                if let Some(v) = rest.get(i + 1) {
                    scopes.insert(v.trim_matches('"').to_string());
                }
                i += 1;
            }
            "-D" | "--deny" => {
                if let Some(v) = rest.get(i + 1) {
                    denials.insert(v.trim_matches('"').to_string());
                }
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }
    for s in scopes {
        key.push_str(" -p ");
        key.push_str(&s);
    }
    for d in denials {
        key.push_str(" -D ");
        key.push_str(&d);
    }
    Some(key)
}

/// Every verdict-deciding invocation in a `run:` block. Continuations are joined, and `&&`, `;`
/// and `|` separate commands.
fn invocations(run: &str) -> Vec<String> {
    let joined = run.replace("\\\n", " ");
    let mut out = Vec::new();
    for line in joined.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for part in line
            .split("&&")
            .flat_map(|p| p.split("||"))
            .flat_map(|p| p.split(';'))
            .flat_map(|p| p.split('|'))
        {
            if let Some(key) = invocation(part) {
                out.push(key);
            }
        }
    }
    out
}

/// Whether the gate's expanded command runs `key`. The scopes and denials are compared as sets,
/// so flag order and the gate's own extra flags do not matter.
fn covers(expanded: &str, key: &str) -> bool {
    let gate: BTreeSet<String> = invocations(expanded).into_iter().collect();
    if gate.contains(key) {
        return true;
    }
    // A gate may deny MORE than the context did (`-D warnings -D clippy::pedantic` covers
    // `-D warnings`), and may run the same program and scope with extra flags.
    let (head, want) = split_key(key);
    gate.iter().any(|g| {
        let (gh, have) = split_key(g);
        gh == head && want.iter().all(|w| have.contains(w))
    })
}

/// `"cargo clippy -p x -D warnings"` → `("cargo clippy -p x", {"-D warnings"})`.
fn split_key(key: &str) -> (String, BTreeSet<String>) {
    let mut head = String::new();
    let mut denials = BTreeSet::new();
    let mut words = key.split_whitespace().peekable();
    while let Some(w) = words.next() {
        if w == "-D" {
            if let Some(v) = words.next() {
                denials.insert(format!("-D {v}"));
            }
        } else {
            if !head.is_empty() {
                head.push(' ');
            }
            head.push_str(w);
        }
    }
    (head, denials)
}

/// `${{ needs.text-gates.outputs.verify_strict }}` → `("text-gates", "verify_strict")`.
fn relay_targets(job: &crate::model::Job) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut scan = |text: &str| {
        let mut rest = text;
        while let Some(i) = rest.find("needs.") {
            rest = &rest[i + "needs.".len()..];
            let Some((job_id, tail)) = rest.split_once(".outputs.") else {
                continue;
            };
            let name: String = tail
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            let job_id: String = job_id
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            if !name.is_empty() && !job_id.is_empty() {
                out.push((job_id, name));
            }
        }
    };
    for step in &job.steps {
        for value in step.env.values() {
            scan(value);
        }
        if let Some(run) = &step.run {
            scan(run);
        }
    }
    out
}

/// `${{ steps.verify_strict.outcome }}` → `verify_strict`.
fn step_of_output(expr: &str) -> Option<String> {
    let rest = expr.split_once("steps.")?.1;
    let id: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    (!id.is_empty()).then_some(id)
}

/// The `run:` blocks whose result a context actually reports. Normally the producer's own; for a
/// relay, the steps it relays. Returns `None` when a relay names a step nothing resolves to.
fn deciding_runs(m: &Model, wi: usize, ji: usize) -> Option<Vec<String>> {
    let job = &m.workflows[wi].jobs[ji];
    let own: Vec<String> = job
        .steps
        .iter()
        .filter_map(|s| s.run.clone())
        .filter(|r| !invocations(r).is_empty())
        .collect();
    if !own.is_empty() {
        return Some(own);
    }
    let targets = relay_targets(job);
    if targets.is_empty() {
        // Not a relay and not a gate: it decides nothing, and nothing is what a replacement has
        // to cover.
        return Some(Vec::new());
    }
    let mut runs = Vec::new();
    for (job_id, output) in targets {
        let target = m.workflows[wi].jobs.iter().find(|j| j.id == job_id)?;
        let step_id = step_of_output(target.outputs.get(&output)?)?;
        let step = target
            .steps
            .iter()
            .find(|s| s.id.as_deref() == Some(step_id.as_str()))?;
        if let Some(run) = &step.run {
            runs.push(run.clone());
        }
    }
    Some(runs)
}

pub fn check(m: &Model) -> Vec<Finding> {
    let mut findings = Vec::new();
    for r in &m.replacements.entries {
        if r.cmd.is_empty() {
            findings.push(finding(
                "CI-RP-1",
                Severity::Critical,
                LEDGER,
                r.line,
                &r.context,
                format!(
                    "declares that gate `{}` replaced it, and no `.gatehouse/gates/{}.json` \
                     defines a command (as `cmd` or as `steps`)",
                    r.gate, r.gate
                ),
                "add the gate definition, or remove the replacement line",
            ));
            continue;
        }
        let producers = m.producers(&r.context);
        if producers.is_empty() {
            findings.push(finding(
                "CI-RP-3",
                Severity::Info,
                LEDGER,
                r.line,
                &r.context,
                format!(
                    "no workflow job produces this context any more, so what gate `{}` replaced \
                     can no longer be compared with what it runs",
                    r.gate
                ),
                "delete the line: its claim is now unfalsifiable and the workflow it named is gone",
            ));
            continue;
        }
        let mut missing: Vec<String> = Vec::new();
        let mut unresolved = false;
        for (wi, ji) in producers {
            let Some(runs) = deciding_runs(m, wi, ji) else {
                unresolved = true;
                continue;
            };
            for run in runs {
                for key in invocations(&run) {
                    if !covers(&r.expanded, &key) && !missing.contains(&key) {
                        missing.push(key);
                    }
                }
            }
        }
        if unresolved {
            findings.push(finding(
                "CI-RP-4",
                Severity::High,
                LEDGER,
                r.line,
                &r.context,
                "the job producing this context only relays another job's step, and the step it \
                 relays could not be resolved — so what the gate must cover is unknown"
                    .to_string(),
                "name the reporting step's output so the parity can be computed, or compare the \
                 gate against the job that runs the command",
            ));
        }
        for key in missing {
            findings.push(finding(
                "CI-RP-2",
                Severity::Critical,
                LEDGER,
                r.line,
                &r.context,
                format!(
                    "the job that produces it runs `{key}`, and gate `{}` does not — the gate \
                     decides less than the context it replaced",
                    r.gate
                ),
                "run the same command in the gate, or stop claiming the replacement",
            ));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_invocation_keeps_what_decides_a_verdict() {
        assert_eq!(
            invocation("cargo clippy --all-targets --all-features -- -D warnings").as_deref(),
            Some("cargo clippy -D warnings")
        );
        assert_eq!(
            invocation("cargo clippy -p portcullis --all-targets -- -D warnings").as_deref(),
            Some("cargo clippy -p portcullis -D warnings")
        );
        assert_eq!(
            invocation("cargo fmt --all -- --check").as_deref(),
            Some("cargo fmt")
        );
        assert_eq!(
            invocation("wasm-pack build sdks/verifier-js --target web --release").as_deref(),
            Some("wasm-pack build")
        );
        assert_eq!(
            invocation("scripts/check-ci-spec.sh").as_deref(),
            Some("scripts/check-ci-spec.sh")
        );
        // Setup is not a verdict.
        assert!(invocation("git fetch -q origin main").is_none());
        assert!(invocation("echo \"- tests: $T\" >> \"$GITHUB_STEP_SUMMARY\"").is_none());
        assert!(invocation("RUSTFLAGS=-Dwarnings").is_none());
        // A case arm's label is not a program, and what follows it may still be one.
        assert!(invocation("skipped) exit 0").is_none());
        assert!(invocation("*) echo \"::error::x\"; exit 1").is_none());
        assert_eq!(
            invocation("success) cargo fmt --all").as_deref(),
            Some("cargo fmt")
        );
        // Shell punctuation left by splitting `cmd || { echo …; exit 1; }` is not a program.
        assert!(invocation("{ ").is_none());
        assert!(invocation("}").is_none());
        assert_eq!(
            invocations("cargo fmt --check || { echo \"::error::fmt\"; exit 1; }"),
            vec!["cargo fmt".to_string()]
        );
    }

    #[test]
    fn the_gate_may_add_flags_and_denials_but_not_drop_a_denial() {
        assert!(covers(
            "cargo clippy --offline --locked --all-targets -- -D warnings",
            "cargo clippy -D warnings"
        ));
        assert!(covers(
            "cargo clippy -- -D warnings -D clippy::pedantic",
            "cargo clippy -D warnings"
        ));
        // The same command with the verdict removed is not the same gate.
        assert!(!covers(
            "cargo clippy --all-targets",
            "cargo clippy -D warnings"
        ));
        // Nor is a differently scoped one.
        assert!(!covers(
            "cargo clippy -p portcullis -- -D warnings",
            "cargo clippy -D warnings"
        ));
    }

    #[test]
    fn a_shell_wrapper_does_not_hide_the_program() {
        assert_eq!(
            invocation("sh -c cargo clippy --offline -- -D warnings").as_deref(),
            Some("cargo clippy -D warnings")
        );
        assert_eq!(
            invocation("exec wasm-pack build x").as_deref(),
            Some("wasm-pack build")
        );
    }

    #[test]
    fn a_wrapper_script_counts_as_running_what_it_runs() {
        let expanded = "sh -c scripts/gatehouse-verifier-sdk.sh && cargo clippy -- -D warnings\n\
                        set -euo pipefail\n\
                        exec wasm-pack build sdks/verifier-js --target web --release\n";
        assert!(covers(expanded, "wasm-pack build"));
    }
}

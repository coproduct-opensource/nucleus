//! `cargo xtask ci-spec local-coverage` — the fast gauntlet's list, held to the contexts it is
//! meant to predict.
//!
//! `scripts/prepush.sh` exists so a developer learns in a minute what CI would tell them in
//! twenty. Nothing checked that its list covered anything. Measured 2026-09-20: ten branches
//! pushed after `just prepush` reported every check green, and CI red on five of the eight it
//! could judge. **Three of those five were gates already in this tree and simply not in the
//! list** — `check-gate-defs-match-plan.sh` (0 s), `xtask ci-spec check` (3 s),
//! `check-clippy-ratchet.sh` (53 s). No cost trade-off was made; no decision was made at all.
//!
//! So `ci/local-deciders.txt` declares, per required context, the command that decides it or
//! `NOT-LOCAL` with a reason, and this checks it in both directions:
//!
//! * every required context has a line — a gate added to CI cannot stay out of the gauntlet
//!   silently;
//! * every line names a context that is actually required — a decider for a context that was
//!   retired is a claim about nothing, the same finding `.clippy-unanalysed.txt` makes when a
//!   listed crate starts compiling;
//! * every `prepush:` line names a command that appears in `scripts/prepush.sh` — a decider
//!   declared and not wired is the same red as one that is missing, because it is.
//!
//! What it does NOT check is that the command decides the SAME question the context does. That
//! is a judgement, and it is why the lines are short enough to read. This buys the population,
//! not the semantics — the same limit `trusted-base.txt` states about its own list.

use anyhow::{Result, bail};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;

const REQUIRED: &str = "ci/required-checks.txt";
const DECIDERS: &str = "ci/local-deciders.txt";
const PREPUSH: &str = "scripts/prepush.sh";

fn fail(failures: &mut u32, msg: &str) {
    println!("  FAIL  {msg}");
    *failures += 1;
}

/// Contexts from the ledger: non-empty, non-comment lines, with any `@app` suffix dropped.
fn required() -> BTreeSet<String> {
    fs::read_to_string(REQUIRED)
        .map(|s| {
            s.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|l| l.split(" @app").next().unwrap_or(l).trim().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// `<context> <- <decider>`; the arrow is the separator because contexts contain spaces.
fn deciders() -> BTreeMap<String, String> {
    let Ok(text) = fs::read_to_string(DECIDERS) else {
        return BTreeMap::new();
    };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once(" <- "))
        .map(|(c, d)| (c.trim().to_string(), d.trim().to_string()))
        .collect()
}

/// `# PINNED = n` / `# NOT-LOCAL = n`.
fn pin(text: &str, key: &str) -> Option<usize> {
    let at = text.find(key)? + key.len();
    text[at..]
        .lines()
        .next()?
        .trim()
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

pub fn run() -> Result<()> {
    let req = required();
    if req.is_empty() {
        bail!("could not look: {REQUIRED} has no contexts");
    }
    let dec = deciders();
    if dec.is_empty() {
        bail!("could not look: {DECIDERS} has no `<context> <- <decider>` lines");
    }
    let Ok(prepush) = fs::read_to_string(PREPUSH) else {
        bail!("could not look: {PREPUSH} is not readable");
    };
    let text = fs::read_to_string(DECIDERS)?;
    let mut failures = 0u32;

    // Both directions between the ledger and the declaration.
    for c in &req {
        if !dec.contains_key(c) {
            fail(
                &mut failures,
                &format!(
                    "`{c}` is required and {DECIDERS} does not say how a developer decides it \
                     (add a `prepush:` line, or NOT-LOCAL with the reason)"
                ),
            );
        }
    }
    for c in dec.keys() {
        if !req.contains(c) {
            fail(
                &mut failures,
                &format!("{DECIDERS} names `{c}`, which is not a required context"),
            );
        }
    }

    // A decider that claims to be in the fast gauntlet must be in the fast gauntlet.
    let mut local = 0usize;
    let mut not_local = 0usize;
    for (c, d) in &dec {
        if let Some(rest) = d.strip_prefix("NOT-LOCAL") {
            not_local += 1;
            if rest.trim_start_matches(':').trim().len() < 8 {
                fail(
                    &mut failures,
                    &format!("`{c}` is NOT-LOCAL with no reason — say what stops it"),
                );
            }
            continue;
        }
        local += 1;
        // `prepush:` and `prepush --full:` are both the gauntlet; the difference is which
        // invocation, and it is worth recording because a --full decider does NOT run on a bare
        // `just prepush` and therefore predicts nothing for the developer who only ran that.
        let Some(cmd) = d
            .strip_prefix("prepush: ")
            .or_else(|| d.strip_prefix("prepush --full: "))
            .map(str::trim)
        else {
            fail(
                &mut failures,
                &format!("`{c}` has decider `{d}`: expected `prepush: <token>` or `NOT-LOCAL: …`"),
            );
            continue;
        };
        // VERBATIM, because the point is to catch the token moving. A looser match -- the first
        // word, say -- would find `cargo` in a file that is nothing but cargo invocations, and
        // the check would pass while the gauntlet ran something else entirely.
        if !prepush.contains(cmd) {
            fail(
                &mut failures,
                &format!("`{c}` declares `{cmd}`, which does not appear in {PREPUSH}"),
            );
        }
    }

    match pin(&text, "# PINNED = ") {
        Some(p) if p != req.len() => fail(
            &mut failures,
            &format!("PINNED = {p} but {} contexts are required", req.len()),
        ),
        None => fail(&mut failures, "no `# PINNED = n` in the header"),
        Some(_) => {}
    }
    match pin(&text, "# NOT-LOCAL = ") {
        Some(p) if p != not_local => fail(
            &mut failures,
            &format!("NOT-LOCAL = {p} but {not_local} line(s) say NOT-LOCAL"),
        ),
        None => fail(&mut failures, "no `# NOT-LOCAL = n` in the header"),
        Some(_) => {}
    }

    if failures > 0 {
        bail!("the fast gauntlet's list and the required contexts disagree: {failures} finding(s)");
    }
    println!(
        "ok: {} required context(s) — {local} decided by the gauntlet, {not_local} declared \
         NOT-LOCAL with a reason",
        req.len()
    );
    Ok(())
}

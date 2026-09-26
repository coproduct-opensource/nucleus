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
///
/// Split from the read so it can be tested at all: a unit test runs with the crate
/// directory as its cwd, so a function that opens `ci/required-checks.txt` itself is
/// reachable only by the gate, and a parser nothing tests is a parser nothing checked.
fn parse_required(text: &str) -> BTreeSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split(" @app").next().unwrap_or(l).trim().to_string())
        .collect()
}

fn required() -> BTreeSet<String> {
    fs::read_to_string(REQUIRED)
        .map(|s| parse_required(&s))
        .unwrap_or_default()
}

/// `<context> <- <decider>`; the arrow is the separator because contexts contain spaces.
fn parse_deciders(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once(" <- "))
        .map(|(c, d)| (c.trim().to_string(), d.trim().to_string()))
        .collect()
}

fn deciders() -> BTreeMap<String, String> {
    let Ok(text) = fs::read_to_string(DECIDERS) else {
        return BTreeMap::new();
    };
    parse_deciders(&text)
}

/// `# PINNED = n` / `# NOT-LOCAL = n`.
fn pin(text: &str, key: &str) -> Option<usize> {
    let at = text.find(key)? + key.len();
    text[at..]
        .lines()
        .next()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// What the audit found, as a function of its inputs alone.
///
/// Extracted from `run` so every rule below is reachable from a test. The whole
/// body used to sit behind three `fs::read_to_string` calls on fixed paths, so a
/// unit test could reach none of it — and the checks it makes are the entire
/// point of the gate.
struct Audit {
    findings: Vec<String>,
    local: usize,
    not_local: usize,
}

fn audit(
    req: &BTreeSet<String>,
    dec: &BTreeMap<String, String>,
    prepush: &str,
    deciders_text: &str,
) -> Audit {
    let mut findings = Vec::new();

    // Both directions between the ledger and the declaration.
    for c in req {
        if !dec.contains_key(c) {
            findings.push(format!(
                "`{c}` is required and {DECIDERS} does not say how a developer decides it \
                 (add a `prepush:` line, or NOT-LOCAL with the reason)"
            ));
        }
    }
    for c in dec.keys() {
        if !req.contains(c) {
            findings.push(format!(
                "{DECIDERS} names `{c}`, which is not a required context"
            ));
        }
    }

    // A decider that claims to be in the fast gauntlet must be in the fast gauntlet.
    let mut local = 0usize;
    let mut not_local = 0usize;
    for (c, d) in dec {
        if let Some(rest) = d.strip_prefix("NOT-LOCAL") {
            not_local += 1;
            if rest.trim_start_matches(':').trim().len() < 8 {
                findings.push(format!(
                    "`{c}` is NOT-LOCAL with no reason — say what stops it"
                ));
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
            findings.push(format!(
                "`{c}` has decider `{d}`: expected `prepush: <token>` or `NOT-LOCAL: …`"
            ));
            continue;
        };
        // VERBATIM, because the point is to catch the token moving. A looser match -- the first
        // word, say -- would find `cargo` in a file that is nothing but cargo invocations, and
        // the check would pass while the gauntlet ran something else entirely.
        if !prepush.contains(cmd) {
            findings.push(format!(
                "`{c}` declares `{cmd}`, which does not appear in {PREPUSH}"
            ));
        }
    }

    match pin(deciders_text, "# PINNED = ") {
        Some(p) if p != req.len() => findings.push(format!(
            "PINNED = {p} but {} contexts are required",
            req.len()
        )),
        None => findings.push("no `# PINNED = n` in the header".to_string()),
        Some(_) => {}
    }
    match pin(deciders_text, "# NOT-LOCAL = ") {
        Some(p) if p != not_local => findings.push(format!(
            "NOT-LOCAL = {p} but {not_local} line(s) say NOT-LOCAL"
        )),
        None => findings.push("no `# NOT-LOCAL = n` in the header".to_string()),
        Some(_) => {}
    }

    Audit {
        findings,
        local,
        not_local,
    }
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

    let found = audit(&req, &dec, &prepush, &text);
    let mut failures = 0u32;
    for f in &found.findings {
        fail(&mut failures, f);
    }
    if failures > 0 {
        bail!("the fast gauntlet's list and the required contexts disagree: {failures} finding(s)");
    }
    println!(
        "ok: {} required context(s) — {} decided by the gauntlet, {} declared \
         NOT-LOCAL with a reason",
        req.len(),
        found.local,
        found.not_local
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ledger_parser_drops_comments_blanks_and_the_app_suffix() {
        let got = parse_required(
            "# a comment\n\
             \n\
             Tests\n\
             gatehouse/required @app 4853870\n\
             \x20  Doctests  \n",
        );
        // The `@app` marker names the producer, not the context, so it must not
        // become part of the name the gauntlet looks up.
        assert!(got.contains("gatehouse/required"), "got {got:?}");
        assert!(!got.iter().any(|c| c.contains("@app")));
        assert!(got.contains("Tests") && got.contains("Doctests"));
        assert_eq!(got.len(), 3, "comment and blank contribute nothing");
    }

    #[test]
    fn a_context_keeps_its_internal_spaces() {
        // The reason the separator is an arrow and not whitespace.
        let got = parse_required("Code Coverage (llvm-cov)\n");
        assert!(got.contains("Code Coverage (llvm-cov)"));
    }

    #[test]
    fn the_decider_parser_splits_on_the_arrow_only() {
        let got = parse_deciders(
            "# header\n\
             Code Coverage (llvm-cov) <- NOT-LOCAL: needs a full llvm-cov run\n\
             Tests <- prepush: cargo nextest run\n\
             a line with no arrow at all\n",
        );
        assert_eq!(got.len(), 2, "the arrowless line is not a decider: {got:?}");
        assert_eq!(
            got.get("Code Coverage (llvm-cov)").map(String::as_str),
            Some("NOT-LOCAL: needs a full llvm-cov run"),
            "the context keeps its spaces and the decider keeps its colon"
        );
        assert_eq!(
            got.get("Tests").map(String::as_str),
            Some("prepush: cargo nextest run")
        );
    }

    #[test]
    fn a_decider_containing_the_arrow_splits_at_the_first_one() {
        // The context ends at the FIRST arrow; a later one belongs to the
        // command, which may legitimately contain it.
        let got = parse_deciders("X <- prepush: a <- b\n");
        assert_eq!(got.get("X").map(String::as_str), Some("prepush: a <- b"));
    }

    #[test]
    fn the_pin_reads_the_number_after_its_key_and_nothing_else() {
        let text = "# PINNED = 47\n# NOT-LOCAL = 12\ntrailing\n";
        assert_eq!(pin(text, "PINNED = "), Some(47));
        assert_eq!(pin(text, "NOT-LOCAL = "), Some(12));
    }

    #[test]
    fn a_pin_that_is_absent_or_unparseable_is_none_not_zero() {
        // Zero would read as a real count and pass a comparison against an
        // empty set; None is "could not look", which the caller refuses.
        assert_eq!(pin("nothing here\n", "PINNED = "), None);
        assert_eq!(pin("# PINNED = later\n", "PINNED = "), None);
        assert_eq!(pin("", "PINNED = "), None);
    }

    #[test]
    fn fail_counts_every_call() {
        let mut n = 0;
        fail(&mut n, "first");
        fail(&mut n, "second");
        assert_eq!(n, 2);
    }

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    fn map(items: &[(&str, &str)]) -> BTreeMap<String, String> {
        items
            .iter()
            .map(|(a, b)| ((*a).to_string(), (*b).to_string()))
            .collect()
    }

    /// The shape that must produce NO findings, so every test below is a
    /// departure from a known-good baseline rather than from nothing.
    fn agreeing() -> (BTreeSet<String>, BTreeMap<String, String>, String, String) {
        (
            set(&["Tests", "Coverage"]),
            map(&[
                ("Tests", "prepush: cargo nextest run"),
                ("Coverage", "NOT-LOCAL: needs a full llvm-cov run"),
            ]),
            "cargo nextest run --workspace\n".to_string(),
            "# PINNED = 2\n# NOT-LOCAL = 1\n".to_string(),
        )
    }

    #[test]
    fn an_agreeing_list_has_nothing_to_report() {
        let (req, dec, pre, txt) = agreeing();
        let got = audit(&req, &dec, &pre, &txt);
        assert!(got.findings.is_empty(), "{:?}", got.findings);
        assert_eq!((got.local, got.not_local), (1, 1));
    }

    #[test]
    fn a_required_context_with_no_decider_is_reported() {
        let (_, dec, pre, txt) = agreeing();
        let req = set(&["Tests", "Coverage", "Doctests"]);
        let got = audit(&req, &dec, &pre, &txt);
        // Two findings: the missing decider, and PINNED now disagreeing.
        assert!(
            got.findings
                .iter()
                .any(|f| f.contains("`Doctests` is required")),
            "{:?}",
            got.findings
        );
    }

    #[test]
    fn a_decider_for_a_retired_context_is_reported() {
        let (req, _, pre, txt) = agreeing();
        let dec = map(&[
            ("Tests", "prepush: cargo nextest run"),
            ("Coverage", "NOT-LOCAL: needs a full llvm-cov run"),
            ("Gone", "prepush: cargo nextest run"),
        ]);
        let got = audit(&req, &dec, &pre, &txt);
        assert!(
            got.findings
                .iter()
                .any(|f| f.contains("`Gone`") && f.contains("not a required context")),
            "{:?}",
            got.findings
        );
    }

    #[test]
    fn not_local_without_a_reason_is_reported_and_a_reason_is_accepted() {
        let (req, _, pre, txt) = agreeing();
        let bare = map(&[
            ("Tests", "prepush: cargo nextest run"),
            ("Coverage", "NOT-LOCAL: slow"),
        ]);
        let got = audit(&req, &bare, &pre, &txt);
        assert!(
            got.findings.iter().any(|f| f.contains("say what stops it")),
            "a four-character reason is not a reason: {:?}",
            got.findings
        );
        // And the baseline's real reason passes, so the rule is not vacuous.
        let (_, ok, _, _) = agreeing();
        assert!(audit(&req, &ok, &pre, &txt).findings.is_empty());
    }

    #[test]
    fn a_declared_command_absent_from_the_gauntlet_is_reported() {
        let (req, dec, _, txt) = agreeing();
        let got = audit(&req, &dec, "echo nothing relevant here\n", &txt);
        assert!(
            got.findings
                .iter()
                .any(|f| f.contains("cargo nextest run") && f.contains("does not appear")),
            "{:?}",
            got.findings
        );
    }

    #[test]
    fn the_full_gauntlet_prefix_is_also_the_gauntlet() {
        let (req, _, pre, txt) = agreeing();
        let dec = map(&[
            ("Tests", "prepush --full: cargo nextest run"),
            ("Coverage", "NOT-LOCAL: needs a full llvm-cov run"),
        ]);
        let got = audit(&req, &dec, &pre, &txt);
        assert!(got.findings.is_empty(), "{:?}", got.findings);
        assert_eq!(got.local, 1, "--full still counts as locally decided");
    }

    #[test]
    fn a_decider_in_neither_form_is_reported() {
        let (req, _, pre, txt) = agreeing();
        let dec = map(&[
            ("Tests", "run it yourself"),
            ("Coverage", "NOT-LOCAL: needs a full llvm-cov run"),
        ]);
        let got = audit(&req, &dec, &pre, &txt);
        assert!(
            got.findings.iter().any(|f| f.contains("expected")),
            "{:?}",
            got.findings
        );
    }

    #[test]
    fn both_pins_are_compared_and_a_missing_pin_is_a_finding() {
        let (req, dec, pre, _) = agreeing();
        let wrong = audit(&req, &dec, &pre, "# PINNED = 9\n# NOT-LOCAL = 9\n");
        assert!(wrong.findings.iter().any(|f| f.contains("PINNED = 9")));
        assert!(wrong.findings.iter().any(|f| f.contains("NOT-LOCAL = 9")));
        let absent = audit(&req, &dec, &pre, "no header at all\n");
        assert!(absent.findings.iter().any(|f| f.contains("no `# PINNED")));
        assert!(
            absent
                .findings
                .iter()
                .any(|f| f.contains("no `# NOT-LOCAL"))
        );
    }
}

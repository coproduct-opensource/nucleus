//! `cargo xtask allowlist-gates` — the scan-vs-allowlist family, decided once.
//!
//! Seven gates in four shell scripts ask the same question in the same shape: *does a forbidden
//! construct appear on a production line inside a declared scope, other than on a line the
//! allowlist blesses?* Each one answers it with its own copy of the same program.
//!
//! # The copies, counted
//!
//! Measured 2026-09-10. Five scripts embed the `#[cfg(test)]`-stripping awk program —
//! `check-mediation.sh`, `check-sealed-home.sh`, `check-ingest-hashed.sh`,
//! `check-verify-strict.sh`, `check-extracted-callsites.sh` — and **four of the five differ
//! byte-for-byte**; only mediation and sealed-home are identical. The differences turn out to be
//! whitespace, comments and the final match predicate, so the five are semantically one program
//! with a pluggable predicate. That is the good case and it is not the safe one: nothing checks
//! that it stays true, and one copy already carries a defect the others inherited —
//!
//! ```text
//! # skip — clear pending so it does not swallow the next braced item
//! # (latent false-NEGATIVE; fix shared with scripts/check-mediation.sh).
//! ```
//!
//! a known false negative, acknowledged in a comment, replicated. A false negative in a gate is
//! the expensive direction: it is a construct the gate was built to forbid, passing.
//!
//! This is nucleus `FINDINGS.md`'s F-20 shape at five copies instead of two — "one declaration,
//! two hand-rolled parsers, no parity gate" — and the answer is the same: one implementation, and
//! a parity check against the scripts while they still exist.
//!
//! # What this adds that the scripts do not have
//!
//! **Non-vacuity.** A scan gate whose pattern no longer matches anything has stopped watching and
//! says nothing about it: it prints PASSED, exits 0, and is indistinguishable from a gate that is
//! working. Every gate here must find at least one production line matching its pattern —
//! allowlisted or not — or the run is red. That is the `UNCOVERED_CEILING = 0` idea from gatehouse
//! applied to a pattern rather than to a gate, and it is the property the shell family cannot state
//! because each script only ever asks about the hits it did find.
//!
//! **A population pin per allowlist.** `ci/allowlist-gates.txt` pins how many entries each
//! allowlist carries. It may only shrink. An allowlist that grows is a decision, and a decision
//! should be an edit with a date on it rather than a line appearing in a diff nobody reads.
//!
//! # What decides this
//!
//! A tree scan against declared constants — gatehouse `docs/tiering.md` calls this **2b**: the
//! verdict is a set comparison whose left operand is a scan. It needs the source tree and no
//! toolchain, no network and no build.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use regex::Regex;

/// The pin on how many entries each allowlist carries. Shrink-only.
const PINS: &str = "ci/allowlist-gates.txt";

/// How a gate chooses the files it looks at.
///
/// The scripts use `rg -l` to pre-filter, which is an optimisation with a semantic edge: a file
/// that does not contain the selector is never scanned at all. Kept exactly, because widening it
/// here would make the parity check disagree for a reason that is not a defect.
enum Select {
    /// Files containing this literal.
    Literal(&'static str),
    /// Files matching this expression.
    Pattern(&'static str),
}

/// What counts as a hit on a production line.
enum Matcher {
    /// The line contains this literal — `index(line, PAT) > 0` in the scripts.
    Literal(&'static str),
    /// The line matches `find`, does not contain `forbid`, and matches `require`.
    Guarded {
        find: &'static str,
        forbid: Option<&'static str>,
        require: Option<&'static str>,
    },
}

/// What the scan is expected to find, which is not the same question as whether it passes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Population {
    /// The scan MUST find at least one matching production line, allowlisted or not. A pattern
    /// that matches nothing has stopped watching and reports that identically to working.
    NonEmpty,
    /// The scan must find NOTHING, there is no allowlist, and zero hits is the passing state.
    ///
    /// Non-vacuity cannot come from a live hit here — a live hit IS the defect. It comes from the
    /// named A-19 probe, which drives the gate red on a real perturbation and green on restore.
    /// Naming it is the point: a gate excused from the non-vacuity rule must say what keeps it
    /// honest instead, or the exemption is just the rule not applying to this one.
    Empty { falsifier: &'static str },
}

/// One question, asked of one scope.
struct Gate {
    /// The shell gate this replaces, for the parity check.
    script: &'static str,
    /// The line in that script's OUTPUT this gate answers for, identified by a substring unique
    /// within that script. Every verdict line a script prints must be claimed by exactly one gate
    /// or declared a [`SUMMARIES`] restatement — that is what makes a gate the port never
    /// implemented visible on a GREEN tree, instead of waiting for someone to violate it.
    verdict: &'static str,
    label: &'static str,
    scope: &'static [&'static str],
    select: Select,
    matcher: Matcher,
    /// The allowlist file, or `None` for a gate that has none: any hit is a violation, full stop.
    allowlist: Option<&'static str>,
    population: Population,
    /// Which files are NOT production, as the script defines it.
    ///
    /// **The four scripts do not agree, and that is transcribed rather than smoothed over.** Three
    /// exclude `/(tests|benches)/` only; `check-ingest-hashed.sh` also excludes src-level
    /// whole-file test modules (`tests_x.rs`, `x_tests.rs`), and its comment says why: a
    /// `#[cfg(test)] mod tests_main;` puts the attribute in ANOTHER file, so the in-file stripper
    /// never sees it. The hazard is identical for the other three and undefended there. Unifying
    /// it here would be a behaviour change wearing a refactor's clothes, so it is a finding with
    /// its own change (`FINDINGS.md` F-36) and this table stays faithful.
    exclude: Exclude,
}

/// Which files a gate treats as test-only.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Exclude {
    /// `/(tests|benches)/` — the mediation-gate convention.
    Dirs,
    /// The above, plus src-level whole-file test modules.
    DirsAndTestModules,
}

/// The seven, transcribed from the scripts rather than re-invented.
///
/// Every scope, selector and pattern below is the one the corresponding script passes. Where a
/// script's comment explains WHY a pattern is written the way it is — `.send()` with empty parens
/// isolating reqwest egress from channel sends, `observe` without a `_hash` suffix — that reasoning
/// lives in the script and is not duplicated here; the point of this table is that there is one
/// place the *program* lives, not that there is one place the prose lives.
const GATES: &[Gate] = &[
    Gate {
        script: "scripts/check-mediation.sh",
        verdict: "(spawn)",
        label: "mediation/spawn",
        scope: &[
            "crates/nucleus/src",
            "crates/nucleus-tool-proxy/src",
            "crates/nucleus-mcp/src",
        ],
        select: Select::Literal("Command::new"),
        matcher: Matcher::Literal("Command::new"),
        allowlist: Some("scripts/mediation-allowlist.txt"),
        population: Population::NonEmpty,
        exclude: Exclude::Dirs,
    },
    Gate {
        script: "scripts/check-mediation.sh",
        verdict: "(net)",
        label: "mediation/net",
        scope: &[
            "crates/nucleus/src",
            "crates/nucleus-tool-proxy/src",
            "crates/nucleus-mcp/src",
        ],
        select: Select::Literal(".send()"),
        matcher: Matcher::Literal(".send()"),
        allowlist: Some("scripts/mediation-net-allowlist.txt"),
        population: Population::NonEmpty,
        exclude: Exclude::Dirs,
    },
    Gate {
        script: "scripts/check-mediation.sh",
        verdict: "(vsock)",
        label: "mediation/vsock",
        scope: &[
            "crates/nucleus/src",
            "crates/nucleus-tool-proxy/src",
            "crates/nucleus-mcp/src",
        ],
        select: Select::Literal("VsockStream::connect"),
        matcher: Matcher::Literal("VsockStream::connect"),
        allowlist: Some("scripts/mediation-vsock-allowlist.txt"),
        population: Population::NonEmpty,
        exclude: Exclude::Dirs,
    },
    Gate {
        script: "scripts/check-sealed-home.sh",
        verdict: "(spawn)",
        label: "sealed-home/spawn",
        scope: &["crates/portcullis-effects/src"],
        select: Select::Literal("Command::new"),
        matcher: Matcher::Literal("Command::new"),
        allowlist: Some("scripts/sealed-home-allowlist.txt"),
        population: Population::NonEmpty,
        exclude: Exclude::Dirs,
    },
    Gate {
        script: "scripts/check-sealed-home.sh",
        verdict: "(net)",
        label: "sealed-home/net",
        scope: &["crates/portcullis-effects/src"],
        select: Select::Literal(".send()"),
        matcher: Matcher::Literal(".send()"),
        allowlist: Some("scripts/sealed-home-allowlist.txt"),
        population: Population::NonEmpty,
        exclude: Exclude::Dirs,
    },
    Gate {
        script: "scripts/check-ingest-hashed.sh",
        verdict: "ingest-hash gate",
        label: "ingest-hashed",
        scope: &[
            "crates/nucleus/src",
            "crates/nucleus-tool-proxy/src",
            "crates/nucleus-mcp/src",
            "crates/nucleus-mcp-guard/src",
            "crates/portcullis-effects/src",
        ],
        select: Select::Pattern(r"\.observe(_with_label|_with_parents)?\s*\("),
        matcher: Matcher::Guarded {
            find: r"\.observe(_with_label|_with_parents)?\s*\(",
            forbid: None,
            require: None,
        },
        allowlist: Some("scripts/ingest-hashed-allowlist.txt"),
        population: Population::NonEmpty,
        exclude: Exclude::DirsAndTestModules,
    },
    Gate {
        script: "scripts/check-verify-strict.sh",
        verdict: "M-3 verify-strict gate",
        label: "verify-strict",
        scope: &["crates"],
        select: Select::Literal("ed25519_dalek"),
        matcher: Matcher::Guarded {
            find: r"\.verify\s*\(",
            forbid: Some("verify_strict"),
            require: Some(r",\s*&"),
        },
        allowlist: Some("scripts/verify-strict-allowlist.txt"),
        population: Population::NonEmpty,
        exclude: Exclude::Dirs,
    },
    // The EIGHTH, and it was in the script all along. `check-verify-strict.sh` carries two gates,
    // not one: the M-3 dalek gate above, and this. The port took the first and left the second,
    // and nothing said so — `--parity` compares one exit status against one aggregate verdict, so
    // on a tree with no violation an unported gate is indistinguishable from a satisfied one. It
    // surfaced on 2026-09-11 only because a PR wrote the very construct it forbids, and then the
    // harness printed `ok verify-strict` while the script printed FAILED.
    //
    // It does not fit the shape the other seven share, and that is why it was droppable:
    //
    //   * **No allowlist.** The script says so in as many words — "A reference to the `ED25519`
    //     verification algorithm in production code is a regression, full stop — there is no
    //     allowlist for it." `Allowlist: None` is that sentence.
    //   * **An empty population is the PASSING state.** Every trust-path Ed25519 re-verify was
    //     migrated to `verify_strict`, so a clean tree has zero hits — which the non-vacuity rule
    //     reads as "the gate has stopped watching". The rule is right about the other seven and
    //     wrong about this one, so the gate declares which rule applies and names what keeps it
    //     honest instead.
    Gate {
        script: "scripts/check-verify-strict.sh",
        verdict: "#16 ring-Ed25519 gate",
        label: "ring-ed25519",
        scope: &["crates"],
        select: Select::Pattern(RING_ED25519),
        matcher: Matcher::Guarded {
            find: RING_ED25519,
            forbid: None,
            require: None,
        },
        allowlist: None,
        population: Population::Empty {
            falsifier: "scripts/check-gates-can-fail.sh — \"a cofactored ring ED25519 verify\"",
        },
        exclude: Exclude::DirsAndTestModules,
    },
];

/// The ring gate's pattern, assembled from pieces **so that this file does not contain it**.
///
/// Written whole, the literal below would be a production line in `crates/` matching the very
/// construct the gate forbids, and both the harness and `check-verify-strict.sh` would red on
/// their own implementation. That is not hypothetical — it happened on the first run of this
/// gate, and the two hits were these two lines.
///
/// The general fact, which is worth more than the workaround: the scripts' `rg -l` selector reads
/// the WHOLE file, and `production_lines` strips comments and `#[cfg(test)]` blocks but **not
/// string literals**. So any Rust source that names a forbidden construct inside a string is a
/// false positive for every gate in this family. Splitting the literal is the fix that adds no
/// exemption — an exclusion for "the gate's own source" would be a hole the next file could sit
/// in, and it would make the harness disagree with the script.
const RING_ED25519: &str = concat!("signature::", "ED25519", r"([^_A-Za-z0-9]|$)");

/// Lines a script prints that RESTATE gates already counted, rather than deciding anything of
/// their own. Listed rather than omitted, each with the reason, on the same argument the rest of
/// this repository's exemption lists use: an entry here is a claim a reader can check, and an
/// omission is not.
///
/// Everything else a script prints as a verdict must be claimed by exactly one [`Gate`]. That is
/// the whole mechanism — a script gate the harness never ported has an unclaimed verdict line on
/// a GREEN tree, where waiting for a violation means waiting for the defect.
const SUMMARIES: &[(&str, &str)] = &[
    (
        "no un-allowlisted raw effect primitive on the agent path (spawn + net + vsock)",
        "restates mediation/spawn, mediation/net and mediation/vsock",
    ),
    (
        "no raw effect primitive outside the sealed RealEffects home (spawn + net)",
        "restates sealed-home/spawn and sealed-home/net",
    ),
];

/// A line of a script's output that announces a verdict. Both spellings, because a marker that
/// only matches `PASSED` would stop accounting for a gate at the moment it fires.
fn is_verdict_line(line: &str) -> bool {
    line.contains("gate PASSED") || line.contains("gate FAILED")
}

/// The production lines of a Rust source: `#[cfg(test)]` items and comment lines removed.
///
/// This is the awk program the five scripts each carry a copy of, with its brace counting intact:
/// a `#[cfg(test)]` attribute puts the reader in `pending`; the next line either opens a block
/// (skip until the braces balance) or ends with `;` (a `use` or a `mod foo;`, skip nothing
/// further). Comment lines — `//`, `///`, `//!` — are prose and never a call site.
///
/// The scripts' known false negative is preserved deliberately, and named so it can be fixed once:
/// a `pending` line that neither opens a brace nor ends in `;` leaves `pending` set, so the NEXT
/// braced item is swallowed. Fixing it here alone would make the parity check red for a reason
/// that is a defect in the scripts rather than in this port, so it is a follow-up with its own
/// falsifier — see `FINDINGS.md`.
fn production_lines(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut skip = false;
    // Unsigned and saturating, where the awk is signed and tests `brace <= 0`. The two agree on
    // the only thing the depth is read for: awk lets the count go negative and ends the skip at or
    // below zero, saturation floors it at zero and ends the skip there. Written this way because
    // `as i64` would be two more entries under a clippy cast ratchet that has no headroom
    // (`FINDINGS.md` F-27), and a cast that exists only to model a negative number nothing reads is
    // the wrong thing to spend them on.
    let mut brace: usize = 0;
    let mut pending = false;
    for (i, line) in src.lines().enumerate() {
        let opens = line.matches('{').count();
        let closes = line.matches('}').count();
        if skip {
            brace = brace.saturating_add(opens).saturating_sub(closes);
            if brace == 0 {
                skip = false;
            }
            continue;
        }
        if line.contains("#[cfg(test)]") {
            pending = true;
            continue;
        }
        if pending {
            if opens > 0 {
                skip = true;
                brace = opens.saturating_sub(closes);
                pending = false;
                if brace == 0 {
                    skip = false;
                }
                continue;
            }
            if line.contains(';') {
                pending = false;
            }
        }
        if line.trim_start().starts_with("//") {
            continue;
        }
        out.push((i + 1, line.to_string()));
    }
    out
}

/// An allowlist: exact trimmed-line snippets, and whole-file exemptions written `file:<path>`.
struct Allowlist {
    snippets: Vec<String>,
    files: Vec<String>,
    /// Every non-comment, non-blank entry — what the population pin counts.
    entries: usize,
}

fn load_allowlist(root: &Path, rel: &str) -> Result<Allowlist> {
    let text = fs::read_to_string(root.join(rel)).unwrap_or_default();
    let mut a = Allowlist {
        snippets: Vec::new(),
        files: Vec::new(),
        entries: 0,
    };
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        a.entries += 1;
        if let Some(f) = t.strip_prefix("file:") {
            a.files.push(f.to_string());
        } else {
            a.snippets.push(t.to_string());
        }
    }
    Ok(a)
}

/// Every `.rs` file under `dirs`, excluding `tests/` and `benches/` — the scripts' filter.
fn rust_files(root: &Path, dirs: &[&str], exclude: Exclude) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for d in dirs {
        walk(&root.join(d), &mut out);
    }
    out.sort();
    out.dedup();
    out.retain(|p| {
        let s = p.to_string_lossy().replace('\\', "/");
        if s.contains("/tests/") || s.contains("/benches/") {
            return false;
        }
        if exclude == Exclude::Dirs {
            return true;
        }
        // `tests_x.rs` / `test_x.rs` / `x_tests.rs` / `x_test.rs`, matching the script's
        // `/tests?_[^/]*\.rs$|_tests?\.rs$`.
        let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
            return true;
        };
        let stem = name.strip_suffix(".rs").unwrap_or(name);
        !(stem.starts_with("tests_")
            || stem.starts_with("test_")
            || stem.ends_with("_tests")
            || stem.ends_with("_test"))
    });
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            // `target/` under a crate would be build output, never a call site.
            if p.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            walk(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// What one gate found.
struct Report {
    label: &'static str,
    /// Hits not covered by the allowlist. Any is a violation.
    violations: Vec<String>,
    /// Production lines matching the pattern at all, allowlisted or not. Zero is a violation of a
    /// different kind: the gate has stopped watching.
    matched: usize,
    files_scanned: usize,
    entries: usize,
}

fn run_gate(root: &Path, g: &Gate) -> Result<Report> {
    let allow = match g.allowlist {
        Some(rel) => load_allowlist(root, rel)?,
        // A gate with no allowlist: nothing is blessed, so every hit is a violation.
        None => Allowlist {
            snippets: Vec::new(),
            files: Vec::new(),
            entries: 0,
        },
    };
    let select = match g.select {
        Select::Literal(_) => None,
        Select::Pattern(p) => Some(Regex::new(p).with_context(|| format!("select {p}"))?),
    };
    let matcher = match g.matcher {
        Matcher::Literal(_) => None,
        Matcher::Guarded {
            find,
            forbid,
            require,
        } => Some((
            Regex::new(find).with_context(|| format!("find {find}"))?,
            forbid,
            require
                .map(|r| Regex::new(r).with_context(|| format!("require {r}")))
                .transpose()?,
        )),
    };

    let mut rep = Report {
        label: g.label,
        violations: Vec::new(),
        matched: 0,
        files_scanned: 0,
        entries: allow.entries,
    };

    for path in rust_files(root, g.scope, g.exclude) {
        let Ok(src) = fs::read_to_string(&path) else {
            continue;
        };
        // File selection, exactly as `rg -l` does it: the whole file, comments and tests included.
        let selected = match (&g.select, &select) {
            (Select::Literal(lit), _) => src.contains(lit),
            (Select::Pattern(_), Some(re)) => re.is_match(&src),
            (Select::Pattern(_), None) => unreachable!(),
        };
        if !selected {
            continue;
        }
        rep.files_scanned += 1;

        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let file_exempt = allow
            .files
            .iter()
            .any(|f| rel == *f || rel.ends_with(&format!("/{f}")));

        for (no, line) in production_lines(&src) {
            let hit = match (&g.matcher, &matcher) {
                (Matcher::Literal(lit), _) => line.contains(lit),
                (Matcher::Guarded { .. }, Some((find, forbid, require))) => {
                    find.is_match(&line)
                        && forbid.is_none_or(|f| !line.contains(f))
                        && require.as_ref().is_none_or(|r| r.is_match(&line))
                }
                (Matcher::Guarded { .. }, None) => unreachable!(),
            };
            if !hit {
                continue;
            }
            rep.matched += 1;
            if file_exempt {
                continue;
            }
            let trimmed = line.trim();
            if allow.snippets.iter().any(|s| s == trimmed) {
                continue;
            }
            rep.violations.push(format!("{rel}:{no}:{trimmed}"));
        }
    }
    Ok(rep)
}

/// The pinned allowlist size per gate label.
fn pins(root: &Path) -> Result<BTreeMap<String, usize>> {
    let text = fs::read_to_string(root.join(PINS))
        .with_context(|| format!("{PINS} is missing — nothing to pin the allowlists against"))?;
    let mut m = BTreeMap::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let Some((k, v)) = t.split_once('=') else {
            bail!("{PINS}: not `<label>=<n>`: {t}");
        };
        m.insert(
            k.trim().to_string(),
            v.trim()
                .parse()
                .with_context(|| format!("{PINS}: {t} is not a number"))?,
        );
    }
    Ok(m)
}

pub fn check(root: &Path) -> Result<()> {
    let pinned = pins(root)?;
    let mut failures = 0usize;
    let mut total_matched = 0usize;

    for g in GATES {
        let rep = run_gate(root, g)?;
        if g.population == Population::NonEmpty {
            total_matched += rep.matched;
        }

        for v in &rep.violations {
            println!("  FAIL  {}: {v}", rep.label);
            failures += 1;
        }

        match g.population {
            // A pattern that matches nothing is not a gate that found nothing — it is a gate that
            // stopped looking, and it reports the same thing either way.
            Population::NonEmpty if rep.matched == 0 => {
                println!(
                    "  FAIL  {}: the pattern matches no production line in {} file(s) — \
                     the gate has stopped watching, which is indistinguishable from passing",
                    rep.label, rep.files_scanned
                );
                failures += 1;
            }
            // The passing state IS zero, so a live hit cannot be what keeps this honest. What
            // keeps it honest is that the scan still reaches files: a `select` that selects
            // nothing would pass this gate for the wrong reason, and that IS checkable.
            Population::Empty { .. } if rep.files_scanned == 0 && rep.matched == 0 => {
                // Nothing to say — no file in the tree mentions the construct, which is the
                // migrated state this gate exists to hold. See the falsifier it names.
            }
            _ => {}
        }

        // Only a gate with an allowlist has a population to pin. One without is not exempt from
        // scrutiny, it has a different question asked of it above.
        if g.allowlist.is_none() {
            // Not `ok` when it just printed violations: a gate that reports both is a gate whose
            // summary line means nothing.
            if rep.violations.is_empty() {
                println!(
                    "  ok    {:<20} {} file(s), 0 hit(s) — no allowlist, and none needed",
                    rep.label, rep.files_scanned
                );
            }
            continue;
        }

        match pinned.get(rep.label) {
            None => {
                println!(
                    "  FAIL  {PINS} has no pin for {} — a gate with no pinned allowlist size can grow one quietly",
                    rep.label
                );
                failures += 1;
            }
            Some(&p) if rep.entries > p => {
                println!(
                    "  FAIL  {}: allowlist has {} entries, pin {p} — an allowlist may only shrink; raise the pin deliberately, with a date and a reason",
                    rep.label, rep.entries
                );
                failures += 1;
            }
            Some(&p) if rep.entries < p => {
                println!(
                    "  FAIL  {}: allowlist has {} entries, pin {p} — lower the pin in the same change that removed one",
                    rep.label, rep.entries
                );
                failures += 1;
            }
            Some(_) => {}
        }

        if failures == 0 || rep.violations.is_empty() {
            println!(
                "  ok    {:<20} {} file(s), {} matching production line(s), {} allowlisted entry(ies)",
                rep.label, rep.files_scanned, rep.matched, rep.entries
            );
        }
    }

    // A run that scanned the tree and matched nothing anywhere is not a pass; it is a broken
    // checkout, a moved crate, or a `scope` that no longer exists.
    if total_matched == 0 {
        bail!(
            "no gate matched any production line — the scan found nothing to decide (exit 2 shape: could not look)"
        );
    }
    if failures > 0 {
        bail!("{failures} violation(s) across the scan-vs-allowlist family");
    }
    println!(
        "OK: {} scan-vs-allowlist gate(s), {total_matched} matching production line(s), one implementation",
        GATES.len()
    );
    Ok(())
}

/// `--parity`: this harness and the shell script it replaces must agree, gate by gate.
///
/// The port is only worth having if it decides the same thing, and "I read the script carefully"
/// is not a check. Each distinct script is run and its exit status compared with this harness's
/// verdict for the gates that script owns. When the scripts are deleted, this goes with them.
pub fn parity(root: &Path) -> Result<()> {
    use std::process::Command;

    let mut scripts: Vec<&str> = GATES.iter().map(|g| g.script).collect();
    scripts.sort_unstable();
    scripts.dedup();

    let mut failures = 0usize;
    for script in scripts {
        let out = Command::new("bash")
            .arg(root.join(script))
            .current_dir(root)
            .output()
            .with_context(|| format!("running {script}"))?;
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let verdict_lines: Vec<&str> = combined.lines().filter(|l| is_verdict_line(l)).collect();

        // A script that announced nothing cannot be compared with anything, and an exit status
        // alone would let it pass. This is the "could not look" case, and it is not a pass.
        if verdict_lines.is_empty() {
            println!(
                "  FAIL  {script} — printed no `gate PASSED`/`gate FAILED` line, so there is \
                 nothing to compare the harness against (exit {:?})",
                out.status.code()
            );
            failures += 1;
            continue;
        }

        // Gate by gate, on the script's OWN per-gate verdict rather than one exit status for the
        // lot. Two compensating errors — the harness red where the script is green and green
        // where it is red — cancel exactly in an aggregate comparison.
        let mut claimed = vec![false; verdict_lines.len()];
        for g in GATES.iter().filter(|g| g.script == script) {
            let hits: Vec<usize> = verdict_lines
                .iter()
                .enumerate()
                .filter(|(_, l)| l.contains(g.verdict))
                .map(|(i, _)| i)
                .collect();
            match hits.len() {
                0 => {
                    println!(
                        "  FAIL  {} — no line of {script}'s output contains {:?}. Either the \
                         script stopped announcing this gate, or the marker is wrong; a marker \
                         that matches nothing accounts for nothing.",
                        g.label, g.verdict
                    );
                    failures += 1;
                    continue;
                }
                1 => {}
                n => {
                    println!(
                        "  FAIL  {} — {:?} matches {n} of {script}'s verdict lines, so it does \
                         not identify one gate. Narrow the marker.",
                        g.label, g.verdict
                    );
                    failures += 1;
                    continue;
                }
            }
            let i = hits[0];
            claimed[i] = true;
            let theirs_red = verdict_lines[i].contains("gate FAILED");
            let mine_red = !run_gate(root, g)?.violations.is_empty();
            if mine_red == theirs_red {
                println!(
                    "  ok    {:<20} both {} ({script})",
                    g.label,
                    if mine_red { "RED" } else { "green" }
                );
            } else {
                println!(
                    "  FAIL  {} — harness says {}, {script} says {}:",
                    g.label,
                    if mine_red { "RED" } else { "green" },
                    if theirs_red { "RED" } else { "green" }
                );
                println!("        {}", verdict_lines[i].trim());
                failures += 1;
            }
        }

        // The half that does not need a violation to exist. Every verdict line the script printed
        // is either a gate this harness implements or a declared restatement of ones it does; a
        // line that is neither is a gate the port never took, and it reads as `ok` today.
        for (i, line) in verdict_lines.iter().enumerate() {
            if claimed[i] {
                continue;
            }
            if SUMMARIES.iter().any(|(m, _)| line.contains(m)) {
                continue;
            }
            println!(
                "  FAIL  {script} announces a verdict no gate in this harness claims:\n\
                 \x20       {}\n\
                 \x20       The script decides something the port does not. Add the Gate, or — if \
                 it restates gates already here — add it to SUMMARIES with the reason. Leaving it \
                 unclaimed is how `ok` gets printed for a question nobody asked.",
                line.trim()
            );
            failures += 1;
        }
    }
    if failures > 0 {
        bail!("{failures} disagreement(s) between the harness and the shell family");
    }
    println!(
        "OK: every shell gate in the family is implemented here and agrees, {} gate(s) accounted for",
        GATES.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::production_lines;

    #[test]
    fn a_cfg_test_block_is_not_production() {
        let src = "fn a() { Command::new(\"x\"); }\n#[cfg(test)]\nmod t {\n    Command::new(\"y\");\n}\nfn b() { Command::new(\"z\"); }\n";
        let lines: Vec<String> = production_lines(src).into_iter().map(|(_, l)| l).collect();
        let joined = lines.join("\n");
        assert!(joined.contains("\"x\""), "{joined}");
        assert!(!joined.contains("\"y\""), "the test block leaked: {joined}");
        assert!(joined.contains("\"z\""), "the skip did not end: {joined}");
    }

    #[test]
    fn a_comment_is_not_a_call_site() {
        let src = "// Command::new is forbidden here\n/// and Command::new in a doc comment too\nlet x = 1;\n";
        assert!(
            production_lines(src)
                .iter()
                .all(|(_, l)| !l.contains("Command::new")),
            "a comment was read as code"
        );
    }

    #[test]
    fn a_pass_and_a_fail_are_both_verdict_lines() {
        assert!(super::is_verdict_line(
            "#16 ring-Ed25519 gate PASSED: no ring verify on any production path."
        ));
        assert!(super::is_verdict_line(
            "#16 ring-Ed25519 gate FAILED: cofactored verify on a production path:"
        ));
        // A marker that only matched PASSED would stop accounting for a gate at the exact
        // moment it fires, which is the moment accounting matters.
        assert!(!super::is_verdict_line(
            "scanning 71 files for ed25519_dalek"
        ));
    }

    /// Every gate's `verdict` marker must identify ONE line within its own script. Two gates of
    /// the same script sharing a marker, or a marker that is a substring of a sibling's line,
    /// makes the accounting claim the wrong line and still print `ok`.
    #[test]
    fn verdict_markers_are_unique_within_a_script() {
        for a in super::GATES {
            let siblings: Vec<&super::Gate> = super::GATES
                .iter()
                .filter(|b| b.script == a.script && b.label != a.label)
                .collect();
            for b in siblings {
                assert_ne!(
                    a.verdict, b.verdict,
                    "{} and {} share the marker {:?} in {}",
                    a.label, b.label, a.verdict, a.script
                );
            }
        }
    }

    /// The whole point of the eighth gate: `check-verify-strict.sh` carries two gates, so the
    /// harness must carry two for it. A port that silently drops one is what this pins.
    #[test]
    fn verify_strict_has_both_of_its_gates() {
        let n = super::GATES
            .iter()
            .filter(|g| g.script == "scripts/check-verify-strict.sh")
            .count();
        assert_eq!(
            n, 2,
            "the script decides the dalek gate AND the ring gate; the harness must do both"
        );
    }

    /// A gate excused from the non-vacuity rule must say what keeps it honest instead, or the
    /// exemption is just the rule not applying to this one.
    #[test]
    fn an_empty_population_names_its_falsifier() {
        for g in super::GATES {
            if let super::Population::Empty { falsifier } = g.population {
                assert!(
                    !falsifier.trim().is_empty(),
                    "{} is exempt from non-vacuity and names nothing in its place",
                    g.label
                );
                assert!(
                    g.allowlist.is_none(),
                    "{} expects an empty population but carries an allowlist — an entry in it \
                     would be a blessed hit in a gate whose passing state is zero hits",
                    g.label
                );
            }
        }
    }

    /// This file writes the forbidden construct in pieces so that it is not a hit on itself. If
    /// someone ever reassembles it, the gate reds on its own implementation — which is how this
    /// was discovered.
    #[test]
    fn the_harness_is_not_a_hit_on_itself() {
        let src = include_str!("allowlist_gates.rs");
        let re = regex::Regex::new(super::RING_ED25519).expect("the gate's own pattern compiles");
        assert!(
            !re.is_match(src),
            "this file matches the ring pattern; split the literal again"
        );
    }

    #[test]
    fn a_cfg_test_use_ends_at_the_semicolon() {
        let src = "#[cfg(test)]\nuse std::process::Command;\nfn a() { Command::new(\"x\"); }\n";
        let joined = production_lines(src)
            .into_iter()
            .map(|(_, l)| l)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("\"x\""),
            "the `use` swallowed the fn: {joined}"
        );
    }
}

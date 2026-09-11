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

/// One question, asked of one scope.
struct Gate {
    /// The shell gate this replaces, for the parity check.
    script: &'static str,
    label: &'static str,
    scope: &'static [&'static str],
    select: Select,
    matcher: Matcher,
    allowlist: &'static str,
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
        label: "mediation/spawn",
        scope: &[
            "crates/nucleus/src",
            "crates/nucleus-tool-proxy/src",
            "crates/nucleus-mcp/src",
        ],
        select: Select::Literal("Command::new"),
        matcher: Matcher::Literal("Command::new"),
        allowlist: "scripts/mediation-allowlist.txt",
        exclude: Exclude::Dirs,
    },
    Gate {
        script: "scripts/check-mediation.sh",
        label: "mediation/net",
        scope: &[
            "crates/nucleus/src",
            "crates/nucleus-tool-proxy/src",
            "crates/nucleus-mcp/src",
        ],
        select: Select::Literal(".send()"),
        matcher: Matcher::Literal(".send()"),
        allowlist: "scripts/mediation-net-allowlist.txt",
        exclude: Exclude::Dirs,
    },
    Gate {
        script: "scripts/check-mediation.sh",
        label: "mediation/vsock",
        scope: &[
            "crates/nucleus/src",
            "crates/nucleus-tool-proxy/src",
            "crates/nucleus-mcp/src",
        ],
        select: Select::Literal("VsockStream::connect"),
        matcher: Matcher::Literal("VsockStream::connect"),
        allowlist: "scripts/mediation-vsock-allowlist.txt",
        exclude: Exclude::Dirs,
    },
    Gate {
        script: "scripts/check-sealed-home.sh",
        label: "sealed-home/spawn",
        scope: &["crates/portcullis-effects/src"],
        select: Select::Literal("Command::new"),
        matcher: Matcher::Literal("Command::new"),
        allowlist: "scripts/sealed-home-allowlist.txt",
        exclude: Exclude::Dirs,
    },
    Gate {
        script: "scripts/check-sealed-home.sh",
        label: "sealed-home/net",
        scope: &["crates/portcullis-effects/src"],
        select: Select::Literal(".send()"),
        matcher: Matcher::Literal(".send()"),
        allowlist: "scripts/sealed-home-allowlist.txt",
        exclude: Exclude::Dirs,
    },
    Gate {
        script: "scripts/check-ingest-hashed.sh",
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
        allowlist: "scripts/ingest-hashed-allowlist.txt",
        exclude: Exclude::DirsAndTestModules,
    },
    Gate {
        script: "scripts/check-verify-strict.sh",
        label: "verify-strict",
        scope: &["crates"],
        select: Select::Literal("ed25519_dalek"),
        matcher: Matcher::Guarded {
            find: r"\.verify\s*\(",
            forbid: Some("verify_strict"),
            require: Some(r",\s*&"),
        },
        allowlist: "scripts/verify-strict-allowlist.txt",
        exclude: Exclude::Dirs,
    },
];

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
    let allow = load_allowlist(root, g.allowlist)?;
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
        total_matched += rep.matched;

        for v in &rep.violations {
            println!("  FAIL  {}: {v}", rep.label);
            failures += 1;
        }

        // A pattern that matches nothing is not a gate that found nothing — it is a gate that
        // stopped looking, and it reports the same thing either way.
        if rep.matched == 0 {
            println!(
                "  FAIL  {}: the pattern matches no production line in {} file(s) — \
                 the gate has stopped watching, which is indistinguishable from passing",
                rep.label, rep.files_scanned
            );
            failures += 1;
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
        let mine_red = GATES
            .iter()
            .filter(|g| g.script == script)
            .map(|g| run_gate(root, g))
            .collect::<Result<Vec<_>>>()?
            .iter()
            .any(|r| !r.violations.is_empty());

        let out = Command::new("bash")
            .arg(root.join(script))
            .current_dir(root)
            .output()
            .with_context(|| format!("running {script}"))?;
        let theirs_red = !out.status.success();

        if mine_red == theirs_red {
            println!(
                "  ok    {script} — both {}",
                if mine_red { "RED" } else { "green" }
            );
        } else {
            println!(
                "  FAIL  {script} — harness says {}, the script says {} (exit {:?})",
                if mine_red { "RED" } else { "green" },
                if theirs_red { "RED" } else { "green" },
                out.status.code()
            );
            print!("{}", String::from_utf8_lossy(&out.stderr));
            failures += 1;
        }
    }
    if failures > 0 {
        bail!("{failures} script(s) disagree with the harness");
    }
    println!("OK: every shell gate in the family agrees with the harness");
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

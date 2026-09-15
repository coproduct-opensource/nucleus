//! `cargo xtask fly-pools` — the committed runner-pool default must be one the manager accepts.
//!
//! `ci/fly-runner/manager.toml` carries a `POOLS` default that a fresh deployment uses
//! until `fly secrets set POOLS=...` replaces it with the real volume ids. The manager
//! validates that JSON at startup (`ci_fly_runner::parse_pools`), and nothing validated
//! the committed copy — so the tracked default could be, and was, a configuration the
//! manager refuses:
//!
//! ```text
//! "size":8,"standby":8,"requires_volume":true      and no "volumes" key
//! ```
//!
//! `requires_volume` with zero volumes for eight machines is rejected by
//! `crates/ci-fly-runner/src/lib.rs`, whose message explains why it must be:
//! machines past the end of the volume list "would compile onto the root filesystem and
//! run out of disk". That failure is not hypothetical — `requires_volume`'s own doc
//! records it costing four required checks, ejected from the merge queue while looking
//! clean, after `ld terminated with signal 7 [Bus error]` and then ENOSPC.
//!
//! The comment two lines above the value asserted the opposite: "this tracked default
//! has none, so a fresh deployment works without them (cold caches)." It could not.
//!
//! This calls **the manager's own validator**. A second implementation of the rule would
//! be a second thing to drift, which is the failure this whole family of gates exists to
//! refuse.
//!
//! # What decides this
//!
//! One committed TOML file. No source tree, no Fly API, no network.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

const MANAGER_TOML: &str = "ci/fly-runner/manager.toml";
/// The prose table that documents the same pools, and disagreed with them.
const README: &str = "ci/fly-runner/README.md";
/// How many `(pool, field)` pairs the README and the TOML may still disagree on. Shrink-only.
const DRIFT: &str = "ci/fly-pools-drift.txt";
/// The other config the same README restates numbers from.
const QUEUE_TOML: &str = "ci/merge-queue.toml";
/// The numeric merge-queue constants this README quotes. One today; the list is the extension
/// point, and a key added here is compared without further code.
const QUEUE_KEYS: &[&str] = &["max_entries_to_build"];

/// The `POOLS = '...'` value, as the manager would receive it.
pub fn pools_json(manager_toml: &str) -> Result<String> {
    for line in manager_toml.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("POOLS") {
            let rest = rest.trim_start();
            let Some(rest) = rest.strip_prefix('=') else {
                continue;
            };
            let rest = rest.trim();
            // Single-quoted TOML literal string: no escapes, so the value is what is between.
            if let Some(inner) = rest.strip_prefix('\'').and_then(|r| r.rsplit_once('\'')) {
                return Ok(inner.0.to_string());
            }
            if let Some(inner) = rest.strip_prefix('"').and_then(|r| r.rsplit_once('"')) {
                return Ok(inner.0.to_string());
            }
            bail!("{MANAGER_TOML}: POOLS is not a quoted string");
        }
    }
    bail!("{MANAGER_TOML}: no POOLS assignment")
}

/// How a `runs-on:` variable is expected to resolve.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RunnerVar {
    /// It must name a label some pool in `POOLS` declares.
    Pool,
    /// It names a runner provisioned outside the Fly manager, with the reason.
    Outside(&'static str),
}

/// Every `vars.*` a `runs-on:` in this repository may use.
///
/// The VALUES live in GitHub's repository variables, which a checkout cannot read — so this is not
/// "the variable is set to the right label", which needs the API. It is the question a checkout
/// CAN answer and that nothing asked: **is this a runner anybody decided on?** A workflow routing
/// jobs at `vars.CI_HEAVY_RUNNER` is syntactically perfect, passes actionlint, and queues forever
/// against a pool nobody deployed; GitHub reports a job waiting for a runner exactly the way it
/// reports a busy pool, which is why it reads as capacity and gets waited on rather than fixed.
const RUNNER_VARS: &[(&str, RunnerVar)] = &[
    ("CI_BUILD_RUNNER", RunnerVar::Pool),
    ("CI_RUNNER", RunnerVar::Pool),
    (
        "CI_MACOS_RUNNER",
        RunnerVar::Outside("Apple hardware; no Fly pool can host it"),
    ),
    (
        "ARM64_METAL_RUNNER",
        RunnerVar::Outside("bare-metal arm64 with KVM and vsock, provisioned per-fork"),
    ),
];

/// Self-hosted labels a `runs-on:` may name as a LITERAL without a pool declaring them. Listed
/// rather than omitted, each with the reason, and shrink-only.
const OUTSIDE_LABELS: &[(&str, &str)] = &[(
    "nucleus-k3s",
    "runner-smoke.yml's default target: a k3s runner the smoke test provisions for itself",
)];

/// GitHub-hosted label families. A `runs-on:` naming one of these needs no pool.
const HOSTED_PREFIXES: &[&str] = &["ubuntu-", "macos-", "windows-", "self-hosted"];

/// One `runs-on:` site, with the job's `if:` if it has one.
struct Site {
    file: String,
    line: usize,
    expr: String,
    guard: Option<String>,
}

/// Every `runs-on:` under `.github/`, including block scalars (`runs-on: >-`), with the `if:` of
/// the job that owns it.
///
/// The `if:` matters and collecting it is the point: an expression that can evaluate to the empty
/// string is only safe when something refuses the empty case, and in this repository exactly one
/// site relies on that.
fn runs_on_sites(root: &Path) -> Result<Vec<Site>> {
    let mut out = Vec::new();
    let dir = root.join(".github/workflows");
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "yml"))
        .collect();
    paths.sort();

    for path in paths {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let text = fs::read_to_string(&path)?;
        let lines: Vec<&str> = text.lines().collect();
        // The most recent `if:` at the job's own indent, which is the one that gates the job.
        let mut pending_if: Option<(usize, String)> = None;
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim_start();
            let ind = line.len() - t.len();
            if let Some(v) = t.strip_prefix("if:") {
                pending_if = Some((ind, v.trim().to_string()));
            }
            let Some(v) = t.strip_prefix("runs-on:") else {
                continue;
            };
            let v = v.trim();
            let expr = if v == ">-" || v == "|" || v == ">" {
                // A block scalar: everything indented deeper than the key, joined.
                lines[i + 1..]
                    .iter()
                    .take_while(|l| l.trim().is_empty() || (l.len() - l.trim_start().len()) > ind)
                    .map(|l| l.trim())
                    .collect::<Vec<_>>()
                    .join(" ")
            } else {
                v.to_string()
            };
            out.push(Site {
                file: rel.clone(),
                line: i + 1,
                expr,
                // An `if:` at the same indent as `runs-on:` belongs to the same job.
                guard: pending_if
                    .as_ref()
                    .filter(|(gi, _)| *gi == ind)
                    .map(|(_, g)| g.clone()),
            });
        }
    }
    Ok(out)
}

/// The `vars.X` names an expression reads.
fn vars_in(expr: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = expr;
    while let Some(i) = rest.find("vars.") {
        let tail = &rest[i + 5..];
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(tail.len());
        if end > 0 {
            out.push(tail[..end].to_string());
        }
        rest = &tail[end..];
    }
    out.sort();
    out.dedup();
    out
}

/// The single-quoted literals an expression can **fall back to** — which is not every quoted
/// literal in it.
///
/// `aeneas-ifc-scoped.yml`'s `runs-on` is a ternary: `needs.scope.outputs.relevant == 'true' && A
/// || B`. Taking every quoted string made `'true'` a candidate runner label and red the gate on a
/// correct workflow. A literal that is the right-hand side of a comparison is an operand of the
/// CONDITION, never a value the expression can produce, so it is skipped.
fn literals_in(expr: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while let Some(i) = expr[at..].find('\'') {
        let open = at + i;
        let Some(j) = expr[open + 1..].find('\'') else {
            break;
        };
        let close = open + 1 + j;
        let before = expr[..open].trim_end();
        if !(before.ends_with("==") || before.ends_with("!=")) {
            out.push(expr[open + 1..close].to_string());
        }
        at = close + 1;
    }
    out
}

fn is_hosted(label: &str) -> bool {
    HOSTED_PREFIXES.iter().any(|p| label.starts_with(p))
}

/// Measured 2026-09-11: 148 `runs-on:` sites across `.github/workflows/`. A scan that finds far
/// fewer has stopped reading the tree, and every verdict below would then be about nothing.
const MIN_SITES: usize = 120;

/// Every job must be routable, and to a runner somebody decided on.
///
/// Two things go wrong here and neither announces itself. A `runs-on:` that evaluates to the empty
/// string, and a `runs-on:` naming a pool that does not exist, both present as a job sitting in
/// `queued` — the same way a job waits for a busy pool. nucleus shares eight build machines
/// between its pull requests and its merge queue, so "waiting for a runner" is the normal state
/// and an unroutable job hides inside it perfectly. One such job at the head of the merge queue
/// holds every entry behind it for `check_response_timeout_minutes`, which is 360.
///
/// Both questions are answered by the tree:
///
///   * an expression that can yield nothing must be guarded by an `if:` that refuses that case;
///   * every `vars.*` it reads must be a runner variable this repository has an opinion about,
///     and every literal self-hosted label must be a declared pool or a listed exception.
fn routing(root: &Path, pools: &[ci_fly_runner::PoolSpec]) -> Result<()> {
    let sites = runs_on_sites(root)?;
    if sites.len() < MIN_SITES {
        bail!(
            "only {} `runs-on:` site(s) found, floor {MIN_SITES} — the scan is wrong, so a clean \
             verdict here would mean nothing",
            sites.len()
        );
    }

    let mut failures = 0usize;
    let mut guarded = 0usize;
    for s in &sites {
        let vars = vars_in(&s.expr);
        // A `runs-on:` with no `${{` IS a label — `runs-on: ubuntu-latest`, or `runs-on:
        // nucleus-fly-build`. The quoted-literal scan below finds the fallbacks inside an
        // expression and would have skipped every bare one, which is 79 of the 148 sites here:
        // the gate would have checked only the sites that happened to be expressions, and said
        // `all routable` about a tree where a bare label pointed at a pool that does not exist.
        let lits = if s.expr.contains("${{") {
            literals_in(&s.expr)
        } else {
            vec![s.expr.trim().to_string()]
        };

        // Routable: a literal `runs-on`, an expression with a literal alternative, or a `${{ }}`
        // resolved from somewhere other than a variable (a matrix value, a workflow input).
        let reads_var = !vars.is_empty();
        let from_elsewhere = s.expr.contains("${{") && !reads_var && lits.is_empty();
        if reads_var && lits.is_empty() && !from_elsewhere {
            // The one shape that can be empty. Only an `if:` naming the same variable saves it.
            let refused = vars.iter().all(|v| {
                s.guard
                    .as_deref()
                    .is_some_and(|g| g.contains(&format!("vars.{v}")))
            });
            if !refused {
                println!(
                    "  FAIL  {}:{} — `runs-on: {}` has no literal fallback and no `if:` refusing \
                     the empty case. Unset, this routes the job to the empty string: GitHub \
                     queues it, reports it exactly as it reports a busy pool, and nothing times \
                     it out until the workflow does.",
                    s.file, s.line, s.expr
                );
                failures += 1;
                continue;
            }
            guarded += 1;
        }

        for v in &vars {
            let Some((_, kind)) = RUNNER_VARS.iter().find(|(n, _)| n == v) else {
                println!(
                    "  FAIL  {}:{} routes at `vars.{v}`, which is not a runner variable this \
                     repository has decided on. Add it to RUNNER_VARS as a pool label or as a \
                     runner provisioned elsewhere, with the reason — a variable nobody declared \
                     is a pool nobody deployed, and the job waits for it the same way it waits \
                     for a busy one.",
                    s.file, s.line
                );
                failures += 1;
                continue;
            };
            if let RunnerVar::Outside(_) = kind {
                continue;
            }
            // `Pool`: nothing here can read the variable's value, and saying so is better than
            // implying it was checked. What IS decided is that a pool exists to be named.
            if pools.is_empty() {
                println!("  FAIL  vars.{v} must name a pool, and POOLS declares none");
                failures += 1;
            }
        }

        for l in &lits {
            if is_hosted(l) || OUTSIDE_LABELS.iter().any(|(n, _)| n == l) {
                continue;
            }
            if pools.iter().any(|p| p.label == *l) {
                continue;
            }
            println!(
                "  FAIL  {}:{} can route to the literal label {l:?}, which is not a GitHub-hosted \
                 family, not a label {MANAGER_TOML} declares, and not a listed exception.",
                s.file, s.line
            );
            failures += 1;
        }
    }

    if failures > 0 {
        bail!(
            "{failures} routing problem(s): a job that cannot reach a runner waits like one that is merely early"
        );
    }
    println!(
        "ok: {} `runs-on:` site(s), all routable — {} pool variable(s), {} guarded against an unset variable, {} listed exception(s)",
        sites.len(),
        RUNNER_VARS
            .iter()
            .filter(|(_, k)| *k == RunnerVar::Pool)
            .count(),
        guarded,
        OUTSIDE_LABELS.len()
    );
    Ok(())
}

pub fn check(root: &Path) -> Result<()> {
    let text = fs::read_to_string(root.join(MANAGER_TOML))
        .with_context(|| format!("reading {MANAGER_TOML}"))?;
    let json = pools_json(&text)?;

    match ci_fly_runner::parse_pools(&json) {
        Ok(pools) => {
            for p in &pools {
                println!(
                    "ok: {} — size {} standby {} volumes {} requires_volume {}",
                    p.label,
                    p.size,
                    p.standby,
                    p.volumes.len(),
                    p.requires_volume
                );
            }
            if pools.is_empty() {
                bail!("{MANAGER_TOML}: POOLS parsed to no pools at all");
            }
            routing(root, &pools)?;
            readme_agrees(root, &pools)
        }
        Err(e) => bail!(
            "{MANAGER_TOML}'s POOLS default is a configuration the manager REFUSES:\n  {e}\n\
             This is the value a fresh deployment uses until `fly secrets set POOLS=...`\n\
             replaces it, so a default the manager rejects is a deployment that does not start."
        ),
    }
}

/// `ci/fly-runner/README.md`'s pool table must agree with the value the manager receives.
///
/// The README is how anyone learns what the pools ARE — it is the first thing a reader opens, and
/// `fly-pools` referenced it zero times, checking only that the TOML parses. So the two could drift
/// silently, and had: measured 2026-09-11, **all four numbers disagreed** — the README said the
/// build pool is size 16 standby 16 where the TOML says 8 and 8, and the gate pool size 40 standby
/// 40 where the TOML says 16 and 16.
///
/// RATCHETED rather than driven to zero, and the reason is that neither side is obviously right.
/// `manager.toml`'s POOLS is the default a fresh deployment uses until `fly secrets set POOLS=...`
/// replaces it, so the README may be describing the deployed secret truthfully while the tracked
/// default describes a bootstrap. Live runner counts settle nothing — `FINDINGS.md` F-75 measured
/// one to two build machines, which matches neither 8 nor 16. Deciding that needs the secret, which
/// is not readable from a checkout; making the disagreement visible and un-growable does not.
fn readme_agrees(root: &Path, pools: &[ci_fly_runner::PoolSpec]) -> Result<()> {
    let text =
        fs::read_to_string(root.join(README)).with_context(|| format!("reading {README}"))?;
    let pin: usize = fs::read_to_string(root.join(DRIFT))
        .with_context(|| format!("{DRIFT} is missing — nothing to ratchet the drift against"))?
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("DRIFT="))
        .and_then(|v| v.trim().parse().ok())
        .with_context(|| format!("{DRIFT} has no DRIFT= line"))?;

    let mut drift = Vec::new();
    let mut rows = 0usize;
    for p in pools {
        // The row naming this pool's label, and the `size N, standby M` it claims.
        let Some(row) = text
            .lines()
            .find(|l| l.starts_with('|') && l.contains(&format!("`{}`", p.label)))
        else {
            bail!(
                "{README} has no table row for pool {:?} — the table is the documentation of record",
                p.label
            );
        };
        rows += 1;
        // The third conjunct of this gate's specification — "size, standby AND VOLUME COUNT" —
        // which #2814 did not implement. `FINDINGS.md` F-79 records that omission and the reason it
        // is a mechanism rather than forgetfulness: a spec with three conjuncts yields a gate that
        // is green when two hold, and the green output cannot say which.
        //
        // The README states volumes as prose, two ways: "no volume", or "one volume each
        // (8 × 40 GB + 8 × 20 GB)" — a sum of counts, not a single number. Both are read here; a
        // row saying neither is an error rather than a zero, because a pool whose volume prose
        // stopped parsing is a pool this gate has silently stopped checking.
        let claimed_volumes = if row.contains("no volume") {
            Some(0usize)
        } else if let Some(inner) = row
            .split("volume each (")
            .nth(1)
            .and_then(|r| r.split(')').next())
        {
            // "8 × 40 GB + 8 × 20 GB" — the count is the first number of each `N × …` term.
            let n: usize = inner
                .split('+')
                .filter_map(|term| {
                    term.trim()
                        .split(|c: char| !c.is_ascii_digit())
                        .find(|t| !t.is_empty())
                        .and_then(|t| t.parse::<usize>().ok())
                })
                .sum();
            Some(n)
        } else {
            None
        };
        match claimed_volumes {
            None => bail!(
                "{README}'s row for {:?} states its volumes in neither form this reads \
                 (\"no volume\", or \"volume each (N × … + M × …)\") — a row that stopped parsing is a \
                 pool this gate stopped checking",
                p.label
            ),
            Some(c) if c != p.volumes.len() => {
                drift.push(format!(
                    "{} volumes: README {c}, {MANAGER_TOML} {}",
                    p.label,
                    p.volumes.len()
                ));
            }
            Some(_) => {}
        }

        for (field, declared) in [("size", p.size), ("standby", p.standby)] {
            let claimed = row
                .split(&format!("{field} "))
                .nth(1)
                .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
                .and_then(|n| n.parse::<usize>().ok());
            match claimed {
                None => bail!("{README}'s row for {:?} states no {field}", p.label),
                Some(c) if c != declared => {
                    drift.push(format!(
                        "{} {field}: README {c}, {MANAGER_TOML} {declared}",
                        p.label
                    ));
                }
                Some(_) => {}
            }
        }
    }
    if rows == 0 {
        bail!("{README} matched no pool rows — the comparison examined nothing");
    }
    for d in &drift {
        println!("  drift  {d}");
    }
    if drift.len() > pin {
        bail!(
            "{} README/TOML disagreement(s), pin {pin} — the file a reader opens to learn the pool \
             sizes does not agree with the value the manager receives. Fix one side, or raise the \
             pin with the reason they differ",
            drift.len()
        );
    }
    if drift.len() < pin {
        bail!(
            "{} disagreement(s), pin {pin} — lower the pin in the same change that fixed one",
            drift.len()
        );
    }
    println!(
        "OK: {rows} pool(s) compared against {README}; {} still disagree (pin {pin})",
        drift.len()
    );
    readme_queue_constants(root, &text)
}

/// The same README also restates merge-queue constants, and nothing compared those either.
///
/// `ci/fly-runner/README.md` explains the queue's throughput by quoting `max_entries_to_build = 1`
/// from `ci/merge-queue.toml`. `ci-spec live-parity` compares that TOML against the LIVE ruleset; no
/// gate reads this README at all. So raising the constant — which was tried and reverted earlier,
/// per merge-queue.toml's own note — would leave the prose saying 1 with nothing to notice.
///
/// **This half is preventive, and that is worth saying plainly.** The pool comparison above found
/// four live disagreements; these two values agree today. A gate half that has never been red on a
/// real defect is a weaker thing than one that has, and the honest place to record which is which is
/// here rather than in a commit message nobody re-reads.
///
/// The value is quoted across a LINE WRAP — `max_entries_to_build` ending one line and `= 1`
/// starting the next — which is why a naive grep misses it and why this class of drift survives.
/// The scan normalises whitespace before matching, deliberately.
fn readme_queue_constants(root: &Path, readme: &str) -> Result<()> {
    let toml = fs::read_to_string(root.join(QUEUE_TOML))
        .with_context(|| format!("reading {QUEUE_TOML}"))?;
    let joined: String = readme.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut checked = 0usize;
    for key in QUEUE_KEYS {
        let Some(declared) = toml
            .lines()
            .map(str::trim)
            .find_map(|l| l.strip_prefix(*key))
            .and_then(|r| r.trim_start().strip_prefix('='))
            .and_then(|r| r.trim().parse::<usize>().ok())
        else {
            bail!("{QUEUE_TOML} states no {key} — the constant this README quotes is gone");
        };
        let Some(after) = joined.split(*key).nth(1) else {
            bail!("{README} no longer quotes {key}; drop this check or restore the sentence");
        };
        let claimed = after
            .trim_start()
            .strip_prefix('=')
            .map(str::trim_start)
            .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|n| n.parse::<usize>().ok());
        match claimed {
            None => bail!("{README} quotes {key} without a value"),
            Some(c) if c != declared => bail!(
                "{README} says {key} = {c}, {QUEUE_TOML} says {declared} — the prose explaining the \
                 queue's throughput disagrees with the queue's configuration"
            ),
            Some(_) => checked += 1,
        }
    }
    if checked == 0 {
        bail!("no merge-queue constant was compared — the check examined nothing");
    }
    println!("OK: {checked} merge-queue constant(s) in {README} agree with {QUEUE_TOML}");
    readme_site_counts(root, &joined)
}

/// The README also counts how many `runs-on:` sites each pool serves, and those are facts about
/// the tree rather than opinions about a deployment.
///
/// Unlike the pool sizes — where `manager.toml` is a default the deployed secret may override, so
/// neither side is authoritative and the drift is ratcheted — a site count is decidable here and
/// now by counting lines. There is a right answer, so this comparison HARD-FAILS rather than
/// ratchets, and the README was corrected in the change that added it.
///
/// Measured 2026-09-11, before the correction: the README claimed 52 gate sites and 27 build sites;
/// the tree had **54 and 24**. Both wrong, in opposite directions.
fn readme_site_counts(root: &Path, joined: &str) -> Result<()> {
    let dir = root.join(".github/workflows");
    let mut runs_on: Vec<String> = Vec::new();
    for e in fs::read_dir(&dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = e?.path();
        if path.extension().is_none_or(|x| x != "yml") {
            continue;
        }
        for line in fs::read_to_string(&path)?.lines() {
            if line.trim_start().starts_with("runs-on:") {
                runs_on.push(line.to_string());
            }
        }
    }
    if runs_on.len() < 50 {
        bail!(
            "only {} `runs-on:` lines found — the scan is wrong, so every count below is noise",
            runs_on.len()
        );
    }

    // Routing: a line naming CI_BUILD_RUNNER goes to the build pool even though it also names
    // CI_RUNNER as its fallback, so the gate count is the difference and not the raw match.
    let build = runs_on
        .iter()
        .filter(|l| l.contains("vars.CI_BUILD_RUNNER"))
        .count();
    let gate = runs_on
        .iter()
        .filter(|l| l.contains("vars.CI_RUNNER") && !l.contains("vars.CI_BUILD_RUNNER"))
        .count();

    let mut wrong = Vec::new();
    for (claim, actual, what) in [
        ("`runs-on` sites)", build, "build"),
        (" sites), opt-in", gate, "gate"),
    ] {
        // The number immediately before the claim phrase, e.g. "(27 `runs-on` sites)".
        let Some(before) = joined
            .split(claim)
            .next()
            .filter(|_| joined.contains(claim))
        else {
            bail!("{README} no longer states the {what} site count in the expected form");
        };
        let claimed: usize = before
            .rsplit(|c: char| !c.is_ascii_digit())
            .find(|t| !t.is_empty())
            .and_then(|n| n.parse().ok())
            .with_context(|| format!("{README}: no number before the {what} site count"))?;
        if claimed != actual {
            wrong.push(format!("{what}: README {claimed}, tree {actual}"));
        }
    }
    if !wrong.is_empty() {
        bail!(
            "{README} miscounts `runs-on` sites — {}. The tree is the authority here: count the \
             lines and correct the prose",
            wrong.join("; ")
        );
    }
    println!("OK: {README}'s site counts match the tree (gate {gate}, build {build})");
    Ok(())
}

#[cfg(test)]
mod tests {

    /// A literal on the right of `==` is an operand of the CONDITION, not a value the expression
    /// can produce. Taking every quoted string made `'true'` a candidate runner label and red the
    /// gate on a correct workflow.
    #[test]
    fn a_comparison_operand_is_not_a_fallback_label() {
        let expr = "${{ needs.scope.outputs.relevant == 'true' \
                    && (vars.CI_BUILD_RUNNER || vars.CI_RUNNER || 'ubuntu-latest') \
                    || (vars.CI_RUNNER || 'ubuntu-latest') }}";
        let lits = super::literals_in(expr);
        assert!(
            !lits.iter().any(|l| l == "true"),
            "the condition's operand leaked in as a label: {lits:?}"
        );
        assert!(lits.iter().any(|l| l == "ubuntu-latest"), "{lits:?}");
    }

    #[test]
    fn a_not_equal_operand_is_skipped_too() {
        assert!(
            super::literals_in("${{ vars.X != 'off' && 'ubuntu-latest' }}")
                .iter()
                .all(|l| l != "off")
        );
    }

    #[test]
    fn every_variable_an_expression_reads_is_found() {
        let v = super::vars_in("${{ vars.CI_BUILD_RUNNER || vars.CI_RUNNER || 'ubuntu-latest' }}");
        assert_eq!(v, vec!["CI_BUILD_RUNNER", "CI_RUNNER"]);
        assert!(super::vars_in("ubuntu-latest").is_empty());
    }

    /// The shipped tree, read the way the gate reads it. 148 measured 2026-09-11; the assertion is
    /// a floor, because the number moves whenever a job is added and a brittle equality here would
    /// be a gate that fails on unrelated work.
    #[test]
    fn the_scan_reaches_the_whole_workflow_tree() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let sites = super::runs_on_sites(&root).expect("the workflows parse");
        assert!(
            sites.len() >= super::MIN_SITES,
            "found {} `runs-on:` sites, floor {}",
            sites.len(),
            super::MIN_SITES
        );
        // The block-scalar site must come through as one expression, not as the bare `>-`.
        assert!(
            sites
                .iter()
                .any(|s| s.expr.contains("needs.scope.outputs.relevant")),
            "the `runs-on: >-` block scalar was not joined"
        );
        // And a bare literal must survive as itself, or the 79 bare sites go unchecked.
        assert!(
            sites.iter().any(|s| s.expr == "ubuntu-latest"),
            "bare literal sites were dropped"
        );
    }

    /// Exactly one site in this repository routes at a variable with no literal fallback, and it
    /// is safe only because an `if:` refuses the unset case. If that pairing is ever broken the
    /// gate must be the thing that notices, so this pins that the guard is FOUND, not just that
    /// the gate passes.
    #[test]
    fn the_unfallbacked_site_is_guarded_by_its_own_variable() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let sites = super::runs_on_sites(&root).expect("the workflows parse");
        let bare: Vec<&super::Site> = sites
            .iter()
            .filter(|s| {
                !super::vars_in(&s.expr).is_empty() && super::literals_in(&s.expr).is_empty()
            })
            .collect();
        for s in &bare {
            for v in super::vars_in(&s.expr) {
                assert!(
                    s.guard
                        .as_deref()
                        .is_some_and(|g| g.contains(&format!("vars.{v}"))),
                    "{}:{} routes at vars.{v} with no fallback and no `if:` naming it",
                    s.file,
                    s.line
                );
            }
        }
    }

    /// Every variable declared here must actually be used by a `runs-on:`. A stale entry is an
    /// exemption for a routing decision nobody makes any more, and it reads as one that is live.
    #[test]
    fn no_declared_runner_variable_is_unused() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let sites = super::runs_on_sites(&root).expect("the workflows parse");
        for (name, _) in super::RUNNER_VARS {
            assert!(
                sites
                    .iter()
                    .any(|s| super::vars_in(&s.expr).iter().any(|v| v == name)),
                "RUNNER_VARS declares {name}, which no `runs-on:` reads"
            );
        }
    }
    use super::*;
    use std::path::PathBuf;

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn the_committed_default_is_one_the_manager_accepts() {
        check(&root()).expect("the tracked POOLS default must validate");
    }

    #[test]
    fn extracts_the_single_quoted_value() {
        let t = "FLY_REGION = \"iad\"\nPOOLS = '[{\"label\":\"a\"}]'\n";
        assert_eq!(pools_json(t).unwrap(), "[{\"label\":\"a\"}]");
    }

    #[test]
    fn a_missing_pools_assignment_is_an_error() {
        assert!(pools_json("FLY_REGION = \"iad\"\n").is_err());
    }

    #[test]
    fn the_defect_this_gate_was_written_for_is_refused() {
        // requires_volume with no volumes: what the tracked default actually held.
        let bad = r#"[{"label":"b","guest":{"cpu_kind":"performance","cpus":8,"memory_mb":32768},"size":8,"standby":8,"requires_volume":true}]"#;
        let e = ci_fly_runner::parse_pools(bad).expect_err("must be refused");
        assert!(e.contains("requires_volume"), "message names the rule: {e}");
    }
}

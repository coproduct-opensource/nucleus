//! Building [`Inputs`] for a context out of a repository.
//!
//! The host does this, never the pod. Everything here reads the tree directly:
//! the workflow's declared filter, the files that match it, the gate's own
//! code, and the toolchain pins. Nothing is taken on a running job's word,
//! which is the property that makes a cross-tree hit admissible at all.

use crate::{ActionKey, Inputs, ReadEntry, Refusal};
use anyhow::{Context, Result};
use ci_spec::model::{Model, PathFilter, Workflow};
use sha2::{Digest, Sha256};
use std::path::Path;

/// The pinned toolchain files. A gate is a function of what runs it: the same
/// `cargo clippy` under two nightlies is two gates, and a receipt that does not
/// say which one it was is a receipt about nothing in particular.
const TOOLCHAIN_FILES: &[&str] = &["rust-toolchain.toml", "Cargo.lock"];

/// The declared read-set for a workflow, or why it has none.
///
/// `merge_group` takes no `paths:` filter — GitHub only accepts
/// `types: [checks_requested]` there — so the declaration lives on
/// `pull_request`, which is also the one GitHub itself acts on when it decides
/// whether to run the job. Using the same filter is what keeps this from being
/// a new trust assumption.
fn filter_of(w: &Workflow) -> Option<&PathFilter> {
    w.triggers
        .pull_request
        .as_ref()
        .or(w.triggers.push.as_ref())
}

/// Does `path` match a GitHub workflow path pattern?
///
/// Segment-wise: `**` matches any run of segments, `*` matches within one
/// segment, everything else is literal. That is the subset this repository
/// uses — `crates/**`, `crates/ck-*/src/**`, `scripts/check-*.sh`, and plain
/// paths.
///
/// Returns `None` for anything outside it (`?`, `!`, `+`, character classes).
/// **An unrecognised pattern must never read as "matches nothing"**: a
/// read-set that quietly shrinks is a receipt reused when it should not have
/// been. "I could not look" is never "I looked and it was fine" (ADR 0007
/// A-2).
fn matches(pattern: &str, path: &str) -> Option<bool> {
    if pattern.contains(['?', '!', '+', '[']) {
        return None;
    }
    let pat: Vec<&str> = pattern.split('/').collect();
    let seg: Vec<&str> = path.split('/').collect();
    Some(match_segments(&pat, &seg))
}

/// Segment matcher. `**` consumes zero or more segments, which is why this is
/// recursive rather than a zip.
fn match_segments(pat: &[&str], seg: &[&str]) -> bool {
    // `split_first` rather than `first()` + `[1..]`: the tail comes back with
    // the head, so there is no second, unchecked way to get it wrong. A panic
    // here would be a key derivation that could not finish, which this crate
    // must never confuse with a key that says "no match".
    let Some((head, pat_rest)) = pat.split_first() else {
        return seg.is_empty();
    };
    if *head == "**" {
        // Zero or more segments. GitHub treats a trailing `**` as "this
        // directory and everything under it".
        return (0..=seg.len()).any(|i| match seg.get(i..) {
            Some(tail) => match_segments(pat_rest, tail),
            None => false,
        });
    }
    match seg.split_first() {
        None => false,
        Some((s, seg_rest)) => match_one(head, s) && match_segments(pat_rest, seg_rest),
    }
}

/// One segment against one pattern segment, with `*` matching any run of
/// non-`/` characters.
fn match_one(pat: &str, seg: &str) -> bool {
    let parts: Vec<&str> = pat.split('*').collect();
    // `split_first`/`split_last` again: the interior is what is left over,
    // which is the same fact as "not the first and not the last" without a
    // second expression of it that can disagree. The old
    // `&parts[1..parts.len().saturating_sub(1)]` was that second expression.
    let Some((first, after_first)) = parts.split_first() else {
        return pat == seg;
    };
    let Some((last, interior)) = after_first.split_last() else {
        // No `*` at all: one part, so the pattern is literal.
        return pat == seg;
    };

    let mut rest = seg;
    // The first part must be a prefix (unless the pattern starts with `*`).
    if !first.is_empty() {
        match rest.strip_prefix(*first) {
            Some(r) => rest = r,
            None => return false,
        }
    }
    // The last must be a suffix (unless the pattern ends with `*`).
    if !last.is_empty() {
        match rest.strip_suffix(*last) {
            Some(r) => rest = r,
            None => return false,
        }
    }
    // Interior parts must appear in order.
    for mid in interior {
        if mid.is_empty() {
            continue;
        }
        // `find` returns a byte offset at a char boundary and `mid` is a
        // substring from there, so the sum is a boundary too — but slicing on
        // an arithmetic result is exactly the shape that panics when the
        // reasoning is wrong, so take the remainder by length instead.
        match rest.find(mid).and_then(|i| {
            rest.get(i..)
                .and_then(|from_match| from_match.get(mid.len()..))
        }) {
            Some(after) => rest = after,
            None => return false,
        }
    }
    true
}

/// Every tracked file under `root`, repo-relative, from git rather than a
/// directory walk.
///
/// `git ls-files` is the enumeration, not `walkdir`: an untracked build
/// artefact that happened to match a pattern would otherwise enter the key and
/// make it depend on the machine.
fn tracked_files(root: &Path) -> Result<Vec<String>> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z"])
        .output()
        .context("running `git ls-files`")?;
    anyhow::ensure!(out.status.success(), "`git ls-files` failed in {root:?}");
    Ok(String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect())
}

fn digest_of(root: &Path, rel: &str) -> Result<[u8; 32]> {
    let bytes = std::fs::read(root.join(rel)).with_context(|| format!("reading {rel}"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(&bytes));
    Ok(out)
}

/// The read-set: tracked files matching `paths:` and not `paths-ignore:`.
///
/// Returns `Err` when a pattern is outside the recognised subset. That is
/// deliberately not a silent empty match: "I could not read this filter" and
/// "this filter selects nothing" must never be the same answer (ADR 0007 A-2).
fn read_set(root: &Path, filter: &PathFilter) -> Result<Vec<ReadEntry>> {
    let files = tracked_files(root)?;
    let mut out = Vec::new();
    for f in files {
        let mut included = false;
        for p in &filter.paths {
            match matches(p, &f) {
                Some(true) => included = true,
                Some(false) => {}
                None => anyhow::bail!(
                    "unrecognised path pattern {p:?}: refusing to guess at a read-set"
                ),
            }
        }
        if !included {
            continue;
        }
        for p in &filter.paths_ignore {
            match matches(p, &f) {
                Some(true) => {
                    included = false;
                    break;
                }
                Some(false) => {}
                None => anyhow::bail!(
                    "unrecognised path-ignore pattern {p:?}: refusing to guess at a read-set"
                ),
            }
        }
        if included {
            out.push(ReadEntry {
                path: f.clone(),
                digest: digest_of(root, &f)?,
            });
        }
    }
    out.sort();
    Ok(out)
}

/// The gate's own code: the workflow file, plus every `scripts/*.sh` its text
/// mentions.
///
/// Without this a gate that was *weakened* keeps answering green out of its
/// stronger self's history — the one failure mode that makes a receipt store
/// worse than no cache at all. The workflow is included whether or not it
/// appears in its own `paths:` filter, because "the gate changed" is not the
/// same question as "an input changed" and a filter that omits itself is
/// common.
fn gate_set(root: &Path, w: &Workflow) -> Result<Vec<ReadEntry>> {
    let mut out = vec![ReadEntry {
        path: w.path.clone(),
        digest: digest_of(root, &w.path)?,
    }];
    for candidate in tracked_files(root)? {
        if (candidate.starts_with("scripts/") || candidate.starts_with("ci/"))
            && candidate.ends_with(".sh")
            && w.raw.contains(&candidate)
        {
            out.push(ReadEntry {
                path: candidate.clone(),
                digest: digest_of(root, &candidate)?,
            });
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn toolchain(root: &Path) -> Result<Vec<(String, String)>> {
    let mut pins = Vec::new();
    for f in TOOLCHAIN_FILES {
        let path = root.join(f);
        if path.exists() {
            pins.push(((*f).to_string(), hex::encode(digest_of(root, f)?)));
        }
    }
    anyhow::ensure!(
        !pins.is_empty(),
        "no toolchain pin found in {root:?}: a key that does not say what compiled the gate is a \
         key about nothing in particular"
    );
    Ok(pins)
}

/// The inputs for one required context, or a refusal naming what a person has
/// to decide.
///
/// The outer `Result` is "could not look"; the inner `Refusal` is "looked, and
/// there is no key". Collapsing the two would make an unreadable workflow
/// indistinguishable from a job that legitimately has no filter.
pub fn inputs_for(root: &Path, model: &Model, context: &str) -> Result<Result<Inputs, Refusal>> {
    let all = model.producers(context);

    // The twin pattern is not ambiguity. `foo.yml` carries the real `paths:`
    // and `foo-noop.yml` carries its complement as `paths-ignore:`; exactly one
    // fires, and the noop reports the same context green in seconds. So the
    // real twin is the gate, and its filter is the declared read-set. Dropping
    // the noop half here is the difference between 11 refusals and 11 keys.
    // `get` rather than `[]` throughout: `producers` hands back indices into
    // `model.workflows`, and this crate must never turn a stale index into a
    // panic. A panic here is a key derivation that could not finish, and the
    // whole design turns on never confusing that with a derivation that
    // finished and said "no key".
    let real: Vec<_> = all
        .iter()
        .copied()
        .filter(|(wi, _)| model.workflows.get(*wi).is_some_and(|w| !w.is_noop()))
        .collect();
    let producers = if real.is_empty() { all.clone() } else { real };

    match producers.len() {
        0 => {
            return Ok(Err(Refusal::NoProducer {
                context: context.to_string(),
            }));
        }
        1 => {}
        _ => {
            return Ok(Err(Refusal::ManyProducers {
                context: context.to_string(),
                producers: producers
                    .iter()
                    .map(|(wi, ji)| match model.workflows.get(*wi) {
                        Some(w) => match w.jobs.get(*ji) {
                            Some(j) => format!("{}::{}", w.path, j.id),
                            None => format!("{}::<job {ji} is gone>", w.path),
                        },
                        None => format!("<workflow {wi} is gone>::<job {ji}>"),
                    })
                    .collect(),
            }));
        }
    }
    // The `match` above established exactly one producer, but "established by
    // an earlier branch" is the reasoning that `[0]` panics on when someone
    // edits the branch. Ask for it.
    let Some(&(wi, _)) = producers.first() else {
        return Ok(Err(Refusal::NoProducer {
            context: context.to_string(),
        }));
    };
    let Some(w) = model.workflows.get(wi) else {
        anyhow::bail!(
            "context {context:?} names workflow index {wi}, which the model does not have: the \
             model changed under the index and a key derived from it would be about nothing"
        );
    };

    let Some(filter) = filter_of(w) else {
        return Ok(Err(Refusal::Unfiltered {
            context: context.to_string(),
            workflow: w.path.clone(),
        }));
    };
    if filter.paths.is_empty() {
        return Ok(Err(if filter.paths_ignore.is_empty() {
            Refusal::Unfiltered {
                context: context.to_string(),
                workflow: w.path.clone(),
            }
        } else {
            Refusal::IgnoreOnly {
                context: context.to_string(),
                workflow: w.path.clone(),
            }
        }));
    }

    Ok(Ok(Inputs {
        context: context.to_string(),
        read_set: read_set(root, filter)?,
        gate: gate_set(root, w)?,
        toolchain: toolchain(root)?,
    }))
}

/// The key for one required context, or the refusal.
pub fn key_for(root: &Path, model: &Model, context: &str) -> Result<Result<ActionKey, Refusal>> {
    Ok(inputs_for(root, model, context)?.map(|i| ActionKey::derive(&i)))
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn a_star_spans_a_segment_but_never_crosses_one() {
        // The live shape from kani-nightly.yml, which the first version of this
        // matcher could not read.
        assert_eq!(
            matches("crates/ck-*/src/**", "crates/ck-policy/src/lib.rs"),
            Some(true)
        );
        assert_eq!(
            matches("crates/ck-*/src/**", "crates/ck-types/src/a/b.rs"),
            Some(true)
        );
        assert_eq!(
            matches("crates/ck-*/src/**", "crates/portcullis/src/lib.rs"),
            Some(false)
        );
        assert_eq!(
            matches("crates/ck-*/src/**", "crates/ck-policy/tests/x.rs"),
            Some(false)
        );
        // `*` must not swallow a `/`.
        assert_eq!(matches("crates/*/lib.rs", "crates/a/b/lib.rs"), Some(false));
    }

    /// A trailing `**` covers the directory itself and everything under it.
    #[test]
    fn a_trailing_double_star_covers_the_directory_and_its_subtree() {
        assert_eq!(matches("crates/**", "crates/a.rs"), Some(true));
        assert_eq!(matches("crates/**", "crates/a/b/c.rs"), Some(true));
        assert_eq!(matches("crates/**", "tools/a.rs"), Some(false));
    }

    #[test]
    fn the_patterns_this_repository_actually_uses_are_recognised() {
        assert_eq!(
            matches("crates/**", "crates/portcullis/src/lib.rs"),
            Some(true)
        );
        assert_eq!(matches("crates/**", "scripts/x.sh"), Some(false));
        assert_eq!(
            matches(
                "tools/nucleus-egress-lint/**",
                "tools/nucleus-egress-lint/src/lib.rs"
            ),
            Some(true)
        );
        assert_eq!(
            matches(
                ".github/workflows/dylint-separation.yml",
                ".github/workflows/dylint-separation.yml"
            ),
            Some(true)
        );
        assert_eq!(
            matches(".observed-ratchet.toml", ".observed-ratchet.toml"),
            Some(true)
        );
        assert_eq!(
            matches("scripts/check-*.sh", "scripts/check-observed-dylint.sh"),
            Some(true)
        );
        assert_eq!(
            matches("scripts/check-*.sh", "scripts/other.sh"),
            Some(false)
        );
        // A `*` must not cross a segment boundary.
        assert_eq!(matches("scripts/*.sh", "scripts/sub/x.sh"), Some(false));
    }

    /// **An unrecognised pattern must not read as "matches nothing".** A
    /// read-set that quietly shrinks is a receipt reused when it should not
    /// have been; "I could not look" is never "I looked and it was fine"
    /// (ADR 0007 A-2).
    #[test]
    fn an_unrecognised_pattern_is_refused_rather_than_treated_as_empty() {
        assert_eq!(
            matches("crates/?ortcullis/**", "crates/portcullis/src/lib.rs"),
            None
        );
        assert_eq!(matches("!crates/**", "crates/a.rs"), None);
        assert_eq!(matches("crates/[ab]/**", "crates/a/x.rs"), None);
    }
}

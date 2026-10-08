//! `ci-scope` — does this CI event change anything a path-scoped job reads?
//!
//! # Why this exists
//!
//! A required status check must be reported exactly once per event and must not be skippable
//! into a pass. GitHub's `paths:` filter gives neither on its own: a pull request outside the
//! paths never reports the context and blocks forever. The repository's answer was a `-noop`
//! twin with `paths-ignore:` set to the same list, but GitHub fires `paths:` when SOME changed
//! file matches and `paths-ignore:` when SOME changed file does not, so a pull request touching
//! one file of each kind fires both twins under one name. A two-second no-op success then
//! stands beside the real result (`twin_both_iff` in `ci/lean/CiSpec/Pipeline.lean` states the
//! case; #3329 shows it on a real pull request).
//!
//! The fix is one producer: the real workflow runs on every event, and the first step of each
//! job asks this crate whether the event changed anything the job reads. One list, one
//! decider, every event.
//!
//! # The rule
//!
//! A job is skipped only when the change was OBSERVED to be non-empty and no file in it is
//! covered by the scope list. Everything else runs the job:
//!
//! * events that are not diff-scoped (`push`, `schedule`, `workflow_dispatch`, and any event
//!   this crate does not know) always run;
//! * a diff-scoped event with no range, a diff that fails, or a diff that lists nothing runs —
//!   "could not look" is never "looked and found nothing" (ADR 0007 A).
//!
//! Running is the safe direction: the job then decides on its own evidence.

use std::fmt;

/// One entry of a scope list, in the subset of GitHub path-filter syntax this repository uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    /// `dir/**`: every path under `dir/`. Stored with the trailing `/`.
    Under(String),
    /// One file, named exactly.
    Exact(String),
}

impl Pattern {
    /// Does this pattern cover `path` (repo-relative, `/`-separated)?
    #[must_use]
    pub fn covers(&self, path: &str) -> bool {
        match self {
            Self::Under(prefix) => path.starts_with(prefix.as_str()),
            Self::Exact(file) => path == file,
        }
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Under(prefix) => write!(f, "{prefix}**"),
            Self::Exact(file) => f.write_str(file),
        }
    }
}

/// Why a scope list was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// No pattern at all. A scope that covers nothing would skip every event.
    Empty,
    /// A line outside the supported syntax (`dir/**` or an exact path).
    Unsupported { line: usize, text: String },
    /// The same pattern twice: one of them is a stale copy of the other.
    Duplicate { line: usize, text: String },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the scope list declares no pattern"),
            Self::Unsupported { line, text } => write!(
                f,
                "line {line}: `{text}` is neither `dir/**` nor an exact repo-relative path"
            ),
            Self::Duplicate { line, text } => write!(f, "line {line}: `{text}` is declared twice"),
        }
    }
}

impl std::error::Error for ParseError {}

/// A parsed, non-empty scope list. The only constructor is [`ScopeList::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeList {
    patterns: Vec<Pattern>,
}

const GLOB_CHARS: [char; 7] = ['*', '?', '[', ']', '{', '}', '!'];

fn plain_path(text: &str) -> bool {
    !text.is_empty()
        && !text.starts_with('/')
        && !text.starts_with("./")
        && !text.contains(GLOB_CHARS)
        && !text.contains("//")
        && !text.split('/').any(|seg| seg == ".." || seg == ".")
        && !text.chars().any(char::is_whitespace)
}

impl ScopeList {
    /// One pattern per line; blank lines and `#` comments are ignored.
    ///
    /// # Errors
    ///
    /// [`ParseError`] when the list is empty, a line is outside the supported syntax, or a
    /// pattern repeats.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        let mut patterns: Vec<Pattern> = Vec::new();
        for (i, raw) in text.lines().enumerate() {
            let line = i.saturating_add(1);
            let entry = raw.trim();
            if entry.is_empty() || entry.starts_with('#') {
                continue;
            }
            let pattern = match entry.strip_suffix("**") {
                Some(dir) if dir.ends_with('/') && plain_path(dir) => Pattern::Under(dir.into()),
                Some(_) => return Err(unsupported(line, entry)),
                None if plain_path(entry) && !entry.ends_with('/') => Pattern::Exact(entry.into()),
                None => return Err(unsupported(line, entry)),
            };
            if patterns.contains(&pattern) {
                return Err(ParseError::Duplicate {
                    line,
                    text: entry.into(),
                });
            }
            patterns.push(pattern);
        }
        if patterns.is_empty() {
            return Err(ParseError::Empty);
        }
        Ok(Self { patterns })
    }

    /// The patterns, in declaration order. Never empty.
    #[must_use]
    pub fn patterns(&self) -> &[Pattern] {
        &self.patterns
    }

    /// Is `path` covered by some pattern?
    #[must_use]
    pub fn covers(&self, path: &str) -> bool {
        self.patterns.iter().any(|p| p.covers(path))
    }
}

fn unsupported(line: usize, text: &str) -> ParseError {
    ParseError::Unsupported {
        line,
        text: text.into(),
    }
}

/// The GitHub event that started the run, as `github.event_name` spells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    PullRequest,
    MergeGroup,
    /// Every other event. These are not diff-scoped: the job always runs.
    Unscoped(String),
}

impl Event {
    #[must_use]
    pub fn from_name(name: &str) -> Self {
        match name {
            "pull_request" => Self::PullRequest,
            "merge_group" => Self::MergeGroup,
            other => Self::Unscoped(other.into()),
        }
    }
}

/// The commits a diff-scoped event compares. Both ends are non-empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Range {
    base: String,
    head: String,
}

impl Range {
    /// `None` when either end is missing or blank.
    #[must_use]
    pub fn new(base: Option<&str>, head: Option<&str>) -> Option<Self> {
        let base = base.map(str::trim).filter(|s| !s.is_empty())?;
        let head = head.map(str::trim).filter(|s| !s.is_empty())?;
        Some(Self {
            base: base.into(),
            head: head.into(),
        })
    }

    #[must_use]
    pub fn base(&self) -> &str {
        &self.base
    }

    #[must_use]
    pub fn head(&self) -> &str {
        &self.head
    }
}

/// Why the job runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunBecause {
    /// The event is not diff-scoped (push to main, schedule, dispatch, …).
    UnscopedEvent(String),
    /// A diff-scoped event arrived without both ends of its range.
    NoRange,
    /// The diff could not be taken.
    DiffFailed(String),
    /// The diff listed no file. An empty change cannot be told from a broken range.
    EmptyDiff,
    /// This changed file is covered by the scope list.
    Touched(String),
}

/// The decision. `Skip` carries how many changed files were examined, and is only built when
/// that number is at least one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Run(RunBecause),
    Skip { examined: usize },
}

impl Decision {
    /// The value of the step's `relevant` output.
    #[must_use]
    pub fn relevant(&self) -> bool {
        match self {
            Self::Run(_) => true,
            Self::Skip { .. } => false,
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Run(RunBecause::UnscopedEvent(e)) => {
                write!(f, "run: `{e}` is not diff-scoped, so the job always runs")
            }
            Self::Run(RunBecause::NoRange) => {
                f.write_str("run: the event carried no base/head range; could not look, so running")
            }
            Self::Run(RunBecause::DiffFailed(why)) => {
                write!(f, "run: the diff failed ({why}); could not look, so running")
            }
            Self::Run(RunBecause::EmptyDiff) => {
                f.write_str("run: the diff listed no file; an empty change is not evidence of scope")
            }
            Self::Run(RunBecause::Touched(file)) => write!(f, "run: in scope -- `{file}` changed"),
            Self::Skip { examined } => write!(
                f,
                "skip: none of the {examined} changed file(s) is in this job's scope"
            ),
        }
    }
}

/// Decide. `diff` is asked for the changed files only for a diff-scoped event with a range.
pub fn decide(
    event: &Event,
    range: Option<&Range>,
    diff: impl FnOnce(&Range) -> Result<Vec<String>, String>,
    scope: &ScopeList,
) -> Decision {
    match event {
        Event::Unscoped(name) => Decision::Run(RunBecause::UnscopedEvent(name.clone())),
        Event::PullRequest | Event::MergeGroup => {
            let Some(range) = range else {
                return Decision::Run(RunBecause::NoRange);
            };
            let files = match diff(range) {
                Ok(files) => files,
                Err(why) => return Decision::Run(RunBecause::DiffFailed(why)),
            };
            if files.is_empty() {
                return Decision::Run(RunBecause::EmptyDiff);
            }
            match files.iter().find(|f| scope.covers(f)) {
                Some(file) => Decision::Run(RunBecause::Touched(file.clone())),
                None => Decision::Skip {
                    examined: files.len(),
                },
            }
        }
    }
}

/// Split `git diff --name-only -z` output into paths.
#[must_use]
pub fn split_nul(out: &[u8]) -> Vec<String> {
    out.split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = "\
# a comment
crates/nucleus-node/**

scripts/check-egress-probe.sh
.github/workflows/quickstart-boot.yml
";

    fn list() -> ScopeList {
        ScopeList::parse(LIST).expect("the fixture parses")
    }

    fn range() -> Range {
        Range::new(Some("aaa"), Some("bbb")).expect("both ends")
    }

    fn files(v: &[&str]) -> Result<Vec<String>, String> {
        Ok(v.iter().map(|s| (*s).to_string()).collect())
    }

    #[test]
    fn parses_directories_and_exact_files_in_order() {
        assert_eq!(
            list().patterns(),
            &[
                Pattern::Under("crates/nucleus-node/".into()),
                Pattern::Exact("scripts/check-egress-probe.sh".into()),
                Pattern::Exact(".github/workflows/quickstart-boot.yml".into()),
            ]
        );
    }

    #[test]
    fn an_empty_list_is_refused_not_read_as_cover_nothing() {
        assert_eq!(ScopeList::parse(""), Err(ParseError::Empty));
        assert_eq!(ScopeList::parse("# only\n\n"), Err(ParseError::Empty));
    }

    #[test]
    fn globs_outside_the_supported_subset_are_refused() {
        for bad in [
            "*.rs",
            "crates/*/src/**",
            "!crates/x/**",
            "/abs/path",
            "./rel",
            "crates/x/",
            "crates/../x/**",
            "crates/x/*",
            "crates/x**",
            "a b",
        ] {
            assert!(
                matches!(
                    ScopeList::parse(bad),
                    Err(ParseError::Unsupported { line: 1, .. })
                ),
                "`{bad}` must be refused"
            );
        }
    }

    #[test]
    fn a_duplicate_is_refused() {
        assert_eq!(
            ScopeList::parse("a/**\nb\na/**\n"),
            Err(ParseError::Duplicate {
                line: 3,
                text: "a/**".into()
            })
        );
    }

    #[test]
    fn directory_patterns_match_only_whole_segments() {
        let l = list();
        assert!(l.covers("crates/nucleus-node/src/main.rs"));
        assert!(!l.covers("crates/nucleus-node-evidence/src/lib.rs"));
        assert!(!l.covers("crates/nucleus-node"));
    }

    #[test]
    fn exact_patterns_match_only_that_file() {
        let l = list();
        assert!(l.covers("scripts/check-egress-probe.sh"));
        assert!(!l.covers("scripts/check-egress-probe.sh.bak"));
        assert!(!l.covers("scripts/check-egress-probe.sh/x"));
    }

    #[test]
    fn unscoped_events_always_run_and_never_diff() {
        for e in ["push", "schedule", "workflow_dispatch", "something_new"] {
            let d = decide(
                &Event::from_name(e),
                Some(&range()),
                |_| panic!("an unscoped event must not diff"),
                &list(),
            );
            assert_eq!(d, Decision::Run(RunBecause::UnscopedEvent(e.into())));
        }
    }

    #[test]
    fn a_missing_range_runs() {
        for e in [Event::PullRequest, Event::MergeGroup] {
            let d = decide(&e, None, |_| panic!("no range, no diff"), &list());
            assert_eq!(d, Decision::Run(RunBecause::NoRange));
        }
        assert_eq!(Range::new(Some(""), Some("b")), None);
        assert_eq!(Range::new(Some("a"), None), None);
    }

    #[test]
    fn a_failed_diff_runs() {
        let d = decide(
            &Event::MergeGroup,
            Some(&range()),
            |_| Err("bad revision".into()),
            &list(),
        );
        assert_eq!(d, Decision::Run(RunBecause::DiffFailed("bad revision".into())));
        assert!(d.relevant());
    }

    #[test]
    fn an_empty_diff_runs() {
        let d = decide(&Event::PullRequest, Some(&range()), |_| files(&[]), &list());
        assert_eq!(d, Decision::Run(RunBecause::EmptyDiff));
        assert!(d.relevant());
    }

    /// The straddling pull request: one file in scope, one outside. With a path-filtered twin
    /// pair this fired both producers; here it is one decision, and it runs.
    #[test]
    fn a_straddling_change_runs() {
        let d = decide(
            &Event::PullRequest,
            Some(&range()),
            |_| files(&["Cargo.lock", "crates/nucleus-node/src/net.rs", "docs/x.md"]),
            &list(),
        );
        assert_eq!(
            d,
            Decision::Run(RunBecause::Touched("crates/nucleus-node/src/net.rs".into()))
        );
    }

    #[test]
    fn a_change_wholly_outside_the_scope_skips_and_says_how_much_it_looked_at() {
        let d = decide(
            &Event::MergeGroup,
            Some(&range()),
            |_| files(&["docs/x.md", "crates/portcullis/src/lib.rs"]),
            &list(),
        );
        assert_eq!(d, Decision::Skip { examined: 2 });
        assert!(!d.relevant());
    }

    #[test]
    fn the_diff_is_asked_for_the_events_range() {
        let mut seen = None;
        let _ = decide(
            &Event::PullRequest,
            Some(&range()),
            |r| {
                seen = Some((r.base().to_string(), r.head().to_string()));
                files(&["docs/x.md"])
            },
            &list(),
        );
        assert_eq!(seen, Some(("aaa".into(), "bbb".into())));
    }

    #[test]
    fn nul_separated_output_splits_without_empty_entries() {
        assert_eq!(split_nul(b"a\0b c\0\0"), vec!["a", "b c"]);
        assert!(split_nul(b"").is_empty());
    }
}

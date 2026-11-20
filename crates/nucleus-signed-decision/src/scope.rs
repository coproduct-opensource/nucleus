//! What a verified decision covers, three-valued (ADR 0007 A-1).
//!
//! Matching is exact. A ref and a capability are covered only by an identical string in the
//! signed scope. A path is covered by an identical path, or by a `<dir>/**` pattern naming a
//! directory it is strictly under, segment by segment, or by a lone `**`, which the owner signed
//! as "anywhere". That is the whole grammar: any other glob
//! character in a signed pattern makes it one this verifier cannot read, and a pattern it cannot
//! read never covers anything. It yields [`Coverage::CannotTell`], which no sink treats as covered.

use crate::record::Scope;

/// Is an action inside a decision's signed scope?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Coverage {
    /// Inside the signed scope.
    Covered,
    /// Outside it, by name.
    OutOfScope,
    /// This verifier cannot say: the action's write set is unknown, a path is not a plain
    /// relative path, or the only patterns that could match use a grammar it does not read.
    /// Never "covered".
    CannotTell,
}

/// One item to check against a decision's scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeRef<'a> {
    /// An issue or pull request, `owner/name#N`.
    Ref(&'a str),
    /// A named runtime capability.
    Capability(&'a str),
    /// A repository-relative path the action writes.
    Path(&'a str),
}

/// What an action writes. "Not known" is its own arm, so it cannot be read as "nothing".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteSet<'a> {
    /// Exactly these repository-relative paths. Empty means the action writes nothing.
    Known(&'a [String]),
    /// The caller cannot say what the action writes.
    Unknown,
}

/// An action that cites a decision: the capability it exercises and what it writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Action<'a> {
    /// The capability exercised. Must be in `scope.capabilities`.
    pub capability: &'a str,
    /// What it writes. Every path must be covered by `scope.paths`.
    pub writes: WriteSet<'a>,
}

const GLOB_CHARS: &[char] = &['*', '?', '[', ']', '{', '}', '\\'];

/// A plain repository-relative path: non-empty segments, none `.` or `..`, no leading `/`, no
/// glob character.
fn plain_path(p: &str) -> bool {
    !p.is_empty()
        && !p.contains(GLOB_CHARS)
        && p.split('/').all(|s| !s.is_empty() && s != "." && s != "..")
}

/// One pattern against one plain path.
fn pattern_covers(pattern: &str, path: &str) -> Coverage {
    if pattern == path && plain_path(pattern) {
        return Coverage::Covered;
    }
    if pattern == "**" {
        return Coverage::Covered;
    }
    if let Some(dir) = pattern.strip_suffix("/**")
        && plain_path(dir)
    {
        return match path.strip_prefix(dir).and_then(|r| r.strip_prefix('/')) {
            Some(rest) if !rest.is_empty() => Coverage::Covered,
            _ => Coverage::OutOfScope,
        };
    }
    if plain_path(pattern) {
        Coverage::OutOfScope
    } else {
        Coverage::CannotTell
    }
}

fn path_covered(patterns: &[String], path: &str) -> Coverage {
    if !plain_path(path) {
        return Coverage::CannotTell;
    }
    let mut unreadable = false;
    for p in patterns {
        match pattern_covers(p, path) {
            Coverage::Covered => return Coverage::Covered,
            Coverage::OutOfScope => {}
            Coverage::CannotTell => unreadable = true,
        }
    }
    if unreadable {
        Coverage::CannotTell
    } else {
        Coverage::OutOfScope
    }
}

fn exact(list: &[String], item: &str) -> Coverage {
    if list.iter().any(|x| x == item) {
        Coverage::Covered
    } else {
        Coverage::OutOfScope
    }
}

/// One item against a scope.
pub(crate) fn covers(scope: &Scope, item: ScopeRef<'_>) -> Coverage {
    let Scope {
        refs,
        paths,
        capabilities,
    } = scope;
    match item {
        ScopeRef::Ref(r) => exact(refs, r),
        ScopeRef::Capability(c) => exact(capabilities, c),
        ScopeRef::Path(p) => path_covered(paths, p),
    }
}

/// An action against a scope: the capability, then every write. A definite refusal on any write
/// outranks a write this verifier cannot read, so a refusal names the path that is out of scope.
pub(crate) fn covers_action(scope: &Scope, action: &Action<'_>) -> Coverage {
    let Action { capability, writes } = action;
    match covers(scope, ScopeRef::Capability(capability)) {
        Coverage::Covered => {}
        other => return other,
    }
    let paths = match writes {
        WriteSet::Known(paths) => *paths,
        WriteSet::Unknown => return Coverage::CannotTell,
    };
    let mut unreadable = false;
    for p in paths {
        match covers(scope, ScopeRef::Path(p)) {
            Coverage::Covered => {}
            Coverage::OutOfScope => return Coverage::OutOfScope,
            Coverage::CannotTell => unreadable = true,
        }
    }
    if unreadable {
        Coverage::CannotTell
    } else {
        Coverage::Covered
    }
}

/// Is `narrow` within `wide`, item by item? The verifier's half of "never wider than proposed":
/// the control plane refuses a wider scope at acceptance, and a bundle that reaches a pod is
/// checked again, so a server that skipped the check is not the only thing standing.
pub(crate) fn first_widening<'a>(narrow: &'a Scope, wide: &Scope) -> Option<&'a str> {
    let Scope {
        refs,
        paths,
        capabilities,
    } = narrow;
    let within = |items: &'a [String], of: &[String]| {
        items.iter().find(|i| !of.contains(i)).map(String::as_str)
    };
    within(refs, &wide.refs)
        .or_else(|| within(paths, &wide.paths))
        .or_else(|| within(capabilities, &wide.capabilities))
}

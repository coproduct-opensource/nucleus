//! Path normalization: one spelling per guest path, as bytes.
//!
//! A normalized path is relative (no leading `/`), has no empty, `.` or `..`
//! components, no NUL, and is joined with single `/`. Non-UTF-8 bytes are kept
//! exactly: a guest filename is bytes, and re-encoding one would rename it.

/// What a raw entry name normalizes to.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Normalized {
    /// The root itself (`/`, `./`, `.`).
    Root,
    /// A path below the root.
    Path(Vec<u8>),
}

/// Why a raw name has no normal form.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PathDefect {
    Empty,
    Nul,
    DotDot,
    TooLong(usize),
}

/// Normalize a raw tar name (or hardlink target).
pub(crate) fn normalize(raw: &[u8], max_len: u64) -> Result<Normalized, PathDefect> {
    if raw.is_empty() {
        return Err(PathDefect::Empty);
    }
    if u64::try_from(raw.len()).unwrap_or(u64::MAX) > max_len {
        return Err(PathDefect::TooLong(raw.len()));
    }
    if raw.contains(&0) {
        return Err(PathDefect::Nul);
    }
    let mut out: Vec<u8> = Vec::with_capacity(raw.len());
    for component in raw.split(|b| *b == b'/') {
        match component {
            b"" | b"." => {}
            b".." => return Err(PathDefect::DotDot),
            name => {
                if !out.is_empty() {
                    out.push(b'/');
                }
                out.extend_from_slice(name);
            }
        }
    }
    if out.is_empty() {
        Ok(Normalized::Root)
    } else {
        Ok(Normalized::Path(out))
    }
}

/// `path` lies strictly below `ancestor`. Everything non-root lies below the root (`b""`).
pub(crate) fn is_strictly_under(path: &[u8], ancestor: &[u8]) -> bool {
    if ancestor.is_empty() {
        return !path.is_empty();
    }
    match path.strip_prefix(ancestor) {
        Some(rest) => rest.first() == Some(&b'/'),
        None => false,
    }
}

/// `a` is `b`, or one lies below the other.
pub(crate) fn related(a: &[u8], b: &[u8]) -> bool {
    a == b || is_strictly_under(a, b) || is_strictly_under(b, a)
}

/// The strict ancestors of a normalized path, shortest first (the root excluded).
pub(crate) fn strict_ancestors(path: &[u8]) -> impl Iterator<Item = &[u8]> {
    path.iter()
        .enumerate()
        .filter(|(_, b)| **b == b'/')
        .filter_map(|(i, _)| path.get(..i))
}

/// The parent (`b""` for a top-level name) and the final component.
pub(crate) fn split_last(path: &[u8]) -> (&[u8], &[u8]) {
    match path.iter().rposition(|b| *b == b'/') {
        Some(i) => (
            path.get(..i).unwrap_or_default(),
            path.get(i.saturating_add(1)..).unwrap_or_default(),
        ),
        None => (&[], path),
    }
}

/// `parent/name`, or `name` at the root.
pub(crate) fn join(parent: &[u8], name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parent.len().saturating_add(name.len()).saturating_add(1));
    out.extend_from_slice(parent);
    if !parent.is_empty() {
        out.push(b'/');
    }
    out.extend_from_slice(name);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(s: &[u8]) -> Result<Normalized, PathDefect> {
        normalize(s, 4096)
    }

    #[test]
    fn strips_leading_slash_and_dot_and_collapses_slashes() {
        assert_eq!(
            norm(b"/etc//passwd"),
            Ok(Normalized::Path(b"etc/passwd".to_vec()))
        );
        assert_eq!(
            norm(b"./usr/./bin/"),
            Ok(Normalized::Path(b"usr/bin".to_vec()))
        );
        assert_eq!(norm(b"./"), Ok(Normalized::Root));
        assert_eq!(norm(b"/"), Ok(Normalized::Root));
    }

    #[test]
    fn refuses_dotdot_nul_empty_and_overlong() {
        assert_eq!(norm(b"../etc/passwd"), Err(PathDefect::DotDot));
        assert_eq!(norm(b"a/../../x"), Err(PathDefect::DotDot));
        assert_eq!(norm(b"a/..b/c"), Ok(Normalized::Path(b"a/..b/c".to_vec())));
        assert_eq!(norm(b"a\0b"), Err(PathDefect::Nul));
        assert_eq!(norm(b""), Err(PathDefect::Empty));
        assert_eq!(normalize(b"abcdef", 5), Err(PathDefect::TooLong(6)));
    }

    #[test]
    fn keeps_non_utf8_bytes() {
        assert_eq!(
            norm(b"x/\xff\xfe"),
            Ok(Normalized::Path(b"x/\xff\xfe".to_vec()))
        );
    }

    #[test]
    fn ancestry() {
        assert!(is_strictly_under(b"etc/nucleus/pod.yaml", b"etc/nucleus"));
        assert!(!is_strictly_under(b"etc/nucleus-x", b"etc/nucleus"));
        assert!(!is_strictly_under(b"etc/nucleus", b"etc/nucleus"));
        assert!(is_strictly_under(b"etc", b""));
        assert!(related(b"etc", b"etc/nucleus/x"));
        assert!(!related(b"etcx", b"etc/nucleus"));
        let a: Vec<&[u8]> = strict_ancestors(b"a/b/c").collect();
        assert_eq!(a, vec![&b"a"[..], &b"a/b"[..]]);
        assert_eq!(split_last(b"a/b/c"), (&b"a/b"[..], &b"c"[..]));
        assert_eq!(split_last(b"c"), (&b""[..], &b"c"[..]));
    }
}

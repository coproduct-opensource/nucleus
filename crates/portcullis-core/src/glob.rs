//! ONE glob primitive for every containment question the lattice asks.
//!
//! Three sites used to answer "is this scope inside that scope" three ways:
//! `SinkScope::contains` compared pattern strings for equality (so a child
//! scoped to `src/foo/**` under a parent scoped to `src/**` was refused),
//! `DelegationScope::is_subset_of` had a hand-rolled segment matcher, and
//! `PathLattice::meet` intersected pattern *strings* (so `src/**` ⊓
//! `src/foo/**` was NOTHING — a narrower child delegated itself out of every
//! path). Three semantics for one relation is how a ceiling stops meaning
//! anything; this module is the relation, and the three sites call it.
//!
//! The shape is gatehouse's `subsetGlob` — the kernel-checked lattice order on
//! its `fsRead`/`fsWrite` capabilities — extended with the two sound cases the
//! nucleus lattice already relied on (a literal under a glob, and
//! segment-wise `*`/`**` subsumption). **Sound and deliberately incomplete**:
//! what it cannot derive it refuses. Incompleteness costs a policy author a
//! rewrite; it never costs a relying party a wrong acceptance, which is the
//! only direction of error that would matter for a containment check.
//!
//! Dependency-free and allocation-free on the match path, so it extracts.

/// Glob syntax shared by every caller:
/// - `*` matches any run of characters except `/` (one path component);
/// - `**` matches any run of characters including `/` (zero or more
///   components); `**/` at the start and `/**` at the end are the usual
///   prefix/suffix forms;
/// - every other byte matches itself.
pub fn glob_match(pattern: &str, path: &str) -> bool {
    match_inner(pattern.as_bytes(), path.as_bytes())
}

fn match_inner(pattern: &[u8], text: &[u8]) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }
    // A trailing `/**` matches zero components too: `src` is under `src/**`
    // (gatehouse's reading, and the one `glob_subsumes` case 3 relies on).
    if pattern == b"/**" && text.is_empty() {
        return true;
    }
    if pattern.len() >= 2 && pattern[0] == b'*' && pattern[1] == b'*' {
        let rest = if pattern.len() > 2 && pattern[2] == b'/' {
            &pattern[3..] // skip `**/`
        } else {
            &pattern[2..] // bare `**` at end
        };
        // `**` matches zero or more characters including `/`
        for i in 0..=text.len() {
            if match_inner(rest, &text[i..]) {
                return true;
            }
        }
        return false;
    }
    if pattern[0] == b'*' {
        // `*` matches zero or more non-`/` characters
        let rest = &pattern[1..];
        for i in 0..=text.len() {
            if i > 0 && text[i - 1] == b'/' {
                break;
            }
            if match_inner(rest, &text[i..]) {
                return true;
            }
        }
        return false;
    }
    if text.is_empty() {
        return false;
    }
    if pattern[0] == text[0] {
        return match_inner(&pattern[1..], &text[1..]);
    }
    false
}

/// Whether a pattern contains a glob metacharacter (`*`).
pub fn has_glob_chars(s: &str) -> bool {
    s.contains('*')
}

/// Whether every path matching `narrow` also matches `wide` — the ordering
/// the capability lattice is actually about.
///
/// Decided cases, each sound:
/// 1. `narrow == wide`;
/// 2. `wide` is `**` (or `**/*`): everything is under it;
/// 3. `wide` is `Q/**` and `narrow` is `Q` itself or lies under `Q/` — the
///    component boundary is load-bearing: `cratesfoo/**` is NOT under
///    `crates/**`, and without the `/` a delegate could reach a sibling
///    directory its ceiling never granted;
/// 4. `narrow` is a literal (no `*`): it is under `wide` iff `wide` matches it;
/// 5. both are globs: segment-wise subsumption, where a `**` segment of `wide`
///    covers any number of `narrow` segments, a `*` segment covers one
///    non-`**` segment, and a literal segment covers only itself.
///
/// Anything else — `a/*/b` under `a/**/b`, say — is REFUSED, not guessed.
pub fn glob_subsumes(narrow: &str, wide: &str) -> bool {
    if narrow == wide {
        return true;
    }
    if wide == "**" || wide == "**/*" {
        return true;
    }
    if let Some(prefix) = wide.strip_suffix("/**")
        && !prefix.is_empty()
        && (narrow == prefix
            || (narrow.len() > prefix.len()
                && narrow.as_bytes()[..prefix.len()] == *prefix.as_bytes()
                && narrow.as_bytes()[prefix.len()] == b'/'))
    {
        return true;
    }
    if !has_glob_chars(narrow) {
        return glob_match(wide, narrow);
    }
    let w: Vec<&str> = wide.split('/').collect();
    let n: Vec<&str> = narrow.split('/').collect();
    subsumes_segments(&w, &n)
}

fn subsumes_segments(wide: &[&str], narrow: &[&str]) -> bool {
    if wide.is_empty() {
        return narrow.is_empty();
    }
    if wide[0] == "**" {
        // `**` can consume zero or more narrow segments
        let rest = &wide[1..];
        for i in 0..=narrow.len() {
            if subsumes_segments(rest, &narrow[i..]) {
                return true;
            }
        }
        return false;
    }
    if narrow.is_empty() {
        return false;
    }
    // A wide `*` covers any single narrow segment except `**`
    if wide[0] == "*" && narrow[0] != "**" {
        return subsumes_segments(&wide[1..], &narrow[1..]);
    }
    // Exact segment match (literal = literal, `**` = `**`, `*` = `*`)
    if wide[0] == narrow[0] {
        return subsumes_segments(&wide[1..], &narrow[1..]);
    }
    false
}

/// Whether every pattern in `narrow` is under some pattern in `wide` — the
/// set form every scope dimension uses. The empty set is under anything.
pub fn all_subsumed<'a, N, W>(narrow: N, wide: W) -> bool
where
    N: IntoIterator<Item = &'a str>,
    W: IntoIterator<Item = &'a str> + Clone,
{
    narrow
        .into_iter()
        .all(|n| wide.clone().into_iter().any(|w| glob_subsumes(n, w)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// gatehouse's golden cases for `subsetGlob`, verbatim
    /// (`crates/writ/tests/prelude.rs#a_narrower_pattern_set_is_under_a_wider_ceiling_and_a_byte_prefix_is_not`).
    #[test]
    fn a_narrower_pattern_set_is_under_a_wider_ceiling_and_a_byte_prefix_is_not() {
        assert!(
            glob_subsumes("crates/writ/**", "crates/**"),
            "narrower is under wider"
        );
        assert!(
            glob_subsumes("crates", "crates/**"),
            "`**` matches zero components"
        );
        assert!(
            all_subsumed(
                ["crates/writ/**", "Cargo.toml"],
                ["crates/**", "Cargo.toml"]
            ),
            "each pattern needs some cover, not the same one"
        );
        assert!(
            all_subsumed([], ["crates/**"]),
            "the empty set is under anything"
        );
        // A byte prefix is not a component prefix — without this, a gate could
        // read a sibling directory its ceiling never granted.
        assert!(!glob_subsumes("cratesfoo/**", "crates/**"));
        // Wider is not under narrower.
        assert!(!glob_subsumes("crates/**", "crates/writ/**"));
        // And a ceiling that is not a `**` pattern covers only itself.
        assert!(!glob_subsumes("crates/writ", "crates"));
    }

    /// The two cases nucleus already relied on, kept sound.
    #[test]
    fn a_literal_is_under_a_glob_that_matches_it_and_segments_subsume() {
        assert!(glob_subsumes("src/main.rs", "src/*.rs"));
        assert!(!glob_subsumes("src/a/main.rs", "src/*.rs"));
        assert!(glob_subsumes("src/*/lib.rs", "src/**"));
        assert!(glob_subsumes("src/*/lib.rs", "src/*/lib.rs"));
        assert!(glob_subsumes("src/*", "src/**"));
        assert!(glob_subsumes("anything/at/all", "**"));
        assert!(glob_subsumes("**/x", "**"));
        // `*` does not cover `**`: one component is not any number.
        assert!(!glob_subsumes("src/**", "src/*"));
        // A segment-wise `**` covers one segment too (sound, derived).
        assert!(glob_subsumes("a/*/b", "a/**/b"));
        // Incomplete on purpose: `a*b` IS under `*b`, but the primitive does
        // not reason inside a segment, so it refuses rather than guesses.
        assert!(!glob_subsumes("a*b", "*b"));
    }

    #[test]
    fn subsumption_is_reflexive_and_transitive_on_the_decided_fragment() {
        for p in ["", "a", "a/b", "a/*", "a/**", "**", "*.rs", "a/*/b/**"] {
            assert!(glob_subsumes(p, p), "{p:?} under itself");
        }
        let chain = ["src/foo/bar.rs", "src/foo/**", "src/**", "**"];
        for i in 0..chain.len() {
            for j in i..chain.len() {
                assert!(
                    glob_subsumes(chain[i], chain[j]),
                    "{} ⊑ {}",
                    chain[i],
                    chain[j]
                );
            }
        }
    }

    #[test]
    fn glob_match_is_the_shared_matcher() {
        assert!(glob_match("src/**", "src/a/b.rs"));
        assert!(glob_match("src/**", "src"));
        assert!(glob_match("**/*.rs", "a/b/c.rs"));
        assert!(glob_match("*.rs", "c.rs"));
        assert!(!glob_match("*.rs", "a/c.rs"));
        assert!(!glob_match("src/*", "src/a/b"));
    }
}

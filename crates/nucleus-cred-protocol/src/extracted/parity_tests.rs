//! The classifier's production functions decide exactly what they decided
//! before they were rewritten over `extracted::classify`.
//!
//! `old` below is the implementation `operation_for`, `EffectTable::declared`
//! and `EffectTable::from_parts` had before the rewrite, kept verbatim and
//! test-only: it is the reference the rewrite is held to, not a second
//! decider (ADR 0007 G-1 — nothing outside this module calls it). Each test
//! compares it with the production function on generated inputs built from
//! the tokens the classifier treats specially: escapes (including the `%+f`
//! form `u8::from_str_radix` accepts), the push service in several spellings,
//! separators, wildcards, refused pattern characters and non-ASCII text.
//!
//! Two details of the old decoder are kept in `classify::percent_decode_once`
//! and are not observable here: an escape `%+X` (the sign `u8::from_str_radix`
//! accepts) decodes to a control byte, and a non-ASCII byte is re-encoded as
//! two. Removing either leaves these tests green (2026-11-18, measured by
//! mutating the core): neither can create, remove or split an ASCII literal,
//! a `/` or a `%`, and every decision reads only those. They are kept so the
//! decoded bytes are the old ones, not because a decision depends on them.

use proptest::prelude::*;

use crate::egress::{
    DeclaredEffect, EffectTable, EffectTableError, EgressMethod, EgressOperation,
    MAX_PATTERN_SEGMENTS, Unclassified, UpstreamKind, operation_for,
};

/// The implementation before the rewrite, verbatim but for paths.
mod old {
    use super::*;

    pub fn operation_for(
        table: &EffectTable,
        method: EgressMethod,
        path: &str,
        query: Option<&str>,
    ) -> Result<EgressOperation, Unclassified> {
        let names_push = |text: &str| decoded_lowercase(text).contains(RECEIVE_SERVICE);
        if names_push(path) || (method.carries_body() && query.is_some_and(names_push)) {
            return Ok(EgressOperation::GitPush);
        }
        if let Some(declared) = declared(table, method, path) {
            return Ok(declared);
        }
        match (table.kind(), method.carries_body()) {
            (UpstreamKind::Forge, true) => Err(Unclassified),
            (UpstreamKind::Forge, false) | (UpstreamKind::Api, _) => Ok(EgressOperation::WebFetch),
        }
    }

    const RECEIVE_SERVICE: &str = "receive-pack";

    fn decoded_lowercase(text: &str) -> String {
        let mut current = text.to_ascii_lowercase();
        for _ in 0..4 {
            let next = percent_decode_once(&current).to_ascii_lowercase();
            if next == current {
                break;
            }
            current = next;
        }
        current
    }

    fn percent_decode_once(text: &str) -> String {
        let bytes = text.as_bytes();
        let mut out = String::with_capacity(bytes.len());
        let mut i = 0;
        while let Some(&b) = bytes.get(i) {
            let escape = (b == b'%')
                .then(|| bytes.get(i + 1..i + 3))
                .flatten()
                .and_then(|hex| std::str::from_utf8(hex).ok())
                .and_then(|hex| u8::from_str_radix(hex, 16).ok());
            match escape {
                Some(decoded) => {
                    if decoded.is_ascii() {
                        out.push(char::from(decoded));
                    }
                    i += 3;
                }
                None => {
                    out.push(char::from(b));
                    i += 1;
                }
            }
        }
        out
    }

    pub fn from_parts(
        kind: Option<UpstreamKind>,
        effects: &[DeclaredEffect],
    ) -> Result<UpstreamKind, EffectTableError> {
        if effects.len() > crate::egress::MAX_EFFECTS {
            return Err(EffectTableError::TooMany(effects.len()));
        }
        let mut parsed: Vec<(&DeclaredEffect, Vec<String>)> = Vec::with_capacity(effects.len());
        for effect in effects {
            let segments = pattern_segments(&effect.path)
                .ok_or_else(|| EffectTableError::BadPattern(effect.path.clone()))?;
            for (other, other_segments) in &parsed {
                if other.method == effect.method
                    && other.operation != effect.operation
                    && overlap(other_segments, &segments)
                {
                    return Err(EffectTableError::Ambiguous(
                        other.path.clone(),
                        effect.path.clone(),
                    ));
                }
            }
            parsed.push((effect, segments));
        }
        Ok(kind.unwrap_or(UpstreamKind::Api))
    }

    pub fn declared(
        table: &EffectTable,
        method: EgressMethod,
        path: &str,
    ) -> Option<EgressOperation> {
        let request = request_segments(path);
        table
            .effects()
            .iter()
            .filter(|e| e.method == method)
            .find(|e| pattern_segments(&e.path).is_some_and(|pattern| matches(&pattern, &request)))
            .map(|e| e.operation)
    }

    fn pattern_segments(pattern: &str) -> Option<Vec<String>> {
        let segments: Vec<String> = pattern
            .split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase)
            .collect();
        let valid = !segments.is_empty()
            && segments.len() <= MAX_PATTERN_SEGMENTS
            && segments.iter().all(|s| {
                s == "*"
                    || (!s.contains(['*', '%', '?', '#', '\\'])
                        && s != ".."
                        && s != "."
                        && s.bytes().all(|b| b.is_ascii_graphic()))
            });
        valid.then_some(segments)
    }

    fn request_segments(path: &str) -> Vec<String> {
        decoded_lowercase(path)
            .split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    }

    fn matches(pattern: &[String], request: &[String]) -> bool {
        pattern.len() == request.len()
            && pattern.iter().zip(request).all(|(p, r)| p == "*" || p == r)
    }

    fn overlap(a: &[String], b: &[String]) -> bool {
        a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x == "*" || y == "*" || x == y)
    }
}

/// Fragments the classifier treats specially, joined into paths and queries.
const TOKENS: &[&str] = &[
    "/",
    "/",
    "//",
    "%",
    "%2",
    "%25",
    "%252",
    "%2d",
    "%2D",
    "%2f",
    "%2F",
    "%2e",
    "%73",
    "%53",
    "%+f",
    "%+",
    "%-1",
    "%zz",
    "%c3%a9",
    "%80",
    "receive",
    "-pack",
    "receive-pack",
    "RECEIVE-PACK",
    "git-",
    "upload-pack",
    "service=",
    "&",
    "repos",
    "REPOS",
    "org",
    "repo",
    "pulls",
    "pull",
    "s",
    "graphql",
    "*",
    ".",
    "..",
    "?",
    "#",
    "\\",
    "é",
    "ß",
    "x",
    "A",
    "_",
];

/// Patterns an operator might declare, valid and not.
const PATTERNS: &[&str] = &[
    "repos/*/*/pulls",
    "/repos/*/*/pulls",
    "REPOS/*/*/PULLS",
    "repos/org/*/pulls",
    "repos/*/repo/*",
    "*/*/git-upload-pack",
    "*/*/git-receive-pack",
    "graphql",
    "*",
    "*/*",
    "a/*",
    "*/b",
    "a/b",
    "",
    "/",
    "repos/*x/pulls",
    "a/%2e/b",
    "a/../b",
    "a/./b",
    "a?b",
    "a#b",
    "a\\b",
    "é/x",
    "pulls",
    "repos//org/*/pulls/",
];

fn tokens() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(TOKENS), 0..10).prop_map(|t| t.concat())
}

/// `c` percent-encoded `levels` times: `-`, `%2d`, `%252d`, `%25252d`, ...
fn encoded(c: char, levels: usize) -> String {
    if levels == 0 {
        return c.to_string();
    }
    let mut out = format!("%{:02x}", u32::from(c));
    for _ in 1..levels {
        out = out.replacen('%', "%25", 1);
    }
    out
}

/// A service name or route word with one character encoded up to six
/// times, so the decoder's pass bound is reached and passed.
fn deep() -> impl Strategy<Value = String> {
    (
        prop::sample::select(vec![
            "git-receive-pack",
            "git-upload-pack",
            "repos/o/r/pulls",
        ]),
        any::<prop::sample::Index>(),
        0usize..7,
    )
        .prop_map(|(word, at, levels)| {
            let at = at.index(word.len());
            let (head, tail) = word.split_at(at);
            let mut chars = tail.chars();
            let c = chars.next().unwrap_or('-');
            format!("{head}{}{}", encoded(c, levels), chars.as_str())
        })
}

fn text() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => tokens(),
        1 => (tokens(), deep(), tokens()).prop_map(|(a, b, c)| format!("{a}{b}{c}")),
    ]
}

fn method() -> impl Strategy<Value = EgressMethod> {
    prop::sample::select(vec![EgressMethod::Get, EgressMethod::Post])
}

fn operation() -> impl Strategy<Value = EgressOperation> {
    prop::sample::select(vec![
        EgressOperation::WebFetch,
        EgressOperation::GitPush,
        EgressOperation::CreatePr,
    ])
}

fn kind() -> impl Strategy<Value = Option<UpstreamKind>> {
    prop::sample::select(vec![
        None,
        Some(UpstreamKind::Api),
        Some(UpstreamKind::Forge),
    ])
}

fn effect() -> impl Strategy<Value = DeclaredEffect> {
    (
        method(),
        prop_oneof![
            prop::sample::select(PATTERNS).prop_map(String::from),
            text()
        ],
        operation(),
    )
        .prop_map(|(method, path, operation)| DeclaredEffect {
            method,
            path,
            operation,
        })
}

/// A table, valid or not: up to six effects, or a run of one effect long
/// enough to reach the `MAX_EFFECTS` bound.
fn effects() -> impl Strategy<Value = Vec<DeclaredEffect>> {
    prop_oneof![
        8 => prop::collection::vec(effect(), 0..6),
        1 => (effect(), 60usize..70).prop_map(|(e, n)| vec![e; n]),
    ]
}

/// A table that builds: the generated effects, with every one that makes the
/// table invalid dropped.
fn table() -> impl Strategy<Value = EffectTable> {
    (kind(), prop::collection::vec(effect(), 0..6)).prop_map(|(kind, candidates)| {
        let mut kept: Vec<DeclaredEffect> = Vec::new();
        for candidate in candidates {
            let mut trial = kept.clone();
            trial.push(candidate);
            if EffectTable::from_parts(kind, trial.clone()).is_ok() {
                kept = trial;
            }
        }
        EffectTable::from_parts(kind, kept).expect("every kept effect was accepted")
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// `EffectTable::from_parts` accepts and refuses exactly the tables, and
    /// names exactly the patterns, it did before.
    #[test]
    fn from_parts_decides_as_before(kind in kind(), effects in effects()) {
        let new = EffectTable::from_parts(kind, effects.clone()).map(|t| t.kind());
        prop_assert_eq!(new, old::from_parts(kind, &effects));
    }

    /// `EffectTable::declared` answers every request as before.
    #[test]
    fn declared_decides_as_before(table in table(), method in method(), path in text()) {
        prop_assert_eq!(
            table.declared(method, &path),
            old::declared(&table, method, &path)
        );
    }

    /// `operation_for` classifies every call as before.
    #[test]
    fn operation_for_decides_as_before(
        table in table(),
        method in method(),
        path in text(),
        query in prop::option::of(text()),
    ) {
        prop_assert_eq!(
            operation_for(&table, method, &path, query.as_deref()),
            old::operation_for(&table, method, &path, query.as_deref())
        );
    }
}

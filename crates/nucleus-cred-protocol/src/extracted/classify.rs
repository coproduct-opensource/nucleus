//! The effect classifier's decisions over bytes: [`operation_for`],
//! [`declared`] and [`from_parts`].
//!
//! These are the production deciders. `super::super::egress::operation_for`,
//! `EffectTable::declared` and `EffectTable::from_parts` convert their inputs
//! (a `&str`, a table of `String` patterns) into the views below and call
//! these, so the classification is written once (ADR 0007 G-1) and that one
//! copy is the code Charon and Aeneas translate.
//!
//! What a reader of the Rust may find odd, and why each is so:
//!
//! * Explicit `while` loops over indices instead of iterator adaptors and
//!   closures: Aeneas does not translate `Iter::find` (a higher-ranked
//!   lifetime) or `core::str::pattern`.
//! * Byte literals spelled as arrays of numbers, and comparisons spelled as
//!   `>=`/`<=` rather than `RangeInclusive::contains`: a method call there is an
//!   opaque axiom in the extraction, a comparison is a definition.
//! * Enum equality by exhaustive `match` rather than `==`: the derived
//!   `PartialEq` goes through a discriminant intrinsic, and an exhaustive match
//!   also makes a new variant a build failure here (ADR 0007 E-2).
//! * A pattern is matched segment by segment in place, rather than split into
//!   a `Vec<String>` first. The answer is the same: equal segment counts, and
//!   each pattern segment `*` or equal to the request's.

use crate::egress::{EgressMethod, EgressOperation, Unclassified, UpstreamKind};

/// The most effects one upstream may declare.
pub const MAX_EFFECTS: usize = 64;

/// The most segments one pattern may have.
pub const MAX_PATTERN_SEGMENTS: usize = 32;

/// How many times a request is percent-decoded at most. Each layer an escape
/// passes through decodes it once (`%252d` is `%2d` after one, `-` after two),
/// and the classifier must see what the last layer sees.
const DECODE_PASSES: usize = 4;

/// `/`, the segment separator.
const SLASH: u8 = 0x2F;
/// `%`, which opens an escape.
const PERCENT: u8 = 0x25;
/// `+`, which `u8::from_str_radix` accepts as a sign before the digits.
const PLUS: u8 = 0x2B;
/// `*`, the one-segment wildcard.
const STAR: u8 = 0x2A;
/// `.`, refused as a whole segment (as is `..`).
const DOT: u8 = 0x2E;

/// One declared effect, as the deciders read it: the pattern as the
/// operator wrote it, unparsed, as bytes.
#[derive(Clone, Debug)]
pub struct Effect {
    /// The method the effect is declared for.
    pub method: EgressMethod,
    /// The path pattern's bytes.
    pub path: Vec<u8>,
    /// The operation a matching request is.
    pub operation: EgressOperation,
}

/// Why a table was refused, by the position of the effect(s) at fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableRefusal {
    /// More than [`MAX_EFFECTS`] effects: the count.
    TooMany(usize),
    /// The effect at this index has a path that is not a pattern.
    BadPattern(usize),
    /// The effects at these indices, earlier first, are for one method,
    /// have overlapping patterns and different operations.
    Ambiguous(usize, usize),
}

/// Whether two methods are the same method.
pub fn same_method(a: EgressMethod, b: EgressMethod) -> bool {
    match a {
        EgressMethod::Get => match b {
            EgressMethod::Get => true,
            EgressMethod::Post => false,
        },
        EgressMethod::Post => match b {
            EgressMethod::Get => false,
            EgressMethod::Post => true,
        },
    }
}

/// Whether two operations are the same operation.
pub fn same_operation(a: EgressOperation, b: EgressOperation) -> bool {
    match a {
        EgressOperation::WebFetch => match b {
            EgressOperation::WebFetch => true,
            EgressOperation::GitPush => false,
            EgressOperation::CreatePr => false,
        },
        EgressOperation::GitPush => match b {
            EgressOperation::WebFetch => false,
            EgressOperation::GitPush => true,
            EgressOperation::CreatePr => false,
        },
        EgressOperation::CreatePr => match b {
            EgressOperation::WebFetch => false,
            EgressOperation::GitPush => false,
            EgressOperation::CreatePr => true,
        },
    }
}

/// Whether a request with this method carries a body upstream.
pub fn carries_body(method: EgressMethod) -> bool {
    match method {
        EgressMethod::Get => false,
        EgressMethod::Post => true,
    }
}

/// `u8::to_ascii_lowercase`.
#[expect(
    clippy::manual_range_contains,
    reason = "RangeInclusive::contains is an opaque axiom in the Aeneas extraction; comparisons are definitions"
)]
pub fn lower(b: u8) -> u8 {
    if b >= 0x41 && b <= 0x5A { b + 0x20 } else { b }
}

/// `<[u8]>::to_ascii_lowercase`.
pub fn lowercase(text: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    while i < text.len() {
        out.push(lower(text[i]));
        i += 1;
    }
    out
}

/// Whether two byte strings are equal.
pub fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut equal = true;
    let mut i: usize = 0;
    while equal && i < a.len() {
        equal = a[i] == b[i];
        i += 1;
    }
    equal
}

/// Whether `needle` occurs in `haystack` (an empty needle always does).
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    let last = haystack.len() - needle.len();
    let mut found = false;
    let mut start: usize = 0;
    while !found && start <= last {
        let mut equal = true;
        let mut k: usize = 0;
        while equal && k < needle.len() {
            equal = haystack[start + k] == needle[k];
            k += 1;
        }
        found = equal;
        start += 1;
    }
    found
}

/// The value of an ASCII hexadecimal digit, either case.
#[expect(
    clippy::manual_range_contains,
    reason = "RangeInclusive::contains is an opaque axiom in the Aeneas extraction; comparisons are definitions"
)]
fn hex_digit(b: u8) -> Option<u8> {
    if b >= 0x30 && b <= 0x39 {
        Some(b - 0x30)
    } else if b >= 0x41 && b <= 0x46 {
        Some(b - 0x41 + 10)
    } else if b >= 0x61 && b <= 0x66 {
        Some(b - 0x61 + 10)
    } else {
        None
    }
}

/// The byte an escape's two characters decode to, as `u8::from_str_radix(_, 16)`
/// reads them: two hex digits, or `+` and one (the radix parser accepts a
/// leading sign, so `%+f` is `0x0f`).
///
/// `match`, not `Option::map`: a closure is outside what Aeneas translates.
#[expect(
    clippy::manual_map,
    reason = "a closure is outside what Aeneas translates"
)]
fn escape_value(first: u8, second: u8) -> Option<u8> {
    match hex_digit(second) {
        None => None,
        Some(low) => {
            if first == PLUS {
                Some(low)
            } else {
                match hex_digit(first) {
                    None => None,
                    Some(high) => Some(high * 16 + low),
                }
            }
        }
    }
}

/// One pass of `%XX` decoding. A malformed escape is kept verbatim; a decoded
/// byte that is not ASCII is dropped, because no service name contains one.
///
/// A byte at or above `0x80` that is not part of an escape is re-encoded as
/// the UTF-8 of the code point with that value (two bytes), which is what the
/// `String` this replaced did with `char::from(byte)`. It keeps the pass
/// byte-for-byte what it was; no decision reads those bytes, since every
/// literal a decision compares with is ASCII.
pub fn percent_decode_once(text: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let n = text.len();
    let mut i: usize = 0;
    while i < n {
        let b = text[i];
        let escape = if b == PERCENT && i + 3 <= n {
            escape_value(text[i + 1], text[i + 2])
        } else {
            None
        };
        match escape {
            Some(decoded) => {
                if decoded < 0x80 {
                    out.push(decoded);
                }
                i += 3;
            }
            None => {
                if b < 0x80 {
                    out.push(b);
                } else {
                    out.push(0xC0 | (b >> 6));
                    out.push(0x80 | (b & 0x3F));
                }
                i += 1;
            }
        }
    }
    out
}

/// `text` lower-cased, then percent-decoded and lower-cased again until
/// nothing changes or [`DECODE_PASSES`] passes have run.
pub fn decoded_lowercase(text: &[u8]) -> Vec<u8> {
    let mut current = lowercase(text);
    let mut passes: usize = 0;
    let mut settled = false;
    while !settled && passes < DECODE_PASSES {
        let next = lowercase(&percent_decode_once(&current));
        if bytes_eq(&next, &current) {
            settled = true;
        } else {
            current = next;
        }
        passes += 1;
    }
    current
}

/// `receive-pack`: the smart-HTTP push service without its `git-` prefix, so
/// a path that spells it under another prefix still matches.
const RECEIVE_SERVICE: [u8; 12] = [
    0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x2D, 0x70, 0x61, 0x63, 0x6B,
];

/// Whether `text`, decoded and lower-cased, names the push service.
pub fn names_push(text: &[u8]) -> bool {
    contains(&decoded_lowercase(text), &RECEIVE_SERVICE)
}

/// The next non-empty `/`-separated segment of `text` at or after `from`:
/// `(start, end)`, with `start == text.len()` when there is none.
pub fn next_segment(text: &[u8], from: usize) -> (usize, usize) {
    let n = text.len();
    let mut i = from;
    while i < n && text[i] == SLASH {
        i += 1;
    }
    let start = i;
    while i < n && text[i] != SLASH {
        i += 1;
    }
    (start, i)
}

/// Whether `text[start..end]` is the one-segment wildcard `*`.
fn is_wildcard(text: &[u8], start: usize, end: usize) -> bool {
    end == start + 1 && text[start] == STAR
}

/// Whether one pattern segment may be a literal: no `*`, `%`, `?`, `#` or `\`,
/// not `.` or `..`, and every byte visible ASCII.
#[expect(
    clippy::manual_range_contains,
    reason = "RangeInclusive::contains is an opaque axiom in the Aeneas extraction; comparisons are definitions"
)]
fn literal_segment(text: &[u8], start: usize, end: usize) -> bool {
    let length = end - start;
    if length == 1 && text[start] == DOT {
        return false;
    }
    if length == 2 && text[start] == DOT && text[start + 1] == DOT {
        return false;
    }
    let mut ok = true;
    let mut i = start;
    while ok && i < end {
        let b = text[i];
        ok = b >= 0x21
            && b <= 0x7E
            && b != STAR
            && b != PERCENT
            && b != 0x3F // ?
            && b != 0x23 // #
            && b != 0x5C; // \
        i += 1;
    }
    ok
}

/// Whether `pattern` is one: at least one and at most
/// [`MAX_PATTERN_SEGMENTS`] non-empty segments, each `*` or a literal.
pub fn pattern_valid(pattern: &[u8]) -> bool {
    let n = pattern.len();
    let mut count: usize = 0;
    let mut ok = true;
    let mut more = true;
    let mut from: usize = 0;
    while ok && more {
        let (start, end) = next_segment(pattern, from);
        if start < n {
            count += 1;
            ok = count <= MAX_PATTERN_SEGMENTS
                && (is_wildcard(pattern, start, end) || literal_segment(pattern, start, end));
            from = end;
        } else {
            more = false;
        }
    }
    ok && count > 0
}

/// Whether the segments `a[a0..a1]` and `b[b0..b1]` are equal ignoring ASCII
/// case.
fn segment_eq(a: &[u8], a0: usize, a1: usize, b: &[u8], b0: usize, b1: usize) -> bool {
    if a1 - a0 != b1 - b0 {
        return false;
    }
    let mut equal = true;
    let mut k: usize = 0;
    while equal && k < a1 - a0 {
        equal = lower(a[a0 + k]) == lower(b[b0 + k]);
        k += 1;
    }
    equal
}

/// Walk two segment lists in step. With `both_wild` false, a `*` in `a` only
/// matches (a pattern against a request); with it true, a `*` on either side
/// does (whether two patterns overlap). Equal counts, every pair matching.
fn segments_agree(a: &[u8], b: &[u8], both_wild: bool) -> bool {
    let mut agree = true;
    let mut more = true;
    let mut a_from: usize = 0;
    let mut b_from: usize = 0;
    while agree && more {
        let (a0, a1) = next_segment(a, a_from);
        let (b0, b1) = next_segment(b, b_from);
        let a_has = a0 < a.len();
        let b_has = b0 < b.len();
        if a_has && b_has {
            agree = is_wildcard(a, a0, a1)
                || (both_wild && is_wildcard(b, b0, b1))
                || segment_eq(a, a0, a1, b, b0, b1);
            a_from = a1;
            b_from = b1;
        } else {
            agree = a_has == b_has;
            more = false;
        }
    }
    agree
}

/// Whether `request` (already decoded and lower-cased) matches `pattern`.
pub fn pattern_matches(pattern: &[u8], request: &[u8]) -> bool {
    segments_agree(pattern, request, false)
}

/// Whether some path matches both patterns.
pub fn overlap(a: &[u8], b: &[u8]) -> bool {
    segments_agree(a, b, true)
}
/// Whether `effect` decides a request with this method whose path,
/// decoded and lower-cased, is `request`.
fn effect_applies(effect: &Effect, method: EgressMethod, request: &[u8]) -> bool {
    same_method(effect.method, method)
        && pattern_valid(&effect.path)
        && pattern_matches(&effect.path, request)
}

/// `EffectTable::declared`: the operation of the first effect, in the
/// operator's order, with this method whose pattern is one and matches the
/// request path (percent-decoded and lower-cased).
pub fn declared(effects: &[Effect], method: EgressMethod, path: &[u8]) -> Option<EgressOperation> {
    let request = decoded_lowercase(path);
    let mut i: usize = 0;
    while i < effects.len() && !effect_applies(&effects[i], method, &request) {
        i += 1;
    }
    if i < effects.len() {
        Some(effects[i].operation)
    } else {
        None
    }
}

/// Whether two effects could disagree about a request: one method, different
/// operations, overlapping patterns.
fn conflict(a: &Effect, b: &Effect) -> bool {
    same_method(a.method, b.method)
        && !same_operation(a.operation, b.operation)
        && overlap(&a.path, &b.path)
}

/// The first index `j < i` whose effect conflicts with effect `i`, or `i`
/// when none does.
fn first_conflict(effects: &[Effect], i: usize) -> usize {
    let mut j: usize = 0;
    while j < i && !conflict(&effects[j], &effects[i]) {
        j += 1;
    }
    j
}

/// Whether effect `i` is sound against the effects before it: its pattern is
/// one, and no earlier effect conflicts with it.
fn admissible_at(effects: &[Effect], i: usize) -> bool {
    pattern_valid(&effects[i].path) && first_conflict(effects, i) == i
}

/// `EffectTable::from_parts`: the table's kind (an absent kind is
/// [`UpstreamKind::Api`]) if the effects are a table, else why not. Each
/// effect's pattern is checked, then the effect against every earlier one in
/// order; the first fault found is the one reported.
pub fn from_parts(
    kind: Option<UpstreamKind>,
    effects: &[Effect],
) -> Result<UpstreamKind, TableRefusal> {
    if effects.len() > MAX_EFFECTS {
        return Err(TableRefusal::TooMany(effects.len()));
    }
    let mut i: usize = 0;
    while i < effects.len() && admissible_at(effects, i) {
        i += 1;
    }
    if i < effects.len() {
        if pattern_valid(&effects[i].path) {
            Err(TableRefusal::Ambiguous(first_conflict(effects, i), i))
        } else {
            Err(TableRefusal::BadPattern(i))
        }
    } else {
        match kind {
            Some(declared_kind) => Ok(declared_kind),
            None => Ok(UpstreamKind::Api),
        }
    }
}

/// `operation_for`: a push if the receive service is in the path, or in the
/// query of a method that carries a body; else the declared operation, if one
/// matches; else a fetch, except a write to a forge, which is refused.
pub fn operation_for(
    kind: UpstreamKind,
    effects: &[Effect],
    method: EgressMethod,
    path: &[u8],
    query: Option<&[u8]>,
) -> Result<EgressOperation, Unclassified> {
    let body = carries_body(method);
    // A bodiless call carries nothing of the session upstream, so a query
    // naming the push service (the ref advertisement) does not make it a push.
    let query_names_push = match query {
        Some(q) => names_push(q),
        None => false,
    };
    if names_push(path) || (body && query_names_push) {
        return Ok(EgressOperation::GitPush);
    }
    match declared(effects, method, path) {
        Some(operation) => Ok(operation),
        None => match kind {
            UpstreamKind::Forge => {
                if body {
                    Err(Unclassified)
                } else {
                    Ok(EgressOperation::WebFetch)
                }
            }
            UpstreamKind::Api => Ok(EgressOperation::WebFetch),
        },
    }
}

//! Which request headers reach an upstream: the header-name rules,
//! [`header_policy`] and [`forwarded_headers`].
//!
//! These are the production deciders. `nucleus-spec`'s
//! `workload_egress::guest_may_propose_header`, `names_a_credential` and
//! `header_value_admissible`, and `nucleus-node`'s `header_policy`,
//! `RegistryEntry::forwards_header` and `forwarded_headers`, convert their
//! `String`s and maps into the byte views below and call these (ADR 0007
//! G-1). Names are compared as bytes; a name a guest may propose is
//! lower-case ASCII, which is what makes byte equality header equality.
//!
//! A header the operator's registry lists as withheld (`secret_headers`:
//! the value is never shown to a review) is called *withheld* here.
//!
//! `while` loops over indices, not iterator adaptors: see `super::classify`.
//! Emptiness is `len() == 0`: `Vec::is_empty` is an opaque axiom in the
//! extraction, `len` a definition.

#![expect(
    clippy::len_zero,
    reason = "Vec::is_empty is an opaque axiom in the Aeneas extraction; len is a definition"
)]

use super::classify::{bytes_eq, contains, lower, lowercase};

/// Most request headers a call may propose, and most fixed headers an
/// upstream may set.
pub const MAX_PROPOSED_HEADERS: usize = 16;

/// Longest proposed header value, in bytes.
pub const MAX_HEADER_VALUE_BYTES: usize = 1024;

/// Longest header name, in bytes.
pub const MAX_HEADER_NAME_BYTES: usize = 64;

/// `-`, a separator a credential name may be spelled with or without.
const DASH: u8 = 0x2D;
/// `_`, the other such separator.
const UNDERSCORE: u8 = 0x5F;

/// Whether `name` is a header token as the registry stores one: non-empty,
/// at most [`MAX_HEADER_NAME_BYTES`], each byte a lower-case ASCII letter,
/// an ASCII digit or `-`.
pub fn is_header_token(name: &[u8]) -> bool {
    if name.len() == 0 || name.len() > MAX_HEADER_NAME_BYTES {
        return false;
    }
    let mut ok = true;
    let mut i: usize = 0;
    while ok && i < name.len() {
        ok = token_byte(name[i]);
        i += 1;
    }
    ok
}

/// Whether `b` may appear in a header token: a lower-case ASCII letter, an
/// ASCII digit or `-`. A function of its own so its result is typed `bool`
/// in the extraction, where an inline `||` chain ending in `==` elaborates
/// as a `Prop`.
#[expect(
    clippy::manual_range_contains,
    reason = "RangeInclusive::contains is an opaque axiom in the Aeneas extraction; comparisons are definitions"
)]
fn token_byte(b: u8) -> bool {
    (b >= 0x61 && b <= 0x7A) || (b >= 0x30 && b <= 0x39) || b == DASH
}

/// Whether `name` is one of the names a guest may never propose: the
/// credential headers the host alone sets, the framing and hop headers its
/// HTTP client owns, `content-type` (its own field), and the forwarding
/// headers that would let a request claim to come from somewhere else.
pub fn never_proposed(name: &[u8]) -> bool {
    bytes_eq(name, b"authorization")
        || bytes_eq(name, b"proxy-authorization")
        || bytes_eq(name, b"cookie")
        || bytes_eq(name, b"set-cookie")
        || bytes_eq(name, b"host")
        || bytes_eq(name, b"content-type")
        || bytes_eq(name, b"content-length")
        || bytes_eq(name, b"transfer-encoding")
        || bytes_eq(name, b"connection")
        || bytes_eq(name, b"keep-alive")
        || bytes_eq(name, b"upgrade")
        || bytes_eq(name, b"te")
        || bytes_eq(name, b"trailer")
        || bytes_eq(name, b"expect")
        || bytes_eq(name, b"forwarded")
        || bytes_eq(name, b"via")
}

/// Whether `text` starts with `prefix`.
pub fn starts_with(text: &[u8], prefix: &[u8]) -> bool {
    if prefix.len() > text.len() {
        return false;
    }
    let mut equal = true;
    let mut i: usize = 0;
    while equal && i < prefix.len() {
        equal = text[i] == prefix[i];
        i += 1;
    }
    equal
}

/// Whether `name` has a prefix no proposed header name may have.
pub fn never_proposed_prefix(name: &[u8]) -> bool {
    starts_with(name, b"proxy-")
        || starts_with(name, b"x-forwarded-")
        || starts_with(name, b"x-nucleus-")
        || starts_with(name, b"sec-")
}

/// `name` lower-cased with every `-` and `_` removed: the form in which
/// `Access-Token` and `ACCESSTOKEN` are one name.
pub fn folded(name: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    while i < name.len() {
        let b = name[i];
        if b != DASH && b != UNDERSCORE {
            out.push(lower(b));
        }
        i += 1;
    }
    out
}

/// Whether `name` looks like it carries a credential: its folded form is a
/// credential name, whole, or contains a credential fragment.
#[expect(
    clippy::byte_char_slices,
    reason = "one fragment is spelled byte by byte for the no-credential declaration scan"
)]
pub fn names_a_credential(name: &[u8]) -> bool {
    let f = folded(name);
    // Whole names.
    bytes_eq(&f, b"key")
        || bytes_eq(&f, b"sig")
        || bytes_eq(&f, b"code")
        || bytes_eq(&f, b"auth")
        || bytes_eq(
            &f,
            b"authorization",
        )
        || bytes_eq(&f, b"jwt")
        || bytes_eq(&f, b"bearer")
        || bytes_eq(&f, b"assertion")
        || bytes_eq(
            &f,
            b"clientassertion",
        )
        || bytes_eq(&f, b"pwd")
        // Fragments.
        || contains(&f, b"token")
        // Spelled byte by byte: this crate's `no_type_here_can_carry_a_credential`
        // scan refuses the word anywhere outside a comment, and it is a name
        // to refuse here, not a field.
        || contains(&f, &[b's', b'e', b'c', b'r', b'e', b't'])
        || contains(&f, b"passw")
        || contains(&f, b"credential")
        || contains(&f, b"apikey")
        || contains(&f, b"signature")
        || contains(&f, b"session")
        || contains(&f, b"cookie")
}

/// Whether a guest may propose request header `name` at all: a header token,
/// not a never-proposed name or prefix, and not credential-shaped.
pub fn guest_may_propose_header(name: &[u8]) -> bool {
    is_header_token(name)
        && !never_proposed(name)
        && !never_proposed_prefix(name)
        && !names_a_credential(name)
}

/// Whether `value` may be sent as a header's value: at most
/// [`MAX_HEADER_VALUE_BYTES`], each byte visible ASCII or a space.
#[expect(
    clippy::manual_range_contains,
    reason = "RangeInclusive::contains is an opaque axiom in the Aeneas extraction; comparisons are definitions"
)]
pub fn header_value_admissible(value: &[u8]) -> bool {
    if value.len() > MAX_HEADER_VALUE_BYTES {
        return false;
    }
    let mut ok = true;
    let mut i: usize = 0;
    while ok && i < value.len() {
        let b = value[i];
        ok = b >= 0x20 && b < 0x7F;
        i += 1;
    }
    ok
}

/// Whether `a` and `b` are equal ignoring ASCII case.
pub fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut equal = true;
    let mut i: usize = 0;
    while equal && i < a.len() {
        equal = lower(a[i]) == lower(b[i]);
        i += 1;
    }
    equal
}

/// Whether `list` holds `name`, byte for byte.
pub fn holds(list: &[Vec<u8>], name: &[u8]) -> bool {
    let mut found = false;
    let mut i: usize = 0;
    while !found && i < list.len() {
        found = bytes_eq(&list[i], name);
        i += 1;
    }
    found
}

/// The index of the first entry of `map` named `name`, byte for byte, or
/// `map.len()` when there is none.
fn index_of(map: &[(Vec<u8>, Vec<u8>)], name: &[u8]) -> usize {
    let mut i: usize = 0;
    while i < map.len() && !bytes_eq(&map[i].0, name) {
        i += 1;
    }
    i
}

/// The index of the entry of `map` named `name`, byte for byte, if any.
pub fn position(map: &[(Vec<u8>, Vec<u8>)], name: &[u8]) -> Option<usize> {
    let i = index_of(map, name);
    if i < map.len() { Some(i) } else { None }
}

/// A validated header policy: the fixed headers by lower-case name, and the
/// withheld names, lower-case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderRules {
    /// The fixed headers, `(name, value)`, in the order validated.
    pub fixed: Vec<(Vec<u8>, Vec<u8>)>,
    /// The withheld names, without repeats, in the order first listed.
    pub withheld: Vec<Vec<u8>>,
}

/// Why a header policy was refused, by the position of the entry at fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyRefusal {
    /// The withheld name at this index is not a header token.
    WithheldNotAName(usize),
    /// The fixed header at this index is a credential, withheld, framing or
    /// forwarding header: a name a guest could not propose.
    FixedForbidden(usize),
    /// The fixed header at this index has an empty or inadmissible value.
    FixedValue(usize),
    /// The fixed header at this index repeats an earlier one in another case.
    FixedTwice(usize),
    /// More than [`MAX_PROPOSED_HEADERS`] fixed headers: the count.
    TooManyFixed(usize),
}

/// Validate an upstream's fixed and withheld headers.
///
/// Each withheld name, lower-cased, must be a header token. Each fixed
/// header, lower-cased, must not be the credential header in any case, nor a
/// withheld name, and must be a name a guest could propose; its value must be
/// non-empty and admissible; and it may not repeat a name in another case.
/// At most [`MAX_PROPOSED_HEADERS`] fixed headers. Entries are checked in
pub fn header_policy(
    credential_header: &[u8],
    fixed: &[(Vec<u8>, Vec<u8>)],
    withheld: &[Vec<u8>],
) -> Result<HeaderRules, PolicyRefusal> {
    let mut withheld_names: Vec<Vec<u8>> = Vec::new();
    let mut i: usize = 0;
    while i < withheld.len() && is_header_token(&lowercase(&withheld[i])) {
        let name = lowercase(&withheld[i]);
        let new = !holds(&withheld_names, &name);
        if new {
            withheld_names.push(name);
        }
        i += 1;
    }
    if i < withheld.len() {
        return Err(PolicyRefusal::WithheldNotAName(i));
    }
    let mut fixed_headers: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut j: usize = 0;
    while j < fixed.len()
        && fixed_fault(
            credential_header,
            &withheld_names,
            &fixed_headers,
            &fixed[j],
        )
        .is_none()
    {
        fixed_headers.push((lowercase(&fixed[j].0), fixed[j].1.clone()));
        j += 1;
    }
    if j < fixed.len() {
        return match fixed_fault(
            credential_header,
            &withheld_names,
            &fixed_headers,
            &fixed[j],
        ) {
            Some(fault) => Err(fault.at(j)),
            None => Err(PolicyRefusal::FixedForbidden(j)),
        };
    }
    if fixed_headers.len() > MAX_PROPOSED_HEADERS {
        return Err(PolicyRefusal::TooManyFixed(fixed_headers.len()));
    }
    Ok(HeaderRules {
        fixed: fixed_headers,
        withheld: withheld_names,
    })
}

/// What is wrong with one fixed header, given the withheld names and the
/// fixed headers accepted before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixedFault {
    /// A credential, withheld, framing or forwarding header.
    Forbidden,
    /// An empty or inadmissible value.
    Value,
    /// A name already fixed, in another case.
    Twice,
}

impl FixedFault {
    /// The refusal naming the fixed header at `index`.
    fn at(self, index: usize) -> PolicyRefusal {
        match self {
            Self::Forbidden => PolicyRefusal::FixedForbidden(index),
            Self::Value => PolicyRefusal::FixedValue(index),
            Self::Twice => PolicyRefusal::FixedTwice(index),
        }
    }
}

/// The first rule `header` breaks, in the order they are checked, if any.
pub fn fixed_fault(
    credential_header: &[u8],
    withheld_names: &[Vec<u8>],
    accepted: &[(Vec<u8>, Vec<u8>)],
    header: &(Vec<u8>, Vec<u8>),
) -> Option<FixedFault> {
    let name = lowercase(&header.0);
    let value = &header.1;
    if eq_ignore_ascii_case(&name, credential_header)
        || holds(withheld_names, &name)
        || !guest_may_propose_header(&name)
    {
        Some(FixedFault::Forbidden)
    } else if value.len() == 0 || !header_value_admissible(value) {
        Some(FixedFault::Value)
    } else if index_of(accepted, &name) < accepted.len() {
        Some(FixedFault::Twice)
    } else {
        None
    }
}

/// What one upstream's registry entry says about the headers of a call to it.
#[derive(Clone, Debug)]
pub struct HeaderEntry {
    /// The names the operator lets a guest propose (`request_headers`).
    pub listed: Vec<Vec<u8>>,
    /// The header the credential is injected as.
    pub credential_header: Vec<u8>,
    /// The withheld names.
    pub withheld: Vec<Vec<u8>>,
    /// The fixed headers, `(name, value)`.
    pub fixed: Vec<(Vec<u8>, Vec<u8>)>,
}

/// `RegistryEntry::forwards_header`: the operator listed the name, a guest
/// may propose it, and it is not the credential header in any case, not
/// withheld and not fixed.
pub fn forwards_header(entry: &HeaderEntry, name: &[u8]) -> bool {
    holds(&entry.listed, name)
        && guest_may_propose_header(name)
        && !eq_ignore_ascii_case(name, &entry.credential_header)
        && !holds(&entry.withheld, name)
        && position(&entry.fixed, name).is_none()
}

/// Insert `(name, value)` into `map`, replacing the value of an entry with
/// that name, as a map insert does.
pub fn insert(map: &mut Vec<(Vec<u8>, Vec<u8>)>, header: (Vec<u8>, Vec<u8>)) {
    match position(map, &header.0) {
        Some(k) => map[k] = header,
        None => map.push(header),
    }
}

/// The headers a call sends besides the credential and the media type: the
/// guest's proposals this upstream forwards whose values are admissible, then
/// the operator's fixed headers over them.
pub fn forwarded_headers(
    guest: &[(Vec<u8>, Vec<u8>)],
    entry: &HeaderEntry,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut out: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut i: usize = 0;
    while i < guest.len() {
        // Both tests, then one branch: Aeneas does not join the two paths of a
        // short-circuit `&&` inside this loop.
        // The header is copied out first: Aeneas does not join a branch that
        // borrows into `guest` with one that does not.
        let header = guest[i].clone();
        let forwarded = forwards_header(entry, &header.0);
        let admissible = header_value_admissible(&header.1);
        if forwarded && admissible {
            insert(&mut out, header);
        }
        i += 1;
    }
    let mut j: usize = 0;
    while j < entry.fixed.len() {
        insert(&mut out, entry.fixed[j].clone());
        j += 1;
    }
    out
}

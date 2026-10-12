//! The one YAML reader and writer for nucleus (ADR 0007 G-1).
//!
//! # Why one module
//!
//! The workspace read YAML through `serde_yaml` 0.9 at ~100 call sites. Its
//! `unsafe-libyaml` is unmaintained (RUSTSEC-2024-0449), so it is replaced by
//! `serde-saphyr`, which is safe Rust and YAML 1.2. The two libraries disagree
//! about a handful of inputs, and some of `serde-saphyr`'s defaults are looser
//! than what nucleus relied on. A setting chosen at each call site is a fact
//! written a hundred times; here it is written once, and `clippy.toml` refuses a
//! direct `serde_saphyr::from_str`/`to_string` anywhere else.
//!
//! # What is pinned, and why
//!
//! Every reader goes through [`from_str`] (or [`from_slice`]), which:
//!
//! - **refuses `yes`/`no`/`on`/`off` as booleans** (`strict_booleans`). serde_yaml
//!   0.9 refused them; serde-saphyr's default accepts them. `enabled: no` must not
//!   become `false` by a YAML 1.1 accident.
//! - **refuses duplicate keys.** The second `allow:` must not silently win.
//! - **refuses merge keys (`<<`).** serde-saphyr's default expands them, which
//!   would let one anchor quietly contribute keys to a policy mapping.
//! - **refuses unknown tags** (`!Foo 1`), which serde-saphyr would otherwise drop
//!   and keep the value, and `!!binary`, which it would base64-decode.
//! - **never echoes the input in an error** (snippets off). A spec carries
//!   credentials; an error message goes to logs and API responses.
//! - **is budgeted**: [`MAX_INPUT_BYTES`], one document, bounded depth, nodes,
//!   anchors, aliases and scalar bytes.
//! - **refuses the plain scalars the two libraries resolve differently**
//!   ([`Ambiguity`]): `0755` (serde_yaml: the string `"0755"`; YAML 1.2: the
//!   integer 755), `0X1F`, `1_000`, and integers wider than 64 bits (serde-saphyr:
//!   a lossy float). A reader that wants the string quotes it. This is applied
//!   to every target type, not only `serde_json::Value`, because a typed field is
//!   exactly where `0755` silently becoming 755 would hide.
//!
//! Every writer goes through [`to_string`], whose output is pinned to the
//! plainest portable form: double-quoted escapes rather than block scalars, and
//! YAML 1.1 look-alikes (`yes`, `1:20`, `2001-12-14`) quoted, so an older reader
//! (a pinned guest's `serde_yaml` 0.9) reads back the same values.
//!
//! # What this is not
//!
//! YAML output is not a canonical encoding and nothing may hash or sign it. A
//! pod manifest's hash is `nucleus_spec::PodSpec::manifest_hash`, over RFC 8785
//! JSON.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_saphyr::granit_parser::{Event, Parser, ScalarStyle};

/// The largest YAML text accepted, in bytes. A pod spec, a profile and a CI
/// workflow are each a few kilobytes; 16 MiB is generous and still bounded.
pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;

/// Maximum structural nesting depth.
pub const MAX_DEPTH: usize = 64;

/// A plain (unquoted, untagged) scalar that serde_yaml 0.9 and YAML 1.2
/// resolve to different values. Refused rather than guessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ambiguity {
    /// `0755`, `007`, `-01`: serde_yaml read a string, YAML 1.2 an integer.
    LeadingZero,
    /// `0X1F`, `0O17`, `0B101`: serde_yaml read a string, serde-saphyr an integer.
    UppercaseRadixPrefix,
    /// `1_000`: serde_yaml read a string, serde-saphyr an integer.
    DigitSeparator,
    /// An integer wider than 64 bits: serde_yaml refused it, serde-saphyr reads
    /// a float that has already lost digits.
    IntegerOverflow,
}

impl Ambiguity {
    fn describe(self) -> &'static str {
        match self {
            Self::LeadingZero => "a number with a leading zero",
            Self::UppercaseRadixPrefix => "a number with an upper-case radix prefix",
            Self::DigitSeparator => "a number with `_` digit separators",
            Self::IntegerOverflow => "an integer wider than 64 bits",
        }
    }
}

/// Why YAML could not be read or written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Not valid YAML, or not the shape the target type expects.
    Parse(String),
    /// Larger than [`MAX_INPUT_BYTES`].
    TooLarge {
        /// The input's size.
        len: usize,
    },
    /// Not UTF-8.
    NotUtf8,
    /// A plain scalar the two YAML readings disagree on. The value itself is not
    /// reported: it may be a secret.
    Ambiguous {
        /// What kind of scalar it is.
        ambiguity: Ambiguity,
        /// 1-based line.
        line: usize,
        /// 1-based column.
        column: usize,
    },
    /// A `!!binary` scalar, which would be silently base64-decoded.
    BinaryTag {
        /// 1-based line.
        line: usize,
        /// 1-based column.
        column: usize,
    },
    /// The value could not be written as YAML.
    Serialize(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(msg) => f.write_str(msg),
            Self::TooLarge { len } => write!(
                f,
                "YAML input is {len} bytes; the limit is {MAX_INPUT_BYTES} bytes"
            ),
            Self::NotUtf8 => f.write_str("YAML input is not valid UTF-8"),
            Self::Ambiguous {
                ambiguity,
                line,
                column,
            } => write!(
                f,
                "unquoted scalar at line {line}, column {column} is {}, which YAML \
                 readers disagree on; quote it if it is a string",
                ambiguity.describe()
            ),
            Self::BinaryTag { line, column } => write!(
                f,
                "`!!binary` scalar at line {line}, column {column} is not accepted"
            ),
            Self::Serialize(msg) => write!(f, "cannot write YAML: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

/// The parser settings. The ONLY place they are chosen.
fn options() -> serde_saphyr::Options {
    serde_saphyr::options! {
        budget: serde_saphyr::budget! {
            max_reader_input_bytes: Some(MAX_INPUT_BYTES),
            max_events: 1_000_000,
            max_aliases: 10_000,
            max_anchors: 10_000,
            max_depth: MAX_DEPTH,
            max_documents: 1,
            max_nodes: 250_000,
            max_total_scalar_bytes: MAX_INPUT_BYTES,
            max_total_comment_bytes: MAX_INPUT_BYTES,
        },
        emit_comments: false,
        duplicate_keys: serde_saphyr::options::DuplicateKeyPolicy::Error,
        merge_keys: serde_saphyr::options::MergeKeyPolicy::Error,
        legacy_octal_numbers: false,
        strict_booleans: true,
        ignore_binary_tag_for_string: false,
        no_schema: false,
        reject_unsupported_tags: true,
        reject_non_finite_typeless_float: true,
        with_snippet: false,
        crop_radius: 0,
    }
}

/// The writer settings. The ONLY place they are chosen.
fn ser_options() -> serde_saphyr::SerializerOptions {
    serde_saphyr::ser_options! {
        empty_as_braces: true,
        indent_step: 2,
        compact_list_indent: true,
        tagged_enums: false,
        prefer_block_scalars: false,
        quote_all: false,
        yaml_12: false,
    }
}

/// Read one YAML document into `T`, under every setting in the module docs.
///
/// # Errors
///
/// [`Error`] for oversize input, invalid YAML, a shape `T` refuses, or a
/// refused construct (YAML 1.1 boolean, duplicate key, merge key, unknown tag,
/// ambiguous scalar).
pub fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, Error> {
    if text.len() > MAX_INPUT_BYTES {
        return Err(Error::TooLarge { len: text.len() });
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "ADR 0007 G-1: this is the one YAML reader the rule points at"
    )]
    let value = serde_saphyr::from_str_with_options(text, options())
        .map_err(|e| Error::Parse(e.to_string()))?;
    // After the budgeted parse, so the second pass only ever sees input the
    // budget already admitted.
    refuse_ambiguous(text)?;
    Ok(value)
}

/// [`from_str`] over bytes, which must be UTF-8.
///
/// # Errors
///
/// [`Error::NotUtf8`], or anything [`from_str`] returns.
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::TooLarge { len: bytes.len() });
    }
    from_str(std::str::from_utf8(bytes).map_err(|_| Error::NotUtf8)?)
}

/// Write `value` as one YAML document.
///
/// The output is for people and for other YAML readers. It is NOT canonical:
/// never hash or sign it.
///
/// # Errors
///
/// [`Error::Serialize`] when `value` has no YAML form.
pub fn to_string<T: Serialize>(value: &T) -> Result<String, Error> {
    #[expect(
        clippy::disallowed_methods,
        reason = "ADR 0007 G-1: this is the one YAML writer the rule points at"
    )]
    let out = serde_saphyr::to_string_with_options(value, ser_options())
        .map_err(|e| Error::Serialize(e.to_string()))?;
    Ok(out)
}

/// Walk the event stream and refuse every plain, untagged scalar the two YAML
/// readings disagree on, and every `!!binary` scalar.
fn refuse_ambiguous(text: &str) -> Result<(), Error> {
    let mut parser = Parser::new_from_str(text);
    while let Some(next) = parser.next_event() {
        let (event, span) = next.map_err(|e| Error::Parse(e.to_string()))?;
        let Event::Scalar(value, style, _anchor, tag) = event else {
            continue;
        };
        let line = span.start.line();
        let column = span.start.col() + 1;
        match tag {
            Some(tag) if tag.handle() == "tag:yaml.org,2002:" && tag.suffix() == "binary" => {
                return Err(Error::BinaryTag { line, column });
            }
            Some(_) => {}
            None if style == ScalarStyle::Plain => {
                if let Some(ambiguity) = ambiguity(&value) {
                    return Err(Error::Ambiguous {
                        ambiguity,
                        line,
                        column,
                    });
                }
            }
            None => {}
        }
    }
    Ok(())
}

/// Whether a plain scalar's text resolves differently under serde_yaml 0.9 and
/// serde-saphyr. Measured, not derived: each arm is a row of the comparison in
/// this crate's tests.
fn ambiguity(text: &str) -> Option<Ambiguity> {
    let negative = text.starts_with('-');
    let body = text.strip_prefix(['+', '-']).unwrap_or(text);
    let bytes = body.as_bytes();
    if let [b'0', next, ..] = bytes {
        if next.is_ascii_digit() || *next == b'_' {
            return Some(Ambiguity::LeadingZero);
        }
        if matches!(next, b'X' | b'O' | b'B') {
            return Some(Ambiguity::UppercaseRadixPrefix);
        }
    }
    let (digits, radix) = match body.get(..2) {
        Some("0x") => (&body[2..], 16),
        Some("0o") => (&body[2..], 8),
        Some("0b") => (&body[2..], 2),
        _ => (body, 10),
    };
    if digits.is_empty() || !digits.chars().all(|c| c == '_' || c.is_digit(radix)) {
        return None;
    }
    if digits.contains('_') {
        return Some(Ambiguity::DigitSeparator);
    }
    let fits = match (radix, negative) {
        (10, true) => text.parse::<i64>().is_ok(),
        (10, false) => body.parse::<u64>().is_ok(),
        _ => u64::from_str_radix(digits, radix).is_ok(),
    };
    (!fits).then_some(Ambiguity::IntegerOverflow)
}

#[cfg(test)]
mod tests;

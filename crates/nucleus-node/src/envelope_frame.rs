//! Framing and bounds for CB4A envelopes arriving from the guest.
//!
//! # Everything here is untrusted input
//!
//! A [`TaskRequestEnvelope`](nucleus_cred_broker::TaskRequestEnvelope) is
//! composed **inside the guest**, by the agent the sandbox exists to contain.
//! It is parsed on the host. That makes this the attack surface of the broker,
//! and the bounds below are the whole point of the module.
//!
//! # Why framing is needed at all
//!
//! vsock has **no message boundaries**. A write from the guest can arrive on the
//! host in arbitrarily many chunks, and does so routinely under load, so a
//! reader that assumes one read equals one message is wrong in a way that only
//! shows up in production. Frames are therefore newline-delimited, and
//! [`MAX_FRAME_BYTES`] bounds reassembly so a guest cannot make the host buffer
//! without limit by simply never sending a newline.
//!
//! # The depth bound, and an honest account of what it buys
//!
//! The obvious claim is that deep nesting overflows the parser's stack, since
//! depth is cheap to produce — 4 000 nested arrays fit in 8 KiB. **That claim was
//! measured and is false for this parser.** `serde_json` enforces its own
//! recursion limit and returns an error rather than recursing: measured exactly,
//! it parses depth 127 and refuses 128 and above, without panicking.
//!
//! So [`MAX_JSON_DEPTH`] is NOT preventing a host crash — the parser already
//! prevents it. What it buys is narrower and worth stating precisely:
//!
//! * the bound is **ours and explicit**, not a library default that could change
//!   under us in a dependency bump;
//! * it is far tighter than 128 — a valid envelope is depth 1 — so it rejects
//!   the adversarial shape rather than merely surviving it;
//! * it rejects **before** the parser runs, in a byte loop with no allocation
//!   and no recursion, which is the only kind of pre-check safe to run on input
//!   you do not trust.
//!
//! Defence in depth against a bound that already exists, in other words, not the
//! sole thing standing between a guest and a crashed host.

// Every item here is now LIVE on the launch path — `classify` applies these
// bounds to each frame the broker accepts. Linux clippy with the allow removed
// reports nothing from this file, which is how that was established rather than
// assumed; the previous blanket allow said the opposite.
//
// NON-LINUX ONLY: on macOS the launch path is behind a cfg guard and none of
// this is compiled.
#![cfg_attr(all(not(test), not(target_os = "linux")), allow(dead_code))]

use nucleus_cred_broker::TaskRequestEnvelope;

/// Largest frame the host will reassemble from the guest.
///
/// An envelope is four short strings; 8 KiB is generous. The bound exists so a
/// guest that never sends a newline cannot make the host buffer forever.
pub const MAX_FRAME_BYTES: usize = 8 * 1024;

/// Deepest JSON nesting the host will parse.
///
/// Chosen far below anything that could overflow: a valid envelope is depth 1.
/// The point is not to permit legitimate nesting — there is none — but to reject
/// the adversarial case cheaply.
pub const MAX_JSON_DEPTH: usize = 8;

/// Longest any single envelope field may be.
///
/// `justification` is free text from the guest and is the amplification risk:
/// it is carried into audit records, so an unbounded field is an unbounded log
/// entry. CB4A calls it auditable evidence, which is a reason to keep it, not a
/// reason to let it be any size.
pub const MAX_FIELD_BYTES: usize = 1024;

/// Why a frame was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// Larger than [`MAX_FRAME_BYTES`].
    TooLarge {
        /// Observed size.
        bytes: usize,
    },
    /// Nested deeper than [`MAX_JSON_DEPTH`].
    TooDeep {
        /// Observed depth.
        depth: usize,
    },
    /// Not valid JSON, or not an envelope.
    Malformed,
    /// A field exceeded [`MAX_FIELD_BYTES`].
    FieldTooLong {
        /// Which field.
        field: &'static str,
        /// Observed length.
        bytes: usize,
    },
}

/// Maximum bracket nesting in `raw`, counted without allocating or recursing.
///
/// Deliberately ignores strings: a `{` inside a quoted string is not nesting.
/// Getting that wrong would reject legitimate justifications containing braces,
/// which an agent could easily produce by accident.
pub fn json_depth(raw: &str) -> usize {
    let (mut depth, mut max, mut in_string, mut escaped) = (0usize, 0usize, false, false);
    for b in raw.bytes() {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max {
                    max = depth;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    max
}

/// Parse one frame from the guest, refusing anything outside the bounds.
///
/// Order matters and is deliberate: **size, then depth, then parse**. Each check
/// is cheaper than the one after it and none of them hands unbounded input to
/// the parser. Reordering so the parse ran first would make every bound useless,
/// because the crash happens during parsing.
pub fn check_frame(raw: &str) -> Result<TaskRequestEnvelope, FrameError> {
    if raw.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge { bytes: raw.len() });
    }
    let depth = json_depth(raw);
    if depth > MAX_JSON_DEPTH {
        return Err(FrameError::TooDeep { depth });
    }
    let env: TaskRequestEnvelope = serde_json::from_str(raw).map_err(|_| FrameError::Malformed)?;

    for (field, value) in [
        ("operation", &env.operation),
        ("target", &env.target),
        ("justification", &env.justification),
    ] {
        if value.len() > MAX_FIELD_BYTES {
            return Err(FrameError::FieldTooLong {
                field,
                bytes: value.len(),
            });
        }
    }
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> String {
        serde_json::json!({
            "operation": "WebFetch",
            "target": "api.example.test",
            "justification": "routine"
        })
        .to_string()
    }

    #[test]
    fn a_well_formed_envelope_parses() {
        let env = check_frame(&valid()).expect("valid envelope");
        assert_eq!(env.operation, "WebFetch");
    }

    /// The bound a byte limit cannot provide: 4 000 nested arrays fit well under
    /// MAX_FRAME_BYTES, so size alone would let them through.
    ///
    /// Note what this does NOT show. serde_json refuses depth >= 128 on its own
    /// (measured), so this is not the only thing preventing a crash — it is a
    /// tighter, explicit bound applied before the parser, rather than reliance
    /// on a library default. The module docs say so.
    #[test]
    fn deeply_nested_json_is_refused_before_it_reaches_the_parser() {
        // Sized to fit UNDER the byte bound on purpose. An earlier version used
        // 5000 pairs (10 000 bytes) and was caught by TooLarge instead — it
        // would have passed while testing nothing about depth. The guard
        // assertion below is what caught that.
        let nesting = 4000;
        let bomb = format!("{}{}", "[".repeat(nesting), "]".repeat(nesting));
        assert!(
            bomb.len() < MAX_FRAME_BYTES,
            "this must be under the size bound or it tests TooLarge, not TooDeep — {} bytes",
            bomb.len()
        );
        match check_frame(&bomb) {
            Err(FrameError::TooDeep { depth }) => assert_eq!(depth, nesting),
            other => panic!("a nesting bomb must be refused on depth, got {other:?}"),
        }
    }

    /// An unterminated frame cannot make the host buffer without limit.
    #[test]
    fn an_oversized_frame_is_refused_on_size() {
        let huge = "x".repeat(MAX_FRAME_BYTES + 1);
        assert!(matches!(
            check_frame(&huge),
            Err(FrameError::TooLarge { .. })
        ));
    }

    /// `justification` is free text carried into audit records, so an unbounded
    /// field is an unbounded log entry.
    #[test]
    fn an_overlong_justification_is_refused_by_name() {
        let env = serde_json::json!({
            "operation": "WebFetch",
            "target": "api.example.test",
            "justification": "a".repeat(MAX_FIELD_BYTES + 1)
        })
        .to_string();
        match check_frame(&env) {
            Err(FrameError::FieldTooLong { field, .. }) => assert_eq!(field, "justification"),
            other => panic!("expected a field-length refusal, got {other:?}"),
        }
    }

    /// Braces INSIDE a string are not nesting. Getting this wrong would reject
    /// legitimate justifications an agent could produce by accident.
    #[test]
    fn braces_inside_strings_do_not_count_as_depth() {
        let env = serde_json::json!({
            "operation": "WebFetch",
            "target": "api.example.test",
            "justification": "the code was {{{{ [[[[ nested }}}} ]]]]"
        })
        .to_string();
        assert!(
            check_frame(&env).is_ok(),
            "brackets in a string must not be counted as structural depth"
        );
    }

    /// An escaped quote must not end the string early — otherwise the following
    /// brackets get counted and a legitimate envelope is refused.
    #[test]
    fn an_escaped_quote_does_not_end_the_string() {
        let raw = r#"{"a":"he said \"[[[[\" and left"}"#;
        assert_eq!(
            json_depth(raw),
            1,
            "only the outer object is structural: {raw}"
        );
    }

    /// Garbage is refused, not panicked on.
    #[test]
    fn malformed_json_is_refused() {
        assert_eq!(check_frame("not json at all"), Err(FrameError::Malformed));
        assert_eq!(check_frame(""), Err(FrameError::Malformed));
        assert_eq!(check_frame("{}"), Err(FrameError::Malformed));
    }

    /// Unbalanced closers must not underflow the depth counter.
    #[test]
    fn unbalanced_brackets_do_not_underflow() {
        assert_eq!(json_depth("]]]]]"), 0);
        assert_eq!(json_depth("}}}}{"), 1);
    }
}

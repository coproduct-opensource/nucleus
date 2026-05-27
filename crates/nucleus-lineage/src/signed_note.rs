//! C2SP signed-note wire format primitives (v2.3a).
//!
//! Implements the byte-level shape from
//! <https://github.com/C2SP/C2SP/blob/main/signed-note.md> and
//! <https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md>:
//!
//! - **Signed-note body**: UTF-8 text, each line terminated with
//!   `U+000A`, no other control chars. A blank line separates the
//!   note body from the signature lines.
//! - **Signature line**: `— <key_name> <base64(key_id_4 || sig_bytes)>`
//!   where the em-dash is U+2014 (3-byte UTF-8 `0xE2 0x80 0x94`).
//! - **Key ID**: first 4 bytes of `SHA-256(key_name || 0x0A ||
//!   sig_type_byte || pubkey)`. The signature-type byte is `0x01`
//!   for plain Ed25519 notes and `0x04` for tlog cosignatures.
//!
//! # What this module does
//!
//! 1. Formats nucleus [`SignedTreeHead`]s as C2SP **tlog-checkpoint
//!    body** text (origin/size/base64-root). The producer's primary
//!    Ed25519 signature can then be appended as a signature line so
//!    external witnesses can parse the checkpoint per spec.
//! 2. Parses C2SP signature lines back into raw `(key_id, signature)`
//!    pairs so a [`crate::Cosignature`] returned from a C2SP witness
//!    can verify.
//! 3. Computes the v2.3 key fingerprint for an Ed25519 pubkey.
//!
//! What it does NOT do (left to v2.3b):
//!
//! - HTTP transport for `POST /add-checkpoint`.
//! - The cosignature-specific "header line + timestamp line + body"
//!   prefix format defined by `tlog-cosignature.md` — we cover the
//!   plain-note signature path only in v2.3a.
//!
//! # Dialect targeted (CRIT-2 / #1647)
//!
//! This implementation targets the **Go sumdb dialect** of C2SP
//! `tlog-checkpoint`, as published by [`transparency-dev/formats`]
//! and consumed by the ArmoredWitness / Sigstore Rekor / Omniwitness
//! ecosystem:
//!
//! - 32-byte raw SHA-256 root hash (no algorithm prefix byte)
//! - Standard RFC 4648 base64 (not URL-safe)
//! - Single `\n` line terminator throughout
//!
//! Sigsum-style algorithm-prefixed root encoding is **NOT** supported.
//!
//! Interop with the external ecosystem is pinned by KAT vectors in
//! `tests/c2sp_interop.rs` — most importantly,
//! `kat_spec_signature_verifies_against_spec_pubkey` which
//! cryptographically verifies the spec's published example signature
//! against the spec's published example pubkey over the spec's
//! published example message. If that test breaks, our wire format
//! has diverged from the C2SP ecosystem and federation will fail
//! silently in production.
//!
//! [`transparency-dev/formats`]: https://github.com/transparency-dev/formats/blob/main/log/checkpoint_test.go

use sha2::{Digest, Sha256};
use thiserror::Error;

/// Em-dash separator at the start of every C2SP signature line.
pub const SIG_LINE_PREFIX: &str = "\u{2014} "; // U+2014 + space

/// Ed25519 plain-note signature type. Used for `tlog-checkpoint`
/// signatures by the log itself.
pub const SIG_TYPE_ED25519: u8 = 0x01;

/// Ed25519 tlog-cosignature signature type. Used by external
/// witnesses (per `tlog-cosignature.md`). The signed bytes are NOT
/// the same as for `SIG_TYPE_ED25519`; v2.3a does not yet sign or
/// verify cosignatures-as-signed-notes — see module note.
pub const SIG_TYPE_COSIGNATURE: u8 = 0x04;

/// Errors raised while parsing C2SP signed notes / signature lines.
#[derive(Debug, Error)]
pub enum SignedNoteError {
    #[error("signature line is missing the em-dash prefix")]
    MissingPrefix,
    #[error("signature line is missing a space after the key name")]
    MissingKeyNameSpace,
    #[error("key name in signature line contains forbidden character: {0:?}")]
    InvalidKeyName(String),
    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("signature payload too short ({got} bytes; need at least 4 for key id)")]
    PayloadTooShort { got: usize },
    #[error("signed-note body must end with a newline")]
    BodyNotTerminated,
    #[error("origin line is empty")]
    EmptyOrigin,
    /// **v2.3b CRIT-1 fix.** Origin or key_name contained a control
    /// char / newline / non-printable byte. Producer-controlled
    /// origins that contain `\n` could otherwise inject extra
    /// checkpoint-body lines visible to a third-party C2SP parser
    /// as different (size, root) than the nucleus verifier
    /// reconstructs — a cross-ecosystem split-view via wire-format
    /// ambiguity, not crypto failure.
    #[error("{field} contains a forbidden character (newline/control/non-ASCII): {value:?}")]
    ForbiddenChar { field: &'static str, value: String },
    /// **v2.3b MED-1 fix.** Origin / key_name exceeded its byte cap.
    /// Producer-supplied bounded length prevents pre-POST allocation
    /// DoS in the bundle-build thread.
    #[error("{field} exceeds maximum length: {got} bytes > {max}")]
    TooLong {
        field: &'static str,
        got: usize,
        max: usize,
    },
}

/// Maximum byte length of an `origin` field. C2SP spec doesn't pin a
/// number but real-world origins are <100 bytes; 512 leaves slack for
/// long schema-less URLs while preventing 1 GB pathological payloads
/// from a misconfigured producer.
pub const MAX_ORIGIN_LEN: usize = 512;

/// Maximum byte length of a C2SP `key_name`. ArmoredWitness-style
/// names like `witness.armoredwitness.transparency.dev/aw-1234` are
/// ~50 bytes; 256 leaves headroom.
pub const MAX_KEY_NAME_LEN: usize = 256;

/// Validate a producer-supplied `origin` string before incorporating
/// it into a C2SP checkpoint body. Per `signed-note.md` body must be
/// UTF-8 text with each line terminated by `U+000A` and "no other
/// control chars"; an origin containing `\n`, `\r`, `\0`, or any
/// non-printable byte breaks that invariant and (worse) allows a
/// malicious producer to inject extra lines so a third-party C2SP
/// parser reads a different (size, root) tuple than the nucleus
/// verifier reconstructs.
///
/// Acceptance set: printable ASCII (0x20..=0x7E). Rejects every other
/// byte explicitly so a future encoding-change in the spec doesn't
/// silently widen the surface.
pub fn validate_origin(origin: &str) -> Result<(), SignedNoteError> {
    if origin.is_empty() {
        return Err(SignedNoteError::EmptyOrigin);
    }
    if origin.len() > MAX_ORIGIN_LEN {
        return Err(SignedNoteError::TooLong {
            field: "origin",
            got: origin.len(),
            max: MAX_ORIGIN_LEN,
        });
    }
    if origin.bytes().any(|b| !(0x20..=0x7E).contains(&b)) {
        return Err(SignedNoteError::ForbiddenChar {
            field: "origin",
            value: origin.to_string(),
        });
    }
    Ok(())
}

/// Validate a producer-supplied `key_name` for a C2SP signature line.
/// Per `signed-note.md` §4 the key name is a non-empty string of
/// printable ASCII (0x20..=0x7E), not containing `+`, em-dash, or
/// whitespace (the line uses single ASCII spaces as token separators).
pub fn validate_key_name(key_name: &str) -> Result<(), SignedNoteError> {
    if key_name.is_empty() {
        return Err(SignedNoteError::InvalidKeyName(String::new()));
    }
    if key_name.len() > MAX_KEY_NAME_LEN {
        return Err(SignedNoteError::TooLong {
            field: "key_name",
            got: key_name.len(),
            max: MAX_KEY_NAME_LEN,
        });
    }
    // Spec-forbidden chars: '+' (used as the vkey separator per
    // signed-note.md §3) and em-dash U+2014 (the signature-line
    // prefix). These are InvalidKeyName — semantically "you can't
    // use this character".
    if key_name.contains('+') || key_name.contains('\u{2014}') {
        return Err(SignedNoteError::InvalidKeyName(key_name.to_string()));
    }
    // Everything else must be printable ASCII (0x21..=0x7E, no
    // space). Anything outside that — newline, CR, NUL, tab, NBSP,
    // em-space, any non-ASCII — is a ForbiddenChar (injection-class
    // attack).
    for b in key_name.bytes() {
        if !matches!(b, 0x21..=0x7E) {
            return Err(SignedNoteError::ForbiddenChar {
                field: "key_name",
                value: key_name.to_string(),
            });
        }
    }
    Ok(())
}

/// Compute the C2SP 4-byte key ID for an Ed25519 verifying key under
/// the given signature-type byte. Use [`SIG_TYPE_ED25519`] for
/// checkpoint signatures from the log itself.
///
/// Formula (per signed-note.md §3): first 4 bytes of
/// `SHA-256(name || 0x0A || sig_type || pubkey)`.
pub fn ed25519_key_id(name: &str, sig_type: u8, pubkey: &[u8; 32]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update([0x0A]);
    h.update([sig_type]);
    h.update(pubkey);
    let digest = h.finalize();
    let mut id = [0u8; 4];
    id.copy_from_slice(&digest[..4]);
    id
}

/// Format a nucleus [`SignedTreeHead`]'s tree as a C2SP **tlog-
/// checkpoint body** — exactly the bytes a producer's primary Ed25519
/// signature would cover under [`SIG_TYPE_ED25519`]. Suitable for
/// emitting the checkpoint portion of a `POST /add-checkpoint` body
/// (the cosignature wrapper is layered on top by v2.3b).
///
/// `origin` is the log's identifier (typically a schema-less URL like
/// `nucleus.example.com/log42`). Tree size is decimal ASCII; root
/// hash is RFC 4648 standard Base64 (NOT hex — RFC says "base64
/// encoding of the root").
pub fn format_checkpoint_body(
    origin: &str,
    tree_size: u64,
    root_hash: &[u8; 32],
) -> Result<String, SignedNoteError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    validate_origin(origin)?;
    let root_b64 = STANDARD.encode(root_hash);
    Ok(format!("{origin}\n{tree_size}\n{root_b64}\n"))
}

/// Build the bytes a producer's Ed25519 signature covers for a
/// checkpoint per C2SP signed-note.md. This is exactly
/// [`format_checkpoint_body`]'s output — the spec says the signature
/// covers "the note text, which includes the final newline but
/// excludes the blank line separating text from signatures."
pub fn checkpoint_signed_bytes(
    origin: &str,
    tree_size: u64,
    root_hash: &[u8; 32],
) -> Result<Vec<u8>, SignedNoteError> {
    Ok(format_checkpoint_body(origin, tree_size, root_hash)?.into_bytes())
}

/// Format a single C2SP signature line. Returns the line WITHOUT a
/// trailing newline; callers can append `\n` when laying out the
/// full signed note.
///
/// **v2.3b CRIT-1**: validates `key_name` so a producer cannot inject
/// control chars / newlines into the signed-note structure. Tests for
/// the historical infallible behavior remain — callers passing a
/// well-formed key_name see no change.
pub fn format_signature_line(
    key_name: &str,
    key_id: &[u8; 4],
    signature: &[u8],
) -> Result<String, SignedNoteError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    validate_key_name(key_name)?;
    let mut payload = Vec::with_capacity(4 + signature.len());
    payload.extend_from_slice(key_id);
    payload.extend_from_slice(signature);
    Ok(format!(
        "{SIG_LINE_PREFIX}{key_name} {}",
        STANDARD.encode(&payload)
    ))
}

/// Parsed contents of one C2SP signature line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSignatureLine {
    /// `key_name` per spec — the public identifier of the signing key.
    pub key_name: String,
    /// 4-byte key ID (first 4 bytes of the base64 payload).
    pub key_id: [u8; 4],
    /// Signature bytes (everything after the key ID in the payload).
    pub signature: Vec<u8>,
}

/// Parse one signature line per C2SP signed-note.md §4. Strict on
/// every field: missing em-dash, malformed key name, short payload
/// all error out so a hostile witness response can't slip through.
///
/// **v2.3b MED-4**: rejects Unicode-NBSP / em-space / tab / any
/// non-printable-ASCII byte in the key_name. Without this an
/// aggregator could ship `key_name = "trusted-witness\u{00A0}attacker"`
/// and slip past a `with_expected_witness_name("trusted-witness")`
/// check while displaying as the trusted name in UIs that don't
/// Unicode-normalize.
pub fn parse_signature_line(line: &str) -> Result<ParsedSignatureLine, SignedNoteError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let rest = line
        .strip_prefix(SIG_LINE_PREFIX)
        .ok_or(SignedNoteError::MissingPrefix)?;
    // Base64 has no internal spaces, so the line is exactly
    // `<key_name> <base64>` — two whitespace-separated tokens.
    // Multiple spaces mean a space leaked into the key name (which
    // the spec forbids).
    let trimmed = rest.trim_end_matches('\n');
    let space_count = trimmed.chars().filter(|c| *c == ' ').count();
    if space_count != 1 {
        return Err(SignedNoteError::InvalidKeyName(trimmed.to_string()));
    }
    let (key_name, b64) = trimmed
        .split_once(' ')
        .ok_or(SignedNoteError::MissingKeyNameSpace)?;
    // Re-use the same strict validation the formatter uses; this
    // catches NBSP/tab/em-space/control-char attacks symmetrically
    // on the parse path.
    validate_key_name(key_name)?;
    let payload = STANDARD.decode(b64.trim_end_matches('\n'))?;
    if payload.len() < 4 {
        return Err(SignedNoteError::PayloadTooShort { got: payload.len() });
    }
    let mut key_id = [0u8; 4];
    key_id.copy_from_slice(&payload[..4]);
    Ok(ParsedSignatureLine {
        key_name: key_name.to_string(),
        key_id,
        signature: payload[4..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_id_matches_c2sp_reference_for_example_vkey() {
        // From signed-note.md example:
        //   vkey: example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k
        // The hex-encoded key ID is 530d903a (4 bytes).
        // Pubkey portion (after the 1-byte sig type 0x01) is the
        // last 32 bytes of the base64 payload "Aeky...3U2k" minus the
        // leading 0x01 sig-type byte.
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let raw = STANDARD
            .decode("AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k")
            .unwrap();
        assert_eq!(raw.len(), 33, "1-byte sig type + 32-byte Ed25519 pubkey");
        assert_eq!(raw[0], SIG_TYPE_ED25519);
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&raw[1..]);
        let id = ed25519_key_id("example.com/foo", SIG_TYPE_ED25519, &pubkey);
        assert_eq!(hex::encode(id), "530d903a", "spec reference key ID");
    }

    #[test]
    fn checkpoint_body_format_pins_byte_layout() {
        let body = format_checkpoint_body("nucleus.example.com/log42", 5, &[0x42u8; 32]).unwrap();
        // Hand-computed reference: lines separated by single \n,
        // base64 of 32-byte root.
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let expected_root = STANDARD.encode([0x42u8; 32]);
        assert_eq!(
            body,
            format!("nucleus.example.com/log42\n5\n{expected_root}\n")
        );
    }

    #[test]
    fn checkpoint_body_rejects_empty_origin() {
        assert!(matches!(
            format_checkpoint_body("", 1, &[0u8; 32]),
            Err(SignedNoteError::EmptyOrigin)
        ));
    }

    #[test]
    fn signature_line_round_trip() {
        let key_name = "nucleus.test/witness1";
        let key_id = [0x12, 0x34, 0x56, 0x78];
        let signature = vec![0xAA; 64]; // mock Ed25519 sig
        let line = format_signature_line(key_name, &key_id, &signature).unwrap();
        // Spec example reference shape:
        //   "— example.com/foo Uw2QOkn8srV1y..."
        assert!(line.starts_with("\u{2014} nucleus.test/witness1 "));
        let parsed = parse_signature_line(&line).unwrap();
        assert_eq!(parsed.key_name, key_name);
        assert_eq!(parsed.key_id, key_id);
        assert_eq!(parsed.signature, signature);
    }

    // ---------- CRIT-1 + MED-4: origin/key_name validation ----------

    #[test]
    fn origin_rejects_newline_injection() {
        let evil = "evil.example.com/log\n9999\nDEADBEEFROOT==";
        let err =
            format_checkpoint_body(evil, 5, &[0u8; 32]).expect_err("must reject newline in origin");
        assert!(
            matches!(
                err,
                SignedNoteError::ForbiddenChar {
                    field: "origin",
                    ..
                }
            ),
            "got {err:?}",
        );
    }

    #[test]
    fn origin_rejects_cr_and_null_and_tab() {
        for evil in ["a\rb", "a\0b", "a\tb", "a\x01b", "a\x7Fb"] {
            assert!(
                matches!(
                    format_checkpoint_body(evil, 1, &[0u8; 32]),
                    Err(SignedNoteError::ForbiddenChar {
                        field: "origin",
                        ..
                    })
                ),
                "must reject control byte in {:?}",
                evil
            );
        }
    }

    #[test]
    fn origin_rejects_non_ascii() {
        // Non-ASCII (e.g. UTF-8 multibyte) is rejected even though it
        // wouldn't cause line injection — printable-ASCII-only keeps
        // the validation pin tight.
        let err = format_checkpoint_body("evil.\u{00A0}com/log", 1, &[0u8; 32]).expect_err("nbsp");
        assert!(matches!(
            err,
            SignedNoteError::ForbiddenChar {
                field: "origin",
                ..
            }
        ));
    }

    #[test]
    fn origin_rejects_oversized() {
        let huge = "a".repeat(MAX_ORIGIN_LEN + 1);
        let err = format_checkpoint_body(&huge, 1, &[0u8; 32]).expect_err("oversized");
        assert!(matches!(
            err,
            SignedNoteError::TooLong {
                field: "origin",
                ..
            }
        ));
    }

    #[test]
    fn key_name_rejects_newline_injection() {
        let evil = "evil\nname";
        let err = format_signature_line(evil, &[0u8; 4], &[0u8; 64])
            .expect_err("must reject newline in key_name");
        assert!(
            matches!(
                err,
                SignedNoteError::ForbiddenChar {
                    field: "key_name",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn key_name_rejects_nbsp_and_tab() {
        for evil in ["bad\u{00A0}name", "bad\tname", "bad\u{2003}name"] {
            assert!(
                format_signature_line(evil, &[0u8; 4], &[0u8; 64]).is_err(),
                "must reject {:?}",
                evil
            );
        }
    }

    #[test]
    fn parse_rejects_nbsp_in_key_name() {
        // Build a signature line whose key_name contains NBSP.
        // The line passes the ASCII-space count (still exactly one),
        // but the key_name validator must catch the NBSP.
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let mut payload = vec![0x12, 0x34, 0x56, 0x78];
        payload.extend_from_slice(&[0xAAu8; 64]);
        let line = format!(
            "\u{2014} trusted\u{00A0}attacker {}",
            STANDARD.encode(&payload)
        );
        let err = parse_signature_line(&line).expect_err("must reject NBSP");
        assert!(matches!(err, SignedNoteError::ForbiddenChar { .. }));
    }

    #[test]
    fn key_name_rejects_em_dash() {
        let err = format_signature_line("name\u{2014}attack", &[0u8; 4], &[0u8; 64])
            .expect_err("em-dash in key_name");
        assert!(matches!(err, SignedNoteError::InvalidKeyName(_)));
    }

    #[test]
    fn key_name_rejects_oversized() {
        let huge = "a".repeat(MAX_KEY_NAME_LEN + 1);
        let err = format_signature_line(&huge, &[0u8; 4], &[0u8; 64]).expect_err("oversized");
        assert!(matches!(
            err,
            SignedNoteError::TooLong {
                field: "key_name",
                ..
            }
        ));
    }

    #[test]
    fn parse_rejects_missing_em_dash() {
        let err =
            parse_signature_line("- name AAECAwQFBgc=").expect_err("must reject missing em-dash");
        assert!(matches!(err, SignedNoteError::MissingPrefix));
    }

    #[test]
    fn parse_rejects_key_name_with_space() {
        let err = parse_signature_line("\u{2014} bad name AAECAwQFBgc=")
            .expect_err("must reject space in key name");
        assert!(matches!(err, SignedNoteError::InvalidKeyName(_)));
    }

    #[test]
    fn parse_rejects_key_name_with_plus() {
        let err = parse_signature_line("\u{2014} bad+name AAECAwQFBgc=")
            .expect_err("must reject + in key name");
        assert!(matches!(err, SignedNoteError::InvalidKeyName(_)));
    }

    #[test]
    fn parse_rejects_short_payload() {
        let err =
            parse_signature_line("\u{2014} name AAA=").expect_err("must reject payload < 4 bytes");
        assert!(matches!(err, SignedNoteError::PayloadTooShort { .. }));
    }

    #[test]
    fn checkpoint_signed_bytes_is_just_body_bytes() {
        let body = format_checkpoint_body("origin", 7, &[1u8; 32]).unwrap();
        let signed = checkpoint_signed_bytes("origin", 7, &[1u8; 32]).unwrap();
        assert_eq!(signed, body.into_bytes());
    }
}

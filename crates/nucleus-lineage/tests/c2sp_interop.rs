//! **CRIT-2 (#1647) fix.** Known-answer test vectors pinning our C2SP
//! wire-format implementation against:
//!
//! 1. The reference Go implementation at
//!    <https://github.com/transparency-dev/formats/blob/main/log/checkpoint_test.go>
//!    — proves our `format_checkpoint_body` produces byte-identical
//!    output for the same structural input.
//!
//! 2. The C2SP signed-note.md spec's **worked example** end-to-end —
//!    extracts the example pubkey from the published vkey, decodes the
//!    example signature line via our `parse_signature_line`, and
//!    cryptographically verifies the signature using ed25519-dalek
//!    against the example message. If this fails, our signed-bytes
//!    canonicalization disagrees with the spec at the byte level and
//!    nucleus cannot federate.
//!
//! ## Dialect targeted
//!
//! This implementation targets the **Go sumdb dialect** of C2SP
//! `tlog-checkpoint`:
//!
//! - 32-byte raw SHA-256 root hash (no algorithm prefix byte)
//! - Standard RFC 4648 base64 (not URL-safe)
//! - Single `\n` line terminator
//! - `key_id = SHA-256(name || 0x0A || sig_type || pubkey)[:4]` per
//!   signed-note.md §3
//!
//! Sigsum-style algorithm-prefixed root encoding is NOT supported.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use nucleus_lineage::{
    ed25519_key_id, format_checkpoint_body, parse_signature_line, SIG_TYPE_ED25519,
};

// ─────────────────────────────────────────────────────────────────────
// KAT 1: byte-identical output to transparency-dev/formats reference
//
// Source: github.com/transparency-dev/formats/log/checkpoint_test.go
// TestMarshal cases (Apache-2.0). The reference allows arbitrary-length
// hashes; nucleus is fixed at 32 bytes. We replicate the byte layout
// (origin\nsize\nbase64(hash)\n) with 32-byte hashes to prove the
// dialect matches.

/// **KAT 1a.** Demonstrates byte layout matches the Go reference's
/// `Log\n123\nYmFuYW5hcw==\n` shape for a 32-byte SHA-256 hash.
#[test]
fn kat_checkpoint_body_byte_layout_matches_reference_dialect() {
    // Hash = 32 bytes of value 0x00 — easy to inspect.
    let body = format_checkpoint_body("Log", 123, &[0u8; 32]).unwrap();
    let expected_root_b64 = STANDARD.encode([0u8; 32]); // "AAAA...AAAA="
                                                        // Expected: "Log\n123\n<base64-of-32-zeros>\n"
    assert_eq!(body, format!("Log\n123\n{expected_root_b64}\n"));
    // Verify the structural pattern: 3 newlines, no extra whitespace.
    assert_eq!(body.matches('\n').count(), 3);
    assert!(!body.contains("\r\n"), "must not contain CRLF");
    assert!(!body.contains("\t"), "must not contain tabs");
}

/// **KAT 1b.** Reference `TestMarshal` second case adapted to 32 bytes.
/// Origin = "Banana", size = 9944, hash = SHA-256-shaped buffer.
#[test]
fn kat_checkpoint_body_handles_non_zero_origin_and_size() {
    let mut hash = [0u8; 32];
    for (i, b) in hash.iter_mut().enumerate() {
        *b = (i * 7) as u8;
    }
    let body = format_checkpoint_body("Banana", 9944, &hash).unwrap();
    let expected_root_b64 = STANDARD.encode(hash);
    assert_eq!(body, format!("Banana\n9944\n{expected_root_b64}\n"));
}

// ─────────────────────────────────────────────────────────────────────
// KAT 2: C2SP signed-note.md spec example end-to-end
//
// Source: github.com/C2SP/C2SP/blob/main/signed-note.md (MIT-licensed,
// quoted verbatim). The spec's worked example:
//
//   Verifier key:
//     example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k
//
//   Signed note:
//     This is an example message.
//     <blank line>
//     — example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=

/// Spec key name.
const SPEC_KEY_NAME: &str = "example.com/foo";
/// Spec hex key ID (first 4 bytes of SHA-256(name || 0x0A || 0x01 || pubkey)).
const SPEC_KEY_ID_HEX: &str = "530d903a";
/// Spec vkey payload = base64(0x01 sig-type byte || 32-byte Ed25519 pubkey).
const SPEC_VKEY_B64: &str = "AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k";
/// Spec signed-note body. MUST include the trailing newline per
/// signed-note.md ("the signature covers the note text, which includes
/// the final newline").
const SPEC_MESSAGE: &str = "This is an example message.\n";
/// Spec signature line (without trailing newline; tests append \n
/// when feeding parse_signature_line).
const SPEC_SIG_LINE: &str = "\u{2014} example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=";

/// **KAT 2a.** Our `ed25519_key_id` formula matches the spec example.
/// Already pinned in `signed_note::tests::key_id_matches_c2sp_reference_for_example_vkey`
/// but re-pinned here as part of the interop suite so a failure here
/// is unambiguous about which surface it's pinning.
#[test]
fn kat_spec_key_id_matches_published_value() {
    let raw = STANDARD.decode(SPEC_VKEY_B64).unwrap();
    assert_eq!(raw.len(), 33, "1-byte sig type + 32-byte Ed25519 pubkey");
    assert_eq!(raw[0], SIG_TYPE_ED25519);
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&raw[1..]);
    let id = ed25519_key_id(SPEC_KEY_NAME, SIG_TYPE_ED25519, &pubkey);
    assert_eq!(hex::encode(id), SPEC_KEY_ID_HEX);
}

/// **KAT 2b.** Our `parse_signature_line` decodes the spec example
/// signature line into the published key_id.
#[test]
fn kat_spec_signature_line_parses_correctly() {
    let parsed = parse_signature_line(SPEC_SIG_LINE).unwrap();
    assert_eq!(parsed.key_name, SPEC_KEY_NAME);
    assert_eq!(hex::encode(parsed.key_id), SPEC_KEY_ID_HEX);
    assert_eq!(
        parsed.signature.len(),
        64,
        "Ed25519 signature is 64 bytes (after stripping 4-byte key_id)"
    );
}

/// **KAT 2c (THE load-bearing interop test).** Cryptographically
/// verify the spec example signature using ed25519-dalek against the
/// spec example pubkey over the spec example message. If THIS fails,
/// our signed-bytes canonicalization is incompatible with the C2SP
/// ecosystem and federation cannot work, regardless of how clean our
/// own round-trips look.
#[test]
fn kat_spec_signature_verifies_against_spec_pubkey() {
    use ed25519_dalek::{Signature, VerifyingKey};

    // Extract pubkey from the spec vkey payload.
    let raw = STANDARD.decode(SPEC_VKEY_B64).unwrap();
    assert_eq!(raw[0], SIG_TYPE_ED25519);
    let mut pubkey_bytes = [0u8; 32];
    pubkey_bytes.copy_from_slice(&raw[1..]);
    let vk =
        VerifyingKey::from_bytes(&pubkey_bytes).expect("spec example pubkey must be valid Ed25519");

    // Extract the signature from the spec sig line.
    let parsed = parse_signature_line(SPEC_SIG_LINE).unwrap();
    assert_eq!(parsed.signature.len(), 64);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&parsed.signature);
    let sig = Signature::from_bytes(&sig_arr);

    // The signed bytes are EXACTLY the message text including the
    // trailing newline, per signed-note.md "the signature covers the
    // note text, which includes the final newline but excludes the
    // separating blank line."
    vk.verify_strict(SPEC_MESSAGE.as_bytes(), &sig).expect(
        "spec example signature MUST verify against spec pubkey over spec message — \
         if this fails, our wire format is incompatible with the C2SP ecosystem",
    );
}

/// **KAT 2d.** Falsification: tampering with the message byte
/// (e.g., dropping the trailing newline) MUST cause verification to
/// fail. Pins that we sign the EXACT bytes the spec demands.
#[test]
fn kat_spec_signature_fails_without_trailing_newline() {
    use ed25519_dalek::{Signature, VerifyingKey};

    let raw = STANDARD.decode(SPEC_VKEY_B64).unwrap();
    let mut pubkey_bytes = [0u8; 32];
    pubkey_bytes.copy_from_slice(&raw[1..]);
    let vk = VerifyingKey::from_bytes(&pubkey_bytes).unwrap();

    let parsed = parse_signature_line(SPEC_SIG_LINE).unwrap();
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&parsed.signature);
    let sig = Signature::from_bytes(&sig_arr);

    // Drop the trailing newline — should NOT verify.
    let tampered = "This is an example message.";
    vk.verify_strict(tampered.as_bytes(), &sig)
        .expect_err("trailing-newline-stripped message must NOT verify");
}

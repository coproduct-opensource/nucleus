//! # Per-hash GUARANTEE RECEIPT (schema_version = 0)
//!
//! ## HONESTY (read this first — a receipt is a SCREEN result, NOT a proof)
//!
//! A guarantee receipt attests **exactly one thing**: that the `aeneas_eligible`
//! *screen* (a NECESSARY condition for Aeneas-extractability — see the crate-level
//! docs) produced a particular `result` for a particular function, at one exact
//! `(normalized_source, toolchain, profile_id)` triple, identified by `anchor_hash`.
//!
//! It is **NOT**:
//! * a proof that the function *is* extractable into a functional model;
//! * a proof that any extracted model is *correct*;
//! * a guarantee of anything beyond "the screen returned this `result` for this hash".
//!
//! A `result = "clean"` receipt is the output of a **necessary-condition** screen:
//! the function tripped none of the *implemented* deny-set rules. It does **not** mean
//! the function is "in the Aeneas subset" — several deny-set rows (floats, nested
//! loops, non-`Vec` collections, iterator combinators) are **not screened at all** and
//! are carried in `guarantees` as `"not_screened"`. A clean receipt is necessary, not
//! sufficient.
//!
//! ## Fail-closed binding
//!
//! The receipt is bound to its inputs by `anchor_hash`. Change the source by one byte,
//! change the toolchain, or change the profile, and the hash changes — the old receipt
//! no longer matches the new function and is **void** (it simply will not be found at
//! `<receipt_dir>/<new_hash>.json`). There is no "approximately matches": the binding
//! is fail-closed by construction.
//!
//! ## Toolchain-relative
//!
//! `toolchain` records the *exact* rustc channel the screen ran under. The Aeneas
//! subset, and the screen's own decidability at the HIR level, are properties of that
//! specific compiler. The receipt's guarantee is **toolchain-relative**: it says
//! nothing about how the same source behaves under a different rustc.
//!
//! ## v0 anchor caveat (whitespace-sensitive)
//!
//! In v0, `normalized_source` is the raw source snippet of the function taken from its
//! HIR span (via `clippy_utils::source::snippet_opt`). This is **whitespace- and
//! comment-sensitive**: reformatting the function (e.g. `rustfmt`) changes the bytes,
//! hence the hash, hence voids the receipt even though the *meaning* is unchanged.
//! That is conservative (fail-closed) but noisy.
//!
//! v1 TODO: switch `normalized_source` to a reformat-robust anchor — either a
//! `rustfmt`-normalized source string or, better, a hash of the StableMIR body — so the
//! anchor tracks *semantics* rather than *bytes*. Until then, treat a v0 receipt as
//! bound to the literal source text.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Domain-separation tag prepended to the hash preimage. Bump only on a
/// breaking change to the preimage construction.
pub const ANCHOR_DOMAIN_TAG: &[u8] = b"nucleus.guarantee-receipt.v0";

/// The current receipt schema version. Bump on any change to the serialized shape.
pub const SCHEMA_VERSION: u32 = 0;

/// The screen profile this receipt attests against. A constant for v0: it identifies
/// *which* screen produced the result. (v1 may fold the aeneas/charon commit + backend
/// + flags into this string.)
pub const PROFILE_ID: &str = "aeneas-eligible-v1";

/// The seven deny-set rules this screen actually implements. A `clean` receipt asserts
/// each of these passed; UNSCREENED rules (floats / nested-loops / non-`Vec` collections
/// / iterator-combinators) are carried separately as `"not_screened"` — see [`Guarantee`].
pub const SCREENED_RULES: [&str; 7] = [
    "no_unsafe",
    "no_async",
    "no_closures",
    "no_dyn_in_sig",
    "no_raw_ptr",
    "no_ffi_call",
    "no_inline_asm",
];

/// The deny-set rows the screen does NOT implement. Carried in `guarantees` as
/// `"not_screened"` so a receipt never *silently* implies coverage it does not have.
pub const NOT_SCREENED_RULES: [&str; 4] = [
    "no_floats",
    "no_nested_loops",
    "no_non_vec_collections",
    "no_iterator_combinators",
];

/// The screen result for a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreenResult {
    /// Tripped none of the implemented deny-set rules. NECESSARY-condition pass only —
    /// see the module docs; this is NOT "in the subset" and NOT a proof.
    Clean,
    /// Tripped at least one implemented deny-set rule (see `ineligible_reasons`).
    Ineligible,
}

/// Per-rule outcome. `Pass`/`Fail` apply only to the seven implemented rules; every
/// unscreened rule is `NotScreened` — never `Pass` — so a clean receipt cannot be
/// misread as asserting coverage the screen does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Guarantee {
    Pass,
    Fail,
    NotScreened,
}

/// A signed-able guarantee receipt. Serializes to canonical JSON (RFC 8785 / JCS) for
/// signing; the `.json` written to disk is the same canonical form so re-canonicalizing
/// is idempotent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub schema_version: u32,
    /// Fully-qualified item path of the screened function (e.g. `crate::module::f`).
    pub item_path: String,
    /// Item kind, e.g. `fn`, `method`.
    pub item_kind: String,
    /// Hex SHA-256 of the domain-tagged preimage — see [`compute_anchor_hash`].
    pub anchor_hash: String,
    /// Exact rustc channel the screen ran under (toolchain-relative guarantee).
    pub toolchain: String,
    /// Screen profile identifier (constant in v0).
    pub profile_id: String,
    pub result: ScreenResult,
    /// Human-readable reasons the function was flagged ineligible; empty when clean.
    pub ineligible_reasons: Vec<String>,
    /// Per-rule outcome map. Keys are rule names; values are pass/fail/not_screened.
    /// Sorted deterministically by `BTreeMap`.
    pub guarantees: BTreeMap<String, Guarantee>,
}

impl Receipt {
    /// Build a receipt for a screened function.
    ///
    /// `failed_rules` is the set of implemented-rule names that tripped (subset of
    /// [`SCREENED_RULES`]). `reasons` is the human-readable hit list. The `guarantees`
    /// map is filled deterministically: each screened rule → `Pass`/`Fail`, each
    /// unscreened rule → `NotScreened`.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        item_path: String,
        item_kind: String,
        normalized_source: &str,
        toolchain: &str,
        profile_id: &str,
        failed_rules: &[&str],
        reasons: Vec<String>,
    ) -> Self {
        let anchor_hash = compute_anchor_hash(normalized_source, toolchain, profile_id);

        let result = if failed_rules.is_empty() {
            ScreenResult::Clean
        } else {
            ScreenResult::Ineligible
        };

        let mut guarantees = BTreeMap::new();
        for rule in SCREENED_RULES {
            let g = if failed_rules.contains(&rule) {
                Guarantee::Fail
            } else {
                Guarantee::Pass
            };
            guarantees.insert(rule.to_string(), g);
        }
        for rule in NOT_SCREENED_RULES {
            guarantees.insert(rule.to_string(), Guarantee::NotScreened);
        }

        Receipt {
            schema_version: SCHEMA_VERSION,
            item_path,
            item_kind,
            anchor_hash,
            toolchain: toolchain.to_string(),
            profile_id: profile_id.to_string(),
            result,
            ineligible_reasons: reasons,
            guarantees,
        }
    }

    /// Canonical JSON bytes (RFC 8785 / JCS) — the exact bytes that are signed and
    /// written to `<receipt_dir>/<anchor_hash>.json`.
    pub fn canonical_json(&self) -> Result<Vec<u8>, ReceiptError> {
        let value = serde_json::to_value(self).map_err(ReceiptError::Json)?;
        serde_jcs::to_vec(&value).map_err(ReceiptError::Json)
    }

    /// Sign the canonical JSON with an ed25519 signing key. Returns the canonical bytes
    /// and the detached signature (so the caller writes `.json` + `.sig` consistently).
    pub fn sign(&self, key: &SigningKey) -> Result<(Vec<u8>, Signature), ReceiptError> {
        let bytes = self.canonical_json()?;
        let sig = key.sign(&bytes);
        Ok((bytes, sig))
    }
}

/// Compute `anchor_hash = SHA-256( TAG ‖ normalized_source ‖ toolchain ‖ profile_id )`,
/// returned as lowercase hex.
///
/// The preimage is the byte concatenation, in order, of:
///   1. [`ANCHOR_DOMAIN_TAG`] (`b"nucleus.guarantee-receipt.v0"`)
///   2. `normalized_source` bytes (v0: the raw HIR-span source snippet)
///   3. `toolchain` bytes (e.g. `nightly-2026-04-16`)
///   4. `profile_id` bytes (e.g. `aeneas-eligible-v1`)
///
/// NO length-prefixing / separators are used in v0: the domain tag + fixed field order
/// give a stable preimage for the screen's own use, but note this is NOT collision-proof
/// across arbitrary field re-splits (a v1 hardening TODO is length-prefixed framing).
pub fn compute_anchor_hash(normalized_source: &str, toolchain: &str, profile_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ANCHOR_DOMAIN_TAG);
    hasher.update(normalized_source.as_bytes());
    hasher.update(toolchain.as_bytes());
    hasher.update(profile_id.as_bytes());
    let digest = hasher.finalize();
    hex::encode(digest)
}

/// Verify a receipt against a witness PUBLIC key.
///
/// Re-canonicalizes the supplied receipt JSON (so a holder need not trust the byte
/// layout they were handed) and checks the ed25519 signature over those canonical bytes.
/// Returns `Ok(true)` iff the signature verifies. A holder who *also* wants to confirm
/// the receipt is bound to a specific source should independently recompute
/// `compute_anchor_hash` and compare to `receipt.anchor_hash` (see
/// [`verify_receipt_bound_to`]).
pub fn verify_receipt(
    receipt_json: &[u8],
    sig_bytes: &[u8],
    pubkey: &VerifyingKey,
) -> Result<bool, ReceiptError> {
    let receipt: Receipt = serde_json::from_slice(receipt_json).map_err(ReceiptError::Json)?;
    let canonical = receipt.canonical_json()?;
    let sig = signature_from_bytes(sig_bytes)?;
    Ok(pubkey.verify(&canonical, &sig).is_ok())
}

/// Stronger check: signature verifies AND `anchor_hash` matches the supplied
/// `(normalized_source, toolchain, profile_id)`. Use this when a holder has the source in
/// hand and wants the fail-closed binding (changed source ⇒ false).
pub fn verify_receipt_bound_to(
    receipt_json: &[u8],
    sig_bytes: &[u8],
    pubkey: &VerifyingKey,
    normalized_source: &str,
    toolchain: &str,
    profile_id: &str,
) -> Result<bool, ReceiptError> {
    let receipt: Receipt = serde_json::from_slice(receipt_json).map_err(ReceiptError::Json)?;
    let expected = compute_anchor_hash(normalized_source, toolchain, profile_id);
    if receipt.anchor_hash != expected {
        return Ok(false);
    }
    let canonical = receipt.canonical_json()?;
    let sig = signature_from_bytes(sig_bytes)?;
    Ok(pubkey.verify(&canonical, &sig).is_ok())
}

fn signature_from_bytes(sig_bytes: &[u8]) -> Result<Signature, ReceiptError> {
    let arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| ReceiptError::BadSignatureLength(sig_bytes.len()))?;
    Ok(Signature::from_bytes(&arr))
}

/// Load a 32-byte ed25519 secret key from raw (32 bytes) or hex (64 ascii hex chars,
/// optionally with surrounding whitespace) bytes. Refuses anything else — there is no
/// fallback to a zero / fake key (honesty: an invalid key is an ERROR, never silently
/// substituted).
pub fn load_signing_key(raw_or_hex: &[u8]) -> Result<SigningKey, ReceiptError> {
    // Raw 32 bytes.
    if raw_or_hex.len() == 32 {
        let arr: [u8; 32] = raw_or_hex.try_into().expect("len checked");
        return Ok(SigningKey::from_bytes(&arr));
    }
    // Hex (trim ASCII whitespace such as a trailing newline).
    let trimmed: Vec<u8> = raw_or_hex
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if trimmed.len() == 64 {
        let bytes = hex::decode(&trimmed).map_err(|_| ReceiptError::BadKey)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| ReceiptError::BadKey)?;
        return Ok(SigningKey::from_bytes(&arr));
    }
    Err(ReceiptError::BadKey)
}

/// Load a 32-byte ed25519 PUBLIC (verifying) key from raw or hex bytes.
pub fn load_verifying_key(raw_or_hex: &[u8]) -> Result<VerifyingKey, ReceiptError> {
    if raw_or_hex.len() == 32 {
        let arr: [u8; 32] = raw_or_hex.try_into().expect("len checked");
        return VerifyingKey::from_bytes(&arr).map_err(|_| ReceiptError::BadKey);
    }
    let trimmed: Vec<u8> = raw_or_hex
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if trimmed.len() == 64 {
        let bytes = hex::decode(&trimmed).map_err(|_| ReceiptError::BadKey)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| ReceiptError::BadKey)?;
        return VerifyingKey::from_bytes(&arr).map_err(|_| ReceiptError::BadKey);
    }
    Err(ReceiptError::BadKey)
}

#[derive(Debug)]
pub enum ReceiptError {
    /// JSON (de)serialization or JCS canonicalization failed.
    Json(serde_json::Error),
    /// The signing/verifying key bytes were neither raw-32 nor hex-64.
    BadKey,
    /// The signature was not 64 bytes.
    BadSignatureLength(usize),
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReceiptError::Json(e) => write!(f, "receipt JSON/JCS error: {e}"),
            ReceiptError::BadKey => write!(
                f,
                "invalid ed25519 key: expected 32 raw bytes or 64 hex chars (NO zero/fake key fallback)"
            ),
            ReceiptError::BadSignatureLength(n) => {
                write!(f, "invalid signature length: expected 64 bytes, got {n}")
            }
        }
    }
}

impl std::error::Error for ReceiptError {}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    // A FRESH key per test, generated in-test only. NO real/private key is ever
    // committed or read from disk in these unit tests (honesty / HARD STOP).
    fn test_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn clean_receipt(src: &str) -> Receipt {
        Receipt::build(
            "crate::clean_add".into(),
            "fn".into(),
            src,
            "nightly-2026-04-16",
            PROFILE_ID,
            &[],
            vec![],
        )
    }

    #[test]
    fn clean_fn_yields_clean_result_and_verifiable_sig() {
        let key = test_key();
        let pubkey = key.verifying_key();
        let receipt = clean_receipt("fn clean_add(a: u64, b: u64) -> u64 { a + b }");

        assert_eq!(receipt.result, ScreenResult::Clean);
        assert!(receipt.ineligible_reasons.is_empty());
        // every screened rule passes; every unscreened rule is NotScreened (never Pass).
        for rule in SCREENED_RULES {
            assert_eq!(receipt.guarantees[rule], Guarantee::Pass, "{rule}");
        }
        for rule in NOT_SCREENED_RULES {
            assert_eq!(receipt.guarantees[rule], Guarantee::NotScreened, "{rule}");
        }

        let (json, sig) = receipt.sign(&key).unwrap();
        assert!(verify_receipt(&json, &sig.to_bytes(), &pubkey).unwrap());
    }

    #[test]
    fn ineligible_fn_records_result_and_reasons() {
        let key = test_key();
        let pubkey = key.verifying_key();
        let receipt = Receipt::build(
            "crate::ineligible_async".into(),
            "fn".into(),
            "async fn ineligible_async() -> u64 { 0 }",
            "nightly-2026-04-16",
            PROFILE_ID,
            &["no_async"],
            vec!["an `async` function signature".into()],
        );

        assert_eq!(receipt.result, ScreenResult::Ineligible);
        assert_eq!(receipt.guarantees["no_async"], Guarantee::Fail);
        assert_eq!(receipt.guarantees["no_unsafe"], Guarantee::Pass);
        assert_eq!(receipt.ineligible_reasons.len(), 1);

        let (json, sig) = receipt.sign(&key).unwrap();
        assert!(verify_receipt(&json, &sig.to_bytes(), &pubkey).unwrap());
    }

    #[test]
    fn same_source_yields_same_anchor_hash_determinism() {
        let src = "fn clean_add(a: u64, b: u64) -> u64 { a + b }";
        let h1 = compute_anchor_hash(src, "nightly-2026-04-16", PROFILE_ID);
        let h2 = compute_anchor_hash(src, "nightly-2026-04-16", PROFILE_ID);
        assert_eq!(h1, h2);
        // and via the full receipt path
        assert_eq!(clean_receipt(src).anchor_hash, clean_receipt(src).anchor_hash);
    }

    #[test]
    fn changing_source_changes_hash() {
        let h1 = compute_anchor_hash("fn f() -> u64 { 0 }", "nightly-2026-04-16", PROFILE_ID);
        let h2 = compute_anchor_hash("fn f() -> u64 { 1 }", "nightly-2026-04-16", PROFILE_ID);
        assert_ne!(h1, h2);
        // even a single whitespace byte changes it (v0 is whitespace-sensitive by design)
        let h3 = compute_anchor_hash("fn f() -> u64 {  0 }", "nightly-2026-04-16", PROFILE_ID);
        assert_ne!(h1, h3);
    }

    #[test]
    fn changing_toolchain_or_profile_changes_hash() {
        let src = "fn f() -> u64 { 0 }";
        let base = compute_anchor_hash(src, "nightly-2026-04-16", PROFILE_ID);
        assert_ne!(base, compute_anchor_hash(src, "nightly-2026-04-17", PROFILE_ID));
        assert_ne!(base, compute_anchor_hash(src, "nightly-2026-04-16", "other-profile"));
    }

    #[test]
    fn tampered_receipt_fails_verification() {
        let key = test_key();
        let pubkey = key.verifying_key();
        let receipt = clean_receipt("fn f() -> u64 { 0 }");
        let (json, sig) = receipt.sign(&key).unwrap();

        // Flip the result clean -> ineligible in the JSON; signature must reject.
        let mut tampered: Receipt = serde_json::from_slice(&json).unwrap();
        tampered.result = ScreenResult::Ineligible;
        let tampered_json = tampered.canonical_json().unwrap();
        assert!(!verify_receipt(&tampered_json, &sig.to_bytes(), &pubkey).unwrap());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let key = test_key();
        let other = test_key();
        let receipt = clean_receipt("fn f() -> u64 { 0 }");
        let (json, sig) = receipt.sign(&key).unwrap();
        assert!(!verify_receipt(&json, &sig.to_bytes(), &other.verifying_key()).unwrap());
    }

    #[test]
    fn verify_bound_to_is_fail_closed_on_source_change() {
        let key = test_key();
        let pubkey = key.verifying_key();
        let src = "fn f() -> u64 { 0 }";
        let receipt = clean_receipt(src);
        let (json, sig) = receipt.sign(&key).unwrap();

        // Correct source: binds.
        assert!(
            verify_receipt_bound_to(&json, &sig.to_bytes(), &pubkey, src, "nightly-2026-04-16", PROFILE_ID)
                .unwrap()
        );
        // Changed source: fail-closed even though the sig itself is valid.
        assert!(
            !verify_receipt_bound_to(
                &json,
                &sig.to_bytes(),
                &pubkey,
                "fn f() -> u64 { 1 }",
                "nightly-2026-04-16",
                PROFILE_ID
            )
            .unwrap()
        );
    }

    #[test]
    fn canonical_json_is_idempotent_and_sorted() {
        let receipt = clean_receipt("fn f() -> u64 { 0 }");
        let c1 = receipt.canonical_json().unwrap();
        // round-trip and re-canonicalize: must be byte-identical (JCS is canonical).
        let parsed: Receipt = serde_json::from_slice(&c1).unwrap();
        let c2 = parsed.canonical_json().unwrap();
        assert_eq!(c1, c2);
        // top-level keys must be sorted (JCS): schema_version is "s", anchor_hash "a"...
        let s = String::from_utf8(c1).unwrap();
        let anchor_pos = s.find("\"anchor_hash\"").unwrap();
        let schema_pos = s.find("\"schema_version\"").unwrap();
        assert!(anchor_pos < schema_pos, "JCS sorts keys: anchor_hash before schema_version");
    }

    #[test]
    fn load_signing_key_raw_and_hex_agree() {
        let key = test_key();
        let raw = key.to_bytes(); // [u8; 32]
        let hexed = hex::encode(raw);

        let from_raw = load_signing_key(&raw).unwrap();
        let from_hex = load_signing_key(hexed.as_bytes()).unwrap();
        let from_hex_nl = load_signing_key(format!("{hexed}\n").as_bytes()).unwrap();

        assert_eq!(from_raw.to_bytes(), key.to_bytes());
        assert_eq!(from_hex.to_bytes(), key.to_bytes());
        assert_eq!(from_hex_nl.to_bytes(), key.to_bytes());
    }

    #[test]
    fn load_signing_key_rejects_bad_input_no_zero_fallback() {
        // wrong length raw
        assert!(load_signing_key(&[0u8; 16]).is_err());
        // non-hex of right length
        assert!(load_signing_key(&[b'z'; 64]).is_err());
        // empty -> error, NOT a zero key
        assert!(load_signing_key(&[]).is_err());
    }
}

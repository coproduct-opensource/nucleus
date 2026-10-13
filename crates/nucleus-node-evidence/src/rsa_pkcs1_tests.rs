//! Tests for the in-crate RSASSA-PKCS1-v1_5 verifier.
//!
//! A-19: each test names the wrong implementation it reds on. The vectors come
//! from outside this crate — OpenSSL (`tests/fixtures/rsa-pkcs1-kat.json`,
//! commands recorded in the file) and Wycheproof (`tests/fixtures/wycheproof/`,
//! source URL and commit recorded in each file) — so they are not a round trip
//! of this module against itself.

use super::*;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Known-answer vectors (OpenSSL 3.6.3)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Kat {
    msg_utf8: String,
    public_key_der: String,
    private_exponent: String,
    sig_sha256: String,
    sig_sha384: String,
}

fn kat() -> Kat {
    serde_json::from_str(include_str!("../tests/fixtures/rsa-pkcs1-kat.json")).unwrap()
}

fn kat_key() -> RsaPublicKey {
    RsaPublicKey::from_spki_der(&hex::decode(kat().public_key_der).unwrap()).unwrap()
}

fn digest(hash: HashAlg) -> Vec<u8> {
    hash.digest(kat().msg_utf8.as_bytes())
}

/// RSASP1 with the KAT's TEST-ONLY private exponent: turns any block into the
/// signature that recovers it, so malformed encodings can be put through the
/// real verifier.
fn sign_raw(key: &RsaPublicKey, em: &[u8]) -> Vec<u8> {
    let d = BigUint::from_bytes_be(&hex::decode(kat().private_exponent).unwrap());
    let m = BigUint::from_bytes_be(em);
    assert!(m < key.n, "test block must be below n");
    i2osp(&m.modpow(&d, &key.n), key.k).unwrap()
}

fn expected_em(key: &RsaPublicKey, hash: HashAlg) -> Vec<u8> {
    emsa_pkcs1_v1_5_encode(hash, &digest(hash), key.k).unwrap()
}

/// Reds if the DigestInfo prefixes, the padding layout, RSAVP1 or I2OSP are
/// wrong: OpenSSL's signatures would not verify.
#[test]
fn openssl_signatures_verify() {
    let key = kat_key();
    let k = kat();
    for (hash, sig) in [
        (HashAlg::Sha256, k.sig_sha256),
        (HashAlg::Sha384, k.sig_sha384),
    ] {
        let sig = hex::decode(sig).unwrap();
        assert_eq!(key.verify_pkcs1v15(hash, &digest(hash), &sig), Ok(()));
    }
}

/// The encoder checked independently of the verifier: signing this module's
/// `EM` with the private exponent reproduces OpenSSL's bytes exactly. Reds on
/// any byte of the encoding that differs from OpenSSL's.
#[test]
fn the_expected_encoding_is_the_one_openssl_signs() {
    let key = kat_key();
    let k = kat();
    assert_eq!(
        sign_raw(&key, &expected_em(&key, HashAlg::Sha256)),
        hex::decode(k.sig_sha256).unwrap()
    );
    assert_eq!(
        sign_raw(&key, &expected_em(&key, HashAlg::Sha384)),
        hex::decode(k.sig_sha384).unwrap()
    );
}

/// Byte identity of the SubjectPublicKeyInfo: AK identities are SHA-256 of
/// these bytes, so a re-encoding that differs from OpenSSL's (or from the
/// `rsa` crate's, which the swtpm fixture's pinned AK digest was made with)
/// moves every pin. Reds on a non-minimal length or a missing 0x00 sign octet.
#[test]
fn spki_round_trips_byte_for_byte() {
    let der = hex::decode(kat().public_key_der).unwrap();
    let key = RsaPublicKey::from_spki_der(&der).unwrap();
    assert_eq!(key.spki_der(), der.as_slice());
    let e = 65_537;
    let n = key.n.to_bytes_be();
    assert_eq!(RsaPublicKey::from_parts(&n, e).unwrap(), key);
    // A TPM's fixed-width buffer may carry leading zeros; same key.
    let mut padded = vec![0, 0];
    padded.extend_from_slice(&n);
    assert_eq!(RsaPublicKey::from_parts(&padded, e).unwrap(), key);
}

// ---------------------------------------------------------------------------
// Signature refusals (each names the reason, so it reds for its own reason)
// ---------------------------------------------------------------------------

/// Reds if the step-1 length check is dropped: a leading zero octet does not
/// change the integer, so only the length check refuses it.
#[test]
fn a_signature_of_the_wrong_length_is_refused() {
    let key = kat_key();
    let good = hex::decode(kat().sig_sha256).unwrap();
    let d = digest(HashAlg::Sha256);
    let mut longer = vec![0];
    longer.extend_from_slice(&good);
    assert_eq!(
        key.verify_pkcs1v15(HashAlg::Sha256, &d, &longer),
        Err(RsaVerifyError::SignatureLength {
            expected: 256,
            got: 257
        })
    );
    assert_eq!(
        key.verify_pkcs1v15(HashAlg::Sha256, &d, &good[1..]),
        Err(RsaVerifyError::SignatureLength {
            expected: 256,
            got: 255
        })
    );
}

/// Reds if `s < n` is not checked: `s + n` recovers the same block, so it would
/// otherwise verify (signature malleability).
#[test]
fn a_signature_not_below_the_modulus_is_refused() {
    let key = kat_key();
    let d = digest(HashAlg::Sha256);
    let n = i2osp(&key.n, key.k).unwrap();
    assert_eq!(
        key.verify_pkcs1v15(HashAlg::Sha256, &d, &n),
        Err(RsaVerifyError::NotBelowModulus)
    );
    let good = BigUint::from_bytes_be(&hex::decode(kat().sig_sha256).unwrap());
    let shifted = good + &key.n;
    if let Some(shifted) = i2osp(&shifted, key.k) {
        assert_eq!(
            key.verify_pkcs1v15(HashAlg::Sha256, &d, &shifted),
            Err(RsaVerifyError::NotBelowModulus)
        );
    }
    assert_eq!(
        key.verify_pkcs1v15(HashAlg::Sha256, &d, &vec![0xff; key.k]),
        Err(RsaVerifyError::NotBelowModulus)
    );
}

#[test]
fn a_digest_of_the_wrong_length_is_refused() {
    let key = kat_key();
    let sig = hex::decode(kat().sig_sha256).unwrap();
    assert_eq!(
        key.verify_pkcs1v15(HashAlg::Sha256, &digest(HashAlg::Sha384), &sig),
        Err(RsaVerifyError::DigestLength {
            expected: 32,
            got: 48
        })
    );
}

fn assert_block_refused(key: &RsaPublicKey, em: &[u8], why: &str) {
    assert_eq!(em.len(), key.k, "{why}: test block is k octets");
    let sig = sign_raw(key, em);
    assert_eq!(
        key.verify_pkcs1v15(HashAlg::Sha256, &digest(HashAlg::Sha256), &sig),
        Err(RsaVerifyError::EncodingMismatch),
        "{why}"
    );
}

/// The Bleichenbacher-'06 family: blocks a lenient parser of the decoded
/// signature accepts. Each reds on a verifier that parses instead of
/// comparing whole buffers.
#[test]
fn malformed_encodings_are_refused() {
    let key = kat_key();
    let em = expected_em(&key, HashAlg::Sha256);
    let t_len = 19 + 32;
    let ps_end = key.k - t_len - 1; // index of the 0x00 separator

    // Block type 02 (encryption padding) in place of 01.
    let mut bt2 = em.clone();
    bt2[1] = 0x02;
    assert_block_refused(&key, &bt2, "block type 02");

    // One padding octet not 0xFF.
    let mut fe = em.clone();
    fe[ps_end / 2] = 0xfe;
    assert_block_refused(&key, &fe, "padding octet 0xFE");

    // Short 0xFF run, with the digest followed by garbage to fill k octets:
    // the classic e=3 forgery shape.
    let mut short = vec![0x00, 0x01];
    short.extend_from_slice(&[0xff; 8]);
    short.push(0x00);
    short.extend_from_slice(&em[ps_end + 1..]);
    short.resize(key.k, 0x42);
    assert_block_refused(&key, &short, "short padding + trailing garbage");

    // 0xFF run of seven: below the RFC's minimum of eight, shifted right.
    let mut seven = vec![0x00; key.k - (3 + 7 + t_len)];
    seven.extend_from_slice(&[0x00, 0x01]);
    seven.extend_from_slice(&[0xff; 7]);
    seven.push(0x00);
    seven.extend_from_slice(&em[ps_end + 1..]);
    assert_block_refused(&key, &seven, "seven-octet padding, left-zeroed");

    // Missing separator: 0xFF where the 0x00 belongs.
    let mut no_sep = em.clone();
    no_sep[ps_end] = 0xff;
    assert_block_refused(&key, &no_sep, "no 0x00 separator");

    // Wrong hash OID in DigestInfo: SHA-512's arc (…2.3) over a 32-byte digest.
    let mut oid = em.clone();
    oid[ps_end + 1 + 14] = 0x03;
    assert_block_refused(&key, &oid, "DigestInfo names another hash");

    // Legacy DigestInfo without the NULL parameters (Wycheproof "MissingNull",
    // RFC 8017 §9.2 note 1). Refused: one valid encoding per digest.
    let missing_null: [u8; 17] = [
        0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x04, 0x20,
    ];
    let mut legacy = vec![0x00, 0x01];
    legacy.resize(key.k - (missing_null.len() + 32) - 1, 0xff);
    legacy.push(0x00);
    legacy.extend_from_slice(&missing_null);
    legacy.extend_from_slice(&digest(HashAlg::Sha256));
    assert_block_refused(&key, &legacy, "DigestInfo without NULL");

    // The right digest, the wrong position: digest moved one octet left with a
    // trailing octet after it.
    let mut trailing = em.clone();
    trailing.remove(2);
    trailing.push(0x00);
    assert_block_refused(&key, &trailing, "trailing octet after the digest");
}

/// A valid SHA-256 signature does not verify as a SHA-384 one. Reds if the
/// DigestInfo prefix is not bound to the claimed hash.
#[test]
fn a_signature_under_another_hash_is_refused() {
    let key = kat_key();
    let sig = hex::decode(kat().sig_sha256).unwrap();
    assert_eq!(
        key.verify_pkcs1v15(HashAlg::Sha384, &digest(HashAlg::Sha384), &sig),
        Err(RsaVerifyError::EncodingMismatch)
    );
}

/// `0^e = 0` and `1^e = 1`: the edge integers. Reds on an arithmetic shortcut
/// that treats them specially.
#[test]
fn zero_and_one_are_refused() {
    let key = kat_key();
    let d = digest(HashAlg::Sha256);
    for v in [0u8, 1] {
        let mut sig = vec![0; key.k];
        sig[key.k - 1] = v;
        assert_eq!(
            key.verify_pkcs1v15(HashAlg::Sha256, &d, &sig),
            Err(RsaVerifyError::EncodingMismatch)
        );
    }
}

// ---------------------------------------------------------------------------
// Key admission
// ---------------------------------------------------------------------------

/// An odd modulus of exactly `bits` bits.
fn odd_modulus(bits: usize) -> Vec<u8> {
    let mut n = vec![0xff; bits.div_ceil(8)];
    let top = bits % 8;
    if top != 0 {
        n[0] = (1u8 << top) - 1;
    }
    n
}

#[test]
fn modulus_size_bounds_are_enforced() {
    assert_eq!(MAX_EXPONENT, u64::from(u32::MAX));
    for bits in [2048, 3072, 4096] {
        assert!(
            RsaPublicKey::from_parts(&odd_modulus(bits), 65_537).is_ok(),
            "{bits}"
        );
    }
    for bits in [1024, 2047, 4097, 8192] {
        assert_eq!(
            RsaPublicKey::from_parts(&odd_modulus(bits), 65_537),
            Err(RsaKeyError::ModulusSize {
                bits: u64::try_from(bits).unwrap()
            }),
            "{bits}"
        );
    }
    assert_eq!(
        RsaPublicKey::from_parts(&[], 65_537),
        Err(RsaKeyError::ModulusSize { bits: 0 })
    );
}

#[test]
fn an_even_modulus_is_refused() {
    let mut n = odd_modulus(2048);
    n[255] = 0xfe;
    assert_eq!(
        RsaPublicKey::from_parts(&n, 65_537),
        Err(RsaKeyError::ModulusEven)
    );
}

#[test]
fn exponent_bounds_are_enforced() {
    let n = odd_modulus(2048);
    for (e, want) in [
        (0, RsaKeyError::ExponentTooSmall),
        (1, RsaKeyError::ExponentTooSmall),
        (3, RsaKeyError::ExponentTooSmall),
        (65_535, RsaKeyError::ExponentTooSmall),
        (65_538, RsaKeyError::ExponentEven),
        (1 << 32, RsaKeyError::ExponentTooLarge),
        ((1 << 32) + 1, RsaKeyError::ExponentTooLarge),
        (u64::MAX, RsaKeyError::ExponentTooLarge),
    ] {
        assert_eq!(RsaPublicKey::from_parts(&n, e), Err(want), "e = {e}");
    }
    assert!(RsaPublicKey::from_parts(&n, 65_537).is_ok());
    assert!(RsaPublicKey::from_parts(&n, u64::from(u32::MAX)).is_ok());
}

/// An SPKI from raw INTEGER contents, so non-canonical encodings can be built.
fn spki_with(n_content: &[u8], e_content: &[u8], alg: &[u8], unused_bits: u8) -> Vec<u8> {
    let mut ints = Vec::new();
    push_tlv(&mut ints, TAG_INTEGER, n_content);
    push_tlv(&mut ints, TAG_INTEGER, e_content);
    let mut seq = Vec::new();
    push_tlv(&mut seq, TAG_SEQUENCE, &ints);
    let mut bits = vec![unused_bits];
    bits.extend_from_slice(&seq);
    let mut body = Vec::new();
    push_tlv(&mut body, TAG_SEQUENCE, alg);
    push_tlv(&mut body, TAG_BIT_STRING, &bits);
    let mut out = Vec::new();
    push_tlv(&mut out, TAG_SEQUENCE, &body);
    out
}

#[test]
fn non_canonical_or_foreign_spki_is_refused() {
    let key = kat_key();
    let mut n = vec![0x00]; // sign octet: the KAT modulus has its high bit set
    n.extend_from_slice(&key.n.to_bytes_be());
    let e = [0x01, 0x00, 0x01];

    // The helper reproduces the canonical form, so the refusals below are
    // about the one thing each changes.
    let canonical = spki_with(&n, &e, &RSA_ENCRYPTION_ALG_ID, 0);
    assert_eq!(canonical, key.spki_der());
    assert!(RsaPublicKey::from_spki_der(&canonical).is_ok());

    let mut trailing = canonical.clone();
    trailing.push(0x00);
    assert_eq!(
        RsaPublicKey::from_spki_der(&trailing),
        Err(RsaKeyError::NotCanonical)
    );

    let mut extra_zero = vec![0x00];
    extra_zero.extend_from_slice(&n);
    assert_eq!(
        RsaPublicKey::from_spki_der(&spki_with(&extra_zero, &e, &RSA_ENCRYPTION_ALG_ID, 0)),
        Err(RsaKeyError::NotCanonical)
    );
    assert_eq!(
        RsaPublicKey::from_spki_der(&spki_with(
            &n,
            &[0x00, 0x01, 0x00, 0x01],
            &RSA_ENCRYPTION_ALG_ID,
            0
        )),
        Err(RsaKeyError::NotCanonical)
    );

    // Negative modulus: the sign octet dropped.
    assert!(matches!(
        RsaPublicKey::from_spki_der(&spki_with(&n[1..], &e, &RSA_ENCRYPTION_ALG_ID, 0)),
        Err(RsaKeyError::Malformed(_))
    ));

    // rsaEncryption without the NULL parameters.
    assert!(matches!(
        RsaPublicKey::from_spki_der(&spki_with(&n, &e, &RSA_ENCRYPTION_ALG_ID[..11], 0)),
        Err(RsaKeyError::Malformed(_))
    ));

    // RSASSA-PSS key OID (1.2.840.113549.1.1.10).
    let mut pss = RSA_ENCRYPTION_ALG_ID;
    pss[10] = 0x0a;
    assert!(matches!(
        RsaPublicKey::from_spki_der(&spki_with(&n, &e, &pss, 0)),
        Err(RsaKeyError::Malformed(_))
    ));

    assert!(matches!(
        RsaPublicKey::from_spki_der(&spki_with(&n, &e, &RSA_ENCRYPTION_ALG_ID, 1)),
        Err(RsaKeyError::Malformed(_))
    ));

    // Exponent wider than 64 bits.
    assert_eq!(
        RsaPublicKey::from_spki_der(&spki_with(&n, &[0x01; 9], &RSA_ENCRYPTION_ALG_ID, 0)),
        Err(RsaKeyError::ExponentTooLarge)
    );

    // Every truncation of a valid key is refused without a panic.
    for cut in 0..canonical.len() {
        assert!(
            RsaPublicKey::from_spki_der(&canonical[..cut]).is_err(),
            "{cut}"
        );
    }
}

// ---------------------------------------------------------------------------
// Wycheproof (C2SP/wycheproof, testvectors_v1)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct WycheproofFile {
    #[serde(rename = "numberOfTests")]
    number_of_tests: usize,
    #[serde(rename = "testGroups")]
    test_groups: Vec<WycheproofGroup>,
}

#[derive(Deserialize)]
struct WycheproofGroup {
    sha: String,
    #[serde(rename = "publicKeyDer")]
    public_key_der: String,
    tests: Vec<WycheproofTest>,
}

#[derive(Deserialize)]
struct WycheproofTest {
    #[serde(rename = "tcId")]
    tc_id: u32,
    msg: String,
    sig: String,
    result: WycheproofResult,
    flags: Vec<String>,
}

#[derive(Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
enum WycheproofResult {
    Valid,
    Invalid,
    /// Wycheproof's "legacy, may be accepted" class. In these files it is only
    /// `MissingNull` (DigestInfo without NULL parameters); this verifier
    /// refuses it — one valid encoding per digest.
    Acceptable,
}

#[derive(Default, Debug)]
struct Tally {
    accepted_valid: usize,
    rejected_invalid: usize,
    rejected_acceptable: usize,
    /// Valid vectors under a key this verifier refuses to admit: Wycheproof's
    /// `SmallPublicKey` groups (e = 3), below the 65537 floor.
    key_refused_valid: usize,
}

fn run(name: &str, json: &str) -> Tally {
    let file: WycheproofFile = serde_json::from_str(json).unwrap();
    let mut tally = Tally::default();
    let mut seen = 0;
    for group in &file.test_groups {
        let hash = match group.sha.as_str() {
            "SHA-256" => HashAlg::Sha256,
            "SHA-384" => HashAlg::Sha384,
            other => panic!("{name}: unexpected hash {other}"),
        };
        let der = hex::decode(&group.public_key_der).unwrap();
        let key = match RsaPublicKey::from_spki_der(&der) {
            Ok(key) => key,
            Err(e) => {
                assert_eq!(e, RsaKeyError::ExponentTooSmall, "{name}");
                for t in &group.tests {
                    assert_eq!(t.result, WycheproofResult::Valid, "{name} #{}", t.tc_id);
                    assert!(t.flags.iter().any(|f| f == "SmallPublicKey"));
                    tally.key_refused_valid += 1;
                    seen += 1;
                }
                continue;
            }
        };
        // Wycheproof's DER is the canonical encoding: byte identity holds.
        assert_eq!(key.spki_der(), der.as_slice(), "{name}");
        for t in &group.tests {
            seen += 1;
            let digest = hash.digest(&hex::decode(&t.msg).unwrap());
            let sig = hex::decode(&t.sig).unwrap();
            let ok = key.verify_pkcs1v15(hash, &digest, &sig).is_ok();
            match (t.result, ok) {
                (WycheproofResult::Valid, true) => tally.accepted_valid += 1,
                (WycheproofResult::Invalid, false) => tally.rejected_invalid += 1,
                (WycheproofResult::Acceptable, false) => tally.rejected_acceptable += 1,
                (result, ok) => panic!(
                    "{name} #{}: expected {result:?}, verifier said ok={ok} ({:?})",
                    t.tc_id, t.flags
                ),
            }
        }
    }
    // A filter that matches nothing proves nothing: every vector ran.
    assert_eq!(seen, file.number_of_tests, "{name}");
    tally
}

/// Reds on any accepted-invalid (a forgery class) or refused-valid vector.
/// The counts are asserted too, so a fixture that silently stops running
/// vectors reds instead of passing vacuously.
#[test]
fn wycheproof_vectors() {
    let cases = [
        (
            "2048/SHA-256",
            include_str!("../tests/fixtures/wycheproof/rsa_signature_2048_sha256_test.json"),
            Tally {
                accepted_valid: 7,
                rejected_invalid: 249,
                rejected_acceptable: 1,
                key_refused_valid: 2,
            },
        ),
        (
            "2048/SHA-384",
            include_str!("../tests/fixtures/wycheproof/rsa_signature_2048_sha384_test.json"),
            Tally {
                accepted_valid: 7,
                rejected_invalid: 250,
                rejected_acceptable: 1,
                key_refused_valid: 0,
            },
        ),
        (
            "3072/SHA-384",
            include_str!("../tests/fixtures/wycheproof/rsa_signature_3072_sha384_test.json"),
            Tally {
                accepted_valid: 7,
                rejected_invalid: 251,
                rejected_acceptable: 1,
                key_refused_valid: 0,
            },
        ),
        (
            "4096/SHA-384",
            include_str!("../tests/fixtures/wycheproof/rsa_signature_4096_sha384_test.json"),
            Tally {
                accepted_valid: 7,
                rejected_invalid: 251,
                rejected_acceptable: 1,
                key_refused_valid: 0,
            },
        ),
    ];
    for (name, json, want) in cases {
        let got = run(name, json);
        assert_eq!(got.accepted_valid, want.accepted_valid, "{name}: {got:?}");
        assert_eq!(
            got.rejected_invalid, want.rejected_invalid,
            "{name}: {got:?}"
        );
        assert_eq!(
            got.rejected_acceptable, want.rejected_acceptable,
            "{name}: {got:?}"
        );
        assert_eq!(
            got.key_refused_valid, want.key_refused_valid,
            "{name}: {got:?}"
        );
    }
}

/// A well-formed 8192-bit key is above the modulus bound.
#[test]
fn wycheproof_8192_bit_key_is_refused() {
    #[derive(Deserialize)]
    struct Key {
        #[serde(rename = "publicKeyDer")]
        public_key_der: String,
    }
    let k: Key = serde_json::from_str(include_str!(
        "../tests/fixtures/wycheproof/rsa_8192_public_key.json"
    ))
    .unwrap();
    assert_eq!(
        RsaPublicKey::from_spki_der(&hex::decode(k.public_key_der).unwrap()),
        Err(RsaKeyError::ModulusSize { bits: 8192 })
    );
}

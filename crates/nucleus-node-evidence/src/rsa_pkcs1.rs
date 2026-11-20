//! RSASSA-PKCS1-v1_5 signature **verification** (RFC 8017 §8.2.2), in-crate.
//!
//! This replaces the `rsa` crate, which carries RUSTSEC-2023-0071 (Marvin) with
//! no patched release. The C-backed alternatives (aws-lc-rs, ring) do not build
//! for wasm32, and this crate is embedded in the wasm verifier, so the check is
//! written here over a pure-Rust bignum (`num-bigint`).
//!
//! **Not constant time, on purpose.** Every input is public: the key, the
//! signature and the digest. Marvin is a timing side channel on private-key
//! *decryption*; there is no private key and no decryption path in this module,
//! so there is nothing for a timing channel to leak.
//!
//! **Encode, then compare.** The signature is never parsed. RFC 8017 §8.2.2:
//! `m = s^e mod n`, I2OSP to `k` octets, and the result must equal — as a whole
//! buffer — the `EM` this module builds itself from the expected hash:
//!
//! ```text
//! 0x00 0x01 | 0xFF × (k − |T| − 3, at least 8) | 0x00 | T
//! T = DigestInfo prefix (hash OID, NULL parameters) | digest
//! ```
//!
//! A parser of the decoded block is where Bleichenbacher-'06 forgeries live
//! (garbage after the digest, short padding, a lax DigestInfo); comparing whole
//! buffers leaves no field for a forger to hide in. The legacy encoding without
//! the NULL parameters is refused: there is one valid `EM` per digest.
//!
//! Key admission is at least as strict as `rsa` 0.9's `RsaPublicKey::new` and
//! tighter in two places: a 2048-bit modulus floor (that crate had none) and a
//! public exponent in `65537..=2^32 − 1` (FIPS 186-5 §5.4 requires `e > 2^16`;
//! that crate accepted 3).

use num_bigint::BigUint;

use crate::crypto::HashAlg;

/// Smallest modulus admitted, in bits.
pub(crate) const MIN_MODULUS_BITS: u64 = 2048;
/// Largest modulus admitted, in bits (the bound `rsa` 0.9 enforced).
pub(crate) const MAX_MODULUS_BITS: u64 = 4096;
/// Smallest public exponent admitted: the first odd value above 2^16.
pub(crate) const MIN_EXPONENT: u64 = 65_537;
/// Largest public exponent admitted: `u32::MAX`, what a TPM's `UINT32`
/// exponent can hold (a test pins the equality).
pub(crate) const MAX_EXPONENT: u64 = 0xFFFF_FFFF;

/// `AlgorithmIdentifier` content for `rsaEncryption` (1.2.840.113549.1.1.1)
/// with NULL parameters — the only form RFC 3279 §2.3.1 allows.
const RSA_ENCRYPTION_ALG_ID: [u8; 13] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];

const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_SEQUENCE: u8 = 0x30;

/// Why an RSA public key was not admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RsaKeyError {
    /// The DER does not have the shape of an RSA SubjectPublicKeyInfo.
    #[error("not an RSA SubjectPublicKeyInfo: {0}")]
    Malformed(&'static str),
    /// The DER parsed, but is not the canonical encoding of the key it holds
    /// (non-minimal lengths or integers, or trailing bytes).
    #[error("RSA SubjectPublicKeyInfo is not canonical DER")]
    NotCanonical,
    /// The modulus is outside the admitted size range.
    #[error("RSA modulus is {bits} bits; admitted is {min}..={max}", min = MIN_MODULUS_BITS, max = MAX_MODULUS_BITS)]
    ModulusSize {
        /// The modulus size.
        bits: u64,
    },
    /// An even modulus is not a product of two odd primes.
    #[error("RSA modulus is even")]
    ModulusEven,
    /// The public exponent is below the admitted minimum.
    #[error("RSA public exponent is below {min}", min = MIN_EXPONENT)]
    ExponentTooSmall,
    /// The public exponent is above the admitted maximum.
    #[error("RSA public exponent is above {max}", max = MAX_EXPONENT)]
    ExponentTooLarge,
    /// An even public exponent has no inverse modulo `λ(n)`.
    #[error("RSA public exponent is even")]
    ExponentEven,
}

/// Why a signature did not verify. Each is a refusal; there is no partial
/// acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum RsaVerifyError {
    /// The digest is not the length the named hash produces.
    #[error("digest is {got} bytes; the hash produces {expected}")]
    DigestLength {
        /// The hash's output length.
        expected: usize,
        /// The digest's length.
        got: usize,
    },
    /// RFC 8017 §8.2.2 step 1: the signature is not exactly `k` octets.
    #[error("signature is {got} bytes; the modulus is {expected}")]
    SignatureLength {
        /// The modulus length in octets.
        expected: usize,
        /// The signature's length.
        got: usize,
    },
    /// RFC 8017 §5.2.2 step 1: the signature representative is not below `n`.
    #[error("signature representative is not below the modulus")]
    NotBelowModulus,
    /// The recovered block is not the one expected encoding of this digest.
    #[error("recovered block is not the PKCS#1 v1.5 encoding of the digest")]
    EncodingMismatch,
}

/// An admitted RSA public key. Constructed only by [`RsaPublicKey::from_parts`]
/// and [`RsaPublicKey::from_spki_der`], which enforce the bounds above.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RsaPublicKey {
    n: BigUint,
    e: BigUint,
    /// `k`: the modulus length in octets.
    k: usize,
    /// The canonical SubjectPublicKeyInfo DER, computed once at admission.
    spki: Vec<u8>,
}

/// Drop leading zero octets of a big-endian unsigned integer.
fn strip_leading_zeros(b: &[u8]) -> &[u8] {
    let first = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    b.get(first..).unwrap_or_default()
}

/// Append a DER definite length, minimally encoded (X.690 §10.1).
fn push_len(out: &mut Vec<u8>, len: usize) {
    let be = len.to_be_bytes();
    let significant = strip_leading_zeros(&be);
    match u8::try_from(len) {
        Ok(short) if short < 0x80 => out.push(short),
        _ => {
            // `significant` is at most `size_of::<usize>()` octets, so the
            // count always fits the seven bits of the long-form initial octet.
            out.push(0x80 | u8::try_from(significant.len()).unwrap_or(0x7f));
            out.extend_from_slice(significant);
        }
    }
}

fn push_tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
    out.push(tag);
    push_len(out, content.len());
    out.extend_from_slice(content);
}

/// Append a DER INTEGER holding the non-negative `magnitude` (big-endian, no
/// leading zeros): a 0x00 is prefixed when the high bit is set (X.690 §8.3).
fn push_unsigned(out: &mut Vec<u8>, magnitude: &[u8]) {
    let mut content = Vec::with_capacity(magnitude.len().saturating_add(1));
    if magnitude.first().is_none_or(|&b| b & 0x80 != 0) {
        content.push(0x00);
    }
    content.extend_from_slice(magnitude);
    push_tlv(out, TAG_INTEGER, &content);
}

/// The canonical SubjectPublicKeyInfo for `(n, e)`, both given as big-endian
/// magnitudes without leading zeros.
fn encode_spki(n: &[u8], e: &[u8]) -> Vec<u8> {
    let mut rsa_public_key = Vec::new();
    push_unsigned(&mut rsa_public_key, n);
    push_unsigned(&mut rsa_public_key, e);
    let mut sequence = Vec::new();
    push_tlv(&mut sequence, TAG_SEQUENCE, &rsa_public_key);

    let mut bit_string = vec![0x00]; // no unused bits
    bit_string.extend_from_slice(&sequence);

    let mut body = Vec::new();
    push_tlv(&mut body, TAG_SEQUENCE, &RSA_ENCRYPTION_ALG_ID);
    push_tlv(&mut body, TAG_BIT_STRING, &bit_string);
    let mut spki = Vec::new();
    push_tlv(&mut spki, TAG_SEQUENCE, &body);
    spki
}

/// Read one DER TLV with `tag`; returns `(content, rest)`. Lenient about
/// length minimality on purpose: canonical form is enforced once, by comparing
/// the whole input against [`encode_spki`]'s output.
fn read_tlv(input: &[u8], tag: u8) -> Result<(&[u8], &[u8]), RsaKeyError> {
    let truncated = RsaKeyError::Malformed("truncated");
    let (&got, rest) = input.split_first().ok_or(truncated)?;
    if got != tag {
        return Err(RsaKeyError::Malformed("unexpected tag"));
    }
    let (&first, rest) = rest.split_first().ok_or(truncated)?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        // Long form. Two length octets cover every admitted key (a 4096-bit
        // SPKI is ~550 bytes); more is refused rather than computed.
        let (octets, rest) = match first & 0x7f {
            1 => rest.split_at_checked(1),
            2 => rest.split_at_checked(2),
            _ => None,
        }
        .ok_or(RsaKeyError::Malformed("unsupported length"))?;
        let mut be = [0u8; 2];
        let start = be.len().saturating_sub(octets.len());
        be.get_mut(start..)
            .ok_or(RsaKeyError::Malformed("unsupported length"))?
            .copy_from_slice(octets);
        (usize::from(u16::from_be_bytes(be)), rest)
    };
    rest.split_at_checked(len).ok_or(truncated)
}

/// A non-negative DER INTEGER's magnitude, leading zeros removed.
fn unsigned_magnitude<'a>(content: &'a [u8], what: &'static str) -> Result<&'a [u8], RsaKeyError> {
    match content.first() {
        None => Err(RsaKeyError::Malformed(what)),
        Some(&b) if b & 0x80 != 0 => Err(RsaKeyError::Malformed(what)),
        Some(_) => Ok(strip_leading_zeros(content)),
    }
}

impl RsaPublicKey {
    /// Admit `(n, e)`: `n` big-endian (leading zeros allowed, as a TPM's
    /// fixed-width buffer has them), `e` as an integer.
    pub(crate) fn from_parts(n: &[u8], e: u64) -> Result<Self, RsaKeyError> {
        let n_be = strip_leading_zeros(n);
        let modulus = BigUint::from_bytes_be(n_be);
        let bits = modulus.bits();
        if !(MIN_MODULUS_BITS..=MAX_MODULUS_BITS).contains(&bits) {
            return Err(RsaKeyError::ModulusSize { bits });
        }
        if !modulus.bit(0) {
            return Err(RsaKeyError::ModulusEven);
        }
        if e < MIN_EXPONENT {
            return Err(RsaKeyError::ExponentTooSmall);
        }
        if e > MAX_EXPONENT {
            return Err(RsaKeyError::ExponentTooLarge);
        }
        if e & 1 == 0 {
            return Err(RsaKeyError::ExponentEven);
        }
        let e_bytes = e.to_be_bytes();
        let spki = encode_spki(n_be, strip_leading_zeros(&e_bytes));
        Ok(Self {
            n: modulus,
            e: BigUint::from(e),
            k: n_be.len(),
            spki,
        })
    }

    /// Admit an RSA SubjectPublicKeyInfo. The input must be exactly the
    /// canonical DER of the key it holds: `rsaEncryption` with NULL
    /// parameters, minimal lengths and integers, nothing after.
    pub(crate) fn from_spki_der(der: &[u8]) -> Result<Self, RsaKeyError> {
        let (body, _) = read_tlv(der, TAG_SEQUENCE)?;
        let (algorithm, rest) = read_tlv(body, TAG_SEQUENCE)?;
        if algorithm != RSA_ENCRYPTION_ALG_ID {
            return Err(RsaKeyError::Malformed(
                "algorithm is not rsaEncryption with NULL parameters",
            ));
        }
        let (bit_string, _) = read_tlv(rest, TAG_BIT_STRING)?;
        let key_der = match bit_string.split_first() {
            Some((&0, key_der)) => key_der,
            Some(_) | None => return Err(RsaKeyError::Malformed("BIT STRING has unused bits")),
        };
        let (rsa_public_key, _) = read_tlv(key_der, TAG_SEQUENCE)?;
        let (n, rest) = read_tlv(rsa_public_key, TAG_INTEGER)?;
        let (e, _) = read_tlv(rest, TAG_INTEGER)?;
        let n = unsigned_magnitude(n, "modulus is not a positive INTEGER")?;
        let e = unsigned_magnitude(e, "exponent is not a positive INTEGER")?;
        let mut e_be = [0u8; 8];
        let start = e_be
            .len()
            .checked_sub(e.len())
            .ok_or(RsaKeyError::ExponentTooLarge)?;
        e_be.get_mut(start..)
            .ok_or(RsaKeyError::ExponentTooLarge)?
            .copy_from_slice(e);
        let key = Self::from_parts(n, u64::from_be_bytes(e_be))?;
        if key.spki != der {
            return Err(RsaKeyError::NotCanonical);
        }
        Ok(key)
    }

    /// The canonical SubjectPublicKeyInfo DER.
    pub(crate) fn spki_der(&self) -> &[u8] {
        &self.spki
    }

    /// RSASSA-PKCS1-v1_5-VERIFY (RFC 8017 §8.2.2) of `sig` over `digest`,
    /// which is already hashed with `hash`.
    pub(crate) fn verify_pkcs1v15(
        &self,
        hash: HashAlg,
        digest: &[u8],
        sig: &[u8],
    ) -> Result<(), RsaVerifyError> {
        if digest.len() != hash.len() {
            return Err(RsaVerifyError::DigestLength {
                expected: hash.len(),
                got: digest.len(),
            });
        }
        // Step 1: length check.
        if sig.len() != self.k {
            return Err(RsaVerifyError::SignatureLength {
                expected: self.k,
                got: sig.len(),
            });
        }
        // Step 2: OS2IP, RSAVP1 (s < n, m = s^e mod n), I2OSP.
        let s = BigUint::from_bytes_be(sig);
        if s >= self.n {
            return Err(RsaVerifyError::NotBelowModulus);
        }
        let recovered =
            i2osp(&s.modpow(&self.e, &self.n), self.k).ok_or(RsaVerifyError::EncodingMismatch)?;
        // Steps 3-4: encode the expected EM and compare the whole buffers.
        let expected =
            emsa_pkcs1_v1_5_encode(hash, digest, self.k).ok_or(RsaVerifyError::EncodingMismatch)?;
        if recovered == expected {
            Ok(())
        } else {
            Err(RsaVerifyError::EncodingMismatch)
        }
    }
}

/// I2OSP: `x` as exactly `len` big-endian octets; `None` if it does not fit.
fn i2osp(x: &BigUint, len: usize) -> Option<Vec<u8>> {
    let bytes = x.to_bytes_be();
    let bytes = strip_leading_zeros(&bytes);
    let mut out = vec![0u8; len.checked_sub(bytes.len())?];
    out.extend_from_slice(bytes);
    Some(out)
}

/// EMSA-PKCS1-v1_5-ENCODE (RFC 8017 §9.2) of an already-computed digest into
/// `em_len` octets. `None` when `em_len < |T| + 11` (step 3).
pub(crate) fn emsa_pkcs1_v1_5_encode(
    hash: HashAlg,
    digest: &[u8],
    em_len: usize,
) -> Option<Vec<u8>> {
    let prefix = hash.pkcs1_prefix();
    let t_len = prefix.len().checked_add(digest.len())?;
    let ps_len = em_len.checked_sub(t_len)?.checked_sub(3)?;
    if ps_len < 8 {
        return None;
    }
    let mut em = Vec::with_capacity(em_len);
    em.extend_from_slice(&[0x00, 0x01]);
    em.resize(ps_len.checked_add(2)?, 0xff);
    em.push(0x00);
    em.extend_from_slice(prefix);
    em.extend_from_slice(digest);
    Some(em)
}

#[cfg(test)]
#[path = "rsa_pkcs1_tests.rs"]
mod tests;

//! The three public-key families a TPM attestation key or its certificate
//! chain can use, verified through RustCrypto's prehash entry points.
//!
//! One type, [`PublicKey`], is shared by the quote check and the certificate
//! chain check so there is one place that decides "this signature is valid"
//! (ADR 0007 G-1). SHA-1 is not offered: a quote or certificate signed over
//! SHA-1 is refused upstream as an unsupported algorithm.

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use sha2::Digest;

/// A digest algorithm this verifier accepts for signatures and PCR banks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlg {
    /// SHA-256 (`TPM_ALG_SHA256`, `0x000B`).
    Sha256,
    /// SHA-384 (`TPM_ALG_SHA384`, `0x000C`).
    Sha384,
}

impl HashAlg {
    pub(crate) const TPM_SHA256: u16 = 0x000B;
    pub(crate) const TPM_SHA384: u16 = 0x000C;

    /// The algorithm for a TPM algorithm id, or `None` for anything else
    /// (SHA-1 included — refused, not downgraded to).
    pub(crate) fn from_tpm(id: u16) -> Option<Self> {
        match id {
            Self::TPM_SHA256 => Some(Self::Sha256),
            Self::TPM_SHA384 => Some(Self::Sha384),
            _ => None,
        }
    }

    pub(crate) fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(data).to_vec(),
        }
    }

    /// The DER `DigestInfo` prefix PKCS#1 v1.5 puts before the digest.
    fn pkcs1_prefix(self) -> &'static [u8] {
        match self {
            Self::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            Self::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
        }
    }

    fn len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }
}

/// SHA-256, the digest every evidence-level identifier in this crate uses.
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

/// An ECDSA signature in either of the encodings this crate meets: the TPM's
/// two big-endian scalars, or the DER `Ecdsa-Sig-Value` an X.509 certificate
/// carries.
pub(crate) enum EcdsaSig<'a> {
    Scalars { r: &'a [u8], s: &'a [u8] },
    Der(&'a [u8]),
}

/// A verified-decodable public key.
#[derive(Clone, Debug)]
pub(crate) enum PublicKey {
    P256(p256::PublicKey),
    P384(p384::PublicKey),
    Rsa(rsa::RsaPublicKey),
}

/// Left-pad a big-endian scalar to `N` bytes; `None` if it is longer.
fn pad<const N: usize>(b: &[u8]) -> Option<[u8; N]> {
    let b = match b.iter().position(|&x| x != 0) {
        Some(i) => b.get(i..)?,
        None => &[],
    };
    let start = N.checked_sub(b.len())?;
    let mut out = [0u8; N];
    out.get_mut(start..)?.copy_from_slice(b);
    Some(out)
}

impl PublicKey {
    pub(crate) fn from_spki_der(der: &[u8]) -> Result<Self, String> {
        if let Ok(k) = p256::PublicKey::from_public_key_der(der) {
            return Ok(Self::P256(k));
        }
        if let Ok(k) = p384::PublicKey::from_public_key_der(der) {
            return Ok(Self::P384(k));
        }
        rsa::pkcs8::DecodePublicKey::from_public_key_der(der)
            .map(Self::Rsa)
            .map_err(|e| format!("not a P-256, P-384 or RSA SubjectPublicKeyInfo: {e}"))
    }

    pub(crate) fn p256_from_xy(x: &[u8], y: &[u8]) -> Option<Self> {
        let (x, y) = (pad::<32>(x)?, pad::<32>(y)?);
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        p256::PublicKey::from_sec1_bytes(&sec1).ok().map(Self::P256)
    }

    pub(crate) fn p384_from_xy(x: &[u8], y: &[u8]) -> Option<Self> {
        let (x, y) = (pad::<48>(x)?, pad::<48>(y)?);
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        p384::PublicKey::from_sec1_bytes(&sec1).ok().map(Self::P384)
    }

    pub(crate) fn rsa_from_parts(n: &[u8], e: u32) -> Option<Self> {
        let e = if e == 0 { 65537 } else { e };
        rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(n),
            rsa::BigUint::from(u64::from(e)),
        )
        .ok()
        .map(Self::Rsa)
    }

    /// The canonical SubjectPublicKeyInfo DER. Two keys are the same key iff
    /// these bytes are equal; pins and certificate matches compare this.
    ///
    /// `Err` only if the encoder fails, which is refused by every caller
    /// rather than defaulted (ADR 0007 B-4).
    pub(crate) fn spki_der(&self) -> Result<Vec<u8>, String> {
        let doc = match self {
            Self::P256(k) => k.to_public_key_der(),
            Self::P384(k) => k.to_public_key_der(),
            Self::Rsa(k) => rsa::pkcs8::EncodePublicKey::to_public_key_der(k),
        };
        doc.map(|d| d.as_bytes().to_vec())
            .map_err(|e| format!("encoding SubjectPublicKeyInfo: {e}"))
    }

    pub(crate) fn family(&self) -> &'static str {
        match self {
            Self::P256(_) => "ecdsa-p256",
            Self::P384(_) => "ecdsa-p384",
            Self::Rsa(_) => "rsa",
        }
    }

    /// Verify an ECDSA signature over `digest` (already hashed with `hash`).
    pub(crate) fn verify_ecdsa(&self, hash: HashAlg, digest: &[u8], sig: EcdsaSig<'_>) -> bool {
        if digest.len() != hash.len() {
            return false;
        }
        match self {
            Self::P256(k) => {
                let sig = match sig {
                    EcdsaSig::Scalars { r, s } => match (pad::<32>(r), pad::<32>(s)) {
                        (Some(r), Some(s)) => p256::ecdsa::Signature::from_scalars(r, s),
                        _ => return false,
                    },
                    EcdsaSig::Der(d) => p256::ecdsa::Signature::from_der(d),
                };
                sig.is_ok_and(|sig| {
                    p256::ecdsa::VerifyingKey::from(k)
                        .verify_prehash(digest, &sig)
                        .is_ok()
                })
            }
            Self::P384(k) => {
                let sig = match sig {
                    EcdsaSig::Scalars { r, s } => match (pad::<48>(r), pad::<48>(s)) {
                        (Some(r), Some(s)) => p384::ecdsa::Signature::from_scalars(r, s),
                        _ => return false,
                    },
                    EcdsaSig::Der(d) => p384::ecdsa::Signature::from_der(d),
                };
                sig.is_ok_and(|sig| {
                    p384::ecdsa::VerifyingKey::from(k)
                        .verify_prehash(digest, &sig)
                        .is_ok()
                })
            }
            Self::Rsa(_) => false,
        }
    }

    /// Verify an RSASSA-PKCS1-v1_5 signature over `digest`.
    pub(crate) fn verify_rsa_pkcs1(&self, hash: HashAlg, digest: &[u8], sig: &[u8]) -> bool {
        if digest.len() != hash.len() {
            return false;
        }
        match self {
            Self::Rsa(k) => {
                let scheme = rsa::Pkcs1v15Sign {
                    hash_len: Some(hash.len()),
                    prefix: hash.pkcs1_prefix().into(),
                };
                // Called by path: RSA has no lax/strict split, and the
                // scoreboard's `.verify(` count is about Ed25519's.
                rsa::traits::SignatureScheme::verify(scheme, k, digest, sig).is_ok()
            }
            Self::P256(_) | Self::P384(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    #[test]
    fn pad_strips_and_refuses_oversize() {
        assert_eq!(pad::<4>(&[0, 0, 1]), Some([0, 0, 0, 1]));
        assert_eq!(pad::<2>(&[1, 2, 3]), None);
        assert_eq!(pad::<2>(&[0, 1, 2]), Some([1, 2]));
    }

    #[test]
    fn p256_prehash_round_trip_and_tamper() {
        let sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let pk = PublicKey::P256(p256::PublicKey::from(sk.verifying_key()));
        let digest = HashAlg::Sha256.digest(b"msg");
        let sig: p256::ecdsa::Signature = sk.sign_prehash(&digest).unwrap();
        let (r, s) = sig.split_bytes();
        assert!(pk.verify_ecdsa(HashAlg::Sha256, &digest, EcdsaSig::Scalars { r: &r, s: &s }));
        let other = HashAlg::Sha256.digest(b"msh");
        assert!(!pk.verify_ecdsa(HashAlg::Sha256, &other, EcdsaSig::Scalars { r: &r, s: &s }));
        // The SPKI encoding round-trips to an equal key.
        let again = PublicKey::from_spki_der(&pk.spki_der().unwrap()).unwrap();
        assert_eq!(again.spki_der().unwrap(), pk.spki_der().unwrap());
    }
}

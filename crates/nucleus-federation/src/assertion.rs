// SPDX-License-Identifier: MIT
//
//! The outbound assertion: whose it is, how long it lives, and who signs it.
//!
//! # Why the subject type cannot be deserialized
//!
//! The one thing an assertion must never get wrong is `sub`. A provider's
//! federation rule matches on it, so an assertion in the wrong name is a
//! credential for the wrong principal. The host knows the pod's SPIFFE ID
//! because it issued the SVID; the guest only claims one. [`AssertionSubject`]
//! is therefore built by host code from host-observed values and has no
//! `Deserialize` impl: there is no path by which a JSON body — the shape
//! everything a guest sends arrives in — becomes a subject. The claims type
//! can only be built from a subject.
//!
//! ```compile_fail
//! // A guest-supplied body cannot become a subject: the type is not Deserialize.
//! let _ = serde_json::from_str::<nucleus_federation::AssertionSubject>(
//!     r#"{"pod_spiffe_id":"spiffe://td/attacker"}"#,
//! );
//! ```
//!
//! ```compile_fail
//! // Nor can a claims set be read back in and re-signed.
//! let _ = serde_json::from_str::<nucleus_federation::AssertionClaims>("{}");
//! ```
//!
//! # Why the signer returns exactly 64 bytes
//!
//! [`AssertionSigner::sign_es256`] returns an [`Es256Signature`], a fixed
//! 64-byte P-256 `r||s`. That is the JOSE encoding (RFC 7518 §3.4) — not DER,
//! which is what most ECDSA APIs return and what a verifier will reject — and
//! it is also the pin: an RSA or Ed25519 signer cannot produce the type, and
//! [`mint`] writes [`SIGNING_ALG`] into the header itself rather than asking
//! the signer. There is no second algorithm to downgrade to. The trait has no
//! associated constant so that the node can hold an `Arc<dyn AssertionSigner>`
//! and swap a KMS-backed signer in without generics leaking outward.

use std::fmt;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// The one algorithm this crate signs with. Written into every header by
/// [`mint`]; `ci/alg-pin-check.sh` asserts it is the only signing algorithm
/// declared in the crate.
pub const SIGNING_ALG: &str = "ES256"; // alg-pin-allow: the single pinned SIGNING algorithm (T04: one issuer, one algorithm)

/// Assertion lifetime when the caller has no reason to choose another.
/// Five minutes covers a token exchange with clock skew to spare, and is
/// short enough that a leaked assertion is stale before it can be used
/// much.
pub const DEFAULT_TTL: Duration = Duration::from_secs(300);

/// The longest assertion this crate will build. A longer one is a
/// long-lived credential by another name.
pub const MAX_TTL: Duration = Duration::from_secs(3600);

/// The pod identity an assertion is minted for, as the **host** observed it.
///
/// Deliberately not `Deserialize` (see the module docs and the compile-fail
/// doctest there): every field comes from the node's own records — the SVID
/// it issued, the certificate chain it admitted — never from a request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionSubject {
    pod_spiffe_id: String,
    tenant: String,
    root_identity: String,
    cert_fingerprint: String,
}

impl AssertionSubject {
    /// A subject from host-observed values.
    ///
    /// - `pod_spiffe_id` becomes `sub`; it must be a `spiffe://` URI.
    /// - `tenant` becomes `nucleus_tenant` (the caller's trust domain).
    /// - `root_identity` becomes `nucleus_root`, the identity at the root of
    ///   the pod's authority-certificate chain.
    /// - `cert_fingerprint` becomes `nucleus_chain`, the fingerprint of the
    ///   certificate the pod runs under.
    pub fn new(
        pod_spiffe_id: impl Into<String>,
        tenant: impl Into<String>,
        root_identity: impl Into<String>,
        cert_fingerprint: impl Into<String>,
    ) -> Result<Self, ClaimsError> {
        let pod_spiffe_id = pod_spiffe_id.into();
        let rest = pod_spiffe_id
            .strip_prefix("spiffe://")
            .ok_or(ClaimsError::Subject)?;
        if rest.is_empty() || rest.starts_with('/') {
            return Err(ClaimsError::Subject);
        }
        let (tenant, root_identity, cert_fingerprint) =
            (tenant.into(), root_identity.into(), cert_fingerprint.into());
        if tenant.is_empty() || root_identity.is_empty() || cert_fingerprint.is_empty() {
            return Err(ClaimsError::Subject);
        }
        Ok(Self {
            pod_spiffe_id,
            tenant,
            root_identity,
            cert_fingerprint,
        })
    }

    /// The pod's SPIFFE ID, which is the assertion's `sub`.
    pub fn pod_spiffe_id(&self) -> &str {
        &self.pod_spiffe_id
    }
}

/// Why a claims set could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClaimsError {
    /// The subject was not a usable host-observed identity.
    #[error("assertion subject is not a valid host-observed pod identity")]
    Subject,
    /// The issuer is not an `https` URL.
    #[error("assertion issuer must be an https URL")]
    Issuer,
    /// Audience or upstream name was empty.
    #[error("assertion audience and upstream must be non-empty")]
    Empty,
    /// The requested lifetime is zero or above [`MAX_TTL`].
    #[error("assertion lifetime must be between 1s and {}s", MAX_TTL.as_secs())]
    Lifetime,
    /// The system random source failed, so no `jti` could be drawn.
    #[error("no randomness available for jti")]
    Random,
}

/// The claims of one outbound assertion.
///
/// Flat string claims only: providers' federation rules match top-level
/// strings, and a nested `act` would invert which party is `sub`. Built only
/// by [`AssertionClaims::new`], which takes an [`AssertionSubject`]; not
/// `Deserialize`, so a claims set cannot be read in from elsewhere and
/// re-signed.
#[derive(Debug, Clone, Serialize)]
pub struct AssertionClaims {
    iss: String,
    sub: String,
    aud: String,
    iat: u64,
    exp: u64,
    jti: String,
    nucleus_tenant: String,
    nucleus_upstream: String,
    nucleus_root: String,
    nucleus_chain: String,
}

impl AssertionClaims {
    /// Claims for one exchange with `audience` on behalf of `subject`,
    /// issued at `now_unix` and living `ttl` (pass [`DEFAULT_TTL`] unless the
    /// upstream's registry entry says otherwise).
    ///
    /// Draws a fresh 128-bit `jti` every call. An assertion is never reused:
    /// a failed exchange re-mints, so a provider's single-use `jti` store
    /// never sees the same value twice from nucleus.
    pub fn new(
        subject: &AssertionSubject,
        issuer: &str,
        audience: &str,
        upstream: &str,
        now_unix: u64,
        ttl: Duration,
    ) -> Result<Self, ClaimsError> {
        let issuer_ok = issuer
            .strip_prefix("https://")
            .is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/'));
        if !issuer_ok {
            return Err(ClaimsError::Issuer);
        }
        if audience.is_empty() || upstream.is_empty() {
            return Err(ClaimsError::Empty);
        }
        if ttl.is_zero() || ttl > MAX_TTL {
            return Err(ClaimsError::Lifetime);
        }
        Ok(Self {
            iss: issuer.to_string(),
            sub: subject.pod_spiffe_id.clone(),
            aud: audience.to_string(),
            iat: now_unix,
            exp: now_unix.saturating_add(ttl.as_secs()),
            jti: fresh_jti()?,
            nucleus_tenant: subject.tenant.clone(),
            nucleus_upstream: upstream.to_string(),
            nucleus_root: subject.root_identity.clone(),
            nucleus_chain: subject.cert_fingerprint.clone(),
        })
    }

    /// `iss` — recorded on the receipt.
    pub fn issuer(&self) -> &str {
        &self.iss
    }
    /// `sub` — the pod's SPIFFE ID.
    pub fn subject(&self) -> &str {
        &self.sub
    }
    /// `aud` — the upstream's registered audience.
    pub fn audience(&self) -> &str {
        &self.aud
    }
    /// `jti` — recorded on the receipt, so an exchange can be matched to the
    /// provider's log without the assertion itself being kept.
    pub fn jti(&self) -> &str {
        &self.jti
    }
    /// `iat`, seconds since the epoch.
    pub fn issued_at(&self) -> u64 {
        self.iat
    }
    /// `exp`, seconds since the epoch.
    pub fn expires_at(&self) -> u64 {
        self.exp
    }
}

/// 128 random bits, base64url without padding (22 characters).
fn fresh_jti() -> Result<String, ClaimsError> {
    let mut bytes = [0u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| ClaimsError::Random)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// A compact-serialized JWT (`header.payload.signature`).
///
/// It is a bearer credential for the length of its life — anyone holding it
/// can present it to the token endpoint — so it prints as `[redacted]` and is
/// wiped on drop. [`CompactJwt::expose`] is the one way to the text, named to
/// be greppable.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CompactJwt(String);

impl CompactJwt {
    /// Wrap a compact JWT obtained elsewhere (for example a workload's own
    /// OIDC token being exchanged).
    pub fn new(compact: impl Into<String>) -> Self {
        Self(compact.into())
    }

    /// The compact serialization, for the one place it is sent.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CompactJwt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CompactJwt([redacted])")
    }
}

/// A P-256 ECDSA signature in JOSE form: `r || s`, 32 bytes each.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Es256Signature(pub [u8; 64]);

impl fmt::Debug for Es256Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Es256Signature(..)")
    }
}

/// Why signing failed. Carries nothing about the key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SignError {
    /// The key bytes were not a P-256 PKCS#8 private key.
    #[error("signing key is not a P-256 PKCS#8 key")]
    Key,
    /// The signing operation itself failed.
    #[error("signing failed")]
    Sign,
    /// The signer returned a key id that is not base64url.
    #[error("signer key id is not base64url")]
    Kid,
    /// The claims could not be serialized.
    #[error("assertion claims could not be serialized")]
    Encode,
}

/// A signer for outbound assertions. ES256 only, by its return type.
///
/// Object-safe so the node can hold `Arc<dyn AssertionSigner>`.
/// Implementations must never expose private key material.
pub trait AssertionSigner: Send + Sync {
    /// The key id written into the header. For the file-backed signer this is
    /// the RFC 7638 thumbprint of the public key, so it is derived from the
    /// key rather than chosen.
    fn kid(&self) -> &str;

    /// Sign `signing_input` (`base64url(header) "." base64url(payload)`)
    /// with ECDSA P-256 / SHA-256.
    fn sign_es256(&self, signing_input: &[u8]) -> Result<Es256Signature, SignError>;

    /// The public half, for publishing in a JWKS.
    fn public_jwk(&self) -> PublicJwk;
}

/// A published P-256 verification key (RFC 7517, RFC 7518 §6.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublicJwk {
    pub kty: &'static str,
    pub crv: &'static str,
    pub x: String,
    pub y: String,
    pub kid: String,
    pub alg: &'static str,
    #[serde(rename = "use")]
    pub use_: &'static str,
}

impl PublicJwk {
    fn p256(x: String, y: String) -> Self {
        let kid = rfc7638_p256_thumbprint(&x, &y);
        Self {
            kty: "EC",
            crv: "P-256",
            x,
            y,
            kid,
            alg: SIGNING_ALG,
            use_: "sig",
        }
    }
}

/// A JWKS document (`{"keys":[...]}`) for the given keys — during rotation,
/// the current key and the next one.
pub fn jwks(keys: &[PublicJwk]) -> serde_json::Value {
    serde_json::json!({ "keys": keys })
}

/// RFC 7638 §3: SHA-256 over the required members in lexicographic order
/// with no whitespace. For an EC key those are `crv`, `kty`, `x`, `y`. The
/// values are base64url, whose alphabet needs no JSON escaping, so building
/// the string directly is exact.
fn rfc7638_p256_thumbprint(x: &str, y: &str) -> String {
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

/// The file-backed ES256 signer: a P-256 key held by `ring`.
///
/// Built from PKCS#8 DER. `ring` does not hand the private scalar back, so
/// once constructed nothing — including this type — can export it.
pub struct EcdsaP256Signer {
    key: EcdsaKeyPair,
    rng: SystemRandom,
    jwk: PublicJwk,
}

impl EcdsaP256Signer {
    /// Load a signer from PKCS#8 DER bytes.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, SignError> {
        let rng = SystemRandom::new();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &rng)
            .map_err(|_| SignError::Key)?;
        // Uncompressed SEC1 point: 0x04 || x (32) || y (32).
        let point = key.public_key().as_ref();
        if point.len() != 65 || point[0] != 0x04 {
            return Err(SignError::Key);
        }
        let jwk = PublicJwk::p256(
            URL_SAFE_NO_PAD.encode(&point[1..33]),
            URL_SAFE_NO_PAD.encode(&point[33..65]),
        );
        Ok(Self { key, rng, jwk })
    }

    /// Generate a fresh P-256 key as PKCS#8 DER, for a caller that persists
    /// it (0400) and loads it with [`EcdsaP256Signer::from_pkcs8`].
    pub fn generate_pkcs8() -> Result<Zeroizing<Vec<u8>>, SignError> {
        let doc =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .map_err(|_| SignError::Key)?;
        Ok(Zeroizing::new(doc.as_ref().to_vec()))
    }

    /// A one-key JWKS for this signer.
    pub fn jwks(&self) -> serde_json::Value {
        jwks(std::slice::from_ref(&self.jwk))
    }
}

impl fmt::Debug for EcdsaP256Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaP256Signer")
            .field("kid", &self.jwk.kid)
            .finish_non_exhaustive()
    }
}

impl AssertionSigner for EcdsaP256Signer {
    fn kid(&self) -> &str {
        &self.jwk.kid
    }

    fn sign_es256(&self, signing_input: &[u8]) -> Result<Es256Signature, SignError> {
        let sig = self
            .key
            .sign(&self.rng, signing_input)
            .map_err(|_| SignError::Sign)?;
        let bytes: [u8; 64] = sig.as_ref().try_into().map_err(|_| SignError::Sign)?;
        Ok(Es256Signature(bytes))
    }

    fn public_jwk(&self) -> PublicJwk {
        self.jwk.clone()
    }
}

/// The header, in a fixed field order. Built from [`SIGNING_ALG`], never from
/// the signer, so the algorithm on the wire cannot differ from the pin.
#[derive(Serialize)]
struct Header<'a> {
    alg: &'static str,
    kid: &'a str,
    typ: &'static str,
}

/// Sign `claims` with `signer` into a compact JWT.
pub fn mint(
    claims: &AssertionClaims,
    signer: &dyn AssertionSigner,
) -> Result<CompactJwt, SignError> {
    let kid = signer.kid();
    // A kid outside base64url is not something the file-backed signer can
    // produce; refusing it keeps a custom signer from putting arbitrary text
    // into a header the provider parses.
    let kid_ok = !kid.is_empty()
        && kid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !kid_ok {
        return Err(SignError::Kid);
    }
    let header = serde_json::to_vec(&Header {
        alg: SIGNING_ALG,
        kid,
        typ: "JWT",
    })
    .map_err(|_| SignError::Encode)?;
    let payload = serde_json::to_vec(claims).map_err(|_| SignError::Encode)?;
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let sig = signer.sign_es256(signing_input.as_bytes())?;
    Ok(CompactJwt(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(sig.0)
    )))
}

// SPDX-License-Identifier: MIT
//
//! Validating a token from an issuer nucleus does not run.
//!
//! An outside agent runtime reaches nucleus with an OIDC token from its own
//! issuer. The operator binds that issuer — exact `iss`, exact `aud`, the
//! algorithms it signs with, where its keys are, how long its tokens may
//! live, and any claims that must match — and [`ExternalIssuerValidator`]
//! holds each token to that binding.
//!
//! # The checks, in order, and why each is here
//!
//! 1. **Algorithm, before any key work.** The header `alg` must be in the
//!    binding's set. [`VerifyAlg`] has no `none` and no HMAC variant, so a
//!    binding that allows them cannot be written; "HS256 with the public key
//!    as the secret" dies here, before a key is looked up.
//! 2. **`kid` is required and must resolve** in this issuer's key set. There
//!    is no "try every key" fallback: a token must say which key signed it.
//! 3. **The key must fit the algorithm** (RFC 8725 §3.1). ES256 needs an EC
//!    P-256 key, ES384 an EC P-384 key, RS/PS an RSA key of at least 2048
//!    bits, and if the JWK names an `alg` it must be this one. The crypto
//!    backend already refuses the grossest mismatch (an RSA key for an EC
//!    algorithm); this also refuses a key published as one curve and used as
//!    another, which the backend cannot see because it is handed only
//!    coordinates.
//! 4. **Signature**, via the workspace's `jsonwebtoken` backend.
//! 5. **Claims** against the caller-supplied `now`: `iss` byte-for-byte,
//!    `aud` equal or contained, `exp` and `iat` present, `exp − iat` within
//!    the binding's maximum, `sub` present, every required claim an exact
//!    string match.
//! 6. **Replay**, last, so a token that fails any other check cannot occupy
//!    the cache. Keyed on SHA-256 of the whole compact token and held until
//!    `exp` plus leeway, because the issuers this serves often send no `jti`.
//!
//! # Discovery pins the issuer
//!
//! With [`JwksSource::Discovery`] the keys come from the `jwks_uri` in
//! `<issuer>/.well-known/openid-configuration`, and that document's `issuer`
//! field must equal the configured issuer **byte for byte** (OpenID Connect
//! Discovery §4.3). Without the check, anyone who can serve a document at
//! that path — a misrouted proxy, a shared host — can point the validator at
//! their own keys. `nucleus-oidc-core`'s `DiscoveryKeyResolver` does not
//! check it and caches by `kid` alone across issuers, so this module keeps
//! its own resolver: one per validator, one issuer per resolver.
//!
//! # EC keys are parsed here, not in `nucleus-oidc-core`
//!
//! `JwkPublicKey` in oidc-core has no EC variant, so a P-256 JWKS resolves
//! there to "no usable keys". Adding one would put EC algorithms on the path
//! oidc-core's EdDSA-only OP relies on and under its algorithm-pin scan. This
//! module reuses oidc-core's wire shape ([`Jwk`]) and does the EC and RSA
//! parsing locally, so the OP's key path is unchanged.
//!
//! # Errors are coarse
//!
//! [`InboundError`]'s `Display` says only "refused" or "unavailable"; that is
//! what goes back to the caller. Which check failed is in
//! [`InboundError::reason`], for the node's own logs. Telling a caller which
//! check it failed turns the validator into an oracle for crafting a token
//! that passes.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey};
use nucleus_oidc_core::{Jwk, Jwks};
use reqwest::Url;
use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::net::{read_capped, transport_allowed};

/// Largest token accepted. A few KiB is generous for any real issuer; the cap
/// bounds the base64 and JSON work an unauthenticated caller can cause.
const MAX_TOKEN_BYTES: usize = 16 * 1024;
/// Largest leeway a binding may set. Clock skew beyond a minute is a broken
/// clock, and leeway extends every token's life by that much.
const MAX_LEEWAY: Duration = Duration::from_secs(60);
/// Largest `max_lifetime` a binding may set. The point of federation is that
/// the credential is short; a day is already long.
const MAX_LIFETIME_CEILING: Duration = Duration::from_secs(24 * 3600);
/// How long fetched keys are trusted before a refetch.
const KEY_TTL: Duration = Duration::from_secs(3600);
/// Minimum gap between fetches. An unknown `kid` triggers a refetch (the
/// issuer may have rotated), so without this a caller spraying random kids
/// would turn the validator into a request amplifier against the issuer.
const MIN_REFETCH: Duration = Duration::from_secs(30);
/// Default replay-cache capacity.
pub const DEFAULT_REPLAY_CAPACITY: usize = 100_000;

/// An algorithm a binding may accept for **verification**. There is no
/// `none`, no HMAC and no EdDSA variant: the first two are the algorithm-
/// confusion attack, and no issuer this serves signs with the third.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerifyAlg {
    Es256,
    Es384,
    Rs256,
    Rs384,
    Rs512,
    Ps256,
    Ps384,
    Ps512,
}

impl VerifyAlg {
    /// The JOSE `alg` name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Es256 => "ES256", // alg-pin-allow: verification allowlist entry, chosen per binding in config
            Self::Es384 => "ES384", // alg-pin-allow: verification allowlist entry, chosen per binding in config
            Self::Rs256 => "RS256", // alg-pin-allow: verification allowlist entry, chosen per binding in config
            Self::Rs384 => "RS384", // alg-pin-allow: verification allowlist entry, chosen per binding in config
            Self::Rs512 => "RS512", // alg-pin-allow: verification allowlist entry, chosen per binding in config
            Self::Ps256 => "PS256", // alg-pin-allow: verification allowlist entry, chosen per binding in config
            Self::Ps384 => "PS384", // alg-pin-allow: verification allowlist entry, chosen per binding in config
            Self::Ps512 => "PS512", // alg-pin-allow: verification allowlist entry, chosen per binding in config
        }
    }

    const ALL: [Self; 8] = [
        Self::Es256,
        Self::Es384,
        Self::Rs256,
        Self::Rs384,
        Self::Rs512,
        Self::Ps256,
        Self::Ps384,
        Self::Ps512,
    ];

    fn from_name(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.name() == s)
    }

    fn backend(self) -> Algorithm {
        match self {
            Self::Es256 => Algorithm::ES256, // alg-pin-allow: verification only, mapped from a VerifyAlg the binding chose
            Self::Es384 => Algorithm::ES384, // alg-pin-allow: verification only, mapped from a VerifyAlg the binding chose
            Self::Rs256 => Algorithm::RS256, // alg-pin-allow: verification only, mapped from a VerifyAlg the binding chose
            Self::Rs384 => Algorithm::RS384, // alg-pin-allow: verification only, mapped from a VerifyAlg the binding chose
            Self::Rs512 => Algorithm::RS512, // alg-pin-allow: verification only, mapped from a VerifyAlg the binding chose
            Self::Ps256 => Algorithm::PS256, // alg-pin-allow: verification only, mapped from a VerifyAlg the binding chose
            Self::Ps384 => Algorithm::PS384, // alg-pin-allow: verification only, mapped from a VerifyAlg the binding chose
            Self::Ps512 => Algorithm::PS512, // alg-pin-allow: verification only, mapped from a VerifyAlg the binding chose
        }
    }
}

impl FromStr for VerifyAlg {
    type Err = ConfigError;
    /// Parse a JOSE name from operator config. Exact and case-sensitive, as
    /// the header comparison is; `none` and `HS*` are unknown names here.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_name(s).ok_or(ConfigError::Algorithm)
    }
}

impl fmt::Display for VerifyAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Where a binding's verification keys come from.
#[derive(Debug, Clone)]
pub enum JwksSource {
    /// `<issuer>/.well-known/openid-configuration` → `jwks_uri`, with the
    /// document's `issuer` pinned to the configured one.
    Discovery,
    /// A fixed JWKS URL.
    Uri(Url),
    /// Keys registered out of band. Rotation means re-registering.
    Inline(Jwks),
}

/// One outside issuer's binding.
#[derive(Debug, Clone)]
pub struct ExternalIssuerConfig {
    /// Exact `iss`. Also the discovery base for [`JwksSource::Discovery`].
    pub issuer: String,
    /// The `aud` value tokens must carry (as the string or in the array).
    pub audience: String,
    /// Algorithms accepted. Must be non-empty.
    pub algs: BTreeSet<VerifyAlg>,
    /// Where the keys are.
    pub jwks: JwksSource,
    /// Largest `exp − iat` accepted.
    pub max_lifetime: Duration,
    /// Clock-skew allowance on `exp`, `iat` and `nbf`; at most 60 s.
    pub leeway: Duration,
    /// Claims that must be present as exactly this string.
    pub required_claims: BTreeMap<String, String>,
    /// Replay-cache capacity (distinct live tokens).
    pub replay_capacity: usize,
}

impl ExternalIssuerConfig {
    /// A binding with a one-hour lifetime cap, 30 s leeway, no required
    /// claims and the default replay capacity.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        algs: impl IntoIterator<Item = VerifyAlg>,
        jwks: JwksSource,
    ) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            algs: algs.into_iter().collect(),
            jwks,
            max_lifetime: Duration::from_secs(3600),
            leeway: Duration::from_secs(30),
            required_claims: BTreeMap::new(),
            replay_capacity: DEFAULT_REPLAY_CAPACITY,
        }
    }
}

/// Why a binding was refused at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("issuer must be an https (or loopback http) URL")]
    Issuer,
    #[error("audience must be non-empty")]
    Audience,
    #[error("unknown or empty algorithm set")]
    Algorithm,
    #[error("leeway must be at most 60s")]
    Leeway,
    #[error("max_lifetime must be between 1s and 24h")]
    Lifetime,
    #[error("jwks source is not usable")]
    Jwks,
    #[error("replay capacity must be non-zero")]
    Capacity,
}

/// Which check refused a token. For logs; never sent to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// Not three base64url JSON parts, or too large.
    Malformed,
    /// The header carried `crit`, which this validator understands none of.
    CriticalHeader,
    /// Header `alg` not in the binding's set (including `none`, `HS*`).
    AlgNotAllowed,
    /// No `kid` in the header.
    MissingKid,
    /// `kid` not in the issuer's key set.
    UnknownKid,
    /// The key's type, curve, size or declared `alg` does not fit the
    /// header's algorithm.
    KeyAlgMismatch,
    /// The signature did not verify.
    BadSignature,
    /// `iss` differs.
    Issuer,
    /// `aud` absent or does not contain the binding's audience.
    Audience,
    /// `exp` or `iat` missing or not an integer.
    MissingTime,
    /// `exp` passed.
    Expired,
    /// `iat` or `nbf` in the future.
    NotYetValid,
    /// `exp − iat` above the binding's maximum, or not positive.
    Lifetime,
    /// `sub` missing or empty.
    Subject,
    /// A required claim missing or different.
    RequiredClaim,
    /// This exact token was already accepted and has not expired.
    Replayed,
    /// Discovery document's `issuer` differs from the configured issuer.
    DiscoveryIssuerMismatch,
    /// Keys could not be fetched or contained no usable key.
    KeysUnavailable,
    /// The replay cache is full of live tokens.
    ReplayCacheFull,
}

/// A refused or unverifiable token. `Display` is deliberately uninformative;
/// log [`InboundError::reason`], return `Display` to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundError {
    /// The token is not acceptable.
    Refused(RefusalReason),
    /// The token could not be judged right now (keys unreachable, cache
    /// full). Fails closed like a refusal; distinct so the node can answer
    /// 503 rather than 401.
    Unavailable(RefusalReason),
}

impl InboundError {
    /// Which check failed, for logs.
    pub fn reason(&self) -> RefusalReason {
        match self {
            Self::Refused(r) | Self::Unavailable(r) => *r,
        }
    }
}

impl fmt::Display for InboundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(_) => f.write_str("token refused"),
            Self::Unavailable(_) => f.write_str("token could not be validated right now"),
        }
    }
}

impl std::error::Error for InboundError {}

fn refused(r: RefusalReason) -> InboundError {
    InboundError::Refused(r)
}

/// A token that passed every check.
#[derive(Debug, Clone)]
pub struct ValidatedCaller {
    /// The token's `sub`.
    pub sub: String,
    /// Every claim, for the binding's mapping to act on.
    pub claims: Map<String, Value>,
    /// SHA-256 of the compact token — the replay key, and the `provenance`
    /// a delegation certificate minted for this caller records.
    pub token_hash: [u8; 32],
    /// The token's `exp`.
    pub exp: u64,
}

/// What a key is, as far as matching it to an algorithm needs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyShape {
    Ec { crv: String, coord_len: usize },
    Rsa { modulus_bits: usize },
}

struct VerifyKey {
    shape: KeyShape,
    declared_alg: Option<String>,
    decoding: DecodingKey,
}

impl VerifyKey {
    /// Parse one JWK, or `None` for a key this validator will not use (not
    /// a signing key, an unsupported type, malformed components).
    fn from_jwk(jwk: &Jwk) -> Option<Self> {
        if jwk.use_.as_deref().is_some_and(|u| u != "sig") {
            return None;
        }
        let (shape, decoding) = match jwk.kty.as_str() {
            "EC" => {
                let (x, y) = (jwk.x.as_deref()?, jwk.y.as_deref()?);
                let xb = URL_SAFE_NO_PAD.decode(x).ok()?;
                let yb = URL_SAFE_NO_PAD.decode(y).ok()?;
                if xb.len() != yb.len() {
                    return None;
                }
                let shape = KeyShape::Ec {
                    crv: jwk.crv.clone()?,
                    coord_len: xb.len(),
                };
                (shape, DecodingKey::from_ec_components(x, y).ok()?)
            }
            "RSA" => {
                let (n, e) = (jwk.n.as_deref()?, jwk.e.as_deref()?);
                let nb = URL_SAFE_NO_PAD.decode(n).ok()?;
                let significant = nb.iter().skip_while(|b| **b == 0).count();
                let shape = KeyShape::Rsa {
                    modulus_bits: significant * 8,
                };
                (shape, DecodingKey::from_rsa_components(n, e).ok()?)
            }
            _ => return None,
        };
        Some(Self {
            shape,
            declared_alg: jwk.alg.clone(),
            decoding,
        })
    }

    /// RFC 8725 §3.1: a key is used with the one algorithm it is for.
    fn admits(&self, alg: VerifyAlg) -> bool {
        let shape_ok = match (alg, &self.shape) {
            (VerifyAlg::Es256, KeyShape::Ec { crv, coord_len }) => {
                crv == "P-256" && *coord_len == 32
            }
            (VerifyAlg::Es384, KeyShape::Ec { crv, coord_len }) => {
                crv == "P-384" && *coord_len == 48
            }
            (
                VerifyAlg::Rs256
                | VerifyAlg::Rs384
                | VerifyAlg::Rs512
                | VerifyAlg::Ps256
                | VerifyAlg::Ps384
                | VerifyAlg::Ps512,
                KeyShape::Rsa { modulus_bits },
            ) => *modulus_bits >= 2048,
            _ => false,
        };
        shape_ok && self.declared_alg.as_deref().is_none_or(|a| a == alg.name())
    }
}

fn keys_from_jwks_value(v: &Value) -> HashMap<String, Arc<VerifyKey>> {
    let mut out = HashMap::new();
    let Some(entries) = v.get("keys").and_then(Value::as_array) else {
        return out;
    };
    for entry in entries {
        // One key at a time, so a JWKS carrying a key type or shape we do
        // not model (an encryption key, a kid-less entry) does not take the
        // usable keys down with it.
        if let Ok(jwk) = serde_json::from_value::<Jwk>(entry.clone()) {
            insert_key(&mut out, &jwk);
        }
    }
    out
}

/// The one per-key parser, shared by fetched and inline key sets.
fn insert_key(out: &mut HashMap<String, Arc<VerifyKey>>, jwk: &Jwk) {
    if jwk.kid.is_empty() {
        return;
    }
    if let Some(k) = VerifyKey::from_jwk(jwk) {
        out.insert(jwk.kid.clone(), Arc::new(k));
    }
}

struct KeyState {
    keys: HashMap<String, Arc<VerifyKey>>,
    fetched_at: Option<Instant>,
    last_attempt: Option<Instant>,
}

/// Token hash → retain-until (unix seconds).
struct ReplayCache {
    seen: HashMap<[u8; 32], u64>,
    capacity: usize,
}

impl ReplayCache {
    fn admit(&mut self, hash: [u8; 32], retain_until: u64, now: u64) -> Result<(), InboundError> {
        if self.seen.get(&hash).is_some_and(|until| *until > now) {
            return Err(refused(RefusalReason::Replayed));
        }
        if self.seen.len() >= self.capacity {
            self.seen.retain(|_, until| *until > now);
        }
        // Full of live tokens: refuse rather than evict. Evicting would make
        // the evicted token replayable, and an attacker who can fill the
        // cache chooses which.
        if self.seen.len() >= self.capacity {
            return Err(InboundError::Unavailable(RefusalReason::ReplayCacheFull));
        }
        self.seen.insert(hash, retain_until);
        Ok(())
    }
}

#[derive(Deserialize)]
struct DiscoveryDoc {
    issuer: String,
    jwks_uri: String,
}

/// Validates one outside issuer's tokens against its binding.
pub struct ExternalIssuerValidator {
    cfg: ExternalIssuerConfig,
    http: reqwest::Client,
    keys: Mutex<KeyState>,
    replay: Mutex<ReplayCache>,
}

impl fmt::Debug for ExternalIssuerValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalIssuerValidator")
            .field("issuer", &self.cfg.issuer)
            .field("audience", &self.cfg.audience)
            .finish_non_exhaustive()
    }
}

impl ExternalIssuerValidator {
    /// Check the binding and build a validator. `http` should come from
    /// [`crate::default_client`] (bounded timeouts, no redirects).
    pub fn new(cfg: ExternalIssuerConfig, http: reqwest::Client) -> Result<Self, ConfigError> {
        let issuer_url = Url::parse(&cfg.issuer).map_err(|_| ConfigError::Issuer)?;
        if !transport_allowed(&issuer_url) {
            return Err(ConfigError::Issuer);
        }
        if cfg.audience.is_empty() {
            return Err(ConfigError::Audience);
        }
        if cfg.algs.is_empty() {
            return Err(ConfigError::Algorithm);
        }
        if cfg.leeway > MAX_LEEWAY {
            return Err(ConfigError::Leeway);
        }
        if cfg.max_lifetime.is_zero() || cfg.max_lifetime > MAX_LIFETIME_CEILING {
            return Err(ConfigError::Lifetime);
        }
        if cfg.replay_capacity == 0 {
            return Err(ConfigError::Capacity);
        }
        let mut state = KeyState {
            keys: HashMap::new(),
            fetched_at: None,
            last_attempt: None,
        };
        match &cfg.jwks {
            JwksSource::Discovery => {}
            JwksSource::Uri(u) => {
                if !transport_allowed(u) {
                    return Err(ConfigError::Jwks);
                }
            }
            JwksSource::Inline(jwks) => {
                for jwk in &jwks.keys {
                    insert_key(&mut state.keys, jwk);
                }
                if state.keys.is_empty() {
                    return Err(ConfigError::Jwks);
                }
            }
        }
        let replay = ReplayCache {
            seen: HashMap::new(),
            capacity: cfg.replay_capacity,
        };
        Ok(Self {
            cfg,
            http,
            keys: Mutex::new(state),
            replay: Mutex::new(replay),
        })
    }

    /// The configured issuer.
    pub fn issuer(&self) -> &str {
        &self.cfg.issuer
    }

    /// Validate `token` at `now_unix`. See the module docs for the checks.
    pub async fn validate(
        &self,
        token: &str,
        now_unix: u64,
    ) -> Result<ValidatedCaller, InboundError> {
        if token.len() > MAX_TOKEN_BYTES {
            return Err(refused(RefusalReason::Malformed));
        }
        let mut parts = token.split('.');
        let (Some(h64), Some(p64), Some(s64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(refused(RefusalReason::Malformed));
        };
        let header = decode_object(h64)?;

        // 1. Algorithm, before any key is touched.
        if header.contains_key("crit") {
            return Err(refused(RefusalReason::CriticalHeader));
        }
        let alg = header
            .get("alg")
            .and_then(Value::as_str)
            .and_then(VerifyAlg::from_name)
            .filter(|a| self.cfg.algs.contains(a))
            .ok_or(refused(RefusalReason::AlgNotAllowed))?;

        // 2. kid, resolved in this issuer's keys only.
        let kid = header
            .get("kid")
            .and_then(Value::as_str)
            .filter(|k| !k.is_empty())
            .ok_or(refused(RefusalReason::MissingKid))?;
        let key = self.resolve(kid).await?;

        // 3. The key must be the kind this algorithm is for.
        if !key.admits(alg) {
            return Err(refused(RefusalReason::KeyAlgMismatch));
        }

        // 4. Signature.
        let signing_input = &token[..h64.len() + 1 + p64.len()];
        let ok = jsonwebtoken::crypto::verify(
            s64,
            signing_input.as_bytes(),
            &key.decoding,
            alg.backend(),
        )
        .unwrap_or(false);
        if !ok {
            return Err(refused(RefusalReason::BadSignature));
        }

        // 5. Claims.
        let claims = decode_object(p64)?;
        let (sub, exp) = self.check_claims(&claims, now_unix)?;

        // 6. Replay, only for a token that passed everything else.
        let token_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let retain_until = exp.saturating_add(self.cfg.leeway.as_secs());
        self.replay
            .lock()
            .map_err(|_| InboundError::Unavailable(RefusalReason::ReplayCacheFull))?
            .admit(token_hash, retain_until, now_unix)?;

        Ok(ValidatedCaller {
            sub,
            claims,
            token_hash,
            exp,
        })
    }

    fn check_claims(
        &self,
        c: &Map<String, Value>,
        now: u64,
    ) -> Result<(String, u64), InboundError> {
        if c.get("iss").and_then(Value::as_str) != Some(self.cfg.issuer.as_str()) {
            return Err(refused(RefusalReason::Issuer));
        }
        let aud_ok = match c.get("aud") {
            Some(Value::String(a)) => *a == self.cfg.audience,
            Some(Value::Array(v)) => v.iter().any(|a| a.as_str() == Some(&self.cfg.audience)),
            _ => false,
        };
        if !aud_ok {
            return Err(refused(RefusalReason::Audience));
        }
        let (Some(exp), Some(iat)) = (
            c.get("exp").and_then(Value::as_u64),
            c.get("iat").and_then(Value::as_u64),
        ) else {
            return Err(refused(RefusalReason::MissingTime));
        };
        let leeway = self.cfg.leeway.as_secs();
        if now >= exp.saturating_add(leeway) {
            return Err(refused(RefusalReason::Expired));
        }
        if iat > now.saturating_add(leeway) {
            return Err(refused(RefusalReason::NotYetValid));
        }
        match c.get("nbf") {
            None => {}
            Some(v) => match v.as_u64() {
                Some(nbf) if nbf <= now.saturating_add(leeway) => {}
                _ => return Err(refused(RefusalReason::NotYetValid)),
            },
        }
        if exp <= iat || exp - iat > self.cfg.max_lifetime.as_secs() {
            return Err(refused(RefusalReason::Lifetime));
        }
        let sub = c
            .get("sub")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or(refused(RefusalReason::Subject))?;
        for (k, want) in &self.cfg.required_claims {
            if c.get(k).and_then(Value::as_str) != Some(want.as_str()) {
                return Err(refused(RefusalReason::RequiredClaim));
            }
        }
        Ok((sub.to_string(), exp))
    }

    async fn resolve(&self, kid: &str) -> Result<Arc<VerifyKey>, InboundError> {
        {
            let st = self
                .keys
                .lock()
                .map_err(|_| InboundError::Unavailable(RefusalReason::KeysUnavailable))?;
            if matches!(self.cfg.jwks, JwksSource::Inline(_)) {
                return st
                    .keys
                    .get(kid)
                    .cloned()
                    .ok_or(refused(RefusalReason::UnknownKid));
            }
            let fresh = st.fetched_at.is_some_and(|t| t.elapsed() < KEY_TTL);
            if fresh && let Some(k) = st.keys.get(kid) {
                return Ok(k.clone());
            }
            if st.last_attempt.is_some_and(|t| t.elapsed() < MIN_REFETCH) {
                // Fetched moments ago and the kid was not there; asking
                // again would not change the answer, only load the issuer.
                return if fresh {
                    Err(refused(RefusalReason::UnknownKid))
                } else {
                    Err(InboundError::Unavailable(RefusalReason::KeysUnavailable))
                };
            }
        }
        if let Ok(mut st) = self.keys.lock() {
            st.last_attempt = Some(Instant::now());
        }
        let keys = self.fetch_keys().await?;
        let mut st = self
            .keys
            .lock()
            .map_err(|_| InboundError::Unavailable(RefusalReason::KeysUnavailable))?;
        st.keys = keys;
        st.fetched_at = Some(Instant::now());
        st.keys
            .get(kid)
            .cloned()
            .ok_or(refused(RefusalReason::UnknownKid))
    }

    async fn fetch_keys(&self) -> Result<HashMap<String, Arc<VerifyKey>>, InboundError> {
        let unavailable = InboundError::Unavailable(RefusalReason::KeysUnavailable);
        let jwks_url = match &self.cfg.jwks {
            JwksSource::Uri(u) => u.clone(),
            JwksSource::Discovery => {
                let url = format!(
                    "{}/.well-known/openid-configuration",
                    self.cfg.issuer.trim_end_matches('/')
                );
                let doc: DiscoveryDoc =
                    serde_json::from_slice(&self.get(&url).await?).map_err(|_| unavailable)?;
                // OpenID Connect Discovery §4.3: byte-for-byte.
                if doc.issuer != self.cfg.issuer {
                    return Err(refused(RefusalReason::DiscoveryIssuerMismatch));
                }
                let u = Url::parse(&doc.jwks_uri).map_err(|_| unavailable)?;
                if !transport_allowed(&u) {
                    return Err(unavailable);
                }
                u
            }
            JwksSource::Inline(_) => return Err(unavailable),
        };
        let body: Value =
            serde_json::from_slice(&self.get(jwks_url.as_str()).await?).map_err(|_| unavailable)?;
        let keys = keys_from_jwks_value(&body);
        if keys.is_empty() {
            return Err(unavailable);
        }
        Ok(keys)
    }

    async fn get(&self, url: &str) -> Result<Vec<u8>, InboundError> {
        let unavailable = InboundError::Unavailable(RefusalReason::KeysUnavailable);
        let resp = self
            .http
            .get(url)
            .timeout(crate::net::REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|_| unavailable)?;
        if !resp.status().is_success() {
            return Err(unavailable);
        }
        read_capped(resp)
            .await
            .map(|b| b.to_vec())
            .ok_or(unavailable)
    }
}

fn decode_object(b64: &str) -> Result<Map<String, Value>, InboundError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|_| refused(RefusalReason::Malformed))?;
    match serde_json::from_slice(&bytes) {
        Ok(Value::Object(m)) => Ok(m),
        _ => Err(refused(RefusalReason::Malformed)),
    }
}

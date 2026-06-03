// SPDX-License-Identifier: MIT
//
//! Inbound SPIFFE Federation — trust-bundle fetch/refresh + cross-domain
//! JWT-SVID validation (the `https_web` bundle-endpoint profile only).
//!
//! # What this module is
//!
//! A *validator* for inbound JWT-SVIDs minted by **foreign** SPIFFE trust
//! domains you have explicitly chosen to federate with. It answers exactly
//! one security question: *does this cross-org workload token authenticate
//! under a key we pinned for its trust domain?*
//!
//! The single-tenant framing: federate your **own** trust domains
//! (`prod` / `staging` / `edge` / `ci`) across failure domains with **no
//! central CA**. Each domain runs its own SPIFFE authority; this module is
//! the inbound side that lets `prod` accept a `ci` workload's JWT-SVID.
//!
//! # Honest scope (read before extending)
//!
//! - **Inbound only.** We *consume* foreign bundles + verify foreign
//!   JWT-SVIDs. We do not mint, and we do not serve our own bundle.
//! - **`https_web` profile only.** Bundles are fetched over ordinary
//!   Web-PKI TLS (reqwest default rustls, RFC 6125 server-cert
//!   validation). There is **no** `https_spiffe` profile, **no**
//!   x509-svid path, and **no** SPIFFE Workload API client here.
//! - **JWT-SVID only**, EC / RSA / PS keys. EdDSA/Ed25519/OKP and `none`
//!   are **out of spec** for JWT-SVID and are rejected by the alg
//!   allowlist (see [`ALLOWED_ALGS`]).
//!
//! # The pinning that makes this safe
//!
//! The map *trust-domain → (bundle endpoint URL, profile)* is **operator
//! supplied and out-of-band** — a `[[federates_with]]`-style config entry.
//! Per the SPIFFE Federation spec this binding "cannot be securely
//! inferred": we NEVER derive the endpoint URL from a trust domain, and we
//! NEVER derive the profile from a URL. A poisoned or rolled-back bundle,
//! or a mis-pinned key, would let a foreign domain forge identity — so the
//! verifying key is selected **only** from the bundle pinned for the
//! token's own trust domain, and **never** from anything named inside the
//! token.
//!
//! # Anti-rollback (HARDENING — beyond the spec)
//!
//! The SPIFFE Federation spec only *SHOULD* compare `spiffe_sequence`. We
//! make it a *MUST* here: a fetched bundle whose `spiffe_sequence` is not
//! strictly greater than the last-accepted sequence is **rejected**, and
//! the current good key set is **kept** (fail-safe — we never blank the
//! key set on a fetch error or a rollback). This is local hardening, not a
//! spec mandate; downgrading it would re-open a key-rollback attack.
//!
//! # Dormant metering seam
//!
//! Cross-domain validation is a natural metering point (proven work:
//! "validated N foreign JWT-SVIDs"). That seam is *documented only* — there
//! is no payment, no token, no counter wired here. See
//! [`FederationStore::validate_jwt_svid`].

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

use crate::error::OidcError;
use crate::jwks::Jwks;

/// The JWT-SVID signing-algorithm allowlist (RFC 8725 §3.1 posture).
///
/// **RS256/384/512, ES256/384, PS256/384/512.** EdDSA/Ed25519 is
/// deliberately absent: it is out of spec for JWT-SVID. `none` is
/// structurally impossible to reach because it is not in this list and the
/// alg is checked against this list before any key work. SPIRE's common
/// default is ES256, so EC support is mandatory.
///
/// **Backend limitation (honest scope):** `ES512` (NIST P-521) is *spec
/// eligible* but is **not** in this list because the workspace-pinned
/// `jsonwebtoken` (`rust_crypto` backend) does not implement P-521. A P-521
/// JWT-SVID is therefore rejected by the allowlist (fail-closed, not
/// silently downgraded). This is a transitive-dependency capability gap,
/// not a security decision; revisit if the backend gains P-521.
pub const ALLOWED_ALGS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
];

/// Default refresh poll period when a bundle carries no
/// `spiffe_refresh_hint` (SPIFFE Federation spec default: 300s).
pub const DEFAULT_REFRESH_SECS: u64 = 300;

/// Which SPIFFE Federation endpoint profile an entry uses.
///
/// Only [`Profile::HttpsWeb`] is implemented. The enum exists so the
/// operator config can *name* the profile explicitly (never inferred from
/// the URL) and so an unsupported profile fails loudly rather than being
/// silently treated as `https_web`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Bundle fetched over ordinary Web-PKI TLS (RFC 6125 server-cert
    /// validation). The only profile this module supports.
    HttpsWeb,
}

/// One operator-pinned federation entry: a foreign trust domain we choose
/// to accept, the out-of-band bundle endpoint, and its profile.
///
/// This is the `[[federates_with]]` config row. None of these fields is
/// ever derived from a token or from each other.
#[derive(Debug, Clone)]
pub struct FederatesWith {
    /// The foreign SPIFFE trust domain authority, e.g. `"ci.example.org"`.
    /// Matched against the authority parsed from a JWT-SVID `sub`.
    pub trust_domain: String,
    /// The pinned `https_web` bundle-endpoint URL. NEVER inferred from
    /// `trust_domain`.
    pub bundle_endpoint_url: String,
    /// The pinned endpoint profile. NEVER inferred from
    /// `bundle_endpoint_url`.
    pub profile: Profile,
}

/// A parsed SPIFFE trust-domain bundle: an RFC 7517 JWK Set plus the two
/// SPIFFE Federation top-level fields.
#[derive(Debug, Clone, Deserialize)]
pub struct SpiffeBundle {
    /// The JWK Set (`{"keys":[...]}`). Reuses [`Jwks`]/[`Jwk`].
    #[serde(flatten)]
    pub jwks: Jwks,
    /// Monotonic bundle sequence number. Drives anti-rollback.
    pub spiffe_sequence: u64,
    /// Operator's suggested poll period, seconds. Optional.
    #[serde(default)]
    pub spiffe_refresh_hint: Option<u64>,
}

impl SpiffeBundle {
    /// Parse a bundle from its JSON bytes.
    pub fn from_json(bytes: &[u8]) -> Result<Self, OidcError> {
        serde_json::from_slice(bytes)
            .map_err(|e| OidcError::InvalidJwks(format!("trust-bundle json: {e}")))
    }

    /// The effective refresh period for this bundle.
    pub fn refresh_period(&self) -> Duration {
        Duration::from_secs(self.spiffe_refresh_hint.unwrap_or(DEFAULT_REFRESH_SECS))
    }

    /// Select the JWT-SVID verifying keys from this bundle.
    ///
    /// MUST-ignore semantics (skip, do not fail) for entries we can't or
    /// shouldn't use:
    /// - `use` missing or not `"jwt-svid"` → skipped (e.g. `"x509-svid"`).
    /// - `kty` not `EC`/`RSA` → skipped (e.g. an `OKP`/Ed25519 entry; that
    ///   key class is out of spec for JWT-SVID).
    /// - any entry that fails to decode into a usable [`DecodingKey`] →
    ///   skipped, so one bad key never poisons the whole bundle.
    ///
    /// Returns `kid → DecodingKey`. Entries with an empty `kid` are kept
    /// under the empty-string key and are tried as a fallback when a token
    /// header carries no `kid`.
    fn jwt_svid_keys(&self) -> HashMap<String, DecodingKey> {
        let mut out = HashMap::new();
        for jwk in &self.jwks.keys {
            // MUST-ignore unknown/missing `use`.
            if jwk.use_.as_deref() != Some("jwt-svid") {
                continue;
            }
            match decoding_key_for(jwk) {
                Some(key) => {
                    out.insert(jwk.kid.clone(), key);
                }
                // MUST-ignore unknown `kty` / malformed key material.
                None => continue,
            }
        }
        out
    }
}

/// Build a `jsonwebtoken` [`DecodingKey`] for a JWT-SVID JWK.
///
/// Only `EC` (P-256/384/521) and `RSA` are accepted. Returns `None` for
/// any other `kty` (including `OKP`/Ed25519, out of spec here) or for
/// malformed key components — the caller treats `None` as "skip this key".
fn decoding_key_for(jwk: &crate::jwks::Jwk) -> Option<DecodingKey> {
    match jwk.kty.as_str() {
        "EC" => {
            let x = jwk.x.as_deref()?;
            let y = jwk.y.as_deref()?;
            // from_ec_components takes base64url-encoded affine coords.
            DecodingKey::from_ec_components(x, y).ok()
        }
        "RSA" => {
            let n = jwk.n.as_deref()?;
            let e = jwk.e.as_deref()?;
            DecodingKey::from_rsa_components(n, e).ok()
        }
        // OKP/Ed25519 and everything else: out of spec for JWT-SVID.
        _ => None,
    }
}

/// A parsed SPIFFE ID: `spiffe://<trust-domain>/<path>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeId {
    /// The trust-domain authority, e.g. `"ci.example.org"`.
    pub trust_domain: String,
    /// The workload path *with* its leading slash, e.g. `"/runner/42"`.
    /// May be empty for a bare trust-domain ID.
    pub path: String,
}

impl SpiffeId {
    /// Hand-rolled `spiffe://` parse (no `spiffe`/`tonic` dependency — we
    /// keep the supply chain lean for a security product).
    ///
    /// Enforces: the `spiffe://` scheme, a non-empty authority, no
    /// userinfo (`@`), no port (`:`) in the authority, and a lowercase
    /// authority (SPIFFE trust domains are case-insensitive; we normalize
    /// so a mixed-case `sub` cannot dodge the pinned-set lookup).
    pub fn parse(s: &str) -> Result<Self, OidcError> {
        let rest = s
            .strip_prefix("spiffe://")
            .ok_or_else(|| OidcError::MalformedSpiffeId(format!("not a spiffe:// URI: {s:?}")))?;
        // Authority is everything up to the first '/'. Path (if any)
        // includes the leading slash.
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        if authority.is_empty() {
            return Err(OidcError::MalformedSpiffeId(format!(
                "empty trust domain in {s:?}"
            )));
        }
        if authority.contains('@') || authority.contains(':') {
            return Err(OidcError::MalformedSpiffeId(format!(
                "trust domain must not contain userinfo or port: {authority:?}"
            )));
        }
        Ok(SpiffeId {
            trust_domain: authority.to_ascii_lowercase(),
            path: path.to_string(),
        })
    }
}

/// Minimal claim shape we read from a JWT-SVID after signature verify.
///
/// SPIFFE JWT-SVID puts the workload identity in `sub` (a SPIFFE ID) and
/// uses `aud` for the relying party. `exp` is mandatory.
#[derive(Debug, Deserialize)]
struct SvidClaims {
    sub: String,
}

/// Per-trust-domain mutable state: the pinned config plus the last
/// accepted sequence and the currently-served JWT-SVID key set.
struct DomainState {
    cfg: FederatesWith,
    /// `None` until the first bundle is accepted.
    last_accepted_seq: Option<u64>,
    /// `kid → DecodingKey` from the last accepted bundle. Kept across a
    /// fetch error or a rollback (fail-safe).
    keys: HashMap<String, DecodingKey>,
    /// Effective refresh period from the last accepted bundle.
    refresh_period: Duration,
}

/// The federation store: the operator-pinned set of foreign trust domains,
/// each with its anti-rollback state and current verifying keys.
///
/// Construct with [`FederationStore::new`], pin domains with
/// [`FederationStore::federate_with`], drive refresh with
/// [`FederationStore::ingest_bundle`] (after a [`BundleFetcher`] GET), and
/// authenticate inbound tokens with
/// [`FederationStore::validate_jwt_svid`].
#[derive(Default)]
pub struct FederationStore {
    /// `trust_domain → DomainState`.
    domains: Mutex<HashMap<String, DomainState>>,
    /// The expected `aud` for inbound JWT-SVIDs (this relying party).
    expected_audience: String,
    /// Clock-skew leeway for `exp`, seconds.
    leeway_secs: u64,
}

impl FederationStore {
    /// A store that requires inbound JWT-SVIDs to carry `expected_audience`
    /// in their `aud`, with a 60s `exp` clock-skew leeway.
    pub fn new(expected_audience: impl Into<String>) -> Self {
        Self {
            domains: Mutex::new(HashMap::new()),
            expected_audience: expected_audience.into(),
            leeway_secs: 60,
        }
    }

    /// Override the `exp` clock-skew leeway (seconds).
    pub fn with_leeway_secs(mut self, leeway_secs: u64) -> Self {
        self.leeway_secs = leeway_secs;
        self
    }

    /// The audience this relying party requires in inbound JWT-SVIDs.
    pub fn expected_audience(&self) -> &str {
        &self.expected_audience
    }

    /// Validate an inbound JWT-SVID against this store's configured
    /// audience. Convenience wrapper over [`Self::validate_jwt_svid`].
    pub fn validate(&self, token: &str) -> Result<SpiffeId, OidcError> {
        let aud = self.expected_audience.clone();
        self.validate_jwt_svid(token, &aud)
    }

    /// Pin a foreign trust domain into the federation set (the
    /// out-of-band `[[federates_with]]` binding). No keys are loaded until
    /// a bundle is ingested.
    pub fn federate_with(&self, cfg: FederatesWith) {
        let mut domains = self.domains.lock().expect("federation store mutex");
        let refresh_period = Duration::from_secs(DEFAULT_REFRESH_SECS);
        domains.insert(
            cfg.trust_domain.clone(),
            DomainState {
                cfg,
                last_accepted_seq: None,
                keys: HashMap::new(),
                refresh_period,
            },
        );
    }

    /// Is this trust domain in the operator-pinned federation set?
    pub fn is_federated(&self, trust_domain: &str) -> bool {
        self.domains
            .lock()
            .expect("federation store mutex")
            .contains_key(trust_domain)
    }

    /// The pinned bundle-endpoint URL + profile for a trust domain, if
    /// federated. Used by a refresh loop to know where to fetch from.
    pub fn endpoint_for(&self, trust_domain: &str) -> Option<(String, Profile)> {
        self.domains
            .lock()
            .expect("federation store mutex")
            .get(trust_domain)
            .map(|d| (d.cfg.bundle_endpoint_url.clone(), d.cfg.profile))
    }

    /// The current refresh period for a federated trust domain.
    pub fn refresh_period(&self, trust_domain: &str) -> Option<Duration> {
        self.domains
            .lock()
            .expect("federation store mutex")
            .get(trust_domain)
            .map(|d| d.refresh_period)
    }

    /// The number of currently-served JWT-SVID keys for a trust domain
    /// (introspection / test assertions).
    pub fn served_key_count(&self, trust_domain: &str) -> Option<usize> {
        self.domains
            .lock()
            .expect("federation store mutex")
            .get(trust_domain)
            .map(|d| d.keys.len())
    }

    /// The last-accepted `spiffe_sequence` for a trust domain.
    pub fn last_accepted_seq(&self, trust_domain: &str) -> Option<u64> {
        self.domains
            .lock()
            .expect("federation store mutex")
            .get(trust_domain)
            .and_then(|d| d.last_accepted_seq)
    }

    /// Ingest a freshly-fetched bundle for `trust_domain`, applying the
    /// anti-rollback rule.
    ///
    /// - Rejects (with [`OidcError::TrustDomainNotFederated`]) a domain not
    ///   in the pinned set.
    /// - Rejects (with [`OidcError::BundleRollback`]) a bundle whose
    ///   `spiffe_sequence` is **not strictly greater** than the
    ///   last-accepted sequence. On rejection the currently-served key set
    ///   is left untouched (fail-safe).
    /// - On accept, atomically swaps in the new JWT-SVID key set and
    ///   records the new sequence + refresh period.
    pub fn ingest_bundle(
        &self,
        trust_domain: &str,
        bundle: &SpiffeBundle,
    ) -> Result<(), OidcError> {
        let mut domains = self.domains.lock().expect("federation store mutex");
        let state = domains
            .get_mut(trust_domain)
            .ok_or_else(|| OidcError::TrustDomainNotFederated(trust_domain.to_string()))?;

        // Anti-rollback (HARDENING beyond the spec SHOULD): require a
        // strictly-increasing sequence. Keep the existing good key set on
        // rejection — never blank it.
        if let Some(last) = state.last_accepted_seq {
            if bundle.spiffe_sequence <= last {
                return Err(OidcError::BundleRollback {
                    fetched: bundle.spiffe_sequence,
                    last,
                });
            }
        }

        state.keys = bundle.jwt_svid_keys();
        state.last_accepted_seq = Some(bundle.spiffe_sequence);
        state.refresh_period = bundle.refresh_period();
        Ok(())
    }

    /// Validate an inbound JWT-SVID, returning its [`SpiffeId`] on success.
    ///
    /// Steps, in order (every one fails closed):
    /// 1. Decode header + claims **without** verifying.
    /// 2. Assert `header.alg ∈` [`ALLOWED_ALGS`] (rejects EdDSA, `none`).
    /// 3. Parse `sub` as `spiffe://<trust-domain>/<path>`.
    /// 4. Look up the **pinned** bundle for that trust domain — if it's
    ///    not in the federation set, REJECT before any signature work.
    /// 5. Select the verifying key from **that bundle only**
    ///    (`use=="jwt-svid"` && `kid` match; no `kid` ⇒ try every
    ///    jwt-svid key). If none, REJECT.
    /// 6. Verify the signature under the pinned `alg`.
    /// 7. `exp` MUST be present and not past (within leeway).
    /// 8. `aud` MUST be present and contain the expected audience.
    ///
    /// The key is **never** chosen from anything named in the token; it is
    /// chosen from the trust-domain-pinned bundle alone.
    ///
    /// (Dormant metering seam: a successful return here is exactly one unit
    /// of "validated foreign JWT-SVID" — the natural place to meter proven
    /// cross-domain work. No payment / counter is wired.)
    pub fn validate_jwt_svid(
        &self,
        token: &str,
        expected_audience: &str,
    ) -> Result<SpiffeId, OidcError> {
        // (1) header WITHOUT verifying.
        let header = decode_header(token).map_err(|e| OidcError::JwtValidation(e.to_string()))?;

        // (2) alg allowlist — before any key work. Rejects EdDSA/none.
        if !ALLOWED_ALGS.contains(&header.alg) {
            return Err(OidcError::UnacceptedAlgorithm(format!("{:?}", header.alg)));
        }

        // (1, cont.) claims WITHOUT verifying — only to read `sub`, so we
        // can pick the trust domain. The signature is verified in step 6
        // against the pinned key, so a forged `sub` can at most route us to
        // a domain whose key won't verify it.
        let svid_sub = peek_svid_sub(token)?;

        // (3) parse the SPIFFE ID, extract the trust domain authority.
        let spiffe_id = SpiffeId::parse(&svid_sub)?;

        // (4) + (5): hold the lock, look up the PINNED bundle, select the
        // candidate keys FROM THAT BUNDLE ONLY, then clone them out so we
        // verify without holding the lock.
        let candidate_keys: Vec<DecodingKey> = {
            let domains = self.domains.lock().expect("federation store mutex");
            let state = domains.get(&spiffe_id.trust_domain).ok_or_else(|| {
                // Fail-closed: a non-federated domain never authenticates.
                OidcError::TrustDomainNotFederated(spiffe_id.trust_domain.clone())
            })?;
            match &header.kid {
                Some(kid) => state.keys.get(kid).cloned().into_iter().collect(),
                // No kid: try every jwt-svid key in THIS bundle.
                None => state.keys.values().cloned().collect(),
            }
        };
        if candidate_keys.is_empty() {
            return Err(OidcError::KeyNotFound(
                header.kid.unwrap_or_else(|| "<none>".to_string()),
            ));
        }

        // (6) verify under the pinned alg; (7) exp; (8) aud.
        let mut validation = Validation::new(header.alg);
        validation.set_required_spec_claims(&["exp", "aud", "sub"]);
        validation.validate_exp = true;
        validation.leeway = self.leeway_secs;
        validation.set_audience(&[expected_audience]);

        let mut last_err: Option<OidcError> = None;
        for key in &candidate_keys {
            match decode::<SvidClaims>(token, key, &validation) {
                Ok(data) => {
                    // The verified `sub` is authoritative; re-parse it
                    // rather than trusting the unverified peek.
                    return SpiffeId::parse(&data.claims.sub);
                }
                Err(e) => last_err = Some(OidcError::JwtValidation(e.to_string())),
            }
        }
        Err(last_err
            .unwrap_or_else(|| OidcError::JwtValidation("no candidate key verified".to_string())))
    }
}

/// Peek the (unverified) `sub` claim of a JWT, used only to pick the trust
/// domain before signature verification. Signature is verified afterward
/// against the pinned key, so a forged `sub` cannot bypass verification.
fn peek_svid_sub(token: &str) -> Result<String, OidcError> {
    #[derive(Deserialize)]
    struct SubPeek {
        sub: String,
    }
    let mut parts = token.splitn(3, '.');
    let _header = parts
        .next()
        .ok_or_else(|| OidcError::JwtValidation("jwt missing header".into()))?;
    let payload_b64 = parts
        .next()
        .ok_or_else(|| OidcError::JwtValidation("jwt missing payload".into()))?;
    let _sig = parts
        .next()
        .ok_or_else(|| OidcError::JwtValidation("jwt missing signature".into()))?;
    if parts.next().is_some() {
        return Err(OidcError::JwtValidation("jwt has more than 3 parts".into()));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| OidcError::JwtValidation(format!("base64url decode: {e}")))?;
    let peek: SubPeek = serde_json::from_slice(&payload)
        .map_err(|e| OidcError::JwtValidation(format!("payload json: {e}")))?;
    Ok(peek.sub)
}

/// Fetches SPIFFE trust-domain bundles over the `https_web` profile.
///
/// Uses reqwest's default Web-PKI / rustls TLS — RFC 6125 server-cert
/// validation. This is the ONLY transport: there is no `https_spiffe`
/// fetch and no Workload API client.
pub struct BundleFetcher {
    http: reqwest::Client,
}

impl BundleFetcher {
    /// A fetcher with a 10s request timeout and default Web-PKI TLS.
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client builds with default config"),
        }
    }

    /// GET + parse a trust-domain bundle from a pinned `https_web`
    /// endpoint URL.
    ///
    /// The caller passes the URL from [`FederationStore::endpoint_for`];
    /// this method does NOT derive the URL from a trust domain. The
    /// returned bundle still has to clear [`FederationStore::ingest_bundle`]
    /// (anti-rollback) before any of its keys are served.
    pub async fn fetch(&self, bundle_endpoint_url: &str) -> Result<SpiffeBundle, OidcError> {
        let bytes = self
            .http
            .get(bundle_endpoint_url)
            .send()
            .await
            .map_err(|e| OidcError::Network(e.to_string()))?
            .error_for_status()
            .map_err(|e| OidcError::Network(e.to_string()))?
            .bytes()
            .await
            .map_err(|e| OidcError::Network(e.to_string()))?;
        SpiffeBundle::from_json(&bytes)
    }
}

impl Default for BundleFetcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- SPIFFE ID parsing ----

    #[test]
    fn parses_spiffe_id_with_path() {
        let id = SpiffeId::parse("spiffe://ci.example.org/runner/42").unwrap();
        assert_eq!(id.trust_domain, "ci.example.org");
        assert_eq!(id.path, "/runner/42");
    }

    #[test]
    fn parses_bare_trust_domain() {
        let id = SpiffeId::parse("spiffe://ci.example.org").unwrap();
        assert_eq!(id.trust_domain, "ci.example.org");
        assert_eq!(id.path, "");
    }

    #[test]
    fn lowercases_trust_domain() {
        let id = SpiffeId::parse("spiffe://CI.Example.ORG/w").unwrap();
        assert_eq!(id.trust_domain, "ci.example.org");
    }

    #[test]
    fn rejects_non_spiffe_scheme() {
        assert!(matches!(
            SpiffeId::parse("https://ci.example.org/w"),
            Err(OidcError::MalformedSpiffeId(_))
        ));
    }

    #[test]
    fn rejects_empty_trust_domain() {
        assert!(matches!(
            SpiffeId::parse("spiffe:///w"),
            Err(OidcError::MalformedSpiffeId(_))
        ));
    }

    #[test]
    fn rejects_trust_domain_with_port() {
        assert!(matches!(
            SpiffeId::parse("spiffe://ci.example.org:8443/w"),
            Err(OidcError::MalformedSpiffeId(_))
        ));
    }

    // ---- bundle parse + key filter ----

    #[test]
    fn parses_bundle_with_sequence_and_hint() {
        let json = br#"{
            "keys": [],
            "spiffe_sequence": 7,
            "spiffe_refresh_hint": 120
        }"#;
        let b = SpiffeBundle::from_json(json).unwrap();
        assert_eq!(b.spiffe_sequence, 7);
        assert_eq!(b.refresh_period(), Duration::from_secs(120));
    }

    #[test]
    fn refresh_defaults_to_300_without_hint() {
        let json = br#"{"keys": [], "spiffe_sequence": 1}"#;
        let b = SpiffeBundle::from_json(json).unwrap();
        assert_eq!(
            b.refresh_period(),
            Duration::from_secs(DEFAULT_REFRESH_SECS)
        );
    }

    #[test]
    fn key_filter_skips_x509_and_unknown_use_and_okp() {
        // x509-svid (skip), missing use (skip), OKP/Ed25519 (skip).
        let json = br#"{
            "keys": [
                {"kty":"EC","kid":"x509","use":"x509-svid","crv":"P-256","x":"AA","y":"BB"},
                {"kty":"EC","kid":"nouse","crv":"P-256","x":"AA","y":"BB"},
                {"kty":"OKP","kid":"ed","use":"jwt-svid","crv":"Ed25519","x":"AA"}
            ],
            "spiffe_sequence": 1
        }"#;
        let b = SpiffeBundle::from_json(json).unwrap();
        // None are usable jwt-svid EC/RSA keys.
        assert_eq!(b.jwt_svid_keys().len(), 0);
    }
}

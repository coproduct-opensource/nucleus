//! `JwtIssuer` — production-grade OIDC access-token / JWT-SVID issuer.
//!
//! Consumes a [`JwtKeyStore`](crate::keystore::JwtKeyStore) for signing
//! material; never holds raw key bytes itself. Hand-rolls the JWS
//! envelope (header.payload.signature) so we sidestep the algorithm-
//! confusion CVE class that affects general-purpose JWT libraries
//! (CVE-2026-22817 / -27804 / -23552 and the long history before).
//!
//! # Closures of the prior gap analyses
//!
//! - `docs/wimse-aims-conformance-gap.md`:
//!   - GAP-3 — `typ: at+jwt` header (RFC 9068 §2.1) is set unconditionally.
//!   - GAP-4 — `client_id` claim is required in `MintRequest`.
//!   - GAP-5 — `scope` claim is optional, omitted from wire when `None`.
//!   - GAP-6 — `act` (RFC 8693 §4.1) is supported via a recursive struct.
//!   - GAP-7 — the nucleus-specific kind hint is serialized as
//!     `urn:nucleus:kind` per RFC 7519 §4.3 collision-resistant naming.
//!   - GAP-9 — issuer URL MUST be `https://...`; rejected at construction.
//!
//! - `docs/local-issuer-prod-readiness-gap.md`:
//!   - GA-3 — rotation lives in the keystore; JwtIssuer always signs
//!     with whatever the keystore says is active.
//!   - GA-6 — lifetime hard-capped at 3600 seconds; rejected higher
//!     at construction.
//!   - GA-10 — algorithm-pinned `EdDSA` in the header at compile time
//!     (literal string in `format!`).
//!   - GA-12 — no `warn_once`; invariants are asserted, not warned.
//!   - GA-13 — no raw key accessor; the keystore signs internally.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use nucleus_lineage::CallSpiffeId;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::keystore::{JwtKeyStore, KeyStoreError};

/// Hard cap on token lifetime, matching `THREAT_MODEL.md` T03 mitigation
/// (replay defense bounded by token TTL). Real-world relying-party
/// SPIFFE WIF integrations cap inbound tokens at 1h; we match that
/// upper bound so our outbound tokens are always acceptable.
pub const MAX_LIFETIME_SECS: u64 = 3600;

#[derive(Debug, Error)]
pub enum JwtIssuerError {
    #[error("issuer URL must start with `https://`, got {0:?}")]
    NonHttpsIssuer(String),
    #[error("issuer URL must be non-empty and contain a host")]
    EmptyIssuer,
    #[error("token lifetime {got}s exceeds cap {max}s")]
    LifetimeTooLong { got: u64, max: u64 },
    #[error("token lifetime must be > 0s (configured: 0)")]
    LifetimeZero,
    #[error("audience must be non-empty")]
    EmptyAudience,
    #[error("client_id must be non-empty")]
    EmptyClientId,
    #[error("keystore does not support rotation; cannot bootstrap production JwtIssuer")]
    KeystoreLacksRotation,
    #[error("keystore error: {0}")]
    Keystore(#[from] KeyStoreError),
    #[error("clock before unix epoch")]
    Clock,
    #[error("claims serialization: {0}")]
    Encoding(String),
}

/// RFC 8693 §4.1 delegated-actor chain. Recursive: an `act` may have
/// its own `act` for multi-hop delegation. v1 emits at most one hop;
/// the recursive shape is preserved so #39 (token exchange) can chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DelegatedActor {
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<DelegatedActor>>,
}

/// Claims wire-shape for the JWT body. Conforms to RFC 9068 + RFC 8693
/// delegation chain + the nucleus extension `urn:nucleus:kind`.
///
/// Field order in the serialized JSON matches struct order. This is
/// not security-significant but makes test KATs stable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub client_id: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<DelegatedActor>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "urn:nucleus:kind"
    )]
    pub nucleus_kind: Option<String>,
}

/// Caller-supplied mint inputs. Variant claims (scope, act, kind,
/// client_id) are explicit so the call site declares its intent rather
/// than defaulting to something surprising.
#[derive(Debug, Clone)]
pub struct MintRequest {
    pub subject: CallSpiffeId,
    pub audience: String,
    /// For pod-bound mints this is typically `subject.as_str()`; for
    /// token-exchange responses (#39) it is the federation-rule ID.
    pub client_id: String,
    pub scope: Option<String>,
    pub act: Option<DelegatedActor>,
    /// Maps to `urn:nucleus:kind` per RFC 7519 §4.3.
    pub kind: Option<String>,
}

/// Boundary kind for [`JwtIssuer::mint_boundary_svid`] — distinguishes
/// the system-boundary class so the minted SVID's path embeds the
/// boundary type explicitly.
///
/// Per `project_per_call_spiffe_lineage` memory (Phase 1, boundary-only):
/// per-call SVIDs are minted ONLY when crossing a system boundary
/// (LLM call, outbound HTTP, external write). Internal tool-to-tool
/// flows stay on portcullis labels — there is no equivalent helper
/// for non-boundary flows, by design.
#[derive(Debug, Clone, Copy)]
pub enum BoundaryKind {
    /// Outbound to an LLM provider (model API call).
    LlmCall,
    /// Outbound HTTP or other network call to a non-LLM destination.
    OutboundHttp,
    /// Write to an external store (filesystem, database, message queue,
    /// blob storage).
    ExternalWrite,
}

impl BoundaryKind {
    /// Path segment identifier embedded in the minted SVID's URI.
    pub fn path_segment(self) -> &'static str {
        match self {
            BoundaryKind::LlmCall => "llm_call",
            BoundaryKind::OutboundHttp => "outbound_http",
            BoundaryKind::ExternalWrite => "external_write",
        }
    }

    /// `urn:nucleus:kind` claim value for the boundary SVID.
    pub fn claim_kind(self) -> String {
        format!("boundary_{}", self.path_segment())
    }
}

/// Boundary-SVID mint request.
#[derive(Debug, Clone)]
pub struct BoundarySvidRequest {
    /// The pod (or upstream call) on whose behalf this boundary-SVID is minted.
    pub parent: CallSpiffeId,
    pub kind: BoundaryKind,
    /// The external audience (e.g. the LLM provider's API URL).
    pub audience: String,
    /// Content fingerprint — bytes whose SHA-256 will be embedded as
    /// `/sha256:<hex>` in the SVID path for content-addressed lineage.
    /// Typically the prompt body (for `LlmCall`) or request body
    /// (for `OutboundHttp` / `ExternalWrite`).
    pub content: Vec<u8>,
    /// Optional scope on the minted token.
    pub scope: Option<String>,
}

/// Outcome of a successful boundary mint.
#[derive(Debug, Clone)]
pub struct MintedBoundarySvid {
    /// The compact JWS — pass this as the bearer token on the outbound
    /// call.
    pub token: String,
    /// The new SPIFFE ID assigned to this boundary call. Audit
    /// emitters use this as the `to` side of an
    /// `EdgeKind::Other { name: "svid_issued" }` lineage edge per
    /// `project_per_call_spiffe_lineage` Phase 1.
    pub subject: CallSpiffeId,
}

/// Production-grade JWT issuer backed by a [`JwtKeyStore`].
///
/// `Arc<JwtIssuer>` is safe to share across the axum router; all
/// internal state delegates to the keystore which is itself `Send + Sync`.
pub struct JwtIssuer {
    keystore: Arc<dyn JwtKeyStore>,
    issuer_url: String,
    lifetime: Duration,
}

impl std::fmt::Debug for JwtIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtIssuer")
            .field("issuer_url", &self.issuer_url)
            .field("lifetime_secs", &self.lifetime.as_secs())
            .field("keystore", &"<dyn JwtKeyStore>")
            .finish()
    }
}

impl JwtIssuer {
    /// Construct. Validates that the issuer URL is HTTPS (GAP-9), the
    /// lifetime is within bounds (GA-6), and the keystore supports
    /// rotation (open question from #31).
    pub fn new(
        keystore: Arc<dyn JwtKeyStore>,
        issuer_url: String,
        lifetime: Duration,
    ) -> Result<Self, JwtIssuerError> {
        if issuer_url.is_empty() {
            return Err(JwtIssuerError::EmptyIssuer);
        }
        let rest = issuer_url
            .strip_prefix("https://")
            .ok_or_else(|| JwtIssuerError::NonHttpsIssuer(issuer_url.clone()))?;
        if rest.is_empty() {
            return Err(JwtIssuerError::EmptyIssuer);
        }
        let secs = lifetime.as_secs();
        if secs == 0 {
            return Err(JwtIssuerError::LifetimeZero);
        }
        if secs > MAX_LIFETIME_SECS {
            return Err(JwtIssuerError::LifetimeTooLong {
                got: secs,
                max: MAX_LIFETIME_SECS,
            });
        }
        if !keystore.supports_rotation() {
            return Err(JwtIssuerError::KeystoreLacksRotation);
        }
        Ok(Self {
            keystore,
            issuer_url,
            lifetime,
        })
    }

    /// The advertised issuer URL (the `iss` claim of every minted token).
    pub fn issuer_url(&self) -> &str {
        &self.issuer_url
    }

    /// The active KID, sourced from the keystore. Exposes the same
    /// answer that the next `mint()` will embed; useful for log
    /// emission without minting.
    pub fn active_kid(&self) -> Result<String, JwtIssuerError> {
        Ok(self.keystore.active_kid()?)
    }

    /// Mint a per-call boundary SVID (Phase 1, boundary-only per
    /// `project_per_call_spiffe_lineage`).
    ///
    /// Derives a child [`CallSpiffeId`] under `parent` with path
    /// `/call/<uuid>/{llm_call|outbound_http|external_write}/sha256:<hex>`,
    /// then mints a JWT bound to that subject. The token carries:
    /// - `sub` = the new child SPIFFE ID
    /// - `client_id` = the parent's SPIFFE ID (the pod on whose behalf)
    /// - `act` = recursive [`DelegatedActor`] rooted at the parent
    /// - `urn:nucleus:kind` = `"boundary_{kind}"` for audit routing
    ///
    /// Acceptance criterion (e) from task #46 — the existence of a
    /// **named, scoped** `mint_boundary_svid` helper (with NO sibling
    /// helper for internal tool-to-tool flows) is the API-level
    /// enforcement of "boundary-only" minting. Internal flows use
    /// portcullis labels, not this method.
    pub fn mint_boundary_svid(
        &self,
        request: BoundarySvidRequest,
    ) -> Result<MintedBoundarySvid, JwtIssuerError> {
        if request.audience.trim().is_empty() {
            return Err(JwtIssuerError::EmptyAudience);
        }
        // Derive the child SPIFFE ID using CallSpiffeId's existing
        // content-addressed derive methods.
        let child = match request.kind {
            BoundaryKind::LlmCall => request
                .parent
                .derive_llm(request.kind.path_segment(), "prompt", &request.content)
                .map_err(|e| JwtIssuerError::Encoding(format!("derive boundary id: {e}")))?,
            BoundaryKind::OutboundHttp | BoundaryKind::ExternalWrite => request
                .parent
                .derive_tool(request.kind.path_segment(), Some(&request.content))
                .map_err(|e| JwtIssuerError::Encoding(format!("derive boundary id: {e}")))?,
        };

        let parent_id = request.parent.to_string();
        let token = self.mint(MintRequest {
            subject: child.clone(),
            audience: request.audience,
            client_id: parent_id.clone(),
            scope: request.scope,
            act: Some(DelegatedActor {
                sub: parent_id,
                act: None,
            }),
            kind: Some(request.kind.claim_kind()),
        })?;

        Ok(MintedBoundarySvid {
            token,
            subject: child,
        })
    }

    /// Mint a compact JWS (RFC 7515 §3.1) — three base64url segments
    /// separated by `.`. The signing material comes from the keystore;
    /// JwtIssuer never sees the raw signing key.
    pub fn mint(&self, request: MintRequest) -> Result<String, JwtIssuerError> {
        if request.audience.trim().is_empty() {
            return Err(JwtIssuerError::EmptyAudience);
        }
        if request.client_id.trim().is_empty() {
            return Err(JwtIssuerError::EmptyClientId);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JwtIssuerError::Clock)?
            .as_secs();

        let kid = self.keystore.active_kid()?;

        // (#55 MED-2) Defense-in-depth: assert the KID is base64url-safe
        // before interpolating into header JSON. KIDs are RFC 7638
        // thumbprints (43 chars from `[A-Za-z0-9_-]`) so the charset
        // is already constrained at the keystore boundary; this
        // `debug_assert!` documents the invariant + catches any future
        // refactor that swaps the KID source for operator-supplied
        // strings (which would break header parsing or smuggle claims).
        debug_assert!(
            kid.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "kid must be base64url-safe (RFC 7638 thumbprint); got {kid:?}"
        );

        // Header: alg/kid/typ in lexicographic order. Hand-built so the
        // typ value is hard-coded; no library can be tricked into
        // emitting `alg: none` or HS-of-public-key etc.
        let header_json = format!(r#"{{"alg":"EdDSA","kid":"{}","typ":"at+jwt"}}"#, kid);

        let claims = AccessTokenClaims {
            iss: self.issuer_url.clone(),
            sub: request.subject.to_string(),
            aud: request.audience,
            client_id: request.client_id,
            iat: now,
            exp: now + self.lifetime.as_secs(),
            jti: Uuid::new_v4().to_string(),
            scope: request.scope,
            act: request.act.map(Box::new),
            nucleus_kind: request.kind,
        };
        let payload_json =
            serde_json::to_string(&claims).map_err(|e| JwtIssuerError::Encoding(e.to_string()))?;

        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");

        let signed = self.keystore.sign(signing_input.as_bytes())?;
        debug_assert_eq!(signed.alg, "EdDSA", "keystore must sign EdDSA");
        debug_assert_eq!(signed.kid, kid, "active KID raced between query and sign");

        let sig_b64 = URL_SAFE_NO_PAD.encode(&signed.signature);
        Ok(format!("{signing_input}.{sig_b64}"))
    }
}

/// Helper for decoding minted tokens in tests. Production callers should
/// use a proper validator (RP-side) — this function does NOT verify the
/// signature and is `#[cfg(test)]`-only.
#[cfg(test)]
pub(crate) fn decode_unverified(
    token: &str,
) -> Result<(serde_json::Value, AccessTokenClaims, Vec<u8>), JwtIssuerError> {
    let mut parts = token.splitn(3, '.');
    let header_b64 = parts
        .next()
        .ok_or_else(|| JwtIssuerError::Encoding("missing header".into()))?;
    let payload_b64 = parts
        .next()
        .ok_or_else(|| JwtIssuerError::Encoding("missing payload".into()))?;
    let sig_b64 = parts
        .next()
        .ok_or_else(|| JwtIssuerError::Encoding("missing signature".into()))?;

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|e| JwtIssuerError::Encoding(format!("header b64: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| JwtIssuerError::Encoding(format!("header json: {e}")))?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| JwtIssuerError::Encoding(format!("payload b64: {e}")))?;
    let claims: AccessTokenClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| JwtIssuerError::Encoding(format!("payload json: {e}")))?;

    let sig = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| JwtIssuerError::Encoding(format!("sig b64: {e}")))?;
    Ok((header, claims, sig))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::InMemoryKeyStore;
    use ed25519_dalek::Verifier as _;

    fn store() -> Arc<dyn JwtKeyStore> {
        Arc::new(InMemoryKeyStore::new())
    }

    fn pod() -> CallSpiffeId {
        CallSpiffeId::pod("prod.example.com", "agents", "coder").unwrap()
    }

    fn issuer(lifetime_secs: u64) -> JwtIssuer {
        JwtIssuer::new(
            store(),
            "https://oidc.nucleus.example/".to_string(),
            Duration::from_secs(lifetime_secs),
        )
        .unwrap()
    }

    fn basic_mint(iss: &JwtIssuer) -> String {
        iss.mint(MintRequest {
            subject: pod(),
            audience: "https://rp-a.example/api".to_string(),
            client_id: "spiffe://prod.example.com/ns/agents/sa/coder".to_string(),
            scope: None,
            act: None,
            kind: None,
        })
        .unwrap()
    }

    #[test]
    fn new_rejects_non_https_issuer() {
        let err = JwtIssuer::new(
            store(),
            "http://nope.example/".to_string(),
            Duration::from_secs(300),
        )
        .unwrap_err();
        assert!(matches!(err, JwtIssuerError::NonHttpsIssuer(_)));
    }

    #[test]
    fn new_rejects_empty_issuer() {
        let err = JwtIssuer::new(store(), String::new(), Duration::from_secs(300)).unwrap_err();
        assert!(matches!(err, JwtIssuerError::EmptyIssuer));
    }

    #[test]
    fn new_rejects_issuer_with_only_scheme() {
        let err =
            JwtIssuer::new(store(), "https://".to_string(), Duration::from_secs(300)).unwrap_err();
        assert!(matches!(err, JwtIssuerError::EmptyIssuer));
    }

    #[test]
    fn new_rejects_lifetime_over_cap() {
        let err = JwtIssuer::new(
            store(),
            "https://oidc.nucleus.example/".to_string(),
            Duration::from_secs(MAX_LIFETIME_SECS + 1),
        )
        .unwrap_err();
        assert!(matches!(err, JwtIssuerError::LifetimeTooLong { .. }));
    }

    #[test]
    fn new_rejects_lifetime_zero() {
        let err = JwtIssuer::new(
            store(),
            "https://oidc.nucleus.example/".to_string(),
            Duration::from_secs(0),
        )
        .unwrap_err();
        assert!(matches!(err, JwtIssuerError::LifetimeZero));
    }

    #[test]
    fn mint_produces_three_dot_separated_segments() {
        let iss = issuer(300);
        let token = basic_mint(&iss);
        assert_eq!(token.matches('.').count(), 2);
    }

    #[test]
    fn header_contains_typ_at_jwt_and_alg_eddsa() {
        let iss = issuer(300);
        let token = basic_mint(&iss);
        let (header, _, _) = decode_unverified(&token).unwrap();
        assert_eq!(header["typ"], "at+jwt");
        assert_eq!(header["alg"], "EdDSA");
        // KID is present and matches the keystore's active KID.
        let kid = header["kid"].as_str().expect("kid present");
        assert!(!kid.is_empty());
    }

    #[test]
    fn header_alg_is_never_none_or_hmac() {
        // Defense-in-depth: scan the header bytes for forbidden alg
        // values. If a refactor ever tries to emit one, this test
        // fires loud.
        let iss = issuer(300);
        let token = basic_mint(&iss);
        let header_b64 = token.split('.').next().unwrap();
        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).unwrap();
        let header_str = std::str::from_utf8(&header_bytes).unwrap();
        for forbidden in [
            "\"alg\":\"none\"",
            "\"alg\":\"HS",
            "\"alg\":\"RS",
            "\"alg\":\"ES",
        ] {
            assert!(
                !header_str.contains(forbidden),
                "header must not contain {forbidden:?}: {header_str}"
            );
        }
    }

    #[test]
    fn claims_carry_required_rfc9068_fields() {
        let iss = issuer(300);
        let token = basic_mint(&iss);
        let (_, claims, _) = decode_unverified(&token).unwrap();
        assert_eq!(claims.iss, "https://oidc.nucleus.example/");
        assert_eq!(claims.sub, pod().to_string());
        assert_eq!(claims.aud, "https://rp-a.example/api");
        assert_eq!(claims.client_id, pod().to_string());
        assert!(claims.exp > claims.iat);
        assert_eq!(claims.exp - claims.iat, 300);
        assert!(!claims.jti.is_empty());
    }

    #[test]
    fn optional_claims_round_trip() {
        let iss = issuer(300);
        let token = iss
            .mint(MintRequest {
                subject: pod(),
                audience: "aud".into(),
                client_id: "client".into(),
                scope: Some("read:bundles".into()),
                act: Some(DelegatedActor {
                    sub: "spiffe://prod.example.com/ns/agents/sa/operator".into(),
                    act: None,
                }),
                kind: Some("llm_call".into()),
            })
            .unwrap();
        let (_, claims, _) = decode_unverified(&token).unwrap();
        assert_eq!(claims.scope.as_deref(), Some("read:bundles"));
        assert_eq!(
            claims.act.unwrap().sub,
            "spiffe://prod.example.com/ns/agents/sa/operator"
        );
        assert_eq!(claims.nucleus_kind.as_deref(), Some("llm_call"));
    }

    #[test]
    fn urn_nucleus_kind_uses_namespaced_name_on_the_wire() {
        let iss = issuer(300);
        let token = iss
            .mint(MintRequest {
                subject: pod(),
                audience: "aud".into(),
                client_id: "client".into(),
                scope: None,
                act: None,
                kind: Some("test-kind".into()),
            })
            .unwrap();
        let payload_b64 = token.split('.').nth(1).unwrap();
        let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
        let payload_str = std::str::from_utf8(&payload_bytes).unwrap();
        // The serialized form MUST use the URN-namespaced name, not the
        // bare struct-field name.
        assert!(payload_str.contains("urn:nucleus:kind"));
        assert!(!payload_str.contains("nucleus_kind"));
    }

    #[test]
    fn empty_audience_rejected() {
        let iss = issuer(300);
        let err = iss
            .mint(MintRequest {
                subject: pod(),
                audience: "".into(),
                client_id: "client".into(),
                scope: None,
                act: None,
                kind: None,
            })
            .unwrap_err();
        assert!(matches!(err, JwtIssuerError::EmptyAudience));
    }

    #[test]
    fn empty_client_id_rejected() {
        let iss = issuer(300);
        let err = iss
            .mint(MintRequest {
                subject: pod(),
                audience: "aud".into(),
                client_id: "".into(),
                scope: None,
                act: None,
                kind: None,
            })
            .unwrap_err();
        assert!(matches!(err, JwtIssuerError::EmptyClientId));
    }

    /// Property test: every minted token's `kid` is present in the
    /// keystore's verify-set. Acceptance criterion (f) from #34.
    #[test]
    fn minted_kid_is_always_in_keystore_verify_set() {
        let store = Arc::new(InMemoryKeyStore::new());
        let iss = JwtIssuer::new(
            store.clone() as Arc<dyn JwtKeyStore>,
            "https://oidc.nucleus.example/".to_string(),
            Duration::from_secs(300),
        )
        .unwrap();

        for _ in 0..20 {
            // Optionally rotate between mints. After rotation, the OLD
            // kid is still in the verify-set (grace window), and the
            // NEW kid is now active. Either way, the kid in the emitted
            // header must be one of the verify-set entries.
            if rand::random::<bool>() {
                store.rotate().unwrap();
            }
            let token = basic_mint(&iss);
            let (header, _, _) = decode_unverified(&token).unwrap();
            let kid = header["kid"].as_str().unwrap();
            store
                .verify_key(kid)
                .unwrap_or_else(|_| panic!("kid {kid:?} must be in verify-set"));
        }
    }

    /// Verifies the signature against the keystore's verifying key.
    /// Closes the round-trip property: mint+verify works end-to-end
    /// when the verifier knows the active KID.
    #[test]
    fn signature_verifies_against_active_keystore_key() {
        let store = Arc::new(InMemoryKeyStore::new());
        let iss = JwtIssuer::new(
            store.clone() as Arc<dyn JwtKeyStore>,
            "https://oidc.nucleus.example/".to_string(),
            Duration::from_secs(300),
        )
        .unwrap();
        let token = basic_mint(&iss);
        let mut parts = token.splitn(3, '.');
        let header_b64 = parts.next().unwrap();
        let payload_b64 = parts.next().unwrap();
        let sig_b64 = parts.next().unwrap();
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).unwrap();
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

        let active_kid = store.active_kid().unwrap();
        let vk = store.verify_key(&active_kid).unwrap();
        vk.verifying_key
            .verify(signing_input.as_bytes(), &sig)
            .expect("signature verifies against active keystore key");
    }

    // ── Boundary-SVID mint helper (#46) ────────────────────────────────

    #[test]
    fn boundary_kind_path_segments_are_distinct() {
        assert_ne!(
            BoundaryKind::LlmCall.path_segment(),
            BoundaryKind::OutboundHttp.path_segment()
        );
        assert_ne!(
            BoundaryKind::OutboundHttp.path_segment(),
            BoundaryKind::ExternalWrite.path_segment()
        );
        for k in [
            BoundaryKind::LlmCall,
            BoundaryKind::OutboundHttp,
            BoundaryKind::ExternalWrite,
        ] {
            assert!(k.claim_kind().starts_with("boundary_"));
        }
    }

    #[test]
    fn llm_call_boundary_mints_child_with_expected_path() {
        let iss = issuer(300);
        let parent = pod();
        let minted = iss
            .mint_boundary_svid(BoundarySvidRequest {
                parent: parent.clone(),
                kind: BoundaryKind::LlmCall,
                audience: "https://llm.rp.example/v1".to_string(),
                content: b"hi model".to_vec(),
                scope: None,
            })
            .unwrap();
        // Child is under parent.
        assert!(minted.subject.as_str().starts_with(parent.as_str()));
        // Path has /call/<uuid>/llm_call/prompt/sha256:...
        assert!(minted.subject.as_str().contains("/call/"));
        assert!(minted.subject.as_str().contains("/llm_call/prompt/sha256:"));
    }

    #[test]
    fn outbound_http_boundary_mints_child_with_expected_path() {
        let iss = issuer(300);
        let parent = pod();
        let minted = iss
            .mint_boundary_svid(BoundarySvidRequest {
                parent: parent.clone(),
                kind: BoundaryKind::OutboundHttp,
                audience: "https://external.rp.example/api".to_string(),
                content: b"request body".to_vec(),
                scope: None,
            })
            .unwrap();
        assert!(minted.subject.as_str().starts_with(parent.as_str()));
        assert!(minted.subject.as_str().contains("/call/"));
        assert!(minted
            .subject
            .as_str()
            .contains("/tool/outbound_http/sha256:"));
    }

    #[test]
    fn boundary_claims_carry_parent_in_act_and_client_id() {
        let iss = issuer(300);
        let parent = pod();
        let minted = iss
            .mint_boundary_svid(BoundarySvidRequest {
                parent: parent.clone(),
                kind: BoundaryKind::LlmCall,
                audience: "https://llm.rp.example/v1".to_string(),
                content: b"x".to_vec(),
                scope: None,
            })
            .unwrap();
        let (_, claims, _) = decode_unverified(&minted.token).unwrap();
        // Subject is the new child SVID.
        assert_eq!(claims.sub, minted.subject.to_string());
        // client_id is the parent (pod on whose behalf).
        assert_eq!(claims.client_id, parent.to_string());
        // act.sub is the parent (RFC 8693 §4.1 delegation chain).
        let act = claims.act.expect("act must be present");
        assert_eq!(act.sub, parent.to_string());
        // kind embeds the boundary class.
        assert_eq!(claims.nucleus_kind.as_deref(), Some("boundary_llm_call"));
    }

    #[test]
    fn boundary_mint_rejects_empty_audience() {
        let iss = issuer(300);
        let err = iss
            .mint_boundary_svid(BoundarySvidRequest {
                parent: pod(),
                kind: BoundaryKind::LlmCall,
                audience: "".into(),
                content: b"x".to_vec(),
                scope: None,
            })
            .unwrap_err();
        assert!(matches!(err, JwtIssuerError::EmptyAudience));
    }

    #[test]
    fn different_content_yields_different_child_paths() {
        let iss = issuer(300);
        let parent = pod();
        let a = iss
            .mint_boundary_svid(BoundarySvidRequest {
                parent: parent.clone(),
                kind: BoundaryKind::ExternalWrite,
                audience: "https://store.rp.example/api".into(),
                content: b"payload-a".to_vec(),
                scope: None,
            })
            .unwrap();
        let b = iss
            .mint_boundary_svid(BoundarySvidRequest {
                parent,
                kind: BoundaryKind::ExternalWrite,
                audience: "https://store.rp.example/api".into(),
                content: b"payload-b".to_vec(),
                scope: None,
            })
            .unwrap();
        // Different content → different content-hash segment.
        // (UUIDs also differ, but content hashes are what tracks lineage.)
        assert_ne!(a.subject.content_hash_hex(), b.subject.content_hash_hex());
    }

    #[test]
    fn deny_unknown_fields_on_wire_types() {
        // Future-proof: if a refactor accidentally adds a field that
        // produces extra wire bytes downstream, this test catches it.
        let extra_field = r#"{
            "iss":"https://oidc.nucleus.example/",
            "sub":"spiffe://prod.example.com/ns/agents/sa/coder",
            "aud":"a","client_id":"c","iat":1,"exp":2,"jti":"j",
            "rogue_field": "should not parse"
        }"#;
        let result: Result<AccessTokenClaims, _> = serde_json::from_str(extra_field);
        assert!(result.is_err(), "unknown field must be rejected");
    }
}

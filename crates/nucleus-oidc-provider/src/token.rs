//! `POST /oauth/token` — RFC 8693 token exchange.
//!
//! Single supported grant: `urn:ietf:params:oauth:grant-type:token-exchange`.
//! The caller presents a `subject_token` (a JWT-SVID) plus an `audience`;
//! the OP validates the subject_token, consults the federation registry
//! (#41, currently allow-all stub), records the jti for replay defense,
//! and mints a fresh audience-bound access token via [`JwtIssuer`].
//!
//! # Validation pipeline
//!
//! 1. Parse `application/x-www-form-urlencoded` body.
//! 2. Enforce `grant_type` and `subject_token_type`.
//! 3. Peek at the subject_token's `iss`, `sub`, `exp`, `jti` claims —
//!    **signature verification against SPIRE bundle is task #45**. Until
//!    then we accept any well-formed JWT-SVID; this is documented as a
//!    pre-prod limitation.
//! 4. Federation rule check (allow-all stub until #41 lands).
//! 5. Reject replay via [`JtiCache`].
//! 6. Mint response via [`JwtIssuer::mint`] with `act` claim attesting
//!    the original SVID subject per RFC 8693 §4.1.
//!
//! Error responses follow RFC 6749 §5.2 + RFC 8693 §2.2.2 shapes
//! (`{error, error_description}`).

use axum::{
    Json,
    extract::{Form, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nucleus_lineage::CallSpiffeId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq as _;

use crate::app::AppState;
use crate::error::OidcApiError;
use crate::issuer::{DelegatedActor, MintRequest};

/// RFC 8693 grant-type URI for token exchange.
pub const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// RFC 8693 token-type URI for JWTs (covers JWT-SVIDs).
pub const TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

/// RFC 8693 token-type URI for issued access tokens.
pub const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";

/// `actor_token_type` for a nucleus pod certificate presented as the acting
/// party's authority.
///
/// RFC 8693 §2.1 lets a token type be any URI, and `actor_token` is the slot
/// for "the party acting on the subject's behalf" — which is exactly what a
/// pod certificate is: the signed, attenuating record of what a person
/// delegated to this workload. It is not a JWT, and it does not need to be.
pub const TOKEN_TYPE_POD_CERTIFICATE: &str = "urn:nucleus:params:oauth:token-type:pod-certificate";

/// RFC 8693 §2.1 request fields. Optional fields are `Option<String>`;
/// missing required fields surface as `InvalidRequest` per RFC 8693
/// §2.2.2.
#[derive(Debug, Deserialize)]
pub struct TokenExchangeRequest {
    pub grant_type: String,
    pub subject_token: String,
    pub subject_token_type: String,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub requested_token_type: Option<String>,
    #[serde(default)]
    pub actor_token: Option<String>,
    #[serde(default)]
    pub actor_token_type: Option<String>,
}

/// RFC 8693 §2.2.1 successful-response body.
#[derive(Debug, Serialize)]
pub struct TokenExchangeResponse {
    pub access_token: String,
    pub issued_token_type: &'static str,
    pub token_type: &'static str,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Hard cap on accepted subject_token lifetime. The OP enforces this
/// regardless of the upstream IdP's `exp` to defend the JtiCache
/// against pollution attacks (#55 HIGH-1).
pub const MAX_SUBJECT_TTL_SECS: u64 = 3600;

/// `aud` claim shape — RFC 7519 §4.1.3 permits either a string or
/// array of strings.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum AudienceClaim {
    Single(String),
    Multi(Vec<String>),
}

impl AudienceClaim {
    fn contains(&self, target: &str) -> bool {
        match self {
            AudienceClaim::Single(s) => s == target,
            AudienceClaim::Multi(v) => v.iter().any(|a| a == target),
        }
    }
}

/// Subset of JWT-SVID claims we read from the subject_token.
/// `iat`/`iss` are accepted-but-not-validated — we keep the field
/// declarations so `deny_unknown_fields` doesn't reject realistic
/// SPIFFE JWT-SVIDs that carry them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct SubjectClaims {
    sub: String,
    #[serde(default)]
    aud: Option<AudienceClaim>,
    #[serde(default)]
    exp: Option<u64>,
    /// RFC 7519 §4.1.5 not-before (#55 HIGH-2).
    #[serde(default)]
    nbf: Option<u64>,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    jti: Option<String>,
}

/// The effects a presented pod certificate grants, if one was presented.
///
/// `None` means no certificate came with the request — not "no effects". The
/// two are different answers and the caller has to keep them apart: a rule that
/// requires delegated authority must refuse the first, not treat it as an empty
/// grant that happens to satisfy nothing.
///
/// # What makes this trustworthy
///
/// `AttenuationToken::verify` walks the chain against the root key **the token
/// itself carries**, which proves the chain is internally consistent and
/// nothing more — anyone can generate a root and mint a certificate under it.
/// So the pinned `cert_root_pubkey` is checked FIRST, in constant time, and a
/// token rooted anywhere else is refused before its chain is even walked. That
/// comparison is the whole security of this function.
fn granted_effects(
    state: &AppState,
    req: &TokenExchangeRequest,
) -> Result<Option<BTreeSet<String>>, OidcApiError> {
    let Some(actor_token) = req.actor_token.as_deref().filter(|t| !t.trim().is_empty()) else {
        return Ok(None);
    };
    match req.actor_token_type.as_deref() {
        Some(TOKEN_TYPE_POD_CERTIFICATE) => {}
        other => {
            return Err(OidcApiError::InvalidGrant(format!(
                "actor_token_type must be {TOKEN_TYPE_POD_CERTIFICATE:?} for a pod certificate, \
                 got {other:?}"
            )));
        }
    }

    let Some(pinned) = state.cert_root_pubkey.as_deref() else {
        tracing::warn!(
            "a pod certificate was presented but the OP has no pinned certificate root \
             (NUCLEUS_OIDC_CERT_ROOT_PUBKEY) — refusing, because an unpinned chain proves \
             only that whoever minted it was consistent with themselves"
        );
        return Err(OidcApiError::InvalidGrant(
            "this OP does not accept pod certificates (no pinned certificate root)".into(),
        ));
    };

    let token = portcullis::AttenuationToken::from_base64(actor_token).map_err(|e| {
        tracing::warn!(error = %e, "actor_token is not a decodable pod certificate");
        OidcApiError::InvalidGrant("actor_token is not a decodable pod certificate".into())
    })?;

    // THE check. Constant-time so a wrong root cannot be recovered a byte at a
    // time by timing the refusal.
    let presented = token.root_public_key();
    let rooted_here =
        presented.len() == pinned.len() && bool::from(presented.ct_eq(pinned.as_slice()));
    if !rooted_here {
        tracing::warn!(
            "actor_token certificate is rooted in a key this OP does not trust — refusing \
             before verifying the chain"
        );
        return Err(OidcApiError::InvalidGrant(
            "actor_token certificate is not rooted in this OP's trusted root".into(),
        ));
    }

    let verified = token.verify_default(chrono::Utc::now()).map_err(|e| {
        tracing::warn!(error = %e, "actor_token certificate failed verification");
        OidcApiError::InvalidGrant("actor_token certificate failed verification".into())
    })?;

    // An unmarked effect dimension is "this certificate says nothing about
    // effects", which is NOT the same as "it grants none" — the marker exists
    // precisely to keep those apart. Either way a rule that requires an effect
    // is not satisfied, so both map to an empty set here and the requirement
    // check refuses; the log says which.
    let caps = &verified.effective().capabilities;
    let effects = portcullis::effect_surface::granted_effects(caps).unwrap_or_default();
    if effects.is_empty() {
        tracing::info!(
            "presented pod certificate grants no effects (or carries no effect dimension)"
        );
    }
    Ok(Some(effects))
}

/// Bound a requested scope by the rule's ceiling.
///
/// Narrowing only, and refusing rather than silently trimming: a caller that
/// asks for `read write` under a rule admitting only `read` gets an error,
/// rather than a token that quietly does half of what they asked. A credential
/// that silently means less than its holder believes is its own class of
/// incident — the holder proceeds, the call fails somewhere downstream, and
/// nothing points at the scope.
///
/// The refusal reaches the CALLER as a bare `invalid_target`, and the detail —
/// which scopes were refused, and what the rule admits — goes to the log. That
/// asymmetry is deliberate and matches what the OP already does for federation
/// denials: answering "which scopes would you accept?" would make this endpoint
/// a policy oracle a caller could enumerate. The operator has the log.
///
/// The three states of `ceiling` are [`FederationRule::max_scope`]'s:
/// `None` bounds nothing and therefore admits nothing but an absent request;
/// `Some([])` admits nothing at all; `Some(list)` admits any subset.
///
/// [`FederationRule::max_scope`]: crate::federation::FederationRule::max_scope
fn clamp_scope(
    requested: Option<&str>,
    ceiling: Option<&[String]>,
    requires: Option<&BTreeMap<String, Vec<String>>>,
    granted: Option<&BTreeSet<String>>,
) -> Result<Option<String>, OidcApiError> {
    // Scope is optional in RFC 8693; asking for none is always fine, whatever
    // the rule says. This is what keeps the change from breaking every caller
    // that never wanted one.
    let Some(requested) = requested.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };

    // Scope is a space-delimited list (RFC 6749 §3.3).
    let asked: Vec<&str> = requested.split_whitespace().collect();

    let Some(ceiling) = ceiling else {
        tracing::warn!(
            requested,
            "token exchange requested a scope under a rule that bounds none — refusing; \
             set `max_scope` on the federation rule to admit it"
        );
        return Err(OidcApiError::InvalidTarget(format!(
            "federation rule bounds no scope, so none may be requested (asked for {requested:?});              set `max_scope` on the rule"
        )));
    };

    let refused: Vec<&str> = asked
        .iter()
        .copied()
        .filter(|a| !ceiling.iter().any(|c| c == a))
        .collect();
    if !refused.is_empty() {
        tracing::warn!(
            requested,
            ?refused,
            ?ceiling,
            "token exchange requested a scope outside the federation rule's ceiling"
        );
        return Err(OidcApiError::InvalidTarget(format!(
            "requested scope is outside the federation rule's ceiling: {refused:?} not in \
             {ceiling:?}"
        )));
    }

    // The PRINCIPAL's ceiling, on top of the operator's.
    //
    // `max_scope` says what this rule is willing to issue. `scope_requires`
    // says what a person actually delegated to this workload, and the two are
    // different questions: an operator can be entirely happy for pods to reach
    // an audience with `logs:write` while THIS pod's grant never included the
    // effect that backs it. Both have to hold.
    //
    // This is the step that makes the federated credential carry the
    // attenuation rather than just the identity. SPIFFE says who the workload
    // is; the certificate says what its principal allowed; the token that
    // leaves here is bounded by both.
    if let Some(requires) = requires {
        let mut unbacked: Vec<&str> = Vec::new();
        let mut missing: Vec<String> = Vec::new();
        for token in &asked {
            let Some(needed) = requires.get(*token) else {
                continue; // no claim about what backs it; `max_scope` alone bounds it
            };
            let Some(granted) = granted else {
                unbacked.push(token);
                continue;
            };
            for effect in needed {
                if !granted.contains(effect) {
                    missing.push(format!("{token} needs {effect}"));
                }
            }
        }
        if !unbacked.is_empty() {
            tracing::warn!(
                ?unbacked,
                "scope requires delegated authority but no pod certificate was presented"
            );
            return Err(OidcApiError::InvalidTarget(
                "requested scope requires a pod certificate (actor_token) and none was presented"
                    .into(),
            ));
        }
        if !missing.is_empty() {
            tracing::warn!(
                ?missing,
                ?granted,
                "requested scope is not backed by the effects this certificate grants"
            );
            return Err(OidcApiError::InvalidTarget(
                "requested scope is not backed by the presented certificate's granted effects"
                    .into(),
            ));
        }
    }

    // Echo what was asked for, not the ceiling: the token grants what the
    // caller requested, bounded by the rule — never the rule's whole ceiling
    // just because the caller asked for part of it.
    Ok(Some(asked.join(" ")))
}

pub async fn handler(
    State(state): State<AppState>,
    Form(req): Form<TokenExchangeRequest>,
) -> Result<Response, OidcApiError> {
    // 1. Grant + subject_token_type discipline.
    if req.grant_type != TOKEN_EXCHANGE_GRANT {
        return Err(OidcApiError::UnsupportedGrantType(format!(
            "grant_type must be {TOKEN_EXCHANGE_GRANT:?}, got {:?}",
            req.grant_type
        )));
    }
    if req.subject_token_type != TOKEN_TYPE_JWT {
        return Err(OidcApiError::InvalidRequest(format!(
            "subject_token_type must be {TOKEN_TYPE_JWT:?}, got {:?}",
            req.subject_token_type
        )));
    }
    if let Some(ref t) = req.requested_token_type
        && t != TOKEN_TYPE_ACCESS_TOKEN
    {
        return Err(OidcApiError::InvalidRequest(format!(
            "requested_token_type must be {TOKEN_TYPE_ACCESS_TOKEN:?}, got {t:?}"
        )));
    }

    // 2. Audience selection — RFC 8693 §2.1 says either `audience` or
    //    `resource` carries the target identifier. We require one of
    //    them for federation-rule lookup.
    let audience = req
        .audience
        .clone()
        .or_else(|| req.resource.clone())
        .ok_or_else(|| {
            OidcApiError::InvalidRequest("missing `audience` or `resource`".to_string())
        })?;
    if audience.trim().is_empty() {
        return Err(OidcApiError::InvalidRequest(
            "audience must be non-empty".to_string(),
        ));
    }

    // 3. Decode + verify the subject_token signature against the
    //    SPIRE trust bundle (#45). The decode step happens first to
    //    extract `kid` + `iss` + `sub`; we then dispatch the verifying
    //    key lookup through `state.bundle_provider`.
    let (header_b64, payload_b64, sig_b64) = split_jwt(&req.subject_token).map_err(|m| {
        tracing::warn!(detail = %m, "subject_token malformed");
        OidcApiError::InvalidGrant(m)
    })?;

    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64.as_bytes())
        .map_err(|e| OidcApiError::InvalidGrant(format!("header b64: {e}")))?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes)
        .map_err(|e| OidcApiError::InvalidGrant(format!("header json: {e}")))?;
    let alg = header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OidcApiError::InvalidGrant("subject_token missing alg".into()))?;
    if alg != "EdDSA" {
        // Algorithm-pin per THREAT_MODEL T04 — we only accept EdDSA
        // subject_tokens. Other algs are documented as v2 work.
        tracing::warn!(alg = %alg, "subject_token unsupported alg");
        return Err(OidcApiError::InvalidGrant(format!(
            "subject_token alg {alg:?} unsupported"
        )));
    }
    let kid = header
        .get("kid")
        .and_then(|v| v.as_str())
        .ok_or_else(|| OidcApiError::InvalidGrant("subject_token missing kid".into()))?;

    let claims = decode_jwt_payload(&req.subject_token)
        .map_err(|m| OidcApiError::InvalidGrant(format!("subject_token claim decode: {m}")))?;

    let sub_spiffe = CallSpiffeId::parse(claims.sub.clone()).map_err(|e| {
        OidcApiError::InvalidGrant(format!("subject_token sub is not a SPIFFE ID: {e}"))
    })?;

    // Extract trust-domain (authority) from `spiffe://<trust-domain>/...`
    let sub_str = sub_spiffe.as_str();
    let trust_domain = sub_str
        .strip_prefix("spiffe://")
        .and_then(|rest| rest.split_once('/').map(|(td, _)| td))
        .ok_or_else(|| {
            OidcApiError::InvalidGrant("subject_token sub missing trust-domain".into())
        })?;

    let vk = state
        .bundle_provider
        .verify_key(trust_domain, kid)
        .ok_or_else(|| {
            tracing::warn!(trust_domain = %trust_domain, kid = %kid, "subject_token kid unknown");
            OidcApiError::InvalidGrant(format!(
                "subject_token kid {kid:?} not in trust bundle for {trust_domain:?}"
            ))
        })?;

    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64.as_bytes())
        .map_err(|e| OidcApiError::InvalidGrant(format!("sig b64: {e}")))?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
        OidcApiError::InvalidGrant("subject_token sig wrong length (Ed25519 = 64 bytes)".into())
    })?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    vk.verify_strict(signing_input.as_bytes(), &sig)
        .map_err(|e| {
            tracing::warn!(error = %e, "subject_token signature verify failed");
            OidcApiError::InvalidGrant("subject_token signature verify failed".into())
        })?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OidcApiError::Internal("clock before unix epoch".into()))?
        .as_secs();

    // (#55 HIGH-3) RFC 8693 §1 confused-deputy defense: subject_token
    // `aud` MUST include the OP's own issuer URL. If absent or empty,
    // accept (downstream SPIRE Agent SVIDs sometimes omit `aud`);
    // if present, require the OP to be in the list.
    if let Some(aud_claim) = &claims.aud
        && !aud_claim.contains(state.issuer_url.as_ref())
    {
        tracing::warn!(?aud_claim, op_issuer = %state.issuer_url, "subject_token aud mismatch");
        return Err(OidcApiError::InvalidGrant(
            "subject_token aud does not include OP issuer".into(),
        ));
    }

    // (#55 HIGH-2) RFC 7519 §4.1.5 nbf check with 60s clock-skew leeway
    // (THREAT_MODEL T06).
    if let Some(nbf) = claims.nbf
        && nbf > now.saturating_add(60)
    {
        tracing::warn!(nbf, now, "subject_token not yet valid");
        return Err(OidcApiError::InvalidGrant(
            "subject_token not yet valid (nbf in the future)".into(),
        ));
    }

    let sub_exp = claims.exp.ok_or_else(|| {
        OidcApiError::InvalidGrant("subject_token missing `exp` claim".to_string())
    })?;
    if sub_exp <= now {
        return Err(OidcApiError::InvalidGrant(format!(
            "subject_token already expired ({sub_exp} <= {now})"
        )));
    }

    // 4. Replay defense — every subject_token presentation must be
    //    fresh within its exp window. Subject tokens without `jti`
    //    cannot be replay-protected; reject conservatively.
    let jti = claims.jti.clone().ok_or_else(|| {
        OidcApiError::InvalidGrant("subject_token missing `jti` claim".to_string())
    })?;
    // (#55 HIGH-1) Clamp the JTI retention bound to defend the cache
    // against an upstream IdP that mints `exp = u64::MAX` tokens.
    // Without this clamp a hostile-bundle key can pollute the cache
    // permanently, evicting legitimate short-lived entries via the
    // soonest-expiring eviction policy.
    let jti_retention_bound = sub_exp.min(now.saturating_add(MAX_SUBJECT_TTL_SECS));
    state
        .jti_cache
        .check_and_mark(&jti, jti_retention_bound)
        .map_err(|_| {
            OidcApiError::InvalidGrant(format!("subject_token jti {jti:?} already presented"))
        })?;

    // 5. Federation rule lookup (#41).
    let decision = state
        .federation
        .evaluate(sub_spiffe.as_str(), &audience, TOKEN_EXCHANGE_GRANT);
    let (rule_max_lifetime, rule_max_scope, rule_scope_requires) = match decision {
        crate::federation::Decision::Allow {
            matched_rule_id,
            max_lifetime,
            max_scope,
            scope_requires,
        } => {
            tracing::info!(
                sub = %sub_spiffe,
                audience = %audience,
                matched_rule = %matched_rule_id,
                "federation: ALLOW"
            );
            (max_lifetime, max_scope, scope_requires)
        }
        crate::federation::Decision::Deny(reason) => {
            tracing::warn!(
                sub = %sub_spiffe,
                audience = %audience,
                ?reason,
                "federation: DENY"
            );
            return Err(OidcApiError::InvalidTarget(format!(
                "federation policy denies (sub, audience) — {reason:?}"
            )));
        }
    };

    // 5b. Scope ceiling. The federation rule bounds WHICH audience this
    //     subject may reach and FOR HOW LONG; this bounds WHAT the issued
    //     token may do when it gets there.
    //
    //     Before this, `scope` was echoed from the request verbatim — a
    //     workload asked and the OP minted. The delegation ceiling that the
    //     kernel, the certificate and the effect gate all enforce inside the
    //     boundary simply stopped at it, which is the one place a federated
    //     credential most needs to carry it.
    let cert_effects = granted_effects(&state, &req)?;
    let granted_scope = clamp_scope(
        req.scope.as_deref(),
        rule_max_scope.as_deref(),
        rule_scope_requires.as_ref(),
        cert_effects.as_ref(),
    )?;

    // 6. Mint response token. `act` claim attests the upstream actor
    //    per RFC 8693 §4.1.
    let mint_lifetime = bounded_lifetime(sub_exp, now).min(rule_max_lifetime);
    let client_id = sub_spiffe.to_string();
    let act = Some(DelegatedActor {
        sub: client_id.clone(),
        act: None,
    });
    let issuer = state.issuer.clone();
    let token = issuer
        .mint(MintRequest {
            subject: sub_spiffe,
            audience: audience.clone(),
            client_id,
            scope: granted_scope.clone(),
            // The attenuation, carried. An RP that understands nucleus can
            // enforce per-effect from the token alone rather than being handed
            // the certificate as well; one that does not ignores a namespaced
            // claim it has never heard of.
            effects: cert_effects
                .as_ref()
                .map(|e| e.iter().cloned().collect::<Vec<_>>()),
            act,
            kind: Some("token_exchange".to_string()),
        })
        .map_err(|e| OidcApiError::Internal(format!("mint: {e}")))?;

    let body = TokenExchangeResponse {
        access_token: token,
        issued_token_type: TOKEN_TYPE_ACCESS_TOKEN,
        token_type: "Bearer",
        expires_in: mint_lifetime.as_secs(),
        scope: granted_scope,
    };
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// Clamp the mint lifetime so the response token never outlives the
/// subject_token's exp. Both bounds: ≤ subject_exp - now AND ≤ 1h.
fn bounded_lifetime(subject_exp: u64, now: u64) -> Duration {
    let remaining = subject_exp.saturating_sub(now);
    let bounded = remaining.min(3600);
    Duration::from_secs(bounded.max(1))
}

fn decode_jwt_payload(jwt: &str) -> Result<SubjectClaims, String> {
    let mut parts = jwt.splitn(3, '.');
    let _header = parts
        .next()
        .ok_or_else(|| "jwt missing header".to_string())?;
    let payload_b64 = parts
        .next()
        .ok_or_else(|| "jwt missing payload".to_string())?;
    let _sig = parts
        .next()
        .ok_or_else(|| "jwt missing signature".to_string())?;
    if parts.next().is_some() {
        return Err("jwt has more than 3 parts".to_string());
    }
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| format!("base64url decode: {e}"))?;
    let claims: SubjectClaims =
        serde_json::from_slice(&payload_bytes).map_err(|e| format!("payload json: {e}"))?;
    Ok(claims)
}

/// Split a compact JWS into its three base64url segments without
/// decoding them. Returns owned `String`s so the caller can pass them
/// to both decode (per-segment) and `format!` (signing-input
/// reconstruction).
fn split_jwt(jwt: &str) -> Result<(String, String, String), String> {
    let mut parts = jwt.splitn(3, '.');
    let header = parts
        .next()
        .ok_or_else(|| "jwt missing header".to_string())?;
    let payload = parts
        .next()
        .ok_or_else(|| "jwt missing payload".to_string())?;
    let sig = parts
        .next()
        .ok_or_else(|| "jwt missing signature".to_string())?;
    if parts.next().is_some() {
        return Err("jwt has more than 3 parts".to_string());
    }
    Ok((header.to_string(), payload.to_string(), sig.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuer::JwtIssuer;
    use crate::keystore::{InMemoryKeyStore, JwtKeyStore};
    use axum::body::Body;
    use axum::http::{Method, Request, header};
    use http_body_util::BodyExt;
    use nucleus_oidc_core::JtiCache;
    use std::sync::Arc;
    use tower::ServiceExt;
    use uuid::Uuid;

    /// Test-fixture upstream signer: same Ed25519 keypair used by
    /// `make_subject_jwt` to sign tokens AND by the bundle provider
    /// to verify them. The `kid` is the RFC 7638 thumbprint.
    fn fixture_signer() -> (ed25519_dalek::SigningKey, String) {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let kid = crate::keystore::rfc7638_kid(&sk.verifying_key());
        (sk, kid)
    }

    fn app() -> axum::Router {
        app_with_scope(None)
    }

    /// The same fixture, with a scope ceiling on the rule.
    fn app_with_scope(max_scope: Option<Vec<String>>) -> axum::Router {
        app_full(max_scope, None, None)
    }

    /// The fixture with every ceiling dial exposed.
    fn app_full(
        max_scope: Option<Vec<String>>,
        scope_requires: Option<std::collections::BTreeMap<String, Vec<String>>>,
        cert_root_pubkey: Option<Vec<u8>>,
    ) -> axum::Router {
        let store: Arc<dyn JwtKeyStore> = Arc::new(InMemoryKeyStore::new());
        let issuer = Arc::new(
            JwtIssuer::new(
                store.clone(),
                "https://oidc.nucleus.example/".to_string(),
                Duration::from_secs(300),
            )
            .unwrap(),
        );
        let rules = crate::federation::FederationRules {
            rule: vec![crate::federation::FederationRule {
                id: "test-allow".to_string(),
                subject_prefix: "spiffe://prod.example.com/*".to_string(),
                audience: "https://rp-a.example/api".to_string(),
                allowed_grants: vec![TOKEN_EXCHANGE_GRANT.to_string()],
                max_token_lifetime_secs: 3600,
                max_scope,
                scope_requires,
            }],
        };
        let federation = Arc::new(crate::federation::FederationRegistry::new(rules));

        // Register the fixture signer's public key under
        // (trust_domain=prod.example.com, kid=<rfc7638-thumbprint>).
        let (sk, kid) = fixture_signer();
        let bundle = crate::spire::StaticBundleProvider::new();
        bundle.add_key("prod.example.com", kid, sk.verifying_key());

        crate::app::build_app(crate::app::AppState {
            keystore: store,
            issuer_url: Arc::from("https://oidc.nucleus.example/"),
            issuer,
            jti_cache: Arc::new(JtiCache::new()),
            cert_root_pubkey: cert_root_pubkey.map(Arc::new),
            federation,
            bundle_provider: Arc::new(bundle),
        })
    }

    fn make_subject_jwt(sub: &str, exp_offset_secs: i64, jti: Option<&str>) -> String {
        let (sk, kid) = fixture_signer();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let exp = (now + exp_offset_secs).max(0) as u64;
        let jti_str = jti
            .map(|j| j.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let header_json = format!(r#"{{"alg":"EdDSA","kid":"{kid}","typ":"JWT"}}"#);
        let payload_json = format!(r#"{{"sub":"{sub}","exp":{exp},"jti":"{jti_str}"}}"#);
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        use ed25519_dalek::Signer;
        let sig = sk.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{signing_input}.{sig_b64}")
    }

    /// Subject_token signed by a key NOT in the bundle. Used by the
    /// signature-verification negative tests.
    fn make_subject_jwt_with_unknown_key(sub: &str) -> String {
        let unknown_sk = ed25519_dalek::SigningKey::from_bytes(&[99; 32]);
        let unknown_kid = crate::keystore::rfc7638_kid(&unknown_sk.verifying_key());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let exp = (now + 300) as u64;
        let jti = Uuid::new_v4().to_string();
        let header_json = format!(r#"{{"alg":"EdDSA","kid":"{unknown_kid}","typ":"JWT"}}"#);
        let payload_json = format!(r#"{{"sub":"{sub}","exp":{exp},"jti":"{jti}"}}"#);
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let signing_input = format!("{header_b64}.{payload_b64}");
        use ed25519_dalek::Signer;
        let sig = unknown_sk.sign(signing_input.as_bytes());
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        format!("{signing_input}.{sig_b64}")
    }

    fn form_body(pairs: &[(&str, &str)]) -> String {
        pairs
            .iter()
            .map(|(k, v)| format!("{}={}", urlencode(k), urlencode(v)))
            .collect::<Vec<_>>()
            .join("&")
    }

    fn urlencode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char)
                }
                _ => out.push_str(&format!("%{:02X}", b)),
            }
        }
        out
    }

    async fn post_token(app: axum::Router, body: String) -> Response<Body> {
        app.oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/oauth/token")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
    }

    async fn body_to_value(body: Body) -> serde_json::Value {
        let bytes = body.collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn happy_path_returns_access_token() {
        let sub = "spiffe://prod.example.com/ns/agents/sa/coder";
        let subject = make_subject_jwt(sub, 300, None);
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &subject),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_to_value(resp.into_body()).await;
        assert!(v["access_token"].as_str().unwrap().contains('.'));
        assert_eq!(v["issued_token_type"], TOKEN_TYPE_ACCESS_TOKEN);
        assert_eq!(v["token_type"], "Bearer");
        assert!(v["expires_in"].as_u64().unwrap() > 0);
        assert!(v["expires_in"].as_u64().unwrap() <= 300);
    }

    /// M-3 strong-binding regression for the OIDC subject_token trust root
    /// (site: subject_token signature check, the `vk.verify_strict(...)`
    /// call). The Ed25519 identity/neutral key (`[1, 0, ..., 0]`) with the
    /// identity-triple signature (R = identity encoding, s = 0) satisfies
    /// the COFACTORED verification equation for EVERY message, so non-strict
    /// `verify()` ACCEPTS it. The crafted subject_token below is otherwise
    /// fully valid (valid SPIFFE `sub`, fresh `exp`/`jti`, matching
    /// `audience`) and the identity key is registered in the trust bundle,
    /// so under non-strict `verify()` the exchange SUCCEEDS (200) and mints
    /// an access token bound to a FORGED identity. `verify_strict()` rejects
    /// the small-order key → 400 invalid_grant. If the site reverts to
    /// `vk.verify(...)`, assertion (ii) sees 200 OK and fails.
    #[tokio::test]
    async fn small_order_key_is_rejected_by_verify_strict() {
        use ed25519_dalek::VerifyingKey;

        // (i) No regression: an honest token still succeeds.
        let honest = make_subject_jwt("spiffe://prod.example.com/ns/agents/sa/coder", 300, None);
        let honest_body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &honest),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        assert_eq!(
            post_token(app(), honest_body).await.status(),
            StatusCode::OK
        );

        // Build an app whose trust bundle contains the small-order identity
        // key under the trust domain the federation rule allows.
        let mut id = [0u8; 32];
        id[0] = 1; // identity/neutral point encoding — a small-order key
        let identity_vk =
            VerifyingKey::from_bytes(&id).expect("identity point is a valid Ed25519 encoding");
        let identity_kid = crate::keystore::rfc7638_kid(&identity_vk);

        let store: Arc<dyn JwtKeyStore> = Arc::new(InMemoryKeyStore::new());
        let issuer = Arc::new(
            JwtIssuer::new(
                store.clone(),
                "https://oidc.nucleus.example/".to_string(),
                Duration::from_secs(300),
            )
            .unwrap(),
        );
        let rules = crate::federation::FederationRules {
            rule: vec![crate::federation::FederationRule {
                id: "test-allow".to_string(),
                subject_prefix: "spiffe://prod.example.com/*".to_string(),
                audience: "https://rp-a.example/api".to_string(),
                allowed_grants: vec![TOKEN_EXCHANGE_GRANT.to_string()],
                max_token_lifetime_secs: 3600,
                max_scope: None,
                scope_requires: None,
            }],
        };
        let federation = Arc::new(crate::federation::FederationRegistry::new(rules));
        let bundle = crate::spire::StaticBundleProvider::new();
        bundle.add_key("prod.example.com", identity_kid.clone(), identity_vk);
        let forged_app = crate::app::build_app(crate::app::AppState {
            keystore: store,
            issuer_url: Arc::from("https://oidc.nucleus.example/"),
            issuer,
            jti_cache: Arc::new(JtiCache::new()),
            cert_root_pubkey: None,
            federation,
            bundle_provider: Arc::new(bundle),
        });

        // (ii) Strong binding: a subject_token that is fully valid EXCEPT
        //      that it carries the identity-triple signature under the
        //      registered small-order identity key.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let exp = (now + 300) as u64;
        let jti = Uuid::new_v4().to_string();
        let header_json = format!(r#"{{"alg":"EdDSA","kid":"{identity_kid}","typ":"JWT"}}"#);
        let payload_json = format!(
            r#"{{"sub":"spiffe://prod.example.com/ns/agents/sa/coder","exp":{exp},"jti":"{jti}"}}"#
        );
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&id); // R = identity, s = 0
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig_bytes);
        let forged = format!("{header_b64}.{payload_b64}.{sig_b64}");
        let forged_body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &forged),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        let resp = post_token(forged_app, forged_body).await;
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "identity-triple subject_token must be REFUSED by verify_strict; a \
             revert to non-strict verify() would mint an access token for a \
             forged identity"
        );
        let v = body_to_value(resp.into_body()).await;
        assert_eq!(v["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn wrong_grant_type_returns_unsupported_grant_type() {
        let subject = make_subject_jwt("spiffe://prod.example.com/ns/x/sa/y", 300, None);
        let body = form_body(&[
            ("grant_type", "authorization_code"),
            ("subject_token", &subject),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_to_value(resp.into_body()).await;
        assert_eq!(v["error"], "unsupported_grant_type");
    }

    #[tokio::test]
    async fn wrong_subject_token_type_returns_invalid_request() {
        let subject = make_subject_jwt("spiffe://prod.example.com/ns/x/sa/y", 300, None);
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &subject),
            ("subject_token_type", "urn:not:a:real:type"),
            ("audience", "https://rp-a.example/api"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_to_value(resp.into_body()).await;
        assert_eq!(v["error"], "invalid_request");
    }

    #[tokio::test]
    async fn missing_audience_and_resource_returns_invalid_request() {
        let subject = make_subject_jwt("spiffe://prod.example.com/ns/x/sa/y", 300, None);
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &subject),
            ("subject_token_type", TOKEN_TYPE_JWT),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_to_value(resp.into_body()).await;
        assert_eq!(v["error"], "invalid_request");
    }

    #[tokio::test]
    async fn malformed_subject_token_returns_invalid_grant() {
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", "not-a-jwt"),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_to_value(resp.into_body()).await;
        assert_eq!(v["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn non_spiffe_subject_returns_invalid_grant() {
        let subject = make_subject_jwt("just-a-string", 300, None);
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &subject),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_to_value(resp.into_body()).await;
        assert_eq!(v["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn expired_subject_token_returns_invalid_grant() {
        let subject = make_subject_jwt("spiffe://prod.example.com/ns/x/sa/y", -10, None);
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &subject),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_to_value(resp.into_body()).await;
        assert_eq!(v["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn replay_of_same_jti_rejected() {
        let app = app();
        let subject = make_subject_jwt(
            "spiffe://prod.example.com/ns/x/sa/y",
            300,
            Some("fixed-jti-1"),
        );
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &subject),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        let r1 = post_token(app.clone(), body.clone()).await;
        assert_eq!(r1.status(), StatusCode::OK);

        let r2 = post_token(app, body).await;
        assert_eq!(r2.status(), StatusCode::BAD_REQUEST);
        let v = body_to_value(r2.into_body()).await;
        assert_eq!(v["error"], "invalid_grant");
        // Per #44 constant-time hardening, the inner replay-specific
        // detail is wire-opaque; assert the canonical description.
        assert_eq!(v["error_description"], crate::error::OPAQUE_INVALID_GRANT);
    }

    #[tokio::test]
    async fn resource_field_accepted_as_audience_alias() {
        let subject = make_subject_jwt("spiffe://prod.example.com/ns/x/sa/y", 300, None);
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &subject),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("resource", "https://rp-a.example/api"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn issued_token_lifetime_bounded_by_subject_exp() {
        // Subject expires in 60s — issued token's expires_in must be ≤ 60s.
        let subject = make_subject_jwt("spiffe://prod.example.com/ns/x/sa/y", 60, None);
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &subject),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_to_value(resp.into_body()).await;
        assert!(v["expires_in"].as_u64().unwrap() <= 60);
    }

    #[tokio::test]
    async fn unknown_kid_returns_invalid_grant() {
        let subject = make_subject_jwt_with_unknown_key("spiffe://prod.example.com/ns/x/sa/y");
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &subject),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_to_value(resp.into_body()).await;
        assert_eq!(v["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn tampered_signature_returns_invalid_grant() {
        // Build a valid token then corrupt the last 4 chars of the
        // signature segment — must fail signature verify.
        let subject = make_subject_jwt("spiffe://prod.example.com/ns/x/sa/y", 300, None);
        let parts: Vec<&str> = subject.splitn(3, '.').collect();
        let tampered_sig = format!("{}AAAA", &parts[2][..parts[2].len().saturating_sub(4)]);
        let tampered = format!("{}.{}.{tampered_sig}", parts[0], parts[1]);
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &tampered),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_to_value(resp.into_body()).await;
        assert_eq!(v["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn unsupported_alg_returns_invalid_grant() {
        // Forge a JWT with `alg=HS256` — must be rejected per T04
        // algorithm-pin discipline, regardless of signature validity.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let exp = now + 300;
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","kid":"x","typ":"JWT"}"#); // alg-pin-allow: negative test asserting HS256 is rejected
        let payload = URL_SAFE_NO_PAD.encode(
            format!(r#"{{"sub":"spiffe://prod.example.com/ns/x/sa/y","exp":{exp},"jti":"j"}}"#)
                .as_bytes(),
        );
        let sig = URL_SAFE_NO_PAD.encode(b"fake-hmac-output");
        let token = format!("{header}.{payload}.{sig}");
        let body = form_body(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", &token),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ]);
        let resp = post_token(app(), body).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let v = body_to_value(resp.into_body()).await;
        assert_eq!(v["error"], "invalid_grant");
    }

    // ── The scope ceiling ───────────────────────────────────────────────────
    //
    // `scope` used to be echoed from the request verbatim: a workload asked,
    // the OP minted. The federation rule bounded which audience a subject could
    // reach and for how long, and nothing bounded what the token could DO when
    // it got there — so the delegation ceiling the kernel, the certificate and
    // the effect gate all enforce inside the boundary stopped at the one place
    // a federated credential most needs to carry it.

    async fn exchange_with_scope(
        app: axum::Router,
        scope: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let subject = make_subject_jwt("spiffe://prod.example.com/ns/x/sa/y", 300, None);
        let mut fields = vec![
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", subject.as_str()),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ];
        if let Some(s) = scope {
            fields.push(("scope", s));
        }
        let resp = post_token(app, form_body(&fields)).await;
        let status = resp.status();
        (status, body_to_value(resp.into_body()).await)
    }

    fn ceiling(scopes: &[&str]) -> Option<Vec<String>> {
        Some(scopes.iter().map(|s| (*s).to_string()).collect())
    }

    #[tokio::test]
    async fn a_scope_within_the_ceiling_round_trips() {
        let app = app_with_scope(ceiling(&["read:bundles", "write:bundles"]));
        let (status, v) = exchange_with_scope(app, Some("read:bundles write:bundles")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["scope"], "read:bundles write:bundles");
    }

    /// Narrowing is fine, and the token grants what was ASKED for rather than
    /// the rule's whole ceiling — a caller that wants read does not silently
    /// receive write as well.
    #[tokio::test]
    async fn asking_for_less_than_the_ceiling_grants_less() {
        let app = app_with_scope(ceiling(&["read:bundles", "write:bundles"]));
        let (status, v) = exchange_with_scope(app, Some("read:bundles")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["scope"], "read:bundles");
    }

    /// THE defect. A scope outside the ceiling is refused, not trimmed: a
    /// credential that silently means less than its holder believes is its own
    /// class of incident.
    #[tokio::test]
    async fn a_scope_outside_the_ceiling_is_refused() {
        let app = app_with_scope(ceiling(&["read:bundles"]));
        let (status, v) = exchange_with_scope(app, Some("read:bundles write:bundles")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(v["error"], "invalid_target");
        // The body says only that it was denied. WHICH scopes a rule admits is
        // operator information, and answering it here would make the token
        // endpoint a policy oracle a caller could enumerate — the OP already
        // makes that call for federation denials, and a scope denial is the
        // same class. The refused scopes and the ceiling go to the log.
        assert!(
            !v.to_string().contains("write:bundles"),
            "the response must not enumerate the ceiling: {v}"
        );
    }

    /// A rule that bounds no scope admits no scope. Fail-closed on the hazard.
    #[tokio::test]
    async fn a_rule_that_bounds_no_scope_refuses_a_requested_one() {
        let (status, v) = exchange_with_scope(app_with_scope(None), Some("read:bundles")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(v["error"], "invalid_target");
    }

    /// `max_scope = []` is "constrained to nothing", and is distinct from an
    /// absent ceiling the same way an empty effect surface is distinct from an
    /// unmarked one.
    #[tokio::test]
    async fn an_empty_ceiling_admits_nothing() {
        let (status, _) = exchange_with_scope(app_with_scope(ceiling(&[])), Some("read")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// What keeps this from breaking every existing caller: asking for no scope
    /// is fine under any rule, including one that bounds none. Scope is
    /// optional in RFC 8693, and the hazard is an unbounded scope being minted
    /// — not the absence of one.
    #[tokio::test]
    async fn asking_for_no_scope_is_unaffected_by_the_ceiling() {
        for rule in [None, ceiling(&[]), ceiling(&["read:bundles"])] {
            let (status, v) = exchange_with_scope(app_with_scope(rule), None).await;
            assert_eq!(status, StatusCode::OK);
            assert!(v.get("scope").is_none() || v["scope"].is_null(), "{v}");
        }
    }

    // ── The principal's ceiling ─────────────────────────────────────────────
    //
    // `max_scope` is what the OPERATOR is willing to issue. `scope_requires` is
    // what a PERSON delegated to this particular workload, read off the pod
    // certificate the request presents. Both have to hold, and the second is
    // what makes the federated credential carry the attenuation rather than
    // only the identity: SPIFFE says who the workload is, the certificate says
    // what its principal allowed.

    /// Mint a real pod certificate granting `effects`, and return it with the
    /// root key it is rooted in — the two halves the OP has to be given
    /// separately, since a token verified against its own embedded root proves
    /// only self-consistency.
    fn pod_certificate(effects: &[&str]) -> (String, Vec<u8>) {
        use portcullis::{
            AttenuationToken, CapabilityLevel, LatticeCertificate, PermissionLattice,
        };
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

        let mut perms = PermissionLattice::restrictive();
        portcullis::effect_surface::mark_effects(&mut perms.capabilities);
        for e in effects {
            portcullis::effect_surface::grant_effect(&mut perms.capabilities, e);
        }
        perms.capabilities.web_fetch = CapabilityLevel::LowRisk;

        let cert = LatticeCertificate::mint_with_holder_key(
            perms,
            "test-approver".to_string(),
            chrono::Utc::now() + chrono::Duration::hours(1),
            None,
            &key,
            &key,
        );
        let root = key.public_key().as_ref().to_vec();
        let token = AttenuationToken::seal(cert, root.clone());
        (token.to_base64().unwrap(), root)
    }

    fn app_requiring(
        max_scope: Option<Vec<String>>,
        requires: &[(&str, &[&str])],
        root: Option<Vec<u8>>,
    ) -> axum::Router {
        let map: std::collections::BTreeMap<String, Vec<String>> = requires
            .iter()
            .map(|(k, v)| {
                (
                    (*k).to_string(),
                    v.iter().map(|e| (*e).to_string()).collect(),
                )
            })
            .collect();
        app_full(max_scope, Some(map), root)
    }

    async fn exchange_full(
        app: axum::Router,
        scope: Option<&str>,
        cert: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let subject = make_subject_jwt("spiffe://prod.example.com/ns/x/sa/y", 300, None);
        let mut fields = vec![
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", subject.as_str()),
            ("subject_token_type", TOKEN_TYPE_JWT),
            ("audience", "https://rp-a.example/api"),
        ];
        if let Some(s) = scope {
            fields.push(("scope", s));
        }
        if let Some(c) = cert {
            fields.push(("actor_token", c));
            fields.push(("actor_token_type", TOKEN_TYPE_POD_CERTIFICATE));
        }
        let resp = post_token(app, form_body(&fields)).await;
        let status = resp.status();
        (status, body_to_value(resp.into_body()).await)
    }

    #[tokio::test]
    async fn a_scope_backed_by_a_granted_effect_is_issued() {
        let (cert, root) = pod_certificate(&["aws/read-logs"]);
        let app = app_requiring(
            ceiling(&["logs:read"]),
            &[("logs:read", &["aws/read-logs"])],
            Some(root),
        );
        let (status, v) = exchange_full(app, Some("logs:read"), Some(&cert)).await;
        assert_eq!(status, StatusCode::OK, "{v}");
        assert_eq!(v["scope"], "logs:read");
    }

    /// THE property. The operator's rule admits `logs:write`; this pod's grant
    /// does not include the effect that backs it, so the token cannot carry it.
    /// The delegation ceiling now survives the boundary.
    #[tokio::test]
    async fn a_scope_the_certificate_does_not_back_is_refused() {
        let (cert, root) = pod_certificate(&["aws/read-logs"]);
        let app = app_requiring(
            ceiling(&["logs:read", "logs:write"]),
            &[
                ("logs:read", &["aws/read-logs"]),
                ("logs:write", &["aws/write-object"]),
            ],
            Some(root),
        );
        let (status, v) = exchange_full(app, Some("logs:write"), Some(&cert)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
        assert!(
            !v.to_string().contains("aws/write-object"),
            "the response must not enumerate what would have satisfied it: {v}"
        );
    }

    /// A rule that says a scope needs delegated authority refuses when none is
    /// shown — rather than falling through to the operator ceiling alone.
    #[tokio::test]
    async fn a_backed_scope_needs_a_certificate() {
        let (_, root) = pod_certificate(&["aws/read-logs"]);
        let app = app_requiring(
            ceiling(&["logs:read"]),
            &[("logs:read", &["aws/read-logs"])],
            Some(root),
        );
        let (status, _) = exchange_full(app, Some("logs:read"), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// The whole security of reading effects off a certificate. `verify` walks
    /// the chain against the root the TOKEN carries, so a caller can always
    /// mint a self-consistent certificate granting itself anything. The pinned
    /// root is what makes it mean something, and this is that check.
    #[tokio::test]
    async fn a_certificate_rooted_elsewhere_is_refused() {
        let (attacker_cert, _attacker_root) = pod_certificate(&["aws/mutate-iam", "aws/read-logs"]);
        let (_, real_root) = pod_certificate(&["aws/read-logs"]);
        let app = app_requiring(
            ceiling(&["logs:read"]),
            &[("logs:read", &["aws/read-logs"])],
            Some(real_root),
        );
        let (status, v) = exchange_full(app, Some("logs:read"), Some(&attacker_cert)).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a certificate minted under the caller's own root must not satisfy anything: {v}"
        );
    }

    /// An OP with no pinned root cannot judge a certificate at all, so it
    /// refuses rather than accepting one on the token's own say-so.
    #[tokio::test]
    async fn without_a_pinned_root_certificates_are_refused() {
        let (cert, _) = pod_certificate(&["aws/read-logs"]);
        let app = app_requiring(
            ceiling(&["logs:read"]),
            &[("logs:read", &["aws/read-logs"])],
            None,
        );
        let (status, _) = exchange_full(app, Some("logs:read"), Some(&cert)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// Decode a JWT's payload without verifying — the signature is covered
    /// elsewhere; here the question is only what claims ride on the wire.
    fn payload_of(jwt: &str) -> serde_json::Value {
        let part = jwt.split('.').nth(1).expect("a JWT has three parts");
        let raw = URL_SAFE_NO_PAD
            .decode(part.as_bytes())
            .expect("b64 payload");
        serde_json::from_slice(&raw).expect("json payload")
    }

    /// The attenuation rides ON the token, so a relying party can re-check it
    /// without being handed the certificate as well. A namespaced private claim
    /// (RFC 7519 §4.3) an RP that has never heard of nucleus simply ignores.
    #[tokio::test]
    async fn the_issued_token_carries_the_granted_effects() {
        let (cert, root) = pod_certificate(&["aws/read-logs", "aws/read-inventory"]);
        let app = app_requiring(
            ceiling(&["logs:read"]),
            &[("logs:read", &["aws/read-logs"])],
            Some(root),
        );
        let (status, v) = exchange_full(app, Some("logs:read"), Some(&cert)).await;
        assert_eq!(status, StatusCode::OK, "{v}");
        let claims = payload_of(v["access_token"].as_str().expect("access_token"));
        let effects = claims["urn:nucleus:effects"]
            .as_array()
            .unwrap_or_else(|| panic!("effects claim missing: {claims}"));
        let mut got: Vec<&str> = effects.iter().filter_map(|e| e.as_str()).collect();
        got.sort_unstable();
        assert_eq!(got, vec!["aws/read-inventory", "aws/read-logs"]);
    }

    /// Absent means "not established", never "none". An exchange with no
    /// certificate must omit the claim rather than assert an empty grant — an
    /// RP reading the first as the second would conclude a workload had been
    /// delegated nothing when in fact nobody had said.
    #[tokio::test]
    async fn no_certificate_means_no_effects_claim_not_an_empty_one() {
        let (status, v) =
            exchange_with_scope(app_with_scope(ceiling(&["plain"])), Some("plain")).await;
        assert_eq!(status, StatusCode::OK, "{v}");
        let claims = payload_of(v["access_token"].as_str().expect("access_token"));
        assert!(
            claims.get("urn:nucleus:effects").is_none(),
            "the claim must be absent, not empty: {claims}"
        );
    }

    /// A scope with no `scope_requires` entry is bounded by `max_scope` alone —
    /// the rule asserts nothing about what backs it, so presenting a
    /// certificate is not required. Keeps the feature opt-in per scope.
    #[tokio::test]
    async fn a_scope_with_no_backing_requirement_is_unaffected() {
        let app = app_requiring(
            ceiling(&["plain:scope"]),
            &[("logs:read", &["aws/read-logs"])],
            None,
        );
        let (status, v) = exchange_full(app, Some("plain:scope"), None).await;
        assert_eq!(status, StatusCode::OK, "{v}");
        assert_eq!(v["scope"], "plain:scope");
    }

    /// Whitespace is not a way past the ceiling: an all-blank scope is an
    /// absent one, and a padded token is the token.
    #[tokio::test]
    async fn whitespace_does_not_defeat_the_ceiling() {
        let app = app_with_scope(ceiling(&["read:bundles"]));
        let (status, v) = exchange_with_scope(app, Some("   ")).await;
        assert_eq!(status, StatusCode::OK, "an all-blank scope is no scope");

        let app = app_with_scope(ceiling(&["read:bundles"]));
        let (status, v2) = exchange_with_scope(app, Some("  read:bundles  ")).await;
        assert_eq!(status, StatusCode::OK, "{v2}");
        assert_eq!(v2["scope"], "read:bundles");
        let _ = v;
    }
}

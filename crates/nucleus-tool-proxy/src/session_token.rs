//! Live-path session task token — startup verification (PR-2, present-not-consumed).
//!
//! This is the FIRST brick of the live-path spawn migration. At pod boot the
//! **host** (orchestrator/node) mints a session [`SignedTaskRef`] scoped to the
//! pod's granted operations and injects the serialized token, its expected
//! effective nonce, and the root issuer public key into the tool-proxy on the
//! **same host-controlled channel that injects credentials** — the pod boot
//! environment set by the node (`NUCLEUS_TASK_TOKEN` / `NUCLEUS_TASK_TOKEN_NONCE`
//! / `NUCLEUS_TASK_TOKEN_ISSUER`). These are process environment variables the
//! agent cannot set (the agent talks to the tool-proxy sidecar over HTTP; it does
//! not control the sidecar's boot env). They are NEVER read from an agent-supplied
//! field (`spec_yaml`, tool args).
//!
//! At startup the tool-proxy [`resolve_session_task_token`]s the injected material
//! **once** and holds the result privately in `AppState`. This PR **does not
//! consume** the token — a later PR gates `RunBash` on it. Consequently this file
//! must be strictly **fail-closed**: if the token is absent
//! ([`SessionTaskToken::Missing`]) or fails verification
//! ([`SessionTaskToken::Invalid`]), the state is recorded such that the later
//! gating PR DENIES. An absent/invalid token is never silently treated as
//! "unrestricted".
//!
//! ## Why a local typestate (deviation note)
//!
//! The token primitives (`SignedTaskRef::verify`, [`TokenScope`], [`TokenError`])
//! live in `nucleus-provenance-memory`, which the tool-proxy already depends on.
//! The `VerifiedTaskRef` typestate referenced by the migration design lives in
//! `portcullis-effects`, which is **not** a dependency of this crate (it is the
//! in-process `NucleusRuntime` enforcement crate, inappropriate to pull into the
//! pod sidecar). [`VerifiedSessionToken`] is the same thin typestate over the
//! identical `SignedTaskRef::verify` call: its only constructor runs the
//! fail-closed verification, so an *unverified* token is unrepresentable inside
//! `AppState`.

use nucleus_provenance_memory::{SignedTaskRef, TokenError, TokenScope};

/// Length of the effective-nonce (bytes).
const NONCE_LEN: usize = 16;
/// Length of an Ed25519 public key (bytes).
const ISSUER_LEN: usize = 32;

/// A session task token that has passed `SignedTaskRef::verify` at startup.
///
/// Typestate: the only constructor is [`VerifiedSessionToken::verify`], which
/// returns `Err` unless the injected token verifies fail-closed (correct root
/// issuer, strict signatures, intact lineage, attenuation-only, unexpired, and
/// effective nonce == the host-supplied expected nonce). Fields are private, so
/// no caller can fabricate a verified token with a scope the signature chain did
/// not authorize.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedSessionToken {
    /// The verified effective (most-attenuated) scope this token grants. Read by
    /// the later RunBash-gating PR.
    scope: TokenScope,
    /// The owned, verified token chain. Retained for the later gating PR (e.g.
    /// re-verification / attenuation for spawned children).
    #[allow(dead_code)]
    token: SignedTaskRef,
    /// The pinned root issuer this token verified against. Retained for the later
    /// gating PR (re-verifying children under the same anchor).
    #[allow(dead_code)]
    root_issuer: [u8; ISSUER_LEN],
}

impl VerifiedSessionToken {
    /// Parse and verify the injected boot-channel material.
    ///
    /// `now_unix` is caller-supplied (verify never reads the system clock), so
    /// callers/tests stay deterministic. `expected_nonce` and `root_issuer`
    /// arrive on the host-controlled boot channel and are the out-of-band inputs
    /// that make the token's truncation defense hold.
    fn verify(
        token_serialized: &str,
        nonce_hex: &str,
        issuer_hex: &str,
        now_unix: u64,
    ) -> Result<Self, SessionTokenError> {
        let expected_nonce = parse_fixed::<NONCE_LEN>(nonce_hex).ok_or(SessionTokenError::Nonce)?;
        let root_issuer = parse_fixed::<ISSUER_LEN>(issuer_hex).ok_or(SessionTokenError::Issuer)?;
        let signed: SignedTaskRef =
            serde_json::from_str(token_serialized).map_err(|_| SessionTokenError::Decode)?;

        // Clone the effective scope out of the borrowed verify result, then the
        // borrow ends and we can move `signed` into the owned typestate.
        let scope = signed
            .verify(&root_issuer, now_unix, &expected_nonce)
            .map_err(SessionTokenError::Verify)?
            .clone();
        Ok(Self {
            scope,
            token: signed,
            root_issuer,
        })
    }

    /// The verified effective (most-attenuated) scope this token grants. Consumed
    /// by the later RunBash-gating PR; unused in this present-not-consumed PR.
    #[allow(dead_code)]
    pub(crate) fn scope(&self) -> &TokenScope {
        &self.scope
    }
}

/// Why parsing/verification of the injected boot material failed. Every variant
/// is fail-closed (maps to [`SessionTaskToken::Invalid`]).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SessionTokenError {
    /// The nonce was not exactly `NONCE_LEN` hex-decoded bytes.
    #[error("session task token nonce is malformed")]
    Nonce,
    /// The issuer key was not exactly `ISSUER_LEN` hex-decoded bytes.
    #[error("session task token issuer key is malformed")]
    Issuer,
    /// The serialized token could not be decoded.
    #[error("session task token could not be decoded")]
    Decode,
    /// The token decoded but failed cryptographic verification.
    #[error("session task token failed verification: {0}")]
    Verify(TokenError),
}

/// The startup verification verdict for the injected session task token, held
/// privately in `AppState`. Fail-closed: only [`Verified`](Self::Verified) grants
/// authority; both [`Missing`](Self::Missing) and [`Invalid`](Self::Invalid) MUST
/// cause the later RunBash-gating PR to DENY.
#[derive(Debug, Clone)]
pub(crate) enum SessionTaskToken {
    /// A token was injected on the host channel and verified at startup.
    Verified(VerifiedSessionToken),
    /// No token was injected on the host channel (or a component was absent).
    /// Fail-closed: the later gating PR denies.
    Missing,
    /// A token was injected but failed to parse/verify. Fail-closed: the later
    /// gating PR denies (never treated as unrestricted).
    Invalid,
}

impl SessionTaskToken {
    /// A short, non-sensitive label for boot logging (never leaks token bytes).
    pub(crate) fn state_label(&self) -> &'static str {
        match self {
            SessionTaskToken::Verified(_) => "verified",
            SessionTaskToken::Missing => "missing (fail-closed)",
            SessionTaskToken::Invalid => "invalid (fail-closed)",
        }
    }

    /// Whether a verified token is held. The later RunBash-gating PR denies when
    /// this is `false`. Unused in this present-not-consumed PR.
    #[allow(dead_code)]
    pub(crate) fn is_verified(&self) -> bool {
        matches!(self, SessionTaskToken::Verified(_))
    }

    /// The verified effective scope, if any. `None` for `Missing`/`Invalid`
    /// (fail-closed). Consumed by the later RunBash-gating PR.
    #[allow(dead_code)]
    pub(crate) fn verified_scope(&self) -> Option<&TokenScope> {
        match self {
            SessionTaskToken::Verified(v) => Some(v.scope()),
            SessionTaskToken::Missing | SessionTaskToken::Invalid => None,
        }
    }
}

/// Resolve the injected boot-channel material into a fail-closed
/// [`SessionTaskToken`]. Pure and deterministic: `now_unix` is caller-supplied.
///
/// - Any of the three components absent ⇒ [`SessionTaskToken::Missing`].
/// - Present but malformed or failing verification ⇒ [`SessionTaskToken::Invalid`].
/// - Present and verifying ⇒ [`SessionTaskToken::Verified`].
pub(crate) fn resolve_session_task_token(
    token_serialized: Option<&str>,
    nonce_hex: Option<&str>,
    issuer_hex: Option<&str>,
    now_unix: u64,
) -> SessionTaskToken {
    let (token_serialized, nonce_hex, issuer_hex) = match (token_serialized, nonce_hex, issuer_hex)
    {
        (Some(t), Some(n), Some(i)) => (t, n, i),
        // Any component absent on the host channel ⇒ fail-closed Missing.
        _ => return SessionTaskToken::Missing,
    };

    match VerifiedSessionToken::verify(token_serialized, nonce_hex, issuer_hex, now_unix) {
        Ok(verified) => SessionTaskToken::Verified(verified),
        Err(_) => SessionTaskToken::Invalid,
    }
}

/// Hex-decode into a fixed-size byte array; `None` on any decode error or a
/// length mismatch.
fn parse_fixed<const N: usize>(hex_str: &str) -> Option<[u8; N]> {
    let bytes = hex::decode(hex_str.trim()).ok()?;
    let arr: [u8; N] = bytes.try_into().ok()?;
    Some(arr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use nucleus::portcullis::Operation;

    // Deterministic, no system clock: fixed issue/ttl/now and fixed nonce.
    const ISSUED_AT: u64 = 1_000;
    const TTL: u64 = 500;
    const NOW: u64 = 1_200;
    const NONCE: [u8; 16] = [7u8; 16];

    // from_bytes is decode-only (no CSPRNG) — a test issuer key, never a
    // production path. Production keys come from the host's key provisioning.
    fn issuer_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn scope() -> TokenScope {
        TokenScope::new(
            vec![Operation::ReadFiles, Operation::EditFiles],
            vec!["src/**".to_string()],
        )
    }

    /// Mint a valid session token and return the exact boot-channel strings the
    /// host would inject.
    fn injected(issuer: &SigningKey, nonce: [u8; 16]) -> (String, String, String) {
        let token = SignedTaskRef::issue("live-task", scope(), nonce, ISSUED_AT, TTL, issuer);
        let token_json = serde_json::to_string(&token).expect("serialize token");
        let nonce_hex = hex::encode(nonce);
        let issuer_hex = hex::encode(issuer.verifying_key().to_bytes());
        (token_json, nonce_hex, issuer_hex)
    }

    // (a) A valid injected session token verifies into session state at startup.
    #[test]
    fn valid_injected_token_verifies_into_session_state() {
        let issuer = issuer_key(1);
        let (token, nonce, issuer_hex) = injected(&issuer, NONCE);

        let state = resolve_session_task_token(Some(&token), Some(&nonce), Some(&issuer_hex), NOW);

        assert!(state.is_verified(), "honest injected token must verify");
        assert_eq!(state.verified_scope(), Some(&scope()));
        assert_eq!(state.state_label(), "verified");
    }

    // (b) An absent token yields the fail-closed Missing state.
    #[test]
    fn absent_token_is_fail_closed_missing() {
        // Nothing injected at all.
        let state = resolve_session_task_token(None, None, None, NOW);
        assert!(matches!(state, SessionTaskToken::Missing));
        assert!(!state.is_verified());
        assert_eq!(state.verified_scope(), None);

        // A partially-injected channel (token present, nonce/issuer absent) is
        // ALSO fail-closed Missing — never silently unrestricted.
        let issuer = issuer_key(1);
        let (token, _n, _i) = injected(&issuer, NONCE);
        let partial = resolve_session_task_token(Some(&token), None, None, NOW);
        assert!(matches!(partial, SessionTaskToken::Missing));
        assert!(!partial.is_verified());
    }

    // (c1) A tampered token (scope widened after signing) is rejected at startup.
    #[test]
    fn tampered_token_is_fail_closed_invalid() {
        let issuer = issuer_key(1);
        let (token_json, nonce, issuer_hex) = injected(&issuer, NONCE);

        // Widen the signed scope after minting — the signature no longer matches.
        let mut token: SignedTaskRef = serde_json::from_str(&token_json).unwrap();
        token.blocks[0]
            .claim
            .scope
            .allowed_operations
            .push(Operation::RunBash);
        let tampered = serde_json::to_string(&token).unwrap();

        let state =
            resolve_session_task_token(Some(&tampered), Some(&nonce), Some(&issuer_hex), NOW);
        assert!(matches!(state, SessionTaskToken::Invalid));
        assert!(!state.is_verified());
        assert_eq!(state.verified_scope(), None);
        assert_eq!(state.state_label(), "invalid (fail-closed)");
    }

    // (c2) A wrong-issuer token (pinned root != signer) is rejected at startup.
    #[test]
    fn wrong_issuer_token_is_fail_closed_invalid() {
        let real_issuer = issuer_key(1);
        let attacker = issuer_key(9);
        // Token minted by the attacker...
        let (token, nonce, _attacker_hex) = injected(&attacker, NONCE);
        // ...but the host-pinned issuer is the real root.
        let real_issuer_hex = hex::encode(real_issuer.verifying_key().to_bytes());

        let state =
            resolve_session_task_token(Some(&token), Some(&nonce), Some(&real_issuer_hex), NOW);
        assert!(matches!(state, SessionTaskToken::Invalid));
        assert!(!state.is_verified());
    }

    // (c3) A stale/mismatched expected nonce is rejected (truncation/replay defense).
    #[test]
    fn wrong_nonce_is_fail_closed_invalid() {
        let issuer = issuer_key(1);
        // Token minted with NONCE, but the host-pinned expected nonce differs.
        let (token, _minted_nonce, issuer_hex) = injected(&issuer, NONCE);
        let wrong_nonce_hex = hex::encode([9u8; 16]);

        let state = resolve_session_task_token(
            Some(&token),
            Some(&wrong_nonce_hex),
            Some(&issuer_hex),
            NOW,
        );
        assert!(matches!(state, SessionTaskToken::Invalid));
    }

    // (c4) An expired token is rejected at startup (deterministic clock).
    #[test]
    fn expired_token_is_fail_closed_invalid() {
        let issuer = issuer_key(1);
        let (token, nonce, issuer_hex) = injected(&issuer, NONCE);
        // deadline = ISSUED_AT + TTL = 1500; verify at now = 1501 ⇒ expired.
        let state =
            resolve_session_task_token(Some(&token), Some(&nonce), Some(&issuer_hex), 1_501);
        assert!(matches!(state, SessionTaskToken::Invalid));
    }

    // Malformed boot material (bad hex / wrong length / non-JSON) is fail-closed
    // Invalid, not a panic and not Missing.
    #[test]
    fn malformed_material_is_fail_closed_invalid() {
        let issuer = issuer_key(1);
        let (token, nonce, issuer_hex) = injected(&issuer, NONCE);

        // Non-JSON token.
        assert!(matches!(
            resolve_session_task_token(Some("not-json"), Some(&nonce), Some(&issuer_hex), NOW),
            SessionTaskToken::Invalid
        ));
        // Short nonce (8 bytes hex).
        assert!(matches!(
            resolve_session_task_token(
                Some(&token),
                Some(&hex::encode([1u8; 8])),
                Some(&issuer_hex),
                NOW
            ),
            SessionTaskToken::Invalid
        ));
        // Non-hex issuer.
        assert!(matches!(
            resolve_session_task_token(Some(&token), Some(&nonce), Some("zz"), NOW),
            SessionTaskToken::Invalid
        ));
    }

    // The specific parse/verify error taxonomy is fail-closed on every arm.
    #[test]
    fn session_token_error_arms_are_fail_closed() {
        let issuer = issuer_key(1);
        let (token, nonce, issuer_hex) = injected(&issuer, NONCE);

        assert_eq!(
            VerifiedSessionToken::verify("nope", &nonce, &issuer_hex, NOW).unwrap_err(),
            SessionTokenError::Decode
        );
        assert_eq!(
            VerifiedSessionToken::verify(&token, "zz", &issuer_hex, NOW).unwrap_err(),
            SessionTokenError::Nonce
        );
        assert_eq!(
            VerifiedSessionToken::verify(&token, &nonce, "zz", NOW).unwrap_err(),
            SessionTokenError::Issuer
        );
        assert!(matches!(
            VerifiedSessionToken::verify(&token, &nonce, &issuer_hex, 1_501).unwrap_err(),
            SessionTokenError::Verify(TokenError::Expired { .. })
        ));
    }
}

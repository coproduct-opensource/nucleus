//! The session task token for a tool-proxy the CLI launches itself.
//!
//! # The defect this closes
//!
//! Every preflight's `InScopeWithTask` obligation admits an operation only if a
//! verified session task token names it. On the pod path the node mints that
//! token from the pod's resolved policy and delivers it on the boot channel.
//! `nucleus shell` and `nucleus run --local` launch the tool-proxy on the host
//! and minted nothing, so their proxies started with the token `Missing` and
//! refused every action -- `ls -la` included. Measured 2026-09-29 by a
//! containment run through `nucleus shell`; the MCP bridge's own defects (every
//! `run` a 422, every refusal reason discarded) had been hiding it.
//!
//! # Trust
//!
//! The CLI is the proxy's parent: it already chooses the proxy's spec, policy
//! and auth secrets, so it is the right issuer for its session. The issuer key
//! is generated per session, used for exactly one signature, and dropped; only
//! its public half reaches the proxy. The token is a scoped capability plus a
//! public key, not a secret (see the node's `session_mint`), so passing it on
//! the proxy's command line is fine -- and a misspelled FLAG is a clap error,
//! where a misspelled environment variable would be silently absent and put the
//! proxy straight back into `Missing`.
//!
//! The scope is `PermissionLattice::granted_operations()` of the policy written
//! into the proxy's spec -- the same decision the node makes per pod, through
//! the same shared mint.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use nucleus_provenance_memory::taskref_token::{MintedTaskToken, mint_session_task_token};
use portcullis::PermissionLattice;

/// Mint the token for one locally launched proxy.
///
/// `ttl_secs` is the session's own timeout, so the token lives exactly as long
/// as the session may. `authority` is the fingerprint of the pod certificate
/// the proxy is launched with, if any: that proxy refuses a token not bound to
/// it.
pub(crate) fn mint_local(
    session_id: &str,
    policy: &PermissionLattice,
    ttl_secs: u64,
    authority: Option<[u8; 32]>,
) -> Result<MintedTaskToken> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the UNIX epoch; cannot date a session token")?
        .as_secs();
    let issuer = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    mint_session_task_token(
        &format!("local-{session_id}"),
        policy.granted_operations(),
        ttl_secs,
        now,
        &issuer,
        authority,
    )
    .context("serializing the session task token")
}

/// The tool-proxy flags that deliver `token`.
pub(crate) fn proxy_args(token: &MintedTaskToken) -> [String; 6] {
    [
        "--task-token".into(),
        token.token_json.clone(),
        "--task-token-nonce".into(),
        token.nonce_hex.clone(),
        "--task-token-issuer".into(),
        token.issuer_hex.clone(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_provenance_memory::SignedTaskRef;
    use portcullis::Operation;

    /// What the proxy does at startup: decode the three strings and verify.
    fn verify(t: &MintedTaskToken, now: u64) -> Vec<Operation> {
        let token: SignedTaskRef = serde_json::from_str(&t.token_json).unwrap();
        let nonce: [u8; 16] = hex::decode(&t.nonce_hex).unwrap().try_into().unwrap();
        let issuer: [u8; 32] = hex::decode(&t.issuer_hex).unwrap().try_into().unwrap();
        token
            .verify(&issuer, now, &nonce)
            .expect("a locally minted token verifies under its own issuer and nonce")
            .allowed_operations
            .clone()
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn a_local_token_grants_exactly_the_policys_operations() {
        let policy = PermissionLattice::local_dev();
        let t = mint_local("s1", &policy, 600, None).unwrap();
        assert_eq!(verify(&t, now() + 1), policy.granted_operations());
        assert!(
            !verify(&t, now() + 1).is_empty(),
            "local_dev grants something"
        );
    }

    /// A policy that denies everything mints an empty scope, never a
    /// wildcard: the fix gives the session what its policy grants, not more.
    #[test]
    fn a_policy_that_grants_nothing_mints_nothing() {
        let t = mint_local("s2", &PermissionLattice::restrictive(), 600, None).unwrap();
        let ops = verify(&t, now() + 1);
        assert_eq!(ops, PermissionLattice::restrictive().granted_operations());
    }

    #[test]
    fn each_session_gets_its_own_issuer_and_nonce() {
        let policy = PermissionLattice::local_dev();
        let a = mint_local("s", &policy, 600, None).unwrap();
        let b = mint_local("s", &policy, 600, None).unwrap();
        assert_ne!(a.issuer_hex, b.issuer_hex);
        assert_ne!(a.nonce_hex, b.nonce_hex);
    }

    #[test]
    fn the_token_lives_as_long_as_the_session_and_no_longer() {
        let t = mint_local("s3", &PermissionLattice::local_dev(), 60, None).unwrap();
        let token: SignedTaskRef = serde_json::from_str(&t.token_json).unwrap();
        let nonce: [u8; 16] = hex::decode(&t.nonce_hex).unwrap().try_into().unwrap();
        let issuer: [u8; 32] = hex::decode(&t.issuer_hex).unwrap().try_into().unwrap();
        assert!(token.verify(&issuer, now() + 3_600, &nonce).is_err());
    }

    #[test]
    fn the_flags_name_the_proxys_arguments() {
        let t = mint_local("s4", &PermissionLattice::local_dev(), 60, None).unwrap();
        let args = proxy_args(&t);
        assert_eq!(args[0], "--task-token");
        assert_eq!(args[2], "--task-token-nonce");
        assert_eq!(args[4], "--task-token-issuer");
        assert_eq!(args[5], t.issuer_hex);
    }
}

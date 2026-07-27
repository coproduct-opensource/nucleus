//! Live-path session capability-token **minting** (the node MINTING half).
//!
//! This is the counterpart to the tool-proxy's startup verification
//! (`nucleus-tool-proxy::session_token`, live-path PR-2). At pod spawn the node
//! mints a fresh [`SignedTaskRef`] scoped to exactly the operations the pod's
//! resolved policy permits, then injects the serialized token, its effective
//! nonce, and the task-issuer PUBLIC key into the pod on the **same
//! host-controlled boot channel** the node already uses for credentials
//! (process env / kernel cmdline the agent cannot set). The tool-proxy reads
//! them from `NUCLEUS_TASK_TOKEN` / `NUCLEUS_TASK_TOKEN_NONCE` /
//! `NUCLEUS_TASK_TOKEN_ISSUER` and verifies once at startup, fail-closed.
//!
//! ## Trust choke point
//!
//! The scope's operation set is [`PermissionLattice::granted_operations`] — the
//! ops whose capability level is strictly above `Never`. By construction the
//! minted [`TokenScope`] is a subset of the policy: an op is in scope **iff**
//! the policy does not fully deny it. A fully-locked-down policy therefore
//! mints an EMPTY-scope token (which later DENIES `RunBash`), never a wildcard.
//!
//! ## What is (and isn't) a secret
//!
//! The token is a **scoped capability plus a public issuer key** — not a
//! secret. Only the issuer's PUBLIC half is ever injected; the private
//! task-issuer key stays on the node ([`TrustGateConfig::task_issuer_signing_key`](crate::trust_gate::TrustGateConfig)).
//! On the Firecracker path the material rides the kernel cmdline alongside the
//! existing `nucleus.auth_secret` (see the M-4 cmdline-readability caveat): the
//! token's confidentiality is not load-bearing, and the anti-truncation /
//! anti-replay defense rests on the host-pinned effective nonce, not on secrecy.
//!
//! ## Paths (deferred)
//!
//! Path scoping is the NEXT gating brick (path mediation). `allowed_paths` is
//! intentionally left EMPTY here rather than lifted from `PathLattice`, whose
//! "empty allowed = all readable" semantics are the inverse of `TokenScope`'s
//! "empty = nothing" allowlist semantics — conflating them would silently
//! mis-scope the token. Operations are the choke point this brick owns.

use ed25519_dalek::SigningKey;
use nucleus_provenance_memory::{SignedTaskRef, TokenScope};
use portcullis::PermissionLattice;
use rand_core::RngCore as _;

/// Width of a [`SignedTaskRef`] block nonce, in bytes.
const NONCE_LEN: usize = 16;

/// The three host-injected boot-channel strings the tool-proxy verify half
/// consumes. Field serialization matches
/// `nucleus-tool-proxy::session_token` exactly: JSON token, lowercase-hex
/// nonce, lowercase-hex issuer public key.
pub(crate) struct MintedTaskToken {
    /// `serde_json` serialization of the [`SignedTaskRef`] → `NUCLEUS_TASK_TOKEN`.
    pub token_json: String,
    /// Hex of the 16-byte effective nonce → `NUCLEUS_TASK_TOKEN_NONCE`.
    pub nonce_hex: String,
    /// Hex of the 32-byte task-issuer PUBLIC key → `NUCLEUS_TASK_TOKEN_ISSUER`.
    pub issuer_hex: String,
}

/// Mint a fresh per-pod session capability token from the pod's resolved
/// policy.
///
/// - `task_id`   — stable id bound into the token signature (the pod UUID).
/// - `policy`    — the pod's resolved [`PermissionLattice`]; its
///   `granted_operations()` become the token's operation scope.
/// - `ttl_secs`  — token lifetime in **seconds** (the pod/session lifetime,
///   e.g. `spec.spec.timeout_seconds`); verify uses `issued_at + ttl < now`.
/// - `now_unix`  — issue time as **UNIX seconds** (wall clock at the spawn
///   site; passed in so this stays pure/deterministic for tests). Matches the
///   verify half's `elapsed.as_secs()`.
/// - `issuer`    — the node's dedicated task-issuer signing key; only its
///   public half is emitted.
///
/// A fresh CSPRNG nonce is drawn per call (per pod), so no two pods share an
/// effective nonce — the host-pinned anti-replay / anti-truncation input.
pub(crate) fn mint_session_task_token(
    task_id: &str,
    policy: &PermissionLattice,
    ttl_secs: u64,
    now_unix: u64,
    issuer: &SigningKey,
) -> Result<MintedTaskToken, serde_json::Error> {
    // Fresh per-pod nonce from the OS CSPRNG, at the exact width SignedTaskRef
    // pins as the effective nonce.
    let mut nonce = [0u8; NONCE_LEN];
    rand_core::OsRng.fill_bytes(&mut nonce);

    // THE choke point: scope operations = ops the policy does not deny. Subset
    // of the policy by construction (granted_operations excludes every Never
    // op). Paths deferred to the next brick — see module docs.
    let scope = TokenScope::new(policy.granted_operations(), Vec::new());

    let token = SignedTaskRef::issue(task_id, scope, nonce, now_unix, ttl_secs, issuer);
    let token_json = serde_json::to_string(&token)?;

    Ok(MintedTaskToken {
        token_json,
        nonce_hex: hex::encode(nonce),
        issuer_hex: hex::encode(issuer.verifying_key().to_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis::{CapabilityLattice, CapabilityLevel, Operation};

    // Decode-only test key (no CSPRNG) — production keys come from the node's
    // persisted task-issuer key file.
    fn issuer_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    const NOW: u64 = 1_700_000_000;
    const TTL: u64 = 3_600;

    /// (c) End-to-end mint→verify: the three injected strings round-trip and the
    /// token `SignedTaskRef::verify` ACCEPTS under the injected issuer pubkey +
    /// injected nonce, at a `now` within the TTL window. The verified effective
    /// scope equals the policy's `granted_operations()` (subset-by-construction).
    #[test]
    fn minted_token_verifies_under_injected_issuer_and_nonce() {
        let issuer = issuer_key(3);
        let policy = PermissionLattice::local_dev(); // read/write/edit/bash/glob/grep/commit

        let minted = mint_session_task_token("pod-abc", &policy, TTL, NOW, &issuer).expect("mint");

        // Reconstruct the verifier inputs from the injected strings exactly as
        // the tool-proxy would.
        let token: SignedTaskRef = serde_json::from_str(&minted.token_json).unwrap();
        let nonce_bytes = hex::decode(&minted.nonce_hex).unwrap();
        let nonce: [u8; 16] = nonce_bytes.try_into().unwrap();
        let issuer_bytes = hex::decode(&minted.issuer_hex).unwrap();
        let issuer_pub: [u8; 32] = issuer_bytes.try_into().unwrap();

        // Injected issuer hex must be the PUBLIC key (never the private key).
        assert_eq!(issuer_pub, issuer.verifying_key().to_bytes());

        let scope = token
            .verify(&issuer_pub, NOW + 10, &nonce)
            .expect("minted token must verify under injected issuer + nonce");

        // The verified scope's operations are exactly granted_operations().
        assert_eq!(scope.allowed_operations, policy.granted_operations());
        assert!(
            scope.allowed_paths.is_empty(),
            "paths deferred to next brick"
        );

        // No minted op is Never in the source policy.
        for op in &scope.allowed_operations {
            assert_ne!(policy.capabilities.level_for(*op), CapabilityLevel::Never);
        }
    }

    /// (b) A fully-locked-down policy mints an EMPTY-scope token — which the
    /// verifier accepts as a valid, zero-authority token. RunBash is absent, so
    /// the later gate DENIES bash (not a wildcard).
    #[test]
    fn all_never_policy_mints_empty_scope_token() {
        let issuer = issuer_key(4);
        let mut policy = PermissionLattice::read_only();
        policy.capabilities = CapabilityLattice {
            read_files: CapabilityLevel::Never,
            write_files: CapabilityLevel::Never,
            edit_files: CapabilityLevel::Never,
            run_bash: CapabilityLevel::Never,
            glob_search: CapabilityLevel::Never,
            grep_search: CapabilityLevel::Never,
            web_search: CapabilityLevel::Never,
            web_fetch: CapabilityLevel::Never,
            git_commit: CapabilityLevel::Never,
            git_push: CapabilityLevel::Never,
            create_pr: CapabilityLevel::Never,
            manage_pods: CapabilityLevel::Never,
            spawn_agent: CapabilityLevel::Never,
            #[cfg(not(kani))]
            extensions: std::collections::BTreeMap::new(),
        };

        let minted = mint_session_task_token("pod-locked", &policy, TTL, NOW, &issuer).unwrap();
        let token: SignedTaskRef = serde_json::from_str(&minted.token_json).unwrap();
        let nonce: [u8; 16] = hex::decode(&minted.nonce_hex).unwrap().try_into().unwrap();
        let issuer_pub: [u8; 32] = hex::decode(&minted.issuer_hex).unwrap().try_into().unwrap();

        let scope = token
            .verify(&issuer_pub, NOW, &nonce)
            .expect("empty token verifies");
        assert!(
            scope.allowed_operations.is_empty(),
            "locked-down policy must mint an EMPTY operation scope, got {:?}",
            scope.allowed_operations
        );
        assert!(!scope.allowed_operations.contains(&Operation::RunBash));
    }

    /// The minted scope is a subset of the policy for a mid-privilege profile:
    /// every op with `level_for == Never` is absent from the token scope.
    #[test]
    fn minted_scope_is_subset_of_policy() {
        let issuer = issuer_key(5);
        let policy = PermissionLattice::pr_review(); // read/glob/grep/web only

        let minted = mint_session_task_token("pod-pr", &policy, TTL, NOW, &issuer).unwrap();
        let token: SignedTaskRef = serde_json::from_str(&minted.token_json).unwrap();

        let scope = token.effective_scope().unwrap();
        for op in Operation::ALL {
            if policy.capabilities.level_for(op) == CapabilityLevel::Never {
                assert!(
                    !scope.allowed_operations.contains(&op),
                    "denied op {op:?} must not appear in the minted scope"
                );
            }
        }
        // Sanity: a denied op (run_bash is Never in pr_review) is absent; an
        // allowed op (read_files) is present.
        assert!(!scope.allowed_operations.contains(&Operation::RunBash));
        assert!(scope.allowed_operations.contains(&Operation::ReadFiles));
    }
}

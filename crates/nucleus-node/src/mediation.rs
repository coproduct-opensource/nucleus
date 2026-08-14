//! Per-pod mediation-key provisioning for the in-guest tool-proxy.
//!
//! Each pod gets its own ed25519 seed that the guest tool-proxy uses to sign
//! [`MediationReceipt`](portcullis::mediation_receipt::MediationReceipt)s. The
//! node mints it here and serves it exactly once over vsock (see
//! `workload_api_vsock`), BEFORE the workload exists — a workload that could read
//! the key could forge receipts in its own name. The key never rides the
//! world-readable kernel command line.
//!
//! Extracted from `main.rs` so the seam is unit-testable and `main` stays under
//! its line ratchet: the construction is a decision about receipt provenance, not
//! boilerplate, and belongs somewhere a test can name it.

/// Mint a fresh 32-byte ed25519 seed, hex-encoded — the guest reconstructs the
/// key with `SigningKey::from_bytes` — and log the corresponding PUBLIC key to
/// the node journal, keyed by pod id.
///
/// The public-key log is the node's own record of the key it minted for this
/// pod, written host-side where the guest cannot reach it. A relying party
/// verifying the pod's receipts cross-checks the guest's self-published pubkey
/// against this one (the boot lane does exactly that): the key the receipts
/// verify under is then anchored in what the NODE minted, not only what the pod
/// claims. Only the public half is logged; the seed never leaves this function
/// except over the one-shot vsock delivery to the guest.
///
/// Fills the seed directly rather than `SigningKey::generate(OsRng)`:
/// ed25519-dalek pins its own `rand_core`, and the workspace `OsRng` is a
/// different version that does not satisfy that crate's `CryptoRng` bound. The
/// bytes are the same either way — a CSPRNG-filled 32-byte seed.
#[must_use]
pub(crate) fn new_seed_hex(pod_id: impl std::fmt::Display) -> Option<String> {
    use rand_core::RngCore;
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    let pubkey = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes(),
    );
    tracing::info!("NUCLEUS-MEDIATOR-PUBKEY {pod_id} {pubkey}");
    Some(hex::encode(seed))
}

/// The mediator SPIFFE id the receipts carry. Self-claimed: a relying party
/// cross-checks the SVID behind it (`verify_attested_receipt`) rather than
/// trusting the string.
#[must_use]
pub(crate) fn spiffe_id(trust_domain: &str, pod_id: impl std::fmt::Display) -> String {
    format!("spiffe://{trust_domain}/mediator/{pod_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minted_seed_is_32_bytes_and_distinct_each_time() {
        let a = new_seed_hex("pod-a").unwrap();
        let b = new_seed_hex("pod-b").unwrap();
        assert_eq!(
            hex::decode(&a).unwrap().len(),
            32,
            "an ed25519 seed is 32 bytes"
        );
        assert_ne!(a, b, "two mints must not collide — the key is per-pod");
    }

    #[test]
    fn the_spiffe_id_is_rooted_in_the_trust_domain_and_names_the_pod() {
        assert_eq!(
            spiffe_id("example.org", "pod-7"),
            "spiffe://example.org/mediator/pod-7"
        );
    }
}

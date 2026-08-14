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
/// key with `SigningKey::from_bytes` — and record the corresponding PUBLIC key to
/// a host-side file the guest cannot reach: `<pod_dir>/mediator-pubkey.hex`.
///
/// That file is the node's own record of the key it minted for this pod. A
/// relying party verifying the pod's receipts cross-checks the guest's
/// self-published pubkey against it (the boot lane does exactly that): the key
/// the receipts verify under is then anchored in what the NODE minted, not only
/// what the pod claims. A *file* rather than a log line on purpose — it does not
/// depend on the node's `RUST_LOG` filter or on which process's journal a test
/// happens to read. Only the public half is written; the seed never leaves this
/// function except over the one-shot vsock delivery to the guest. A write failure
/// degrades the anchor to absent (logged), never fails the pod's boot.
///
/// Fills the seed directly rather than `SigningKey::generate(OsRng)`:
/// ed25519-dalek pins its own `rand_core`, and the workspace `OsRng` is a
/// different version that does not satisfy that crate's `CryptoRng` bound. The
/// bytes are the same either way — a CSPRNG-filled 32-byte seed.
#[must_use]
pub(crate) fn new_seed_hex(pod_dir: &std::path::Path) -> Option<String> {
    use rand_core::RngCore;
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    let pubkey = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes(),
    );
    let anchor = pod_dir.join("mediator-pubkey.hex");
    // Trailing newline: several anchors may be `cat`-concatenated by a reader, and
    // without it two pubkeys would run together into one token.
    if let Err(e) = std::fs::write(&anchor, format!("{pubkey}\n")) {
        tracing::warn!(path = %anchor.display(), error = %e, "could not record the mediator pubkey anchor");
    }
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
    fn a_minted_seed_is_32_bytes_and_distinct_each_time_and_writes_a_matching_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let a = new_seed_hex(dir.path()).unwrap();
        assert_eq!(
            hex::decode(&a).unwrap().len(),
            32,
            "an ed25519 seed is 32 bytes"
        );
        // The anchor file holds the PUBLIC key for the seed just minted.
        let anchor = std::fs::read_to_string(dir.path().join("mediator-pubkey.hex"))
            .unwrap()
            .trim()
            .to_string();
        let seed_bytes: [u8; 32] = hex::decode(&a).unwrap().try_into().unwrap();
        let expect = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&seed_bytes)
                .verifying_key()
                .to_bytes(),
        );
        assert_eq!(anchor, expect, "the anchor must be the minted key's pubkey");

        let b = new_seed_hex(dir.path()).unwrap();
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

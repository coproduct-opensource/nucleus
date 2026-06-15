//! Slice 2: the **iroh-gossip carrier** for the slice-1 verifiable-head
//! message layer.
//!
//! This module is gated behind the **default-OFF** `transport` feature.
//! With default features the crate is exactly slice 1 — zero
//! iroh / iroh-gossip / QUIC dependencies — and downstream consumers,
//! the wasm/default build, and `cargo hack` all see a pure crate. The
//! heavy networking stack appears ONLY under `--features transport`.
//!
//! # What this is (and is NOT)
//!
//! It is a **best-effort byte carrier** for [`SignedWitnessHead`] values
//! over an [`iroh_gossip`] swarm keyed by a topic derived from the log
//! origin. It is **NOT** consensus, availability, or ordering, and it
//! adds **NO** trust.
//!
//! ## Fail-closed-on-receive (load-bearing)
//!
//! Bytes received from gossip are **UNTRUSTED**. [`next_head`] and
//! [`head_from_event`] decode them into a [`SignedWitnessHead`] and hand
//! it up **UNVERIFIED** — they perform **no** cryptographic check and
//! deliberately have **no** access to any trusted key. The consumer MUST
//! run the slice-1 [`crate::verify_head`] (or [`crate::collect_verified_names`])
//! against a pubkey from its OWN policy before the head may influence any
//! decision. The carrier never verifies-and-trusts on its own, never
//! bypasses `verify_head`, and never introduces a pubkey-from-the-wire
//! trust path. The sole cryptographic trust boundary remains the slice-1
//! k-of-n cosignature check, unchanged.
//!
//! # API mirrors iroh-gossip 0.100.0 verbatim
//!
//! - publish: [`iroh_gossip::api::GossipSender::broadcast`] (takes `Bytes`)
//! - receive: [`iroh_gossip::api::GossipReceiver`] as a `Stream` of
//!   `Result<`[`iroh_gossip::api::Event`]`, _>`, where
//!   [`Event::Received`] carries a [`iroh_gossip::api::Message`] whose
//!   `content: Bytes` is the raw datagram.

use iroh_gossip::api::{Event, GossipReceiver, GossipSender};
use iroh_gossip::TopicId;
use n0_future::StreamExt;

use crate::SignedWitnessHead;

/// Error type for transport operations.
///
/// Receive-side decode failures are intentionally NOT errors: corrupt or
/// undecodable gossip datagrams are silently dropped (best-effort), so
/// [`next_head`] / [`head_from_event`] return `None` rather than erroring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// `postcard` serialization of a head failed before broadcast.
    SerializationError(String),
    /// The gossip broadcast call failed (network / swarm error).
    PublishError(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::SerializationError(e) => write!(f, "serialization error: {e}"),
            TransportError::PublishError(e) => write!(f, "publish error: {e}"),
        }
    }
}

impl std::error::Error for TransportError {}

/// Result type for transport operations.
pub type TransportResult<T> = Result<T, TransportError>;

/// Derive a deterministic [`TopicId`] from a log origin.
///
/// Uses the BLAKE3 hash of the origin bytes, giving a deterministic,
/// uniformly-distributed topic id so publishers and subscribers coordinate
/// on the same swarm without an explicit topic-exchange step. This is a
/// pure routing key — it carries no authority and is not security-relevant
/// (trust still comes only from [`crate::verify_head`]).
pub fn topic_for(origin: &str) -> TopicId {
    let hash = blake3::hash(origin.as_bytes());
    TopicId::from_bytes(*hash.as_bytes())
}

/// Serialize a head to its gossip wire bytes (`postcard`).
///
/// This is the exact codec used by [`publish_head`]; exposed so the wire
/// round-trip is unit-testable without any networking. (`postcard` is a
/// maintained, compact serde binary codec — chosen over `bincode 1`, which
/// is unmaintained per RUSTSEC-2025-0141.)
pub fn encode_head(head: &SignedWitnessHead) -> TransportResult<Vec<u8>> {
    postcard::to_allocvec(head).map_err(|e| TransportError::SerializationError(e.to_string()))
}

/// Decode a head from gossip wire bytes, or `None` if the bytes are not a
/// valid [`SignedWitnessHead`].
///
/// **The returned head is UNVERIFIED.** Decoding proves only that the
/// bytes are well-formed, never that the cosignature is valid. The caller
/// MUST run [`crate::verify_head`] against a trusted policy key before
/// trusting it. A decode failure yields `None` (best-effort gossip: a
/// corrupt datagram is dropped, never fatal).
pub fn decode_head(bytes: &[u8]) -> Option<SignedWitnessHead> {
    postcard::from_bytes(bytes).ok()
}

/// Publish a signed witness head to the gossip topic for its `origin`.
///
/// Serializes the head with `postcard` and broadcasts the bytes via
/// [`iroh_gossip::api::GossipSender::broadcast`]. The `sender` is obtained
/// from `gossip.subscribe(`[`topic_for`]`(origin), ..).await?.split()`,
/// so the caller is responsible for subscribing to the matching topic.
///
/// **Contract:** best-effort datagram — no ordering, no delivery, no
/// consensus. The receiver is responsible for [`crate::verify_head`]
/// before accepting the head into any decision.
pub async fn publish_head(sender: &GossipSender, head: &SignedWitnessHead) -> TransportResult<()> {
    let bytes = encode_head(head)?;
    // `Vec<u8>: Into<Bytes>` — broadcast takes `Bytes` (iroh-gossip 0.100.0).
    sender
        .broadcast(bytes.into())
        .await
        .map_err(|e| TransportError::PublishError(e.to_string()))
}

/// Extract an **UNVERIFIED** head from a single gossip [`Event`].
///
/// Returns `Some(head)` only for an [`Event::Received`] whose payload
/// decodes; `NeighborUp` / `NeighborDown` / `Lagged` and undecodable
/// payloads yield `None`. **No cryptographic verification is performed**
/// (fail-closed-on-receive): the caller MUST run [`crate::verify_head`]
/// with a trusted policy key before trusting the result.
pub fn head_from_event(event: &Event) -> Option<SignedWitnessHead> {
    match event {
        Event::Received(message) => decode_head(&message.content),
        _ => None,
    }
}

/// Pull the next **UNVERIFIED** head off a gossip subscription, skipping
/// non-message events, receiver lag, and undecodable datagrams.
///
/// Returns `None` when the subscription ends. **The head is UNVERIFIED**
/// — exactly the fail-closed-on-receive boundary: this function has no
/// access to any key and performs no crypto. The caller MUST verify:
///
/// ```ignore
/// while let Some(unverified) = next_head(&mut receiver).await {
///     if verify_head(&unverified, &trusted_pubkey) {
///         // only now may `unverified` influence a decision
///     }
/// }
/// ```
pub async fn next_head(receiver: &mut GossipReceiver) -> Option<SignedWitnessHead> {
    while let Some(event) = receiver.next().await {
        // Receiver errors / lag are best-effort transport noise: skip.
        let Ok(event) = event else { continue };
        if let Some(head) = head_from_event(&event) {
            return Some(head);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use nucleus_witness::WitnessKey;

    const NOTE: &[u8] = b"nucleus.example/log\n5\ncm9vdA==\n";

    /// Mint a real head by cosigning `note_body` with `wk`, parsing the
    /// cosignature line's `keyID(4) || ts(8) || sig(64)` payload back out
    /// — the SAME bytes a witness emits on the wire (mirrors slice 1).
    fn mint_head(wk: &WitnessKey, origin: &str, note_body: &[u8], ts: u64) -> SignedWitnessHead {
        let line = wk.cosign_line(note_body, ts);
        let b64 = line.rsplit(' ').next().expect("base64 token");
        let payload = B64.decode(b64).expect("valid base64 payload");
        assert_eq!(payload.len(), 4 + 8 + 64, "keyID(4)||ts(8)||sig(64)");
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&payload[12..]);
        SignedWitnessHead {
            origin: origin.to_string(),
            witness_name: wk.name().to_string(),
            timestamp: ts,
            note_body: note_body.to_vec(),
            sig,
        }
    }

    fn sample_head() -> SignedWitnessHead {
        SignedWitnessHead {
            origin: "nucleus.example/log".to_string(),
            witness_name: "w1".to_string(),
            timestamp: 1_700_000_000,
            note_body: b"checkpoint body\n".to_vec(),
            sig: [9u8; 64],
        }
    }

    // --- Wire round-trip: these RUN (in CI, under --features transport). ---

    /// `encode_head` ∘ `decode_head` is the identity on a well-formed head
    /// — the carrier preserves every signed field byte-for-byte.
    #[test]
    fn wire_round_trip_preserves_head() {
        let head = sample_head();
        let bytes = encode_head(&head).expect("encode");
        let decoded = decode_head(&bytes).expect("decode");
        assert_eq!(decoded, head);
    }

    /// A real cosigned head also survives the wire codec unchanged, and the
    /// decoded (UNVERIFIED) head still verifies under the trusted key —
    /// proving the carrier neither mangles the signed bytes nor is the
    /// verification step.
    #[test]
    fn real_head_round_trips_and_then_verifies() {
        let wk = WitnessKey::from_seed([7u8; 32], "w1");
        let head = mint_head(&wk, "nucleus.example/log", NOTE, 1_700_000_000);
        let bytes = encode_head(&head).expect("encode");
        let decoded = decode_head(&bytes).expect("decode");
        assert_eq!(decoded, head);
        // The CARRIER does not verify; the consumer does (slice 1).
        assert!(crate::verify_head(&decoded, &wk.verifying_key_bytes()));
    }

    /// Garbage bytes decode to `None` (best-effort drop, never a panic /
    /// error) — corrupt datagrams contribute nothing.
    #[test]
    fn decode_rejects_garbage() {
        assert!(decode_head(b"not a valid signed witness head").is_none());
        assert!(decode_head(&[]).is_none());
    }

    /// `topic_for` is deterministic for one origin and distinct across
    /// origins.
    #[test]
    fn topic_for_is_deterministic_and_origin_distinct() {
        let a1 = topic_for("nucleus.example.com/log42");
        let a2 = topic_for("nucleus.example.com/log42");
        let b = topic_for("nucleus.example.com/log43");
        assert_eq!(a1, a2);
        assert_ne!(a1, b);
    }

    // --- Live 2-node networking: COMPILED in CI (catches API misuse),
    //     #[ignore]'d so the flaky QUIC path is not RUN in CI. Run with
    //     `cargo test -p nucleus-witness-gossip --features transport \
    //       -- --ignored two_node`. ---

    #[tokio::test]
    #[ignore = "live QUIC between two iroh endpoints; compiled in CI, run manually"]
    async fn two_node_gossip_carries_head_consumer_then_verifies(
    ) -> Result<(), Box<dyn std::error::Error>> {
        use iroh::{endpoint::presets, protocol::Router, Endpoint};
        use iroh_gossip::Gossip;

        // A real cosigned head and the key the CONSUMER trusts (slice 1).
        let wk = WitnessKey::from_seed([7u8; 32], "w1");
        let origin = "nucleus.example/log";
        let head = mint_head(&wk, origin, NOTE, 1_700_000_000);
        let trusted_pubkey = wk.verifying_key_bytes();

        let topic = topic_for(origin);

        // Node A (publisher).
        let ep_a = Endpoint::bind(presets::N0).await?;
        let gossip_a = Gossip::builder().spawn(ep_a.clone());
        let _router_a = Router::builder(ep_a.clone())
            .accept(iroh_gossip::ALPN, gossip_a.clone())
            .spawn();
        let id_a = ep_a.id();

        // Node B (subscriber) bootstraps off A.
        let ep_b = Endpoint::bind(presets::N0).await?;
        let gossip_b = Gossip::builder().spawn(ep_b.clone());
        let _router_b = Router::builder(ep_b.clone())
            .accept(iroh_gossip::ALPN, gossip_b.clone())
            .spawn();

        let (tx_a, _rx_a) = gossip_a.subscribe(topic, vec![]).await?.split();
        let (_tx_b, mut rx_b) = gossip_b.subscribe(topic, vec![id_a]).await?.split();
        rx_b.joined().await?;

        // A publishes the head over the carrier.
        publish_head(&tx_a, &head).await?;

        // B receives an UNVERIFIED head, then applies slice-1 verification.
        let received = next_head(&mut rx_b)
            .await
            .expect("received a head from the swarm");
        assert!(
            crate::verify_head(&received, &trusted_pubkey),
            "carrier handed up UNVERIFIED bytes; trust comes only from verify_head"
        );
        assert_eq!(received, head);
        Ok(())
    }
}

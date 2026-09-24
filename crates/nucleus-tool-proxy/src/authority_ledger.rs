//! Where a cleared round is written down, per participant.
//!
//! # Why one edge each, and not one edge with the bids as parents
//!
//! `EdgeKind::Allocation`'s own doc suggests "Parents are the bid edges that fed
//! into this allocation." That shape works only when every bidder shares one
//! session. The moment two different pods contend — which is the case an
//! authority exchange exists for — their bid edges live under different session
//! roots, and `nucleus_envelope::verify_bundle` refuses the allocation outright:
//!
//! ```text
//! // 5) Membership: child AND every parent must be under the session
//! // root. The parent check defends against a Merge edge whose child is
//! // syntactically under root but whose parents reach into a foreign
//! // pod's lineage.
//! ```
//!
//! So the join across participants happens at **verification** time, not at
//! **graph** time. Each participant gets one edge in its own lineage, and every
//! one of those edges commits to the same `content_hash_hex` — the round's
//! receipt. Anyone holding the receipt recomputes the whole clearing with
//! `nucleus_recompute::verify_receipt` and checks that each separately-signed
//! edge names that same round. Parentage stays intra-session, which is what the
//! envelope invariant requires; the receipt is the cross-session join key.
//!
//! # The outcome is the edge KIND, not an attribute
//!
//! A winner's edge is an `Allocation`; a loser's is a `Bid`. That distinction is
//! load-bearing and it is *signed*: `canonical_edge_bytes` covers `kind_tag`.
//! Putting the outcome — or the bid value, or the price — in `attrs` would be a
//! false guarantee, because `canonical_edge_bytes` does **not** sign `attrs`.
//! This is the trap `docs/rfcs/verified-agent-commerce-quickstart.md` records
//! hitting once already: *"putting the commerce binding only in the payload
//! would be a false guarantee."* Every number a reader needs is inside the
//! receipt the content hash commits to.
//!
//! # What this does not record
//!
//! Parents. The proxy does not maintain each caller's call graph, so an edge
//! here is a root in this log rather than a continuation of the caller's prior
//! work. Its binding to the round is the content hash and its binding to the
//! caller is `child`; what is missing is the caller's own history, and saying so
//! is cheaper than implying a provenance chain that is not there.

use std::path::Path;
use std::sync::Mutex;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use nucleus_lineage::JsonlSink;
use nucleus_lineage::edge::{EdgeKind, LineageEdge};
use nucleus_lineage::id::CallSpiffeId;
use nucleus_lineage::proof::{Proof, canonical_edge_bytes, edge_content_hash};
use nucleus_lineage::sink::LineageSink;

/// Appends signed, hash-chained edges recording each participant's part in a
/// cleared round.
pub(crate) struct AuthorityLedger {
    sink: JsonlSink,
    key: SigningKey,
    kid: String,
    /// The running chain head. `verify_chain` recomputes it the same way, so the
    /// two must agree edge for edge: sign over `canonical_edge_bytes(edge,
    /// prev)`, then advance to `edge_content_hash(edge, prev)`.
    prev: Mutex<Option<[u8; 32]>>,
}

impl AuthorityLedger {
    /// Open a ledger at `path`, signing with the pod's mediation key.
    ///
    /// Reuses `NUCLEUS_MEDIATION_SIGNING_KEY` rather than introducing a second
    /// pod key: one key, one identity to cross-check against the node's record
    /// of what it minted. A pod without that key has no ledger, and the exchange
    /// then clears without a durable record — which is why the caller treats a
    /// missing ledger as a reason to refuse rather than a reason to proceed
    /// quietly.
    pub(crate) fn open(path: &Path, seed: [u8; 32], kid: impl Into<String>) -> Option<Self> {
        match JsonlSink::open(path) {
            Ok(sink) => Some(AuthorityLedger {
                sink,
                key: SigningKey::from_bytes(&seed),
                kid: kid.into(),
                prev: Mutex::new(None),
            }),
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "could not open the authority ledger; cleared rounds will not be recorded"
                );
                None
            }
        }
    }

    /// The public half, for a relying party that wants to check these edges.
    pub(crate) fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// The kid these edges are signed under.
    pub(crate) fn kid(&self) -> &str {
        &self.kid
    }

    /// Record one participant's part in a round.
    ///
    /// `receipt_hash_hex` MUST be `nucleus_recompute::content_hash_hex` of the
    /// round's receipt — the same value for every participant, which is what
    /// makes their separate edges checkably about the same round.
    pub(crate) fn record(
        &self,
        child: CallSpiffeId,
        kind: EdgeKind,
        receipt_hash_hex: String,
    ) -> Result<(), String> {
        let mut prev = self.prev.lock().unwrap_or_else(|e| e.into_inner());
        let mut edge = LineageEdge {
            child,
            parents: Vec::new(),
            kind,
            content_hash_hex: Some(receipt_hash_hex),
            ts: chrono::Utc::now(),
            attrs: std::collections::BTreeMap::new(),
            proof: None,
            verifier_attestation: None,
        };
        let bytes = canonical_edge_bytes(&edge, prev.as_ref());
        edge.proof = Some(Proof {
            kid: self.kid.clone(),
            alg: "EdDSA".to_string(),
            sig: self.key.sign(&bytes).to_bytes().to_vec(),
            prev_hash: *prev,
        });
        let next = edge_content_hash(&edge, prev.as_ref());
        self.sink.emit(edge).map_err(|e| e.to_string())?;
        // Advanced only after the write succeeds: a chain head that moved past
        // an edge nobody stored would break every later edge's verification for
        // a reason no reader could see.
        *prev = Some(next);
        Ok(())
    }

    /// Every edge written so far. `cfg(test)` until something reads the ledger
    /// back in production — a walk over this log belongs with the `nucleus
    /// lineage` command, which does not reach into the guest today.
    #[cfg(test)]
    pub(crate) fn edges(&self) -> Result<Vec<LineageEdge>, String> {
        self.sink.iter().map_err(|e| e.to_string())
    }

    /// A JWKS carrying just this ledger's key, so a caller can verify its own
    /// chain without reaching for an issuer. `cfg(test)` for the same reason as
    /// [`Self::edges`]: production publishes the raw verifying key at startup
    /// and the reader assembles its own JWKS.
    #[cfg(test)]
    pub(crate) fn jwks(&self) -> nucleus_lineage::Jwks {
        nucleus_lineage::verify::StaticKeyResolver::new()
            .insert(self.kid.clone(), self.verifying_key())
            .into_jwks()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_lineage::verify::verify_chain;

    fn ledger(dir: &tempfile::TempDir) -> AuthorityLedger {
        AuthorityLedger::open(
            &dir.path().join("authority.jsonl"),
            [7u8; 32],
            "pod-mediation",
        )
        .expect("opens")
    }

    /// Built the way production builds it: parse the caller's workload id, then
    /// `derive_tool`, which mints the `/call/<uuid>` segment. A hand-written
    /// call id is rejected by the parser — the `/call/` segment must be a real
    /// UUID — so a fixture that fabricated one would be testing a shape the
    /// runtime cannot produce.
    fn call(n: u32) -> CallSpiffeId {
        CallSpiffeId::parse(format!("spiffe://example.org/ns/default/sa/pod-{n}"))
            .expect("valid workload id")
            .derive_tool("authority", None)
            .expect("derives a call id")
    }

    /// The property the whole file is for: separately-signed edges, one per
    /// participant, that a stranger can verify as a chain.
    #[test]
    fn the_chain_verifies_against_the_ledgers_own_key() {
        let dir = tempfile::tempdir().expect("tmp");
        let l = ledger(&dir);
        let round = "a1b2c3".to_string();
        l.record(
            call(1),
            EdgeKind::Allocation {
                market_id: "r-1".into(),
                mechanism: "vcg".into(),
            },
            round.clone(),
        )
        .expect("winner");
        l.record(
            call(2),
            EdgeKind::Bid {
                market_id: "r-1".into(),
            },
            round.clone(),
        )
        .expect("loser");

        let edges = l.edges().expect("readable");
        assert_eq!(edges.len(), 2);
        verify_chain(&edges, &l.jwks()).expect("the chain must verify");
        // Both participants commit to the SAME round, which is what makes their
        // separate edges checkably about one clearing.
        assert!(
            edges
                .iter()
                .all(|e| e.content_hash_hex.as_deref() == Some(round.as_str())),
            "every participant's edge must name the same receipt"
        );
    }

    /// The outcome is in the kind, and the kind is signed — so flipping a loser
    /// into a winner breaks the signature rather than rewriting history.
    #[test]
    fn rewriting_the_outcome_breaks_the_signature() {
        let dir = tempfile::tempdir().expect("tmp");
        let l = ledger(&dir);
        l.record(
            call(1),
            EdgeKind::Bid {
                market_id: "r-1".into(),
            },
            "deadbeef".to_string(),
        )
        .expect("loser");

        let mut edges = l.edges().expect("readable");
        edges[0].kind = EdgeKind::Allocation {
            market_id: "r-1".into(),
            mechanism: "vcg".into(),
        };
        assert!(
            verify_chain(&edges, &l.jwks()).is_err(),
            "a loser promoted to a winner must not verify"
        );
    }

    /// And so does repointing an edge at a different round.
    #[test]
    fn repointing_an_edge_at_another_round_breaks_the_signature() {
        let dir = tempfile::tempdir().expect("tmp");
        let l = ledger(&dir);
        l.record(
            call(1),
            EdgeKind::Bid {
                market_id: "r-1".into(),
            },
            "deadbeef".to_string(),
        )
        .expect("bid");
        let mut edges = l.edges().expect("readable");
        edges[0].content_hash_hex = Some("feedface".to_string());
        assert!(
            verify_chain(&edges, &l.jwks()).is_err(),
            "an edge repointed at another receipt must not verify"
        );
    }

    /// A wrong key is a wrong key: these edges say who wrote them.
    #[test]
    fn another_key_does_not_verify_this_chain() {
        let dir = tempfile::tempdir().expect("tmp");
        let l = ledger(&dir);
        l.record(
            call(1),
            EdgeKind::Bid {
                market_id: "r-1".into(),
            },
            "deadbeef".to_string(),
        )
        .expect("bid");
        let edges = l.edges().expect("readable");
        let other = nucleus_lineage::verify::StaticKeyResolver::new()
            .insert(
                "pod-mediation",
                SigningKey::from_bytes(&[9u8; 32]).verifying_key(),
            )
            .into_jwks();
        assert!(verify_chain(&edges, &other).is_err());
    }
}

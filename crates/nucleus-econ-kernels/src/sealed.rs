//! Two-phase commit-reveal sealed bids (Bet A — REAL slice).
//!
//! # What this module IS (shipped, verified)
//!
//! A pure, integer-only **commit-reveal** lifecycle that
//! lets an auction collect *binding but hidden* bids in a first phase,
//! then open them in a second phase, and clear with the **unchanged**
//! [`crate::run_vcg`] / [`crate::run_vcg_with_externalities`] kernels on
//! the revealed bids. The construction is the standard cryptographic
//! commitment scheme:
//!
//! ```text
//! commitment c = SHA-256(
//!     COMMIT_DOMAIN
//!  || chain_id            (u64 BE)        -- replay domain separation
//!  || auction_id          (len-prefixed)  -- binds to one auction
//!  || agent_spiffe_id     (len-prefixed)  -- binds to one bidder
//!  || effective_value     (u64 LE)        -- the sealed value
//!  || externality_profile (canonical bytes from nucleus-externality)
//!  || nonce               (32 bytes)      -- hiding randomness
//! )
//! ```
//!
//! The reveal supplies `(value, profile, nonce)`; the verifier recomputes
//! `c` and checks bit-for-bit equality, then constructs the SAME
//! [`crate::IntegerBid`] the plaintext path uses. **`run_vcg` is never
//! touched** — see `tests/sealed_bid_parity.rs` for the byte-for-byte
//! parity assertion against the plaintext clearing.
//!
//! ## On wasm portability (honest status)
//!
//! The *constructs in this module* are wasm-portable: only `sha2`,
//! integer arithmetic, length-prefixed byte work, and no floats or RNG.
//! However, the **crate as a whole does not currently compile to
//! `wasm32-unknown-unknown`**: a pre-existing transitive `uuid` dependency
//! (via `nucleus-externality` → vendored `nucleus-lineage`) emits a
//! `compile_error!` on wasm32 demanding a randomness feature. So "the code
//! is wasm-portable" is true of this module's logic but "the crate builds
//! for wasm" is **not** currently verified — `cargo check
//! -p nucleus-econ-kernels --target wasm32-unknown-unknown` fails on
//! `uuid`. The lifted pure clearing core (Bet C, `nucleus-wasm`) is what
//! actually targets and builds for wasm today; fixing this crate's wasm
//! build means changing the vendored `nucleus-lineage`/`uuid` feature set,
//! which is out of this crate's scope.
//!
//! ## Security properties this construction gives (and does not)
//!
//! - **Binding** — under SHA-256 collision resistance, a bidder cannot
//!   open one commitment to two different bids. (Standard hash-commitment
//!   binding; we do not re-prove SHA-256.)
//! - **Hiding** — this is an *argued* computational property, NOT a
//!   unit-tested one. The 32-byte uniformly-random `nonce` (sampled by
//!   the caller from a CSPRNG) is what makes the commitment computationally
//!   hiding even for a low-entropy value space (e.g. round-number bids):
//!   without it, an adversary could brute-force the (small) value space
//!   and de-seal a bid. Computational/IND-CPA hiding rests on SHA-256
//!   behaving as a random oracle over the `nonce` + message-space entropy
//!   and is **not** something a unit test can establish. What the unit
//!   test `commitment_is_distinct_and_leaks_no_plaintext_bytes` *does*
//!   pin is the weaker, testable consequence: distinct openings yield
//!   distinct commitments, and the commitment digest contains no literal
//!   plaintext-value bytes. That is an encoding/distinctness sanity
//!   check, not a proof of hiding.
//! - **Binding to context** — `chain_id`, `auction_id`, and
//!   `agent_spiffe_id` are inside the hash, so a commitment from auction
//!   A or chain X cannot be replayed into auction B / chain Y.
//!
//! # What this module is NOT (the honest gap — see SEALED-BIDS-DESIGN.md)
//!
//! Commit-reveal **alone does not stop the last-mover / non-reveal grief
//! attack**: a bidder who sees others' reveals (or simply dislikes the
//! outcome) can refuse to open, withholding information and skewing the
//! clearing. The classic fixes are (a) **deposits/slashing** or (b)
//! **delayed-execution / threshold time-lock encryption** so a withheld
//! bid is decryptable by *anyone* after a public beacon. This module
//! ships only the commit-reveal primitive plus a typed **integration
//! seam** ([`crate::tlock`]) for the time-lock path; the anti-grief
//! crypto itself is a documented spike, NOT shipped. Do not represent
//! the non-reveal attack as solved.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use nucleus_externality::{canonical_externality_bytes, ExternalityProfile};

use crate::vcg::IntegerBid;

/// Domain-separation tag for the bid commitment hash. Bumping this
/// constant invalidates every prior commitment (v1 contract). The
/// trailing NUL mirrors the externality crate's `PROFILE_DOMAIN`
/// convention so the two domain spaces can never collide on a prefix.
pub const COMMIT_DOMAIN: &[u8] = b"nucleus/auction/sealed-bid/commit/v1\0";

/// A 32-byte SHA-256 bid commitment. This is what a bidder publishes in
/// the **commit phase**; it hides the bid value and externality profile
/// while binding the bidder to exactly one opening.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BidCommitment(pub [u8; 32]);

impl BidCommitment {
    /// Lower-hex encoding (64 chars), for wire transport / logging.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from a 64-char lower/upper-hex string.
    pub fn from_hex(s: &str) -> Result<Self, SealedBidError> {
        let raw = hex::decode(s).map_err(|_| SealedBidError::MalformedCommitmentHex)?;
        let arr: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| SealedBidError::MalformedCommitmentHex)?;
        Ok(BidCommitment(arr))
    }
}

/// The secret opening of a [`BidCommitment`]. The bidder keeps this
/// private during the commit phase and publishes it in the reveal phase.
///
/// All fields are bound into the commitment hash; changing any one of
/// them produces a different commitment, so a verifier can detect any
/// post-hoc tampering by recomputation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BidOpening {
    /// SPIFFE identity of the bidder. Must equal the value committed.
    pub agent_spiffe_id: String,
    /// Auction this bid targets. Bound into the commitment so a
    /// commitment cannot be replayed across auctions.
    pub auction_id: String,
    /// The sealed effective value, in `u64` micro-USD.
    pub effective_value_micro_usd: u64,
    /// The sealed externality profile. `None` ⇒ an empty profile is
    /// committed (the canonical bytes of `ExternalityProfile::new()`),
    /// so the commitment is still well-defined and the VCG path falls
    /// back to single-good Vickrey exactly as the plaintext path does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub externality_profile: Option<ExternalityProfile>,
    /// 32-byte hiding nonce. MUST be sampled from a CSPRNG by the
    /// bidder. This crate is pure (no RNG dependency) — nonce
    /// generation is the caller's responsibility; see the design doc.
    pub nonce: [u8; 32],
}

/// Errors from the sealed-bid lifecycle.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SealedBidError {
    /// The recomputed commitment did not equal the published one. The
    /// reveal does not open the commitment it claims to.
    #[error("reveal does not match commitment: recomputed {recomputed} != published {published}")]
    CommitmentMismatch {
        published: String,
        recomputed: String,
    },
    /// A commitment hex string was not 32 bytes of valid hex.
    #[error("malformed commitment hex")]
    MalformedCommitmentHex,
    /// The reveal's `auction_id` does not match the auction the verifier
    /// is clearing. Defends against cross-auction reveal confusion even
    /// before the (also-checked) commitment recomputation.
    #[error("reveal auction_id {got:?} does not match expected {expected:?}")]
    AuctionIdMismatch { expected: String, got: String },
}

/// Compute the canonical commitment for a `(chain_id, opening)` pair.
///
/// This is the single source of truth for the commitment byte layout;
/// both the bidder (to commit) and the verifier (to check a reveal) call
/// it, so they cannot drift. Pure and allocation-bounded.
///
/// `chain_id` is the replay-domain identifier (e.g. an EVM chain id, or
/// a Nucleus-internal epoch id). It is hashed in big-endian so the
/// commitment is host-endianness-independent.
pub fn compute_commitment(chain_id: u64, opening: &BidOpening) -> BidCommitment {
    let mut h = Sha256::new();
    h.update(COMMIT_DOMAIN);
    h.update(chain_id.to_be_bytes());

    // Length-prefixed strings so concatenation is unambiguous (no
    // "ab"||"c" == "a"||"bc" collisions across the two string fields).
    write_len_prefixed(&mut h, opening.auction_id.as_bytes());
    write_len_prefixed(&mut h, opening.agent_spiffe_id.as_bytes());

    // Value little-endian per the pinned construction.
    h.update(opening.effective_value_micro_usd.to_le_bytes());

    // Externality profile via the externality crate's OWN canonical
    // encoding so the seal binds the exact bytes the Pigouvian kernel
    // will later hash/score. `None` → the canonical empty profile.
    let empty;
    let profile = match &opening.externality_profile {
        Some(p) => p,
        None => {
            empty = ExternalityProfile::new();
            &empty
        }
    };
    let profile_bytes = canonical_externality_bytes(profile);
    write_len_prefixed(&mut h, &profile_bytes);

    h.update(opening.nonce);

    let digest = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&digest);
    BidCommitment(arr)
}

/// Hash a length-prefixed byte string: `u64_be(len) || bytes`. The
/// length prefix removes concatenation ambiguity between adjacent
/// variable-length fields.
fn write_len_prefixed(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
}

/// **Reveal-phase verification.** Recompute the commitment from the
/// opening and check it equals `published`. On success, return the
/// [`IntegerBid`] that the *plaintext* path would have produced for the
/// same bidder — so the downstream clearing is byte-for-byte identical
/// to the un-sealed auction (proven in `tests/sealed_bid_parity.rs`).
///
/// `expected_auction_id` is the auction the caller is clearing; a
/// mismatch is rejected up front (defence in depth — the commitment
/// recomputation would also fail, but the explicit check gives a precise
/// error).
pub fn verify_reveal(
    chain_id: u64,
    expected_auction_id: &str,
    published: &BidCommitment,
    opening: &BidOpening,
) -> Result<IntegerBid, SealedBidError> {
    if opening.auction_id != expected_auction_id {
        return Err(SealedBidError::AuctionIdMismatch {
            expected: expected_auction_id.to_string(),
            got: opening.auction_id.clone(),
        });
    }
    let recomputed = compute_commitment(chain_id, opening);
    if &recomputed != published {
        return Err(SealedBidError::CommitmentMismatch {
            published: published.to_hex(),
            recomputed: recomputed.to_hex(),
        });
    }
    Ok(opening_to_integer_bid(opening))
}

/// Map a verified opening onto the kernel's [`IntegerBid`]. This is the
/// SAME field mapping the plaintext (un-sealed) hub path uses, which is
/// why a revealed-bid clearing equals a plaintext clearing. Note that
/// the externality profile is NOT carried on `IntegerBid` (the kernel is
/// externality-agnostic); it flows separately into
/// [`crate::run_vcg_with_externalities`]. Callers that need the profile
/// for the Pigouvian path read it from the [`BidOpening`].
pub fn opening_to_integer_bid(opening: &BidOpening) -> IntegerBid {
    IntegerBid {
        bidder: opening.agent_spiffe_id.clone(),
        proposal_id: opening.auction_id.clone(),
        effective_value_micro_usd: opening.effective_value_micro_usd,
    }
}

// ───────────────────────────────────────────────────────────────────────
// Commitment SET publication (Bet C keystone — the OMIT defence).
//
// recompute (#46) closes (a) MISPRICE and bidder-signatures close (b)
// FABRICATE, but neither can see a bid the auctioneer silently DROPPED:
// a recompute over the bids the auctioneer chose to publish is blind to a
// withheld commitment. The keystone closes (c) OMIT by binding the hub,
// at commit-close, to a single 32-byte commitment over the COMPLETE
// SORTED MULTISET of every accepted `BidCommitment`. That root is
//   (1) returned to each bidder as a commit ACK at submit time, and
//   (2) anchored on-chain at commit-close (one extra datum field on
//       bond_escrow.ak — no new crypto).
// A bidder holding a commit ACK can then prove omission: a bidder-signed
// `BidCommitment` that is NOT a member of the published sorted set is a
// withheld bid. This module ships the pure, integer-only, wasm-safe root
// + membership primitive. It does NOT touch `vickrey_clear` / `run_vcg`.
//
// SCOPE (honest): this is EX-POST credibility — the auctioneer CAN still
// attempt to omit during the auction, but the deviation is now DETECTABLE
// (root mismatch / non-membership) and PUNISHABLE (bond slash). It is NOT
// ex-ante structural impossibility (Chitra et al public-broadcast, where
// bidders post commitments directly on-chain so the hub physically cannot
// omit). Ex-ante is the named frontier, not claimed here.
// ───────────────────────────────────────────────────────────────────────

/// Domain-separation tag for the commitment-SET root hash. Distinct from
/// [`COMMIT_DOMAIN`] (the per-bid tag) so a single bid commitment can
/// never be confused with a set root on the wire. Trailing NUL matches
/// the convention.
pub const COMMIT_SET_DOMAIN: &[u8] = b"nucleus/auction/sealed-bid/commit-set/v1\0";

/// A 32-byte root committing to the complete sorted multiset of all
/// `BidCommitment`s accepted in the commit phase.
///
/// Computed as `SHA-256( COMMIT_SET_DOMAIN || chain_id_be || auction_id
/// (len-prefixed) || count_be || c_0 || c_1 || … )` where the `c_i` are
/// the accepted commitments **sorted ascending by their 32-byte value**.
/// Sorting makes the root a function of the multiset only (submission
/// order cannot change it), and `count` length-prefixes the set so a
/// shorter set cannot be a prefix-collision of a longer one.
///
/// This is the digest the hub returns as a commit ACK and anchors
/// on-chain at commit-close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CommitmentSetRoot(pub [u8; 32]);

impl CommitmentSetRoot {
    /// Lower-hex encoding (64 chars), for wire transport / the on-chain
    /// datum field / logging.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from a 64-char hex string.
    pub fn from_hex(s: &str) -> Result<Self, SealedBidError> {
        let raw = hex::decode(s).map_err(|_| SealedBidError::MalformedCommitmentHex)?;
        let arr: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| SealedBidError::MalformedCommitmentHex)?;
        Ok(CommitmentSetRoot(arr))
    }
}

/// Return the accepted commitments as a canonical **sorted** vector
/// (ascending by 32-byte value). Pure helper used by both the root
/// computation and direct membership checking at reveal-close.
///
/// Duplicates are PRESERVED — the construction commits to the sorted
/// *multiset*, so two distinct bidders who (astronomically improbably)
/// produce the same commitment are both represented. Membership of a
/// bidder's own ACK'd commitment is therefore unaffected by another
/// bidder's commitment value.
pub fn sorted_commitment_set(commitments: &[BidCommitment]) -> Vec<BidCommitment> {
    let mut v = commitments.to_vec();
    v.sort_by_key(|a| a.0);
    v
}

/// Compute the [`CommitmentSetRoot`] over the accepted commitments.
///
/// Deterministic and order-independent: the input is sorted into a
/// canonical multiset before hashing, so the hub cannot make the root
/// depend on submission order, and a verifier re-deriving the root from
/// the published set gets the same value regardless of the order it
/// receives them in. Pure, allocation-bounded, no RNG, no floats —
/// wasm-safe (the same SHA-256 + integer-bytes discipline as
/// [`compute_commitment`]).
pub fn compute_commitment_set_root(
    chain_id: u64,
    auction_id: &str,
    commitments: &[BidCommitment],
) -> CommitmentSetRoot {
    let sorted = sorted_commitment_set(commitments);
    let mut h = Sha256::new();
    h.update(COMMIT_SET_DOMAIN);
    h.update(chain_id.to_be_bytes());
    write_len_prefixed(&mut h, auction_id.as_bytes());
    // Count is length-prefixed so {c} and {c, c'} (or any prefix) can
    // never collide; combined with per-element fixed 32-byte width this
    // is an unambiguous encoding of the sorted multiset.
    h.update((sorted.len() as u64).to_be_bytes());
    for c in &sorted {
        h.update(c.0);
    }
    let digest = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&digest);
    CommitmentSetRoot(arr)
}

/// A bidder's **commit acknowledgement** — what the hub returns at submit
/// time and the bidder retains as omission evidence.
///
/// It pins the bidder's own `commitment` to the `set_root` the hub
/// committed to (and later anchored on-chain) for `(chain_id,
/// auction_id)`. At reveal-close the full accepted set is published; the
/// bidder checks that its `commitment` is a member of that published set
/// AND that the published set re-derives to `set_root`. Either check
/// failing is provable auctioneer misbehaviour (omission or a swapped
/// root), slashable via the bond.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitAck {
    /// Replay-domain id (matches the per-bid commitment's `chain_id`).
    pub chain_id: u64,
    /// The auction this ACK is scoped to.
    pub auction_id: String,
    /// The bidder's own commitment the hub acknowledged accepting.
    pub commitment: BidCommitment,
    /// The set root the hub committed to at commit-close (the value
    /// anchored on-chain). The bidder verifies the published set
    /// re-derives to this.
    pub set_root: CommitmentSetRoot,
}

/// Result of auditing a [`CommitAck`] against a published commitment set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OmissionAudit {
    /// The bidder's commitment is a member of the published set AND the
    /// published set re-derives to the ACK'd root. No omission.
    Included,
    /// The published set re-derives to the ACK'd root, but the bidder's
    /// commitment is NOT in it — a provable OMISSION (the keystone
    /// detection). The auctioneer dropped an accepted bid.
    Omitted,
    /// The published set does NOT re-derive to the ACK'd root — the hub
    /// published a different set than the one it committed to on-chain
    /// (a swapped/forged set). Also provable misbehaviour.
    RootMismatch,
}

/// Audit a bidder's [`CommitAck`] against the set the hub published at
/// reveal-close.
///
/// This is the bidder-side omission check the keystone enables. The
/// `published_set` is the full list of accepted commitments the hub
/// reveals at reveal-close (anchored on-chain by its root). The audit:
///   1. Re-derives the root of `published_set` and compares to the ACK'd
///      root — catches a hub that swapped the set after committing.
///   2. Checks the bidder's own `commitment` is a member — catches the
///      hub silently dropping THIS bidder's accepted bid.
///
/// Returns the [`OmissionAudit`] verdict. `Included` is the only honest
/// outcome; the other two are slashable.
pub fn audit_commit_ack(ack: &CommitAck, published_set: &[BidCommitment]) -> OmissionAudit {
    let rederived = compute_commitment_set_root(ack.chain_id, &ack.auction_id, published_set);
    if rederived != ack.set_root {
        return OmissionAudit::RootMismatch;
    }
    if published_set.contains(&ack.commitment) {
        OmissionAudit::Included
    } else {
        OmissionAudit::Omitted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use nucleus_externality::{sign_claim, ResourceDim, SignedExternalityClaim};

    fn mk_profile(units: u64) -> ExternalityProfile {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let claim = sign_claim(
            &sk,
            SignedExternalityClaim {
                resource: ResourceDim::GpuSeconds,
                units_micro: units,
                ts_unix_micros: 1_700_000_000_000_000,
                not_after_unix_micros: 1_700_000_000_000_000 + 3_600_000_000,
                subject_identity: "spiffe://nucleus.io/ns/agents/sa/a1".into(),
                kid: "o1".into(),
                sig_b64: String::new(),
            },
        );
        let mut p = ExternalityProfile::new();
        p.insert(ResourceDim::GpuSeconds, claim);
        p
    }

    fn opening(value: u64, nonce: u8) -> BidOpening {
        BidOpening {
            agent_spiffe_id: "spiffe://nucleus.io/ns/agents/sa/alice".into(),
            auction_id: "a1".into(),
            effective_value_micro_usd: value,
            externality_profile: Some(mk_profile(1_000_000)),
            nonce: [nonce; 32],
        }
    }

    // (a) Distinctness + no-plaintext-leak. NOTE: this is NOT a test of
    // cryptographic (IND-CPA) hiding — that is an argued property resting
    // on SHA-256 + the 32-byte CSPRNG nonce and is not unit-testable. What
    // we assert here is the weaker, deterministic consequence: different
    // value and/or different nonce produce distinct commitments, and the
    // digest embeds no literal plaintext-value bytes (it is a hash, not an
    // encoding). The load-bearing secret for actual hiding is the nonce.
    #[test]
    fn commitment_is_distinct_and_leaks_no_plaintext_bytes() {
        let c_lo = compute_commitment(1, &opening(100_000, 1));
        let c_hi = compute_commitment(1, &opening(900_000, 1));
        // Different values → different commitments (no value leak you
        // could read off directly; you'd have to brute-force value AND
        // 256-bit nonce).
        assert_ne!(c_lo, c_hi);

        // Same value, different nonce → different commitment (hiding
        // across the random coin).
        let c_a = compute_commitment(1, &opening(500_000, 1));
        let c_b = compute_commitment(1, &opening(500_000, 2));
        assert_ne!(c_a, c_b);

        // The commitment bytes contain no plaintext substring of the
        // value's LE encoding (sanity: it is a hash, not an encoding).
        let v: u64 = 500_000;
        assert!(
            !c_a.0.windows(8).any(|w| w == v.to_le_bytes()),
            "commitment must not embed the plaintext value bytes"
        );
    }

    // Commit/reveal round-trips: a faithful opening verifies and yields
    // the expected IntegerBid.
    #[test]
    fn faithful_reveal_verifies() {
        let o = opening(750_000, 9);
        let c = compute_commitment(7, &o);
        let bid = verify_reveal(7, "a1", &c, &o).expect("faithful reveal verifies");
        assert_eq!(bid.bidder, o.agent_spiffe_id);
        assert_eq!(bid.proposal_id, "a1");
        assert_eq!(bid.effective_value_micro_usd, 750_000);
    }

    // (b) A MISMATCHED reveal is rejected — tampering with any committed
    // field (value, nonce, profile, identity, chain) breaks the seal.
    #[test]
    fn mismatched_reveal_is_rejected_on_value() {
        let o = opening(750_000, 9);
        let c = compute_commitment(7, &o);
        let mut tampered = o.clone();
        tampered.effective_value_micro_usd = 750_001; // raise the bid post-hoc
        let err = verify_reveal(7, "a1", &c, &tampered).unwrap_err();
        assert!(matches!(err, SealedBidError::CommitmentMismatch { .. }));
    }

    #[test]
    fn mismatched_reveal_is_rejected_on_nonce() {
        let o = opening(750_000, 9);
        let c = compute_commitment(7, &o);
        let mut tampered = o.clone();
        tampered.nonce = [10u8; 32];
        let err = verify_reveal(7, "a1", &c, &tampered).unwrap_err();
        assert!(matches!(err, SealedBidError::CommitmentMismatch { .. }));
    }

    #[test]
    fn mismatched_reveal_is_rejected_on_profile() {
        let o = opening(750_000, 9);
        let c = compute_commitment(7, &o);
        let mut tampered = o.clone();
        tampered.externality_profile = Some(mk_profile(2_000_000)); // bigger ext claim
        let err = verify_reveal(7, "a1", &c, &tampered).unwrap_err();
        assert!(matches!(err, SealedBidError::CommitmentMismatch { .. }));
    }

    #[test]
    fn mismatched_reveal_is_rejected_on_identity() {
        let o = opening(750_000, 9);
        let c = compute_commitment(7, &o);
        let mut tampered = o.clone();
        // Swap the bidder identity after committing. agent_spiffe_id is
        // length-prefixed into the commitment hash (sealed.rs:161), so the
        // recomputation must not match — a bidder cannot re-attribute a
        // sealed bid to a different identity.
        tampered.agent_spiffe_id = "spiffe://nucleus.io/ns/agents/sa/mallory".into();
        let err = verify_reveal(7, "a1", &c, &tampered).unwrap_err();
        assert!(matches!(err, SealedBidError::CommitmentMismatch { .. }));
    }

    #[test]
    fn cross_chain_replay_is_rejected() {
        let o = opening(750_000, 9);
        let c_chain1 = compute_commitment(1, &o);
        // Same opening, different chain → recomputation under chain 2
        // does not match a chain-1 commitment.
        let err = verify_reveal(2, "a1", &c_chain1, &o).unwrap_err();
        assert!(matches!(err, SealedBidError::CommitmentMismatch { .. }));
    }

    #[test]
    fn cross_auction_reveal_is_rejected_early() {
        let o = opening(750_000, 9);
        let c = compute_commitment(7, &o);
        // Verifier is clearing a different auction.
        let err = verify_reveal(7, "a2", &c, &o).unwrap_err();
        assert!(matches!(err, SealedBidError::AuctionIdMismatch { .. }));
    }

    #[test]
    fn commitment_hex_roundtrips() {
        let c = compute_commitment(1, &opening(123, 4));
        let s = c.to_hex();
        assert_eq!(s.len(), 64);
        assert_eq!(BidCommitment::from_hex(&s).unwrap(), c);
        assert_eq!(
            BidCommitment::from_hex("not-hex"),
            Err(SealedBidError::MalformedCommitmentHex)
        );
    }

    // None-profile commits the canonical empty profile and round-trips.
    #[test]
    fn none_profile_commits_empty_and_verifies() {
        let o = BidOpening {
            agent_spiffe_id: "spiffe://nucleus.io/ns/agents/sa/bob".into(),
            auction_id: "a1".into(),
            effective_value_micro_usd: 42,
            externality_profile: None,
            nonce: [3u8; 32],
        };
        let c = compute_commitment(1, &o);
        let bid = verify_reveal(1, "a1", &c, &o).unwrap();
        assert_eq!(bid.effective_value_micro_usd, 42);
    }

    // ── Commitment SET (the OMIT defence) ──────────────────────────────

    fn ack_opening(spiffe: &str, value: u64, nonce: u8) -> BidOpening {
        BidOpening {
            agent_spiffe_id: spiffe.into(),
            auction_id: "a1".into(),
            effective_value_micro_usd: value,
            externality_profile: None,
            nonce: [nonce; 32],
        }
    }

    fn three_commitments() -> Vec<BidCommitment> {
        vec![
            compute_commitment(9, &ack_opening("spiffe://x/alice", 1_000_000, 1)),
            compute_commitment(9, &ack_opening("spiffe://x/bob", 600_000, 2)),
            compute_commitment(9, &ack_opening("spiffe://x/carol", 400_000, 3)),
        ]
    }

    #[test]
    fn set_root_is_order_independent() {
        let cs = three_commitments();
        let mut reordered = cs.clone();
        reordered.reverse();
        let r1 = compute_commitment_set_root(9, "a1", &cs);
        let r2 = compute_commitment_set_root(9, "a1", &reordered);
        assert_eq!(
            r1, r2,
            "the set root must commit to the multiset, not the order"
        );
    }

    #[test]
    fn omitting_a_commitment_changes_the_root() {
        let cs = three_commitments();
        let full = compute_commitment_set_root(9, "a1", &cs);
        // Auctioneer drops carol (the would-be 2nd-price-setter, say).
        let dropped: Vec<_> = cs[..2].to_vec();
        let omitted = compute_commitment_set_root(9, "a1", &dropped);
        assert_ne!(full, omitted, "dropping a bid MUST move the published root");
    }

    #[test]
    fn adding_an_extra_commitment_changes_the_root() {
        let cs = three_commitments();
        let full = compute_commitment_set_root(9, "a1", &cs);
        let mut padded = cs.clone();
        // A shill commitment the auctioneer slips in.
        padded.push(compute_commitment(
            9,
            &ack_opening("spiffe://x/shill", 999, 9),
        ));
        let extended = compute_commitment_set_root(9, "a1", &padded);
        assert_ne!(full, extended, "injecting an extra bid MUST move the root");
    }

    #[test]
    fn set_root_binds_chain_and_auction_context() {
        let cs = three_commitments();
        let base = compute_commitment_set_root(9, "a1", &cs);
        assert_ne!(
            base,
            compute_commitment_set_root(10, "a1", &cs),
            "chain-bound"
        );
        assert_ne!(
            base,
            compute_commitment_set_root(9, "a2", &cs),
            "auction-bound"
        );
    }

    #[test]
    fn count_prefix_prevents_prefix_collision() {
        // {c0} must not collide with {c0, c1}: a 1-element set is not a
        // prefix of a 2-element set because the count is length-prefixed.
        let cs = three_commitments();
        let one = compute_commitment_set_root(9, "a1", &cs[..1]);
        let two = compute_commitment_set_root(9, "a1", &cs[..2]);
        assert_ne!(one, two);
    }

    #[test]
    fn honest_bidder_ack_audits_as_included() {
        let cs = three_commitments();
        let root = compute_commitment_set_root(9, "a1", &cs);
        let ack = CommitAck {
            chain_id: 9,
            auction_id: "a1".into(),
            commitment: cs[1], // bob's
            set_root: root,
        };
        // Hub publishes the full set at reveal-close.
        assert_eq!(audit_commit_ack(&ack, &cs), OmissionAudit::Included);
    }

    #[test]
    fn omitted_bidder_can_prove_omission() {
        let cs = three_commitments();
        // The hub COMMITTED to the full set on-chain (the ACK root)…
        let committed_root = compute_commitment_set_root(9, "a1", &cs);
        let carol_ack = CommitAck {
            chain_id: 9,
            auction_id: "a1".into(),
            commitment: cs[2], // carol's
            set_root: committed_root,
        };
        // …but at reveal-close it publishes a set WITHOUT carol. Because
        // the published set no longer re-derives to the committed root,
        // the audit catches the swap as a RootMismatch (the on-chain
        // anchor pins the hub to the complete set).
        let dropped: Vec<_> = cs[..2].to_vec();
        assert_eq!(
            audit_commit_ack(&carol_ack, &dropped),
            OmissionAudit::RootMismatch,
            "a set that omits an accepted bid cannot re-derive the anchored root"
        );
    }

    #[test]
    fn omission_within_a_consistent_root_is_caught_as_omitted() {
        // The pure `Omitted` branch: the ACK's root matches the published
        // set (so the hub did NOT swap the set), yet the bidder's own
        // commitment is absent. This models a bidder whose ACK referenced
        // a root the hub then honoured for everyone else but the bidder's
        // commitment was never actually in it — directly provable.
        let cs = three_commitments();
        let published = cs[..2].to_vec(); // alice + bob only
        let published_root = compute_commitment_set_root(9, "a1", &published);
        let carol_ack = CommitAck {
            chain_id: 9,
            auction_id: "a1".into(),
            commitment: cs[2], // carol — not in `published`
            set_root: published_root,
        };
        assert_eq!(
            audit_commit_ack(&carol_ack, &published),
            OmissionAudit::Omitted
        );
    }

    #[test]
    fn set_root_hex_roundtrips() {
        let r = compute_commitment_set_root(1, "a1", &three_commitments());
        let s = r.to_hex();
        assert_eq!(s.len(), 64);
        assert_eq!(CommitmentSetRoot::from_hex(&s).unwrap(), r);
        assert_eq!(
            CommitmentSetRoot::from_hex("zzz"),
            Err(SealedBidError::MalformedCommitmentHex)
        );
    }

    #[test]
    fn empty_set_has_a_well_defined_root() {
        let r = compute_commitment_set_root(1, "a1", &[]);
        // Distinct from a 1-element set (count prefix differs).
        let one = compute_commitment_set_root(1, "a1", &three_commitments()[..1]);
        assert_ne!(r, one);
    }
}

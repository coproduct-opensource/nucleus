//! Time-lock encryption integration **SEAM** for anti-grief sealed bids
//! (Bet A — SPIKE, NOT shipped crypto).
//!
//! # Why this exists (the gap commit-reveal leaves open)
//!
//! Plain commit-reveal ([`crate::sealed`]) is binding + hiding, but a
//! bidder can still **grief by not revealing**: after seeing the commit
//! set (or guessing the outcome), a bidder withholds their opening,
//! denying the auctioneer information and skewing the clearing. The two
//! standard mitigations are:
//!
//! 1. **Deposit + slashing** — economically punishing non-reveal. We
//!    explicitly do NOT take this path: it needs custody of a stake,
//!    which drags in MTL/BitLicense custody questions the project is
//!    avoiding (non-custodial mandate).
//! 2. **Delayed-execution / threshold time-lock encryption (tlock)** —
//!    bids are encrypted *to a future time*, not to the auctioneer.
//!    After a public threshold-BLS beacon (drand `quicknet`) publishes
//!    the round signature, **anyone** can decrypt **every** bid. A
//!    non-revealing bidder cannot grief because the auctioneer (or any
//!    peer) decrypts on their behalf. This is the integrate-don't-invent
//!    path and the one this seam targets.
//!
//! # HONEST STATUS: this is a SEAM + design, NOT working crypto
//!
//! The types below define the *interface* a real tlock backend must
//! satisfy. There is **no threshold-BLS, no IBE, no drand client** in
//! this crate — wiring real `tlock` (and its `arkworks`/BLS12-381
//! transitive deps) is incompatible with this crate's pure,
//! integer-only, wasm-safe, float-banned discipline and is deferred to a
//! sibling `nucleus-tlock` crate (see `docs/SEALED-BIDS-DESIGN.md`). The
//! [`StubBeacon`] backend here is a TEST DOUBLE that performs NO real
//! encryption; every method that would need cryptography returns
//! [`TlockError::NotImplemented`] and the only runnable test is
//! `#[ignore]`d. Do not represent this module as providing
//! confidentiality.

use serde::{Deserialize, Serialize};

/// Identifies a drand round the ciphertext is locked to. With drand
/// `quicknet` (3s period) the round number maps deterministically to a
/// wall-clock unlock time; the auctioneer sets the reveal deadline by
/// choosing the round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrandRound(pub u64);

/// A time-lock-encrypted bid opening. Opaque ciphertext bytes plus the
/// round they unlock at. In a real backend the plaintext is the
/// serialized [`crate::sealed::BidOpening`]; here it is never produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelockedBid {
    /// drand round whose beacon signature decrypts this ciphertext.
    pub unlock_round: DrandRound,
    /// Opaque ciphertext (age-armored tlock blob in a real backend).
    pub ciphertext: Vec<u8>,
}

/// Errors from the tlock seam.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TlockError {
    /// The operation requires real threshold-encryption that this seam
    /// does not implement. See `docs/SEALED-BIDS-DESIGN.md`.
    #[error("tlock backend not implemented (SPIKE seam); use a real nucleus-tlock backend")]
    NotImplemented,
    /// The requested round has not yet been reached on the beacon (its
    /// signature is not yet public), so decryption cannot proceed.
    #[error("round {0} not yet available on the beacon")]
    RoundNotYetAvailable(u64),
}

/// The contract a real time-lock backend must satisfy to plug into the
/// sealed-bid lifecycle. Defining it here lets the hub depend on the
/// SEAM (this trait) rather than on any particular crypto, so the real
/// `nucleus-tlock` crate can land later without touching call sites.
///
/// ## Proof obligations a real implementor MUST discharge
///
/// - **PO-1 (correctness):** for all `round`, `opening`,
///   `decrypt(encrypt(opening, round), beacon(round)) == opening`.
/// - **PO-2 (timed hiding):** before `beacon(round)` is public, the
///   ciphertext is IND-CPA-hiding (reduces to drand threshold-BLS
///   unforgeability + the IBE security of the tlock scheme).
/// - **PO-3 (public openability / anti-grief):** once `beacon(round)`
///   is public, ANY party — not just the bidder — can `decrypt`. This
///   is the property that defeats the non-reveal grief attack and the
///   reason this beats deposit/slashing for a non-custodial design.
/// - **PO-4 (binding cross-check):** the decrypted [`BidOpening`] is
///   still fed through [`crate::sealed::verify_reveal`], so tlock
///   provides *availability of the opening*, while the SHA-256
///   commitment continues to provide *binding*. The two layers compose;
///   neither replaces the other.
pub trait TimelockBackend {
    /// Encrypt an already-serialized opening to a future `round`.
    fn encrypt(&self, plaintext: &[u8], round: DrandRound) -> Result<TimelockedBid, TlockError>;

    /// Decrypt once the round's beacon signature is public. In a real
    /// backend the signature is fetched from a drand HTTP relay; the
    /// SEAM keeps that out of the pure crate.
    fn decrypt(&self, blob: &TimelockedBid) -> Result<Vec<u8>, TlockError>;
}

/// A NON-CRYPTOGRAPHIC test double. It records the round and stores the
/// plaintext verbatim so lifecycle wiring can be exercised in tests, but
/// it provides ZERO confidentiality and both methods of the "real" path
/// deliberately surface [`TlockError::NotImplemented`] to make the gap
/// impossible to ship by accident.
#[derive(Debug, Default, Clone)]
pub struct StubBeacon;

impl TimelockBackend for StubBeacon {
    fn encrypt(&self, _plaintext: &[u8], _round: DrandRound) -> Result<TimelockedBid, TlockError> {
        // A real backend would IBE-encrypt to the round's public key.
        Err(TlockError::NotImplemented)
    }

    fn decrypt(&self, _blob: &TimelockedBid) -> Result<Vec<u8>, TlockError> {
        Err(TlockError::NotImplemented)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The SEAM is wired but intentionally unimplemented. This test
    // documents that the stub refuses to pretend it has crypto.
    #[test]
    fn stub_refuses_to_fake_crypto() {
        let b = StubBeacon;
        assert_eq!(
            b.encrypt(b"opening", DrandRound(1000)),
            Err(TlockError::NotImplemented)
        );
        assert_eq!(
            b.decrypt(&TimelockedBid {
                unlock_round: DrandRound(1000),
                ciphertext: vec![]
            }),
            Err(TlockError::NotImplemented)
        );
    }

    // A placeholder for the REAL round-trip a `nucleus-tlock` backend
    // must pass (PO-1). Ignored because no real backend exists in this
    // crate; it exists to pin the expected shape and fail loudly if
    // someone wires a backend without satisfying correctness.
    #[test]
    #[ignore = "SPIKE: requires a real threshold-BLS/tlock backend (nucleus-tlock); not in this pure crate"]
    fn real_backend_roundtrips_po1() {
        // let backend = RealDrandTlock::quicknet();
        // let blob = backend.encrypt(b"opening", DrandRound(...)).unwrap();
        // ... wait for round ...
        // assert_eq!(backend.decrypt(&blob).unwrap(), b"opening");
        unreachable!("no real backend in the pure econ-kernels crate");
    }
}

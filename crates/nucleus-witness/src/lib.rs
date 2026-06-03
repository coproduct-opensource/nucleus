//! `nucleus-witness` — a [C2SP `tlog-witness`] server that mints Ed25519
//! cosignatures over checkpoints, enforcing the spec status matrix.
//!
//! # What this is
//!
//! A witness is the "second pair of eyes" in a transparency log: it
//! cosigns a log's checkpoint only after checking that the new checkpoint
//! (a) is signed by a trusted log key, (b) extends the last checkpoint
//! the witness cosigned (RFC 6962 consistency proof), and (c) is not a
//! rollback to a smaller/different tree. A verifier that requires a
//! k-of-n witness quorum (see [`nucleus_lineage::policy`]) then cannot be
//! shown a forged or rolled-back log unless the attacker compromises a
//! threshold of witnesses across independent failure domains.
//!
//! # Single-tenant split-trust (the deployment model)
//!
//! This crate is built for **one operator running their own k-of-n
//! witnesses** across diverse regions / clouds / HSMs — NOT for
//! federating with other organizations. The value is **failure-domain
//! diversity**: no single region outage, cloud-account compromise, or
//! key-store breach can forge or roll back your log, because a quorum of
//! independently-hosted witnesses must each cosign. You get
//! transparency-log integrity without depending on a volunteer witness
//! commons.
//!
//! # Dormant metering seam (documented, NOT implemented)
//!
//! A valid cosignature over a real checkpoint is a unit of *proven
//! work* — the natural meter point for a future **parallel paid tier**:
//! priced by VCG/Pigou and settled over x402 / L402. That tier would
//! meter ONLY proven cosignatures, never the volunteer commons (Tor's
//! lesson: run a paid lane in parallel, don't tax the free one). None of
//! that billing logic exists in this crate today — this is a forward
//! note so the seam isn't designed shut.
//!
//! C2SP itself flags **witness sustainability / funding as an unsolved
//! open problem**; the paid-tier seam above is one possible answer, not
//! a settled one.
//!
//! # Crypto reuse
//!
//! This crate reinvents NO cryptography. It builds on
//! [`nucleus_lineage`]'s signed-note primitives (signature-line
//! parse/format, key-ID derivation, checkpoint-body bytes) and on
//! `ct-merkle` for RFC 6962 consistency verification. The only net-new
//! logic is the C2SP status matrix ([`server::decide`]) and the
//! cosignature/v1 message framing ([`cosign::WitnessKey`]).
//!
//! [C2SP `tlog-witness`]: https://c2sp.org/tlog-witness

pub mod app;
pub mod cosign;
pub mod parse;
pub mod server;
pub mod store;

pub use cosign::{verify_cosign_line, CosignVerifyError, WitnessKey};
pub use parse::{parse_add_checkpoint, AddCheckpointRequest, Checkpoint, ParseError};
pub use server::{add_checkpoint_handler, decide, Decision, WitnessState};
pub use store::{CosignedPosition, InMemoryStore, OriginRecord, OriginStore, TrustedLogKey};

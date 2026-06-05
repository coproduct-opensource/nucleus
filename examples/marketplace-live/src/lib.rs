//! REAL Base Sepolia (testnet) settlement for the nucleus marketplace dashboard.
//!
//! Building blocks, shared by the binary and the no-funds integration tests:
//! - [`signer`] — load a `PrivateKeySigner` from an encrypted keystore with a
//!   securely-resolved password (never on argv).
//! - [`facilitator`] — [`X402Facilitator`]: real x402 settle + tx-hash decode +
//!   real `balanceOf`, implementing `nucleus_marketplace_dashboard::Facilitator`.
//! - [`seller`] — the local x402 seller route (with the IFC pre-gate) the
//!   facilitator pays.

pub mod facilitator;
pub mod seller;
pub mod signer;

pub use facilitator::{decode_settlement, X402Facilitator};
pub use seller::seller_router;
pub use signer::{load_keystore_signer, resolve_keystore_password, PasswordSource};

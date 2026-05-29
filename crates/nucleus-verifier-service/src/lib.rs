//! Public verifier-as-a-service for nucleus provenance bundles.
//!
//! Stateless HTTPS endpoint. Anyone (customer, regulator, third party)
//! can POST a bundle plus the trust anchor they intend to verify
//! against; the service runs `nucleus_envelope::verify_bundle` and
//! returns a structured report.
//!
//! # What this service does NOT do
//!
//! - **It does not store anything by default.** No bundles, no logs of
//!   what was verified, no rate-limit history. Adding append-only
//!   verification logs is a deliberate v2 surface.
//! - **It does not impose its own trust opinions.** Callers MUST
//!   supply the JWKS they intend to verify against (or explicitly opt
//!   into self-check mode). The service is a neutral compute
//!   primitive, not a trust authority.
//! - **It does not fetch trust anchors over the network.** A future
//!   `trust_jwks_url` field would introduce SSRF surface — deferred
//!   until we have a hardening story.
//!
//! # Wire contract
//!
//! `POST /v1/verify`
//!
//! ```json
//! {
//!   "bundle": <Bundle JSON>,
//!   "trust_jwks": <JWKS JSON>,    // optional — without it, self-check mode
//!   "allow_empty": false           // optional, default false
//! }
//! ```
//!
//! Returns 200 with `{ok: true, report: ...}` on successful
//! verification, or a 4xx with `{ok: false, error: "...", message: "..."}`
//! on any failure.

pub mod app;
pub mod db;
pub mod error;
pub mod log;
pub mod merkle;
pub mod retention;
pub mod routes;
pub mod signing;
pub mod witness;

pub use app::{build_app, with_rate_limit};
pub use db::{connect_and_migrate, connect_and_migrate_path, VerificationRecord};
pub use error::VerifyApiError;
pub use log::{
    append_entry as log_append_entry, current_sth as log_current_sth, log_size, UnsignedTreeHead,
};
pub use signing::{canonical_sth_bytes, VerifierSigner};

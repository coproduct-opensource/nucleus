//! The environment-name → material-kind classifier — the trusted map FM-5's
//! completeness argument rests on, colocated with the extracted oracle it feeds.
//!
//! Moved here from `nucleus-tool-proxy/src/workload.rs` (which re-exports it, so
//! the launch builder's behaviour is unchanged) for two reasons:
//!
//! 1. **One roof.** `ident_may_deliver` (extracted, proven) decides delivery for
//!    a `MaterialKind`; this classifier decides which `MaterialKind` an env name
//!    IS. Splitting them across crates left the classifier in the spawn crate
//!    while its meaning lived here. The pair is the whole judgment.
//! 2. **The conformance harness.** The boot gate's delivery-conformance step
//!    (`nucleus-delivery-conformance`) replays the in-guest probe's observed
//!    environment inventory through classifier + oracle. It must use THIS
//!    function — a restated table would be a second copy that drifts.
//!
//! This module is NOT part of the Aeneas-translated slice set (string matching
//! is opaque to Aeneas — the `_ => OrdinaryData` fallthrough is the known,
//! fundamental residual; see the FM-5 row in `docs/production-delta.md`). It
//! lives beside `extracted/`, not inside it.

use crate::extracted::identity::MaterialKind;

/// Classify an environment variable name as the identity material it carries.
///
/// The `_ => OrdinaryData` fallthrough is the one place a NEW secret hides: a
/// `NUCLEUS_*` variable added to the overlay without a case here would be
/// classified public and admitted. The corpus test in
/// `nucleus-tool-proxy/src/workload.rs` enumerates the `NUCLEUS_*` namespace
/// against an independently-written oracle to catch exactly that.
pub fn env_key_material(key: &str) -> MaterialKind {
    match key {
        "NUCLEUS_IDENTITY_CERT" => MaterialKind::SvidCert,
        "NUCLEUS_TASK_TOKEN" | "NUCLEUS_TASK_TOKEN_NONCE" | "NUCLEUS_TASK_TOKEN_ISSUER" => {
            MaterialKind::TaskToken
        }
        "NUCLEUS_TOOL_PROXY_BROKER_SECRET" | "NUCLEUS_TOOL_PROXY_BROKER_PORT" => {
            MaterialKind::BrokerSecret
        }
        "NUCLEUS_TOOL_PROXY_APPROVAL_SECRET" => MaterialKind::ApprovalSecret,
        "NUCLEUS_SANDBOX_TOKEN" => MaterialKind::SandboxToken,
        "NUCLEUS_TOOL_PROXY_AUTH_SECRET" => MaterialKind::ProxyAuthSecret,
        k if k.starts_with("NUCLEUS_DLC_") => MaterialKind::DlcCredentials,
        k if k.starts_with("NUCLEUS_EGRESS_") => MaterialKind::EgressEnv,
        _ => MaterialKind::OrdinaryData,
    }
}

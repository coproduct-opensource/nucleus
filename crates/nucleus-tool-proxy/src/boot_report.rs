//! The first audit entry a pod writes, and why it is on a deadline.

use std::time::Duration;

use tracing::warn;

use crate::AuditEntry;
use crate::{ApiError, AppState, now_unix};

/// [`emit_boot_report`] under a deadline, because the audit log anchors every
/// entry to the drand beacon and a pod cannot reach it.
///
/// MEASURED, on an M5 Pro via Lima -> KVM -> Firecracker: this single call was
/// **5044 ms of a 5497 ms tool-proxy startup — 92%**. `AuditLog::log` fills
/// `drand_round` by fetching `https://api.drand.sh/public/latest` with a 5 s
/// timeout (`nucleus_client::drand`, `.timeout(Duration::from_secs(5))`), and a
/// pod runs under default-deny egress, so the fetch cannot succeed. Every pod
/// paid a five-second timeout for a network round trip its own network policy
/// forbids, before it would serve a single request.
///
/// The deadline is 250 ms: long enough for a beacon that is genuinely reachable
/// (an operator who allows the drand host in `dns_allow`), far short of the
/// doomed case. On expiry the boot entry is still written — the chain must not
/// gain a hole — just without an anchor it was never going to get.
///
/// This does not weaken approvals. Anchoring exists to stop pre-computation of
/// approval signatures, `/v1/approve` validates its own round, and
/// `DrandFailMode::Strict` still refuses an approval when the beacon is absent.
/// What changes is that the refusal is no longer paid at boot by every pod.
pub(crate) async fn emit_boot_report_bounded(state: &AppState) -> Result<(), ApiError> {
    match tokio::time::timeout(Duration::from_millis(250), emit_boot_report(state)).await {
        Ok(res) => res,
        Err(_) => {
            warn!(
                "boot report exceeded its 250ms deadline (drand unreachable under \
                 default-deny egress); serving without a beacon-anchored boot entry"
            );
            Ok(())
        }
    }
}

async fn emit_boot_report(state: &AppState) -> Result<(), ApiError> {
    // Always emit boot report — this is the first entry in the audit chain.
    // Optional env var adds a custom message; otherwise use a default.
    let message = std::env::var("NUCLEUS_TOOL_PROXY_BOOT_REPORT")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "tool-proxy started".to_string());
    let actor = std::env::var("NUCLEUS_TOOL_PROXY_BOOT_ACTOR").ok();
    let report = format!(
        "{} [sandbox_proof={}]",
        message,
        state.sandbox_proof.tier_label()
    );

    state
        .audit
        .log(AuditEntry {
            timestamp_unix: now_unix(),
            actor,
            event: "boot".to_string(),
            subject: report,
            result: "ok".to_string(),
            prev_hash: String::new(),
            hash: String::new(),
            signature: String::new(),
            drand_round: None, // Will be filled by AuditLog::log
            spiffe_id: None,
            policy_rule: None,
        })
        .await?;

    Ok(())
}

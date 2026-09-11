//! The escalation proposal a denial carries with it.
//!
//! Every rejection has four questions behind it: what did the agent try, why
//! exactly was it stopped, what is the *minimum* authority that would have
//! allowed it, and what new risk would granting that create.
//! `portcullis::escalation_proposal` has answered all four since ADR 0004
//! milestone 4 — and only after a run had ended, at the CLI, by re-parsing a
//! trace file off disk. The agent that was actually denied got a sentence, and
//! the person watching got the affordance when it was too late to use.
//!
//! This is the missing half: the proposal built at the moment of denial, from
//! state the proxy already holds, and attached to the refusal itself.
//!
//! # Why the agent is told
//!
//! The proposal names the least authority that would have allowed the call, so
//! carrying it to the agent tells an untrusted party something about the shape
//! of the boundary. That is a considered position, not an oversight, and it is
//! the opposite of the one taken at the federation token endpoint (#2756),
//! where a requested scope is refused with a bare `invalid_target` precisely so
//! a caller cannot enumerate the ceiling.
//!
//! The difference is the trust position. A remote workload asking for a token
//! is *outside*, and its authority is the question being decided. The agent
//! here is *inside* the boundary and already holds the certificate that lists
//! its own grant — it can enumerate what it has without asking us. Telling it
//! what it would need is therefore not a disclosure, and the effect gate has
//! done exactly this for some time (`EFFECT_NOT_GRANTED … would be admitted by
//! github/open-pr`).
//!
//! If those two ever need reconciling, reconcile them *apart*: the rule is
//! about who is asking, not about which endpoint they reached.

use portcullis::escalation_proposal::EscalationProposal;
use portcullis::kernel::DenyReason;
use portcullis::task_grant::TaskGrant;
use portcullis::{EffectCatalog, Operation, PermissionLattice, WeakeningCostConfig};

/// What a proposal needs beyond the denial itself, resolved once at boot.
///
/// Absent when the pod was not launched under a sealed grant, which is the
/// common case for a profile run — and then denials read exactly as they did
/// before. This can make a refusal more informative; it can never make one
/// allow.
pub(crate) struct ProposalContext {
    grant: TaskGrant,
    ceiling: PermissionLattice,
    catalog: EffectCatalog,
    cost: WeakeningCostConfig,
}

impl ProposalContext {
    /// Resolve from a verified grant.
    ///
    /// The ceiling is looked up by the name the grant records. A grant sealed
    /// against a profile this build does not ship still yields proposals — the
    /// ceiling then falls back to the grant's own lattice, which makes
    /// `outside_ceiling` unreachable and every other answer unchanged. Better
    /// a proposal that cannot say "that is outside your ceiling" than no
    /// proposal at all.
    pub(crate) fn new(grant: TaskGrant, catalog: EffectCatalog) -> Self {
        let ceiling = portcullis::profile::ProfileRegistry::default()
            .resolve(&grant.ceiling_profile)
            .unwrap_or_else(|_| grant.lattice.clone());
        Self {
            grant,
            ceiling,
            catalog,
            cost: WeakeningCostConfig::default(),
        }
    }

    /// The proposal for one denial.
    pub(crate) fn propose(
        &self,
        operation: Operation,
        subject: &str,
        reason: &DenyReason,
    ) -> EscalationProposal {
        portcullis::propose_escalation(
            &self.grant,
            &self.ceiling,
            &self.catalog,
            &self.cost,
            operation,
            subject,
            reason,
        )
    }
}

/// Read a sealed grant from `path` and verify it against the pinned root.
///
/// The same root the pod certificate is checked against, and for the same
/// reason: a sealed grant carries the key it was signed with, so verifying it
/// against that key proves only that whoever wrote the file was consistent
/// with themselves. Without a pinned root there is nothing to check against
/// and the grant is refused.
///
/// The repository digest is deliberately NOT checked here. The proxy runs
/// inside the pod, where the repository the grant was compiled against may not
/// be present at the same path; the binding that matters for enforcement is
/// the certificate, which is verified at boot and is what actually bounds the
/// pod. This grant is used only to explain a refusal.
pub(crate) fn load(
    path: &std::path::Path,
    root_pubkey_hex: Option<&str>,
) -> Result<ProposalContext, String> {
    let Some(hex_key) = root_pubkey_hex else {
        return Err("no --cert-root-pubkey to verify the grant against".to_string());
    };
    let root = decode_hex(hex_key)?;
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let sealed: portcullis::sealed_grant::SealedTaskGrant =
        serde_json::from_str(&text).map_err(|e| format!("parsing the sealed grant: {e}"))?;
    let verified = sealed
        .verify(chrono::Utc::now(), std::slice::from_ref(&root), None)
        .map_err(|e| format!("verifying the sealed grant: {e:?}"))?;
    let catalog = load_catalog();
    Ok(ProposalContext::new(verified.grant().clone(), catalog))
}

/// The built-in catalog, extended by the pod's own `.nucleus/effects` when it
/// has one — the same vocabulary the effect gate admits requests against, so a
/// proposal cannot name an effect the gate would not recognise.
fn load_catalog() -> EffectCatalog {
    let mut catalog = EffectCatalog::builtin().unwrap_or_else(|_| EffectCatalog::empty());
    let _ = catalog.load_from_dir(std::path::Path::new(".nucleus/effects"));
    catalog
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err("root key hex has an odd number of digits".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("root key hex: {e}")))
        .collect()
}

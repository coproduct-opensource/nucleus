//! Information-flow monitor for the WASI boundary — a **floating-label** tracker
//! that turns the capability host into an IFC monitor.
//!
//! ## Why this exists
//!
//! Capabilities ([`world_of`](crate::world_of)) answer "*may* this component
//! touch the filesystem / network?". They say nothing about the **lethal
//! trifecta**: a component that legitimately reads a secret and then
//! legitimately makes a network call can exfiltrate it. The field has converged
//! on information-flow control as the fix (Microsoft Research's FIDES, DeepMind's
//! CaMeL, the dual-LLM pattern). This module is the substrate-level realization:
//! the same WASI import boundary that enforces capabilities also enforces
//! **information flow**, backed by `portcullis-core`'s Lean-verified
//! [`IFCLabel`] lattice.
//!
//! ## The model (floating label / Denning-style monitor)
//!
//! The guest is treated as an **opaque transformer** — once bytes enter its
//! linear memory the host cannot track them per-byte (that would need
//! interpreter instrumentation, the wrong layer). Instead the monitor keeps a
//! single *floating label* `pc` summarizing everything the component has read:
//!
//! - **Source reads** ([`stamp`](BoundaryMonitor::stamp)) join the source's
//!   label into `pc`. Reading adversarial web content drops `pc`'s integrity;
//!   reading a secret raises `pc`'s confidentiality. This is `IFCLabel::join`.
//! - **Sink calls** ([`check`](BoundaryMonitor::check)) test `pc.flows_to(req)`
//!   against the sink's requirement. This is the proven `IFCLabel::flows_to`.
//!
//! Two sink requirements encode FIDES's two policies:
//!
//! - [`trusted_action`] — a consequential local action (file write). Requires
//!   `Trusted` integrity + `Directive` authority: **untrusted/adversarial input
//!   cannot steer a privileged action**. Confidentiality is unconstrained (a
//!   local write does not exfiltrate).
//! - [`public_egress`] — an outbound network call. Requires `Public`
//!   confidentiality: **secret data cannot leave**. Integrity is unconstrained
//!   (we don't care about the trust of bytes going *out*, only their secrecy).
//!
//! ## Honest limitation: label creep
//!
//! Because the guest is opaque, the monitor is *coarse*: once `pc` is raised it
//! stays raised, so any later sink is checked against the high-water mark. A
//! component that reads a secret can never egress again **without
//! declassification** — the audited escape valve that `portcullis-core`'s
//! `declassify` module (and its Lean proofs) governs. This is the correct
//! conservative behavior, not a bug: it is exactly the floating-label tradeoff,
//! and it is *sound* (proven in `WasiIfcBoundary.lean`).

use portcullis_core::declassify::{DeclassificationRule, DeclassifyAction, DeclassifyResult};
use portcullis_core::{AuthorityLevel, ConfLevel, IFCLabel, IntegLevel};

// ═══════════════════════════════════════════════════════════════════════════
// The monitor
// ═══════════════════════════════════════════════════════════════════════════

/// A floating-label IFC monitor for one component instance.
///
/// `pc` starts at [`IFCLabel::bottom`] (the least-restrictive label: public,
/// trusted, full authority) — having read nothing, the component may perform
/// any action. Each [`stamp`](Self::stamp) can only *raise* `pc` (join is
/// monotone), so the monitor is conservative by construction.
#[derive(Debug, Clone, Copy)]
pub struct BoundaryMonitor {
    pc: IFCLabel,
}

impl Default for BoundaryMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl BoundaryMonitor {
    /// A fresh monitor with `pc = ⊥` (nothing read yet).
    pub fn new() -> Self {
        BoundaryMonitor {
            pc: IFCLabel::bottom(),
        }
    }

    /// The current floating label.
    pub fn pc(&self) -> IFCLabel {
        self.pc
    }

    /// Record that data labeled `source` has entered the component. Joins
    /// `source` into `pc` — the floating-label taint step. Monotone: `pc` never
    /// decreases.
    pub fn stamp(&mut self, source: IFCLabel) {
        self.pc = self.pc.join(source);
    }

    /// Test whether the component's accumulated context may flow to a sink with
    /// requirement `sink`. `Ok(())` iff `pc.flows_to(sink)`.
    pub fn check(&self, sink: IFCLabel) -> Result<(), IfcDenial> {
        if self.pc.flows_to(sink) {
            Ok(())
        } else {
            Err(IfcDenial { pc: self.pc, sink })
        }
    }

    /// Apply an **authorized** declassification rule to the floating label — the
    /// *sole* operation that may lower `pc` (every other transition only raises
    /// it). Returns the [`DeclassifyResult`] audit record: which rule ran, the
    /// before/after labels, and whether the precondition actually fired.
    ///
    /// This is the escape valve from label creep. It models FIDES's "quarantined
    /// summarizer" pattern: a trusted, attested component (whose authorization is
    /// represented by holding the `rule`) has produced sanitized output, so the
    /// policy permits a specific downgrade. The rule only fires when its
    /// precondition matches `pc` and it is a genuine downgrade; otherwise `pc` is
    /// unchanged and `applied` is `false`. Soundness — that this can only lower
    /// confidentiality, never launder integrity — is proven in
    /// `WasiIfcBoundary.lean` (`declassify_only_lowers_conf`,
    /// `declassify_preserves_block_on_integrity`).
    pub fn declassify(&mut self, rule: &DeclassificationRule) -> DeclassifyResult {
        let result = rule.apply(self.pc);
        self.pc = result.label;
        result
    }
}

/// A rejected flow: the component's context (`pc`) is not permitted to reach a
/// sink requiring `sink`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IfcDenial {
    /// The component's accumulated floating label at the point of the sink call.
    pub pc: IFCLabel,
    /// The sink's requirement that `pc` failed to satisfy.
    pub sink: IFCLabel,
}

impl std::fmt::Display for IfcDenial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IFC denial: context label {{conf={:?}, integ={:?}, auth={:?}}} \
             does not flow to sink requirement {{conf={:?}, integ={:?}, auth={:?}}}",
            self.pc.confidentiality,
            self.pc.integrity,
            self.pc.authority,
            self.sink.confidentiality,
            self.sink.integrity,
            self.sink.authority,
        )
    }
}

impl std::error::Error for IfcDenial {}

// ═══════════════════════════════════════════════════════════════════════════
// Sink requirements (FIDES policies)
// ═══════════════════════════════════════════════════════════════════════════
//
// Each is built from `IFCLabel::top()` — the fully-permissive sink target that
// `flows_to` always accepts — by *tightening only* the dimensions the policy
// cares about. Provenance and derivation are left at top (`0x3F` / OpaqueExternal)
// so they never bind; freshness is ignored by `flows_to`.

/// Requirement for a **consequential action** (e.g. a file write): the context
/// must be `Trusted` integrity and `Directive` authority. Enforces FIDES's
/// trusted-action policy — untrusted input cannot drive a privileged action.
pub fn trusted_action() -> IFCLabel {
    IFCLabel {
        integrity: IntegLevel::Trusted,
        authority: AuthorityLevel::Directive,
        ..IFCLabel::top()
    }
}

/// Requirement for **public egress** (an outbound network call): the context
/// must be `Public` confidentiality. Enforces FIDES's confidentiality policy —
/// secret data cannot be exfiltrated.
pub fn public_egress() -> IFCLabel {
    IFCLabel {
        confidentiality: ConfLevel::Public,
        ..IFCLabel::top()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Canonical source labels (for seeding / fixtures)
// ═══════════════════════════════════════════════════════════════════════════

/// Adversarial external content (web page, tool output): `Public`,
/// `Adversarial` integrity, `NoAuthority`. The indirect-prompt-injection source.
pub fn untrusted_content() -> IFCLabel {
    IFCLabel {
        integrity: IntegLevel::Adversarial,
        authority: AuthorityLevel::NoAuthority,
        ..IFCLabel::bottom()
    }
}

/// A local secret (credential, PII): `Secret` confidentiality, but `Trusted`
/// and `Directive` (it is our own data — trustworthy, just not for egress).
pub fn secret() -> IFCLabel {
    IFCLabel {
        confidentiality: ConfLevel::Secret,
        ..IFCLabel::bottom()
    }
}

/// Trusted, public, user-authorized data: `IFCLabel::bottom()` — flows to every
/// sink.
pub fn trusted_public() -> IFCLabel {
    IFCLabel::bottom()
}

// ═══════════════════════════════════════════════════════════════════════════
// Declassification rules (the audited escape valve)
// ═══════════════════════════════════════════════════════════════════════════

/// The canonical rule a verified summarizer is authorized to apply: lower
/// `Secret` confidentiality to `Public`. Fires only when `pc` is actually
/// `Secret`; leaves integrity/authority untouched (declassifying confidentiality
/// cannot make adversarial content trustworthy). Mirrors
/// `DeclassifyAction::LowerConfidentiality`.
pub fn sanitize_to_public() -> DeclassificationRule {
    DeclassificationRule {
        action: DeclassifyAction::LowerConfidentiality {
            from: ConfLevel::Secret,
            to: ConfLevel::Public,
        },
        justification: "verified summarizer produced a sanitized public summary",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_monitor_permits_every_sink() {
        let m = BoundaryMonitor::new();
        assert!(m.check(trusted_action()).is_ok());
        assert!(m.check(public_egress()).is_ok());
    }

    #[test]
    fn untrusted_read_blocks_trusted_action_but_allows_egress() {
        let mut m = BoundaryMonitor::new();
        m.stamp(untrusted_content());
        // Adversarial context cannot drive a consequential action…
        assert!(m.check(trusted_action()).is_err());
        // …but adversarial *public* content is fine to send out (it's not secret).
        assert!(m.check(public_egress()).is_ok());
    }

    #[test]
    fn secret_read_blocks_egress_but_allows_trusted_action() {
        let mut m = BoundaryMonitor::new();
        m.stamp(secret());
        // Secret context cannot be exfiltrated…
        assert!(m.check(public_egress()).is_err());
        // …but a secret is trusted, so it may drive a local action.
        assert!(m.check(trusted_action()).is_ok());
    }

    /// The lethal trifecta: untrusted content + private data + an egress vector.
    /// After ingesting both, egress is blocked on confidentiality.
    #[test]
    fn lethal_trifecta_egress_blocked() {
        let mut m = BoundaryMonitor::new();
        m.stamp(untrusted_content());
        m.stamp(secret());
        assert!(m.check(public_egress()).is_err());
        assert!(m.check(trusted_action()).is_err());
    }

    #[test]
    fn clean_context_flows_everywhere() {
        let mut m = BoundaryMonitor::new();
        m.stamp(trusted_public());
        assert!(m.check(trusted_action()).is_ok());
        assert!(m.check(public_egress()).is_ok());
    }

    /// `stamp` only raises `pc`: once a sink is denied, re-stamping cannot
    /// re-permit it (the label-creep / monotonicity property).
    #[test]
    fn denial_is_monotone() {
        let mut m = BoundaryMonitor::new();
        m.stamp(secret());
        assert!(m.check(public_egress()).is_err());
        // Reading more — even trusted-public data — cannot lower confidentiality.
        m.stamp(trusted_public());
        m.stamp(untrusted_content());
        assert!(m.check(public_egress()).is_err());
    }

    /// The denial carries the actual labels for repair/audit.
    #[test]
    fn denial_reports_labels() {
        let mut m = BoundaryMonitor::new();
        m.stamp(secret());
        let err = m.check(public_egress()).unwrap_err();
        assert_eq!(err.pc.confidentiality, ConfLevel::Secret);
        assert_eq!(err.sink.confidentiality, ConfLevel::Public);
    }

    /// An authorized declassification lowers `pc` and unblocks egress — and the
    /// audit record proves it happened.
    #[test]
    fn authorized_declassification_unblocks_egress() {
        let mut m = BoundaryMonitor::new();
        m.stamp(secret());
        assert!(m.check(public_egress()).is_err());

        let record = m.declassify(&sanitize_to_public());
        assert!(record.applied);
        assert_eq!(record.original.confidentiality, ConfLevel::Secret);
        assert_eq!(record.label.confidentiality, ConfLevel::Public);

        // Egress now permitted (via the explicit, audited downgrade).
        assert!(m.check(public_egress()).is_ok());
    }

    /// Declassifying confidentiality cannot launder integrity: after reading
    /// adversarial content, a trusted action stays blocked even post-declassify.
    #[test]
    fn declassification_does_not_fix_integrity() {
        let mut m = BoundaryMonitor::new();
        m.stamp(untrusted_content());
        m.stamp(secret());
        // Sanitize confidentiality…
        m.declassify(&sanitize_to_public());
        // …egress (confidentiality) is now ok…
        assert!(m.check(public_egress()).is_ok());
        // …but the trusted action (integrity) is still denied.
        assert!(m.check(trusted_action()).is_err());
    }

    /// The rule is a no-op when its precondition doesn't match (`pc` not Secret):
    /// no silent label changes, `applied` is `false`.
    #[test]
    fn declassification_noop_when_precondition_unmet() {
        let mut m = BoundaryMonitor::new();
        m.stamp(trusted_public()); // pc stays Public
        let before = m.pc();
        let record = m.declassify(&sanitize_to_public());
        assert!(!record.applied);
        assert_eq!(m.pc(), before);
    }
}

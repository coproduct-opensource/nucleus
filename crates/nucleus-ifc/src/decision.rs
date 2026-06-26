//! The model-level IFC **decision** over the inputs a call *declares* it will be
//! exposed to — the lethal-trifecta gate as a pure, deterministic function.
//!
//! This composes [`crate::FlowTracker`] (the same engine the rest of nucleus
//! uses) and turns a [`FlowDeclaration`] into an [`IfcVerdict`]. It is **homed
//! here** (rather than in `nucleus-verify-commerce`) precisely so it is
//! **wasm-safe and the single source of truth**: the `@nucleus/verify` recompute
//! SDK re-derives the verdict with the EXACT same code the production gate runs —
//! a recompute that can never drift from enforcement.
//!
//! # Honesty boundary
//!
//! A **model-level** decision over **declared** inputs — not an end-to-end proof
//! that exfiltration cannot happen. Coverage is the limit: an input the caller
//! never declares is one the lattice never sees, so [`IfcVerdict`] carries the
//! declared set verbatim for a verifier to judge coverage. Per-call (no
//! cross-session taint ratchet). Fails closed.

use crate::{FlowTracker, NodeKind};
use portcullis_core::ConfLevel;
use serde::{Deserialize, Serialize};

/// One declared data-flow input a call will be exposed to. The caller declares
/// every input; the gate maps each to its IFC lattice node kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeclaredInput {
    /// Trusted, directive user prompt.
    UserPrompt,
    /// Adversarial public web content (indirect prompt-injection vector).
    WebContent,
    /// Untrusted MCP / tool response.
    ToolResponse,
    /// Private file contents.
    FileRead,
    /// An environment variable (potentially secret).
    EnvVar,
    /// A credential / API key.
    Secret,
    /// A row from a local database (internal, trusted).
    DatabaseRow,
    /// A memory entry recalled into context.
    MemoryRead,
    /// A structured HTTP/API response from an external service.
    HttpResponse,
}

impl DeclaredInput {
    fn node_kind(self) -> NodeKind {
        match self {
            DeclaredInput::UserPrompt => NodeKind::UserPrompt,
            DeclaredInput::WebContent => NodeKind::WebContent,
            DeclaredInput::ToolResponse => NodeKind::ToolResponse,
            DeclaredInput::FileRead => NodeKind::FileRead,
            DeclaredInput::EnvVar => NodeKind::EnvVar,
            DeclaredInput::Secret => NodeKind::Secret,
            DeclaredInput::DatabaseRow => NodeKind::DatabaseRow,
            DeclaredInput::MemoryRead => NodeKind::MemoryRead,
            DeclaredInput::HttpResponse => NodeKind::HTTPResponse,
        }
    }

    /// Stable wire token (matches the serde `snake_case` rename).
    pub fn token(self) -> &'static str {
        match self {
            DeclaredInput::UserPrompt => "user_prompt",
            DeclaredInput::WebContent => "web_content",
            DeclaredInput::ToolResponse => "tool_response",
            DeclaredInput::FileRead => "file_read",
            DeclaredInput::EnvVar => "env_var",
            DeclaredInput::Secret => "secret",
            DeclaredInput::DatabaseRow => "database_row",
            DeclaredInput::MemoryRead => "memory_read",
            DeclaredInput::HttpResponse => "http_response",
        }
    }

    /// Parse a wire token back to a [`DeclaredInput`] (inverse of [`Self::token`]).
    /// Used by the recompute path to rebuild a declaration from a receipt's
    /// `declared_inputs`.
    pub fn from_token(token: &str) -> Option<Self> {
        Some(match token {
            "user_prompt" => DeclaredInput::UserPrompt,
            "web_content" => DeclaredInput::WebContent,
            "tool_response" => DeclaredInput::ToolResponse,
            "file_read" => DeclaredInput::FileRead,
            "env_var" => DeclaredInput::EnvVar,
            "secret" => DeclaredInput::Secret,
            "database_row" => DeclaredInput::DatabaseRow,
            "memory_read" => DeclaredInput::MemoryRead,
            "http_response" => DeclaredInput::HttpResponse,
            _ => return None,
        })
    }
}

/// The declared data-flow surface of a call. The action is modelled as an
/// `OutboundAction` sink whose causal parents are the declared inputs, so the
/// gate sees the full lethal trifecta.
///
/// `sink_public` sets the sink's maximum confidentiality: `false` (default) =
/// delivered to an authenticated counterparty (`ConfLevel::Internal`); `true` =
/// publicly visible (`ConfLevel::Public`, tighter).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowDeclaration {
    /// Every input the handler will be exposed to.
    pub inputs: Vec<DeclaredInput>,
    /// Whether the action requires `Directive` authority (most do not).
    #[serde(default)]
    pub requires_authority: bool,
    /// Whether the response is publicly visible (vs. delivered to the
    /// authenticated counterparty). See the type docs.
    #[serde(default)]
    pub sink_public: bool,
}

impl FlowDeclaration {
    /// A declaration with the given inputs, no authority requirement, and a
    /// counterparty (non-public) sink.
    pub fn new(inputs: impl IntoIterator<Item = DeclaredInput>) -> Self {
        Self {
            inputs: inputs.into_iter().collect(),
            requires_authority: false,
            sink_public: false,
        }
    }

    /// Rebuild a declaration from wire tokens (e.g. a receipt's `declared_inputs`)
    /// plus the sink visibility. Unknown tokens are rejected (returns `None`) so
    /// the recompute fails closed on an unrecognised input rather than silently
    /// dropping it.
    pub fn from_tokens<'a>(
        tokens: impl IntoIterator<Item = &'a str>,
        requires_authority: bool,
        sink_public: bool,
    ) -> Option<Self> {
        let inputs = tokens
            .into_iter()
            .map(DeclaredInput::from_token)
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            inputs,
            requires_authority,
            sink_public,
        })
    }

    /// Mark the response as publicly visible (tightens confidentiality from
    /// `Internal` to `Public`).
    pub fn public_sink(mut self) -> Self {
        self.sink_public = true;
        self
    }

    /// Run the model-level IFC decision for this declaration. Fails closed.
    pub fn decide(&self) -> IfcVerdict {
        // Sorted, de-duplicated declared set for a deterministic, auditable
        // verdict (independent of declaration order).
        let mut declared: Vec<DeclaredInput> = self.inputs.clone();
        declared.sort();
        declared.dedup();
        let declared_tokens: Vec<String> = declared.iter().map(|i| i.token().to_string()).collect();

        let mut tracker = FlowTracker::new();
        let mut parents = Vec::with_capacity(self.inputs.len());
        for input in &self.inputs {
            match tracker.observe(input.node_kind()) {
                Ok(id) => parents.push(id),
                Err(e) => {
                    return IfcVerdict::deny(
                        format!("flow tracking error observing input: {e}"),
                        declared_tokens,
                    );
                }
            }
        }
        // The action is an outbound sink that may communicate externally.
        let sink = match tracker.observe_with_parents(NodeKind::OutboundAction, &parents) {
            Ok(id) => id,
            Err(e) => {
                return IfcVerdict::deny(
                    format!("flow tracking error observing sink: {e}"),
                    declared_tokens,
                );
            }
        };
        let sink_max_conf = if self.sink_public {
            ConfLevel::Public
        } else {
            ConfLevel::Internal
        };
        let check = tracker.check_exfiltration_safety(sink, self.requires_authority, sink_max_conf);
        if check.is_safe() {
            IfcVerdict::allow(declared_tokens)
        } else {
            IfcVerdict::deny(format!("{check:?}"), declared_tokens)
        }
    }
}

/// The result of the IFC gate. Serializable + deterministic so it can be folded
/// into a signed receipt and independently re-derived by a verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IfcVerdict {
    /// Whether the action is permitted by the model-level IFC decision.
    pub allow: bool,
    /// Human/audit reason (`SafetyCheck` debug form on deny, `"safe"` on allow).
    pub reason: String,
    /// The declared inputs the decision was made over, sorted + deduped. Carried
    /// verbatim so a verifier can judge **coverage**, not just the verdict.
    pub declared_inputs: Vec<String>,
}

impl IfcVerdict {
    fn allow(declared_inputs: Vec<String>) -> Self {
        Self {
            allow: true,
            reason: "safe".to_string(),
            declared_inputs,
        }
    }

    fn deny(reason: String, declared_inputs: Vec<String>) -> Self {
        Self {
            allow: false,
            reason,
            declared_inputs,
        }
    }

    /// `true` if the gate permits the action.
    pub fn is_allow(&self) -> bool {
        self.allow
    }

    /// Deterministic canonical string of the verdict, for the signed binding.
    /// NUL-separated; `allow` + the sorted declared set fully determine it (the
    /// `reason` is descriptive and intentionally excluded).
    pub fn canonical(&self) -> String {
        let mut s = String::new();
        s.push_str(if self.allow { "allow" } else { "deny" });
        s.push('\0');
        s.push_str(&self.declared_inputs.join(","));
        s
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Proof-carrying decision — the per-decision conformance certificate.
//
// Proof-Carrying Code applied to ONE decision against the IFC-down-flow
// obligation Φ. The (untrusted, possibly backdoored) model is the PROVER; it
// emits a certificate `(spec, declaration, verdict)`. A small TRUSTED CHECKER
// (`recheck`) re-derives the verdict — here by RECOMPUTE, since `decide` is
// deterministic and the obligation is decidable — and admits the action only if
// it recomputes, names this obligation, and the verdict permits it. A
// spec-violating action has no admitting certificate, and a forged "allow" is
// caught by recompute: that is the per-decision *bond*, enforced by logic (a
// deterministic trigger cannot produce a proof that does not exist), not by
// incentive.
//
// HONESTY BOUNDARY: this bonds the DECIDABLE IFC-down-flow fragment only. An
// in-policy semantic defection (the in-spec sleeper) carries a *valid*
// certificate — Φ does not see intent. The checker here is recompute; a
// Lean-kernel-checked proof term against `IFCSemilatticeProofs` is the stronger
// follow-on variant. Never read this as "certifies alignment".
// ───────────────────────────────────────────────────────────────────────────

/// The alignment-spec fragment a [`ConformanceCertificate`] is denominated in.
/// A stable id so a verifier knows exactly which obligation was checked — never
/// the word "alignment".
pub const SPEC_IFC_DOWNFLOW_V1: &str = "ifc-downflow/v1: declared flow is \
     exfiltration-safe (no adversarial ancestry; no confidentiality up-flow to the sink)";

/// A proof-carrying decision: the declared flow, the verdict, and the named
/// obligation it claims to satisfy. Serializable so it folds into a signed
/// receipt and is re-checkable offline by any third party.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceCertificate {
    /// The obligation Φ this certificate is denominated in (see [`SPEC_IFC_DOWNFLOW_V1`]).
    pub spec: String,
    /// The declared data-flow surface of the decision.
    pub declaration: FlowDeclaration,
    /// The verdict the (untrusted) producer carried for that declaration.
    pub verdict: IfcVerdict,
    /// The kernel-checked, CI-gated Lean theorem that *backs* the integrity leg
    /// of Φ: it proves an allow-verdict cannot coexist with an adversarial-ancestry
    /// → outbound-sink flow (`portcullis-core/lean` `web_tainted_never_git_pushes`
    /// / `integrity_sink_never_admitted`, proven over Aeneas-extracted-from-Rust
    /// code). The runtime still RECOMPUTEs; this names what kernel-proves the
    /// allow ⇒ non-interference implication. Empty if unbacked.
    pub backed_by_theorem: String,
    /// The honest proof scope — carried verbatim so a verifier never over-reads
    /// the certificate. Distinguishes the extracted-kernel integrity leg from the
    /// hand-model confidentiality leg, and names the open residuals.
    pub proof_scope: ProofScope,
}

/// How strongly a given axis of Φ is backed. Carried on the certificate so the
/// guarantee is never over-stated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStatus {
    /// Kernel-checked in Lean over Aeneas-extracted-from-Rust code (the strongest
    /// today): the per-step join/flows-to primitive is tied to the binary by
    /// exhaustive parity to the production label algebra.
    ExtractedKernelChecked,
    /// Kernel-checked in Lean over a HAND-WRITTEN model (not extracted): real, but
    /// the model↔binary correspondence is by structural tests, not extraction.
    HandModelKernelChecked,
    /// Backed only by runtime recompute — no kernel theorem.
    RecomputeOnly,
}

/// The proof scope of a [`ConformanceCertificate`]'s Φ — honest by construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofScope {
    /// Integrity axis (no adversarial-ancestry → outbound sink).
    pub integrity_axis: ProofStatus,
    /// Confidentiality axis (no secret → public down-flow).
    pub confidentiality_axis: ProofStatus,
    /// Named open residuals this certificate does NOT cover.
    pub open_residuals: Vec<String>,
}

/// The result of independently re-checking a [`ConformanceCertificate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecheckReport {
    /// Re-running `decide` on the declaration reproduces the carried verdict —
    /// a forged verdict is caught here (recompute, not trust).
    pub recomputes: bool,
    /// The certificate names the obligation this checker actually enforces.
    pub spec_matches: bool,
    /// The decision is ADMISSIBLE: it recomputes, the spec matches, and the
    /// recomputed verdict permits the action. A spec-violating action cannot be
    /// admissible; a forged "allow" cannot be admissible.
    pub admissible: bool,
}

impl FlowDeclaration {
    /// Produce a proof-carrying decision for the IFC-down-flow obligation: run
    /// the deterministic gate and bind the verdict to the named spec.
    pub fn certify(&self) -> ConformanceCertificate {
        ConformanceCertificate {
            spec: SPEC_IFC_DOWNFLOW_V1.to_string(),
            declaration: self.clone(),
            verdict: self.decide(),
            backed_by_theorem: "portcullis_core::lean::IntegrityNoninterferenceExtracted::\
                                 {integrity_sink_never_admitted, web_tainted_never_git_pushes}"
                .to_string(),
            proof_scope: ProofScope {
                // The integrity leg is proven in Lean over Aeneas-extracted-from-Rust
                // code (CI-gated, axiom set [propext, Classical.choice, Quot.sound]); the
                // `decide_matches_extracted_integrity_model` test below ties decide()'s
                // integrity verdict to that extracted primitive over the conf-safe inputs.
                integrity_axis: ProofStatus::ExtractedKernelChecked,
                // The confidentiality dual is proven only over a hand model
                // (formal/Nucleus/HolyGrail/ConfidentialityNoninterference.lean) — real,
                // but NOT extracted from the running Rust. Stated honestly, never unified.
                // C1 IN PROGRESS: the extracted confidentiality slice + dual theorem are
                // STAGED (portcullis-core extracted::ifc_confidentiality +
                // ConfidentialityNoninterferenceExtracted.lean, wired into aeneas-ifc-scoped).
                // Flip this to ExtractedKernelChecked ONLY after that job verifies the dual
                // (the integrity leg above is the precedent) — do not flip on stage alone.
                confidentiality_axis: ProofStatus::HandModelKernelChecked,
                open_residuals: vec![
                    "the FlowTracker graph-fold loop is hand-written Lean (irun), not extracted".to_string(),
                    "decide()'s composition is tied to the extracted primitive by sampled parity, not proof".to_string(),
                    "in-policy semantic malice / the in-spec sleeper carries a valid certificate".to_string(),
                    "covert/timing channels, label adequacy, and permitted sinks are out of scope".to_string(),
                ],
            },
        }
    }
}

impl ConformanceCertificate {
    /// Independently re-check: recompute `decide` from the declaration and
    /// confirm it matches the carried verdict, the spec is the one this checker
    /// enforces, and the verdict admits the action. Why-agnostic: it does not
    /// matter whether a hostile verdict came from a jailbreak or a backdoor —
    /// an action that violates Φ has no admitting certificate.
    pub fn recheck(&self) -> RecheckReport {
        let recomputed = self.declaration.decide();
        let recomputes = recomputed == self.verdict;
        let spec_matches = self.spec == SPEC_IFC_DOWNFLOW_V1;
        RecheckReport {
            recomputes,
            spec_matches,
            admissible: recomputes && spec_matches && recomputed.is_allow(),
        }
    }

    /// Convenience: is this a valid admitting certificate?
    pub fn admits(&self) -> bool {
        self.recheck().admissible
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conformance_cert_admits_safe_decision() {
        let cert =
            FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::DatabaseRow]).certify();
        let r = cert.recheck();
        assert!(
            r.recomputes && r.spec_matches && r.admissible,
            "safe decision must admit: {r:?}"
        );
        assert!(cert.admits());
    }

    #[test]
    fn conformance_cert_refuses_spec_violating_decision() {
        // secret -> public egress: decide() denies, so an HONEST cert is non-admissible.
        let cert = FlowDeclaration::new([DeclaredInput::Secret])
            .public_sink()
            .certify();
        let r = cert.recheck();
        assert!(r.recomputes, "an honest cert still recomputes faithfully");
        assert!(
            !r.admissible,
            "a spec-violating action must NOT be admitted: {r:?}"
        );
    }

    #[test]
    fn forged_allow_is_caught_by_recompute() {
        // The EchoLeak exfil shape: adversarial web content into an outbound action.
        let decl = FlowDeclaration::new([DeclaredInput::WebContent]);
        let mut cert = decl.certify();
        assert!(
            !cert.verdict.is_allow(),
            "baseline denies adversarial ancestry"
        );
        // Forge: claim an allow on a declaration decide() denies.
        cert.verdict = IfcVerdict::allow(cert.verdict.declared_inputs.clone());
        let r = cert.recheck();
        assert!(!r.recomputes, "a forged allow must fail recompute");
        assert!(!r.admissible, "and therefore must not be admitted: {r:?}");
    }

    #[test]
    fn wrong_spec_is_flagged() {
        let mut cert = FlowDeclaration::new([DeclaredInput::UserPrompt]).certify();
        cert.spec = "some-other-obligation".to_string();
        let r = cert.recheck();
        assert!(
            !r.spec_matches,
            "a cert for a different obligation can't admit here"
        );
        assert!(!r.admissible);
    }

    #[test]
    fn certify_carries_backing_theorem_and_honest_scope() {
        let cert = FlowDeclaration::new([DeclaredInput::UserPrompt]).certify();
        assert!(cert
            .backed_by_theorem
            .contains("integrity_sink_never_admitted"));
        assert_eq!(
            cert.proof_scope.integrity_axis,
            ProofStatus::ExtractedKernelChecked
        );
        // The confidentiality leg must be honestly marked hand-model, never unified.
        assert_eq!(
            cert.proof_scope.confidentiality_axis,
            ProofStatus::HandModelKernelChecked
        );
        assert!(
            !cert.proof_scope.open_residuals.is_empty(),
            "must name its residuals"
        );
    }

    /// The bridge that makes `backed_by_theorem` real (not ceremony): the production
    /// `decide()` integrity verdict matches the Aeneas-extracted, Lean-kernel-proven
    /// integrity model (`portcullis_core::extracted::ifc_integrity`), EXHAUSTIVELY over
    /// the inputs whose intrinsic confidentiality is ≤ Internal and whose integrity is
    /// Trusted or Adversarial. That restriction isolates the integrity axis (a non-public
    /// sink's confidentiality conjunct never trips) and sidesteps the Untrusted tier, so
    /// `decide().allow ⟺ no adversarial ancestry` — exactly what `integrity_sink_never_admitted`
    /// proves.
    #[test]
    fn decide_matches_extracted_integrity_model() {
        use portcullis_core::extracted::ifc_integrity as ext;
        use portcullis_core::flow::intrinsic_label;
        use portcullis_core::{ConfLevel, IntegLevel};

        fn to_ext(i: IntegLevel) -> ext::IntegLevel {
            match i {
                IntegLevel::Adversarial => ext::IntegLevel::Adversarial,
                IntegLevel::Untrusted => ext::IntegLevel::Untrusted,
                IntegLevel::Trusted => ext::IntegLevel::Trusted,
            }
        }

        let all = [
            DeclaredInput::UserPrompt,
            DeclaredInput::WebContent,
            DeclaredInput::ToolResponse,
            DeclaredInput::FileRead,
            DeclaredInput::EnvVar,
            DeclaredInput::Secret,
            DeclaredInput::DatabaseRow,
            DeclaredInput::MemoryRead,
            DeclaredInput::HttpResponse,
        ];
        let inputs: Vec<DeclaredInput> = all
            .into_iter()
            .filter(|i| {
                let l = intrinsic_label(i.node_kind(), 0);
                l.confidentiality <= ConfLevel::Internal
                    && matches!(l.integrity, IntegLevel::Trusted | IntegLevel::Adversarial)
            })
            .collect();
        let n = inputs.len();
        assert!(
            n >= 2,
            "need a mix of trusted+adversarial conf-safe inputs, got {n}"
        );

        let mut checked = 0u64;
        for mask in 0u32..(1u32 << n) {
            let subset: Vec<DeclaredInput> = (0..n)
                .filter(|i| mask & (1 << i) != 0)
                .map(|i| inputs[i])
                .collect();
            if subset.len() > 8 {
                continue; // engine fan-in bound
            }
            // Extracted, kernel-proven integrity model: fold imeet from Trusted, then
            // iflows_to the OutboundAction sink's required integrity (Trusted).
            let mut acc = ext::IntegLevel::Trusted;
            for &inp in &subset {
                acc = ext::imeet(acc, to_ext(intrinsic_label(inp.node_kind(), 0).integrity));
            }
            let model_admits = ext::iflows_to(acc, ext::IntegLevel::Trusted);
            // Production decide() over a non-public, no-authority sink — conf-safe by
            // construction, so the verdict is integrity-determined.
            let prod_allows = FlowDeclaration::new(subset.clone()).decide().is_allow();
            assert_eq!(
                prod_allows, model_admits,
                "decide() integrity verdict diverged from the extracted Lean model: \
                 subset={subset:?} prod={prod_allows} model={model_admits}"
            );
            checked += 1;
        }
        assert!(checked > 0, "no conf-safe subsets enumerated");
    }

    #[test]
    fn safe_declaration_allows() {
        let v =
            FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::DatabaseRow]).decide();
        assert!(v.is_allow(), "clean flow must be allowed: {v:?}");
    }

    #[test]
    fn untrusted_content_to_action_is_denied() {
        let v =
            FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::WebContent]).decide();
        assert!(!v.is_allow(), "adversarial ancestry must be denied: {v:?}");
    }

    #[test]
    fn secret_to_counterparty_is_denied() {
        let v = FlowDeclaration::new([DeclaredInput::Secret]).decide();
        assert!(!v.is_allow(), "secret→counterparty must be denied: {v:?}");
    }

    #[test]
    fn internal_to_counterparty_ok_but_public_denied() {
        let to_buyer = FlowDeclaration::new([DeclaredInput::DatabaseRow]).decide();
        assert!(to_buyer.is_allow());
        let to_public = FlowDeclaration::new([DeclaredInput::DatabaseRow])
            .public_sink()
            .decide();
        assert!(!to_public.is_allow());
    }

    #[test]
    fn declared_inputs_sorted_and_deduped() {
        let v = FlowDeclaration::new([
            DeclaredInput::WebContent,
            DeclaredInput::UserPrompt,
            DeclaredInput::WebContent,
        ])
        .decide();
        assert_eq!(v.declared_inputs, ["user_prompt", "web_content"]);
    }

    #[test]
    fn canonical_is_order_independent() {
        let a = FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::DatabaseRow])
            .decide()
            .canonical();
        let b = FlowDeclaration::new([DeclaredInput::DatabaseRow, DeclaredInput::UserPrompt])
            .decide()
            .canonical();
        assert_eq!(a, b);
    }

    #[test]
    fn token_round_trips() {
        for t in [
            "user_prompt",
            "web_content",
            "secret",
            "database_row",
            "http_response",
        ] {
            assert_eq!(DeclaredInput::from_token(t).unwrap().token(), t);
        }
        assert_eq!(DeclaredInput::from_token("nope"), None);
    }

    #[test]
    fn from_tokens_recomputes_same_verdict() {
        // The recompute path: rebuild from tokens → decide → same canonical.
        let orig = FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::WebContent]);
        let v1 = orig.decide();
        let rebuilt =
            FlowDeclaration::from_tokens(["user_prompt", "web_content"], false, false).unwrap();
        let v2 = rebuilt.decide();
        assert_eq!(v1.canonical(), v2.canonical());
        assert!(!v2.is_allow());
        // Unknown token fails closed.
        assert!(FlowDeclaration::from_tokens(["bogus"], false, false).is_none());
    }

    // ── Safety monotonicity (property-based) ───────────────────────────

    use proptest::prelude::*;

    fn any_input() -> impl Strategy<Value = DeclaredInput> {
        prop_oneof![
            Just(DeclaredInput::UserPrompt),
            Just(DeclaredInput::WebContent),
            Just(DeclaredInput::ToolResponse),
            Just(DeclaredInput::FileRead),
            Just(DeclaredInput::EnvVar),
            Just(DeclaredInput::Secret),
            Just(DeclaredInput::DatabaseRow),
            Just(DeclaredInput::MemoryRead),
            Just(DeclaredInput::HttpResponse),
        ]
    }

    proptest! {
        /// **The gate is monotone-restrictive in its declared inputs.** Adding an
        /// input can only make the verdict *more* restrictive (flip allow→deny),
        /// never *less* (deny→allow): more declared sources mean the outbound sink
        /// is at least as tainted, so the lethal-trifecta gate is at most as
        /// permissive. Equivalently, if a SUPERSET of inputs is allowed, every
        /// subset is too. This is the core safety property — a caller can't earn an
        /// `allow` by *declaring more* exposure — and it held only on hand-picked
        /// cases before; here it's checked over arbitrary declarations.
        #[test]
        fn adding_an_input_never_loosens_the_verdict(
            inputs in proptest::collection::vec(any_input(), 0..6),
            extra in any_input(),
            requires_authority in any::<bool>(),
            sink_public in any::<bool>(),
        ) {
            let mut base = FlowDeclaration::new(inputs.clone());
            base.requires_authority = requires_authority;
            base.sink_public = sink_public;

            let mut more = base.clone();
            more.inputs.push(extra);

            if more.decide().is_allow() {
                prop_assert!(
                    base.decide().is_allow(),
                    "adding {extra:?} loosened deny→allow (base inputs={inputs:?}, \
                     sink_public={sink_public}, requires_authority={requires_authority})"
                );
            }
        }
    }
}

//! Galois connections for principled trust domain translation.
//!
//! A **Galois connection** between posets (L, ≤) and (R, ≤) consists of:
//! - `α: L → R` (abstraction / restriction)
//! - `γ: R → L` (concretization / embedding)
//!
//! Such that: `α(l) ≤ r ⟺ l ≤ γ(r)`
//!
//! # Security Applications
//!
//! When agents span trust domains (e.g., cross-organization communication),
//! Galois connections provide principled security label translation:
//!
//! - **Abstraction (α)**: Restrict permissions when entering a less-trusted domain
//! - **Concretization (γ)**: Embed permissions from an external domain conservatively
//!
//! The adjunction property guarantees that translations preserve the security ordering.
//!
//! # Example
//!
//! ```rust
//! use lattice_guard::galois::{GaloisConnection, TrustDomainBridge};
//! use lattice_guard::PermissionLattice;
//!
//! // Create a bridge between internal and external domains
//! let bridge = TrustDomainBridge::new(
//!     "spiffe://internal.corp",
//!     "spiffe://partner.org",
//!     // Going external: restrict to network-only
//!     |p: &PermissionLattice| p.meet(&PermissionLattice::network_only()),
//!     // Coming internal: block filesystem
//!     |p: &PermissionLattice| {
//!         let mut restricted = p.clone();
//!         restricted.capabilities.read_files = lattice_guard::CapabilityLevel::Never;
//!         restricted.capabilities.write_files = lattice_guard::CapabilityLevel::Never;
//!         restricted
//!     },
//! );
//!
//! let internal_perms = PermissionLattice::permissive();
//! let external_perms = bridge.to_target(&internal_perms);
//! ```

use crate::frame::Lattice;
use crate::PermissionLattice;

/// Error returned when Galois connection verification fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GaloisVerificationError {
    /// Index of the sample that failed verification
    pub sample_index: usize,
    /// Human-readable error message
    pub message: String,
}

impl std::fmt::Display for GaloisVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for GaloisVerificationError {}

/// A Galois connection between two lattices.
///
/// The adjunction property guarantees security-preserving translations:
/// `α(l) ≤ r ⟺ l ≤ γ(r)`
///
/// # Type Parameters
///
/// - `L`: The left (source) lattice
/// - `R`: The right (target) lattice
pub struct GaloisConnection<L, R> {
    /// Abstraction function (left adjoint): L → R
    pub alpha: Box<dyn Fn(&L) -> R + Send + Sync>,
    /// Concretization function (right adjoint): R → L
    pub gamma: Box<dyn Fn(&R) -> L + Send + Sync>,
}

impl<L: Lattice, R: Lattice> GaloisConnection<L, R> {
    /// Create a new Galois connection.
    ///
    /// # Security Warning
    ///
    /// This constructor does NOT verify that the provided functions form a valid
    /// Galois connection. The adjunction property `α(l) ≤ r ⟺ l ≤ γ(r)` is
    /// claimed but not enforced at construction time.
    ///
    /// For security-critical applications:
    /// - Use `new_verified` with sample elements to validate the connection
    /// - Use preset bridges from the `presets` module which are tested
    /// - Add property-based tests for custom connections
    ///
    /// # See Also
    ///
    /// - [`Self::new_verified`] - Validates the connection with sample elements
    /// - [`Self::verify`] - Check the adjunction for specific elements
    pub fn new<A, G>(alpha: A, gamma: G) -> Self
    where
        A: Fn(&L) -> R + Send + Sync + 'static,
        G: Fn(&R) -> L + Send + Sync + 'static,
    {
        Self {
            alpha: Box::new(alpha),
            gamma: Box::new(gamma),
        }
    }

    /// Create a new Galois connection with verification.
    ///
    /// Validates the adjunction property against provided sample elements.
    /// Returns an error if any sample pair violates the property.
    ///
    /// # Arguments
    ///
    /// * `alpha` - The abstraction function (L → R)
    /// * `gamma` - The concretization function (R → L)
    /// * `samples` - Pairs of (L, R) elements to test the adjunction
    ///
    /// # Errors
    ///
    /// Returns `GaloisVerificationError` if any sample violates the adjunction.
    ///
    /// # Security Note
    ///
    /// While this provides more confidence than `new`, sampling cannot prove
    /// the property holds for ALL elements. For full verification, use
    /// property-based testing in your test suite.
    pub fn new_verified<A, G>(
        alpha: A,
        gamma: G,
        samples: &[(L, R)],
    ) -> Result<Self, GaloisVerificationError>
    where
        A: Fn(&L) -> R + Send + Sync + 'static,
        G: Fn(&R) -> L + Send + Sync + 'static,
    {
        let connection = Self::new(alpha, gamma);

        for (i, (l, r)) in samples.iter().enumerate() {
            if !connection.verify(l, r) {
                return Err(GaloisVerificationError {
                    sample_index: i,
                    message: format!(
                        "Galois adjunction violated at sample {}: α(l) ≤ r ⟺ l ≤ γ(r) failed",
                        i
                    ),
                });
            }
        }

        Ok(connection)
    }

    /// Apply the abstraction function (α): L → R.
    ///
    /// This typically restricts/weakens permissions when moving to a
    /// less-trusted domain.
    pub fn abstract_to(&self, l: &L) -> R {
        (self.alpha)(l)
    }

    /// Apply the concretization function (γ): R → L.
    ///
    /// This typically embeds external permissions conservatively into
    /// the internal domain.
    pub fn concretize_from(&self, r: &R) -> L {
        (self.gamma)(r)
    }

    /// Verify the Galois connection property for specific elements.
    ///
    /// Returns true if `α(l) ≤ r ⟺ l ≤ γ(r)`.
    pub fn verify(&self, l: &L, r: &R) -> bool {
        let alpha_l = self.abstract_to(l);
        let gamma_r = self.concretize_from(r);

        let lhs = alpha_l.leq(r);
        let rhs = l.leq(&gamma_r);

        lhs == rhs
    }

    /// Compute the closure: γ ∘ α.
    ///
    /// This is a closure operator on L, representing the "round-trip"
    /// of going to R and back. Elements in the image of γ are fixed points.
    pub fn closure(&self, l: &L) -> L {
        self.concretize_from(&self.abstract_to(l))
    }

    /// Compute the kernel: α ∘ γ.
    ///
    /// This is a kernel operator on R, representing the "round-trip"
    /// of going to L and back.
    pub fn kernel(&self, r: &R) -> R {
        self.abstract_to(&self.concretize_from(r))
    }
}

impl<L: Lattice + 'static, R: Lattice + 'static> GaloisConnection<L, R> {
    /// Compose two Galois connections: `(L ⇄ R) ∘ (R ⇄ S) → (L ⇄ S)`.
    ///
    /// This is the fundamental categorical composition. Given:
    /// - `self: GaloisConnection<L, R>` with (α₁, γ₁)
    /// - `other: GaloisConnection<R, S>` with (α₂, γ₂)
    ///
    /// Produces `GaloisConnection<L, S>` with:
    /// - `α = α₂ ∘ α₁` (abstract through both)
    /// - `γ = γ₁ ∘ γ₂` (concretize through both, reversed)
    ///
    /// The adjunction property is preserved by composition:
    /// if both connections satisfy `α(l) ≤ r ⟺ l ≤ γ(r)`,
    /// then so does the composed connection.
    pub fn compose<S: Lattice + 'static>(
        self,
        other: GaloisConnection<R, S>,
    ) -> GaloisConnection<L, S> {
        use std::sync::Arc;
        let alpha1 = Arc::new(self.alpha);
        let gamma1 = Arc::new(self.gamma);
        let alpha2 = Arc::new(other.alpha);
        let gamma2 = Arc::new(other.gamma);

        let a1 = Arc::clone(&alpha1);
        let a2 = Arc::clone(&alpha2);
        let g1 = Arc::clone(&gamma1);
        let g2 = Arc::clone(&gamma2);

        GaloisConnection::new(move |l: &L| a2(&a1(l)), move |s: &S| g1(&g2(s)))
    }
}

impl<L, R> std::fmt::Debug for GaloisConnection<L, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GaloisConnection")
            .field("alpha", &"<function>")
            .field("gamma", &"<function>")
            .finish()
    }
}

/// A trust domain bridge using Galois connections.
///
/// This provides a concrete implementation for translating permissions
/// between SPIFFE trust domains.
#[derive(Debug)]
pub struct TrustDomainBridge {
    /// Source trust domain (e.g., "spiffe://internal.corp")
    pub source: String,
    /// Target trust domain (e.g., "spiffe://partner.org")
    pub target: String,
    /// The Galois connection for translation
    connection: GaloisConnection<PermissionLattice, PermissionLattice>,
}

impl TrustDomainBridge {
    /// Create a new trust domain bridge.
    ///
    /// # Arguments
    ///
    /// - `source`: The source trust domain URI
    /// - `target`: The target trust domain URI
    /// - `to_target`: Abstraction function (typically restricts permissions)
    /// - `from_target`: Concretization function (typically embeds conservatively)
    pub fn new<A, G>(
        source: impl Into<String>,
        target: impl Into<String>,
        to_target: A,
        from_target: G,
    ) -> Self
    where
        A: Fn(&PermissionLattice) -> PermissionLattice + Send + Sync + 'static,
        G: Fn(&PermissionLattice) -> PermissionLattice + Send + Sync + 'static,
    {
        Self {
            source: source.into(),
            target: target.into(),
            connection: GaloisConnection::new(to_target, from_target),
        }
    }

    /// Translate permissions from source to target domain.
    ///
    /// This applies the abstraction function (α), typically restricting
    /// permissions for the target domain.
    pub fn to_target(&self, perms: &PermissionLattice) -> PermissionLattice {
        self.connection.abstract_to(perms)
    }

    /// Translate permissions from target to source domain.
    ///
    /// This applies the concretization function (γ), typically embedding
    /// external permissions conservatively.
    pub fn from_target(&self, perms: &PermissionLattice) -> PermissionLattice {
        self.connection.concretize_from(perms)
    }

    /// Verify the Galois connection property.
    pub fn verify(
        &self,
        source_perms: &PermissionLattice,
        target_perms: &PermissionLattice,
    ) -> bool {
        self.connection.verify(source_perms, target_perms)
    }

    /// Compute what permissions would survive a round-trip.
    ///
    /// This is useful for understanding what information is preserved
    /// when crossing domain boundaries.
    pub fn round_trip(&self, perms: &PermissionLattice) -> PermissionLattice {
        self.connection.closure(perms)
    }
}

/// Pre-built bridges for common trust domain patterns.
pub mod presets {
    use super::*;
    use crate::CapabilityLevel;

    /// Create a bridge for internal-to-external communication.
    ///
    /// External domain gets network-only access, no filesystem.
    pub fn internal_external(internal: &str, external: &str) -> TrustDomainBridge {
        TrustDomainBridge::new(
            internal,
            external,
            // To external: restrict to network-only
            |p| p.meet(&PermissionLattice::network_only()),
            // From external: block all filesystem access
            |p| {
                let mut restricted = p.clone();
                restricted.capabilities.read_files = CapabilityLevel::Never;
                restricted.capabilities.write_files = CapabilityLevel::Never;
                restricted.capabilities.edit_files = CapabilityLevel::Never;
                restricted.capabilities.run_bash = CapabilityLevel::Never;
                restricted
            },
        )
    }

    /// Create a bridge for production-to-staging isolation.
    ///
    /// Staging gets full capabilities, production restricts write operations.
    pub fn production_staging(production: &str, staging: &str) -> TrustDomainBridge {
        TrustDomainBridge::new(
            production,
            staging,
            // To staging: allow full access (testing)
            |p| p.clone(),
            // From staging: restrict writes
            |p| {
                let mut restricted = p.clone();
                restricted.capabilities.write_files = CapabilityLevel::Never;
                restricted.capabilities.edit_files = CapabilityLevel::Never;
                restricted.capabilities.git_push = CapabilityLevel::Never;
                restricted.capabilities.create_pr = CapabilityLevel::Never;
                restricted
            },
        )
    }

    /// Create a bridge for human-to-agent delegation.
    ///
    /// Agents get reduced capabilities compared to human principals.
    pub fn human_agent(human_domain: &str, agent_domain: &str) -> TrustDomainBridge {
        TrustDomainBridge::new(
            human_domain,
            agent_domain,
            // To agent: apply default restrictions
            |p| p.meet(&PermissionLattice::default()),
            // From agent: trust nothing (agents can't elevate human permissions)
            |_p| PermissionLattice::restrictive(),
        )
    }

    /// Create a read-only bridge.
    ///
    /// Target domain can only read, never write.
    pub fn read_only(source: &str, target: &str) -> TrustDomainBridge {
        TrustDomainBridge::new(
            source,
            target,
            // To target: read-only
            |p| p.meet(&PermissionLattice::read_only()),
            // From target: also read-only (symmetric)
            |p| p.meet(&PermissionLattice::read_only()),
        )
    }
}

/// A step in an auditable bridge translation.
#[derive(Debug, Clone)]
pub struct TranslationStep {
    /// Source trust domain for this hop.
    pub from_domain: String,
    /// Target trust domain for this hop.
    pub to_domain: String,
    /// Permissions before this step.
    pub input_description: String,
    /// Permissions after this step.
    pub output_description: String,
    /// Whether this step narrowed permissions (output ≤ input).
    pub was_narrowed: bool,
}

/// An auditable report of a multi-hop bridge translation.
#[derive(Debug, Clone)]
pub struct TranslationReport {
    /// The individual steps taken.
    pub steps: Vec<TranslationStep>,
    /// Total number of hops.
    pub hop_count: usize,
    /// Whether any step narrowed permissions.
    pub any_narrowing: bool,
}

/// A chain of trust domain bridges.
///
/// Represents a path through multiple trust domains, composing
/// the Galois connections along the way.
#[derive(Debug, Default)]
pub struct BridgeChain {
    bridges: Vec<TrustDomainBridge>,
}

impl BridgeChain {
    /// Create an empty bridge chain.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a bridge to the chain.
    pub fn add(&mut self, bridge: TrustDomainBridge) {
        self.bridges.push(bridge);
    }

    /// Translate permissions through the entire chain (forward).
    pub fn translate_forward(&self, perms: &PermissionLattice) -> PermissionLattice {
        self.bridges
            .iter()
            .fold(perms.clone(), |p, bridge| bridge.to_target(&p))
    }

    /// Translate permissions through the entire chain (backward).
    pub fn translate_backward(&self, perms: &PermissionLattice) -> PermissionLattice {
        self.bridges
            .iter()
            .rev()
            .fold(perms.clone(), |p, bridge| bridge.from_target(&p))
    }

    /// Get the source domain of the chain.
    pub fn source(&self) -> Option<&str> {
        self.bridges.first().map(|b| b.source.as_str())
    }

    /// Get the target domain of the chain.
    pub fn target(&self) -> Option<&str> {
        self.bridges.last().map(|b| b.target.as_str())
    }

    /// Translate forward with an auditable report of each hop.
    ///
    /// Returns the final permissions and a `TranslationReport` showing
    /// what happened at each bridge crossing.
    pub fn translate_forward_audited(
        &self,
        perms: &PermissionLattice,
    ) -> (PermissionLattice, TranslationReport) {
        let mut current = perms.clone();
        let mut steps = Vec::with_capacity(self.bridges.len());

        for bridge in &self.bridges {
            let input_desc = current.description.clone();
            let output = bridge.to_target(&current);
            let was_narrowed = output.leq(&current) && current != output;

            steps.push(TranslationStep {
                from_domain: bridge.source.clone(),
                to_domain: bridge.target.clone(),
                input_description: input_desc,
                output_description: output.description.clone(),
                was_narrowed,
            });

            current = output;
        }

        let any_narrowing = steps.iter().any(|s| s.was_narrowed);
        let hop_count = steps.len();

        (
            current,
            TranslationReport {
                steps,
                hop_count,
                any_narrowing,
            },
        )
    }

    /// Compose the entire chain into a single `GaloisConnection`.
    ///
    /// This produces a single connection `L ⇄ R` where L is the source
    /// domain and R is the final target domain. The composed connection
    /// satisfies the adjunction property if each individual bridge does.
    ///
    /// Returns `None` if the chain is empty.
    pub fn compose_to_connection(
        self,
    ) -> Option<GaloisConnection<PermissionLattice, PermissionLattice>> {
        use std::sync::Arc;

        let mut iter = self.bridges.into_iter();
        let first = Arc::new(iter.next()?);

        let f1 = Arc::clone(&first);
        let f2 = Arc::clone(&first);
        let mut composed = GaloisConnection::new(
            move |p: &PermissionLattice| f1.to_target(p),
            move |p: &PermissionLattice| f2.from_target(p),
        );

        for bridge in iter {
            let b = Arc::new(bridge);
            let b1 = Arc::clone(&b);
            let b2 = Arc::clone(&b);
            composed = composed.compose(GaloisConnection::new(
                move |p: &PermissionLattice| b1.to_target(p),
                move |p: &PermissionLattice| b2.from_target(p),
            ));
        }

        Some(composed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CapabilityLevel;

    #[test]
    fn test_galois_connection_identity() {
        // Identity functions form a trivial Galois connection
        let connection: GaloisConnection<PermissionLattice, PermissionLattice> =
            GaloisConnection::new(
                |p: &PermissionLattice| p.clone(),
                |p: &PermissionLattice| p.clone(),
            );

        let perms = PermissionLattice::default();

        // α(l) should equal l
        assert_eq!(connection.abstract_to(&perms), perms);

        // γ(r) should equal r
        assert_eq!(connection.concretize_from(&perms), perms);

        // Closure should be identity
        assert_eq!(connection.closure(&perms), perms);
    }

    #[test]
    fn test_trust_domain_bridge_restriction() {
        let bridge = presets::internal_external("spiffe://internal.corp", "spiffe://partner.org");

        let internal = PermissionLattice::permissive();
        let external = bridge.to_target(&internal);

        // External should be network-only
        assert_eq!(external.capabilities.web_fetch, CapabilityLevel::LowRisk);
        assert_eq!(external.capabilities.web_search, CapabilityLevel::LowRisk);
        assert_eq!(external.capabilities.read_files, CapabilityLevel::Never);
        assert_eq!(external.capabilities.write_files, CapabilityLevel::Never);
    }

    #[test]
    fn test_trust_domain_bridge_embedding() {
        let bridge = presets::internal_external("spiffe://internal.corp", "spiffe://partner.org");

        // External permissions coming in
        let external = PermissionLattice::permissive();
        let internal = bridge.from_target(&external);

        // Internal view should block filesystem
        assert_eq!(internal.capabilities.read_files, CapabilityLevel::Never);
        assert_eq!(internal.capabilities.write_files, CapabilityLevel::Never);
        assert_eq!(internal.capabilities.run_bash, CapabilityLevel::Never);
    }

    #[test]
    fn test_bridge_chain_composition() {
        let mut chain = BridgeChain::new();

        chain.add(presets::internal_external(
            "spiffe://corp.internal",
            "spiffe://dmz.corp",
        ));
        chain.add(presets::read_only(
            "spiffe://dmz.corp",
            "spiffe://partner.org",
        ));

        let perms = PermissionLattice::permissive();
        let final_perms = chain.translate_forward(&perms);

        // After two restrictions, should be very limited
        assert_eq!(final_perms.capabilities.write_files, CapabilityLevel::Never);
        assert_eq!(final_perms.capabilities.edit_files, CapabilityLevel::Never);
    }

    #[test]
    fn test_round_trip_is_deflating() {
        let bridge = presets::internal_external("spiffe://internal.corp", "spiffe://external.org");

        let perms = PermissionLattice::permissive();
        let round_trip = bridge.round_trip(&perms);

        // Round trip should lose information (deflating)
        assert!(round_trip.leq(&perms));
    }

    #[test]
    fn test_human_agent_bridge() {
        let bridge =
            presets::human_agent("spiffe://corp/human/alice", "spiffe://corp/agent/coder-001");

        let human_perms = PermissionLattice::permissive();
        let agent_perms = bridge.to_target(&human_perms);

        // Agent should have default restrictions
        assert!(agent_perms.leq(&human_perms));

        // Coming back from agent should be restrictive (agents can't elevate)
        let back = bridge.from_target(&agent_perms);
        assert_eq!(back.description, "Restrictive permissions");
    }

    #[test]
    fn test_galois_connection_compose() {
        // Compose two connections: identity ∘ restriction = restriction
        let restrict: GaloisConnection<PermissionLattice, PermissionLattice> =
            GaloisConnection::new(
                |p: &PermissionLattice| p.meet(&PermissionLattice::read_only()),
                |p: &PermissionLattice| p.clone(),
            );
        let identity: GaloisConnection<PermissionLattice, PermissionLattice> =
            GaloisConnection::new(
                |p: &PermissionLattice| p.clone(),
                |p: &PermissionLattice| p.clone(),
            );

        let composed = restrict.compose(identity);
        let perms = PermissionLattice::permissive();
        let result = composed.abstract_to(&perms);

        // Should be read-only after composition
        assert_eq!(result.capabilities.write_files, CapabilityLevel::Never);
        assert_eq!(result.capabilities.read_files, CapabilityLevel::Always);
    }

    #[test]
    fn test_galois_compose_associativity() {
        // (f ∘ g) ∘ h should give same result as f ∘ (g ∘ h)

        // (f ∘ g) ∘ h
        let fg = GaloisConnection::new(
            |p: &PermissionLattice| p.meet(&PermissionLattice::read_only()),
            |p: &PermissionLattice| p.clone(),
        )
        .compose(GaloisConnection::new(
            |p: &PermissionLattice| p.meet(&PermissionLattice::network_only()),
            |p: &PermissionLattice| p.clone(),
        ));
        let fgh_left = fg.compose(GaloisConnection::new(
            |p: &PermissionLattice| {
                let mut r = p.clone();
                r.capabilities.run_bash = CapabilityLevel::Never;
                r
            },
            |p: &PermissionLattice| p.clone(),
        ));

        // f ∘ (g ∘ h)
        let gh = GaloisConnection::new(
            |p: &PermissionLattice| p.meet(&PermissionLattice::network_only()),
            |p: &PermissionLattice| p.clone(),
        )
        .compose(GaloisConnection::new(
            |p: &PermissionLattice| {
                let mut r = p.clone();
                r.capabilities.run_bash = CapabilityLevel::Never;
                r
            },
            |p: &PermissionLattice| p.clone(),
        ));
        let fgh_right = GaloisConnection::new(
            |p: &PermissionLattice| p.meet(&PermissionLattice::read_only()),
            |p: &PermissionLattice| p.clone(),
        )
        .compose(gh);

        let perms = PermissionLattice::permissive();
        let left = fgh_left.abstract_to(&perms);
        let right = fgh_right.abstract_to(&perms);

        // Compare security-relevant fields (UUIDs, timestamps are per-instance)
        assert_eq!(left.capabilities, right.capabilities);
        assert_eq!(left.obligations, right.obligations);
        assert_eq!(left.budget, right.budget);
    }

    #[test]
    fn test_bridge_chain_compose_to_connection() {
        let mut chain = BridgeChain::new();
        chain.add(presets::internal_external(
            "spiffe://corp.internal",
            "spiffe://dmz.corp",
        ));
        chain.add(presets::read_only(
            "spiffe://dmz.corp",
            "spiffe://partner.org",
        ));

        let perms = PermissionLattice::permissive();
        let expected = chain.translate_forward(&perms);

        // Compose to single connection and verify security-equivalent result
        let connection = chain.compose_to_connection().unwrap();
        let actual = connection.abstract_to(&perms);

        assert_eq!(actual.capabilities, expected.capabilities);
        assert_eq!(actual.obligations, expected.obligations);
        assert_eq!(actual.budget, expected.budget);
    }

    #[test]
    fn test_translate_forward_audited() {
        let mut chain = BridgeChain::new();
        chain.add(presets::internal_external(
            "spiffe://corp.internal",
            "spiffe://dmz.corp",
        ));
        chain.add(presets::read_only(
            "spiffe://dmz.corp",
            "spiffe://partner.org",
        ));

        let perms = PermissionLattice::permissive();
        let (result, report) = chain.translate_forward_audited(&perms);

        // Should have 2 hops
        assert_eq!(report.hop_count, 2);
        assert_eq!(report.steps.len(), 2);

        // Both steps should narrow
        assert!(report.any_narrowing);
        assert!(report.steps[0].was_narrowed);

        // Domain names correct
        assert_eq!(report.steps[0].from_domain, "spiffe://corp.internal");
        assert_eq!(report.steps[0].to_domain, "spiffe://dmz.corp");
        assert_eq!(report.steps[1].from_domain, "spiffe://dmz.corp");
        assert_eq!(report.steps[1].to_domain, "spiffe://partner.org");

        // Result should match non-audited path
        let mut chain2 = BridgeChain::new();
        chain2.add(presets::internal_external(
            "spiffe://corp.internal",
            "spiffe://dmz.corp",
        ));
        chain2.add(presets::read_only(
            "spiffe://dmz.corp",
            "spiffe://partner.org",
        ));
        let expected = chain2.translate_forward(&perms);
        assert_eq!(result.capabilities, expected.capabilities);
        assert_eq!(result.obligations, expected.obligations);
        assert_eq!(result.budget, expected.budget);
    }

    #[test]
    fn test_empty_chain_compose_returns_none() {
        let chain = BridgeChain::new();
        assert!(chain.compose_to_connection().is_none());
    }

    #[test]
    fn test_galois_closure_is_deflating() {
        // For a Galois connection, the closure γ ∘ α is deflationary
        // (round-trip loses information)
        let bridge = presets::read_only("spiffe://source", "spiffe://target");

        let perms = PermissionLattice::permissive();
        let round_trip = bridge.round_trip(&perms);

        // Closure should be ≤ original (in terms of capabilities)
        assert!(round_trip.capabilities.leq(&perms.capabilities));
    }
}

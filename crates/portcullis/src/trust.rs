//! Trust profiles: named presets mapping trust tiers to capability + isolation ceilings.
//!
//! A `TrustProfile` pairs a [`CapabilityLattice`] ceiling with an [`IsolationLattice`]
//! floor, expressing the contract: "at this trust tier, capabilities are capped at
//! `ceiling` and isolation must be at least `floor`."
//!
//! # Lattice Semantics
//!
//! ```text
//! enforce(effective, profile) =
//!     capabilities:  meet(effective.caps, profile.ceiling)
//!     isolation:     join(effective.isolation, profile.floor)
//! ```
//!
//! - **Capabilities** use meet (∧) to restrict: the result is never more permissive
//!   than either the effective permissions or the profile ceiling.
//! - **Isolation** uses join (∨) to strengthen: the result is at least as isolated
//!   as the profile requires.
//!
//! # Named Presets
//!
//! | Tier | Capabilities | Isolation | Use case |
//! |------|-------------|-----------|----------|
//! | `operator()` | Permissive (all Always) | Localhost (Shared/Unrestricted/Host) | Operator's own repos |
//! | `tenant()` | Permissive + approval on push/PR | Sandboxed (Namespaced/Sandboxed/Filtered) | Customer BYOK repos |
//! | `untrusted()` | Read-only + search only | MicroVM with network (MicroVM/ReadOnly/Filtered) | Arbitrary third-party repos |
//! | `airgapped()` | Read-only, no network tools | MicroVM (MicroVM/Ephemeral/Airgapped) | Maximum security |

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::capability::{CapabilityLattice, CapabilityLevel, Obligations, Operation};
use crate::frame::Lattice;
use crate::isolation::IsolationLattice;

/// A trust profile combining a capability ceiling with an isolation floor.
///
/// When applied to effective permissions, capabilities are restricted (meet)
/// and isolation is strengthened (join). This ensures that no trust tier
/// can exceed its capability ceiling or operate below its isolation floor.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TrustProfile {
    /// Human-readable name for this profile.
    pub name: String,

    /// Maximum capabilities allowed at this trust tier.
    /// Effective capabilities = meet(effective, ceiling).
    pub capability_ceiling: CapabilityLattice,

    /// Minimum isolation required at this trust tier.
    /// Effective isolation = join(effective, floor).
    pub isolation_floor: IsolationLattice,

    /// Additional obligations that must be satisfied regardless of capabilities.
    /// These are merged (union) with any existing obligations.
    #[cfg_attr(feature = "serde", serde(default))]
    pub mandatory_obligations: Obligations,
}

impl TrustProfile {
    /// Create a custom trust profile.
    pub fn new(
        name: impl Into<String>,
        capability_ceiling: CapabilityLattice,
        isolation_floor: IsolationLattice,
    ) -> Self {
        Self {
            name: name.into(),
            capability_ceiling,
            isolation_floor,
            mandatory_obligations: Obligations::default(),
        }
    }

    /// Add mandatory obligations to this profile.
    pub fn with_obligations(mut self, obligations: Obligations) -> Self {
        self.mandatory_obligations = obligations;
        self
    }

    /// Operator profile: full capabilities, no isolation requirements.
    ///
    /// Suitable for the operator's own repos in single-tenant mode.
    /// No restrictions on capabilities or isolation.
    pub fn operator() -> Self {
        Self {
            name: "operator".into(),
            capability_ceiling: CapabilityLattice::permissive(),
            isolation_floor: IsolationLattice::localhost(),
            mandatory_obligations: Obligations::default(),
        }
    }

    /// Tenant profile: full capabilities with approval gates on exfiltration.
    ///
    /// Suitable for customer BYOK repos where the customer has provided
    /// their own credentials. Allows all operations but requires approval
    /// for git push and PR creation (exfiltration vectors).
    pub fn tenant() -> Self {
        let mut obligations = Obligations::default();
        obligations.approvals.insert(Operation::GitPush);
        obligations.approvals.insert(Operation::CreatePr);

        Self {
            name: "tenant".into(),
            capability_ceiling: CapabilityLattice::permissive(),
            isolation_floor: IsolationLattice::sandboxed(),
            mandatory_obligations: obligations,
        }
    }

    /// Untrusted profile: read-only + search, sandboxed with filtered network.
    ///
    /// Suitable for arbitrary third-party repos. Write operations are blocked,
    /// network tools require approval, and the execution environment must be
    /// isolated in a microVM with read-only filesystem.
    pub fn untrusted() -> Self {
        let ceiling = CapabilityLattice {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::Never,
            edit_files: CapabilityLevel::Never,
            run_bash: CapabilityLevel::Never,
            glob_search: CapabilityLevel::Always,
            grep_search: CapabilityLevel::Always,
            web_search: CapabilityLevel::Never,
            web_fetch: CapabilityLevel::Never,
            git_commit: CapabilityLevel::Never,
            git_push: CapabilityLevel::Never,
            create_pr: CapabilityLevel::Never,
            manage_pods: CapabilityLevel::Never,
            #[cfg(not(kani))]
            extensions: std::collections::BTreeMap::new(),
        };

        Self {
            name: "untrusted".into(),
            capability_ceiling: ceiling,
            isolation_floor: IsolationLattice::microvm_with_network(),
            mandatory_obligations: Obligations::default(),
        }
    }

    /// Airgapped profile: read-only, no network, maximum isolation.
    ///
    /// The most restrictive profile. Suitable for security audits of
    /// untrusted code where no network access is acceptable.
    pub fn airgapped() -> Self {
        let ceiling = CapabilityLattice {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::Never,
            edit_files: CapabilityLevel::Never,
            run_bash: CapabilityLevel::Never,
            glob_search: CapabilityLevel::Always,
            grep_search: CapabilityLevel::Always,
            web_search: CapabilityLevel::Never,
            web_fetch: CapabilityLevel::Never,
            git_commit: CapabilityLevel::Never,
            git_push: CapabilityLevel::Never,
            create_pr: CapabilityLevel::Never,
            manage_pods: CapabilityLevel::Never,
            #[cfg(not(kani))]
            extensions: std::collections::BTreeMap::new(),
        };

        Self {
            name: "airgapped".into(),
            capability_ceiling: ceiling,
            isolation_floor: IsolationLattice::microvm(),
            mandatory_obligations: Obligations::default(),
        }
    }

    /// Derive a trust profile from an attestation bracket grade.
    ///
    /// Maps Coproduct Trust attestation brackets (A-F) to portcullis
    /// trust profiles. This enables dynamic permission scoping based
    /// on an agent's demonstrated reputation.
    ///
    /// | Bracket | Profile | Rationale |
    /// |---------|---------|-----------|
    /// | A | `operator()` | Exceptional track record — full trust |
    /// | B | `tenant()` | Good — full caps with approval gates |
    /// | C | `tenant()` | Adequate — same as B (conservative) |
    /// | D | `untrusted()` | Below average — read-only + search |
    /// | F | `airgapped()` | Poor — maximum restriction |
    pub fn from_attestation_bracket(bracket: &str) -> Self {
        match bracket.to_uppercase().as_str() {
            "A" => Self::operator(),
            "B" | "C" => Self::tenant(),
            "D" => Self::untrusted(),
            _ => Self::airgapped(), // F or unknown
        }
    }

    /// Derive a trust profile continuously from a reputation score.
    ///
    /// Instead of discrete brackets (A→operator, B→tenant, etc.), this maps
    /// the reputation score directly to a capability lattice where each
    /// operation has its own unlock threshold. No cliffs — autonomy scales
    /// smoothly with demonstrated quality.
    ///
    /// # Thresholds
    ///
    /// | Operation | Threshold | Rationale |
    /// |-----------|-----------|-----------|
    /// | read/search | 0.0 | Always safe |
    /// | web_search/fetch | 0.3 | Low risk, useful for research |
    /// | write/edit | 0.5 | Moderate — can modify files |
    /// | run_bash | 0.6 | Higher risk — arbitrary commands |
    /// | git_commit | 0.7 | Creates persistent state |
    /// | git_push/create_pr | 0.85 | Exfiltration vector |
    /// | manage_pods | 0.95 | Infrastructure control |
    ///
    /// Isolation scales inversely: high reputation = less isolation needed.
    pub fn from_reputation_score(score: f64) -> Self {
        let cap = |threshold: f64| -> CapabilityLevel {
            if score >= threshold + 0.1 {
                CapabilityLevel::Always
            } else if score >= threshold {
                CapabilityLevel::LowRisk // Approval gate in the transition zone
            } else {
                CapabilityLevel::Never
            }
        };

        let capability_ceiling = CapabilityLattice {
            read_files: CapabilityLevel::Always, // Always allowed
            glob_search: CapabilityLevel::Always,
            grep_search: CapabilityLevel::Always,
            web_search: cap(0.3),
            web_fetch: cap(0.3),
            write_files: cap(0.5),
            edit_files: cap(0.5),
            run_bash: cap(0.6),
            git_commit: cap(0.7),
            git_push: cap(0.85),
            create_pr: cap(0.85),
            manage_pods: cap(0.95),
            #[cfg(not(kani))]
            extensions: std::collections::BTreeMap::new(),
        };

        let isolation_floor = if score >= 0.9 {
            IsolationLattice::localhost()
        } else if score >= 0.7 {
            IsolationLattice::sandboxed()
        } else if score >= 0.5 {
            IsolationLattice::microvm_with_network()
        } else {
            IsolationLattice::microvm()
        };

        // Obligations: require approval for capabilities in the transition zone
        let mut obligations = Obligations::default();
        if score < 0.95 {
            obligations.approvals.insert(Operation::GitPush);
            obligations.approvals.insert(Operation::CreatePr);
        }

        Self {
            name: format!("reputation:{:.2}", score),
            capability_ceiling,
            isolation_floor,
            mandatory_obligations: obligations,
        }
    }

    /// Apply this profile as a ceiling on capabilities and a floor on isolation.
    ///
    /// Returns the restricted capabilities and the effective isolation.
    /// Also returns the merged obligations (existing + mandatory).
    pub fn enforce(
        &self,
        capabilities: &CapabilityLattice,
        isolation: &IsolationLattice,
        existing_obligations: &Obligations,
    ) -> EnforcementResult {
        // Meet: restrict capabilities to never exceed the ceiling
        let enforced_caps = capabilities.meet(&self.capability_ceiling);

        // Join: strengthen isolation to at least the floor
        let enforced_isolation = isolation.join(&self.isolation_floor);

        // Union: merge mandatory obligations with existing
        let mut merged_obligations = existing_obligations.clone();
        for op in &self.mandatory_obligations.approvals {
            merged_obligations.approvals.insert(*op);
        }

        let was_restricted = enforced_caps != *capabilities
            || enforced_isolation != *isolation
            || merged_obligations != *existing_obligations;

        EnforcementResult {
            capabilities: enforced_caps,
            isolation: enforced_isolation,
            obligations: merged_obligations,
            profile_name: self.name.clone(),
            was_restricted,
        }
    }
}

/// Result of applying a trust profile's enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementResult {
    /// Capabilities after applying the ceiling (meet).
    pub capabilities: CapabilityLattice,
    /// Isolation after applying the floor (join).
    pub isolation: IsolationLattice,
    /// Obligations after merging mandatory ones.
    pub obligations: Obligations,
    /// Name of the profile that was applied.
    pub profile_name: String,
    /// Whether any restriction was actually applied
    /// (false means the input was already within the profile).
    pub was_restricted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::{FileIsolation, NetworkIsolation, ProcessIsolation};

    #[test]
    fn operator_profile_is_permissive() {
        let profile = TrustProfile::operator();
        let caps = CapabilityLattice::permissive();
        let iso = IsolationLattice::localhost();
        let obligations = Obligations::default();

        let result = profile.enforce(&caps, &iso, &obligations);

        assert!(!result.was_restricted);
        assert_eq!(result.capabilities, caps);
        assert_eq!(result.isolation, iso);
        assert!(result.obligations.approvals.is_empty());
    }

    #[test]
    fn tenant_profile_adds_exfiltration_gates() {
        let profile = TrustProfile::tenant();
        let caps = CapabilityLattice::permissive();
        let iso = IsolationLattice::localhost();
        let obligations = Obligations::default();

        let result = profile.enforce(&caps, &iso, &obligations);

        // Capabilities unchanged (tenant ceiling is permissive)
        assert_eq!(result.capabilities, caps);

        // Isolation strengthened to at least sandboxed
        assert!(result.isolation.process >= ProcessIsolation::Namespaced);
        assert!(result.isolation.file >= FileIsolation::Sandboxed);
        assert!(result.isolation.network >= NetworkIsolation::Filtered);

        // Mandatory obligations added
        assert!(result.obligations.approvals.contains(&Operation::GitPush));
        assert!(result.obligations.approvals.contains(&Operation::CreatePr));
        assert!(result.was_restricted);
    }

    #[test]
    fn untrusted_profile_blocks_writes_and_commands() {
        let profile = TrustProfile::untrusted();
        let caps = CapabilityLattice::permissive();
        let iso = IsolationLattice::localhost();
        let obligations = Obligations::default();

        let result = profile.enforce(&caps, &iso, &obligations);

        // Write and command capabilities blocked
        assert_eq!(result.capabilities.write_files, CapabilityLevel::Never);
        assert_eq!(result.capabilities.edit_files, CapabilityLevel::Never);
        assert_eq!(result.capabilities.run_bash, CapabilityLevel::Never);
        assert_eq!(result.capabilities.git_push, CapabilityLevel::Never);
        assert_eq!(result.capabilities.create_pr, CapabilityLevel::Never);

        // Read + search preserved
        assert_eq!(result.capabilities.read_files, CapabilityLevel::Always);
        assert_eq!(result.capabilities.glob_search, CapabilityLevel::Always);
        assert_eq!(result.capabilities.grep_search, CapabilityLevel::Always);

        // Isolation strengthened to microVM
        assert_eq!(result.isolation.process, ProcessIsolation::MicroVM);
        assert_eq!(result.isolation.file, FileIsolation::ReadOnly);
        assert_eq!(result.isolation.network, NetworkIsolation::Filtered);

        assert!(result.was_restricted);
    }

    #[test]
    fn airgapped_profile_blocks_all_network_and_writes() {
        let profile = TrustProfile::airgapped();
        let caps = CapabilityLattice::permissive();
        let iso = IsolationLattice::localhost();
        let obligations = Obligations::default();

        let result = profile.enforce(&caps, &iso, &obligations);

        assert_eq!(result.capabilities.web_search, CapabilityLevel::Never);
        assert_eq!(result.capabilities.web_fetch, CapabilityLevel::Never);
        assert_eq!(result.isolation.network, NetworkIsolation::Airgapped);
        assert_eq!(result.isolation.file, FileIsolation::Ephemeral);
    }

    #[test]
    fn enforce_meet_never_exceeds_ceiling() {
        let profile = TrustProfile::untrusted();

        // Even if we pass permissive caps, enforce should cap them
        let caps = CapabilityLattice::permissive();
        let iso = IsolationLattice::sandboxed();
        let obligations = Obligations::default();

        let result = profile.enforce(&caps, &iso, &obligations);

        // Every field should be ≤ the ceiling
        assert!(result.capabilities.write_files <= profile.capability_ceiling.write_files);
        assert!(result.capabilities.run_bash <= profile.capability_ceiling.run_bash);
        assert!(result.capabilities.git_push <= profile.capability_ceiling.git_push);
    }

    #[test]
    fn enforce_join_never_weakens_isolation() {
        let profile = TrustProfile::tenant();

        // Even if we pass strong isolation, enforce should keep it
        let caps = CapabilityLattice::permissive();
        let iso = IsolationLattice::microvm();
        let obligations = Obligations::default();

        let result = profile.enforce(&caps, &iso, &obligations);

        // Isolation should be at least microvm (stronger than sandboxed floor)
        assert!(result.isolation.process >= ProcessIsolation::MicroVM);
    }

    #[test]
    fn already_restricted_input_is_not_flagged() {
        let profile = TrustProfile::untrusted();

        // Start with already-restricted capabilities and strong isolation
        let caps = CapabilityLattice::restrictive();
        let iso = IsolationLattice::microvm();
        let obligations = Obligations::default();

        let result = profile.enforce(&caps, &iso, &obligations);
        assert!(!result.was_restricted);
    }

    #[test]
    fn custom_profile_with_obligations() {
        let mut obligations = Obligations::default();
        obligations.approvals.insert(Operation::RunBash);

        let profile = TrustProfile::new(
            "custom-readonly",
            CapabilityLattice::restrictive(),
            IsolationLattice::sandboxed(),
        )
        .with_obligations(obligations);

        let caps = CapabilityLattice::permissive();
        let iso = IsolationLattice::localhost();
        let existing = Obligations::default();

        let result = profile.enforce(&caps, &iso, &existing);

        assert!(result.obligations.approvals.contains(&Operation::RunBash));
        assert!(result.was_restricted);
    }

    #[test]
    fn profile_names_are_correct() {
        assert_eq!(TrustProfile::operator().name, "operator");
        assert_eq!(TrustProfile::tenant().name, "tenant");
        assert_eq!(TrustProfile::untrusted().name, "untrusted");
        assert_eq!(TrustProfile::airgapped().name, "airgapped");
    }

    #[test]
    fn attestation_bracket_a_gets_operator() {
        let profile = TrustProfile::from_attestation_bracket("A");
        assert_eq!(profile.name, "operator");
    }

    #[test]
    fn attestation_bracket_b_gets_tenant() {
        let profile = TrustProfile::from_attestation_bracket("B");
        assert_eq!(profile.name, "tenant");

        // C also gets tenant
        let profile_c = TrustProfile::from_attestation_bracket("C");
        assert_eq!(profile_c.name, "tenant");
    }

    #[test]
    fn attestation_bracket_d_gets_untrusted() {
        let profile = TrustProfile::from_attestation_bracket("D");
        assert_eq!(profile.name, "untrusted");
    }

    #[test]
    fn attestation_bracket_f_gets_airgapped() {
        let profile = TrustProfile::from_attestation_bracket("F");
        assert_eq!(profile.name, "airgapped");

        // Unknown also gets airgapped (safe default)
        let profile_unknown = TrustProfile::from_attestation_bracket("Z");
        assert_eq!(profile_unknown.name, "airgapped");
    }

    #[test]
    fn reputation_score_smooth_scaling() {
        // Low reputation: read-only, microVM
        let low = TrustProfile::from_reputation_score(0.2);
        assert_eq!(low.capability_ceiling.read_files, CapabilityLevel::Always);
        assert_eq!(low.capability_ceiling.write_files, CapabilityLevel::Never);
        assert_eq!(low.capability_ceiling.run_bash, CapabilityLevel::Never);
        assert_eq!(low.capability_ceiling.git_push, CapabilityLevel::Never);

        // Medium reputation: can write + bash, git_commit in transition
        let mid = TrustProfile::from_reputation_score(0.72);
        assert_eq!(mid.capability_ceiling.write_files, CapabilityLevel::Always);
        assert_eq!(mid.capability_ceiling.run_bash, CapabilityLevel::Always);
        assert_eq!(mid.capability_ceiling.git_commit, CapabilityLevel::LowRisk); // In transition zone [0.7, 0.8)
        assert_eq!(mid.capability_ceiling.git_push, CapabilityLevel::Never);

        // High reputation: can push with approval
        let high = TrustProfile::from_reputation_score(0.88);
        assert_eq!(high.capability_ceiling.git_push, CapabilityLevel::LowRisk);
        assert_eq!(high.capability_ceiling.create_pr, CapabilityLevel::LowRisk);
        assert_eq!(high.capability_ceiling.manage_pods, CapabilityLevel::Never);

        // Excellent reputation: push/PR autonomous, manage_pods in transition
        let excellent = TrustProfile::from_reputation_score(0.97);
        assert_eq!(
            excellent.capability_ceiling.git_push,
            CapabilityLevel::Always
        );
        assert_eq!(
            excellent.capability_ceiling.create_pr,
            CapabilityLevel::Always
        );
        // manage_pods threshold=0.95, score=0.97 is in [0.95, 1.05) → LowRisk
        assert_eq!(
            excellent.capability_ceiling.manage_pods,
            CapabilityLevel::LowRisk
        );
    }

    #[test]
    fn reputation_score_no_cliffs() {
        // Property: from_reputation_score is a morphism of posets — the capability
        // ceiling is monotone in the score. For all s1 ≤ s2, every field of
        // from_reputation_score(s1).capability_ceiling must be ≤ the corresponding
        // field in from_reputation_score(s2).capability_ceiling (CapabilityLevel order:
        // Never ≤ LowRisk ≤ Always).
        //
        // Also verifies the cliff-free property: no single 0.01 step jumps directly
        // Never → Always. The 0.1-wide transition zone in cap() guarantees this.
        let scores: Vec<f64> = (0..=100).map(|i| i as f64 / 100.0).collect();
        for window in scores.windows(2) {
            let s1 = window[0];
            let s2 = window[1];
            assert!(s1 < s2);
            let a = TrustProfile::from_reputation_score(s1);
            let b = TrustProfile::from_reputation_score(s2);

            // Monotonicity assertion for every capability field
            macro_rules! assert_monotone {
                ($field:ident) => {
                    assert!(
                        a.capability_ceiling.$field <= b.capability_ceiling.$field,
                        "Morphism violated: {} decreased from s1={:.2} to s2={:.2}: {:?} > {:?}",
                        stringify!($field),
                        s1,
                        s2,
                        a.capability_ceiling.$field,
                        b.capability_ceiling.$field
                    );
                    // No cliff: a single 0.01 step must not jump Never → Always
                    assert!(
                        !(a.capability_ceiling.$field == CapabilityLevel::Never
                            && b.capability_ceiling.$field == CapabilityLevel::Always),
                        "Cliff detected: {} jumped Never→Always from s1={:.2} to s2={:.2}",
                        stringify!($field),
                        s1,
                        s2
                    );
                };
            }

            assert_monotone!(read_files);
            assert_monotone!(glob_search);
            assert_monotone!(grep_search);
            assert_monotone!(web_search);
            assert_monotone!(web_fetch);
            assert_monotone!(write_files);
            assert_monotone!(edit_files);
            assert_monotone!(run_bash);
            assert_monotone!(git_commit);
            assert_monotone!(git_push);
            assert_monotone!(create_pr);
            assert_monotone!(manage_pods);
        }
    }

    #[test]
    fn reputation_profile_names_include_score() {
        let p = TrustProfile::from_reputation_score(0.73);
        assert!(p.name.starts_with("reputation:"));
        assert!(p.name.contains("0.73"));
    }

    #[test]
    fn attestation_bracket_case_insensitive() {
        assert_eq!(TrustProfile::from_attestation_bracket("a").name, "operator");
        assert_eq!(TrustProfile::from_attestation_bracket("b").name, "tenant");
    }
}

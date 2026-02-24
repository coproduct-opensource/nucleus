//! Delegation chain reconstruction from audit events.
//!
//! Provides backward chain reconstruction: given a leaf agent identity,
//! walk `DelegationDecision` audit events to trace the complete permission
//! ancestry from human approval through orchestrator to leaf agent.
//!
//! # Example
//!
//! ```rust
//! use lattice_guard::audit::{AuditLog, AuditEntry, PermissionEvent};
//!
//! let log = AuditLog::in_memory();
//!
//! // Record delegation: human → orchestrator → coder
//! log.record(AuditEntry::new(
//!     "spiffe://nucleus.local/human/alice",
//!     PermissionEvent::DelegationDecision {
//!         from_identity: "spiffe://nucleus.local/human/alice".into(),
//!         to_identity: "spiffe://nucleus.local/agent/orch-001".into(),
//!         requested_description: "full".into(),
//!         granted_description: "full minus git_push".into(),
//!         was_narrowed: true,
//!         restricted_dimensions: vec!["git_push".into()],
//!     },
//! ).with_correlation_id("task-42"));
//!
//! // Reconstruct the chain
//! let chain = log.reconstruct_delegation_chain(
//!     "spiffe://nucleus.local/agent/orch-001",
//!     Some("task-42"),
//! );
//! assert!(chain.is_some());
//! ```

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

use crate::audit::{AuditEntry, AuditLog, PermissionEvent};

/// A link in a reconstructed delegation chain.
///
/// Unlike `SpiffeTraceChain` (which is built forward during delegation),
/// this is reconstructed backward from audit events for compliance queries.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DelegationLink {
    /// SPIFFE ID of the delegator (parent).
    pub from_identity: String,
    /// SPIFFE ID of the delegate (child).
    pub to_identity: String,
    /// Permissions granted at this link.
    pub granted_description: String,
    /// Whether permissions were narrowed from what was requested.
    pub was_narrowed: bool,
    /// Dimensions that were restricted.
    pub restricted_dimensions: Vec<String>,
    /// Timestamp of the delegation.
    pub timestamp: SystemTime,
    /// Sequence number of the audit entry recording this delegation.
    pub audit_sequence: u64,
}

/// A full delegation chain reconstructed from audit events.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DelegationChain {
    /// The leaf identity whose chain this represents.
    pub leaf_identity: String,
    /// The root identity (trust anchor).
    pub root_identity: Option<String>,
    /// Ordered links from root to leaf.
    pub links: Vec<DelegationLink>,
    /// Correlation ID used to bind this chain.
    pub correlation_id: Option<String>,
}

impl DelegationChain {
    /// The depth of the delegation chain (number of hops from root to leaf).
    pub fn depth(&self) -> usize {
        self.links.len()
    }

    /// Whether any link in the chain was narrowed.
    pub fn has_narrowing(&self) -> bool {
        self.links.iter().any(|l| l.was_narrowed)
    }

    /// All unique identities in the chain, from root to leaf.
    pub fn identities(&self) -> Vec<&str> {
        let mut ids = Vec::new();
        for link in &self.links {
            if ids.is_empty() || ids.last() != Some(&link.from_identity.as_str()) {
                ids.push(link.from_identity.as_str());
            }
            ids.push(link.to_identity.as_str());
        }
        ids
    }

    /// All dimensions restricted across the full chain.
    pub fn all_restricted_dimensions(&self) -> Vec<&str> {
        let mut dims: Vec<&str> = self
            .links
            .iter()
            .flat_map(|l| l.restricted_dimensions.iter().map(|s| s.as_str()))
            .collect();
        dims.sort();
        dims.dedup();
        dims
    }
}

impl AuditLog {
    /// Reconstruct the delegation chain for a given identity.
    ///
    /// Walks `DelegationDecision` events backward from the leaf identity
    /// to the root, building a complete chain. Uses correlation_id to
    /// scope the reconstruction to a specific session/task.
    ///
    /// Returns `None` if no delegation events exist for this identity.
    pub fn reconstruct_delegation_chain(
        &self,
        leaf_identity: &str,
        correlation_id: Option<&str>,
    ) -> Option<DelegationChain> {
        let entries = if let Some(cid) = correlation_id {
            self.entries_by_correlation(cid)
        } else {
            self.export()
        };

        let delegation_events: Vec<&AuditEntry> = entries
            .iter()
            .filter(|e| matches!(e.event, PermissionEvent::DelegationDecision { .. }))
            .collect();

        if delegation_events.is_empty() {
            return None;
        }

        let mut links = Vec::new();
        let mut current_identity = leaf_identity.to_string();

        loop {
            let parent_event = delegation_events.iter().rev().find(|e| {
                if let PermissionEvent::DelegationDecision { to_identity, .. } = &e.event {
                    to_identity == &current_identity
                } else {
                    false
                }
            });

            match parent_event {
                Some(entry) => {
                    if let PermissionEvent::DelegationDecision {
                        from_identity,
                        to_identity,
                        granted_description,
                        was_narrowed,
                        restricted_dimensions,
                        ..
                    } = &entry.event
                    {
                        links.push(DelegationLink {
                            from_identity: from_identity.clone(),
                            to_identity: to_identity.clone(),
                            granted_description: granted_description.clone(),
                            was_narrowed: *was_narrowed,
                            restricted_dimensions: restricted_dimensions.clone(),
                            timestamp: entry.timestamp,
                            audit_sequence: entry.sequence,
                        });
                        current_identity = from_identity.clone();
                    }
                }
                None => break,
            }

            if links.len() > 100 {
                break;
            }
        }

        links.reverse();
        let root_identity = links.first().map(|l| l.from_identity.clone());

        Some(DelegationChain {
            leaf_identity: leaf_identity.to_string(),
            root_identity,
            links,
            correlation_id: correlation_id.map(String::from),
        })
    }

    /// Get all delegation decisions for a specific identity.
    pub fn delegations_involving(&self, identity: &str) -> Vec<AuditEntry> {
        self.export()
            .into_iter()
            .filter(|e| {
                if let PermissionEvent::DelegationDecision {
                    from_identity,
                    to_identity,
                    ..
                } = &e.event
                {
                    from_identity == identity || to_identity == identity
                } else {
                    false
                }
            })
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DECISION JUSTIFICATION
// ═══════════════════════════════════════════════════════════════════════════

/// A dimension that was restricted during a meet or delegation operation.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RestrictionDetail {
    /// Which dimension was restricted (e.g., "read_files", "git_push", "budget").
    pub dimension: String,
    /// The parent/ceiling level for this dimension.
    pub parent_level: String,
    /// The requested level for this dimension.
    pub requested_level: String,
    /// The effective (granted) level for this dimension.
    pub effective_level: String,
    /// Why this dimension was restricted.
    pub reason: RestrictionReason,
}

/// Why a dimension was restricted.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RestrictionReason {
    /// Parent ceiling is more restrictive than the request.
    CeilingExceeded,
    /// Trifecta constraint demoted this capability.
    TrifectaDemotion,
    /// Budget exceeded available amount.
    BudgetExceeded,
    /// Path access narrowed (blocked paths added, allowed paths reduced).
    PathNarrowed,
    /// Command set narrowed.
    CommandNarrowed,
    /// Time window narrowed.
    TimeNarrowed,
}

/// Complete justification for a meet/delegation decision.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MeetJustification {
    /// Dimensions that were restricted.
    pub restrictions: Vec<RestrictionDetail>,
    /// Whether the trifecta constraint was applied.
    pub trifecta_applied: bool,
    /// Whether any dimension was narrowed.
    pub was_narrowed: bool,
    /// Human-readable summary of the decision.
    pub summary: String,
}

impl MeetJustification {
    /// Get the list of restricted dimension names.
    pub fn restricted_dimensions(&self) -> Vec<&str> {
        self.restrictions
            .iter()
            .map(|r| r.dimension.as_str())
            .collect()
    }
}

/// Compute the meet of two permission lattices with a detailed justification
/// explaining which dimensions were restricted and why.
///
/// This is the auditable counterpart to `PermissionLattice::meet()`.
pub fn meet_with_justification(
    parent: &crate::PermissionLattice,
    requested: &crate::PermissionLattice,
) -> (crate::PermissionLattice, MeetJustification) {
    let result = parent.meet(requested);
    let mut restrictions = Vec::new();

    // Check each capability dimension
    let cap_checks = [
        (
            "read_files",
            parent.capabilities.read_files,
            requested.capabilities.read_files,
            result.capabilities.read_files,
        ),
        (
            "write_files",
            parent.capabilities.write_files,
            requested.capabilities.write_files,
            result.capabilities.write_files,
        ),
        (
            "edit_files",
            parent.capabilities.edit_files,
            requested.capabilities.edit_files,
            result.capabilities.edit_files,
        ),
        (
            "run_bash",
            parent.capabilities.run_bash,
            requested.capabilities.run_bash,
            result.capabilities.run_bash,
        ),
        (
            "web_search",
            parent.capabilities.web_search,
            requested.capabilities.web_search,
            result.capabilities.web_search,
        ),
        (
            "web_fetch",
            parent.capabilities.web_fetch,
            requested.capabilities.web_fetch,
            result.capabilities.web_fetch,
        ),
        (
            "git_push",
            parent.capabilities.git_push,
            requested.capabilities.git_push,
            result.capabilities.git_push,
        ),
        (
            "create_pr",
            parent.capabilities.create_pr,
            requested.capabilities.create_pr,
            result.capabilities.create_pr,
        ),
    ];

    for &(name, parent_level, requested_level, effective_level) in &cap_checks {
        if effective_level < requested_level {
            let reason = if effective_level < parent_level.min(requested_level) {
                RestrictionReason::TrifectaDemotion
            } else {
                RestrictionReason::CeilingExceeded
            };
            restrictions.push(RestrictionDetail {
                dimension: name.to_string(),
                parent_level: format!("{:?}", parent_level),
                requested_level: format!("{:?}", requested_level),
                effective_level: format!("{:?}", effective_level),
                reason,
            });
        }
    }

    // Check budget
    if result.budget.max_cost_usd < requested.budget.max_cost_usd {
        restrictions.push(RestrictionDetail {
            dimension: "budget".to_string(),
            parent_level: format!("{}", parent.budget.max_cost_usd),
            requested_level: format!("{}", requested.budget.max_cost_usd),
            effective_level: format!("{}", result.budget.max_cost_usd),
            reason: RestrictionReason::BudgetExceeded,
        });
    }

    let trifecta_applied = (parent.trifecta_constraint || requested.trifecta_constraint)
        && result.is_trifecta_vulnerable();
    let was_narrowed = !restrictions.is_empty();

    let summary = if restrictions.is_empty() {
        "All requested permissions granted without restriction".to_string()
    } else {
        let dims: Vec<&str> = restrictions.iter().map(|r| r.dimension.as_str()).collect();
        format!(
            "{} dimension(s) restricted: {}{}",
            restrictions.len(),
            dims.join(", "),
            if trifecta_applied {
                " (trifecta constraint active)"
            } else {
                ""
            }
        )
    };

    let justification = MeetJustification {
        restrictions,
        trifecta_applied,
        was_narrowed,
        summary,
    };

    (result, justification)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delegation_chain_reconstruction() {
        let log = AuditLog::in_memory();
        let cid = "task-123";

        // Human → Orchestrator
        log.record(
            AuditEntry::new(
                "spiffe://test/human/alice",
                PermissionEvent::DelegationDecision {
                    from_identity: "spiffe://test/human/alice".into(),
                    to_identity: "spiffe://test/agent/orchestrator".into(),
                    requested_description: "full".into(),
                    granted_description: "full minus git_push".into(),
                    was_narrowed: true,
                    restricted_dimensions: vec!["git_push".into()],
                },
            )
            .with_correlation_id(cid),
        );

        // Orchestrator → Coder
        log.record(
            AuditEntry::new(
                "spiffe://test/agent/orchestrator",
                PermissionEvent::DelegationDecision {
                    from_identity: "spiffe://test/agent/orchestrator".into(),
                    to_identity: "spiffe://test/agent/coder-042".into(),
                    requested_description: "codegen".into(),
                    granted_description: "codegen minus web_fetch".into(),
                    was_narrowed: true,
                    restricted_dimensions: vec!["web_fetch".into()],
                },
            )
            .with_correlation_id(cid),
        );

        let chain = log
            .reconstruct_delegation_chain("spiffe://test/agent/coder-042", Some(cid))
            .unwrap();
        assert_eq!(chain.depth(), 2);
        assert_eq!(
            chain.root_identity.as_deref(),
            Some("spiffe://test/human/alice")
        );
        assert_eq!(chain.leaf_identity, "spiffe://test/agent/coder-042");
        assert!(chain.has_narrowing());
        assert_eq!(
            chain.all_restricted_dimensions(),
            vec!["git_push", "web_fetch"]
        );
        assert_eq!(chain.identities().len(), 3);
    }

    #[test]
    fn test_no_delegations_returns_none() {
        let log = AuditLog::in_memory();
        assert!(log
            .reconstruct_delegation_chain("spiffe://test/agent/unknown", None)
            .is_none());
    }

    #[test]
    fn test_delegations_involving() {
        let log = AuditLog::in_memory();
        log.record(AuditEntry::new(
            "spiffe://test/agent/orch",
            PermissionEvent::DelegationDecision {
                from_identity: "spiffe://test/agent/orch".into(),
                to_identity: "spiffe://test/agent/coder".into(),
                requested_description: "codegen".into(),
                granted_description: "codegen".into(),
                was_narrowed: false,
                restricted_dimensions: vec![],
            },
        ));

        assert_eq!(
            log.delegations_involving("spiffe://test/agent/orch").len(),
            1
        );
        assert_eq!(
            log.delegations_involving("spiffe://test/agent/coder").len(),
            1
        );
        assert_eq!(
            log.delegations_involving("spiffe://test/agent/other").len(),
            0
        );
    }

    #[test]
    fn test_single_hop_chain() {
        let log = AuditLog::in_memory();
        log.record(AuditEntry::new(
            "spiffe://test/human/bob",
            PermissionEvent::DelegationDecision {
                from_identity: "spiffe://test/human/bob".into(),
                to_identity: "spiffe://test/agent/reviewer".into(),
                requested_description: "review".into(),
                granted_description: "review".into(),
                was_narrowed: false,
                restricted_dimensions: vec![],
            },
        ));

        let chain = log
            .reconstruct_delegation_chain("spiffe://test/agent/reviewer", None)
            .unwrap();
        assert_eq!(chain.depth(), 1);
        assert!(!chain.has_narrowing());
        assert!(chain.all_restricted_dimensions().is_empty());
    }

    #[test]
    fn test_chain_without_correlation_id() {
        let log = AuditLog::in_memory();

        log.record(AuditEntry::new(
            "spiffe://test/sys",
            PermissionEvent::DelegationDecision {
                from_identity: "spiffe://test/sys".into(),
                to_identity: "spiffe://test/agent/a".into(),
                requested_description: "all".into(),
                granted_description: "all".into(),
                was_narrowed: false,
                restricted_dimensions: vec![],
            },
        ));

        // Without correlation_id, searches all events
        let chain = log
            .reconstruct_delegation_chain("spiffe://test/agent/a", None)
            .unwrap();
        assert_eq!(chain.depth(), 1);
    }

    #[test]
    fn test_meet_with_justification_no_restriction() {
        let a = crate::PermissionLattice::permissive();
        let b = crate::PermissionLattice::permissive();
        let (_result, justification) = meet_with_justification(&a, &b);
        assert!(!justification.was_narrowed);
        assert!(justification.restrictions.is_empty());
        assert!(justification.summary.contains("without restriction"));
    }

    #[test]
    fn test_meet_with_justification_ceiling_exceeded() {
        let mut parent = crate::PermissionLattice::permissive();
        parent.capabilities.git_push = crate::CapabilityLevel::Never;

        let requested = crate::PermissionLattice::permissive();
        let (_result, justification) = meet_with_justification(&parent, &requested);
        assert!(justification.was_narrowed);
        assert!(justification.restricted_dimensions().contains(&"git_push"));
        assert!(justification.summary.contains("restricted"));
    }
}

//! SPIFFE trace chains for agent provenance and escalation.
//!
//! This module implements a provenance-based escalation model where permissions
//! flow through a chain of SPIFFE identities. Each link in the chain represents
//! a delegation or escalation event, cryptographically timestamped via drand.
//!
//! # Key Concepts
//!
//! ## Trace Chains
//!
//! A trace chain captures the causal history of how an agent came to have
//! certain permissions:
//!
//! ```text
//! spiffe://nucleus.local/human/alice
//!   └─► spiffe://nucleus.local/agent/orchestrator-001
//!         └─► spiffe://nucleus.local/agent/coder-042
//! ```
//!
//! ## Ceiling Theorem
//!
//! An agent's effective permissions can never exceed the meet of all
//! permissions in their trace chain:
//!
//! ```text
//! ∀ agent: effective_perms(agent) ≤ ceiling(trace_chain(agent))
//! ```
//!
//! ## Escalation
//!
//! Escalation allows an agent to request elevated permissions, but only
//! up to the ceiling defined by an approver's own trace chain.
//!
//! # Example
//!
//! ```
//! use lattice_guard::escalation::{SpiffeTraceChain, SpiffeTraceLink, EscalationRequest};
//! use lattice_guard::PermissionLattice;
//!
//! // Create a chain starting from a human root
//! let mut chain = SpiffeTraceChain::new_root(
//!     "spiffe://nucleus.local/human/alice",
//!     PermissionLattice::permissive(),
//!     12345, // drand round
//! );
//!
//! // Delegate to an orchestrator with reduced permissions
//! chain.extend(SpiffeTraceLink::new(
//!     "spiffe://nucleus.local/agent/orchestrator-001",
//!     PermissionLattice::codegen(),
//!     12346,
//! ));
//!
//! // Verify the chain is valid
//! assert!(chain.verify());
//!
//! // Compute the ceiling
//! let ceiling = chain.ceiling();
//! ```

use chrono::{DateTime, Duration, Utc};
use uuid::Uuid;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::identity::SpiffeIdMatcher;
use crate::PermissionLattice;

/// A link in the SPIFFE provenance chain.
///
/// Each link represents a delegation or escalation event from one identity
/// to another, with permissions bounded by the parent's capabilities.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SpiffeTraceLink {
    /// Unique identifier for this link
    pub id: Uuid,
    /// The SPIFFE ID at this point in the chain
    pub spiffe_id: String,
    /// Permissions granted at this link (must be ≤ parent's permissions)
    pub permissions: PermissionLattice,
    /// Drand round when this link was created (cryptographic timestamp)
    pub drand_round: u64,
    /// When this link was created
    pub created_at: DateTime<Utc>,
    /// When this link expires (if set)
    pub expires_at: Option<DateTime<Utc>>,
    /// Optional attestation data (e.g., signature from parent)
    #[cfg_attr(feature = "serde", serde(default))]
    pub attestation: Vec<u8>,
    /// Reason for this delegation/escalation
    pub reason: String,
}

impl SpiffeTraceLink {
    /// Create a new trace link.
    pub fn new(
        spiffe_id: impl Into<String>,
        permissions: PermissionLattice,
        drand_round: u64,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            spiffe_id: spiffe_id.into(),
            permissions,
            drand_round,
            created_at: Utc::now(),
            expires_at: None,
            attestation: Vec::new(),
            reason: String::new(),
        }
    }

    /// Create a link with a TTL.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.expires_at = Some(Utc::now() + ttl);
        self
    }

    /// Create a link with an expiration time.
    pub fn with_expiry(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Create a link with a reason.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }

    /// Create a link with attestation data.
    ///
    /// The attestation should be a signature over the canonical message:
    /// `{parent_spiffe_id}|{child_spiffe_id}|{drand_round}|{permissions_hash}`
    pub fn with_attestation(mut self, attestation: Vec<u8>) -> Self {
        self.attestation = attestation;
        self
    }

    /// Check if this link has expired.
    pub fn is_expired(&self) -> bool {
        self.expires_at.map(|e| Utc::now() > e).unwrap_or(false)
    }

    /// Check if this link is currently valid.
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && self.permissions.is_valid()
    }

    /// Check if this link has attestation data.
    pub fn has_attestation(&self) -> bool {
        !self.attestation.is_empty()
    }

    /// Compute the canonical message that should be signed for attestation.
    ///
    /// Format: `{spiffe_id}|{drand_round}|{permissions_description}`
    ///
    /// This provides a deterministic representation of the link contents
    /// that can be verified against the attestation signature.
    pub fn canonical_attestation_message(&self) -> Vec<u8> {
        format!(
            "{}|{}|{}",
            self.spiffe_id, self.drand_round, self.permissions.description
        )
        .into_bytes()
    }
}

/// Full provenance chain from root to current agent.
///
/// The chain captures the complete delegation history, allowing:
/// - Ceiling computation via the meet of all permissions
/// - Verification that each link is bounded by its parent
/// - Revocation propagation (if any link is revoked, chain is invalid)
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SpiffeTraceChain {
    /// Unique identifier for this chain
    pub id: Uuid,
    /// Ordered links from root (human/system) to leaf (current agent)
    pub links: Vec<SpiffeTraceLink>,
}

impl SpiffeTraceChain {
    /// Create a new chain with a root link.
    ///
    /// The root is typically a human identity or system bootstrap identity
    /// that serves as the trust anchor for the chain.
    pub fn new_root(
        spiffe_id: impl Into<String>,
        permissions: PermissionLattice,
        drand_round: u64,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            links: vec![SpiffeTraceLink::new(spiffe_id, permissions, drand_round)],
        }
    }

    /// Create an empty chain (for testing or special cases).
    pub fn empty() -> Self {
        Self {
            id: Uuid::new_v4(),
            links: Vec::new(),
        }
    }

    /// Extend the chain with a new link.
    ///
    /// The new link's permissions are automatically bounded by the current ceiling.
    pub fn extend(&mut self, mut link: SpiffeTraceLink) {
        // Ensure the new link's permissions don't exceed the ceiling
        if let Some(ceiling) = self.ceiling() {
            link.permissions = ceiling.meet(&link.permissions);
        }
        self.links.push(link);
    }

    /// Try to extend the chain, returning an error if permissions exceed ceiling.
    pub fn try_extend(&mut self, link: SpiffeTraceLink) -> Result<(), EscalationError> {
        if let Some(ceiling) = self.ceiling() {
            if !link.permissions.leq(&ceiling) {
                return Err(EscalationError::ExceedsCeiling {
                    requested: link.permissions.description.clone(),
                    ceiling: ceiling.description.clone(),
                });
            }
        }
        self.links.push(link);
        Ok(())
    }

    /// Compute the ceiling - the meet of all permissions in the chain.
    ///
    /// Returns `None` if the chain is empty.
    pub fn ceiling(&self) -> Option<PermissionLattice> {
        if self.links.is_empty() {
            return None;
        }

        let mut result = self.links[0].permissions.clone();
        for link in &self.links[1..] {
            result = result.meet(&link.permissions);
        }
        Some(result)
    }

    /// Verify the chain is valid.
    ///
    /// A chain is valid if:
    /// 1. Each link's permissions are ≤ the parent's permissions
    /// 2. No links have expired
    /// 3. The chain is non-empty
    pub fn verify(&self) -> bool {
        if self.links.is_empty() {
            return false;
        }

        // Check no links are expired
        if self.links.iter().any(|l| l.is_expired()) {
            return false;
        }

        // Check monotonicity: each link ≤ parent
        self.links
            .windows(2)
            .all(|w| w[1].permissions.leq(&w[0].permissions))
    }

    /// Get detailed verification result.
    pub fn verify_detailed(&self) -> ChainVerificationResult {
        if self.links.is_empty() {
            return ChainVerificationResult::Invalid {
                reason: "Chain is empty".to_string(),
                failed_link_index: None,
            };
        }

        // Check for expired links
        for (i, link) in self.links.iter().enumerate() {
            if link.is_expired() {
                return ChainVerificationResult::Invalid {
                    reason: format!("Link {} has expired", i),
                    failed_link_index: Some(i),
                };
            }
        }

        // Check monotonicity
        for (i, window) in self.links.windows(2).enumerate() {
            if !window[1].permissions.leq(&window[0].permissions) {
                return ChainVerificationResult::Invalid {
                    reason: format!("Link {} exceeds parent permissions at link {}", i + 1, i),
                    failed_link_index: Some(i + 1),
                };
            }
        }

        ChainVerificationResult::Valid {
            ceiling: Box::new(self.ceiling().unwrap()),
            depth: self.links.len(),
        }
    }

    /// Get the root (first) link in the chain.
    pub fn root(&self) -> Option<&SpiffeTraceLink> {
        self.links.first()
    }

    /// Get the leaf (last) link in the chain.
    pub fn leaf(&self) -> Option<&SpiffeTraceLink> {
        self.links.last()
    }

    /// Get the current SPIFFE ID (leaf identity).
    pub fn current_spiffe_id(&self) -> Option<&str> {
        self.leaf().map(|l| l.spiffe_id.as_str())
    }

    /// Get the root SPIFFE ID (trust anchor).
    pub fn root_spiffe_id(&self) -> Option<&str> {
        self.root().map(|l| l.spiffe_id.as_str())
    }

    /// Get the chain depth (number of links).
    pub fn depth(&self) -> usize {
        self.links.len()
    }

    /// Check if a SPIFFE ID pattern appears anywhere in the chain.
    pub fn contains_pattern(&self, pattern: &str) -> bool {
        if let Some(matcher) = SpiffeIdMatcher::try_new(pattern) {
            self.links.iter().any(|l| matcher.matches(&l.spiffe_id))
        } else {
            false
        }
    }

    /// Check if an exact SPIFFE ID appears anywhere in the chain.
    ///
    /// Unlike `contains_pattern`, this performs an exact string match,
    /// not glob pattern matching. Used for security-critical identity checks.
    pub fn contains_spiffe_id(&self, spiffe_id: &str) -> bool {
        self.links.iter().any(|l| l.spiffe_id == spiffe_id)
    }

    /// Find the most recent drand round in the chain.
    pub fn latest_drand_round(&self) -> Option<u64> {
        self.links.iter().map(|l| l.drand_round).max()
    }

    /// Check if all links in the chain have attestation data.
    ///
    /// SECURITY: A chain without attestation should be treated as untrusted
    /// and may only be used for logging/debugging purposes.
    pub fn has_complete_attestation(&self) -> bool {
        // Root link doesn't need attestation (it's the trust anchor)
        // All subsequent links must have attestation
        self.links.iter().skip(1).all(|l| l.has_attestation())
    }

    /// Get the attestation status for audit logging.
    pub fn attestation_status(&self) -> AttestationStatus {
        if self.links.is_empty() {
            return AttestationStatus::Empty;
        }

        let attested_count = self
            .links
            .iter()
            .skip(1)
            .filter(|l| l.has_attestation())
            .count();
        let required_count = self.links.len().saturating_sub(1);

        if required_count == 0 {
            AttestationStatus::RootOnly
        } else if attested_count == required_count {
            AttestationStatus::Complete
        } else if attested_count == 0 {
            AttestationStatus::None
        } else {
            AttestationStatus::Partial {
                attested: attested_count,
                required: required_count,
            }
        }
    }
}

/// Attestation status of a trace chain.
#[derive(Debug, Clone, PartialEq)]
pub enum AttestationStatus {
    /// Chain is empty (no links)
    Empty,
    /// Chain has only a root link (no attestation needed)
    RootOnly,
    /// All non-root links have attestation
    Complete,
    /// No non-root links have attestation
    None,
    /// Some non-root links have attestation
    Partial {
        /// Number of attested links
        attested: usize,
        /// Number of links requiring attestation
        required: usize,
    },
}

/// Result of chain verification.
#[derive(Debug, Clone)]
pub enum ChainVerificationResult {
    /// Chain is valid
    Valid {
        /// The computed ceiling permissions (boxed to reduce enum size)
        ceiling: Box<PermissionLattice>,
        /// Chain depth
        depth: usize,
    },
    /// Chain is invalid
    Invalid {
        /// Reason for invalidity
        reason: String,
        /// Index of the failed link (if applicable)
        failed_link_index: Option<usize>,
    },
}

impl ChainVerificationResult {
    /// Check if the result is valid.
    pub fn is_valid(&self) -> bool {
        matches!(self, ChainVerificationResult::Valid { .. })
    }
}

/// An escalation request from an agent.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EscalationRequest {
    /// Unique identifier for this request
    pub id: Uuid,
    /// The requesting agent's full provenance chain
    pub requestor_chain: SpiffeTraceChain,
    /// Requested permissions (must be ≤ some approver's ceiling)
    pub requested: PermissionLattice,
    /// Justification for the escalation
    pub reason: String,
    /// TTL for the escalated permissions (in seconds)
    pub ttl_seconds: u64,
    /// When this request was created
    pub created_at: DateTime<Utc>,
    /// When this request expires (requests have a limited window)
    pub expires_at: DateTime<Utc>,
}

impl EscalationRequest {
    /// Create a new escalation request.
    pub fn new(
        requestor_chain: SpiffeTraceChain,
        requested: PermissionLattice,
        reason: impl Into<String>,
        ttl_seconds: u64,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            requestor_chain,
            requested,
            reason: reason.into(),
            ttl_seconds,
            created_at: now,
            // Requests are valid for 5 minutes by default
            expires_at: now + Duration::minutes(5),
        }
    }

    /// Set custom request expiry.
    pub fn with_request_expiry(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = expires_at;
        self
    }

    /// Check if this request has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Validate the request.
    pub fn validate(&self) -> Result<(), EscalationError> {
        if self.is_expired() {
            return Err(EscalationError::RequestExpired);
        }

        if !self.requestor_chain.verify() {
            return Err(EscalationError::InvalidRequestorChain);
        }

        if self.ttl_seconds == 0 {
            return Err(EscalationError::InvalidTtl);
        }

        Ok(())
    }
}

/// An escalation grant from an approver.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EscalationGrant {
    /// Unique identifier for this grant
    pub id: Uuid,
    /// The original request ID
    pub request_id: Uuid,
    /// The approver's provenance chain
    pub approver_chain: SpiffeTraceChain,
    /// The granted permissions (≤ approver's ceiling, ≤ requested)
    pub granted: PermissionLattice,
    /// The new chain for the escalated agent
    pub escalated_chain: SpiffeTraceChain,
    /// Drand round of the grant (cryptographic timestamp)
    pub drand_round: u64,
    /// When this grant was created
    pub created_at: DateTime<Utc>,
    /// When this grant expires
    pub expires_at: DateTime<Utc>,
}

impl EscalationGrant {
    /// Create a new escalation grant.
    ///
    /// This verifies that:
    /// 1. The approver's chain is valid
    /// 2. The granted permissions don't exceed the approver's ceiling
    /// 3. The granted permissions don't exceed what was requested
    pub fn new(
        request: &EscalationRequest,
        approver_chain: SpiffeTraceChain,
        drand_round: u64,
    ) -> Result<Self, EscalationError> {
        // Validate request
        request.validate()?;

        // Validate approver chain
        if !approver_chain.verify() {
            return Err(EscalationError::InvalidApproverChain);
        }

        let approver_ceiling = approver_chain
            .ceiling()
            .ok_or(EscalationError::InvalidApproverChain)?;

        // Compute granted permissions: min(requested, approver_ceiling)
        let granted = request.requested.meet(&approver_ceiling);

        // Build the new escalated chain
        let mut escalated_chain = request.requestor_chain.clone();
        escalated_chain.id = Uuid::new_v4();

        // Add a new link for the escalation
        let escalation_link = SpiffeTraceLink::new(
            request
                .requestor_chain
                .current_spiffe_id()
                .unwrap_or("unknown"),
            granted.clone(),
            drand_round,
        )
        .with_ttl(Duration::seconds(request.ttl_seconds as i64))
        .with_reason(format!(
            "Escalation approved by {}",
            approver_chain.current_spiffe_id().unwrap_or("unknown")
        ));

        escalated_chain.extend(escalation_link);

        let now = Utc::now();
        let expires_at = now + Duration::seconds(request.ttl_seconds as i64);

        Ok(Self {
            id: Uuid::new_v4(),
            request_id: request.id,
            approver_chain,
            granted,
            escalated_chain,
            drand_round,
            created_at: now,
            expires_at,
        })
    }

    /// Check if this grant has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if this grant is currently valid.
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && self.escalated_chain.verify()
    }
}

/// Escalation policy defining who can approve escalations.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EscalationPolicy {
    /// Pattern matching requestors who can use this policy
    pub requestor_pattern: String,
    /// Pattern matching approvers who can grant escalations
    pub approver_pattern: String,
    /// Maximum permissions that can be granted via this policy
    pub max_grant: PermissionLattice,
    /// Maximum TTL in seconds for grants under this policy
    pub max_ttl_seconds: u64,
    /// Whether this policy requires the approver to be in a different chain
    /// (prevents self-escalation)
    pub require_distinct_chains: bool,
    /// Whether this policy requires complete attestation on all chains.
    ///
    /// SECURITY: When true, chains without complete attestation are REJECTED,
    /// not just logged. This is the recommended setting for production.
    /// Default: true
    pub require_attestation: bool,
    /// Human-readable description of this policy
    pub description: String,
}

impl EscalationPolicy {
    /// Create a new escalation policy.
    ///
    /// By default, attestation is REQUIRED. Set `with_attestation(false)` to
    /// allow unattested chains (NOT recommended for production).
    pub fn new(
        requestor_pattern: impl Into<String>,
        approver_pattern: impl Into<String>,
        max_grant: PermissionLattice,
    ) -> Self {
        Self {
            requestor_pattern: requestor_pattern.into(),
            approver_pattern: approver_pattern.into(),
            max_grant,
            max_ttl_seconds: 3600, // 1 hour default
            require_distinct_chains: true,
            require_attestation: true, // SECURE DEFAULT
            description: String::new(),
        }
    }

    /// Set maximum TTL.
    pub fn with_max_ttl(mut self, seconds: u64) -> Self {
        self.max_ttl_seconds = seconds;
        self
    }

    /// Set whether distinct chains are required.
    pub fn with_distinct_chains(mut self, required: bool) -> Self {
        self.require_distinct_chains = required;
        self
    }

    /// Set whether attestation is required.
    ///
    /// SECURITY WARNING: Setting this to false allows unattested chains,
    /// which cannot be cryptographically verified. Only disable for testing
    /// or development environments.
    pub fn with_attestation(mut self, required: bool) -> Self {
        self.require_attestation = required;
        self
    }

    /// Set description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Check if a requestor matches this policy.
    pub fn matches_requestor(&self, spiffe_id: &str) -> bool {
        SpiffeIdMatcher::try_new(&self.requestor_pattern)
            .map(|m| m.matches(spiffe_id))
            .unwrap_or(false)
    }

    /// Check if an approver matches this policy.
    pub fn matches_approver(&self, spiffe_id: &str) -> bool {
        SpiffeIdMatcher::try_new(&self.approver_pattern)
            .map(|m| m.matches(spiffe_id))
            .unwrap_or(false)
    }

    /// Validate an escalation request against this policy.
    pub fn validate_request(
        &self,
        request: &EscalationRequest,
        approver_chain: &SpiffeTraceChain,
    ) -> Result<(), EscalationError> {
        // SECURITY: Check attestation status FIRST and ENFORCE if required
        let requestor_attestation = request.requestor_chain.attestation_status();
        let approver_attestation = approver_chain.attestation_status();

        // Helper to format attestation status for errors
        fn format_attestation_status(status: &AttestationStatus) -> String {
            match status {
                AttestationStatus::Empty => "empty".to_string(),
                AttestationStatus::RootOnly => "root_only".to_string(),
                AttestationStatus::Complete => "complete".to_string(),
                AttestationStatus::None => "none".to_string(),
                AttestationStatus::Partial { attested, required } => {
                    format!("partial({}/{})", attested, required)
                }
            }
        }

        // SECURITY: When attestation is required, REJECT unattested chains
        // This is the critical fix - previously we only logged warnings
        if self.require_attestation {
            // Check requestor chain attestation
            match &requestor_attestation {
                AttestationStatus::None | AttestationStatus::Partial { .. } => {
                    tracing::warn!(
                        chain_id = %request.requestor_chain.id,
                        attestation_status = %format_attestation_status(&requestor_attestation),
                        policy_requires_attestation = true,
                        "REJECTING: requestor chain does not have complete attestation"
                    );
                    return Err(EscalationError::AttestationRequired {
                        chain_type: "requestor".to_string(),
                        status: format_attestation_status(&requestor_attestation),
                    });
                }
                AttestationStatus::Empty => {
                    // Empty chains are handled by InvalidRequestorChain later
                }
                AttestationStatus::RootOnly | AttestationStatus::Complete => {
                    // These are acceptable
                }
            }

            // Check approver chain attestation
            match &approver_attestation {
                AttestationStatus::None | AttestationStatus::Partial { .. } => {
                    tracing::warn!(
                        chain_id = %approver_chain.id,
                        attestation_status = %format_attestation_status(&approver_attestation),
                        policy_requires_attestation = true,
                        "REJECTING: approver chain does not have complete attestation"
                    );
                    return Err(EscalationError::AttestationRequired {
                        chain_type: "approver".to_string(),
                        status: format_attestation_status(&approver_attestation),
                    });
                }
                AttestationStatus::Empty => {
                    // Empty chains are handled by InvalidApproverChain later
                }
                AttestationStatus::RootOnly | AttestationStatus::Complete => {
                    // These are acceptable
                }
            }
        } else {
            // Attestation not required - log warnings but don't reject
            match &requestor_attestation {
                AttestationStatus::None => {
                    tracing::warn!(
                        chain_id = %request.requestor_chain.id,
                        policy_requires_attestation = false,
                        "requestor chain has no attestation - allowing due to policy"
                    );
                }
                AttestationStatus::Partial { attested, required } => {
                    tracing::warn!(
                        chain_id = %request.requestor_chain.id,
                        attested = %attested,
                        required = %required,
                        policy_requires_attestation = false,
                        "requestor chain has partial attestation - allowing due to policy"
                    );
                }
                _ => {}
            }

            match &approver_attestation {
                AttestationStatus::None => {
                    tracing::warn!(
                        chain_id = %approver_chain.id,
                        policy_requires_attestation = false,
                        "approver chain has no attestation - allowing due to policy"
                    );
                }
                AttestationStatus::Partial { attested, required } => {
                    tracing::warn!(
                        chain_id = %approver_chain.id,
                        attested = %attested,
                        required = %required,
                        policy_requires_attestation = false,
                        "approver chain has partial attestation - allowing due to policy"
                    );
                }
                _ => {}
            }
        }

        // Check requestor matches
        let requestor_id = request
            .requestor_chain
            .current_spiffe_id()
            .ok_or(EscalationError::InvalidRequestorChain)?;

        if !self.matches_requestor(requestor_id) {
            return Err(EscalationError::PolicyMismatch {
                reason: "Requestor does not match policy pattern".to_string(),
            });
        }

        // Check approver matches
        let approver_id = approver_chain
            .current_spiffe_id()
            .ok_or(EscalationError::InvalidApproverChain)?;

        if !self.matches_approver(approver_id) {
            return Err(EscalationError::PolicyMismatch {
                reason: "Approver does not match policy pattern".to_string(),
            });
        }

        // SECURITY: Check distinct chains FIRST (before permission checks)
        // This prevents self-escalation attacks where an agent tries to approve itself
        if self.require_distinct_chains {
            // Check 1: No identity in the requestor's chain can appear in the approver's chain
            // This is a STRICT intersection check - any overlap is forbidden
            for requestor_link in &request.requestor_chain.links {
                if approver_chain.contains_spiffe_id(&requestor_link.spiffe_id) {
                    return Err(EscalationError::SelfEscalation);
                }
            }

            // Check 2: No identity in the approver's chain can appear in the requestor's chain
            // This handles the symmetric case where approver is in requestor's lineage
            for approver_link in &approver_chain.links {
                if request
                    .requestor_chain
                    .contains_spiffe_id(&approver_link.spiffe_id)
                {
                    return Err(EscalationError::SelfEscalation);
                }
            }

            // Check 3: Verify the chains have different trust roots
            // Even with no direct overlap, shared roots indicate potential collusion
            let requestor_root = request.requestor_chain.root_spiffe_id();
            let approver_root = approver_chain.root_spiffe_id();
            if requestor_root.is_some() && requestor_root == approver_root {
                // Same trust root - additional scrutiny required
                // For now, we allow this if identities are distinct (checked above)
                // but log a warning for auditing
                tracing::warn!(
                    requestor_root = ?requestor_root,
                    approver_root = ?approver_root,
                    "escalation with shared trust root - identities verified distinct"
                );
            }
        }

        // Check TTL doesn't exceed policy maximum
        if request.ttl_seconds > self.max_ttl_seconds {
            return Err(EscalationError::TtlExceedsPolicy {
                requested: request.ttl_seconds,
                max: self.max_ttl_seconds,
            });
        }

        // Check requested permissions don't exceed policy maximum
        // We compare capabilities rather than full leq to avoid obligation-based false positives
        if !request
            .requested
            .capabilities
            .leq(&self.max_grant.capabilities)
        {
            return Err(EscalationError::ExceedsPolicyMax);
        }

        Ok(())
    }
}

/// A set of escalation policies.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EscalationPolicySet {
    /// Ordered list of policies. First matching policy is used.
    pub policies: Vec<EscalationPolicy>,
}

impl EscalationPolicySet {
    /// Create a new empty policy set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a policy to the set.
    pub fn add_policy(&mut self, policy: EscalationPolicy) {
        self.policies.push(policy);
    }

    /// Find the first matching policy for a request.
    pub fn find_policy(
        &self,
        request: &EscalationRequest,
        approver_chain: &SpiffeTraceChain,
    ) -> Option<&EscalationPolicy> {
        let requestor_id = request.requestor_chain.current_spiffe_id()?;
        let approver_id = approver_chain.current_spiffe_id()?;

        self.policies
            .iter()
            .find(|p| p.matches_requestor(requestor_id) && p.matches_approver(approver_id))
    }

    /// Validate and find a policy for an escalation.
    pub fn validate_escalation(
        &self,
        request: &EscalationRequest,
        approver_chain: &SpiffeTraceChain,
    ) -> Result<&EscalationPolicy, EscalationError> {
        let policy = self
            .find_policy(request, approver_chain)
            .ok_or(EscalationError::NoMatchingPolicy)?;

        policy.validate_request(request, approver_chain)?;

        Ok(policy)
    }
}

/// Errors that can occur during escalation.
#[derive(Debug, Clone, PartialEq)]
pub enum EscalationError {
    /// The escalation request has expired
    RequestExpired,
    /// The requestor's chain is invalid
    InvalidRequestorChain,
    /// The approver's chain is invalid
    InvalidApproverChain,
    /// Requested permissions exceed the approver's ceiling
    ExceedsCeiling {
        /// What was requested
        requested: String,
        /// The ceiling that was exceeded
        ceiling: String,
    },
    /// Requested permissions exceed the policy maximum
    ExceedsPolicyMax,
    /// TTL exceeds policy maximum
    TtlExceedsPolicy {
        /// Requested TTL
        requested: u64,
        /// Maximum allowed TTL
        max: u64,
    },
    /// No matching escalation policy found
    NoMatchingPolicy,
    /// Request/approver doesn't match policy patterns
    PolicyMismatch {
        /// Reason for mismatch
        reason: String,
    },
    /// Attempted self-escalation (approver is in requestor's chain)
    SelfEscalation,
    /// Invalid TTL (zero or negative)
    InvalidTtl,
    /// Chain verification failed
    ChainVerificationFailed {
        /// Reason for failure
        reason: String,
    },
    /// Attestation required but chain is not fully attested
    AttestationRequired {
        /// Which chain is missing attestation
        chain_type: String,
        /// Current attestation status
        status: String,
    },
}

impl std::fmt::Display for EscalationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RequestExpired => write!(f, "Escalation request has expired"),
            Self::InvalidRequestorChain => write!(f, "Requestor's trace chain is invalid"),
            Self::InvalidApproverChain => write!(f, "Approver's trace chain is invalid"),
            Self::ExceedsCeiling { requested, ceiling } => {
                write!(
                    f,
                    "Requested permissions '{}' exceed ceiling '{}'",
                    requested, ceiling
                )
            }
            Self::ExceedsPolicyMax => {
                write!(f, "Requested permissions exceed policy maximum")
            }
            Self::TtlExceedsPolicy { requested, max } => {
                write!(
                    f,
                    "Requested TTL ({} seconds) exceeds policy maximum ({} seconds)",
                    requested, max
                )
            }
            Self::NoMatchingPolicy => write!(f, "No matching escalation policy found"),
            Self::PolicyMismatch { reason } => write!(f, "Policy mismatch: {}", reason),
            Self::SelfEscalation => {
                write!(
                    f,
                    "Self-escalation not allowed: approver is in requestor's chain"
                )
            }
            Self::InvalidTtl => write!(f, "Invalid TTL: must be positive"),
            Self::ChainVerificationFailed { reason } => {
                write!(f, "Chain verification failed: {}", reason)
            }
            Self::AttestationRequired { chain_type, status } => {
                write!(
                    f,
                    "Attestation required but {} chain has status: {}",
                    chain_type, status
                )
            }
        }
    }
}

impl std::error::Error for EscalationError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_chain(spiffe_ids: &[&str], base_perms: PermissionLattice) -> SpiffeTraceChain {
        let mut chain = SpiffeTraceChain::new_root(spiffe_ids[0], base_perms.clone(), 1000);
        for (i, id) in spiffe_ids.iter().enumerate().skip(1) {
            chain.extend(SpiffeTraceLink::new(
                *id,
                base_perms.clone(),
                1000 + i as u64,
            ));
        }
        chain
    }

    #[test]
    fn test_trace_chain_creation() {
        let chain = SpiffeTraceChain::new_root(
            "spiffe://nucleus.local/human/alice",
            PermissionLattice::permissive(),
            12345,
        );

        assert_eq!(chain.depth(), 1);
        assert_eq!(
            chain.current_spiffe_id(),
            Some("spiffe://nucleus.local/human/alice")
        );
        assert!(chain.verify());
    }

    #[test]
    fn test_trace_chain_extension() {
        let mut chain = SpiffeTraceChain::new_root(
            "spiffe://nucleus.local/human/alice",
            PermissionLattice::permissive(),
            12345,
        );

        chain.extend(SpiffeTraceLink::new(
            "spiffe://nucleus.local/agent/orchestrator-001",
            PermissionLattice::codegen(),
            12346,
        ));

        chain.extend(SpiffeTraceLink::new(
            "spiffe://nucleus.local/agent/coder-042",
            PermissionLattice::codegen(),
            12347,
        ));

        assert_eq!(chain.depth(), 3);
        assert_eq!(
            chain.root_spiffe_id(),
            Some("spiffe://nucleus.local/human/alice")
        );
        assert_eq!(
            chain.current_spiffe_id(),
            Some("spiffe://nucleus.local/agent/coder-042")
        );
        assert!(chain.verify());
    }

    #[test]
    fn test_ceiling_computation() {
        let mut chain = SpiffeTraceChain::new_root(
            "spiffe://nucleus.local/human/alice",
            PermissionLattice::permissive(),
            12345,
        );

        chain.extend(SpiffeTraceLink::new(
            "spiffe://nucleus.local/agent/orchestrator",
            PermissionLattice::codegen(),
            12346,
        ));

        let ceiling = chain.ceiling().unwrap();

        // Ceiling capabilities should be bounded by codegen (the more restrictive)
        // Note: We check capabilities rather than full leq because meet adds obligations
        assert!(ceiling
            .capabilities
            .leq(&PermissionLattice::permissive().capabilities));
        assert!(ceiling
            .capabilities
            .leq(&PermissionLattice::codegen().capabilities));
    }

    #[test]
    fn test_chain_with_expired_link() {
        let mut chain = SpiffeTraceChain::new_root(
            "spiffe://nucleus.local/human/alice",
            PermissionLattice::permissive(),
            12345,
        );

        // Add an already-expired link
        let expired_link = SpiffeTraceLink::new(
            "spiffe://nucleus.local/agent/expired",
            PermissionLattice::codegen(),
            12346,
        )
        .with_expiry(Utc::now() - Duration::hours(1));

        chain.links.push(expired_link);

        assert!(!chain.verify());

        let result = chain.verify_detailed();
        assert!(!result.is_valid());
    }

    #[test]
    fn test_escalation_request() {
        let requestor_chain = make_chain(
            &[
                "spiffe://nucleus.local/human/alice",
                "spiffe://nucleus.local/agent/coder-001",
            ],
            PermissionLattice::codegen(),
        );

        let request = EscalationRequest::new(
            requestor_chain,
            PermissionLattice::permissive(),
            "Need network access for API integration",
            3600,
        );

        assert!(!request.is_expired());
        assert!(request.validate().is_ok());
    }

    #[test]
    fn test_escalation_grant() {
        let requestor_chain = make_chain(
            &[
                "spiffe://nucleus.local/human/alice",
                "spiffe://nucleus.local/agent/coder-001",
            ],
            PermissionLattice::codegen(),
        );

        let approver_chain = make_chain(
            &[
                "spiffe://nucleus.local/human/bob",
                "spiffe://nucleus.local/agent/supervisor-001",
            ],
            PermissionLattice::permissive(),
        );

        let request = EscalationRequest::new(
            requestor_chain,
            PermissionLattice::fix_issue(),
            "Need write access for bug fix",
            1800,
        );

        let grant = EscalationGrant::new(&request, approver_chain, 12350).unwrap();

        assert!(!grant.is_expired());
        assert!(grant.is_valid());
        // Granted capabilities should be bounded by both requested and approver ceiling
        // Note: We check capabilities because meet adds obligations
        assert!(grant
            .granted
            .capabilities
            .leq(&PermissionLattice::fix_issue().capabilities));
    }

    #[test]
    fn test_escalation_policy() {
        let policy = EscalationPolicy::new(
            "spiffe://nucleus.local/agent/coder-*",
            "spiffe://nucleus.local/agent/supervisor-*",
            PermissionLattice::fix_issue(),
        )
        .with_max_ttl(7200)
        .with_description("Coders can request fix_issue from supervisors");

        assert!(policy.matches_requestor("spiffe://nucleus.local/agent/coder-001"));
        assert!(!policy.matches_requestor("spiffe://nucleus.local/agent/reviewer-001"));
        assert!(policy.matches_approver("spiffe://nucleus.local/agent/supervisor-001"));
        assert!(!policy.matches_approver("spiffe://nucleus.local/agent/coder-001"));
    }

    #[test]
    fn test_self_escalation_blocked() {
        // Scenario: An agent tries to approve its own escalation request
        // by having the same identity approve itself
        let shared_root = "spiffe://nucleus.local/human/alice";

        // Requestor is coder-001
        let mut requestor_chain =
            SpiffeTraceChain::new_root(shared_root, PermissionLattice::permissive(), 12345);
        requestor_chain.extend(SpiffeTraceLink::new(
            "spiffe://nucleus.local/agent/coder-001",
            PermissionLattice::codegen(),
            12346,
        ));

        // Approver is the SAME agent (coder-001) - trying to approve itself
        let mut approver_chain =
            SpiffeTraceChain::new_root(shared_root, PermissionLattice::permissive(), 12345);
        approver_chain.extend(SpiffeTraceLink::new(
            "spiffe://nucleus.local/agent/coder-001",
            PermissionLattice::codegen(),
            12346,
        ));

        // Use permissive as max_grant to avoid ExceedsPolicyMax issues
        // The self-escalation check should trigger before we check max_grant
        let max_grant = PermissionLattice::permissive();

        let policy = EscalationPolicy::new(
            "spiffe://nucleus.local/agent/coder-*",
            "spiffe://nucleus.local/agent/coder-*", // Allow coder to approve coder (for this test)
            max_grant.clone(),
        )
        .with_distinct_chains(true)
        .with_attestation(false); // Disable attestation for this test - we're testing self-escalation

        let request = EscalationRequest::new(
            requestor_chain,
            PermissionLattice::codegen(), // Request codegen, which is ≤ permissive
            "Self-escalation attempt",
            3600,
        );

        let result = policy.validate_request(&request, &approver_chain);
        assert!(matches!(result, Err(EscalationError::SelfEscalation)));
    }

    #[test]
    fn test_escalation_policy_set() {
        let mut policy_set = EscalationPolicySet::new();

        policy_set.add_policy(
            EscalationPolicy::new(
                "spiffe://nucleus.local/agent/coder-*",
                "spiffe://nucleus.local/agent/supervisor-*",
                PermissionLattice::fix_issue(),
            )
            .with_max_ttl(3600),
        );

        policy_set.add_policy(
            EscalationPolicy::new(
                "spiffe://nucleus.local/agent/**",
                "spiffe://nucleus.local/human/*",
                PermissionLattice::permissive(),
            )
            .with_max_ttl(7200),
        );

        let requestor_chain = make_chain(
            &[
                "spiffe://nucleus.local/human/alice",
                "spiffe://nucleus.local/agent/coder-001",
            ],
            PermissionLattice::codegen(),
        );

        let supervisor_chain = make_chain(
            &[
                "spiffe://nucleus.local/human/bob",
                "spiffe://nucleus.local/agent/supervisor-001",
            ],
            PermissionLattice::permissive(),
        );

        let request = EscalationRequest::new(
            requestor_chain,
            PermissionLattice::fix_issue(),
            "Need elevated access",
            3600,
        );

        // Should match the first policy (coder -> supervisor)
        let policy = policy_set.find_policy(&request, &supervisor_chain);
        assert!(policy.is_some());
    }

    #[test]
    fn test_ttl_exceeds_policy() {
        let policy = EscalationPolicy::new(
            "spiffe://nucleus.local/agent/**",
            "spiffe://nucleus.local/agent/supervisor-*",
            PermissionLattice::fix_issue(),
        )
        .with_max_ttl(3600) // 1 hour max
        .with_attestation(false); // Disable attestation for this test - we're testing TTL

        let requestor_chain = make_chain(
            &[
                "spiffe://nucleus.local/human/alice",
                "spiffe://nucleus.local/agent/coder-001",
            ],
            PermissionLattice::codegen(),
        );

        let approver_chain = make_chain(
            &[
                "spiffe://nucleus.local/human/bob",
                "spiffe://nucleus.local/agent/supervisor-001",
            ],
            PermissionLattice::permissive(),
        );

        let request = EscalationRequest::new(
            requestor_chain,
            PermissionLattice::fix_issue(),
            "Need long-term access",
            7200, // 2 hours - exceeds policy
        );

        let result = policy.validate_request(&request, &approver_chain);
        assert!(matches!(
            result,
            Err(EscalationError::TtlExceedsPolicy {
                requested: 7200,
                max: 3600
            })
        ));
    }

    #[test]
    fn test_chain_contains_pattern() {
        let mut chain = SpiffeTraceChain::new_root(
            "spiffe://nucleus.local/human/alice",
            PermissionLattice::permissive(),
            12345,
        );

        chain.extend(SpiffeTraceLink::new(
            "spiffe://nucleus.local/agent/orchestrator-001",
            PermissionLattice::codegen(),
            12346,
        ));

        chain.extend(SpiffeTraceLink::new(
            "spiffe://nucleus.local/agent/coder-042",
            PermissionLattice::codegen(),
            12347,
        ));

        assert!(chain.contains_pattern("spiffe://nucleus.local/human/*"));
        assert!(chain.contains_pattern("spiffe://nucleus.local/agent/coder-*"));
        assert!(chain.contains_pattern("spiffe://nucleus.local/agent/**"));
        assert!(!chain.contains_pattern("spiffe://nucleus.local/agent/reviewer-*"));
    }

    #[test]
    fn test_chain_contains_spiffe_id() {
        let mut chain = SpiffeTraceChain::new_root(
            "spiffe://nucleus.local/human/alice",
            PermissionLattice::permissive(),
            12345,
        );

        chain.extend(SpiffeTraceLink::new(
            "spiffe://nucleus.local/agent/coder-001",
            PermissionLattice::codegen(),
            12346,
        ));

        // Exact match
        assert!(chain.contains_spiffe_id("spiffe://nucleus.local/human/alice"));
        assert!(chain.contains_spiffe_id("spiffe://nucleus.local/agent/coder-001"));

        // No exact match (different suffix)
        assert!(!chain.contains_spiffe_id("spiffe://nucleus.local/agent/coder-002"));

        // Pattern matching is NOT used for exact match
        assert!(!chain.contains_spiffe_id("spiffe://nucleus.local/agent/coder-*"));
    }

    #[test]
    fn test_self_escalation_shared_root_blocked() {
        // Scenario: Same trust root (human/alice) but different leaf identities
        // The shared root IS allowed if identities are distinct (no overlap)
        let requestor_chain = make_chain(
            &[
                "spiffe://nucleus.local/human/alice",
                "spiffe://nucleus.local/agent/coder-001",
            ],
            PermissionLattice::codegen(),
        );

        let approver_chain = make_chain(
            &[
                "spiffe://nucleus.local/human/alice",          // SAME root
                "spiffe://nucleus.local/agent/supervisor-001", // Different leaf
            ],
            PermissionLattice::permissive(),
        );

        let policy = EscalationPolicy::new(
            "spiffe://nucleus.local/agent/coder-*",
            "spiffe://nucleus.local/agent/supervisor-*",
            PermissionLattice::permissive(),
        )
        .with_distinct_chains(true)
        .with_attestation(false); // Disable attestation for this test - we're testing self-escalation

        let request = EscalationRequest::new(
            requestor_chain,
            PermissionLattice::codegen(),
            "Request with shared root",
            3600,
        );

        // The root alice appears in BOTH chains - this triggers SelfEscalation
        let result = policy.validate_request(&request, &approver_chain);
        assert!(matches!(result, Err(EscalationError::SelfEscalation)));
    }

    #[test]
    fn test_self_escalation_delegator_in_requestor_chain() {
        // Scenario: Approver's chain contains supervisor-001
        // Requestor's chain also contains supervisor-001 (was delegated by same supervisor)
        let requestor_chain = make_chain(
            &[
                "spiffe://nucleus.local/human/bob",
                "spiffe://nucleus.local/agent/supervisor-001", // Supervisor delegated to coder
                "spiffe://nucleus.local/agent/coder-001",
            ],
            PermissionLattice::codegen(),
        );

        let approver_chain = make_chain(
            &[
                "spiffe://nucleus.local/human/alice",
                "spiffe://nucleus.local/agent/supervisor-001", // SAME supervisor approving
            ],
            PermissionLattice::permissive(),
        );

        let policy = EscalationPolicy::new(
            "spiffe://nucleus.local/agent/coder-*",
            "spiffe://nucleus.local/agent/supervisor-*",
            PermissionLattice::permissive(),
        )
        .with_distinct_chains(true)
        .with_attestation(false); // Disable attestation for this test - we're testing self-escalation

        let request = EscalationRequest::new(
            requestor_chain,
            PermissionLattice::codegen(),
            "Request from delegated coder",
            3600,
        );

        // supervisor-001 appears in BOTH chains - blocked
        let result = policy.validate_request(&request, &approver_chain);
        assert!(matches!(result, Err(EscalationError::SelfEscalation)));
    }

    #[test]
    fn test_valid_escalation_distinct_chains() {
        // Scenario: Completely independent chains - should be allowed
        let requestor_chain = make_chain(
            &[
                "spiffe://nucleus.local/human/alice",
                "spiffe://nucleus.local/agent/orchestrator-001",
                "spiffe://nucleus.local/agent/coder-001",
            ],
            PermissionLattice::codegen(),
        );

        let approver_chain = make_chain(
            &[
                "spiffe://nucleus.local/human/bob",            // Different root
                "spiffe://nucleus.local/agent/supervisor-001", // Different leaf
            ],
            PermissionLattice::permissive(),
        );

        let policy = EscalationPolicy::new(
            "spiffe://nucleus.local/agent/coder-*",
            "spiffe://nucleus.local/agent/supervisor-*",
            PermissionLattice::permissive(),
        )
        .with_distinct_chains(true)
        .with_attestation(false); // Disable attestation for this test - we're testing distinct chains

        let request = EscalationRequest::new(
            requestor_chain,
            PermissionLattice::codegen(),
            "Valid escalation request",
            3600,
        );

        // No overlap - should pass
        let result = policy.validate_request(&request, &approver_chain);
        assert!(result.is_ok());
    }

    #[test]
    fn test_attestation_status() {
        // Root only - no attestation needed
        let root_only = SpiffeTraceChain::new_root(
            "spiffe://nucleus.local/human/alice",
            PermissionLattice::permissive(),
            12345,
        );
        assert_eq!(root_only.attestation_status(), AttestationStatus::RootOnly);

        // Chain with no attestation
        let mut no_attest = root_only.clone();
        no_attest.extend(SpiffeTraceLink::new(
            "spiffe://nucleus.local/agent/coder-001",
            PermissionLattice::codegen(),
            12346,
        ));
        assert_eq!(no_attest.attestation_status(), AttestationStatus::None);

        // Chain with attestation
        let mut with_attest = root_only.clone();
        with_attest.extend(
            SpiffeTraceLink::new(
                "spiffe://nucleus.local/agent/coder-001",
                PermissionLattice::codegen(),
                12346,
            )
            .with_attestation(vec![1, 2, 3, 4]),
        );
        assert_eq!(
            with_attest.attestation_status(),
            AttestationStatus::Complete
        );

        // Partial attestation
        let mut partial = root_only;
        partial.extend(SpiffeTraceLink::new(
            "spiffe://nucleus.local/agent/orchestrator",
            PermissionLattice::codegen(),
            12346,
        ));
        partial.extend(
            SpiffeTraceLink::new(
                "spiffe://nucleus.local/agent/coder-001",
                PermissionLattice::codegen(),
                12347,
            )
            .with_attestation(vec![1, 2, 3, 4]),
        );
        assert_eq!(
            partial.attestation_status(),
            AttestationStatus::Partial {
                attested: 1,
                required: 2
            }
        );
    }

    #[test]
    fn test_canonical_attestation_message() {
        let link = SpiffeTraceLink::new(
            "spiffe://nucleus.local/agent/coder-001",
            PermissionLattice::codegen(),
            12345,
        );

        let message = link.canonical_attestation_message();
        let message_str = String::from_utf8(message).unwrap();

        assert!(message_str.contains("spiffe://nucleus.local/agent/coder-001"));
        assert!(message_str.contains("12345"));
        assert!(message_str.contains("Code generation"));
    }

    #[test]
    fn test_attestation_required_rejects_unattested_chains() {
        // Create chains without attestation
        let requestor_chain = make_chain(
            &[
                "spiffe://nucleus.local/human/alice",
                "spiffe://nucleus.local/agent/coder-001",
            ],
            PermissionLattice::codegen(),
        );

        let approver_chain = make_chain(
            &[
                "spiffe://nucleus.local/human/bob",
                "spiffe://nucleus.local/agent/supervisor-001",
            ],
            PermissionLattice::permissive(),
        );

        // Policy with attestation required (the default)
        let policy = EscalationPolicy::new(
            "spiffe://nucleus.local/agent/coder-*",
            "spiffe://nucleus.local/agent/supervisor-*",
            PermissionLattice::permissive(),
        )
        .with_distinct_chains(true)
        .with_attestation(true); // Explicitly require attestation

        let request = EscalationRequest::new(
            requestor_chain,
            PermissionLattice::codegen(),
            "Should fail due to missing attestation",
            3600,
        );

        // Should fail because chains have no attestation
        let result = policy.validate_request(&request, &approver_chain);
        assert!(matches!(
            result,
            Err(EscalationError::AttestationRequired { .. })
        ));
    }

    #[test]
    fn test_attestation_required_accepts_attested_chains() {
        // Helper to create attested chains
        fn make_attested_chain(
            spiffe_ids: &[&str],
            base_perms: PermissionLattice,
        ) -> SpiffeTraceChain {
            let mut chain = SpiffeTraceChain::new_root(spiffe_ids[0], base_perms.clone(), 1000);
            for (i, id) in spiffe_ids.iter().enumerate().skip(1) {
                chain.extend(
                    SpiffeTraceLink::new(*id, base_perms.clone(), 1000 + i as u64)
                        .with_attestation(vec![0xDE, 0xAD, 0xBE, 0xEF]), // Fake attestation
                );
            }
            chain
        }

        let requestor_chain = make_attested_chain(
            &[
                "spiffe://nucleus.local/human/alice",
                "spiffe://nucleus.local/agent/coder-001",
            ],
            PermissionLattice::codegen(),
        );

        let approver_chain = make_attested_chain(
            &[
                "spiffe://nucleus.local/human/bob",
                "spiffe://nucleus.local/agent/supervisor-001",
            ],
            PermissionLattice::permissive(),
        );

        // Policy with attestation required
        let policy = EscalationPolicy::new(
            "spiffe://nucleus.local/agent/coder-*",
            "spiffe://nucleus.local/agent/supervisor-*",
            PermissionLattice::permissive(),
        )
        .with_distinct_chains(true)
        .with_attestation(true);

        let request = EscalationRequest::new(
            requestor_chain,
            PermissionLattice::codegen(),
            "Should succeed with attestation",
            3600,
        );

        // Should succeed because chains have attestation
        let result = policy.validate_request(&request, &approver_chain);
        assert!(result.is_ok());
    }

    #[test]
    fn test_attestation_disabled_accepts_unattested_chains() {
        // Create chains without attestation
        let requestor_chain = make_chain(
            &[
                "spiffe://nucleus.local/human/alice",
                "spiffe://nucleus.local/agent/coder-001",
            ],
            PermissionLattice::codegen(),
        );

        let approver_chain = make_chain(
            &[
                "spiffe://nucleus.local/human/bob",
                "spiffe://nucleus.local/agent/supervisor-001",
            ],
            PermissionLattice::permissive(),
        );

        // Policy with attestation explicitly disabled
        let policy = EscalationPolicy::new(
            "spiffe://nucleus.local/agent/coder-*",
            "spiffe://nucleus.local/agent/supervisor-*",
            PermissionLattice::permissive(),
        )
        .with_distinct_chains(true)
        .with_attestation(false); // Disable attestation

        let request = EscalationRequest::new(
            requestor_chain,
            PermissionLattice::codegen(),
            "Should succeed without attestation when disabled",
            3600,
        );

        // Should succeed because attestation is not required
        let result = policy.validate_request(&request, &approver_chain);
        assert!(result.is_ok());
    }
}

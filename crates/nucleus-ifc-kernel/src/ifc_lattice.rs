//! Information Flow Control labels — the Flow Kernel foundation.
//!
//! A product lattice of 6 dimensions (confidentiality, integrity, authority,
//! provenance, freshness, derivation) that tracks data provenance, trust, and
//! authority through agent execution — the formal substrate for defending against
//! trust-boundary exploits (indirect prompt injection, memory poisoning,
//! confused-deputy). Design follows Microsoft FIDES (arXiv:2505.23643) and
//! classical BLP+Biba composition with a novel `AuthorityLevel` dimension.
//!
//! Extracted verbatim from `lib.rs` (MVK carve M1, RFC
//! `minimum-viable-ifc-kernel.md`) so the ~540-LOC closure-critical lattice is
//! isolated from the other ~3.4k LOC of `lib.rs` and brought under the kernel
//! boundary ratchet. Re-exported at the crate root, so `portcullis_core::IFCLabel`
//! (and every axis type) is unchanged for all consumers.

/// Confidentiality level — covariant (join = max).
///
/// Combining data from different confidentiality levels produces
/// a label at the HIGHEST level. Secret data stays secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[repr(u8)]
pub enum ConfLevel {
    /// Publicly available data (web content, public repos, docs).
    #[default]
    Public = 0,
    /// Internal data (private repos, user files, env vars).
    Internal = 1,
    /// Secret data (API keys, credentials, PII).
    Secret = 2,
}

/// Integrity level — CONTRAVARIANT (join = min, least trusted wins).
///
/// Combining trusted data with untrusted data produces UNTRUSTED output.
/// This is the Biba integrity model, inverted from BLP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[repr(u8)]
pub enum IntegLevel {
    /// Adversarially controlled (public issue bodies, web scraping results).
    Adversarial = 0,
    /// Untrusted but not adversarial (MCP tool output, cached data).
    Untrusted = 1,
    /// Trusted (user prompts, system config, verified sources).
    #[default]
    Trusted = 2,
}

/// Authority-to-instruct level — CONTRAVARIANT (join = min).
///
/// The critical innovation: formal encoding of "can this data steer the agent?"
/// Web content gets NoAuthority — it can be READ but cannot INSTRUCT.
/// When correctly labeled at runtime, this enables blocking indirect
/// prompt injection — web content cannot acquire instruction authority
/// regardless of what the LLM decides to do with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[repr(u8)]
pub enum AuthorityLevel {
    /// Cannot instruct the agent in any way (web content, public issues).
    #[cfg_attr(feature = "serde", serde(rename = "no_authority"))]
    NoAuthority = 0,
    /// Informational only — can provide context but not direct actions.
    Informational = 1,
    /// Can suggest actions but requires approval (MCP tool descriptions).
    Suggestive = 2,
    /// Full authority to direct agent actions (user prompts, system config).
    #[default]
    Directive = 3,
}

/// Provenance bitset — covariant (join = union, all sources tracked).
///
/// Tracks which sources contributed to a datum. Represented as a 6-bit
/// bitmask for Aeneas translatability (no BTreeSet, no Vec).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProvenanceSet(u8);

impl ProvenanceSet {
    pub const USER: ProvenanceSet = ProvenanceSet(1 << 0);
    pub const TOOL: ProvenanceSet = ProvenanceSet(1 << 1);
    pub const WEB: ProvenanceSet = ProvenanceSet(1 << 2);
    pub const MEMORY: ProvenanceSet = ProvenanceSet(1 << 3);
    pub const MODEL: ProvenanceSet = ProvenanceSet(1 << 4);
    pub const SYSTEM: ProvenanceSet = ProvenanceSet(1 << 5);

    pub const EMPTY: ProvenanceSet = ProvenanceSet(0);

    /// Union of two provenance sets.
    pub fn union(self, other: Self) -> Self {
        ProvenanceSet(self.0 | other.0)
    }

    /// Check if a specific source is present.
    pub fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Intersection of two provenance sets (for meet operation).
    pub fn intersection(self, other: Self) -> Self {
        ProvenanceSet(self.0 & other.0)
    }

    /// Subset check (for lattice ordering).
    pub fn is_subset_of(self, other: Self) -> bool {
        (self.0 & other.0) == self.0
    }

    /// Raw bitmask value (for serialization/signing).
    pub fn bits(self) -> u8 {
        self.0
    }

    /// Construct from raw bitmask (for deserialization/wire protocol).
    /// Only the lower 6 bits are used.
    pub fn from_bits(bits: u8) -> Self {
        Self(bits & 0x3F)
    }
}

/// Freshness — covariant (join = oldest timestamp, shortest TTL).
///
/// Uses u64 unix timestamps for Aeneas translatability (no chrono).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Freshness {
    /// Unix timestamp when the data was observed.
    pub observed_at: u64,
    /// Time-to-live in seconds (0 = no expiry).
    pub ttl_secs: u64,
}

impl Freshness {
    /// Join: oldest observation, shortest TTL.
    pub fn join(self, other: Self) -> Self {
        Self {
            observed_at: self.observed_at.min(other.observed_at),
            ttl_secs: if self.ttl_secs == 0 && other.ttl_secs == 0 {
                0
            } else if self.ttl_secs == 0 {
                other.ttl_secs
            } else if other.ttl_secs == 0 {
                self.ttl_secs
            } else {
                self.ttl_secs.min(other.ttl_secs)
            },
        }
    }

    /// Meet: newest observation, longest TTL (greatest lower bound).
    ///
    /// Dual of `join`. The meet is the least restrictive freshness that
    /// is at most as restrictive as both inputs.
    pub fn meet(self, other: Self) -> Self {
        Self {
            observed_at: self.observed_at.max(other.observed_at),
            ttl_secs: if self.ttl_secs == 0 || other.ttl_secs == 0 {
                0 // either has no expiry → meet has no expiry
            } else {
                self.ttl_secs.max(other.ttl_secs)
            },
        }
    }

    /// Lattice partial order for freshness.
    ///
    /// `self ≤ other` means self is less restrictive (newer, longer TTL).
    /// In the join semilattice, join takes oldest/shortest, so the ordering
    /// goes: newer/longer-TTL ≤ older/shorter-TTL.
    ///
    /// `ttl_secs = 0` means "no expiry" — the least restrictive (bottom)
    /// value for the TTL dimension. So `self.ttl_secs == 0` implies
    /// `self ≤ other` for the TTL dimension (bottom ≤ anything).
    pub fn leq(self, other: Self) -> bool {
        self.observed_at >= other.observed_at
            && (self.ttl_secs == 0 || (other.ttl_secs != 0 && self.ttl_secs >= other.ttl_secs))
    }

    /// Check if data has expired at a given time.
    ///
    /// Uses `saturating_add` to prevent overflow: if `observed_at + ttl_secs`
    /// would wrap, the deadline saturates to `u64::MAX`, making the data
    /// appear non-expired (fail-safe: overflow → treat as fresh rather than
    /// silently marking stale data as current).
    pub fn is_expired_at(self, now: u64) -> bool {
        self.ttl_secs > 0 && now > self.observed_at.saturating_add(self.ttl_secs)
    }
}

/// Derivation class — determinism-aware integrity classification.
///
/// Tracks whether a datum was produced by a deterministic computation,
/// AI generation, or some combination. This is the 6th dimension of
/// the IFC product lattice and the core DPI primitive: it determines
/// whether data can be auto-verified or requires human attestation.
///
/// Lattice order (bottom to top): `Deterministic < AIDerived < Mixed < OpaqueExternal`
/// `HumanPromoted` sits beside `Mixed` — promotion does not cleanse.
///
/// Key invariant ("no silent cleansing"): `AIDerived.join(x) != Deterministic`
/// for any `x` — AI-derived data cannot become deterministic without explicit
/// human promotion, and even then the result is `Mixed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[repr(u8)]
pub enum DerivationClass {
    /// Reproducible: pure transform, deterministic fetch, parser output.
    #[default]
    Deterministic = 0,
    /// LLM-generated, not reproducible (classification, extraction, generation).
    AIDerived = 1,
    /// Combination of deterministic and AI-derived inputs.
    Mixed = 2,
    /// AI-derived data explicitly approved by a human. Preserves ancestry
    /// but signals attestation — joining with anything produces Mixed.
    HumanPromoted = 3,
    /// External system with unknown determinism profile. Top element.
    OpaqueExternal = 4,
}

impl DerivationClass {
    /// Join (least upper bound) of two derivation classes.
    ///
    /// Lattice structure (Hasse diagram):
    /// ```text
    ///       OpaqueExternal  (top)
    ///            |
    ///          Mixed
    ///         /     \
    ///   AIDerived  HumanPromoted
    ///         \     /
    ///       Deterministic  (bottom)
    /// ```
    ///
    /// - Deterministic is bottom: `Deterministic ⊔ x = x`
    /// - OpaqueExternal is top: `x ⊔ OpaqueExternal = OpaqueExternal`
    /// - AIDerived ⊔ HumanPromoted = Mixed
    /// - Mixed ⊔ {AIDerived, HumanPromoted} = Mixed
    ///
    /// Key invariant ("no silent cleansing"): `AIDerived.join(x) != Deterministic`
    /// for any x — AI-derived data can never be laundered back to deterministic.
    pub fn join(self, other: Self) -> Self {
        use DerivationClass::*;
        match (self, other) {
            // Deterministic is bottom — identity for join
            (Deterministic, x) | (x, Deterministic) => x,
            // OpaqueExternal is top — absorbs everything
            (OpaqueExternal, _) | (_, OpaqueExternal) => OpaqueExternal,
            // Same class: idempotent
            (AIDerived, AIDerived) => AIDerived,
            (HumanPromoted, HumanPromoted) => HumanPromoted,
            (Mixed, Mixed) => Mixed,
            // Different non-bottom, non-top classes → Mixed
            // AIDerived + HumanPromoted, AIDerived + Mixed, HumanPromoted + Mixed
            _ => Mixed,
        }
    }

    /// Meet (greatest lower bound) of two derivation classes.
    ///
    /// Dual of join:
    /// - OpaqueExternal is top — identity for meet: `meet(x, OpaqueExternal) = x`
    /// - Deterministic is bottom — absorber for meet: `meet(x, Deterministic) = Deterministic`
    /// - `meet(AIDerived, HumanPromoted) = Deterministic` (greatest lower bound of incomparables)
    /// - `meet(Mixed, x) = x` when x is AIDerived or HumanPromoted
    pub fn meet(self, other: Self) -> Self {
        use DerivationClass::*;
        match (self, other) {
            // OpaqueExternal is top — identity for meet
            (OpaqueExternal, x) | (x, OpaqueExternal) => x,
            // Deterministic is bottom — absorber for meet
            (Deterministic, _) | (_, Deterministic) => Deterministic,
            // Same class: idempotent
            (AIDerived, AIDerived) => AIDerived,
            (HumanPromoted, HumanPromoted) => HumanPromoted,
            (Mixed, Mixed) => Mixed,
            // Mixed meets AIDerived or HumanPromoted = the lower element
            (Mixed, x) | (x, Mixed) => x,
            // AIDerived meets HumanPromoted = Deterministic (their GLB)
            (AIDerived, HumanPromoted) | (HumanPromoted, AIDerived) => Deterministic,
        }
    }

    /// Lattice partial order: `self ≤ other`.
    ///
    /// `a.leq(b)` iff `a.join(b) == b` (standard lattice definition).
    pub fn leq(self, other: Self) -> bool {
        self.join(other) == other
    }
}

/// Information flow control label — 6-dimensional product lattice.
///
/// The lattice order follows BLP (confidentiality) + Biba (integrity)
/// composition with authority confinement and derivation tracking:
///
/// - Confidentiality: covariant — join = max (most secret wins)
/// - Integrity: CONTRAVARIANT — join = min (least trusted wins)
/// - Provenance: covariant — join = union (all sources tracked)
/// - Freshness: covariant — join = oldest, shortest TTL
/// - Authority: CONTRAVARIANT — join = min (least authority wins)
/// - Derivation: covariant — join per DerivationClass rules (Mixed absorbs)
///
/// Key property: combining a trusted user prompt with web content produces
/// `integrity = Adversarial, authority = NoAuthority`. This data cannot
/// steer privileged actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IFCLabel {
    pub confidentiality: ConfLevel,
    pub integrity: IntegLevel,
    pub provenance: ProvenanceSet,
    pub freshness: Freshness,
    pub authority: AuthorityLevel,
    /// Derivation class — tracks whether this datum was deterministically
    /// computed, AI-generated, mixed, human-promoted, or from an opaque source.
    pub derivation: DerivationClass,
}

impl Default for IFCLabel {
    /// Default: minimum privilege — public, untrusted, no provenance, no authority.
    ///
    /// The safe default. Forgetting to set a field results in LESS privilege,
    /// not more. Use the named constructors (user_prompt, web_content, etc.)
    /// for specific contexts.
    fn default() -> Self {
        Self {
            confidentiality: ConfLevel::Public,
            integrity: IntegLevel::Untrusted,
            provenance: ProvenanceSet::EMPTY,
            freshness: Freshness::default(),
            authority: AuthorityLevel::NoAuthority,
            derivation: DerivationClass::Deterministic,
        }
    }
}

impl IFCLabel {
    /// Join two labels (least upper bound in the product lattice).
    ///
    /// Confidentiality and provenance are covariant (max/union).
    /// Integrity and authority are CONTRAVARIANT (min).
    pub fn join(self, other: Self) -> Self {
        Self {
            confidentiality: if self.confidentiality >= other.confidentiality {
                self.confidentiality
            } else {
                other.confidentiality
            },
            // Contravariant: least trusted wins
            integrity: if self.integrity <= other.integrity {
                self.integrity
            } else {
                other.integrity
            },
            provenance: self.provenance.union(other.provenance),
            freshness: self.freshness.join(other.freshness),
            // Contravariant: least authority wins
            authority: if self.authority <= other.authority {
                self.authority
            } else {
                other.authority
            },
            derivation: self.derivation.join(other.derivation),
        }
    }

    /// Check if this label flows to (is less restrictive than) another.
    ///
    /// `a.flows_to(b)` means data labeled `a` may be used where `b` is expected.
    /// Confidentiality: a.conf ≤ b.conf (can't send secret to public)
    /// Integrity: a.integ ≥ b.integ (can't use untrusted where trusted needed)
    /// Authority: a.auth ≥ b.auth (can't use NoAuthority where Directive needed)
    /// Provenance: a.prov ⊆ b.prov (target must accept all sources)
    ///
    /// Note: freshness is checked separately in `check_flow` (Rule 4) because
    /// it depends on wall-clock time, not just the label lattice ordering.
    pub fn flows_to(self, target: Self) -> bool {
        self.confidentiality <= target.confidentiality
            && self.integrity >= target.integrity
            && self.authority >= target.authority
            && self.provenance.is_subset_of(target.provenance)
            && self.derivation.leq(target.derivation)
    }

    /// Bottom label (least restrictive): public, trusted, no provenance, full authority.
    ///
    /// For contravariant dimensions (integrity, authority), bottom = maximum value
    /// so that `join(x, bottom) = x` (joining with bottom doesn't restrict).
    /// Freshness uses `observed_at = u64::MAX` (newest possible) and `ttl_secs = 0`
    /// (no expiry) — the least restrictive freshness.
    pub fn bottom() -> Self {
        Self {
            confidentiality: ConfLevel::Public,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::EMPTY,
            freshness: Freshness {
                observed_at: u64::MAX,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Directive,
            derivation: DerivationClass::Deterministic,
        }
    }

    /// Top label: secret, adversarial, all sources, no authority, expired.
    ///
    /// The most restrictive possible label. Data with this label cannot
    /// flow anywhere useful and will fail freshness checks.
    pub fn top() -> Self {
        Self {
            confidentiality: ConfLevel::Secret,
            integrity: IntegLevel::Adversarial,
            provenance: ProvenanceSet(0x3F), // all 6 bits
            freshness: Freshness {
                observed_at: 0,
                ttl_secs: 1, // expired immediately (observed_at=0, ttl=1 → expired at t=1)
            },
            authority: AuthorityLevel::NoAuthority,
            derivation: DerivationClass::OpaqueExternal,
        }
    }

    /// Intrinsic label for web content — the key indirect-injection defense.
    pub fn web_content(now: u64) -> Self {
        Self {
            confidentiality: ConfLevel::Public,
            integrity: IntegLevel::Adversarial,
            provenance: ProvenanceSet::WEB,
            freshness: Freshness {
                observed_at: now,
                ttl_secs: 3600,
            },
            authority: AuthorityLevel::NoAuthority,
            derivation: DerivationClass::OpaqueExternal,
        }
    }

    /// Intrinsic label for user prompts — full trust and authority.
    pub fn user_prompt(now: u64) -> Self {
        Self {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::USER,
            freshness: Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Directive,
            derivation: DerivationClass::Deterministic,
        }
    }

    /// Intrinsic label for secrets (API keys, credentials).
    pub fn secret(now: u64) -> Self {
        Self {
            confidentiality: ConfLevel::Secret,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::SYSTEM,
            freshness: Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::NoAuthority,
            derivation: DerivationClass::Deterministic,
        }
    }

    /// Intrinsic label for MCP tool responses.
    pub fn tool_response(now: u64) -> Self {
        Self {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Untrusted,
            provenance: ProvenanceSet::TOOL,
            freshness: Freshness {
                observed_at: now,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Informational,
            derivation: DerivationClass::Deterministic,
        }
    }

    /// Intrinsic label for memory entries.
    pub fn memory_entry(now: u64) -> Self {
        Self {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Untrusted,
            provenance: ProvenanceSet::MEMORY,
            freshness: Freshness {
                observed_at: now,
                ttl_secs: 86400,
            },
            authority: AuthorityLevel::Informational,
            derivation: DerivationClass::Deterministic,
        }
    }

    /// Meet two labels (greatest lower bound in the product lattice).
    ///
    /// Dual of `join`: the meet is the least restrictive label that is
    /// at most as restrictive as both inputs.
    ///
    /// Confidentiality and provenance are covariant (meet = min / intersection).
    /// Integrity and authority are CONTRAVARIANT (meet = max).
    pub fn meet(self, other: Self) -> Self {
        Self {
            confidentiality: if self.confidentiality <= other.confidentiality {
                self.confidentiality
            } else {
                other.confidentiality
            },
            // Contravariant: most trusted wins (max = greatest lower bound)
            integrity: if self.integrity >= other.integrity {
                self.integrity
            } else {
                other.integrity
            },
            provenance: self.provenance.intersection(other.provenance),
            freshness: self.freshness.meet(other.freshness),
            // Contravariant: most authority wins (max = greatest lower bound)
            authority: if self.authority >= other.authority {
                self.authority
            } else {
                other.authority
            },
            derivation: self.derivation.meet(other.derivation),
        }
    }

    /// Lattice partial order: `self ≤ other` in the product lattice.
    ///
    /// This is the lattice ordering (not the flow relation). A label `a` is
    /// less than `b` when `a` is less restrictive: lower confidentiality,
    /// higher integrity, higher authority, subset provenance.
    ///
    /// Note: This is equivalent to `self.join(other) == other`.
    pub fn leq(self, other: Self) -> bool {
        self.confidentiality <= other.confidentiality
            && self.integrity >= other.integrity
            && self.authority >= other.authority
            && self.provenance.is_subset_of(other.provenance)
            && self.freshness.leq(other.freshness)
            && self.derivation.leq(other.derivation)
    }
}

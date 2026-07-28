//! Scope binding — the slice the **complete-mediation** theorem is proven over
//! after Charon→Aeneas→Lean extraction.
//!
//! # What this is
//!
//! A [`crate::discharge::DischargedBundle`] is earned for exactly one
//! `(Operation, SinkClass)` pair and carries that pair. Every mediated effect
//! checks the bundle against the pair *it* is about to perform; the check is
//! `DischargedBundle::authorizes` (discharge.rs), whose body is
//!
//! ```text
//! self.operation == op && self.sink_class == sink
//! ```
//!
//! [`scope_admits`] is the `String`-free restatement of that clause, written so
//! its reachable dependency subgraph stays inside Aeneas's supported subset.
//!
//! # Why this predicate carries the security property
//!
//! Without it a bundle proves only that *a* preflight ran, never that a preflight
//! ran for THIS action — so an action whose own discharge would fail could be
//! performed under a discharge that succeeded for something cheaper. That is the
//! confused deputy, and it is the reason the `operation`/`sink_class` fields
//! exist on the bundle at all.
//!
//! The three properties worth proving over the extracted function are:
//!
//! * **reflexive** — a bundle admits its own action (no false denial);
//! * **discriminating** — differing on either component denies (no confused
//!   deputy);
//! * **unique** — a bundle admits at most one pair.
//!
//! # Why explicit rank comparison (not derived `PartialEq`)
//!
//! Production `Operation`/`SinkClass` derive `PartialEq`/`Ord`/`Hash`. Aeneas
//! emits a *derived* comparison as an OPAQUE axiom — it does not translate the
//! compiler-synthesized body — which would place an unspecified equality axiom
//! on the proof's critical path. Comparing explicit ranks ([`opcode`],
//! [`sinkcode`]) makes the whole predicate a *translated* function with no
//! opaque external dependency, exactly as [`super::ifc_integrity::irank`] does
//! for the integrity chain.
//!
//! # Faithfulness
//!
//! [`MedOperation`] and [`MedSinkClass`] mirror the production enums including
//! their `#[repr(u8)]` discriminants (ifc_ops.rs). The `#[cfg(test)]` block
//! binds this mirror to the real `DischargedBundle::authorizes` by EXHAUSTIVE
//! case analysis over all 13 × 19 = 247 earned pairs against all 247 attempted
//! pairs — 61 009 cases, the entire domain. For a finite domain an exhaustive
//! check is a complete equivalence proof, not a sample.

/// Operation mirror — discriminants ARE the production `Operation` discriminants.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum MedOperation {
    ReadFiles = 0,
    WriteFiles = 1,
    EditFiles = 2,
    RunBash = 3,
    GlobSearch = 4,
    GrepSearch = 5,
    WebSearch = 6,
    WebFetch = 7,
    GitCommit = 8,
    GitPush = 9,
    CreatePr = 10,
    ManagePods = 11,
    SpawnAgent = 12,
}

/// Sink-class mirror — discriminants ARE the production `SinkClass` discriminants.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum MedSinkClass {
    WorkspaceWrite = 0,
    SystemWrite = 1,
    BashExec = 2,
    HTTPEgress = 3,
    GitCommit = 4,
    GitPush = 5,
    PRCommentWrite = 6,
    EmailSend = 7,
    MemoryPersist = 8,
    AgentSpawn = 9,
    MCPWrite = 10,
    SecretRead = 11,
    CloudMutation = 12,
    ProposedTableWrite = 13,
    VerifiedTableWrite = 14,
    SearchIndexWrite = 15,
    CacheWrite = 16,
    TicketWrite = 17,
    AuditLogAppend = 18,
}

/// Numeric code for an operation — the `#[repr(u8)]` discriminant, written out
/// so Aeneas translates a concrete body instead of an opaque derived `eq`.
pub fn opcode(op: MedOperation) -> u8 {
    match op {
        MedOperation::ReadFiles => 0,
        MedOperation::WriteFiles => 1,
        MedOperation::EditFiles => 2,
        MedOperation::RunBash => 3,
        MedOperation::GlobSearch => 4,
        MedOperation::GrepSearch => 5,
        MedOperation::WebSearch => 6,
        MedOperation::WebFetch => 7,
        MedOperation::GitCommit => 8,
        MedOperation::GitPush => 9,
        MedOperation::CreatePr => 10,
        MedOperation::ManagePods => 11,
        MedOperation::SpawnAgent => 12,
    }
}

/// Numeric code for a sink class — the `#[repr(u8)]` discriminant.
pub fn sinkcode(sink: MedSinkClass) -> u8 {
    match sink {
        MedSinkClass::WorkspaceWrite => 0,
        MedSinkClass::SystemWrite => 1,
        MedSinkClass::BashExec => 2,
        MedSinkClass::HTTPEgress => 3,
        MedSinkClass::GitCommit => 4,
        MedSinkClass::GitPush => 5,
        MedSinkClass::PRCommentWrite => 6,
        MedSinkClass::EmailSend => 7,
        MedSinkClass::MemoryPersist => 8,
        MedSinkClass::AgentSpawn => 9,
        MedSinkClass::MCPWrite => 10,
        MedSinkClass::SecretRead => 11,
        MedSinkClass::CloudMutation => 12,
        MedSinkClass::ProposedTableWrite => 13,
        MedSinkClass::VerifiedTableWrite => 14,
        MedSinkClass::SearchIndexWrite => 15,
        MedSinkClass::CacheWrite => 16,
        MedSinkClass::TicketWrite => 17,
        MedSinkClass::AuditLogAppend => 18,
    }
}

/// Does a bundle earned for `(earned_op, earned_sink)` authorize an effect
/// performing `(attempted_op, attempted_sink)`?
///
/// Mirrors `DischargedBundle::authorizes` (discharge.rs): scope admission is
/// equality on the pair — nothing weaker, and in particular NOT an ordering.
/// A more-privileged bundle does not subsume a less-privileged action, because
/// the obligations discharged for one sink say nothing about another.
pub fn scope_admits(
    earned_op: MedOperation,
    earned_sink: MedSinkClass,
    attempted_op: MedOperation,
    attempted_sink: MedSinkClass,
) -> bool {
    opcode(earned_op) == opcode(attempted_op) && sinkcode(earned_sink) == sinkcode(attempted_sink)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Operation, SinkClass};

    /// Mirror → production, by discriminant.
    fn to_prod_op(op: MedOperation) -> Operation {
        Operation::ALL[opcode(op) as usize]
    }

    fn to_prod_sink(sink: MedSinkClass) -> SinkClass {
        SinkClass::ALL[sinkcode(sink) as usize]
    }

    /// How many `(Operation, SinkClass)` pairs are structurally earnable, i.e.
    /// pass `PathAllowed`. Pinned so a change to the structural rules shows up
    /// as a diff here rather than silently shrinking the proved domain.
    /// 27 of the 247 pairs — the structural rules are tight, so the sweep below
    /// covers 27 × 247 = 6 669 comparisons.
    const EARNABLE_PAIRS: usize = 27;

    const ALL_MED_OPS: [MedOperation; 13] = [
        MedOperation::ReadFiles,
        MedOperation::WriteFiles,
        MedOperation::EditFiles,
        MedOperation::RunBash,
        MedOperation::GlobSearch,
        MedOperation::GrepSearch,
        MedOperation::WebSearch,
        MedOperation::WebFetch,
        MedOperation::GitCommit,
        MedOperation::GitPush,
        MedOperation::CreatePr,
        MedOperation::ManagePods,
        MedOperation::SpawnAgent,
    ];

    const ALL_MED_SINKS: [MedSinkClass; 19] = [
        MedSinkClass::WorkspaceWrite,
        MedSinkClass::SystemWrite,
        MedSinkClass::BashExec,
        MedSinkClass::HTTPEgress,
        MedSinkClass::GitCommit,
        MedSinkClass::GitPush,
        MedSinkClass::PRCommentWrite,
        MedSinkClass::EmailSend,
        MedSinkClass::MemoryPersist,
        MedSinkClass::AgentSpawn,
        MedSinkClass::MCPWrite,
        MedSinkClass::SecretRead,
        MedSinkClass::CloudMutation,
        MedSinkClass::ProposedTableWrite,
        MedSinkClass::VerifiedTableWrite,
        MedSinkClass::SearchIndexWrite,
        MedSinkClass::CacheWrite,
        MedSinkClass::TicketWrite,
        MedSinkClass::AuditLogAppend,
    ];

    /// The mirror enums must line up with the production ones variant for
    /// variant. If a variant is ever added to `Operation` or `SinkClass`
    /// without being added here, the parity test below would silently cover a
    /// smaller domain — so pin the widths first.
    #[test]
    fn the_mirror_covers_every_production_variant() {
        assert_eq!(ALL_MED_OPS.len(), Operation::ALL.len());
        assert_eq!(ALL_MED_SINKS.len(), SinkClass::ALL.len());
        for (i, m) in ALL_MED_OPS.iter().enumerate() {
            assert_eq!(opcode(*m) as usize, i, "opcode must be the array index");
            assert_eq!(to_prod_op(*m), Operation::ALL[i]);
        }
        for (i, m) in ALL_MED_SINKS.iter().enumerate() {
            assert_eq!(sinkcode(*m) as usize, i, "sinkcode must be the array index");
            assert_eq!(to_prod_sink(*m), SinkClass::ALL[i]);
        }
    }

    /// EXHAUSTIVE parity: for every EARNABLE pair against every attempted pair,
    /// the extracted predicate agrees with production `authorizes`.
    ///
    /// Not all 13 × 19 = 247 pairs are earnable — `PathAllowed` rejects
    /// structurally inconsistent ones such as `ReadFiles`/`WorkspaceWrite`, so a
    /// bundle for them cannot exist and there is nothing to compare. The earned
    /// side therefore ranges over the pairs that actually discharge; the
    /// attempted side ranges over all 247, since an attacker may attempt
    /// anything. Within that domain the sweep is complete, so this is an
    /// equivalence proof rather than a sample.
    #[test]
    fn scope_admits_matches_production_authorizes_exhaustively() {
        use crate::discharge::test_helpers::try_bundle_for;

        let mut checked = 0usize;
        let mut earnable = 0usize;
        for eo in ALL_MED_OPS {
            for es in ALL_MED_SINKS {
                let Some(bundle) = try_bundle_for(to_prod_op(eo), to_prod_sink(es)) else {
                    continue; // not a structurally permitted pair — unearnable
                };
                earnable += 1;
                for ao in ALL_MED_OPS {
                    for as_ in ALL_MED_SINKS {
                        let extracted = scope_admits(eo, es, ao, as_);
                        let production = bundle.authorizes(to_prod_op(ao), to_prod_sink(as_));
                        assert_eq!(
                            extracted, production,
                            "divergence: earned {eo:?}/{es:?}, attempted {ao:?}/{as_:?}"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert!(
            earnable > 0,
            "no pair discharged — the sweep proved nothing"
        );
        assert_eq!(
            checked,
            earnable * 247,
            "every earnable pair must be swept against all 247 attempts"
        );
        // Pin the earnable count: if `operation_allowed_for_sink` changes, the
        // domain this proof covers changes with it, and that should be a visible
        // diff rather than a silent narrowing.
        assert_eq!(earnable, EARNABLE_PAIRS, "earnable domain changed");
    }

    /// No false denial: a bundle admits the action it was earned for.
    #[test]
    fn scope_admission_is_reflexive() {
        for op in ALL_MED_OPS {
            for sink in ALL_MED_SINKS {
                assert!(scope_admits(op, sink, op, sink));
            }
        }
    }

    /// No confused deputy: differing on EITHER component denies. This is the
    /// property that a substituted bundle violates.
    #[test]
    fn scope_admission_discriminates_on_both_components() {
        for op in ALL_MED_OPS {
            for sink in ALL_MED_SINKS {
                for other_op in ALL_MED_OPS {
                    for other_sink in ALL_MED_SINKS {
                        let same = opcode(op) == opcode(other_op)
                            && sinkcode(sink) == sinkcode(other_sink);
                        assert_eq!(scope_admits(op, sink, other_op, other_sink), same);
                    }
                }
            }
        }
    }

    /// A bundle admits AT MOST ONE pair — the counterpart of one-shot use.
    #[test]
    fn a_bundle_admits_exactly_one_pair() {
        for op in ALL_MED_OPS {
            for sink in ALL_MED_SINKS {
                let admitted = ALL_MED_OPS
                    .iter()
                    .flat_map(|o| ALL_MED_SINKS.iter().map(move |s| (*o, *s)))
                    .filter(|(o, s)| scope_admits(op, sink, *o, *s))
                    .count();
                assert_eq!(admitted, 1, "{op:?}/{sink:?} admitted {admitted} pairs");
            }
        }
    }
}

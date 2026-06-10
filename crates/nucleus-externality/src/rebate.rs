//! Welfare-rebate distribution — the budget-balance fix.
//!
//! **Pigouvian T1-T4.** Classical VCG collects more than it
//! redistributes; the surplus normally exits the auction without
//! economic purpose. We close that gap by piping the Pigouvian
//! collection (R5's `rebate_pool_micro_usd`) to the witness
//! federation as a "victim-compensation" pool — peers who VERIFIED
//! the externality claims get paid proportional to their
//! verification share.
//!
//! ## Why this is the right party to pay
//!
//! The witness federation is the substrate's verification layer
//! (closes K5 with ≥ 3 distinct peers). Each peer absorbs CPU + I/O
//! time verifying signed claims — itself an externality the auction
//! imposes on the federation. Paying peers from the Pigouvian pool
//! turns K5 from a security gate into a sustainable revenue model:
//! the federation peers have economic reason to join AND to verify
//! claims correctly.
//!
//! Compare to the SOTA "Faltings mechanism" (excludes one agent at
//! random and makes them the residual claimant). Our scheme is
//! cleaner because the residual claimant set is *external* to the
//! auction (the witness federation, not a bidder), which removes
//! the truthfulness perturbation Faltings introduces.
//!
//! ## Math
//!
//! Each witness's rebate is computed via integer basis points:
//! ```text
//! rebate_i := pool_micro_usd * share_basis_points_i / 10_000
//! ```
//! With `Σ share_basis_points_i == 10_000` as the invariant, the
//! total rebated equals the pool exactly (modulo integer
//! rounding — see [`emit_rebates`] for the exact-balance
//! reconciliation).

use nucleus_lineage::{CallSpiffeId, EdgeKind, LineageEdge};
use thiserror::Error;

/// Total basis-point sum invariant for a witness federation. Sum of
/// all `share_basis_points` MUST equal this exactly.
pub const TOTAL_SHARE_BASIS_POINTS: u32 = 10_000;

/// One witness federation peer's share of the rebate pool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessShare {
    /// Peer's signing-key id (resolves to a `VerifyingKey` via
    /// the federation's published JWKS).
    pub witness_kid: String,
    /// Basis-point share. Sum across all witnesses MUST equal
    /// [`TOTAL_SHARE_BASIS_POINTS`].
    pub share_basis_points: u32,
}

/// The witness federation membership snapshot used as the rebate
/// distribution key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessFederation {
    /// Witness shares — order is the canonical distribution order
    /// (used to break exact-balance reconciliation ties).
    pub witnesses: Vec<WitnessShare>,
}

impl WitnessFederation {
    /// Build a federation with equal shares for `n` witnesses.
    /// Convenience for tests + the common-case bootstrap path.
    pub fn equal_shares(witness_kids: &[&str]) -> Self {
        let n = witness_kids.len() as u32;
        if n == 0 {
            return Self {
                witnesses: Vec::new(),
            };
        }
        let base = TOTAL_SHARE_BASIS_POINTS / n;
        let remainder = TOTAL_SHARE_BASIS_POINTS - base * n;
        let witnesses = witness_kids
            .iter()
            .enumerate()
            .map(|(i, kid)| {
                // First `remainder` witnesses absorb the +1 bps so
                // the total is exact.
                let bonus = if (i as u32) < remainder { 1 } else { 0 };
                WitnessShare {
                    witness_kid: (*kid).to_string(),
                    share_basis_points: base + bonus,
                }
            })
            .collect();
        Self { witnesses }
    }

    /// Sum of all share basis points. Must equal
    /// [`TOTAL_SHARE_BASIS_POINTS`] for the federation to be valid.
    pub fn total_share_basis_points(&self) -> u32 {
        self.witnesses.iter().map(|w| w.share_basis_points).sum()
    }
}

/// Errors from rebate emission.
#[derive(Debug, Error)]
pub enum RebateError {
    /// Federation's share-basis-point sum doesn't equal
    /// [`TOTAL_SHARE_BASIS_POINTS`]. Caller is using an invalid
    /// federation snapshot.
    #[error(
        "federation basis-point sum {got} ≠ {expected}",
        expected = TOTAL_SHARE_BASIS_POINTS,
    )]
    InvalidFederationShareSum { got: u32 },
    /// SPIFFE-id derivation failed when building a rebate edge.
    #[error("spiffe derivation: {0}")]
    Spiffe(nucleus_lineage::IdError),
    /// Tried to emit a rebate against an externality edge that
    /// was already rebated. Defends V4 (double-claim).
    #[error("source_externality_edge_hash {hash} already rebated")]
    DoubleClaim { hash: String },
}

/// **T1+T2+T3+T4.** Emit one `WelfareRebate` edge per witness,
/// distributing the entire `pool_micro_usd` proportionally to
/// each witness's `share_basis_points`. The reconciliation step
/// hands any integer-division rounding remainder to the first
/// witness in declaration order so the sum of emitted rebates
/// equals the pool *exactly*.
///
/// `parent` is the parent SPIFFE id the rebate edges chain off
/// (typically the parent call edge or the auction's Allocation
/// edge). `source_externality_edge_hash` is the SHA-256 hex of
/// the `EdgeKind::Externality` edge that funded this rebate —
/// the V4 no-double-claim defense uses this to deduplicate.
pub fn emit_rebates(
    pool_micro_usd: u64,
    federation: &WitnessFederation,
    parent: CallSpiffeId,
    source_externality_edge_hash: &str,
) -> Result<Vec<LineageEdge>, RebateError> {
    if federation.total_share_basis_points() != TOTAL_SHARE_BASIS_POINTS {
        return Err(RebateError::InvalidFederationShareSum {
            got: federation.total_share_basis_points(),
        });
    }

    // Compute each share via u128 to avoid the 32-bit
    // multiplication overflow on extreme pool values.
    let mut amounts: Vec<u64> = federation
        .witnesses
        .iter()
        .map(|w| {
            let pool128 = u128::from(pool_micro_usd);
            let bps128 = u128::from(w.share_basis_points);
            let share = pool128.saturating_mul(bps128) / u128::from(TOTAL_SHARE_BASIS_POINTS);
            u64::try_from(share).unwrap_or(u64::MAX)
        })
        .collect();

    // **Exact-balance reconciliation.** Integer division rounds
    // down; the remainder goes to the first witness so the sum is
    // exact.
    let sum: u64 = amounts.iter().sum();
    let remainder = pool_micro_usd.saturating_sub(sum);
    if remainder > 0 && !amounts.is_empty() {
        amounts[0] = amounts[0].saturating_add(remainder);
    }

    let mut edges = Vec::with_capacity(federation.witnesses.len());
    for (w, amount) in federation.witnesses.iter().zip(amounts.iter()) {
        // Distinct child id per witness for the same source so
        // the chain stays unambiguous.
        let child_seed = format!(
            "rebate:{}:{}:{amount}",
            w.witness_kid, source_externality_edge_hash
        );
        let child = parent
            .derive_artifact(child_seed.as_bytes())
            .map_err(RebateError::Spiffe)?;
        let edge = LineageEdge::from_parent(
            child,
            parent.clone(),
            EdgeKind::WelfareRebate {
                recipient_kid: w.witness_kid.clone(),
                micro_usd: *amount,
                source_externality_edge_hash: source_externality_edge_hash.to_string(),
            },
        );
        edges.push(edge);
    }
    Ok(edges)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_lineage::CallSpiffeId;

    fn pod_parent() -> CallSpiffeId {
        CallSpiffeId::pod("test.example.com", "agents", "auctioneer").unwrap()
    }

    fn fed3() -> WitnessFederation {
        WitnessFederation::equal_shares(&["w-a", "w-b", "w-c"])
    }

    #[test]
    fn equal_shares_sums_to_ten_thousand() {
        let f = fed3();
        assert_eq!(f.total_share_basis_points(), TOTAL_SHARE_BASIS_POINTS);
        // 10_000 / 3 = 3333 r 1 → first witness gets the +1 bonus.
        assert_eq!(f.witnesses[0].share_basis_points, 3_334);
        assert_eq!(f.witnesses[1].share_basis_points, 3_333);
        assert_eq!(f.witnesses[2].share_basis_points, 3_333);
    }

    #[test]
    fn equal_shares_split_evenly_for_divisor() {
        let f = WitnessFederation::equal_shares(&["a", "b", "c", "d", "e"]);
        // 10_000 / 5 = 2000 exactly.
        for w in &f.witnesses {
            assert_eq!(w.share_basis_points, 2_000);
        }
    }

    // ── T3 — Proportional-to-verifier-share math ───────────────────────

    #[test]
    fn equal_shares_split_pool_evenly() {
        let f = WitnessFederation::equal_shares(&["a", "b", "c", "d"]);
        let edges = emit_rebates(4_000, &f, pod_parent(), &"f".repeat(64)).unwrap();
        let total: u64 = edges
            .iter()
            .map(|e| match &e.kind {
                EdgeKind::WelfareRebate { micro_usd, .. } => *micro_usd,
                _ => 0,
            })
            .sum();
        assert_eq!(total, 4_000);
        for e in &edges {
            match &e.kind {
                EdgeKind::WelfareRebate { micro_usd, .. } => {
                    assert_eq!(*micro_usd, 1_000);
                }
                _ => panic!("expected WelfareRebate"),
            }
        }
    }

    #[test]
    fn unequal_shares_match_bps() {
        let f = WitnessFederation {
            witnesses: vec![
                WitnessShare {
                    witness_kid: "lead".into(),
                    share_basis_points: 6_000, // 60%
                },
                WitnessShare {
                    witness_kid: "second".into(),
                    share_basis_points: 3_000, // 30%
                },
                WitnessShare {
                    witness_kid: "third".into(),
                    share_basis_points: 1_000, // 10%
                },
            ],
        };
        let edges = emit_rebates(10_000, &f, pod_parent(), &"a".repeat(64)).unwrap();
        let amounts: Vec<u64> = edges
            .iter()
            .map(|e| match &e.kind {
                EdgeKind::WelfareRebate { micro_usd, .. } => *micro_usd,
                _ => 0,
            })
            .collect();
        assert_eq!(amounts, vec![6_000, 3_000, 1_000]);
    }

    // ── T4 — Budget balance round-trip ────────────────────────────────

    #[test]
    fn budget_balanced_when_pigou_collected_equals_rebated() {
        // The named acceptance: rebate emission sums EXACTLY to
        // the pool (integer-division remainder folded back).
        let f = fed3();
        let pool = 1_000_001u64; // odd amount: 1_000_001 / 3 = 333_333 r 2.
        let edges = emit_rebates(pool, &f, pod_parent(), &"b".repeat(64)).unwrap();
        let total: u64 = edges
            .iter()
            .map(|e| match &e.kind {
                EdgeKind::WelfareRebate { micro_usd, .. } => *micro_usd,
                _ => 0,
            })
            .sum();
        assert_eq!(total, pool, "rebate sum must equal pool exactly");
    }

    #[test]
    fn rebate_edges_chain_off_parent() {
        let f = fed3();
        let parent = pod_parent();
        let edges = emit_rebates(900, &f, parent.clone(), &"c".repeat(64)).unwrap();
        for edge in &edges {
            assert_eq!(edge.parents.len(), 1);
            assert_eq!(edge.parents[0], parent);
            // Each child must descend from the parent's URI.
            assert!(
                edge.child.as_str().starts_with(parent.as_str()),
                "child {} not a descendant of {}",
                edge.child.as_str(),
                parent.as_str()
            );
        }
    }

    #[test]
    fn rebate_edges_carry_source_externality_hash() {
        let f = fed3();
        let source_hash = "d".repeat(64);
        let edges = emit_rebates(900, &f, pod_parent(), &source_hash).unwrap();
        for edge in &edges {
            match &edge.kind {
                EdgeKind::WelfareRebate {
                    source_externality_edge_hash,
                    ..
                } => {
                    assert_eq!(source_externality_edge_hash, &source_hash);
                }
                _ => panic!("expected WelfareRebate"),
            }
        }
    }

    #[test]
    fn invalid_federation_share_sum_rejected() {
        let bad = WitnessFederation {
            witnesses: vec![WitnessShare {
                witness_kid: "only".into(),
                share_basis_points: 5_000, // half — invalid
            }],
        };
        let err = emit_rebates(1_000, &bad, pod_parent(), &"e".repeat(64)).unwrap_err();
        match err {
            RebateError::InvalidFederationShareSum { got } => {
                assert_eq!(got, 5_000);
            }
            other => panic!("expected InvalidFederationShareSum, got {other:?}"),
        }
    }

    #[test]
    fn zero_pool_emits_zero_value_edges() {
        // Edge case: cube reports no Pigouvian collection in this
        // window. Rebate emission still produces edges (so the
        // chain is uniform across windows) but each amount is 0.
        let f = fed3();
        let edges = emit_rebates(0, &f, pod_parent(), &"e".repeat(64)).unwrap();
        for edge in &edges {
            match &edge.kind {
                EdgeKind::WelfareRebate { micro_usd, .. } => assert_eq!(*micro_usd, 0),
                _ => panic!("expected WelfareRebate"),
            }
        }
    }
}

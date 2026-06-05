//! Commons routing — where the Pigouvian externality revenue *goes*.
//!
//! A Pigouvian-VCG clearing collects a tax pool ([`crate::vcg_pigou::PigouvianClearing::rebate_pool_micro_usd`])
//! that internalises the social/environmental cost of the cleared transactions
//! (carbon, congestion, data pollution — see [`crate::vcg_pigou`] /
//! `nucleus-externality`'s `ResourceDim`). This module routes that pool to
//! **remediation + the commons** (e.g. carbon removal, affected-party rebates,
//! public verifier infrastructure) with a **no-skim conservation** guarantee:
//! every micro-USD collected is accounted for in the allocations, so the flow is
//! transparent and independently auditable ("watch the money fund the fix").
//!
//! This is the social-good steering: the marketplace prices the true cost AND
//! routes the revenue to fixing it, non-extractively. Pure + deterministic, so a
//! settlement contract can run it on-chain and anyone can recompute the split.
//!
//! HONESTY: this routes the pool faithfully; it does NOT verify that a
//! `destination` actually *performs* the remediation (that the carbon-removal
//! address really removes carbon). That last-mile attestation is an oracle
//! problem, the same open frontier as measuring the externality itself.

use serde::{Deserialize, Serialize};

/// Basis-point scale (100% = 10_000).
pub const COMMONS_BPS_SCALE: u64 = 10_000;

/// A destination share of the commons pool, in basis points.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommonsShare {
    /// Where this slice goes (a chain address, a remediation program id, …).
    pub destination: String,
    /// Share of the pool in basis points; all shares must sum to 10_000.
    pub bps: u64,
}

/// A concrete allocation of pool funds to a destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommonsAllocation {
    /// The destination this allocation funds.
    pub destination: String,
    /// Amount in micro-USD.
    pub amount_micro: u64,
}

/// Routing errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommonsError {
    /// No shares were supplied.
    #[error("no commons shares supplied")]
    NoShares,
    /// Shares did not sum to exactly 10_000 bps (would skim or over-allocate).
    #[error("commons shares must sum to 10000 bps, got {got}")]
    SharesMustSumTo10000 { got: u64 },
}

/// Route `pool_micro` across `shares`, returning one [`CommonsAllocation`] per
/// share (in order). Integer-division dust is assigned to the first share so the
/// allocations sum to **exactly** `pool_micro` — nothing is skimmed or lost.
///
/// Errors if shares are empty or do not sum to 10_000 bps.
pub fn route_to_commons(
    pool_micro: u64,
    shares: &[CommonsShare],
) -> Result<Vec<CommonsAllocation>, CommonsError> {
    if shares.is_empty() {
        return Err(CommonsError::NoShares);
    }
    let sum_bps: u64 = shares.iter().map(|s| s.bps).sum();
    if sum_bps != COMMONS_BPS_SCALE {
        return Err(CommonsError::SharesMustSumTo10000 { got: sum_bps });
    }

    let mut allocations: Vec<CommonsAllocation> = shares
        .iter()
        .map(|s| CommonsAllocation {
            destination: s.destination.clone(),
            amount_micro: ((pool_micro as u128 * s.bps as u128) / COMMONS_BPS_SCALE as u128) as u64,
        })
        .collect();

    // Conservation: assign integer-division dust to the first share so the
    // allocations sum to exactly the pool (no skim).
    let allocated: u64 = allocations.iter().map(|a| a.amount_micro).sum();
    let dust = pool_micro - allocated; // allocated ≤ pool since Σbps == scale
    if let Some(first) = allocations.first_mut() {
        first.amount_micro += dust;
    }
    Ok(allocations)
}

/// Total routed (for audit assertions): should always equal the input pool.
pub fn total_routed(allocations: &[CommonsAllocation]) -> u64 {
    allocations.iter().map(|a| a.amount_micro).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share(dest: &str, bps: u64) -> CommonsShare {
        CommonsShare {
            destination: dest.into(),
            bps,
        }
    }

    fn example_splits() -> Vec<CommonsShare> {
        vec![
            share("carbon-removal", 6_000),          // 60% to drawdown
            share("affected-party-rebate", 2_500),   // 25% back to those harmed
            share("public-verifier-commons", 1_500), // 15% to keep the mesh honest
        ]
    }

    #[test]
    fn conservation_no_skim() {
        // Every micro-USD of the pool is accounted for — the auditable property.
        for &pool in &[0u64, 1, 7, 1_000_000, 9_999_999, u64::MAX / 4] {
            let allocs = route_to_commons(pool, &example_splits()).unwrap();
            assert_eq!(total_routed(&allocs), pool, "skim/loss at pool={pool}");
        }
    }

    #[test]
    fn proportional_split_with_dust_to_first() {
        let allocs = route_to_commons(1_000_000, &example_splits()).unwrap();
        assert_eq!(allocs[0].amount_micro, 600_000); // 60%
        assert_eq!(allocs[1].amount_micro, 250_000); // 25%
        assert_eq!(allocs[2].amount_micro, 150_000); // 15%
                                                     // dusty pool: 100 µ over 60/25/15 → 60/25/15, dust 0 here; test a dusty one
        let d = route_to_commons(7, &example_splits()).unwrap();
        assert_eq!(total_routed(&d), 7);
        // 7*6000/10000=4, 7*2500/10000=1, 7*1500/10000=1 → 6; dust 1 → first=5
        assert_eq!(d[0].amount_micro, 5);
    }

    #[test]
    fn rejects_bad_shares() {
        assert_eq!(route_to_commons(100, &[]), Err(CommonsError::NoShares));
        let bad = vec![share("a", 5_000), share("b", 4_000)]; // sums 9000
        assert_eq!(
            route_to_commons(100, &bad),
            Err(CommonsError::SharesMustSumTo10000 { got: 9_000 })
        );
    }
}

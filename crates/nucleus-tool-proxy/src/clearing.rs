//! How a request pays for the authority it asks for.
//!
//! Two mechanisms, and a dimension uses exactly one of them. `--clearing` names the
//! dimensions that clear by AUCTION: those requests join a round and are admitted only
//! if they win and the Clarke pivot is charged. Everything else goes to the posted-price
//! screen, which reads a bid from a header. Running both would price the same slot twice,
//! so `clear_by_auction` runs first and the caller falls through to the screen only when
//! this module did not decide.
//!
//! Split out of `main.rs` because that file is 2x its line-ratchet target and this is a
//! whole concern rather than a slice of one: the flag that selects the mechanism, the
//! mechanism, the ledger write that records a round, and the header bid it replaces.

use axum::http::HeaderMap;
use nucleus_authority_exchange::{CertifiedCeiling, SignedBid, Verdict};
use nucleus_econ_types::AgentId;
use nucleus_permission_market::{PermissionBid, PermissionDimension, PermissionGrant};
use tracing::warn;

use crate::pod_cert::CertifiedPermissions;
use crate::{ApiError, AppState, HEADER_PERMISSION_BID};

/// Which dimensions `--clearing` names, or why the flag is wrong.
///
/// An unknown name is an error, not a skip. The failure this forbids is a typo
/// (`network-egress` for `network_egress`) that leaves the operator believing a
/// dimension is auctioned while it quietly stays on the posted-price path —
/// absence of evidence reading as evidence of absence, which is the exact shape
/// `GI002` exists to catch in the shell gates.
pub(crate) fn parse_clearing_dimensions(
    names: &[String],
) -> Result<std::collections::BTreeSet<PermissionDimension>, String> {
    let mut set = std::collections::BTreeSet::new();
    for name in names {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let Some(dim) = PermissionDimension::ALL
            .iter()
            .copied()
            .find(|d| d.label() == name)
        else {
            return Err(format!(
                "--clearing: unknown dimension {name:?}; expected one of {}",
                PermissionDimension::ALL
                    .iter()
                    .map(|d| d.label())
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        };
        set.insert(dim);
    }
    Ok(set)
}

#[cfg(test)]
mod clearing_flag_tests {
    use super::*;

    /// INERTNESS, and it is the property that matters most about this feature:
    /// with no `--clearing`, no dimension is auctioned, `authority_exchange`
    /// stays `None`, and every request takes exactly the path it took before.
    #[test]
    fn the_default_auctions_nothing() {
        assert!(
            parse_clearing_dimensions(&[])
                .expect("empty is valid")
                .is_empty()
        );
    }

    #[test]
    fn every_dimension_is_nameable_by_its_own_label() {
        for d in PermissionDimension::ALL {
            let got = parse_clearing_dimensions(&[d.label().to_string()]).expect("label parses");
            assert!(got.contains(d), "{} did not parse to itself", d.label());
        }
    }

    /// A typo must not read as "auction nothing". An operator who asked for a
    /// dimension and got silence would believe the mechanism was running.
    #[test]
    fn an_unknown_dimension_is_an_error_not_a_skip() {
        let err = parse_clearing_dimensions(&["network-egress".to_string()])
            .expect_err("a typo must not be ignored");
        assert!(err.contains("network-egress"), "{err}");
        assert!(
            err.contains("network_egress"),
            "the error must name the fix: {err}"
        );
    }

    #[test]
    fn blank_entries_from_a_trailing_comma_are_not_errors() {
        let got = parse_clearing_dimensions(&["network_egress".into(), String::new()])
            .expect("a trailing comma is not a typo");
        assert_eq!(got.len(), 1);
    }
}

/// Clear this request's dimension by auction, when the operator named it.
///
/// A dimension the operator named clears by auction: the request joins a
/// round, waits for it to close, and is admitted only if it wins AND the
/// Clarke pivot is charged. Every other outcome refuses. This runs BEFORE
/// the posted-price screen below, because the two are alternative
/// mechanisms for the same decision and running both would price the slot
/// twice.
///
/// `Ok(())` means this module did not refuse: either the dimension is not auctioned
/// or the request won its round. The caller then runs the posted-price screen.
pub(crate) async fn clear_by_auction(
    state: &AppState,
    path: &str,
    certified_perms: Option<&CertifiedPermissions>,
) -> Result<(), ApiError> {
    if let Some(scheduler) = state.authority_exchange.clone()
        && let Some(dimension) = PermissionDimension::from_endpoint(path)
        && state.clearing_dimensions.contains(&dimension)
    {
        // The ceiling comes from the verified certificate, so a request without
        // one cannot bid. Refusing is the only honest option: the alternative is
        // to invent a ceiling, which is what "the agent declares its own value"
        // means.
        let Some(ref certified) = certified_perms else {
            return Err(ApiError::KernelDenied {
                message: format!(
                    "{} is cleared by auction; a verified delegation certificate is                      required to bid for it",
                    dimension.label()
                ),
                code: None,
            });
        };
        let ceiling = CertifiedCeiling::from_verified(&certified.verified);
        // v1 bids the full certified ceiling. Under a second-price rule that is
        // the truthful report when the ceiling IS the principal's value for the
        // task, which is what `budget.max_cost_usd` on a task-scoped certificate
        // means. A per-task value carried in the certificate is the refinement
        // this leaves open, and it is a certificate change, not a mechanism one.
        let bid = SignedBid::new(
            AgentId::new(certified.verified.leaf_identity().to_string()),
            dimension,
            ceiling.get(),
            ceiling,
        )
        .map_err(|e| ApiError::KernelDenied {
            message: format!("authority bid refused: {e}"),
            code: None,
        })?;

        match scheduler.join(bid).await {
            Verdict::Won {
                round,
                price,
                receipt,
            } => {
                record_round(
                    state,
                    certified.verified.leaf_identity(),
                    nucleus_lineage::edge::EdgeKind::Allocation {
                        market_id: round.as_str().to_string(),
                        mechanism: "vcg".to_string(),
                    },
                    &receipt,
                );
                tracing::info!(
                    dimension = dimension.label(),
                    round = round.as_str(),
                    price_micro_usd = price.get(),
                    leaf = %certified.verified.leaf_identity(),
                    event = "authority_slot_won",
                    "authority slot cleared and charged"
                );
            }
            Verdict::Lost { round, receipt } => {
                // A loser is recorded too, and gets the receipt: being outbid is
                // a fact about a round it can recompute, not a claim it has to
                // accept.
                record_round(
                    state,
                    certified.verified.leaf_identity(),
                    nucleus_lineage::edge::EdgeKind::Bid {
                        market_id: round.as_str().to_string(),
                    },
                    &receipt,
                );
                return Err(ApiError::KernelDenied {
                    message: format!(
                        "outbid for the {} slot in round {}",
                        dimension.label(),
                        round.as_str()
                    ),
                    code: None,
                });
            }
            Verdict::Denied(reason) => {
                // Every non-win refuses, including a round that never closed.
                tracing::warn!(
                    dimension = dimension.label(),
                    reason = %reason,
                    event = "authority_slot_denied",
                    "authority clearing refused the request"
                );
                return Err(ApiError::KernelDenied {
                    message: format!("{} slot not granted: {reason}", dimension.label()),
                    code: None,
                });
            }
        }
    }
    Ok(())
}

/// Write one participant's part in a cleared round to the authority ledger.
///
/// A failure to record is logged and does not fail the request: the round has
/// already cleared and the winner has already been charged, so refusing here
/// would deny a slot that was paid for. The startup check is where a missing
/// ledger is refused — by the time a round has cleared it is too late to
/// pretend it did not.
fn record_round(
    state: &AppState,
    leaf_identity: &str,
    kind: nucleus_lineage::edge::EdgeKind,
    receipt: &nucleus_recompute::ClearingReceipt,
) {
    let Some(ledger) = state.authority_ledger.as_ref() else {
        return;
    };
    let child = match nucleus_lineage::id::CallSpiffeId::parse(leaf_identity)
        .and_then(|id| id.derive_tool("authority", None))
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                leaf = leaf_identity,
                error = %e,
                event = "authority_round_unrecorded",
                "cleared round not recorded: the caller's identity is not a SPIFFE id"
            );
            return;
        }
    };
    if let Err(e) = ledger.record(child, kind, nucleus_recompute::content_hash_hex(receipt)) {
        tracing::warn!(
            error = %e,
            event = "authority_round_unrecorded",
            "cleared round not recorded"
        );
    }
}

/// Parse and evaluate a permission bid from request headers.
///
/// Returns `Some(PermissionGrant)` if a valid bid was present, `None` otherwise.
/// Invalid bid JSON is silently ignored (logged at warn level).
pub(crate) fn evaluate_permission_bid(
    headers: &HeaderMap,
    state: &AppState,
) -> Option<PermissionGrant> {
    let bid_header = headers.get(HEADER_PERMISSION_BID)?;
    let bid_str = bid_header.to_str().ok()?;
    let bid: PermissionBid = match serde_json::from_str(bid_str) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "invalid permission bid header");
            return None;
        }
    };

    let market = state.permission_market.lock().unwrap();
    let grant = market.evaluate_bid(&bid);

    tracing::info!(
        skill_id = %bid.skill_id,
        granted = grant.granted.len(),
        denied = grant.denied.len(),
        total_cost = grant.total_cost,
        event = "permission_bid_evaluated",
        "permission market evaluated bid"
    );

    Some(grant)
}

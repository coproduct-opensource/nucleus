//! The authority exchange's wiring into the proxy: the `--clearing` flag, the
//! scheduler and ledger built from it at startup, the round a request joins in
//! `auth_middleware`, and the per-participant record afterwards.
//!
//! Extracted from `main.rs` whole, so `main.rs` stays under its line ceiling;
//! nothing here decides anything `main.rs` did not already decide the same way.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use nucleus_authority_exchange::{CertifiedCeiling, Charger, RoundScheduler, SignedBid, Verdict};
use nucleus_econ_types::AgentId;
use nucleus_permission_market::PermissionDimension;
use tracing::info;

use crate::{ApiError, AppState, art12_sink, authority_ledger, pod_cert};

/// Which dimensions `--clearing` names, or why the flag is wrong.
///
/// An unknown name is an error, not a skip. The failure this forbids is a typo
/// (`network-egress` for `network_egress`) that leaves the operator believing a
/// dimension is auctioned while it quietly stays on the posted-price path —
/// absence of evidence reading as evidence of absence, which is the exact shape
/// `GI002` exists to catch in the shell gates.
pub(crate) fn parse_clearing_dimensions(
    names: &[String],
) -> Result<BTreeSet<PermissionDimension>, String> {
    let mut set = BTreeSet::new();
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

/// What startup builds from the `--clearing*` flags.
pub(crate) struct Exchange {
    pub(crate) clearing_dimensions: BTreeSet<PermissionDimension>,
    pub(crate) scheduler: Option<Arc<RoundScheduler<Box<dyn Charger>>>>,
    pub(crate) ledger: Option<Arc<authority_ledger::AuthorityLedger>>,
}

/// Build the exchange from the flags, or refuse to start.
///
/// Inert unless an operator names a dimension: an empty `--clearing` leaves
/// both halves `None` and every dimension on the posted-price path it is on
/// today. With a dimension named, the ledger is REQUIRED: fail closed at
/// startup rather than clear unrecorded, because a price nobody can check
/// afterwards is not what an auction is for.
pub(crate) fn build(
    clearing: &[String],
    clearing_window_ms: u64,
    ledger_path: Option<&PathBuf>,
    delegation_ceiling: &portcullis::PermissionLattice,
) -> Result<Exchange, ApiError> {
    let clearing_dimensions = parse_clearing_dimensions(clearing).map_err(ApiError::Body)?;
    if clearing_dimensions.is_empty() {
        return Ok(Exchange {
            clearing_dimensions,
            scheduler: None,
            ledger: None,
        });
    }
    // The pod cannot spend more on authority than it was delegated: the
    // ledger's ceiling IS this pod's delegated budget, so a round it cannot
    // afford denies rather than overdrawing.
    let charger: Box<dyn Charger> =
        Box::new(nucleus_authority_exchange::scheduler::LedgerCharger::new(
            portcullis::budget_ledger::BudgetLedger::for_parent(&delegation_ceiling.budget),
        ));
    info!(
        dimensions = %clearing_dimensions.iter().map(|d| d.label()).collect::<Vec<_>>().join(","),
        window_ms = clearing_window_ms,
        "authority exchange enabled: these dimensions clear by truthful auction"
    );
    let scheduler = RoundScheduler::new(
        std::time::Duration::from_millis(clearing_window_ms),
        charger,
    );

    let Some(path) = ledger_path else {
        return Err(ApiError::Body(
            "--clearing names a dimension but --authority-ledger is unset; a cleared \
             round must be recorded or its price cannot be checked afterwards"
                .to_string(),
        ));
    };
    let Some(seed) = art12_sink::mediation_seed_from_env() else {
        return Err(ApiError::Body(
            "--clearing names a dimension but NUCLEUS_MEDIATION_SIGNING_KEY is unset \
             or malformed; the authority ledger signs with the pod's mediation key"
                .to_string(),
        ));
    };
    let Some(ledger) = authority_ledger::AuthorityLedger::open(path, seed, "pod-mediation") else {
        return Err(ApiError::Body(format!(
            "could not open the authority ledger at {}",
            path.display()
        )));
    };
    // The PUBLIC half, once, so a reader of the ledger can verify its chain.
    // Without this the edges are signed by a key nobody outside the pod has,
    // which makes a tamper-evident log tamper-evident to nobody. Same
    // reasoning, and the same key, as the mediation receipts' console
    // publication; a relying party cross-checks it against the node's record
    // of the key it minted for this pod.
    info!(
        path = %path.display(),
        kid = ledger.kid(),
        verifying_key_hex = %hex::encode(ledger.verifying_key().to_bytes()),
        "authority ledger open: every cleared round is recorded per participant"
    );
    Ok(Exchange {
        clearing_dimensions,
        scheduler: Some(scheduler),
        ledger: Some(Arc::new(ledger)),
    })
}

/// A request for an auctioned dimension joins a round, waits for it to close,
/// and is admitted only if it wins AND the Clarke pivot is charged. Every other
/// outcome refuses.
///
/// Called BEFORE the posted-price screen, because the two are alternative
/// mechanisms for the same decision and running both would price the slot
/// twice. `Ok(())` when the dimension is not auctioned at all.
pub(crate) async fn join_if_auctioned(
    state: &AppState,
    path: &str,
    certified_perms: Option<&pod_cert::CertifiedPermissions>,
) -> Result<(), ApiError> {
    let Some(scheduler) = state.authority_exchange.clone() else {
        return Ok(());
    };
    let Some(dimension) = PermissionDimension::from_endpoint(path) else {
        return Ok(());
    };
    if !state.clearing_dimensions.contains(&dimension) {
        return Ok(());
    }
    // The ceiling comes from the verified certificate, so a request without
    // one cannot bid. Refusing is the only honest option: the alternative is
    // to invent a ceiling, which is what "the agent declares its own value"
    // means.
    let Some(certified) = certified_perms else {
        return Err(ApiError::KernelDenied {
            message: format!(
                "{} is cleared by auction; a verified delegation certificate is \
                 required to bid for it",
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
            Ok(())
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
            Err(ApiError::KernelDenied {
                message: format!(
                    "outbid for the {} slot in round {}",
                    dimension.label(),
                    round.as_str()
                ),
                code: None,
            })
        }
        Verdict::Denied(reason) => {
            // Every non-win refuses, including a round that never closed.
            tracing::warn!(
                dimension = dimension.label(),
                reason = %reason,
                event = "authority_slot_denied",
                "authority clearing refused the request"
            );
            Err(ApiError::KernelDenied {
                message: format!("{} slot not granted: {reason}", dimension.label()),
                code: None,
            })
        }
    }
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

    /// Inertness at the level ABOVE the flag parser: with no `--clearing`, the
    /// builder returns an exchange that cannot clear anything, so the whole
    /// mechanism is unreachable rather than merely unused.
    #[test]
    fn with_no_dimension_named_the_builder_returns_an_inert_exchange() {
        let lattice = portcullis::PermissionLattice::permissive();
        let ex = build(&[], 20, None, &lattice).expect("an empty --clearing is valid");
        assert!(ex.clearing_dimensions.is_empty());
        assert!(
            ex.scheduler.is_none() && ex.ledger.is_none(),
            "an inert exchange holds neither half"
        );
    }

    /// And it stays inert when the flag is present but names nothing, which is
    /// what `--clearing ""` produces.
    ///
    /// A lone `","` is NOT this case and must not be: each argument is trimmed
    /// on its own, so `","` is a dimension nobody recognises and errors. That
    /// is the same refusal a typo gets, and it is the right one — silently
    /// treating an unrecognised argument as "nothing named" is how a dimension
    /// stays on the posted-price path while the operator believes it is
    /// auctioned.
    #[test]
    fn a_flag_that_names_nothing_is_still_inert() {
        let lattice = portcullis::PermissionLattice::permissive();
        let ex = build(&[String::new()], 20, None, &lattice).expect("names nothing, so valid");
        assert!(
            ex.scheduler.is_none(),
            "an empty name built a live exchange"
        );

        assert!(
            build(&[",".to_string()], 20, None, &lattice).is_err(),
            "a lone comma is an unrecognised dimension, not an empty one"
        );
    }

    /// FAIL CLOSED. A dimension that clears by auction with nowhere to record
    /// the round must refuse at startup, because a price nobody can check
    /// afterwards is not what an auction is for. Refusing here rather than at
    /// the first request is the difference between a server that will not start
    /// and one that clears unrecorded until someone looks.
    #[test]
    fn a_named_dimension_without_a_ledger_refuses_to_start() {
        let lattice = portcullis::PermissionLattice::permissive();
        // Matched rather than `expect_err`, which would need `Exchange: Debug`
        // — and it holds a boxed trait object that has no reason to be.
        let Err(err) = build(&["network_egress".to_string()], 20, None, &lattice) else {
            panic!("a named dimension with no ledger must refuse");
        };
        let msg = format!("{err:?}");
        assert!(
            msg.contains("--authority-ledger is unset"),
            "the refusal must name the missing flag: {msg}"
        );
        assert!(
            msg.contains("cannot be checked afterwards") || msg.contains("must be recorded"),
            "the refusal must say WHY recording is required: {msg}"
        );
    }

    /// The refusal is about the ledger, not about the dimension: every
    /// auctionable dimension refuses the same way, so the fail-closed rule
    /// cannot be true of one label and false of another.
    #[test]
    fn every_dimension_refuses_the_same_way_without_a_ledger() {
        let lattice = portcullis::PermissionLattice::permissive();
        for d in PermissionDimension::ALL {
            let Err(err) = build(&[d.label().to_string()], 20, None, &lattice) else {
                panic!("{}: no ledger, so it must refuse", d.label());
            };
            assert!(
                format!("{err:?}").contains("--authority-ledger is unset"),
                "{} refused for a different reason",
                d.label()
            );
        }
    }
}

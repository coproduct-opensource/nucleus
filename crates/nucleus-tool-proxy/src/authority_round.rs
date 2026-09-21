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
use nucleus_econ_types::{AgentId, MicroUsd};
use nucleus_permission_market::PermissionDimension;
use portcullis::certificate::VerifiedPermissions;
use tracing::info;

use crate::host_socket::PodPeer;
use crate::{ApiError, AppState, art12_sink, authority_ledger, pod_cert};

/// Who is asking for an auctioned slot, as established by facts a request
/// cannot claim (#2988).
pub(crate) enum Bidder<'a> {
    /// An mTLS caller whose delegation-certificate chain verified: it bids
    /// under its own ceiling, as its own leaf identity.
    Certified(&'a pod_cert::CertifiedPermissions),
    /// A process inside the pod, named by the kernel over the peer-verified
    /// Unix socket: it bids under the POD's certificate, as `(uid, pid)` beneath
    /// the pod's leaf. Two processes are two bidders; one process is one.
    PodPeer(PodPeer),
    /// Neither. Cannot bid, and an auctioned dimension refuses it.
    Nobody,
}

/// The header a bidder may use to declare a value BELOW its ceiling, in
/// micro-USD. Absent or unparsable means "the whole ceiling"; a value above
/// the ceiling is refused by `SignedBid::new`, never clamped.
pub(crate) const HEADER_BID_MICRO_USD: &str = "x-nucleus-bid-micro-usd";

/// The declared value, if the header carries a non-negative integer.
pub(crate) fn bid_value(headers: &axum::http::HeaderMap) -> Option<MicroUsd> {
    headers
        .get(HEADER_BID_MICRO_USD)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(MicroUsd::new)
}

/// The bidder identity of a process inside the pod: the pod's leaf with the
/// kernel-reported `(uid, pid)` beneath it. `DuplicateBidder` in the round is
/// what makes one process one bidder per round; distinct processes are
/// distinct. Splitting oneself across processes cannot lower one's own price
/// under the second-price rule, and every peer draws on the same pod ledger,
/// so the pod is charged once for what its processes won.
pub(crate) fn peer_agent_id(pod_leaf: &str, peer: PodPeer) -> AgentId {
    AgentId::new(format!(
        "{pod_leaf}/peer/uid-{}/pid-{}",
        peer.uid,
        peer.pid.unwrap_or(0)
    ))
}

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
    bidder: Bidder<'_>,
    headers: &axum::http::HeaderMap,
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
    // The ceiling comes from a VERIFIED chain — the caller's own certificate,
    // or the pod's for a kernel-attributed process inside it — so a request
    // that is neither cannot bid. Refusing is the only honest option: the
    // alternative is to invent a ceiling, which is what "the agent declares
    // its own value" means.
    let (verified, agent, peer): (&VerifiedPermissions, AgentId, Option<PodPeer>) = match bidder {
        Bidder::Certified(c) => (
            &c.verified,
            AgentId::new(c.verified.leaf_identity().to_string()),
            None,
        ),
        Bidder::PodPeer(peer) => {
            let Some(v) = state.pod_verified.as_deref() else {
                return Err(ApiError::KernelDenied {
                    message: format!(
                        "{} is cleared by auction; this pod holds no certificate, so a \
                         process inside it has no ceiling to bid under",
                        dimension.label()
                    ),
                    code: None,
                });
            };
            (v, peer_agent_id(v.leaf_identity(), peer), Some(peer))
        }
        Bidder::Nobody => {
            return Err(ApiError::KernelDenied {
                message: format!(
                    "{} is cleared by auction; a verified delegation certificate or a \
                     kernel-attributed pod peer is required to bid for it",
                    dimension.label()
                ),
                code: None,
            });
        }
    };
    let leaf = verified.leaf_identity().to_string();
    let ceiling = CertifiedCeiling::from_verified(verified);
    // The bid is the caller's declared value, capped by the verified ceiling
    // (`SignedBid::new` refuses one above it), or the whole ceiling when none
    // is declared. Declaring a value UNDER a verified ceiling is what a bid is;
    // what #2526 removed was a value with no ceiling behind it. Under the
    // second-price rule the dominant strategy is the true value, so nothing
    // here rewards misreporting.
    let value = bid_value(headers).unwrap_or_else(|| ceiling.get());
    let bid =
        // The proxy's scarce good IS a permission dimension; the conversion is
        // the boundary between this pod's vocabulary and the mechanism's.
        SignedBid::new(agent, dimension.into(), value, ceiling).map_err(|e| ApiError::KernelDenied {
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
                &leaf,
                peer,
                nucleus_lineage::edge::EdgeKind::Allocation {
                    market_id: round.as_str().to_string(),
                    mechanism: "vcg".to_string(),
                },
                &receipt,
            );
            // The charge was made in this guest's ledger; tell the host, signed,
            // so the node can fold what was spent rather than everything (#2541).
            if let Some(ref shipper) = state.spend_shipper {
                shipper.charge(
                    price.get(),
                    &format!(
                        "authority-round:{}",
                        nucleus_recompute::content_hash_hex(&receipt)
                    ),
                    &receipt,
                );
            }
            tracing::info!(
                dimension = dimension.label(),
                round = round.as_str(),
                price_micro_usd = price.get(),
                leaf = %leaf,
                peer = ?peer,
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
                &leaf,
                peer,
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
    peer: Option<PodPeer>,
    kind: nucleus_lineage::edge::EdgeKind,
    receipt: &nucleus_recompute::ClearingReceipt,
) {
    let Some(ledger) = state.authority_ledger.as_ref() else {
        return;
    };
    // A pod peer's edge hangs off the POD's identity (the chain the ceiling
    // came from) with the peer bound into the derived id's content hash, so
    // two peers' edges are two edges under one leaf rather than one edge
    // written twice.
    let peer_tag = peer.map(|p| peer_agent_id(leaf_identity, p).as_str().as_bytes().to_vec());
    let child = match nucleus_lineage::id::CallSpiffeId::parse(leaf_identity)
        .and_then(|id| id.derive_tool("authority", peer_tag.as_deref()))
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

#[cfg(test)]
mod pod_peer_bidder_tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    const LEAF: &str = "spiffe://nucleus.local/ns/pods/sa/0f7b3a2e";

    /// The property #2988 exists for: two processes in one pod are two
    /// bidders, and the same process is the same bidder. Both under the pod's
    /// leaf, so the ledger charging the pod is charging the right principal.
    #[test]
    fn distinct_processes_are_distinct_bidders_under_one_leaf() {
        let a = peer_agent_id(
            LEAF,
            PodPeer {
                uid: 65534,
                pid: Some(41),
            },
        );
        let b = peer_agent_id(
            LEAF,
            PodPeer {
                uid: 65534,
                pid: Some(42),
            },
        );
        let a_again = peer_agent_id(
            LEAF,
            PodPeer {
                uid: 65534,
                pid: Some(41),
            },
        );
        assert_ne!(a, b, "two pids, two bidders");
        assert_eq!(a, a_again, "one pid, one bidder");
        assert!(
            a.as_str().starts_with(LEAF),
            "{a:?} is not under the pod's leaf"
        );
        // Different uids with the same pid cannot happen in one namespace, but
        // the identity must still tell them apart rather than collapse them.
        let c = peer_agent_id(
            LEAF,
            PodPeer {
                uid: 1000,
                pid: Some(41),
            },
        );
        assert_ne!(a, c);
    }

    #[test]
    fn a_declared_value_is_read_and_garbage_means_the_whole_ceiling() {
        let mut h = HeaderMap::new();
        assert_eq!(bid_value(&h), None, "absent: the caller bids its ceiling");
        h.insert(HEADER_BID_MICRO_USD, HeaderValue::from_static(" 250000 "));
        assert_eq!(bid_value(&h), Some(MicroUsd::new(250_000)));
        h.insert(HEADER_BID_MICRO_USD, HeaderValue::from_static("-1"));
        assert_eq!(bid_value(&h), None, "a negative value is not a bid");
        h.insert(HEADER_BID_MICRO_USD, HeaderValue::from_static("lots"));
        assert_eq!(bid_value(&h), None);
    }

    /// The peer's lineage edge is derived from the POD's id with the peer
    /// bound into it: `record_round` must be able to parse the pod leaf, and
    /// the peer tag must change the derived id.
    #[test]
    fn a_peer_edge_is_derived_from_the_pod_leaf_with_the_peer_bound_in() {
        let pod = nucleus_lineage::id::CallSpiffeId::parse(LEAF).expect("a pod leaf parses");
        let tag_a = peer_agent_id(
            LEAF,
            PodPeer {
                uid: 65534,
                pid: Some(41),
            },
        );
        let tag_b = peer_agent_id(
            LEAF,
            PodPeer {
                uid: 65534,
                pid: Some(42),
            },
        );
        let a = pod
            .derive_tool("authority", Some(tag_a.as_str().as_bytes()))
            .expect("derives");
        let b = pod
            .derive_tool("authority", Some(tag_b.as_str().as_bytes()))
            .expect("derives");
        // `derive_tool` mints a fresh uuid each call, so compare the bound
        // content hash, which is the peer.
        let hash = |id: &nucleus_lineage::id::CallSpiffeId| {
            id.as_str().rsplit("/sha256:").next().map(str::to_owned)
        };
        assert_ne!(hash(&a), hash(&b), "two peers must not share a derived id");
    }
}

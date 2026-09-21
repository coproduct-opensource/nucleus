//! `nucleus-perf exchange` — what does clearing authority by auction actually buy?
//!
//! # What this measures, and what it deliberately does not
//!
//! A VCG round awards a contended slot to the highest bidder. FIFO awards it to
//! whoever asked first. That VCG wins on realised welfare is **arithmetic, not a
//! finding** — it allocates to the maximum by construction, so a harness that
//! reported "VCG is better" as a result would be reporting its own definition
//! back to itself.
//!
//! The numbers worth having are the ones that depend on the workload rather than
//! on the mechanism:
//!
//! * **The contested fraction.** Below it, the auction is pure overhead: an
//!   uncontested round clears at a price of zero and allocates to the only
//!   bidder, which is what FIFO would have done, one window later. This is the
//!   number that decides whether to enable a dimension at all, and it is a
//!   property of the arrival rate against the window, not of VCG.
//! * **What FIFO leaves on the table**, in the same units, at *this* arrival
//!   rate. The size of that gap is a fact about the value distribution.
//! * **The clearing price distribution** — what a slot of authority actually
//!   costs when someone else wants it. This is the series that has never existed,
//!   and it is the one output here that is not derivable from the inputs.
//!
//! # Why it drives the real scheduler
//!
//! Bugs in this system have hidden in composition, not in units. The harness
//! drives `nucleus_authority_exchange::RoundScheduler` itself — real windows,
//! real detached closer tasks, real `run_vcg` — so a regression in the grouping
//! or the pivot shows up here. A reimplementation of the mechanism would measure
//! the reimplementation.
//!
//! # Non-vacuity
//!
//! If no round was contested the run reports it and **exits non-zero**. A
//! measurement over rounds that never had two bidders says nothing about an
//! auction, and reporting a welfare uplift from such a run would be reporting
//! noise as a result.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use clap::Parser;
use nucleus_authority_exchange::{
    ChargeError, Charger, RoundScheduler, Verdict, test_support::bid,
};
use nucleus_econ_types::{AgentId, MicroUsd};
use nucleus_permission_market::PermissionDimension;

#[derive(Parser, Debug)]
pub struct Args {
    /// How many bids to submit in total.
    #[arg(long, default_value_t = 400)]
    bids: u32,

    /// Mean gap between arrivals, in milliseconds. Contention is this against
    /// `--window-ms`: a rate far slower than the window produces rounds of one.
    #[arg(long, default_value_t = 5)]
    arrival_gap_ms: u64,

    /// The round's collection window.
    #[arg(long, default_value_t = 20)]
    window_ms: u64,

    /// Highest private value a bidder may draw, in micro-USD. Values are drawn
    /// uniformly from `1..=max-value`.
    #[arg(long, default_value_t = 10_000)]
    max_value: u64,

    /// Seed. The same seed gives the same run, so a reported number can be
    /// reproduced rather than believed.
    #[arg(long, default_value_t = 1)]
    seed: u64,
}

/// Accepts every charge: this harness measures allocation, not solvency. Stated
/// because a charger that refused would silently make every win a denial and the
/// welfare numbers would be zero for a reason unrelated to the mechanism.
struct AlwaysPays;

impl Charger for AlwaysPays {
    fn charge(&self, _payer: &AgentId, _price: MicroUsd) -> Result<(), ChargeError> {
        Ok(())
    }
}

/// splitmix64 — a seeded generator so a run is reproducible from its `--seed`
/// alone, with no dependency added for four lines of arithmetic.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `1..=hi`.
    fn upto(&mut self, hi: u64) -> u64 {
        if hi == 0 { 0 } else { self.next() % hi + 1 }
    }
}

/// One bid's outcome, as observed.
struct Observed {
    /// The bidder's private value, which is also what it reported.
    value: u64,
    /// `Some(price)` if it won.
    won_at: Option<u64>,
    /// Arrival order within the whole run — the FIFO baseline's tiebreaker.
    seq: u32,
    /// Which round it landed in, recovered from the receipt's declared bids.
    round: Option<String>,
    /// The round's receipt, kept so the run can close the loop into standing.
    receipt: Option<std::sync::Arc<nucleus_recompute::ClearingReceipt>>,
}

pub async fn run(args: Args) -> Result<()> {
    let dim = PermissionDimension::NetworkEgress;
    let scheduler = RoundScheduler::new(Duration::from_millis(args.window_ms), AlwaysPays);
    let mut rng = Rng(args.seed);

    let mut handles = Vec::new();
    for seq in 0..args.bids {
        let value = rng.upto(args.max_value);
        let s = Arc::clone(&scheduler);
        let agent = format!("bidder-{seq:05}");
        handles.push(tokio::spawn(async move {
            let verdict = s.join(bid(&agent, value, dim)).await;
            (seq, value, verdict)
        }));
        // Arrival pacing. Jittered around the mean so bids do not land in
        // lockstep, which would make the contested fraction an artefact of the
        // harness rather than of the rate.
        let gap = rng.upto(args.arrival_gap_ms.saturating_mul(2));
        tokio::time::sleep(Duration::from_millis(gap)).await;
    }

    let mut observed = Vec::new();
    for h in handles {
        let (seq, value, verdict) = h.await?;
        let (won_at, round, receipt) = match verdict {
            // `round` is deliberately ignored in favour of a label derived from
            // the RECEIPT: taking the scheduler's own id would be the harness
            // agreeing with the thing it is measuring about which bids shared a
            // round. Now that a loser carries the receipt too, every bid gets
            // its label from a signed artefact rather than from string matching.
            Verdict::Won { price, receipt, .. } => {
                (Some(price.get()), round_label(&receipt), Some(receipt))
            }
            Verdict::Lost { receipt, .. } => (None, round_label(&receipt), Some(receipt)),
            Verdict::Denied(reason) => bail!(
                "bid {seq} was denied ({reason}); this harness charges everything, \
                 so a denial means the mechanism refused and the run is not measuring \
                 what it claims"
            ),
        };
        observed.push(Observed {
            value,
            won_at,
            seq,
            round,
            receipt,
        });
    }

    report(&observed, &args)
}

/// A round's identity, recovered from the receipt: the sorted bidder set. Two
/// bids share a round exactly when their receipts declare the same bidders, and
/// that is read from the signed receipt rather than from the harness's own
/// bookkeeping — so a grouping bug cannot be hidden by the harness agreeing with
/// itself.
fn round_label(receipt: &nucleus_recompute::ClearingReceipt) -> Option<String> {
    let nucleus_recompute::ClearingReceipt::Vcg(claim) = receipt else {
        return None;
    };
    let mut ids: Vec<&str> = claim.bids.iter().map(|b| b.bidder.as_str()).collect();
    ids.sort_unstable();
    Some(ids.join(","))
}

fn report(observed: &[Observed], args: &Args) -> Result<()> {
    let wins: Vec<&Observed> = observed.iter().filter(|o| o.won_at.is_some()).collect();
    let rounds = wins.len();
    // A round is contested when its winner paid more than zero — the Clarke
    // pivot is zero exactly when nobody was displaced.
    let contested: Vec<&&Observed> = wins
        .iter()
        .filter(|o| o.won_at.is_some_and(|p| p > 0))
        .collect();

    // Realised welfare under VCG: the sum of the winners' true values.
    let vcg_welfare: u128 = wins.iter().map(|o| u128::from(o.value)).sum();

    // FIFO over the SAME rounds: in each round, the earliest arrival takes it.
    let mut fifo_welfare: u128 = 0;
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for w in &wins {
        let Some(label) = w.round.as_deref() else {
            continue;
        };
        if !seen.insert(label) {
            continue;
        }
        let first = observed
            .iter()
            .filter(|o| o.round.as_deref() == Some(label))
            .min_by_key(|o| o.seq);
        if let Some(f) = first {
            fifo_welfare = fifo_welfare.saturating_add(u128::from(f.value));
        }
    }

    let mut prices: Vec<u64> = contested.iter().filter_map(|o| o.won_at).collect();
    prices.sort_unstable();

    println!("nucleus-perf exchange — seed {}", args.seed);
    println!(
        "  {} bid(s), arrival gap ~{} ms, window {} ms, values 1..={} µUSD",
        observed.len(),
        args.arrival_gap_ms,
        args.window_ms,
        args.max_value
    );
    println!("  rounds cleared        {rounds}");
    println!(
        "  contested             {} ({:.1}% — below this the auction is overhead)",
        contested.len(),
        pct(contested.len(), rounds)
    );

    if contested.is_empty() {
        println!();
        println!(
            "  NON-VACUITY FAILED: no round had two bidders, so nothing here is a\n\
             \x20 measurement of an auction. Raise --bids, lower --arrival-gap-ms, or\n\
             \x20 raise --window-ms until rounds actually contend."
        );
        bail!("no contested round");
    }

    println!(
        "  clearing price        p50 {} µUSD, p90 {} µUSD, max {} µUSD",
        pctl(&prices, 50),
        pctl(&prices, 90),
        prices.last().copied().unwrap_or(0)
    );
    println!("  welfare (VCG)         {vcg_welfare} µUSD");
    println!("  welfare (FIFO)        {fifo_welfare} µUSD");
    if fifo_welfare > 0 {
        println!(
            "  FIFO leaves           {} µUSD on the table ({:.1}%)",
            vcg_welfare.saturating_sub(fifo_welfare),
            pct_u128(vcg_welfare.saturating_sub(fifo_welfare), vcg_welfare)
        );
    }

    standing(observed)?;

    println!();
    println!(
        "  Read this as a fact about the workload, not about VCG: allocating to the\n\
         \x20 highest bidder beats allocating to the earliest by construction. What the\n\
         \x20 run tells you is HOW MUCH, at this arrival rate, and what a contended slot\n\
         \x20 costs when someone else wants it."
    );
    Ok(())
}

/// Close the loop the receipts exist for: `receipt → recompute → CreditEvent →
/// CreditFile → required_bond`.
///
/// # Whose standing this is
///
/// **The clearing site's, not a bidder's.** A clearing receipt's honesty is a
/// fact about the *clearing* — it recomputed from declared inputs — and says
/// nothing about who bid into it. So what accrues here is the standing of the
/// party that issued the receipts, which is exactly the credible-clearing story:
/// the auctioneer is untrusted, and every clearing anyone can re-derive is one
/// more reason not to need to trust it. Reading this as a bidder's reputation
/// would be attributing a property of the arithmetic to a participant.
///
/// # Reported, never enforced
///
/// `docs/rfcs/receipt-provenance-defection.md` sets four conditions before
/// standing may gate anything: every money-gating event derives from a
/// recompute-verified receipt *in code*; obligations are signed and debits land
/// on the signing key; the bond is posted and slashable; and the ledger is
/// durable and transparency-logged. Only the first holds here. This is a number
/// printed at the end of a run, and nothing in the exchange consults it.
/// Fold the run's receipts into a deduped set of credit events.
///
/// Extracted from [`standing`] so the deduplication can be pinned by a test: it
/// is the part that is easy to get wrong and invisible when wrong, because a
/// multiplied reputation looks exactly like a larger one.
fn reputation_set(observed: &[Observed]) -> nucleus_creditworthiness::crdt::ReputationSet {
    let mut set = nucleus_creditworthiness::crdt::ReputationSet::new();
    for o in observed {
        if let Some(r) = o.receipt.as_deref() {
            set.verified_insert(r);
        }
    }
    set
}

fn standing(observed: &[Observed]) -> Result<()> {
    // Deduped by receipt hash, which is the point of using the CRDT rather than
    // folding the receipts directly: every participant in a round holds the SAME
    // receipt, so a naive fold would multiply one honest clearing by the number
    // of bidders who witnessed it.
    let set = reputation_set(observed);
    if set.is_empty() {
        bail!(
            "no receipt minted a credit event: the standing below would be zero for a \
             reason unrelated to the clearings, so the run is not measuring what it claims"
        );
    }
    let file = set.credit_file();
    let reputation = file.reputation_micro();
    println!();
    println!(
        "  standing of the clearing site (deduped over {} receipt(s))",
        set.len()
    );
    println!("    reputation          {reputation} µUSD of verified clearing");
    // What that standing substitutes for: the bond an identity would otherwise
    // post to deter a one-shot defection worth the largest price seen.
    let worst = observed.iter().filter_map(|o| o.won_at).max().unwrap_or(0);
    println!(
        "    required bond       {} µUSD to deter a defection worth {worst} µUSD",
        file.required_bond(worst).0
    );
    println!(
        "    (reported, not enforced — three of the four conditions in\n\
         \x20    receipt-provenance-defection.md are not met, so nothing gates on it)"
    );
    Ok(())
}

fn pct(n: usize, d: usize) -> f64 {
    pct_u128(
        u128::try_from(n).unwrap_or(u128::MAX),
        u128::try_from(d).unwrap_or(u128::MAX),
    )
}

/// `100 · n / d` to two decimals, computed in integers and converted losslessly:
/// basis points fit `u32`, and `u32 → f64` is exact. No `as f64` on a count.
fn pct_u128(n: u128, d: u128) -> f64 {
    if d == 0 {
        return 0.0;
    }
    let bps = n.saturating_mul(10_000).checked_div(d).unwrap_or(0);
    f64::from(u32::try_from(bps).unwrap_or(u32::MAX)) / 100.0
}

fn pctl(sorted: &[u64], p: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (sorted.len().saturating_sub(1)).saturating_mul(p) / 100;
    sorted.get(idx).copied().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seed is the reproducibility contract: same seed, same draws.
    #[test]
    fn the_same_seed_gives_the_same_run() {
        let a: Vec<u64> = (0..8).scan(Rng(7), |r, _| Some(r.upto(1000))).collect();
        let b: Vec<u64> = (0..8).scan(Rng(7), |r, _| Some(r.upto(1000))).collect();
        assert_eq!(a, b);
        let c: Vec<u64> = (0..8).scan(Rng(8), |r, _| Some(r.upto(1000))).collect();
        assert_ne!(a, c, "a different seed must give a different run");
    }

    /// Values are in range and never zero — a zero bid is refused by
    /// `SignedBid`, so drawing one would abort the run rather than measure it.
    #[test]
    fn drawn_values_are_never_zero() {
        let mut r = Rng(42);
        for _ in 0..1000 {
            let v = r.upto(10);
            assert!((1..=10).contains(&v), "{v}");
        }
    }

    /// Every participant in a round holds the SAME receipt, so a round must
    /// contribute ONE credit event however many bidders witnessed it. Folding
    /// the receipts directly would multiply one honest clearing by the size of
    /// the round, and a multiplied reputation looks exactly like a larger one.
    #[tokio::test]
    async fn a_round_contributes_one_credit_event_however_many_bid() {
        let dim = PermissionDimension::NetworkEgress;
        let s = RoundScheduler::new(Duration::from_millis(20), AlwaysPays);
        let mut handles = Vec::new();
        for (name, v) in [("a", 100u64), ("b", 70), ("c", 40)] {
            let s = Arc::clone(&s);
            handles.push(tokio::spawn(async move { s.join(bid(name, v, dim)).await }));
        }
        let mut observed = Vec::new();
        for (seq, h) in handles.into_iter().enumerate() {
            let (won_at, receipt) = match h.await.expect("joined") {
                Verdict::Won { price, receipt, .. } => (Some(price.get()), Some(receipt)),
                Verdict::Lost { receipt, .. } => (None, Some(receipt)),
                Verdict::Denied(r) => panic!("denied: {r}"),
            };
            observed.push(Observed {
                value: 1,
                won_at,
                seq: u32::try_from(seq).expect("fewer than 2^32 observations"),
                round: None,
                receipt,
            });
        }
        assert_eq!(observed.len(), 3, "three bidders took part");
        assert_eq!(
            reputation_set(&observed).len(),
            1,
            "three witnesses to one clearing is one credit event, not three"
        );
        // And what the naive fold would have given, so this test carries its own
        // evidence that the deduplication is load-bearing rather than incidental.
        let receipts: Vec<_> = observed
            .iter()
            .filter_map(|o| o.receipt.as_deref().cloned())
            .collect();
        assert_eq!(
            nucleus_creditworthiness::mint::mint_events(&receipts).len(),
            3,
            "folding the receipts directly triples one clearing — the defect the \
             deduped set exists to prevent"
        );
    }

    /// The round label is the sorted bidder set from the receipt, so two bids
    /// that shared a round get byte-identical labels regardless of the order
    /// their verdicts came back in.
    #[test]
    fn the_round_label_is_order_independent() {
        use nucleus_econ_kernels::{Clearing as KClearing, IntegerBid, IntegerProposal};
        let mk = |names: [&str; 2]| {
            nucleus_recompute::ClearingReceipt::Vcg(nucleus_recompute::VcgClaim {
                bids: names
                    .iter()
                    .map(|n| IntegerBid {
                        bidder: (*n).to_string(),
                        proposal_id: "slot".into(),
                        effective_value_micro_usd: 1,
                    })
                    .collect(),
                proposals: vec![IntegerProposal {
                    id: "slot".into(),
                    cost_micro_usd: 1,
                }],
                budget_micro_usd: 1,
                clearing: KClearing {
                    winners: Vec::new(),
                    losers: Vec::new(),
                    total_effective_value_micro_usd: 0,
                    total_payments_micro_usd: 0,
                    budget_remaining_micro_usd: 1,
                },
            })
        };
        assert_eq!(
            round_label(&mk(["b", "a"])),
            round_label(&mk(["a", "b"])),
            "membership, not submission order, identifies a round"
        );
    }
}

//! The whole payout lifecycle, offline and runnable:
//!
//! ```text
//! cargo run -p nucleus-recompute --example payout_lifecycle
//! ```
//!
//! clearing → payout → settlement attestations → verification, and then four
//! attacks, each caught by a different check. Nothing here talks to a network:
//! every verdict is a recomputation a payee could run itself.

use nucleus_econ_kernels::commons::CommonsShare;
use nucleus_recompute::offer::{
    disclosure_hash_hex, offer_content_hash_hex, verify_offer, Offer, Sponsorship, SponsorshipKind,
    Terms,
};
use nucleus_recompute::payout::{issue_payout, verify_payout, Attribution};
use nucleus_recompute::settlement_attestation::{
    issue_settlement_attestation, verify_settlement, verify_settlement_set, SettlementSetOutcome,
};
use nucleus_recompute::{issue_settlement, verify_receipt};

fn main() {
    // ── 0. The offer being transacted. Its hash is what `Attribution` names, so
    //       the payout points at exact commercial terms rather than a blank.
    let offer = Offer::new(
        "offer-summarise-v1",
        "spiffe://vendor.example/seller",
        "summarise",
        "c".repeat(64),
        1_000_000,
        "USD",
        Sponsorship::paid(
            SponsorshipKind::PaidPlacement,
            "AcmeCorp",
            "Sponsored by AcmeCorp. Placement paid for; ranking unaffected.",
        ),
        Terms::default(),
    );
    println!("offer verifies: {:?}", verify_offer(&offer));
    println!("  hash:       {}", &offer_content_hash_hex(&offer)[..16]);
    println!("  disclosure: {}", &disclosure_hash_hex(&offer)[..16]);

    // ── 1. A cleared sale. Full delivery, so the whole price is distributable.
    let clearing = issue_settlement(1_000_000, 10_000); // $1.00, 100% delivered
    println!("clearing recomputes: {:?}", verify_receipt(&clearing));

    // ── 2. The split. Bps must sum to 10_000 — the proven kernel refuses
    //       anything else, so a skim cannot produce a standing receipt.
    let shares = vec![
        CommonsShare {
            destination: "seller".into(),
            bps: 7_000,
        },
        CommonsShare {
            destination: "runtime".into(),
            bps: 2_500,
        },
        CommonsShare {
            destination: "commons".into(),
            bps: 500,
        },
    ];
    let attribution = Attribution {
        workload_spiffe_id: "spiffe://nucleus.local/runtime/acme".into(),
        assurance: 1,
        offer_hash_hex: offer_content_hash_hex(&offer),
        disclosure_hash_hex: disclosure_hash_hex(&offer),
    };
    let payout = issue_payout(clearing, shares, attribution).expect("well-formed");

    println!("\npayout ({:?}):", verify_payout(&payout));
    for a in &payout.allocations {
        println!("  {:>8}  {:>9} µUSD", a.destination, a.amount_micro);
    }
    let total: u64 = payout.allocations.iter().map(|a| a.amount_micro).sum();
    println!(
        "  {:>8}  {total:>9} µUSD   (routed_conserves: nothing skimmed)",
        "TOTAL"
    );

    // ── 3. Settle every payee, and check the SET — not just one receipt.
    let attestations: Vec<_> = payout
        .allocations
        .iter()
        .map(|a| {
            issue_settlement_attestation(&payout, &a.destination, "x402-evm", "0xdeadbeef")
                .expect("known destination")
        })
        .collect();
    println!(
        "\nsettlement set: {:?}",
        verify_settlement_set(&attestations, &payout)
    );

    // ── 4. Four attacks. Each is caught by a different check, which is the
    //       point: no single one of them is doing all the work.
    println!("\nattacks:");

    // (a) The operator rounds a payee down by one micro-USD.
    let mut short = attestations[0].clone();
    short.amount_micro_usd_signed -= 1;
    println!(
        "  short-pay a payee     → {:?}",
        verify_settlement(&short, &payout)
    );

    // (b) The operator pays a wallet the split does not owe.
    let mut stranger = attestations[0].clone();
    stranger.destination = "spiffe://attacker.example/wallet".into();
    println!(
        "  pay a stranger        → {:?}",
        verify_settlement(&stranger, &payout)
    );

    // (c) The operator pays two of three, and shows each payee its own receipt.
    //     Every receipt verifies alone; the SET does not.
    let partial = &attestations[..2];
    for a in partial {
        assert!(
            verify_settlement(a, &payout).is_match(),
            "each verifies alone"
        );
    }
    match verify_settlement_set(partial, &payout) {
        SettlementSetOutcome::Unsettled { destinations } => {
            println!("  pay 2 of 3            → Unsettled {destinations:?}  (each receipt verified alone!)");
        }
        other => println!("  pay 2 of 3            → {other:?}"),
    }

    // (d) The operator re-points a settlement at a cheaper payout.
    let cheaper = issue_payout(
        issue_settlement(1_000_000, 5_000), // half delivered → half the pool
        vec![CommonsShare {
            destination: "seller".into(),
            bps: 10_000,
        }],
        Attribution {
            workload_spiffe_id: "spiffe://nucleus.local/runtime/acme".into(),
            assurance: 1,
            offer_hash_hex: offer_content_hash_hex(&offer),
            disclosure_hash_hex: disclosure_hash_hex(&offer),
        },
    )
    .expect("well-formed");
    let outcome = verify_settlement(&attestations[0], &cheaper);
    println!(
        "  re-point the payout   → {}",
        match outcome {
            nucleus_recompute::settlement_attestation::SettlementOutcome::PayoutMismatch {
                ..
            } => "PayoutMismatch (the attestation names its payout by hash)".to_string(),
            other => format!("{other:?}"),
        }
    );

    println!("\nNothing above consulted a network. A payee runs exactly this.");
}

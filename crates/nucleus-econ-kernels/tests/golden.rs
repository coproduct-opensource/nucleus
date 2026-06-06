//! Golden-vector parity reader (Rust) — gap G3.
//!
//! Loads the canonical vectors in `tests/golden/*.json` — the SINGLE SOURCE that
//! also pins the Lean (`Nucleus/Golden.lean`, generated from these same files),
//! the Solidity (`CredibleSettlement.t.sol`), and the WASM (`@coproduct/verify`)
//! implementations — and asserts the Rust kernels reproduce them exactly. Editing
//! any kernel so it diverges from the golden bytes turns this test (and CI) red.

use std::path::PathBuf;

use nucleus_econ_kernels::{
    classify, refund, route_to_commons, run_vcg, seller_gross, CommonsShare, IntegerBid,
    IntegerProposal, Verdict,
};
use serde_json::Value;

fn golden(name: &str) -> Value {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "golden", name]
        .iter()
        .collect();
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {path:?}: {e}"))
}

fn u64f(v: &Value, k: &str) -> u64 {
    v.get(k)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("missing u64 field {k} in {v}"))
}

#[test]
fn settlement_matches_golden() {
    let g = golden("settlement.json");
    for vec in g["vectors"].as_array().unwrap() {
        let price = u64f(vec, "price_micro");
        let bps = u64f(vec, "delivered_bps");
        let want_verdict = u64f(vec, "verdict");
        let got_verdict = match classify(bps) {
            Verdict::Reverse => 0,
            Verdict::Partial => 1,
            Verdict::Release => 2,
        };
        assert_eq!(got_verdict, want_verdict, "classify {price}/{bps}");
        assert_eq!(
            seller_gross(price, bps),
            u64f(vec, "seller_gross"),
            "seller {price}/{bps}"
        );
        assert_eq!(
            refund(price, bps),
            u64f(vec, "refund"),
            "refund {price}/{bps}"
        );
    }
}

#[test]
fn commons_matches_golden() {
    let g = golden("commons.json");
    let shares: Vec<CommonsShare> = serde_json::from_value(g["shares"].clone()).unwrap();
    for vec in g["vectors"].as_array().unwrap() {
        let pool = u64f(vec, "pool_micro");
        let want: Vec<u64> = vec["allocations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_u64().unwrap())
            .collect();
        let got: Vec<u64> = route_to_commons(pool, &shares)
            .unwrap()
            .iter()
            .map(|a| a.amount_micro)
            .collect();
        assert_eq!(got, want, "commons pool={pool}");
        // No-skim: allocations sum to exactly the pool.
        assert_eq!(
            got.iter().sum::<u64>(),
            pool,
            "commons conservation pool={pool}"
        );
    }
}

#[test]
fn vcg_matches_golden() {
    let g = golden("vcg.json");
    for vec in g["vectors"].as_array().unwrap() {
        let bids: Vec<IntegerBid> = serde_json::from_value(vec["bids"].clone()).unwrap();
        let proposals: Vec<IntegerProposal> =
            serde_json::from_value(vec["proposals"].clone()).unwrap();
        let budget = u64f(vec, "budget_micro_usd");
        let clearing = run_vcg(&bids, &proposals, budget).unwrap();

        let want_winners = vec["winners"].as_array().unwrap();
        assert_eq!(clearing.winners.len(), want_winners.len(), "winner count");
        for (got, want) in clearing.winners.iter().zip(want_winners) {
            assert_eq!(got.bidder, want["bidder"].as_str().unwrap());
            assert_eq!(got.proposal_id, want["proposal_id"].as_str().unwrap());
            assert_eq!(
                got.vcg_payment_micro_usd,
                u64f(want, "vcg_payment_micro_usd"),
                "vcg payment for {}",
                got.bidder
            );
        }
        assert_eq!(
            clearing.total_payments_micro_usd,
            u64f(vec, "total_payments_micro_usd"),
            "total payments"
        );
    }
}

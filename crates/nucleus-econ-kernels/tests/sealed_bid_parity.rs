// Bet A — sealed-bid (commit-reveal) PARITY proptest.
//
// The load-bearing claim of the REAL slice: a set of bids submitted via
// the two-phase commit-reveal lifecycle, then revealed and verified,
// clears BYTE-FOR-BYTE identically to the same bids submitted as
// plaintext. This is what lets us say "run_vcg is untouched" — the
// sealed path is a pure pre-image around the unchanged kernel.
//
// We prove it two ways:
//   (1) parity_plain_vcg — sealed-then-revealed IntegerBids fed to the
//       unchanged `run_vcg` produce an identical `Clearing` to the same
//       IntegerBids fed to `run_vcg` directly.
//   (2) parity_pigouvian_vcg — sealed-then-revealed bids + their
//       revealed externality profiles fed to the unchanged
//       `run_vcg_with_externalities` produce an identical
//       `PigouvianClearing` to the plaintext path.
//
// A faithful reveal MUST verify (no false rejection), and a tampered
// reveal MUST be rejected (no false acceptance) — proptested too.

#![deny(clippy::float_arithmetic)]

use ed25519_dalek::SigningKey;
use nucleus_econ_kernels::{
    compute_commitment, run_vcg, run_vcg_with_externalities, verify_reveal, BidOpening, IntegerBid,
    IntegerProposal, PigouvianRates,
};
use nucleus_externality::{sign_claim, ExternalityProfile, ResourceDim, SignedExternalityClaim};
use proptest::prelude::*;

const CHAIN_ID: u64 = 8453; // Base mainnet chain id, as a domain tag

fn mk_profile(units: u64) -> ExternalityProfile {
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let claim = sign_claim(
        &sk,
        SignedExternalityClaim {
            resource: ResourceDim::GpuSeconds,
            units_micro: units,
            ts_unix_micros: 1_700_000_000_000_000,
            not_after_unix_micros: 1_700_000_000_000_000 + 3_600_000_000,
            subject_identity: "spiffe://nucleus.io/ns/agents/sa/x".into(),
            kid: "o1".into(),
            sig_b64: String::new(),
        },
    );
    let mut p = ExternalityProfile::new();
    p.insert(ResourceDim::GpuSeconds, claim);
    p
}

proptest! {
    // (1) Plain VCG parity: sealed→revealed bids clear identically to
    // plaintext bids on the UNCHANGED run_vcg kernel.
    #[test]
    fn parity_plain_vcg(
        values in proptest::collection::vec(1_000u64..2_000_000, 1..8),
        nonce_seed in any::<u8>(),
        budget in 50_000u64..500_000,
    ) {
        let auction_id = "a1";
        let proposals = vec![IntegerProposal { id: auction_id.into(), cost_micro_usd: 50_000 }];

        // Build plaintext bids (unique bidder ids).
        let plaintext: Vec<IntegerBid> = values
            .iter()
            .enumerate()
            .map(|(i, &v)| IntegerBid {
                bidder: format!("spiffe://nucleus.io/ns/agents/sa/agent-{i}"),
                proposal_id: auction_id.into(),
                effective_value_micro_usd: v,
            })
            .collect();

        // Seal each as a commitment, then reveal+verify back to IntegerBid.
        let revealed: Vec<IntegerBid> = values
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                let opening = BidOpening {
                    agent_spiffe_id: format!("spiffe://nucleus.io/ns/agents/sa/agent-{i}"),
                    auction_id: auction_id.into(),
                    effective_value_micro_usd: v,
                    externality_profile: None,
                    nonce: [nonce_seed.wrapping_add(i as u8); 32],
                };
                let c = compute_commitment(CHAIN_ID, &opening);
                verify_reveal(CHAIN_ID, auction_id, &c, &opening)
                    .expect("faithful reveal must verify")
            })
            .collect();

        let clear_plain = run_vcg(&plaintext, &proposals, budget);
        let clear_sealed = run_vcg(&revealed, &proposals, budget);
        prop_assert_eq!(clear_plain, clear_sealed);
    }

    // (2) Pigouvian VCG parity: sealed→revealed bids + revealed profiles
    // clear identically on the UNCHANGED run_vcg_with_externalities.
    #[test]
    fn parity_pigouvian_vcg(
        values in proptest::collection::vec(1_000u64..2_000_000, 1..6),
        ext_units in proptest::collection::vec(0u64..2_000_000, 1..6),
        nonce_seed in any::<u8>(),
        lambda in 0u64..500,
    ) {
        let n = values.len().min(ext_units.len());
        let auction_id = "a1";
        let proposals = vec![IntegerProposal { id: auction_id.into(), cost_micro_usd: 50_000 }];
        let mut rates = PigouvianRates::zero();
        rates.rates.insert(ResourceDim::GpuSeconds, lambda);

        let mut plaintext = Vec::new();
        let mut plaintext_profiles = Vec::new();
        let mut revealed = Vec::new();
        let mut revealed_profiles = Vec::new();

        for i in 0..n {
            let id = format!("spiffe://nucleus.io/ns/agents/sa/agent-{i}");
            let prof = mk_profile(ext_units[i]);
            plaintext.push(IntegerBid {
                bidder: id.clone(),
                proposal_id: auction_id.into(),
                effective_value_micro_usd: values[i],
            });
            plaintext_profiles.push(prof.clone());

            let opening = BidOpening {
                agent_spiffe_id: id.clone(),
                auction_id: auction_id.into(),
                effective_value_micro_usd: values[i],
                externality_profile: Some(prof.clone()),
                nonce: [nonce_seed.wrapping_add(i as u8); 32],
            };
            let c = compute_commitment(CHAIN_ID, &opening);
            let bid = verify_reveal(CHAIN_ID, auction_id, &c, &opening)
                .expect("faithful reveal must verify");
            // The revealed profile flows separately into the Pigouvian
            // kernel; it must equal the committed one.
            let revealed_prof = opening.externality_profile.clone().unwrap();
            prop_assert_eq!(&revealed_prof, &prof);
            revealed.push(bid);
            revealed_profiles.push(revealed_prof);
        }

        let clear_plain = run_vcg_with_externalities(
            &plaintext, &proposals, 50_000, &plaintext_profiles, &rates,
        ).unwrap();
        let clear_sealed = run_vcg_with_externalities(
            &revealed, &proposals, 50_000, &revealed_profiles, &rates,
        ).unwrap();

        // PigouvianClearing isn't PartialEq; compare the load-bearing fields.
        prop_assert_eq!(
            clear_plain.rebate_pool_micro_usd,
            clear_sealed.rebate_pool_micro_usd
        );
        prop_assert_eq!(clear_plain.clearing, clear_sealed.clearing);
    }

    // No false rejection: a faithful reveal always verifies.
    #[test]
    fn faithful_reveal_never_rejected(
        value in any::<u64>(),
        nonce in any::<[u8; 32]>(),
        ext in 0u64..5_000_000,
    ) {
        let opening = BidOpening {
            agent_spiffe_id: "spiffe://nucleus.io/ns/agents/sa/a".into(),
            auction_id: "a1".into(),
            effective_value_micro_usd: value,
            externality_profile: Some(mk_profile(ext)),
            nonce,
        };
        let c = compute_commitment(CHAIN_ID, &opening);
        prop_assert!(verify_reveal(CHAIN_ID, "a1", &c, &opening).is_ok());
    }

    // No false acceptance: any change to the sealed value is rejected.
    #[test]
    fn tampered_value_always_rejected(
        value in any::<u64>(),
        delta in 1u64..1_000_000,
        nonce in any::<[u8; 32]>(),
    ) {
        let opening = BidOpening {
            agent_spiffe_id: "spiffe://nucleus.io/ns/agents/sa/a".into(),
            auction_id: "a1".into(),
            effective_value_micro_usd: value,
            externality_profile: None,
            nonce,
        };
        let c = compute_commitment(CHAIN_ID, &opening);
        let mut tampered = opening.clone();
        tampered.effective_value_micro_usd = value.wrapping_add(delta);
        prop_assert!(verify_reveal(CHAIN_ID, "a1", &c, &tampered).is_err());
    }
}

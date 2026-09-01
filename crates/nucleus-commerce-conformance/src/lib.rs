//! # Commerce conformance — what "any runtime can integrate" has to mean
//!
//! The open-commerce claim is that an independent agent runtime can join the
//! marketplace and receive a share of revenue. That claim is worth nothing if
//! "integrating" means "asserting you integrated". This crate is the difference:
//! a corpus of scenarios, each with the verdict a conforming implementation
//! **must** reach, exportable as JSON so a runtime written in any language can
//! check itself without running Rust, trusting nucleus, or asking permission.
//!
//! It follows the shape `nucleus-envelope-adversarial-corpus` already uses in
//! this repo — a named case list, CI-gated — extended in one way that matters.
//!
//! ## Why the corpus contains honest cases too
//!
//! An adversarial corpus alone is satisfied by an implementation that rejects
//! **everything**. That is the classic vacuous pass: perfect security, zero
//! function, full marks. So every property here carries cases in both
//! directions, and [`corpus_covers_both_directions`] fails the build if any
//! property loses one. A conforming runtime has to say yes to the honest case
//! *and* no to the attack; either alone is free.
//!
//! ## The four properties
//!
//! | property | the question a payee/buyer is really asking |
//! |---|---|
//! | [`Property::PayoutRecomputes`] | is my share the proven function of a real pool? |
//! | [`Property::SettlementDischarges`] | was **everyone** paid, exactly once? |
//! | [`Property::DisclosureRequired`] | can paid placement reach me undisclosed? |
//! | [`Property::MandateCoversCart`] | did a human approve *this exact* cart? |
//!
//! ## What conformance does NOT establish
//!
//! Passing this corpus means an implementation agrees with nucleus on these
//! scenarios. It does not mean it is correct on scenarios nobody wrote down, and
//! it cannot: a corpus is a lower bound on agreement, never a proof of
//! equivalence. It also says nothing about whether the implementation *uses* its
//! own verifier on the live path — a runtime can classify every vector perfectly
//! and never call the check in production. That is a different gate, and
//! claiming this one covers it would be the exact overclaim the whole project
//! exists to argue against.

use serde::{Deserialize, Serialize};

use nucleus_econ_kernels::commons::CommonsShare;
use nucleus_ifc::decision::{DeclaredInput, FlowDeclaration};
use nucleus_recompute::cart::{cart_content_hash_hex, verify_mandate_covers_cart, Cart, CartItem};
use nucleus_recompute::payout::{issue_payout, verify_payout, Attribution, PayoutClaim};
use nucleus_recompute::settlement_attestation::{
    issue_settlement_attestation, verify_settlement_set, SettlementAttestation,
    SettlementSetOutcome,
};
use nucleus_recompute::{issue_settlement, RecomputeOutcome};

/// The four properties an integrator must agree with nucleus about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Property {
    /// The revenue split is the proven function of a real, re-derivable pool.
    PayoutRecomputes,
    /// Every allocation is discharged, exactly once.
    SettlementDischarges,
    /// Paid placement cannot be served without a disclosure record.
    DisclosureRequired,
    /// A human approved this exact cart.
    MandateCoversCart,
}

impl Property {
    /// Stable wire token.
    pub fn token(self) -> &'static str {
        match self {
            Property::PayoutRecomputes => "payout_recomputes",
            Property::SettlementDischarges => "settlement_discharges",
            Property::DisclosureRequired => "disclosure_required",
            Property::MandateCoversCart => "mandate_covers_cart",
        }
    }

    /// Every property, for coverage checks.
    pub fn all() -> [Property; 4] {
        [
            Property::PayoutRecomputes,
            Property::SettlementDischarges,
            Property::DisclosureRequired,
            Property::MandateCoversCart,
        ]
    }
}

/// The verdict a conforming implementation must reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expect {
    /// The scenario is legitimate and must be accepted.
    Accept,
    /// The scenario is an attack or a malformed input and must be rejected.
    Reject,
}

/// The input a case presents. Serializable so the whole corpus can be exported
/// as vectors for a non-Rust implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CaseInput {
    /// A payout to recompute.
    Payout(PayoutClaim),
    /// A payout plus the settlements claimed to discharge it.
    Settlement {
        /// The payout being discharged.
        payout: PayoutClaim,
        /// The settlements presented.
        attestations: Vec<SettlementAttestation>,
    },
    /// A declared information flow to decide.
    Flow(FlowDeclaration),
    /// A mandate's covered-cart hash, and the cart actually presented.
    Cart {
        /// The cart hash the (already signature-verified) mandate covers.
        mandate_manifest_hash: String,
        /// The cart presented for payment.
        cart: Cart,
    },
}

/// One conformance scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceCase {
    /// Stable identifier — cite this in a conformance report.
    pub name: &'static str,
    /// What the case is testing, in one line.
    pub summary: &'static str,
    /// Which property it exercises.
    pub property: Property,
    /// The verdict a conforming implementation must reach.
    pub expect: Expect,
    /// A substring the rejection reason must contain, when the verdict alone is
    /// not enough to tell conforming from broken.
    ///
    /// This exists because of a gap a mutation test found: sponsored content is
    /// adversarial, so a flow containing it is denied by the lethal-trifecta
    /// rules **whether or not** the disclosure precondition is enforced. The
    /// verdicts are identical; only the reason differs. A corpus checking
    /// verdicts alone therefore passed an implementation with disclosure
    /// enforcement deleted — it claimed coverage it did not have.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect_reason_contains: Option<&'static str>,
    /// The scenario itself.
    pub input: CaseInput,
}

/// Evaluate a case with **nucleus's own** implementation, returning the verdict
/// and the reason behind it.
///
/// This is the reference answer. An integrator compares against
/// [`ConformanceCase::expect`] (and `expect_reason_contains` where present), not
/// against this function — the point of exporting vectors is that nobody has to
/// run this.
pub fn evaluate(input: &CaseInput) -> (Expect, String) {
    let (accepted, reason) = match input {
        CaseInput::Payout(p) => {
            let o = verify_payout(p);
            (o == RecomputeOutcome::Match, format!("{o:?}"))
        }
        CaseInput::Settlement {
            payout,
            attestations,
        } => {
            let o = verify_settlement_set(attestations, payout);
            (o == SettlementSetOutcome::Complete, format!("{o:?}"))
        }
        CaseInput::Flow(d) => {
            let v = d.decide();
            (v.is_allow(), format!("{v:?}"))
        }
        CaseInput::Cart {
            mandate_manifest_hash,
            cart,
        } => {
            let o = verify_mandate_covers_cart(mandate_manifest_hash, cart);
            (o.is_match(), format!("{o:?}"))
        }
    };
    (
        if accepted {
            Expect::Accept
        } else {
            Expect::Reject
        },
        reason,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

const DISCLOSURE: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

fn shares() -> Vec<CommonsShare> {
    vec![
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
    ]
}

fn attribution() -> Attribution {
    Attribution {
        workload_spiffe_id: "spiffe://nucleus.local/runtime/acme".into(),
        assurance: 1,
        offer_hash_hex: "a".repeat(64),
        disclosure_hash_hex: DISCLOSURE.into(),
    }
}

fn honest_payout() -> PayoutClaim {
    issue_payout(issue_settlement(1_000_000, 10_000), shares(), attribution()).expect("well-formed")
}

fn cart() -> Cart {
    Cart {
        items: vec![CartItem {
            offer_hash_hex: "a".repeat(64),
            quantity: 2,
            unit_price_micro: 500_000,
        }],
        total_micro: 1_000_000,
        currency: "USD".into(),
        payer_spiffe_id: "spiffe://nucleus.local/human/alice".into(),
    }
}

fn attest(p: &PayoutClaim, dest: &str) -> SettlementAttestation {
    issue_settlement_attestation(p, dest, "x402-evm", "0xabc").expect("known destination")
}

/// The conformance corpus.
///
/// Each entry is a scenario with a required verdict. Both directions are present
/// for every property — see the module docs on why an attack-only corpus is
/// satisfied by rejecting everything.
pub fn corpus() -> Vec<ConformanceCase> {
    let mut cases = Vec::new();

    // ── PayoutRecomputes ────────────────────────────────────────────────────
    cases.push(ConformanceCase {
        name: "payout/honest",
        summary: "a split issued by the proven kernel re-derives",
        property: Property::PayoutRecomputes,
        expect: Expect::Accept,
        expect_reason_contains: None,
        input: CaseInput::Payout(honest_payout()),
    });

    let mut skimmed = honest_payout();
    skimmed.allocations[0].amount_micro += 1;
    skimmed.allocations[2].amount_micro -= 1;
    cases.push(ConformanceCase {
        name: "payout/skimmed-one-micro-usd",
        summary: "one micro-USD moved from the commons to the seller",
        property: Property::PayoutRecomputes,
        expect: Expect::Reject,
        expect_reason_contains: None,
        input: CaseInput::Payout(skimmed),
    });

    let mut inflated = honest_payout();
    if let nucleus_recompute::ClearingReceipt::Settlement(s) = &mut inflated.clearing {
        s.seller_gross += 500_000;
    }
    cases.push(ConformanceCase {
        name: "payout/fabricated-pool",
        summary: "the split is honest but the clearing it distributes is not",
        property: Property::PayoutRecomputes,
        expect: Expect::Reject,
        expect_reason_contains: None,
        input: CaseInput::Payout(inflated),
    });

    // ── SettlementDischarges ────────────────────────────────────────────────
    let p = honest_payout();
    let all: Vec<_> = p
        .allocations
        .iter()
        .map(|a| attest(&p, &a.destination))
        .collect();
    cases.push(ConformanceCase {
        name: "settlement/all-payees-once",
        summary: "every allocation discharged exactly once",
        property: Property::SettlementDischarges,
        expect: Expect::Accept,
        expect_reason_contains: None,
        input: CaseInput::Settlement {
            payout: p.clone(),
            attestations: all.clone(),
        },
    });

    cases.push(ConformanceCase {
        name: "settlement/two-of-three",
        summary: "each receipt verifies alone; the set leaves a payee unpaid",
        property: Property::SettlementDischarges,
        expect: Expect::Reject,
        expect_reason_contains: None,
        input: CaseInput::Settlement {
            payout: p.clone(),
            attestations: all[..2].to_vec(),
        },
    });

    let mut short = all.clone();
    short[0].amount_micro_usd_signed -= 1;
    cases.push(ConformanceCase {
        name: "settlement/short-paid",
        summary: "a payee is paid one micro-USD less than the proven split",
        property: Property::SettlementDischarges,
        expect: Expect::Reject,
        expect_reason_contains: None,
        input: CaseInput::Settlement {
            payout: p.clone(),
            attestations: short,
        },
    });

    let mut stranger = all.clone();
    stranger[0].destination = "spiffe://attacker.example/wallet".into();
    cases.push(ConformanceCase {
        name: "settlement/paid-a-stranger",
        summary: "money moved to a destination the split does not owe",
        property: Property::SettlementDischarges,
        expect: Expect::Reject,
        expect_reason_contains: None,
        input: CaseInput::Settlement {
            payout: p,
            attestations: stranger,
        },
    });

    // ── DisclosureRequired ──────────────────────────────────────────────────
    cases.push(ConformanceCase {
        name: "disclosure/no-sponsored-content",
        summary: "an ordinary flow with no paid placement is unaffected",
        property: Property::DisclosureRequired,
        expect: Expect::Accept,
        expect_reason_contains: None,
        input: CaseInput::Flow(FlowDeclaration::new([
            DeclaredInput::UserPrompt,
            DeclaredInput::DatabaseRow,
        ])),
    });

    cases.push(ConformanceCase {
        name: "disclosure/sponsored-undisclosed",
        summary: "paid placement with no disclosure record must be refused FOR THAT REASON",
        property: Property::DisclosureRequired,
        expect: Expect::Reject,
        // The verdict alone proves nothing here — the trifecta denies this flow
        // anyway. Pinning the reason is what makes disclosure enforcement
        // observable, and what makes deleting it fail this corpus.
        expect_reason_contains: Some("disclosure"),
        input: CaseInput::Flow(FlowDeclaration::new([
            DeclaredInput::UserPrompt,
            DeclaredInput::SponsoredOffer,
        ])),
    });

    cases.push(ConformanceCase {
        name: "disclosure/sponsored-cannot-act",
        summary: "even disclosed, paid placement may not drive an outbound action",
        property: Property::DisclosureRequired,
        expect: Expect::Reject,
        // Once disclosed it must NOT still cite disclosure — an operator reading
        // the verdict is told which control actually stopped it. Pinning
        // `AdversarialAncestry` asserts two things at once: disclosure was
        // satisfied, AND the offer is still being treated as adversarial.
        // Re-labelling SponsoredOffer as trusted changes this string.
        expect_reason_contains: Some("AdversarialAncestry"),
        input: CaseInput::Flow(
            FlowDeclaration::new([DeclaredInput::UserPrompt, DeclaredInput::SponsoredOffer])
                .with_disclosure(DISCLOSURE),
        ),
    });

    // ── MandateCoversCart ───────────────────────────────────────────────────
    let c = cart();
    cases.push(ConformanceCase {
        name: "cart/exact-match",
        summary: "the mandate covers the cart presented",
        property: Property::MandateCoversCart,
        expect: Expect::Accept,
        expect_reason_contains: None,
        input: CaseInput::Cart {
            mandate_manifest_hash: cart_content_hash_hex(&c),
            cart: c.clone(),
        },
    });

    let mut added = c.clone();
    added.items.push(CartItem {
        offer_hash_hex: "b".repeat(64),
        quantity: 1,
        unit_price_micro: 250_000,
    });
    added.total_micro += 250_000;
    cases.push(ConformanceCase {
        name: "cart/item-added-after-approval",
        summary: "an item appended after the human approved is not covered",
        property: Property::MandateCoversCart,
        expect: Expect::Reject,
        expect_reason_contains: None,
        input: CaseInput::Cart {
            mandate_manifest_hash: cart_content_hash_hex(&c),
            cart: added,
        },
    });

    let mut lying = c.clone();
    lying.total_micro = 1; // the human is shown 0.000001 USD
    cases.push(ConformanceCase {
        name: "cart/total-disagrees-with-lines",
        summary: "a cart whose stated total is not the sum of its lines is malformed",
        property: Property::MandateCoversCart,
        expect: Expect::Reject,
        expect_reason_contains: None,
        input: CaseInput::Cart {
            mandate_manifest_hash: cart_content_hash_hex(&lying),
            cart: lying,
        },
    });

    let mut repayer = c.clone();
    repayer.payer_spiffe_id = "spiffe://nucleus.local/human/mallory".into();
    cases.push(ConformanceCase {
        name: "cart/lifted-onto-another-payer",
        summary: "a mandate cannot be moved onto someone else's account",
        property: Property::MandateCoversCart,
        expect: Expect::Reject,
        expect_reason_contains: None,
        input: CaseInput::Cart {
            mandate_manifest_hash: cart_content_hash_hex(&c),
            cart: repayer,
        },
    });

    cases
}

/// Export the corpus as JSON vectors.
///
/// This is the artifact that makes the "open" claim real: a runtime in any
/// language reads these, runs its own checks, and compares verdicts. It never
/// executes nucleus code, never calls a nucleus service, and needs nobody's
/// permission to prove it conforms.
pub fn export_vectors() -> String {
    let cases: Vec<_> = corpus()
        .into_iter()
        .map(|c| {
            serde_json::json!({
                "name": c.name,
                "summary": c.summary,
                "property": c.property.token(),
                "expect": c.expect,
                "expect_reason_contains": c.expect_reason_contains,
                "input": c.input,
            })
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "version": 1,
        "cases": cases,
    }))
    .expect("corpus serialization is infallible")
}

/// Does every property carry cases in **both** directions?
///
/// This is the anti-vacuity guard, and it is load-bearing rather than tidy. An
/// attack-only corpus is passed in full by an implementation that rejects
/// everything — perfect security, zero function. Returns the properties missing
/// a direction; empty means the corpus can actually distinguish a conforming
/// implementation from a broken one.
pub fn corpus_covers_both_directions() -> Vec<(Property, Expect)> {
    let cases = corpus();
    let mut missing = Vec::new();
    for p in Property::all() {
        for e in [Expect::Accept, Expect::Reject] {
            if !cases.iter().any(|c| c.property == p && c.expect == e) {
                missing.push((p, e));
            }
        }
    }
    missing
}

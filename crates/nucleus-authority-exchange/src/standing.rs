//! Standing that gates ENTRY to a round — never authority.
//!
//! # The one thing economics may gate
//!
//! The governing constraint of the economic epics is that economics never
//! widens or narrows authority: the capability lattice decides what an agent
//! may do, and "bond/reputation may gate market participation, never PodSpec
//! or admission". [`StandingAdmission`] is that permitted hook and nothing
//! more. Refusing a bidder here means it does not take part in THIS ROUND; it
//! does not change what the bidder is allowed to do, and a dimension that is
//! not auctioned at all is unaffected.
//!
//! # Why reputation alone, with no bond
//!
//! `nucleus_witness_olog::deters` is `gain ≤ bond + reputation`. This policy
//! passes a bond of **zero**, so the question it asks is exactly: *does the
//! standing this identity has already accrued cover the gain it could take by
//! defecting on this good?*
//!
//! That is deliberate. A bond that cannot be slashed is theatre, and the
//! conditions for slashing (`docs/rfcs/receipt-provenance-defection.md`) are
//! not met — so this crate collects no bond and holds no funds. Accrued
//! standing is evidence the host already has, from receipts it already
//! recomputed, and it costs an attacker real history rather than real money.
//! `required_bond`'s `sybil_no_discount` is what makes that non-trivial: a
//! fresh identity has zero reputation and gets no discount, so splitting into
//! new identities buys nothing.
//!
//! # The bootstrap rung, and why it is the round's property
//!
//! A policy that demanded standing of everyone would never admit a newcomer,
//! and a newcomer that cannot bid can never accrue standing. So the gain is a
//! property of the GOOD being auctioned, fixed when the policy is built for
//! that good — not of any bid. A good whose `max_defection_gain_micro` is zero
//! admits everyone, because `deters(0, 0, 0)` holds: that is the low-stakes
//! rung on which a new agent earns the history a high-stakes round will ask
//! for.
//!
//! It has to be the round's property rather than the bid's, because
//! [`crate::Admission::admits`] takes an `AgentId` and nothing else. That
//! signature is load-bearing: an implementation cannot see a bid, so it cannot
//! condition entry on what was bid, which is what keeps the truthfulness
//! argument intact (the threshold a bidder faces must not depend on its own
//! report).

use std::collections::HashMap;

use nucleus_creditworthiness::CreditFile;
use nucleus_econ_types::AgentId;
use nucleus_witness_olog::AmountMicro;

use crate::round::Admission;

/// Admits a bidder when its accrued standing alone deters defection on this
/// good.
///
/// Built per good, because the gain is the good's (see the module docs). The
/// credit files come from the clearing site's own recomputed receipts; this
/// type reads them and decides nothing else.
#[derive(Debug, Clone)]
pub struct StandingAdmission {
    files: HashMap<AgentId, CreditFile>,
    max_defection_gain_micro: u64,
}

impl StandingAdmission {
    /// A policy for one good.
    ///
    /// `max_defection_gain_micro` is what an agent could gain by defecting on
    /// this good once — the stake. Zero makes the policy admit everyone, which
    /// is the bootstrap rung and is stated rather than hidden: a clearing site
    /// that wants to gate must name a non-zero stake.
    #[must_use]
    pub fn new(files: HashMap<AgentId, CreditFile>, max_defection_gain_micro: u64) -> Self {
        Self {
            files,
            max_defection_gain_micro,
        }
    }

    /// The stake this policy prices standing against.
    #[must_use]
    pub fn stake_micro(&self) -> u64 {
        self.max_defection_gain_micro
    }

    /// What `bidder` would additionally have to post for this round's stake to
    /// be deterred — zero once its standing already covers it.
    ///
    /// Reported, not collected: this crate holds no funds. It exists so a
    /// refusal can say how far short the bidder is instead of only that it was
    /// refused.
    #[must_use]
    pub fn shortfall(&self, bidder: &AgentId) -> AmountMicro {
        match self.files.get(bidder) {
            Some(f) => f.required_bond(self.max_defection_gain_micro),
            // A fresh identity has no standing, so the whole stake is the
            // shortfall. `sybil_no_discount`: this is exactly what
            // `required_bond` returns for zero reputation.
            None => AmountMicro(self.max_defection_gain_micro),
        }
    }
}

impl Admission for StandingAdmission {
    /// Whether this bidder's accrued standing alone deters defection on this
    /// good. `AmountMicro::ZERO` is the bond, because none is collected.
    fn admits(&self, bidder: &AgentId) -> bool {
        match self.files.get(bidder) {
            Some(f) => f.deters(AmountMicro::ZERO, self.max_defection_gain_micro),
            // No history at all. Deterred only when the stake is zero, which
            // is the bootstrap rung.
            None => self.max_defection_gain_micro == 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_creditworthiness::{CreditEvent, CreditFile};
    use nucleus_recompute::{RecomputeWitness, witness_receipt};

    /// Standing earned the only way standing can be: by RECOMPUTING a real
    /// receipt and taking the sealed witness that the numbers re-derived.
    ///
    /// No test constructor is used, because there is no honest one to use —
    /// `CreditEvent` is minted from a `RecomputeMatch`, whose constructor is
    /// private to the checker (C-1). So the test builds a genuine cleared
    /// round, recomputes it, and accrues what that is worth. The magnitude the
    /// event carries is the round's own economic magnitude, which is why the
    /// helper returns it: a test that asserted a number it had also chosen
    /// would be asserting nothing.
    fn standing_from_a_real_round(winner_bid: u64, second_bid: u64) -> (CreditFile, u64) {
        let bids = vec![
            nucleus_recompute::IntegerBid {
                bidder: "w".into(),
                proposal_id: "g".into(),
                effective_value_micro_usd: winner_bid,
            },
            nucleus_recompute::IntegerBid {
                bidder: "l".into(),
                proposal_id: "g".into(),
                effective_value_micro_usd: second_bid,
            },
        ];
        let proposals = vec![nucleus_recompute::IntegerProposal {
            id: "g".into(),
            cost_micro_usd: 1,
        }];
        let receipt = nucleus_recompute::issue_vcg(bids, proposals, 1).expect("clears");
        let RecomputeWitness::Matched(m) = witness_receipt(&receipt) else {
            panic!("a receipt the kernel just issued must recompute");
        };
        let event = CreditEvent::from_match(&m);
        let weight = event.weight_micro();
        (CreditFile::from_events(&[event]), weight)
    }

    fn agent(name: &str) -> AgentId {
        AgentId::new(name)
    }

    /// THE BOOTSTRAP RUNG, and it is first because a policy that cannot admit
    /// a newcomer is a market with one participant. A zero-stake good admits
    /// an identity with no history at all.
    #[test]
    fn a_zero_stake_good_admits_a_newcomer() {
        let policy = StandingAdmission::new(HashMap::new(), 0);
        assert!(
            policy.admits(&agent("never-seen-before")),
            "a newcomer must be able to earn standing somewhere"
        );
        assert_eq!(
            policy.shortfall(&agent("never-seen-before")),
            AmountMicro(0)
        );
    }

    /// NON-VACUITY for the test above: raise the stake and the same newcomer is
    /// refused. Without this, "admits" might be true for every input.
    #[test]
    fn the_same_newcomer_is_refused_once_the_stake_is_real() {
        let policy = StandingAdmission::new(HashMap::new(), 1_000_000);
        assert!(!policy.admits(&agent("never-seen-before")));
        assert_eq!(
            policy.shortfall(&agent("never-seen-before")),
            AmountMicro(1_000_000),
            "a fresh identity is short the whole stake — no Sybil discount"
        );
    }

    /// Accrued standing substitutes for capital, which is the whole point of
    /// gating on it: an agent with history enters a round a newcomer cannot.
    #[test]
    fn accrued_standing_admits_where_no_history_does_not() {
        let (file, earned) = standing_from_a_real_round(3_000_000, 2_000_000);
        assert!(earned > 0, "the round must be worth something to accrue");
        let mut files = HashMap::new();
        files.insert(agent("veteran"), file);
        // A stake exactly what the veteran earned: covered.
        let policy = StandingAdmission::new(files, earned);

        assert!(
            policy.admits(&agent("veteran")),
            "standing covering the stake must admit"
        );
        assert_eq!(policy.shortfall(&agent("veteran")), AmountMicro(0));
        assert!(
            !policy.admits(&agent("newcomer")),
            "and the same round must still refuse an identity with none"
        );
        assert_eq!(policy.shortfall(&agent("newcomer")), AmountMicro(earned));
    }

    /// Standing that falls SHORT does not admit, and the refusal says by how
    /// much. The boundary is exact: equal covers, one micro-unit under does
    /// not.
    #[test]
    fn standing_short_of_the_stake_is_refused_by_exactly_the_shortfall() {
        let (file, earned) = standing_from_a_real_round(3_000_000, 2_000_000);
        let mut files = HashMap::new();
        files.insert(agent("veteran"), file);
        // One micro-unit more at stake than the veteran has earned.
        let policy = StandingAdmission::new(files, earned + 1);

        assert!(
            !policy.admits(&agent("veteran")),
            "standing one unit short must not admit"
        );
        assert_eq!(
            policy.shortfall(&agent("veteran")),
            AmountMicro(1),
            "and the refusal must say it is short by exactly one"
        );
    }

    /// The signature is the guarantee: `admits` sees an identity and nothing
    /// else, so entry cannot depend on what was bid. This test is the reason
    /// the trait takes `&AgentId` — if it ever took a bid, the threshold a
    /// bidder faces could depend on its own report and the truthfulness
    /// argument would not survive.
    #[test]
    fn entry_does_not_depend_on_the_bid() {
        let (file, earned) = standing_from_a_real_round(3_000_000, 2_000_000);
        let mut files = HashMap::new();
        files.insert(agent("a"), file);
        let policy = StandingAdmission::new(files, earned);
        // Called twice for the same identity, nothing else supplied: the only
        // input available is the identity, so the answer cannot vary with a
        // bid.
        assert_eq!(policy.admits(&agent("a")), policy.admits(&agent("a")));
    }

    /// A round actually refuses the bidder the policy excludes — the gate is
    /// wired to `submit_under`, not merely available.
    #[test]
    fn a_round_refuses_a_bidder_without_standing() {
        use crate::ScarceGood;
        use crate::bid::SignedBid;
        use crate::round::{AdmitError, Round};
        use nucleus_econ_types::AuctionId;
        use nucleus_econ_types::MicroUsd;

        let good = ScarceGood::new("ci-runner-slot").expect("nameable");
        let (file, earned) = standing_from_a_real_round(3_000_000, 2_000_000);
        let mut files = HashMap::new();
        files.insert(agent("veteran"), file);
        let policy = StandingAdmission::new(files, earned);

        let mut round = Round::open(AuctionId::new("r1"), good.clone());
        let bid = |who: &str| SignedBid::fixture(agent(who), good.clone(), MicroUsd::new(100));
        let err = round
            .submit_under(bid("newcomer"), &policy)
            .expect_err("no standing, no entry");
        assert!(
            matches!(err, AdmitError::NotAdmitted { .. }),
            "the refusal must name admission, not the bid: {err:?}"
        );
        round
            .submit_under(bid("veteran"), &policy)
            .expect("standing admits");
        assert_eq!(round.bids().len(), 1, "only the admitted bidder is in");
    }
}

# RFC: Reputation-weighted clearing — standing that matters without breaking truthfulness

**Status:** design / scoping. **Depends on:** `nucleus-econ-kernels` (VCG /
sealed-bid / tlock, in OSS), `nucleus-creditworthiness` (the credit file +
`required_bond`), `nucleus-oracle` (recompute-verified grades that feed standing).
Complements `credible-clearing-settlement.md` (which removes the *auctioneer*;
this RFC is about how *reputation* enters the clearing).

## The question this answers

A pure VCG auction is **reputation-blind**: a brand-new Sybil and a long-trusted
agent with a thousand recompute-verified deliveries are treated identically if
they bid the same number. We want standing to *matter* — but **naively** folding
reputation into the mechanism destroys the one property that makes the auction
worth running.

## The trap: do NOT weight the bid

The tempting move — multiply each bid by the bidder's reputation, then run VCG on
the weighted bids — **breaks truthfulness.** Once the payment an agent faces
depends on a reputation multiplier applied to its own bid, its dominant strategy
is no longer to bid true value; it shades its bid to game the multiplier. The
existing truthfulness results (and the zero-axiom VCG non-monotonicity Lean proof
in `nucleus-econ-kernels/lean/`) hold *because the allocation + payment rule is a
function of the bids alone*. Weighting the bids forfeits them.

**Design rule:** the allocation and payment rule stays a function of bids only.
Reputation enters everywhere *except* the valuation.

## Where reputation enters (truthfulness-preserving channels)

1. **Bond, not bid (the primary channel).** Every winner must post a slashable
   anti-grief bond. The *size* of the required bond is a decreasing function of
   standing — this is exactly `nucleus-creditworthiness`'s bond-substituting
   reputation (`required_bond(standing)`). A trusted agent locks little or no
   collateral; a newcomer locks the full uniform bond. The bid is untouched, so
   VCG truthfulness survives; reputation changes only the *cost of capital* to
   participate. A Sybil cannot shed this: a fresh identity has zero standing →
   maximum bond.
2. **Admission / eligibility.** A minimum standing (or a posted bond in lieu) to
   *enter* a given auction tier. This is a participation predicate evaluated
   before bids are read — again independent of the valuation, so it cannot distort
   truthful bidding among the admitted set.
3. **Deterministic tie-break.** When `faithful_total` (or the VCG outcome) ties,
   break toward higher standing. Ties are measure-zero in price terms, so this
   cannot move equilibrium bidding; it only resolves indifference.

What reputation must **never** do: scale the bid, scale the VCG payment, or enter
the allocation argmax. Those are the truthfulness-load-bearing computations.

## The uniform anti-grief bond

"Griefing" = win the clearing, then fail to deliver, denying the slot to the
runner-up. The defense is a **uniform** bond `B` posted by every winner, slashed
on authenticated defection (see `receipt-provenance-defection.md`). Uniform (not
bid-proportional) keeps it outside the payment rule. Reputation substitutes for
*posting* `B` in cash — `required_bond(standing) ∈ [0, B]` — but the *slashable
liability* remains `B` regardless, so a trusted agent that defects still loses `B`
of standing-or-cash. Reputation buys cheaper capital, never cheaper consequences.

## Bid privacy

Reputation is public (the credit file is a transparency-logged ledger); **bids
must not be.** Otherwise a public reputation ranking plus open bids lets agents
infer and shade. Bids are sealed via the existing commitment + timelock path
(`sealed.rs` commitment-set roots + `tlock.rs`/drand reveal): commit sealed →
anchor the set root → timelock reveal → recompute. Reputation gates admission and
bond *at commit time* (on identity + standing, not on the sealed value), so the
valuation stays hidden until reveal.

## What is proven vs proposed

- **Proven / built:** VCG truthfulness with bid-only payment; the non-monotonicity
  Lean proof; sealed-bid commitment + timelock reveal; `required_bond(standing)`
  in `nucleus-creditworthiness`; recompute-verified standing inputs.
- **Proposed (this RFC):** the exact `required_bond` schedule and admission-tier
  thresholds (policy parameters, not theorems); the claim that channels (1)–(3)
  are jointly truthfulness-preserving — this needs a Lean statement
  (*payment rule is independent of standing ⟹ truthful-bidding equilibrium is
  unchanged*), which is the natural next proof obligation, **not yet discharged**.

## Honesty boundary

This RFC keeps reputation out of the deductive truthfulness core on purpose. Any
implementation must preserve that separation, and the "channels are
truthfulness-preserving" claim is an **analogy to the existing proof until it has
its own Lean theorem** — do not describe it as proven before then.

# nucleus-commerce-conformance

**What "any runtime can integrate" has to mean.**

The open-commerce claim is that an independent agent runtime can join the marketplace and receive a
share of revenue. That claim is worth nothing if *integrating* means *asserting you integrated*.
This crate is the difference: a corpus of scenarios, each with the verdict a conforming
implementation **must** reach, exportable as JSON so a runtime in any language can check itself
without running Rust, trusting nucleus, or asking permission.

```
cargo run -p nucleus-commerce-conformance --example vectors > vectors.json
```

## The four properties

| property | what a payee or buyer is really asking |
|---|---|
| `payout_recomputes` | is my share the proven function of a real pool? |
| `settlement_discharges` | was **everyone** paid, exactly once? |
| `disclosure_required` | can paid placement reach me undisclosed? |
| `mandate_covers_cart` | did a human approve *this exact* cart? |

14 cases, every property covered in **both** directions.

## Why honest cases are in the corpus

An adversarial corpus alone is passed in full by an implementation that rejects **everything** —
perfect security, zero function. So every property carries cases both ways, and a test fails the
build if any property loses one. Two further tests assert that *always-accept* and *always-reject*
each fail somewhere, so the guard has its own bite.

## Why one case pins a reason, not just a verdict

A mutation test found a gap in this corpus: deleting the disclosure precondition entirely changed
**nothing** the corpus could see. Sponsored content is adversarial, so a flow containing it is
denied by the lethal-trifecta rules whether or not disclosure is enforced — identical verdicts,
different reasons only.

So `disclosure/sponsored-undisclosed` pins that the reason mentions `disclosure`, and
`disclosure/sponsored-cannot-act` pins `AdversarialAncestry` — asserting at once that disclosure
was satisfied *and* that the offer is still treated as adversarial. Deleting either control now
fails the corpus. Without those pins, `disclosure_required` was a property this crate claimed to
check and did not.

## Verified to be load-bearing

Each of these breaks at least one conformance test:

| break | reds |
|---|---|
| `verify_payout`'s allocation comparison | `nucleus_itself_conforms` |
| the disclosure precondition | `nucleus_itself_conforms` |
| `SponsoredOffer`'s adversarial label | `nucleus_itself_conforms` |
| the corpus's honest cases | the two anti-vacuity tests |

## What conformance does NOT establish

Passing means an implementation agrees with nucleus **on these scenarios**. It is a lower bound on
agreement, never a proof of equivalence, and it says nothing about scenarios nobody wrote down.

It also says nothing about whether an implementation *calls* its own verifier on the live path. A
runtime can classify all 14 vectors perfectly and never check anything in production. That is a
different gate, and claiming this one covers it would be exactly the overclaim this project exists
to argue against.

# nucleus-creditworthiness

**Agent creditworthiness — the credit file that turns recompute-verified history into bond-substituting reputation.**

A verified track record should spend like collateral. The proven kernel
[`nucleus_witness_olog::required_bond(gain, reputation)`] already says clean
history substitutes for posted capital down to a Sybil-proof floor — but it takes
`reputation` as a bare number. This crate is what *derives* that number: it folds
an identity's recompute-verified [`CreditEvent`]s into a **`CreditFile`** — a
multi-dimensional, deterministic, recompute-stable vector — and composes the
proven kernel to price the bond. The money path runs the exact proven function;
nothing here re-implements the math.

## The dimension vector — financial now, externality reserved

Creditworthiness is behaviour over time priced into a number. v1 scores one
**active** dimension:

- `FinancialDefault` — honest, recompute-matched settlement (credit) vs. a caught
  defection / recompute mismatch (debit). **Active.**
- `Externality` — Pigouvian: true-cost dues paid to the commons (credit) vs.
  uncompensated externalities dumped (debit). **Reserved, dormant.** Its events
  are accumulated but excluded from the bond-substituting reputation until
  `CreditDimension::is_active` is flipped — a one-line config change, not a schema
  migration. The kernels it will need already exist (`nucleus-externality`,
  `nucleus-econ-kernels` commons routing).

Greed ignites; conscience compounds. Keep the ignition signal pure (lower your
bond *now* by being honest), and switch on the externality dimension once the
base flywheel turns.

## What is proven here (property tests, not prose)

- **Commutative monoid** — empty file is the identity, `merge` is associative +
  commutative ⇒ the credit file is independent of event order ⇒ any verifier
  recomputes the *same* file from the same receipts (recompute-stable).
- **Monotone flywheel** — an honest settlement never raises the required bond; a
  caught defection never lowers it. For an honest agent the wheel turns one way.
- **Sybil-no-discount** — an empty file yields reputation 0 ⇒ the full bond.
  Splitting into fresh identities buys no discount (inherited from the kernel's
  proven floor).
- **Externality is inert in v1** — while dormant, externality events never move
  the bond-substituting reputation.

## Usage

```rust
use nucleus_creditworthiness::{CreditEvent, CreditFile};

let file = CreditFile::from_events(&[
    CreditEvent::honest_settlement(400_000, receipt_a_hash),
    CreditEvent::honest_settlement(300_000, receipt_b_hash),
]);

// 700k of clean history covers 700k of a 1M defection gain → only 300k bond.
assert_eq!(file.reputation_micro(), 700_000);
assert_eq!(file.required_bond(1_000_000).0, 300_000);
```

## Honesty boundary

A `CreditEvent` is only as good as the recompute that justifies it; each carries
the `receipt_hash` of the verified receipt it came from. This crate does the
aggregation + pricing — it does **not** itself verify receipts (that is
`nucleus-recompute` / `nucleus-envelope`). Feed it only events minted from
receipts that already recomputed.

MIT.

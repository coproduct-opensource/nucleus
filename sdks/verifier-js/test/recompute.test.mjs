// WASM binding for nucleus-recompute::verify_receipt (gap G4 follow-up).
//
// recomputeReceipt re-derives a whole clearing receipt (declared inputs + claimed
// outputs) against the PROVEN kernels, in-browser — the keystone "verify, don't
// trust" check. These assert: an honest receipt → match; each way of lying about
// the outputs → mismatch on the right field; malformed inputs → invalid.
//
// Requires ./pkg (run `npm run build:wasm` first; CI builds it).

import { test } from "node:test";
import assert from "node:assert/strict";

import { recomputeReceipt } from "../index.js";

test("honest settlement receipt recomputes to match", async () => {
  const r = await recomputeReceipt({
    kind: "settlement",
    price_micro: 1_000_000,
    delivered_bps: 2_500,
    verdict: "partial",
    seller_gross: 250_000,
    refund: 750_000,
  });
  assert.equal(r.outcome, "match");
});

test("a mispriced settlement receipt is caught (seller_gross)", async () => {
  const r = await recomputeReceipt({
    kind: "settlement",
    price_micro: 1_000_000,
    delivered_bps: 2_500,
    verdict: "partial",
    seller_gross: 250_001, // skim
    refund: 750_000,
  });
  assert.equal(r.outcome, "mismatch");
  assert.equal(r.field, "seller_gross");
});

test("honest commons receipt recomputes to match", async () => {
  const r = await recomputeReceipt({
    kind: "commons",
    pool_micro: 1_000_000,
    shares: [
      { destination: "carbon", bps: 6_000 },
      { destination: "affected", bps: 2_500 },
      { destination: "verifier", bps: 1_500 },
    ],
    allocations: [
      { destination: "carbon", amount_micro: 600_000 },
      { destination: "affected", amount_micro: 250_000 },
      { destination: "verifier", amount_micro: 150_000 },
    ],
  });
  assert.equal(r.outcome, "match");
});

test("a skimmed commons receipt is caught (allocations)", async () => {
  const r = await recomputeReceipt({
    kind: "commons",
    pool_micro: 1_000_000,
    shares: [
      { destination: "carbon", bps: 6_000 },
      { destination: "affected", bps: 2_500 },
      { destination: "verifier", bps: 1_500 },
    ],
    allocations: [
      { destination: "carbon", amount_micro: 599_900 }, // skim 100
      { destination: "affected", amount_micro: 250_000 },
      { destination: "verifier", amount_micro: 150_000 },
    ],
  });
  assert.equal(r.outcome, "mismatch");
  assert.equal(r.field, "allocations");
});

test("commons shares that don't sum to 10000 are invalid", async () => {
  const r = await recomputeReceipt({
    kind: "commons",
    pool_micro: 1_000_000,
    shares: [{ destination: "only", bps: 9_999 }],
    allocations: [{ destination: "only", amount_micro: 1_000_000 }],
  });
  assert.equal(r.outcome, "invalid");
});

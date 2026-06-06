// WASM bindings for nucleus-creditworthiness: an agent's whole history → its bond.
//
// creditReputationFromReceipts / requiredBondFromReceipts run the full pipeline
// in-process — recompute each receipt against the proven kernels, fold the honest
// ones up (a caught lie BURNS standing), and price the bond. No server trust.
//
// Requires ./pkg (run `npm run build:wasm` first; CI builds it).

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  creditReputationFromReceipts,
  requiredBondFromReceipts,
} from "../index.js";

// An honest settlement (recomputes to match — see recompute.test.mjs). Its
// declared-input magnitude is price_micro = 1_000_000.
const honestSettlement = {
  kind: "settlement",
  price_micro: 1_000_000,
  delivered_bps: 2_500,
  verdict: "partial",
  seller_gross: 250_000,
  refund: 750_000,
};

// An honest commons routing (recomputes to match). Magnitude = pool_micro = 1M.
const honestCommons = {
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
};

// The same settlement, but the seller skimmed — recompute catches it (a caught
// defection). Magnitude is still the DECLARED price (1M), not the inflated claim.
const skimmedSettlement = { ...honestSettlement, seller_gross: 250_001 };

test("verified history accrues reputation across receipt types", async () => {
  const rep = await creditReputationFromReceipts([honestSettlement, honestCommons]);
  assert.equal(rep, 2_000_000n); // 1M price + 1M pool
});

test("more clean history lowers the required bond (the flywheel)", async () => {
  const bond = await requiredBondFromReceipts(
    [honestSettlement, honestCommons],
    2_500_000,
  );
  assert.equal(bond, 500_000n); // 2.5M gain − 2M reputation
});

test("a caught lie burns the credit it would have earned", async () => {
  // honest (+1M) then the same trade skimmed (−1M, caught by recompute) → 0.
  const rep = await creditReputationFromReceipts([honestSettlement, skimmedSettlement]);
  assert.equal(rep, 0n);
});

test("a fresh agent with no history pays the full bond (sybil-no-discount)", async () => {
  const bond = await requiredBondFromReceipts([], 1_000_000);
  assert.equal(bond, 1_000_000n);
});

test("reputation alone can cover the gain → zero bond", async () => {
  const bond = await requiredBondFromReceipts([honestSettlement, honestCommons], 1_500_000);
  assert.equal(bond, 0n); // 2M reputation ≥ 1.5M gain
});

// WASM reader of the cross-language golden seal (gap G3b).
//
// The SAME JSON vectors in crates/nucleus-econ-kernels/tests/golden/ pin the
// settlement + commons + VCG kernels across Lean (Nucleus/Golden.lean `decide`,
// settlement + commons), Rust (tests/golden.rs, all three), and — here — the
// @coproduct/verify WASM bindings (settlement + commons + VCG). This test asserts
// recomputeSettlement / recomputeCommons / recomputeVcg reproduce the golden bytes
// exactly, so the u64↔BigInt marshaling and serde_wasm_bindgen layer can't drift
// from the proven kernels without turning CI red.
//
// Requires ./pkg (run `npm run build:wasm` first; CI builds it).

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { recomputeSettlement, recomputeCommons, recomputeVcg } from "../index.js";

// test/ -> verifier-js/ -> sdks/ -> repo root -> crates/...
const goldenDir = new URL(
  "../../../crates/nucleus-econ-kernels/tests/golden/",
  import.meta.url,
);

async function readGolden(name) {
  const text = await readFile(fileURLToPath(new URL(name, goldenDir)), "utf8");
  return JSON.parse(text);
}

// settlement.json encodes verdict as 0/1/2; the WASM enum is snake_case.
const VERDICT = ["reverse", "partial", "release"];

test("recomputeSettlement matches every golden settlement vector", async () => {
  const g = await readGolden("settlement.json");
  for (const v of g.vectors) {
    const r = await recomputeSettlement(v.price_micro, v.delivered_bps);
    assert.equal(
      r.verdict,
      VERDICT[v.verdict],
      `verdict ${v.price_micro}/${v.delivered_bps}`,
    );
    assert.equal(
      BigInt(r.seller_gross),
      BigInt(v.seller_gross),
      `seller_gross ${v.price_micro}/${v.delivered_bps}`,
    );
    assert.equal(
      BigInt(r.refund),
      BigInt(v.refund),
      `refund ${v.price_micro}/${v.delivered_bps}`,
    );
    // Conservation (the Lean theorem) holds on the WASM path too.
    assert.equal(
      BigInt(r.seller_gross) + BigInt(r.refund),
      BigInt(v.price_micro),
      `conservation ${v.price_micro}/${v.delivered_bps}`,
    );
  }
});

test("recomputeCommons matches every golden commons vector (no skim)", async () => {
  const g = await readGolden("commons.json");
  for (const v of g.vectors) {
    const allocs = await recomputeCommons(v.pool_micro, g.shares);
    const got = allocs.map((a) => BigInt(a.amount_micro));
    const want = v.allocations.map((x) => BigInt(x));
    assert.deepEqual(got, want, `commons pool=${v.pool_micro}`);
    // No-skim: allocations sum to exactly the pool (matches Lean routed_conserves).
    const sum = got.reduce((acc, x) => acc + x, 0n);
    assert.equal(sum, BigInt(v.pool_micro), `conservation pool=${v.pool_micro}`);
  }
});

test("recomputeVcg matches every golden VCG vector (winners + Clarke pivots)", async () => {
  const g = await readGolden("vcg.json");
  for (const v of g.vectors) {
    const c = await recomputeVcg(v.bids, v.proposals, v.budget_micro_usd);
    // Winners: same count, same (bidder, proposal_id, vcg_payment) in order.
    assert.equal(c.winners.length, v.winners.length, `winner count ${v._name}`);
    for (let i = 0; i < v.winners.length; i++) {
      assert.equal(c.winners[i].bidder, v.winners[i].bidder, `winner bidder ${v._name}`);
      assert.equal(
        c.winners[i].proposal_id,
        v.winners[i].proposal_id,
        `winner proposal ${v._name}`,
      );
      assert.equal(
        BigInt(c.winners[i].vcg_payment_micro_usd),
        BigInt(v.winners[i].vcg_payment_micro_usd),
        `vcg payment ${v._name}/${v.winners[i].bidder}`,
      );
    }
    assert.equal(
      BigInt(c.total_payments_micro_usd),
      BigInt(v.total_payments_micro_usd),
      `total payments ${v._name}`,
    );
  }
});

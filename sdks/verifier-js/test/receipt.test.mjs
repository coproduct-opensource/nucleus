// Node test for verifyReceipt — the colimit receipt envelope (nucleus-receipt:
// Session + Projection[] signed Ed25519 over BLAKE3 of the RFC 8785 canonical
// bytes) verified through the SAME `Receipt::verify` everything upstream runs.
//
// The fixture is REAL: signed by `nucleus-receipt` itself with the
// deterministic test key `SigningKey::from_bytes([7u8; 32])` (see
// fixtures/receipt.json `_generated_by`). Tamper variants are derived here from
// the genuine fixture, so a pass means the WASM path reproduces the upstream
// canonical bytes exactly — one verifier code path for every receipt kind.
//
// Requires ./pkg to exist — run `npm run build:wasm` first (CI builds it).

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { verifyReceipt } from "../index.js";

const fixtureUrl = new URL("./fixtures/receipt.json", import.meta.url);

async function readFixture() {
  const text = await readFile(fileURLToPath(fixtureUrl), "utf8");
  return JSON.parse(text);
}

test("accepts the real, untampered fixture receipt (hex key)", async () => {
  const { receipt, verifying_key_hex } = await readFixture();
  const v = await verifyReceipt(receipt, verifying_key_hex);
  assert.equal(v.outcome, "verified");
  assert.equal(v.version, 1);
  assert.equal(v.session_id, "spiffe://test/agent-x");
  assert.equal(v.issuer_kid, "test-kid");
  assert.deepEqual(v.projection_kinds, ["identity", "economic"]);
  assert.equal(v.root_hash_hex, receipt.root_hash_hex);
});

test("accepts the fixture receipt with a Uint8Array key and a string receipt", async () => {
  const { receipt, verifying_key_hex } = await readFixture();
  const keyBytes = Uint8Array.from(
    verifying_key_hex.match(/.{2}/g).map((b) => parseInt(b, 16)),
  );
  const v = await verifyReceipt(JSON.stringify(receipt), keyBytes);
  assert.equal(v.outcome, "verified");
});

test("a projection tampered after signing is a root_hash_mismatch", async () => {
  const { receipt, verifying_key_hex } = await readFixture();
  // Inflate the claimed price — the classic post-signing tamper.
  receipt.projections[1].body.price_micro_usd = 9_999_999;
  const v = await verifyReceipt(receipt, verifying_key_hex);
  assert.equal(v.outcome, "root_hash_mismatch");
  assert.equal(v.expected, receipt.root_hash_hex);
  assert.notEqual(v.actual, v.expected);
});

test("the wrong issuer key is a signature_mismatch (content untouched)", async () => {
  const { receipt } = await readFixture();
  // A VALID Ed25519 key that simply isn't the issuer's — the verifying key of
  // `SigningKey::from_bytes([8u8; 32])`. (A bit-flipped key would not decode
  // to a curve point at all and is rejected as malformed input instead.)
  // Content still hashes correctly, so the failure must be attributed to the
  // signature, not the root hash.
  const wrongKey =
    "1398f62c6d1a457c51ba6a4b5f3dbd2f69fca93216218dc8997e416bd17d93ca";
  const v = await verifyReceipt(receipt, wrongKey);
  assert.equal(v.outcome, "signature_mismatch");
  assert.ok(v.reason.length > 0, "rejection should carry a reason");
});

test("an undecodable issuer key (not a curve point) throws a clean input error", async () => {
  const { receipt, verifying_key_hex } = await readFixture();
  // Flip the first nibble of the fixture key — still 32 bytes, but no longer
  // a valid compressed Edwards point for THIS key (verified empirically).
  const broken =
    (verifying_key_hex[0] === "0" ? "1" : "0") + verifying_key_hex.slice(1);
  await assert.rejects(verifyReceipt(receipt, broken), /verifying key invalid/);
});

test("malformed receipt JSON throws a clean input error", async () => {
  const { verifying_key_hex } = await readFixture();
  await assert.rejects(
    verifyReceipt("not valid json", verifying_key_hex),
    /receipt JSON/,
  );
});

test("a wrong-length key throws a clean input error", async () => {
  const { receipt } = await readFixture();
  await assert.rejects(
    verifyReceipt(receipt, "deadbeef"), // 4 bytes, not 32
    /32 bytes/,
  );
});

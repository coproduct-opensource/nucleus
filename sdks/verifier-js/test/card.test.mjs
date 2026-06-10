// Node test for verifyAgentCard — the signed A2A v1.0 Agent Card (detached
// ES256 JWS over the RFC 8785 JCS of the card minus its `signatures` field,
// per spec §8.4) verified through the SAME `nucleus_agent_card::verify_card`
// every native recipient runs. Nucleus claims (spiffe_id/did/trust JWKS/
// runtime guarantees) ride in the card's `capabilities.extensions` entry.
//
// The fixture is REAL: signed by `nucleus-agent-card`'s sign_card with a ring
// P-256 key (see fixtures/agent-card.json `_generated_by`); `resolved_jwk` is
// the matching public key a recipient would resolve out-of-band, `wrong_jwk`
// an unrelated key. Tamper variants are derived here from the genuine
// fixture, so a pass means the WASM path reproduces the upstream JCS bytes
// and ES256 verification exactly.
//
// Requires ./pkg to exist — run `npm run build:wasm` first (CI builds it).

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { verifyAgentCard } from "../index.js";

const fixtureUrl = new URL("./fixtures/agent-card.json", import.meta.url);

async function readFixture() {
  const text = await readFile(fileURLToPath(fixtureUrl), "utf8");
  return JSON.parse(text);
}

const NUCLEUS_EXT_URI = "https://coproduct.one/a2a/ext/runtime-guarantees/v1";

/** The nucleus extension params of a v1.0 card (where the claims live). */
function nucleusParams(card) {
  const ext = card.capabilities.extensions.find(
    (e) => e.uri === NUCLEUS_EXT_URI,
  );
  assert.ok(ext, "fixture card declares the nucleus extension");
  return ext.params;
}

test("accepts the real, untampered fixture card with its profile summary", async () => {
  const { signed_card, resolved_jwk } = await readFixture();
  const v = await verifyAgentCard(signed_card, resolved_jwk);
  assert.equal(v.outcome, "verified");
  assert.equal(v.spiffe_id, "spiffe://prod.example.com/ns/agents/sa/coder");
  assert.equal(v.did, "did:web:coder.prod.example.com");
  assert.deepEqual(v.supported_envelope_schema_versions, ["1"]);
  assert.deepEqual(v.trust_jwks_kids, ["issuer-k1"]);
  // The declared runtime-guarantee profile is authentic attestation.
  assert.equal(v.runtime_guarantees.profile_version, "1.0");
  assert.deepEqual(v.runtime_guarantees.tracked_sources, [
    "web_content",
    "secret",
  ]);
  assert.deepEqual(v.runtime_guarantees.enforcement_rules, [
    "no_adversarial_to_outbound",
  ]);
  assert.equal(v.runtime_guarantees.attestation_reference, null);
});

test("accepts JSON-string inputs identically", async () => {
  const { signed_card, resolved_jwk } = await readFixture();
  const v = await verifyAgentCard(
    JSON.stringify(signed_card),
    JSON.stringify(resolved_jwk),
  );
  assert.equal(v.outcome, "verified");
});

test("a card tampered after signing is rejected (verdict, not throw)", async () => {
  const { signed_card, resolved_jwk } = await readFixture();
  nucleusParams(signed_card).did = "did:web:attacker.example.com";
  const v = await verifyAgentCard(signed_card, resolved_jwk);
  assert.equal(v.outcome, "rejected");
});

test("tampering a base v1.0 card field also breaks the signature", async () => {
  const { signed_card, resolved_jwk } = await readFixture();
  signed_card.name = "Imposter Agent";
  const v = await verifyAgentCard(signed_card, resolved_jwk);
  assert.equal(v.outcome, "rejected");
});

test("a tampered runtime-guarantee declaration breaks the signature", async () => {
  const { signed_card, resolved_jwk } = await readFixture();
  nucleusParams(signed_card).runtimeGuarantees.enforcementRules[0].name =
    "allow_everything";
  const v = await verifyAgentCard(signed_card, resolved_jwk);
  assert.equal(v.outcome, "rejected");
});

test("the wrong resolved key is rejected — the out-of-band key is load-bearing", async () => {
  const { signed_card, wrong_jwk } = await readFixture();
  const v = await verifyAgentCard(signed_card, wrong_jwk);
  assert.equal(v.outcome, "rejected");
  assert.match(v.reason, /JWS verification failed/);
});

test("malformed card JSON throws (input error, not a verdict)", async () => {
  const { resolved_jwk } = await readFixture();
  await assert.rejects(
    () => verifyAgentCard("not valid json", resolved_jwk),
    /signed card JSON/,
  );
});

test("malformed JWK JSON throws (input error, not a verdict)", async () => {
  const { signed_card } = await readFixture();
  await assert.rejects(
    () => verifyAgentCard(signed_card, "{}"),
    /resolved JWK JSON/,
  );
});

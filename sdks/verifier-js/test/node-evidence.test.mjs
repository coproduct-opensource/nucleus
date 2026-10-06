// Node test for verifyNodeEvidence — node TPM evidence (ADR 0011) appraised
// through the WASM build of the SAME `nucleus_node_evidence::appraise` the
// Rust verifier runs.
//
// Parity: the cases and golden reports are the Rust crate's own
// (crates/nucleus-node-evidence/tests/fixtures/parity/), read in place rather
// than copied. tests/parity.rs checks the Rust verifier against them; this
// requires the wasm build to reproduce each report deep-equal. The fixtures
// are real cloud-vTPM evidence, including the live run's epoch-4 document
// whose digest a signed Firecracker receipt named.
//
// Requires ./pkg to exist — run `npm run build:wasm` first (CI builds it).

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { verifyNodeEvidence, VerifyError } from "../index.js";

const fixtures = new URL(
  "../../../crates/nucleus-node-evidence/tests/fixtures/",
  import.meta.url,
);
const bytes = (name) => readFile(fileURLToPath(new URL(name, fixtures)));
const text = async (name) => (await bytes(name)).toString("utf8");

const { cases } = JSON.parse(await text("parity/cases.json"));

const status = (r) =>
  r.outcome === "refused" ? "refused" : r.ear.submods.node["ear.status"];

test("the parity list is the one the Rust verifier checks", () => {
  // A list that silently emptied would pass every case it no longer holds.
  assert.equal(cases.length, 7);
  assert.deepEqual(
    [...new Set(cases.map((c) => c.expect_status))].sort(),
    ["affirming", "contraindicated", "none", "refused", "warning"],
  );
});

for (const c of cases) {
  test(`${c.name}: ${c.expect_status}, and the Rust verifier's report exactly`, async () => {
    const got = await verifyNodeEvidence(
      new Uint8Array(await bytes(c.evidence)),
      await text(c.reference),
      c.relying_party,
    );
    assert.equal(status(got), c.expect_status);
    assert.deepEqual(got, JSON.parse(await text(c.report)));
  });
}

test("the live epoch document's digest is the one the signed receipt named", async () => {
  const c = cases.find((x) => x.name === "live-epoch4-attested");
  const got = await verifyNodeEvidence(
    await text(c.evidence),
    JSON.parse(await text(c.reference)),
    JSON.stringify(c.relying_party),
  );
  assert.equal(
    got.evidence_sha256,
    "d0689ce45219cf0e9e7827e0988c00a0a8545df93f773339734d92f44837bcab",
  );
  assert.equal(got.ear.submods.node["nucleus.appraisal"].tier.tier, "attested");
  assert.deepEqual(got.ear.submods.node["nucleus.appraisal"].anchor, {
    operator_fetched: { source: "gcp-shielded-vm-identity:attest-live-x86" },
  });
});

test("a parsed evidence object is refused: re-serializing would change its digest", async () => {
  const c = cases[0];
  await assert.rejects(
    verifyNodeEvidence(JSON.parse(await text(c.evidence)), await text(c.reference), c.relying_party),
    (e) => e instanceof VerifyError && e.code === "INPUT",
  );
});

test("a relying party that omits operator_pins is an input error, not a verdict", async () => {
  const c = cases[0];
  const { operator_pins: _omitted, ...rp } = c.relying_party;
  await assert.rejects(
    verifyNodeEvidence(await bytes(c.evidence), await text(c.reference), rp),
    (e) => e instanceof VerifyError && e.code === "INPUT" && /operator_pins/.test(e.message),
  );
});

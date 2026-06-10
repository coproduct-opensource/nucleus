// @coproduct/verify — the one-line drop-in over the nucleus WASM verifier.
//
// Design goals (the wedge): the developer writes ONE line and never touches
// WASM init, never reads from a network, never reimplements crypto:
//
//     import { verify } from "@coproduct/verify";
//     const r = await verify(receipt, trustAnchor);
//     if (!r.ok) throw new Error(r.error.message);
//
// This is a *thin facade* over `nucleus-verifier-wasm` (the audited Rust
// envelope verifier compiled to WASM, in ./pkg). It adds NO crypto: it only
// (1) auto-initialises the WASM exactly once, lazily, and (2) translates the
// throw-on-failure WASM API into an ergonomic discriminated-union result so a
// failed verification is an ordinary value (`r.ok === false`), not a thrown
// exception you have to remember to catch.
//
// Works in Node (>=18) and the browser with the same import — see initWasm().
//
// ── DORMANT PAYMENT SEAM (documented only; NOT wired) ─────────────────────
// A *successful* verify() is the natural per-verification metering point for a
// future paid tier (x402 / L402 "pay-per-verify"). It is the unit of value the
// caller actually consumes. This seam is DORMANT: verify() performs NO payment,
// keeps NO counter, and makes NO network call. Turning it on would mean
// wrapping the `ok: true` branch below with an x402/L402 settlement step — a
// deliberate, separate go-live decision, exactly like the gated publish
// workflow and the DOCS_DEPLOY seam. Do not infer any billing from this file.
// ──────────────────────────────────────────────────────────────────────────

/**
 * Stable, machine-readable failure codes. Mirrors the sigstore-js / zod
 * `safeParse` idiom: callers branch on a discriminant, not on string-matching
 * an exception message.
 *
 * @typedef {"INPUT"|"INIT"|"VERIFICATION"} VerifyErrorCode
 */

/**
 * A typed verification error. Carries a stable `code` plus the underlying
 * message from the WASM verifier (e.g. "merkle inclusion proof invalid").
 */
export class VerifyError extends Error {
  /**
   * @param {VerifyErrorCode} code
   * @param {string} message
   * @param {{ cause?: unknown }} [opts]
   */
  constructor(code, message, opts) {
    super(message, opts);
    this.name = "VerifyError";
    /** @type {VerifyErrorCode} */
    this.code = code;
  }
}

// Memoised init promise: the WASM module is instantiated at most once per
// process / page, no matter how many times verify() is called concurrently.
/** @type {Promise<typeof import("./pkg/nucleus_verifier_wasm.js")> | null} */
let _wasmReady = null;

/**
 * Lazily import + instantiate the WASM verifier exactly once.
 *
 * The ./pkg artifact is the wasm-pack `web` target: `default` is an async init
 * that, given no argument, resolves `new URL("..._bg.wasm", import.meta.url)`
 * and `fetch`es it (correct in browsers). Node's global `fetch` cannot load a
 * `file:` URL, so under Node we read the `.wasm` bytes off disk and hand them
 * to init directly — same audited bytes, no network either way.
 */
async function initWasm() {
  if (_wasmReady) return _wasmReady;
  _wasmReady = (async () => {
    const mod = await import("./pkg/nucleus_verifier_wasm.js");
    const isNode =
      typeof process !== "undefined" &&
      process.versions != null &&
      process.versions.node != null;
    if (isNode) {
      // Read the wasm bytes relative to the pkg JS and instantiate from a
      // BufferSource — no fetch, no network, works for file:// installs.
      const { readFile } = await import("node:fs/promises");
      const { fileURLToPath } = await import("node:url");
      const wasmUrl = new URL(
        "./pkg/nucleus_verifier_wasm_bg.wasm",
        import.meta.url,
      );
      const bytes = await readFile(fileURLToPath(wasmUrl));
      await mod.default({ module_or_path: bytes });
    } else {
      // Browser / bundler: default init fetches the co-located .wasm.
      await mod.default();
    }
    return mod;
  })().catch((e) => {
    // Reset so a transient init failure can be retried on the next call.
    _wasmReady = null;
    throw new VerifyError(
      "INIT",
      `failed to initialise WASM verifier: ${e?.message ?? String(e)}`,
      { cause: e },
    );
  });
  return _wasmReady;
}

/**
 * The report the WASM verifier returns on success. Shape mirrors the Rust
 * `VerifyReport` (see ../src/lib.rs).
 *
 * @typedef {object} VerifyReport
 * @property {true} ok
 * @property {"out_of_band"|"self_check_only"} trust_mode
 * @property {string} trust_domain
 * @property {number} edge_count
 * @property {number} checkpoint_count
 * @property {string} head_edge_hash_hex
 * @property {number} schema_version
 * @property {string[]} kids
 * @property {boolean} merkle_verified
 * @property {number} cosignatures_verified
 * @property {string[]} matched_witness_pubkeys_hex
 * @property {boolean} payload_binding_verified
 */

/**
 * Successful verification result.
 * @typedef {{ ok: true, report: VerifyReport }} VerifyOk
 */

/**
 * Failed verification result.
 * @typedef {{ ok: false, error: VerifyError }} VerifyFail
 */

/**
 * Discriminated union — branch on `.ok`.
 * @typedef {VerifyOk | VerifyFail} VerifyResult
 */

/**
 * Coerce a receipt/anchor that may be a string OR an object into the JSON
 * string the WASM expects. Strings are passed through verbatim (we do NOT
 * re-stringify, to avoid double-encoding); objects are JSON-serialised.
 *
 * @param {unknown} v
 * @returns {string}
 */
function asJsonString(v) {
  if (typeof v === "string") return v;
  return JSON.stringify(v);
}

/**
 * Verify a nucleus provenance receipt (bundle) against a pinned trust anchor.
 *
 * One call, auto-init, no infra. Returns a result object — a failed
 * verification is `{ ok: false, error }`, NOT a thrown exception. (Only
 * programmer errors — bad input shape, WASM init failure — surface via the
 * error branch with codes "INPUT" / "INIT"; a cryptographically-rejected
 * receipt surfaces as code "VERIFICATION".)
 *
 * SCOPE (honest): this proves the receipt is *tamper-evident* (hash-chained +
 * Merkle-anchored) and *authentic* (signed/cosigned by keys in YOUR anchor).
 * It does NOT prove the agent behaved well, that IFC policy held, or that any
 * computation was correct. The trust anchor must be supplied/pinned by you.
 *
 * @param {string | object} receipt
 *   A nucleus `Bundle` — JSON string or already-parsed object.
 * @param {string | object} trustAnchor
 *   A trust-anchor input — JSON string or object. Typically
 *   `{ trust_jwks: {...}, trust_witness_pubkey_hex?, cosignature_threshold? }`.
 * @returns {Promise<VerifyResult>}
 */
export async function verify(receipt, trustAnchor) {
  let bundleJson;
  let anchorJson;
  try {
    bundleJson = asJsonString(receipt);
    anchorJson = asJsonString(trustAnchor);
  } catch (e) {
    return {
      ok: false,
      error: new VerifyError(
        "INPUT",
        `could not serialise input to JSON: ${e?.message ?? String(e)}`,
        { cause: e },
      ),
    };
  }

  let mod;
  try {
    mod = await initWasm();
  } catch (e) {
    // initWasm already wraps in a VerifyError("INIT", ...).
    return { ok: false, error: /** @type {VerifyError} */ (e) };
  }

  try {
    const report = /** @type {VerifyReport} */ (
      mod.verifyBundle(bundleJson, anchorJson)
    );
    return { ok: true, report };
  } catch (e) {
    // The WASM throws on any cryptographic / structural rejection. This is the
    // expected "receipt did not verify" path — surface it as a typed value.
    return {
      ok: false,
      error: new VerifyError("VERIFICATION", e?.message ?? String(e), {
        cause: e,
      }),
    };
  }
}

/**
 * The semver of the underlying WASM verifier. Useful for "verify the verifier"
 * diagnostics. Auto-inits.
 * @returns {Promise<string>}
 */
export async function verifierVersion() {
  const mod = await initWasm();
  return mod.sdkVersion();
}

/**
 * The envelope-schema version this build can verify. Auto-inits.
 * @returns {Promise<number>}
 */
export async function supportedSchemaVersion() {
  const mod = await initWasm();
  return mod.supportedEnvelopeSchemaVersion();
}

// ── COLIMIT RECEIPT: verify the nucleus-receipt envelope ──────────────────────
// `verify()` covers the lineage bundle; `verifyReceipt()` covers the OTHER
// signed artifact — the colimit receipt (Session + Projection[] signed Ed25519
// over BLAKE3 of the RFC 8785 canonical bytes). The WASM runs the SAME
// `Receipt::verify` everything upstream runs: one verifier code path for every
// receipt kind, in your process, trusting no server.

/**
 * Decode a hex string into bytes for the 32-byte Ed25519 key input.
 * @param {string} hex
 * @returns {Uint8Array}
 */
function hexToBytes(hex) {
  const clean = hex.trim();
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) {
    throw new VerifyError("INPUT", `verifying key hex is malformed: "${hex}"`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}

/**
 * Verify a colimit receipt (`nucleus-receipt` envelope) against the issuer's
 * 32-byte Ed25519 verifying key. Re-canonicalizes (RFC 8785), recomputes the
 * BLAKE3 root hash, and re-verifies the signature — the exact upstream
 * `Receipt::verify`, compiled to this WASM.
 *
 * Returns a structured verdict the caller branches on: a cryptographic
 * rejection is a VALUE (`outcome`), distinguishing content tampered after
 * signing (`root_hash_mismatch`) from a wrong/forged key (`signature_mismatch`).
 * Throws only on malformed input (bad JSON, wrong key length).
 *
 * @param {string | object} receipt
 *   A `Receipt` — JSON string or parsed object
 *   (`{version, session, projections, root_hash_hex, signature_b64}`).
 * @param {string | Uint8Array} verifyingKey
 *   The issuer's raw 32-byte Ed25519 public key — hex string or bytes.
 * @returns {Promise<
 *   | { outcome: "verified", version: number, session_id: string,
 *       issuer_kid: string, projection_kinds: string[], root_hash_hex: string }
 *   | { outcome: "root_hash_mismatch", expected: string, actual: string }
 *   | { outcome: "signature_mismatch", reason: string }
 * >}
 */
export async function verifyReceipt(receipt, verifyingKey) {
  const mod = await initWasm();
  const keyBytes =
    typeof verifyingKey === "string" ? hexToBytes(verifyingKey) : verifyingKey;
  return mod.verifyReceipt(
    typeof receipt === "string" ? receipt : JSON.stringify(receipt),
    keyBytes,
  );
}

// ── AGENT CARD: verify the counterparty's signed identity BEFORE acting ───────
// `verify()` answers WHAT happened, `verifyReceipt()` what was SIGNED —
// `verifyAgentCard()` answers WHO you are about to act with. The WASM runs the
// SAME `verify_card` every native recipient runs (JCS re-canonicalization +
// detached ES256 JWS + advertised-JWKS usability) against a key YOU resolved
// out-of-band. The card's own key material is never trusted: a card verified
// against an attacker-supplied key is "verified garbage", by design.

/**
 * Verify a signed A2A Agent Card against an out-of-band-resolved key.
 *
 * Returns a structured verdict the caller branches on: a cryptographic
 * rejection (no signatures, wrong key, tampered card, unusable advertised
 * JWKS) is a VALUE (`outcome: "rejected"`), not a thrown exception. Throws
 * only on malformed input (bad card JSON, bad JWK JSON).
 *
 * On success the verdict includes the card's runtime-guarantee profile
 * summary — authentic attestation (covered by the card's signature), NOT
 * proof of enforcement.
 *
 * @param {string | object} signedCard
 *   A `SignedAgentCard` — JSON string or parsed object (`{card, signatures}`).
 * @param {string | object} resolvedJwk
 *   The out-of-band-resolved verification key — JWK JSON string or object
 *   (`{"kty":"EC","crv":"P-256","x":"...","y":"..."}`). NEVER from the card.
 * @returns {Promise<
 *   | { outcome: "verified", spiffe_id: string, did: string,
 *       supported_envelope_schema_versions: string[],
 *       trust_jwks_kids: string[],
 *       runtime_guarantees: {
 *         profile_version: string, tracked_sources: string[],
 *         enforcement_rules: string[], attestation_reference: string | null,
 *       } | null }
 *   | { outcome: "rejected", reason: string }
 * >}
 */
export async function verifyAgentCard(signedCard, resolvedJwk) {
  const mod = await initWasm();
  return mod.verifyAgentCard(
    asJsonString(signedCard),
    asJsonString(resolvedJwk),
  );
}

// ── RECOMPUTE: re-derive the decision, don't just check the signature ─────────
// `verify()` proves a receipt was *signed*; `recompute()` proves the in-bounds
// IFC *decision* was correct by re-running the EXACT same gate function the
// production seller runs (nucleus-ifc, compiled to this WASM). This is the
// structural differentiator: a verdict a counterparty independently re-derives,
// not a vendor's signature over the vendor's own claim. SCOPE (honest):
// model-level over the DECLARED inputs (coverage-limited, per-call); fails closed
// on an unknown input token.

/**
 * The recomputed IFC verdict. Mirrors the Rust `RecomputeReport`.
 * @typedef {object} RecomputeReport
 * @property {boolean} allow
 * @property {string} reason
 * @property {string[]} declared_inputs
 * @property {string} canonical
 */

/**
 * Re-derive the IFC verdict for a call's declared inputs by running the same
 * decision the production gate runs (no network, no trust in any server).
 *
 * @param {string[]} declaredInputs
 *   Input tokens, e.g. `["user_prompt","web_content"]` (the set a receipt binds).
 * @param {{ requiresAuthority?: boolean, sinkPublic?: boolean }} [opts]
 * @returns {Promise<{ ok: true, verdict: RecomputeReport } | VerifyFail>}
 */
export async function recompute(declaredInputs, opts = {}) {
  let mod;
  try {
    mod = await initWasm();
  } catch (e) {
    return { ok: false, error: /** @type {VerifyError} */ (e) };
  }
  const { requiresAuthority = false, sinkPublic = false } = opts;
  try {
    const verdict = /** @type {RecomputeReport} */ (
      mod.recomputeVerdict(
        JSON.stringify(declaredInputs),
        requiresAuthority,
        sinkPublic,
      )
    );
    return { ok: true, verdict };
  } catch (e) {
    // Unknown token (fails closed) or bad input.
    return {
      ok: false,
      error: new VerifyError("INPUT", e?.message ?? String(e), { cause: e }),
    };
  }
}

/**
 * Recompute and compare to a *claimed* verdict (e.g. the one a receipt binds).
 * The one-liner that turns "trust the receipt" into "verify it": returns `true`
 * iff the independently re-derived `allow` matches `claimedAllow`.
 *
 * @param {string[]} declaredInputs
 * @param {boolean} claimedAllow
 * @param {{ requiresAuthority?: boolean, sinkPublic?: boolean }} [opts]
 * @returns {Promise<boolean>}
 */
export async function checkVerdict(declaredInputs, claimedAllow, opts = {}) {
  const mod = await initWasm();
  const { requiresAuthority = false, sinkPublic = false } = opts;
  return mod.checkVerdict(
    JSON.stringify(declaredInputs),
    requiresAuthority,
    sinkPublic,
    claimedAllow,
  );
}

// ── RECOMPUTE THE ECONOMICS: cleared price (VCG + Pigou), settlement, commons ──
// All run the EXACT proven `nucleus-econ-kernels` functions in-process — a
// counterparty re-derives the price, the externality charge, the payout split,
// and where the externality revenue is routed, trusting no server. `u64` fields
// cross the wasm boundary as BigInt.

const big = (x) => (typeof x === "bigint" ? x : BigInt(x));

/**
 * Re-derive the truthful VCG clearing (winners + Clarke-pivot payments).
 * @param {object[]} bids `IntegerBid[]` `{bidder, proposal_id, effective_value_micro_usd}`
 * @param {object[]} proposals `IntegerProposal[]` `{id, cost_micro_usd}`
 * @param {number|bigint} budgetMicroUsd
 * @returns {Promise<object>} the `Clearing` (winners/losers/totals).
 */
export async function recomputeVcg(bids, proposals, budgetMicroUsd) {
  const mod = await initWasm();
  return mod.recomputeVcg(JSON.stringify(bids), JSON.stringify(proposals), big(budgetMicroUsd));
}

/**
 * Re-derive the Pigouvian-VCG clearing — the cleared price INCLUDING the
 * internalised externality charge + the resulting rebate pool.
 * @param {object[]} bids @param {object[]} proposals @param {number|bigint} budgetMicroUsd
 * @param {object[]} externalities `ExternalityProfile[]` (signed claims per resource dim)
 * @param {object} rates `PigouvianRates` `{lambdas:{<dim>:<u64>}}`
 * @returns {Promise<object>} the `PigouvianClearing` `{clearing, rebate_pool_micro_usd}`.
 */
export async function recomputeVcgPigou(bids, proposals, budgetMicroUsd, externalities, rates) {
  const mod = await initWasm();
  return mod.recomputeVcgPigou(
    JSON.stringify(bids),
    JSON.stringify(proposals),
    big(budgetMicroUsd),
    JSON.stringify(externalities),
    JSON.stringify(rates),
  );
}

/**
 * Re-derive the settlement split for a cleared price at a delivery score (bps):
 * `{ verdict, seller_gross, refund }` with `seller_gross + refund == price`.
 * @param {number|bigint} priceMicro @param {number|bigint} deliveredBps
 * @returns {Promise<{verdict:"reverse"|"partial"|"release", seller_gross:bigint, refund:bigint}>}
 */
export async function recomputeSettlement(priceMicro, deliveredBps) {
  const mod = await initWasm();
  return mod.recomputeSettlement(big(priceMicro), big(deliveredBps));
}

/**
 * Re-derive the externality→commons routing (no-skim conservation; sum equals
 * the pool). The social-good audit: watch the money fund the fix.
 * @param {number|bigint} poolMicro
 * @param {object[]} shares `CommonsShare[]` `{destination, bps}` (must sum to 10000)
 * @returns {Promise<object[]>} `CommonsAllocation[]` `{destination, amount_micro}`.
 */
export async function recomputeCommons(poolMicro, shares) {
  const mod = await initWasm();
  return mod.recomputeCommons(big(poolMicro), JSON.stringify(shares));
}

/**
 * Re-derive a whole **clearing receipt** — its declared inputs + claimed outputs
 * for a settlement / commons / VCG outcome — against the proven kernels. The
 * keystone "verify, don't trust" check: a relying party who never saw the auction
 * confirms every claimed number by recomputing it.
 * @param {object} receipt a `ClearingReceipt` `{kind:"settlement"|"commons"|"vcg", ...}`
 * @returns {Promise<object>} `{outcome:"match"}` |
 *   `{outcome:"mismatch", field, claimed, recomputed}` |
 *   `{outcome:"invalid", reason}`.
 */
export async function recomputeReceipt(receipt) {
  const mod = await initWasm();
  return mod.recomputeReceipt(
    typeof receipt === "string" ? receipt : JSON.stringify(receipt),
  );
}

/**
 * Surface the **assurance rung** of an externality profile — how much trust each
 * dimension's `units_micro` demands, and the profile's overall (weakest-link)
 * rung. The rung is DERIVED from what actually verified (an unsigned dimension is
 * `self_reported` no matter what evidence is attached); the overall is the
 * MINIMUM across dimensions. This is the anti-greenwashing primitive: a receipt
 * states its own, checkable assurance level.
 *
 * SCOPE: reports the trust LEVEL of the measurement; it does not itself attest
 * the physical sensor (the irreducible residue — see the externality-oracle RFC).
 *
 * @param {object[]} layers per-dimension verification outcomes:
 *   `{ dimension, signature_ok, tee_ok, multi_source_disputed, zk_envelope_ok }`.
 * @returns {Promise<{ overall_rung: string|null, dimensions: {dimension: string, rung: string}[] }>}
 */
export async function recomputeAssuranceRung(layers) {
  const mod = await initWasm();
  return mod.recomputeAssuranceRung(JSON.stringify(layers));
}

/**
 * Re-derive the **minimum bond** a counterparty should require of an agent, given
 * its worst-case one-shot defection exposure and its (verified) reputation value
 * at risk. The flywheel made actionable: more verifiable clean history ⇒ a lower
 * bond to lock — recomputable by anyone, no server trust. Runs the proven
 * `required_bond` (antitone in reputation; a fresh identity pays the full bond;
 * floored so you can't under-collateralize).
 *
 * SCOPE: the capital arithmetic only — it does not attest that `reputationMicro`
 * is real (that's the recompute+pinning layer re-deriving the agent's history).
 *
 * @param {number|bigint} maxDefectionGainMicro
 * @param {number|bigint} reputationMicro
 * @returns {Promise<bigint>} the minimum bond in micro-units.
 */
export async function recomputeRequiredBond(maxDefectionGainMicro, reputationMicro) {
  const mod = await initWasm();
  return mod.recomputeRequiredBond(big(maxDefectionGainMicro), big(reputationMicro));
}

/**
 * Re-derive whether `bondMicro` + `reputationMicro` deters a one-shot defection
 * worth `maxDefectionGainMicro` (proven `deters`: `gain ≤ bond + rep`).
 * @param {number|bigint} bondMicro
 * @param {number|bigint} reputationMicro
 * @param {number|bigint} maxDefectionGainMicro
 * @returns {Promise<boolean>}
 */
export async function recomputeDeters(bondMicro, reputationMicro, maxDefectionGainMicro) {
  const mod = await initWasm();
  return mod.recomputeDeters(big(bondMicro), big(reputationMicro), big(maxDefectionGainMicro));
}

// ── CREDITWORTHINESS: an agent's whole history → its required bond ─────────────
// recomputeRequiredBond takes a bare reputation number; these take the agent's
// RECEIPTS and run the whole pipeline — recompute each, fold the honest ones up
// (a caught lie burns standing), price the bond — in-process, no server trust.

/**
 * Re-derive an agent's bond-substituting reputation (micro) from its clearing
 * receipts. Each is recomputed against the proven kernels: a Match builds
 * standing, a Mismatch (a caught defection) burns it, an Invalid receipt is
 * ignored. Returns the financial-dimension reputation (the reserved Pigouvian
 * dimension is dormant). No server trust.
 * @param {object[]|string} receipts a `ClearingReceipt[]` (array or JSON string)
 * @returns {Promise<bigint>} reputation in micro-units
 */
export async function creditReputationFromReceipts(receipts) {
  const mod = await initWasm();
  return mod.creditReputationFromReceipts(
    typeof receipts === "string" ? receipts : JSON.stringify(receipts),
  );
}

/**
 * Re-derive the minimum bond an agent must post to deter a defection worth
 * `maxDefectionGainMicro`, given the reputation its receipts earn it — the
 * flywheel end-to-end (receipt → recompute → credit file → bond), in-process,
 * trusting no server. More verified clean history ⇒ a lower bond.
 * @param {object[]|string} receipts a `ClearingReceipt[]` (array or JSON string)
 * @param {number|bigint} maxDefectionGainMicro
 * @returns {Promise<bigint>} the minimum bond in micro-units
 */
export async function requiredBondFromReceipts(receipts, maxDefectionGainMicro) {
  const mod = await initWasm();
  return mod.requiredBondFromReceipts(
    typeof receipts === "string" ? receipts : JSON.stringify(receipts),
    big(maxDefectionGainMicro),
  );
}

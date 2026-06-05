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

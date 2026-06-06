// Type declarations for @coproduct/verify — the one-line verify() facade.

/** Stable, machine-readable failure codes. */
export type VerifyErrorCode = "INPUT" | "INIT" | "VERIFICATION";

/**
 * A typed verification error. Branch on `.code` rather than string-matching
 * `.message`. `VERIFICATION` = the receipt was cryptographically/structurally
 * rejected; `INPUT` = the receipt/anchor could not be serialised; `INIT` = the
 * WASM verifier failed to load.
 */
export class VerifyError extends Error {
  readonly name: "VerifyError";
  readonly code: VerifyErrorCode;
  constructor(code: VerifyErrorCode, message: string, opts?: { cause?: unknown });
}

/** Success report — mirrors the Rust `VerifyReport`. */
export interface VerifyReport {
  ok: true;
  trust_mode: "out_of_band" | "self_check_only";
  trust_domain: string;
  edge_count: number;
  checkpoint_count: number;
  /** 64-char SHA-256 hex of the head edge. */
  head_edge_hash_hex: string;
  schema_version: number;
  /** Every key id covered by the trust JWKS. */
  kids: string[];
  /** True iff the v2 Merkle anchor was checked. */
  merkle_verified: boolean;
  /** Count of cosignatures verified (>= requested threshold on success). */
  cosignatures_verified: number;
  matched_witness_pubkeys_hex: string[];
  payload_binding_verified: boolean;
}

/** Successful verification. */
export interface VerifyOk {
  ok: true;
  report: VerifyReport;
}

/** Failed verification (including bad input / init failure). */
export interface VerifyFail {
  ok: false;
  error: VerifyError;
}

/** Discriminated union — branch on `.ok`. */
export type VerifyResult = VerifyOk | VerifyFail;

/**
 * Verify a nucleus provenance receipt against a pinned trust anchor.
 *
 * One call, auto-init, no infra. A failed verification is returned as
 * `{ ok: false, error }`, not thrown.
 *
 * SCOPE: proves tamper-evidence + authenticity of the lineage against the
 * anchor YOU pin. Does NOT prove the agent behaved well, IFC, or correctness.
 *
 * @param receipt A nucleus `Bundle` — JSON string or parsed object.
 * @param trustAnchor A trust-anchor input — JSON string or object.
 */
export function verify(
  receipt: string | object,
  trustAnchor: string | object,
): Promise<VerifyResult>;

/** Semver of the underlying WASM verifier. Auto-inits. */
export function verifierVersion(): Promise<string>;

/** Envelope-schema version this build can verify. Auto-inits. */
export function supportedSchemaVersion(): Promise<number>;

/** The recomputed IFC verdict — mirrors the Rust `RecomputeReport`. */
export interface RecomputeReport {
  /** Whether the action is permitted by the re-derived decision. */
  allow: boolean;
  /** Audit reason (`"safe"` on allow; the `SafetyCheck` form on deny). */
  reason: string;
  /** The (sorted, deduped) declared inputs the verdict was derived over. */
  declared_inputs: string[];
  /** Canonical binding string (`allow\0inputs`) for comparison to a receipt. */
  canonical: string;
}

/** Options for the recompute path. */
export interface RecomputeOptions {
  /** Whether the action requires `Directive` authority. Default `false`. */
  requiresAuthority?: boolean;
  /** Whether the response is publicly visible (vs. counterparty). Default `false`. */
  sinkPublic?: boolean;
}

/**
 * Re-derive the IFC verdict from a call's declared inputs, running the SAME gate
 * function the production seller runs (no network, no server trust) — proving
 * the in-bounds *decision* was correct, not just that a receipt was signed.
 * Fails closed (`{ ok: false }`) on an unknown token.
 *
 * SCOPE: model-level over the DECLARED inputs (coverage-limited, per-call).
 */
export function recompute(
  declaredInputs: string[],
  opts?: RecomputeOptions,
): Promise<{ ok: true; verdict: RecomputeReport } | VerifyFail>;

/**
 * Recompute and compare to a claimed verdict. Returns `true` iff the
 * independently re-derived `allow` matches `claimedAllow`.
 */
export function checkVerdict(
  declaredInputs: string[],
  claimedAllow: boolean,
  opts?: RecomputeOptions,
): Promise<boolean>;

// ── Economic recompute (proven nucleus-econ-kernels; u64 fields are bigint) ────

/** Re-derive the truthful VCG clearing (winners + Clarke-pivot payments). */
export function recomputeVcg(
  bids: object[],
  proposals: object[],
  budgetMicroUsd: number | bigint,
): Promise<object>;

/** Re-derive the Pigouvian-VCG clearing — cleared price incl. the externality charge. */
export function recomputeVcgPigou(
  bids: object[],
  proposals: object[],
  budgetMicroUsd: number | bigint,
  externalities: object[],
  rates: object,
): Promise<object>;

/** Re-derive the settlement split (`seller_gross + refund == price`). */
export function recomputeSettlement(
  priceMicro: number | bigint,
  deliveredBps: number | bigint,
): Promise<{ verdict: "reverse" | "partial" | "release"; seller_gross: bigint; refund: bigint }>;

/** Re-derive the externality→commons routing (no-skim; sum equals the pool). */
export function recomputeCommons(
  poolMicro: number | bigint,
  shares: object[],
): Promise<Array<{ destination: string; amount_micro: bigint }>>;

/** The assurance rung an externality dimension's measurement reached. Derived
 *  from what verified; ordered weakest→strongest. */
export type AssuranceRung =
  | "self_reported"
  | "oracle_signed"
  | "tee_attested"
  | "multi_source_disputed"
  | "zk_upper_envelope";

/** Per-dimension verification outcomes fed to {@link recomputeAssuranceRung}. */
export interface AssuranceLayerOutcome {
  /** The `ResourceDim` tag this outcome is for (e.g. `"grid_carbon_grams_co2"`). */
  dimension: string;
  /** The independent oracle Ed25519 signature verified (fresh, bound). */
  signature_ok?: boolean;
  /** A TEE attestation over the oracle key verified. */
  tee_ok?: boolean;
  /** ≥2 independent sources corroborated under a staked dispute window. */
  multi_source_disputed?: boolean;
  /** A zk upper-envelope proof bounded `units_micro` and verified. */
  zk_envelope_ok?: boolean;
}

/**
 * Surface the assurance rung of an externality profile — each dimension's
 * DERIVED rung (never self-asserted) plus the profile's overall **weakest-link**
 * rung (`null` for an empty profile). The anti-greenwashing primitive: a receipt
 * states its own, checkable assurance level.
 */
export function recomputeAssuranceRung(
  layers: AssuranceLayerOutcome[],
): Promise<{
  overall_rung: AssuranceRung | null;
  dimensions: Array<{ dimension: string; rung: AssuranceRung }>;
}>;

/**
 * Re-derive the minimum bond a counterparty should require, given an agent's
 * one-shot defection exposure and its verified reputation value at risk. The
 * reputation↔capital flywheel made actionable: more clean history ⇒ less bond.
 * Runs the proven `required_bond` (antitone in reputation; fresh identity pays the
 * full bond; floored so you cannot under-collateralize). Returns micro-units.
 */
export function recomputeRequiredBond(
  maxDefectionGainMicro: number | bigint,
  reputationMicro: number | bigint,
): Promise<bigint>;

/** Re-derive whether `bond + reputation` deters a defection of the given gain
 *  (proven `deters`: `gain ≤ bond + rep`). */
export function recomputeDeters(
  bondMicro: number | bigint,
  reputationMicro: number | bigint,
  maxDefectionGainMicro: number | bigint,
): Promise<boolean>;

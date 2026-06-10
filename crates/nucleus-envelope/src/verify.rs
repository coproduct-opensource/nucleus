//! [`verify_bundle`] — re-validate a [`Bundle`] against a caller-supplied
//! [`TrustAnchor`].
//!
//! # Trust model (read this before using)
//!
//! The bundle's embedded `jwks` is **producer-controlled material**. An
//! attacker who fabricates a whole bundle generates their own keypair,
//! signs whatever edges they like, and ships the matching JWKS — every
//! signature, hash chain, and membership check passes against the
//! bundle's *own* claims.
//!
//! Therefore `verify_bundle` requires a [`TrustAnchor`] that names *which*
//! issuers the verifier trusts out-of-band:
//!
//! - [`TrustAnchor::from_jwks(trusted)`] — verifier supplies a JWKS they
//!   obtained through some authenticated side channel (file under
//!   `chmod 400`, OIDC discovery, signed bundle from operator). Edges
//!   must verify against this JWKS, not the one inside the bundle. The
//!   embedded JWKS is ignored.
//! - [`TrustAnchor::self_check_only()`] — explicit opt-in to "validate the
//!   envelope against the JWKS it carries." Proves the bundle is
//!   *internally consistent*; does NOT prove the producer is who they
//!   claim to be. The [`VerificationReport`] flags this mode so downstream
//!   code can refuse to treat it as a provenance claim.

use std::collections::HashSet;
use std::time::Duration;

use nucleus_lineage::{
    edge_content_hash, verify_chain, Ed25519Witness, InclusionProof, Jwks, LineageEdge, RootHash,
    VerifyError,
};
use sha2::Sha256;
use thiserror::Error;

/// Defense-in-depth cap on `SignedTreeHead.cosignatures` length at the
/// verifier. Producers should bound this anyway; this bound stops a
/// malicious bundle from forcing the verifier into O(cosigs × trusted)
/// Ed25519 verifications. 64 distinct witnesses is well past any
/// production federation setup (typical 3-5 trusted witnesses).
const MAX_COSIGNATURES_PER_STH: usize = 64;

/// **CRIT-3 (#1648) fix.** Defense-in-depth cap on `Envelope.edges`
/// length at the verifier. Each edge triggers one Ed25519 verify
/// (~60µs) in `verify_chain` plus O(len(session_root)) string compares
/// in `is_under_root`. Within the verifier-service's 2 MiB body cap,
/// an attacker can pack ~10k empty edges → seconds of single-thread
/// CPU per request, pinning workers. Reject BEFORE crypto work, in
/// the same spirit as [`MAX_COSIGNATURES_PER_STH`].
///
/// 10k edges is generous: a typical agent-run session emits ~20-200
/// edges (tool calls + LLM responses + artifacts). 10k accommodates
/// long-running batch jobs while bounding the worst case.
const MAX_ENVELOPE_EDGES: usize = 10_000;

/// **CRIT-3 (#1648) fix.** Defense-in-depth cap on `Envelope.checkpoints`
/// length. Each checkpoint carries a `SignedTreeHead` which a future
/// extension may verify (today: stored but not validated per-element).
/// 64 is the same bound used for cosignatures — a session that emits
/// more than ~64 STH-worthy events is a producer bug.
const MAX_ENVELOPE_CHECKPOINTS: usize = 64;

/// **CRIT-3 (#1648) fix.** Defense-in-depth cap on the audit-path
/// length of a single `EdgeInclusionProof`. RFC 6962 §2.1.1 inclusion
/// proofs are ≤ ⌈log₂(tree_size)⌉ hashes. A tree of size 2³⁰ = ~1B
/// leaves needs 30 hashes; cap at 1024 covers 2¹⁰²⁴ leaves which is
/// physically impossible — anything larger is a malformed proof
/// designed to amplify per-proof CPU cost in
/// `ct_merkle::InclusionProof::try_from_bytes` (hex decode + verify).
const MAX_INCLUSION_PROOF_AUDIT_PATH_LEN: usize = 1024;

use crate::bundle::{Bundle, ENVELOPE_SCHEMA_VERSION};

/// What the verifier trusts. See module docs for why this is required.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    jwks: Jwks,
    mode: TrustMode,
    /// Whether a bundle with zero edges is acceptable. Off by default —
    /// an empty envelope authenticates nothing yet a non-expert may read
    /// "ok" as a provenance claim. Opt-in only for callers that
    /// deliberately want "no-claim made" bundles (e.g. dry-run checks).
    allow_empty: bool,
    /// **v2 trust extension.** Ed25519 verifying-key bytes for the
    /// transparency-log witness that signed any
    /// [`crate::MerkleAnchor::sth`] on the bundle. When `None`, a
    /// bundle's Merkle anchor is left UNCHECKED and the verification
    /// report records `merkle_verified = false`. When `Some`, an
    /// envelope without a Merkle anchor still verifies (chain-only),
    /// but a present anchor MUST validate.
    witness_pubkey: Option<[u8; 32]>,
    /// **v2.1 witness federation.** Ed25519 verifying-key bytes for
    /// external witnesses the verifier trusts. Cosignatures on the
    /// STH from witnesses NOT in this set are ignored; the verifier
    /// counts only matches.
    trusted_witnesses: Vec<[u8; 32]>,
    /// **v2.1 witness federation.** Minimum number of trusted-witness
    /// cosignatures required for verification to succeed when the
    /// bundle has a Merkle anchor. Default 0 (federation optional);
    /// set to N to require N-of-trusted countersignatures.
    cosignature_threshold: usize,
    /// **v2.1.1 freshness.** Maximum acceptable age of the Merkle
    /// anchor's STH at verification time. When set, an STH older
    /// than this is rejected; when `None`, no freshness check is
    /// performed (default — backwards-compat).
    sth_max_age: Option<Duration>,
    /// **v2.2 payload binding.** When `true`, reject bundles that
    /// lack a [`crate::PayloadBinding`]. Default `false` for
    /// backwards-compat with v1/v2/v2.1 bundles.
    require_payload_binding: bool,
    /// **v2.3 C2SP federation.** Log origin string used when
    /// reconstructing the C2SP tlog-checkpoint body bytes for
    /// `CosignatureKind::C2sp` cosignatures. Without this set, C2SP
    /// cosignatures cannot be verified — they're silently uncountable.
    /// Operators federating with the external C2SP ecosystem must
    /// call [`Self::with_c2sp_origin`].
    c2sp_origin: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TrustMode {
    /// JWKS came from the caller out-of-band; embedded JWKS is ignored.
    OutOfBand,
    /// Caller explicitly opted into "use the JWKS in the bundle." The
    /// verifier still does the math, but the report carries
    /// `trust_mode = "self_check_only"` so downstream consumers know
    /// this is integrity-against-itself, not provenance.
    SelfCheckOnly,
}

impl TrustAnchor {
    /// Construct a trust anchor from a JWKS the verifier obtained
    /// out-of-band (file, OIDC discovery, signed operator bundle).
    /// This is the production path.
    pub fn from_jwks(jwks: Jwks) -> Self {
        Self {
            jwks,
            mode: TrustMode::OutOfBand,
            allow_empty: false,
            witness_pubkey: None,
            trusted_witnesses: Vec::new(),
            cosignature_threshold: 0,
            sth_max_age: None,
            require_payload_binding: false,
            c2sp_origin: None,
        }
    }

    /// Explicit opt-in to validating an envelope against its own
    /// embedded JWKS. **Not a provenance claim** — only proves the
    /// bundle is internally consistent. Useful for offline audit of
    /// internal consistency, never for "is this from who they say."
    pub fn self_check_only() -> Self {
        Self {
            jwks: Jwks { keys: vec![] }, // unused; verify_bundle reads bundle.envelope.jwks
            mode: TrustMode::SelfCheckOnly,
            allow_empty: false,
            witness_pubkey: None,
            trusted_witnesses: Vec::new(),
            cosignature_threshold: 0,
            sth_max_age: None,
            require_payload_binding: false,
            c2sp_origin: None,
        }
    }

    /// Permit bundles with zero envelope edges. Off by default — empty
    /// envelopes are forgeable nothings. See [`HIGH-4`] in audit log.
    pub fn allow_empty(mut self) -> Self {
        self.allow_empty = true;
        self
    }

    /// True if this anchor is opt-in self-check (not a provenance claim).
    pub fn is_self_check_only(&self) -> bool {
        self.mode == TrustMode::SelfCheckOnly
    }

    /// **v2 trust extension.** Attach the Ed25519 verifying-key bytes
    /// for the transparency-log witness whose STH the bundle's Merkle
    /// anchor was signed by. Callers obtain this key OUT-OF-BAND, the
    /// same as JWKS material.
    ///
    /// When set: a bundle with `merkle_anchor: Some(_)` MUST validate
    /// against this key (STH signature + per-edge inclusion proofs).
    /// When unset: a Merkle anchor present in the bundle is left
    /// unchecked; the report records `merkle_verified = false`.
    pub fn with_witness_pubkey(mut self, key_bytes: [u8; 32]) -> Self {
        self.witness_pubkey = Some(key_bytes);
        self
    }

    /// **v2.1 witness federation.** Add an Ed25519 verifying-key for
    /// an external witness the verifier trusts. Cosignatures on the
    /// STH from this witness will count toward
    /// [`Self::cosignature_threshold`]. Cosignatures from witnesses
    /// NOT in this set are ignored (not an error — they're just
    /// extra material).
    ///
    /// **Dedup behavior**: duplicate calls with the same key are
    /// no-ops. This is critical for the federation semantics — the
    /// threshold is "N distinct trusted witnesses cosigned," not
    /// "N cosignatures verified against any subset of trusted keys."
    /// (See audit CRIT-2: without dedup, a duplicate-key list inflates
    /// the count and a single compromised witness could appear to
    /// satisfy threshold-N.)
    pub fn with_trusted_witness(mut self, key_bytes: [u8; 32]) -> Self {
        if !self.trusted_witnesses.contains(&key_bytes) {
            self.trusted_witnesses.push(key_bytes);
        }
        self
    }

    /// **v2.1 witness federation.** Require at least `n` countersignatures
    /// from witnesses in the trusted set before a Merkle-anchored
    /// bundle is accepted. Default 0 (federation optional).
    ///
    /// Has no effect on bundles without a Merkle anchor (chain-only
    /// v1 bundles).
    pub fn cosignature_threshold(mut self, n: usize) -> Self {
        self.cosignature_threshold = n;
        self
    }

    /// **v2.1.1 freshness check.** Reject a bundle's Merkle anchor if
    /// its STH `timestamp_ms` is older than `now() - max_age`. Defaults
    /// off; production deployments should set this in line with the
    /// log's MMD (typical CT MMD is 24h). When the trust anchor lacks
    /// a witness pubkey, this knob is unused (no anchor verification).
    pub fn sth_max_age(mut self, max_age: Duration) -> Self {
        self.sth_max_age = Some(max_age);
        self
    }

    /// **v2.2 payload binding.** When set, [`verify_bundle`] rejects
    /// any bundle that lacks a [`crate::PayloadBinding`]. Default off
    /// (backwards-compat with v1/v2/v2.1 bundles); production
    /// deployments accepting bundles from untrusted producers should
    /// turn this on, since the binding is the only thing in the
    /// envelope chain that authenticates the payload bytes.
    pub fn require_payload_binding(mut self) -> Self {
        self.require_payload_binding = true;
        self
    }

    /// **v2.3 C2SP federation.** Set the log origin string that
    /// C2SP-protocol cosignatures will be verified against. Required
    /// for any [`nucleus_lineage::CosignatureKind::C2sp`] cosignatures
    /// to contribute to the federation threshold; without it, C2SP
    /// cosignatures are silently uncountable.
    ///
    /// The origin must match exactly what the producer used to format
    /// the checkpoint body (e.g. `"nucleus.example.com/log42"`).
    ///
    /// # Panics
    ///
    /// **MED-1 (audit) fix.** Panics if `origin` is not a valid C2SP
    /// origin string (empty, oversized, contains a newline / control
    /// character / non-printable ASCII byte). Pre-fix the verifier
    /// would silently drop EVERY C2SP cosig when the trust-anchor's
    /// origin failed `validate_origin` (typically a copy-paste error
    /// leaving a trailing `\n`), yielding `cosignatures_verified: 0`
    /// with no operator signal. Fail fast at config time instead.
    ///
    /// Operators who can't fail-fast at config (e.g. CLI flag parsing
    /// where the user's input is partial) should use
    /// [`Self::try_with_c2sp_origin`] which returns Result.
    pub fn with_c2sp_origin(self, origin: impl Into<String>) -> Self {
        self.try_with_c2sp_origin(origin)
            .expect("with_c2sp_origin: origin string failed C2SP validate_origin")
    }

    /// **MED-1 (audit) fix.** Fallible variant of
    /// [`Self::with_c2sp_origin`]. Validates the origin via
    /// [`nucleus_lineage::validate_origin`] (rejects newline /
    /// control chars / non-printable ASCII / empty / oversized)
    /// BEFORE storing it on the trust anchor. Returns
    /// [`VerifyBundleError::BadPayloadBinding`] with a `detail` field
    /// naming the validation failure on rejection.
    pub fn try_with_c2sp_origin(
        mut self,
        origin: impl Into<String>,
    ) -> Result<Self, VerifyBundleError> {
        let origin = origin.into();
        nucleus_lineage::validate_origin(&origin).map_err(|e| {
            VerifyBundleError::BadPayloadBinding {
                detail: format!("c2sp_origin failed C2SP validation: {e}"),
            }
        })?;
        self.c2sp_origin = Some(origin);
        Ok(self)
    }
}

/// Errors returned by [`verify_bundle`].
#[derive(Debug, Error)]
pub enum VerifyBundleError {
    /// Envelope schema version is newer than this verifier understands.
    #[error("envelope schema version {got} > supported {supported}")]
    UnsupportedSchema { got: u32, supported: u32 },
    /// Session root SPIFFE id is not a pod-shaped id (it carries a
    /// `/call/` suffix). A pod root has no call segments.
    #[error("session root {root} is not a pod-shaped SPIFFE id (must have no /call/ suffix)")]
    SessionRootNotPod { root: String },
    /// Envelope is empty and the trust anchor did not opt into accepting
    /// empty envelopes. Empty bundles authenticate nothing.
    #[error("envelope has zero edges; pass TrustAnchor::allow_empty() to accept")]
    EmptyEnvelope,
    /// First edge must be a pod-admit for the session root with no
    /// parents and no `prev_hash`.
    #[error(
        "edges[0] must be a PodAdmit edge for session root, with empty parents and no prev_hash; \
         got child={child} kind={kind}"
    )]
    BadHead { child: String, kind: String },
    /// At least one edge's child OR parents fall outside the session
    /// root. Membership is checked against both endpoints to catch
    /// merge edges that import foreign-trust-domain parents.
    #[error(
        "edge #{index} {endpoint} {id} is not under session root {root} — envelope must be \
         constrained to the session"
    )]
    OutsideRoot {
        index: usize,
        endpoint: &'static str,
        id: String,
        root: String,
    },
    /// Per-edge signature / chain verification failed against the trust
    /// anchor's JWKS.
    #[error("edge #{index} signature/chain verification failed: {source}")]
    Chain {
        index: usize,
        #[source]
        source: VerifyError,
    },
    /// Bundle carries a `merkle_anchor` but no `witness_pubkey` was
    /// supplied in the trust anchor.
    #[error(
        "bundle has a merkle_anchor but trust anchor has no witness_pubkey \
         (call TrustAnchor::with_witness_pubkey to verify it)"
    )]
    MissingWitnessKey,
    /// The witness signature on the Merkle anchor's STH did not verify.
    #[error("Merkle anchor STH signature verification failed: {0}")]
    MerkleAnchorBadSignature(String),
    /// Number of inclusion proofs doesn't match the number of envelope
    /// edges. The anchor commits to a specific edge ordering; any
    /// mismatch indicates tampering or builder bug.
    #[error("Merkle anchor has {got} inclusion proofs but envelope has {expected} edges")]
    MerkleAnchorLengthMismatch { got: usize, expected: usize },
    /// An inclusion proof failed to reconstruct the signed root from
    /// its leaf. `index` is the edge index in `envelope.edges`.
    #[error("edge #{index} inclusion proof failed against signed root: {detail}")]
    MerkleAnchorInclusionFailed { index: usize, detail: String },
    /// Fewer DISTINCT trusted witnesses cosigned the STH than the
    /// configured threshold demands. The `verified` count is the
    /// number of *distinct* trusted-witness keys whose cosignature
    /// validated — NOT the number of cosignatures in the STH (one
    /// witness's two cosigs count as 1).
    #[error(
        "witness-federation threshold not met: {verified} distinct trusted witnesses cosigned, \
         threshold {required}"
    )]
    InsufficientCosignatures { verified: usize, required: usize },
    /// The STH carries more cosignatures than this verifier accepts
    /// per the [`MAX_COSIGNATURES_PER_STH`] DoS bound.
    #[error(
        "Merkle anchor STH has {got} cosignatures (max {max}); likely DoS amplifier in a hostile bundle"
    )]
    CosignatureListTooLarge { got: usize, max: usize },
    /// **CRIT-3 (#1648) fix.** Bundle's collection size (edges,
    /// checkpoints, or inclusion-proof audit-path) exceeds the
    /// verifier's defense-in-depth cap. Discriminator says which
    /// collection. Rejected BEFORE any crypto work so a hostile bundle
    /// can't pin a verifier worker for seconds of Ed25519 verifies.
    #[error("envelope `{what}` length {got} exceeds verifier cap {max} (DoS amplifier)")]
    EnvelopeTooLarge {
        what: &'static str,
        got: usize,
        max: usize,
    },
    /// The Merkle anchor's STH is older than the trust anchor's
    /// `sth_max_age` allows.
    #[error("Merkle anchor STH is too old: age {age_ms}ms exceeds max {max_age_ms}ms")]
    StaleSth { age_ms: u64, max_age_ms: u64 },
    /// `require_payload_binding` was set but the bundle has no
    /// `binding`.
    #[error(
        "payload binding required but bundle has none (call TrustAnchor::require_payload_binding only \
         on producers known to emit bindings)"
    )]
    MissingPayloadBinding,
    /// The payload binding's signature did not verify, or one of its
    /// content hashes diverged from the recomputed values.
    #[error("payload binding verification failed: {detail}")]
    BadPayloadBinding { detail: String },
    /// **v2.3b HIGH-1 fix.** Bundle's STH carries one or more
    /// [`nucleus_lineage::CosignatureKind::C2sp`] cosignatures but the
    /// [`TrustAnchor`] has no `c2sp_origin` configured — so the
    /// verifier can't reconstruct the signed bytes for those cosigs.
    /// Before this fix the verifier silently dropped the cosigs and
    /// failed with a generic `InsufficientCosignatures{verified:0}`,
    /// giving operators no signal that the problem was missing
    /// origin config. Call [`TrustAnchor::with_c2sp_origin`].
    #[error(
        "bundle has {c2sp_cosig_count} C2SP-protocol cosignature(s) but trust anchor has no \
         c2sp_origin — they cannot be verified; call TrustAnchor::with_c2sp_origin"
    )]
    MissingC2spOrigin { c2sp_cosig_count: usize },
}

/// Result of a successful [`verify_bundle`] call.
#[derive(Debug, Clone)]
pub struct VerificationReport {
    /// Number of edges in the verified envelope.
    pub edge_count: usize,
    /// Sorted, deduplicated list of issuer `kid`s observed in `proof`
    /// fields. Cross-reference these against your out-of-band trust
    /// directory.
    pub kids: Vec<String>,
    /// SPIFFE trust domain (URI authority) of the session root.
    pub trust_domain: String,
    /// SHA-256 of the canonical bytes of the last edge in the chain,
    /// hex-encoded. Pin this in your downstream system to detect bundle
    /// substitution — a different log produces a different head.
    pub head_edge_hash_hex: String,
    /// Number of signed tree heads attached to the envelope.
    pub checkpoint_count: usize,
    /// `true` if the caller chose [`TrustAnchor::self_check_only`] —
    /// the report attests *internal consistency*, not provenance.
    /// Downstream code MUST refuse to treat this as a provenance claim
    /// without further out-of-band evidence.
    pub trust_mode_self_check_only: bool,
    /// `true` if the bundle's `merkle_anchor` was present AND verified
    /// against the trust anchor's witness pubkey. Strongest claim a
    /// v2 bundle can produce — "this exact session is committed in
    /// the witness's log under a signed root."
    pub merkle_verified: bool,
    /// **v2.1 witness federation.** Number of DISTINCT trusted
    /// witnesses whose cosignature verified. Zero when federation
    /// isn't in use; otherwise reports the achieved quorum
    /// (≥ threshold when verification succeeds). See
    /// [`Self::matched_witness_pubkeys_hex`] for the actual keys
    /// (auditable diversity check).
    pub cosignatures_verified: usize,
    /// **v2.1 witness federation.** Hex-encoded public keys of the
    /// trusted witnesses whose cosignatures verified. Surfaces the
    /// actual quorum identity so downstream consumers can check
    /// witness diversity rather than just trusting the count.
    pub matched_witness_pubkeys_hex: Vec<String>,
    /// **v2.2.** `true` if the bundle carried a [`crate::PayloadBinding`]
    /// AND it verified against the trust anchor's JWKS. Confirms the
    /// payload-to-envelope binding: a tampered payload would have
    /// failed signature verification.
    pub payload_binding_verified: bool,
    /// **v2.3b HIGH-2 diagnostic.** Count of C2SP-kind cosignatures
    /// whose 64-byte signature did NOT verify against any trusted
    /// witness key over the reconstructed C2SP body bytes.
    ///
    /// **HIGH-5 (audit) clarification.** This counter conflates three
    /// causes the verifier cannot distinguish from a single cosig:
    /// (a) producer used a different `c2sp_origin` string than the
    /// verifier expects, (b) cosig is from a witness whose pubkey
    /// isn't in `trusted_witnesses`, (c) cosig is over different STH
    /// bytes (tree_size / timestamp / root) than the verifier
    /// reconstructed. Operators seeing `cosignatures_verified < threshold`
    /// AND `c2sp_cosigs_byte_mismatch > 0` should re-check:
    /// 1. `c2sp_origin` matches the producer's exactly
    /// 2. All federated witnesses are in `trusted_witnesses`
    /// 3. The bundle isn't stale (older STH than current trust set)
    ///
    /// The malformed-signature case (cosig.signature.len() != 64) is
    /// counted separately in [`Self::c2sp_cosigs_malformed_signature`]
    /// so wire-corruption vs config issues can be told apart.
    pub c2sp_cosigs_byte_mismatch: usize,
    /// **HIGH-5 (audit) fix.** Count of C2SP-kind cosignatures whose
    /// raw signature bytes were the wrong length (not 64 bytes).
    /// Pre-HIGH-5 these were silently skipped with no operator signal;
    /// now they're separately reported so a hostile or buggy producer
    /// can be distinguished from honest cosigs over wrong bytes.
    ///
    /// Non-zero values indicate either: (a) producer wire-format bug,
    /// or (b) man-in-the-middle / proxy tampering with cosig bytes.
    pub c2sp_cosigs_malformed_signature: usize,
}

/// Verify a [`Bundle`] against an explicit [`TrustAnchor`].
///
/// Performs (in order):
///
/// 1. **Schema check** — refuses envelopes from a future schema version.
/// 2. **Session-root shape** — root must be a pod-shaped SPIFFE id (no
///    `/call/` segment); otherwise the envelope's claimed "session"
///    semantic is nonsense.
/// 3. **Non-empty / empty opt-in** — empty bundles authenticate nothing,
///    so are rejected unless [`TrustAnchor::allow_empty`] was set.
/// 4. **Head edge** — `edges[0]` must be a pod-admit for `session_root`
///    with empty `parents` and (if signed) no `prev_hash`.
/// 5. **Membership** — every edge's `child` AND every `parent` must fall
///    under the session root via the same SPIFFE-URI prefix rule
///    [`crate::extract::is_under_root`] uses.
/// 6. **Trust-domain agreement** — every edge's child trust-domain must
///    match the session root's trust domain.
/// 7. **Chain verification** — `nucleus_lineage::verify_chain` validates
///    every edge's signature and `prev_hash` linkage against the *trust
///    anchor's* JWKS, NOT the JWKS embedded in the bundle (except in
///    explicit self-check-only mode).
///
/// STH signatures and Merkle inclusion proofs are not in v1; see crate
/// docs §"Scope limits."
pub fn verify_bundle(
    bundle: &Bundle,
    trust: &TrustAnchor,
) -> Result<VerificationReport, VerifyBundleError> {
    let env = &bundle.envelope;

    // 0) **CRIT-3 (#1648) DoS caps.** Reject oversized collections
    //    BEFORE any crypto work — these checks cost O(1). A hostile
    //    bundle within the verifier-service's 2 MiB body cap can pack
    //    ~10k empty edges that would otherwise burn seconds of
    //    per-edge Ed25519 verifies pinning a worker.
    if env.edges.len() > MAX_ENVELOPE_EDGES {
        return Err(VerifyBundleError::EnvelopeTooLarge {
            what: "edges",
            got: env.edges.len(),
            max: MAX_ENVELOPE_EDGES,
        });
    }
    if env.checkpoints.len() > MAX_ENVELOPE_CHECKPOINTS {
        return Err(VerifyBundleError::EnvelopeTooLarge {
            what: "checkpoints",
            got: env.checkpoints.len(),
            max: MAX_ENVELOPE_CHECKPOINTS,
        });
    }
    if let Some(anchor) = &env.merkle_anchor {
        // Per-proof audit-path bound. Hex-encoded; each tree hash is
        // 32 bytes = 64 hex chars; cap of 1024 hashes ⇒ ≤ 64 KiB hex
        // per inclusion proof. Defends against the rare but pathological
        // case of a malformed audit path designed to amplify the
        // ct-merkle parse+verify cost.
        for (i, inc) in anchor.inclusion_proofs.iter().enumerate() {
            // 64 hex chars per 32-byte hash; integer-divide.
            let hash_count = inc.audit_path_hex.len() / 64;
            if hash_count > MAX_INCLUSION_PROOF_AUDIT_PATH_LEN {
                return Err(VerifyBundleError::EnvelopeTooLarge {
                    what: "inclusion_proof.audit_path",
                    got: hash_count,
                    max: MAX_INCLUSION_PROOF_AUDIT_PATH_LEN,
                });
            }
            // Belt-and-suspenders: drop the index `i` into the error
            // would be nice but the variant doesn't carry it. Future:
            // EnvelopeTooLarge { index: Option<usize>, ... }.
            let _ = i;
        }
    }

    // 1) Schema.
    if env.meta.schema_version > ENVELOPE_SCHEMA_VERSION {
        return Err(VerifyBundleError::UnsupportedSchema {
            got: env.meta.schema_version,
            supported: ENVELOPE_SCHEMA_VERSION,
        });
    }

    // 2) Session root must be a pod (no /call/ segments). `is_call()` is
    // load-bearing here — a non-pod root would let an attacker claim a
    // tool-call SPIFFE id as the "session," which would prefix-match a
    // narrow subset of edges and mis-frame the envelope's scope.
    if env.session_root.is_call() {
        return Err(VerifyBundleError::SessionRootNotPod {
            root: env.session_root.to_string(),
        });
    }

    let trust_domain = spiffe_authority(env.session_root.as_str()).to_string();

    // 3) Empty envelopes authenticate nothing.
    if env.edges.is_empty() {
        if trust.allow_empty {
            return Ok(VerificationReport {
                edge_count: 0,
                kids: Vec::new(),
                trust_domain,
                head_edge_hash_hex: String::new(),
                checkpoint_count: env.checkpoints.len(),
                trust_mode_self_check_only: trust.is_self_check_only(),
                merkle_verified: false,
                cosignatures_verified: 0,
                matched_witness_pubkeys_hex: Vec::new(),
                payload_binding_verified: false,
                c2sp_cosigs_byte_mismatch: 0,
                c2sp_cosigs_malformed_signature: 0,
            });
        }
        return Err(VerifyBundleError::EmptyEnvelope);
    }

    // 4) Head edge must be pod-admit for session_root.
    let head = &env.edges[0];
    let head_ok = head.child == env.session_root
        && matches!(head.kind, nucleus_lineage::EdgeKind::PodAdmit)
        && head.parents.is_empty()
        && head
            .proof
            .as_ref()
            .map(|p| p.prev_hash.is_none())
            .unwrap_or(true);
    if !head_ok {
        return Err(VerifyBundleError::BadHead {
            child: head.child.to_string(),
            kind: format!("{:?}", head.kind),
        });
    }

    // 5) Membership: child AND every parent must be under the session
    // root. The parent check defends against a Merge edge whose child is
    // syntactically under root but whose parents reach into a foreign
    // pod's lineage.
    for (index, edge) in env.edges.iter().enumerate() {
        if !crate::extract::is_under_root(&edge.child, &env.session_root) {
            return Err(VerifyBundleError::OutsideRoot {
                index,
                endpoint: "child",
                id: edge.child.to_string(),
                root: env.session_root.to_string(),
            });
        }
        for parent in &edge.parents {
            if !crate::extract::is_under_root(parent, &env.session_root) {
                return Err(VerifyBundleError::OutsideRoot {
                    index,
                    endpoint: "parent",
                    id: parent.to_string(),
                    root: env.session_root.to_string(),
                });
            }
        }
    }

    // 6) Chain verification against the trust anchor's JWKS (or the
    // embedded one in explicit self-check mode).
    let verifying_jwks = match trust.mode {
        TrustMode::OutOfBand => &trust.jwks,
        TrustMode::SelfCheckOnly => &env.jwks,
    };
    verify_chain(&env.edges, verifying_jwks)
        .map_err(|(index, source)| VerifyBundleError::Chain { index, source })?;

    // 7) v2: Merkle anchor verification (binds session edges to a
    //    witness-signed root). Only attempted if the bundle carries
    //    an anchor; a bundle without one is a v1 bundle and is
    //    accepted at the chain-only level.
    //
    // Self-check mode SKIPS the anchor: self-check means "trust the
    // producer's own claim," and the Merkle anchor IS the producer's
    // claim. The producer can't validate the anchor against itself
    // without already trusting itself. Downstream verifiers with the
    // out-of-band witness pubkey are the ones who actually exercise
    // the anchor — and they must use `TrustAnchor::from_jwks(...)` +
    // `with_witness_pubkey(...)`.
    let (
        merkle_verified,
        cosignatures_verified,
        matched_witness_pubkeys_hex,
        c2sp_cosigs_byte_mismatch,
        c2sp_cosigs_malformed_signature,
    ) = if trust.is_self_check_only() {
        (false, 0, Vec::new(), 0, 0)
    } else if let Some(anchor) = &env.merkle_anchor {
        let outcome = verify_merkle_anchor(env.edges.as_slice(), anchor, trust)?;
        let count = outcome.matched_witnesses.len();
        let hex_keys = outcome.matched_witnesses.iter().map(hex::encode).collect();
        (
            true,
            count,
            hex_keys,
            outcome.c2sp_cosigs_byte_mismatch,
            outcome.c2sp_cosigs_malformed_signature,
        )
    } else {
        (false, 0, Vec::new(), 0, 0)
    };

    // 8) Report.
    let mut kids: Vec<String> = env
        .edges
        .iter()
        .filter_map(|e| e.proof.as_ref().map(|p| p.kid.clone()))
        .collect();
    kids.sort();
    kids.dedup();

    let head_edge_hash_hex = compute_head_edge_hash_hex(&env.edges);

    // 8) v2.2 payload binding (optional). Self-check mode does NOT
    //    verify the binding — same rationale as the Merkle anchor:
    //    the binding signer is the producer; checking it against
    //    itself proves nothing. Out-of-band mode verifies against
    //    the trust anchor's JWKS.
    let payload_binding_verified = match (&bundle.binding, trust.require_payload_binding) {
        (Some(binding), _) if !trust.is_self_check_only() => {
            verify_payload_binding(bundle, binding, &head_edge_hash_hex, trust)?;
            true
        }
        (None, true) => {
            return Err(VerifyBundleError::MissingPayloadBinding);
        }
        _ => false,
    };

    Ok(VerificationReport {
        edge_count: env.edges.len(),
        kids,
        trust_domain,
        head_edge_hash_hex,
        checkpoint_count: env.checkpoints.len(),
        trust_mode_self_check_only: trust.is_self_check_only(),
        merkle_verified,
        cosignatures_verified,
        matched_witness_pubkeys_hex,
        payload_binding_verified,
        c2sp_cosigs_byte_mismatch,
        c2sp_cosigs_malformed_signature,
    })
}

/// **v2.3b HIGH-2 diagnostic.** Outcome of the merkle-anchor +
/// cosignature-federation check. Carries both the matched-witness set
/// (load-bearing for the threshold gate) and the count of C2SP cosigs
/// that ran the byte-reconstruction-then-verify path but didn't match
/// any trusted key — surfaces as `c2sp_cosigs_byte_mismatch` in the
/// report so an operator who set the wrong `c2sp_origin` sees a
/// non-zero count instead of just `verified: 0`.
struct MerkleAnchorOutcome {
    matched_witnesses: Vec<[u8; 32]>,
    c2sp_cosigs_byte_mismatch: usize,
    c2sp_cosigs_malformed_signature: usize,
}

/// Verify the v2.2 payload binding: recompute payload hash + envelope
/// head hash, cross-check the binding's claimed Merkle root against
/// the envelope's anchor, look up the signing key in the trust
/// anchor's JWKS, verify the Ed25519 signature over the DSSE PAE.
fn verify_payload_binding(
    bundle: &Bundle,
    binding: &crate::PayloadBinding,
    envelope_head_hash_hex: &str,
    trust: &TrustAnchor,
) -> Result<(), VerifyBundleError> {
    use crate::binding::{payload_hash, signed_bytes};
    use ed25519_dalek::Signature;

    // 1) Recompute payload hash and check it.
    let p_hash =
        payload_hash(&bundle.payload).map_err(|e| VerifyBundleError::BadPayloadBinding {
            detail: format!("payload hash: {e}"),
        })?;
    let p_hash_hex = hex::encode(p_hash);
    if p_hash_hex != binding.payload_hash_hex {
        return Err(VerifyBundleError::BadPayloadBinding {
            detail: format!(
                "payload hash mismatch: recomputed {p_hash_hex}, binding claims {}",
                binding.payload_hash_hex
            ),
        });
    }

    // 2) Envelope head must match the head we computed during chain
    //    verification. Pin via string equality (both 64-char hex).
    if envelope_head_hash_hex != binding.envelope_head_hash_hex {
        return Err(VerifyBundleError::BadPayloadBinding {
            detail: format!(
                "envelope head mismatch: recomputed {envelope_head_hash_hex}, binding claims {}",
                binding.envelope_head_hash_hex
            ),
        });
    }

    // 3) Merkle root agreement. If the bundle has an anchor, the
    //    binding MUST cover the same root; conversely, a binding
    //    claiming a Merkle root without an anchor present is malformed.
    let envelope_root = bundle
        .envelope
        .merkle_anchor
        .as_ref()
        .map(|a| a.sth.root_hash_hex.clone());
    match (&envelope_root, &binding.merkle_root_hex) {
        (Some(env_root), Some(binding_root)) => {
            if env_root != binding_root {
                return Err(VerifyBundleError::BadPayloadBinding {
                    detail: format!(
                        "merkle root mismatch: anchor {env_root}, binding {binding_root}"
                    ),
                });
            }
        }
        (Some(_), None) => {
            return Err(VerifyBundleError::BadPayloadBinding {
                detail: "envelope has a Merkle anchor but binding omits merkle_root_hex".into(),
            });
        }
        (None, Some(_)) => {
            return Err(VerifyBundleError::BadPayloadBinding {
                detail: "binding includes merkle_root_hex but envelope has no anchor".into(),
            });
        }
        (None, None) => {} // v1/v2.1 bundle without anchor — fine
    }

    // 4) Look up the signing key in the trust anchor's JWKS (NOT the
    //    envelope's embedded one). This is the same out-of-band trust
    //    discipline as edge verification.
    let vk = trust.jwks.verifying_key(&binding.keyid).map_err(|_| {
        VerifyBundleError::BadPayloadBinding {
            detail: format!("keyid {:?} not in trust anchor JWKS", binding.keyid),
        }
    })?;

    // 5) Recompute the signed bytes and verify.
    let envelope_head_bytes: [u8; 32] = hex::decode(envelope_head_hash_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| VerifyBundleError::BadPayloadBinding {
            detail: "envelope head hash is not 32 hex bytes".into(),
        })?;
    let merkle_root_bytes: Option<[u8; 32]> = binding.merkle_root_hex.as_ref().and_then(|s| {
        hex::decode(s)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
    });
    let to_verify = signed_bytes(
        &binding.payload_type,
        &p_hash,
        &envelope_head_bytes,
        merkle_root_bytes.as_ref(),
    );

    if binding.signature.len() != 64 {
        return Err(VerifyBundleError::BadPayloadBinding {
            detail: format!(
                "signature length {} != 64 (Ed25519)",
                binding.signature.len()
            ),
        });
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&binding.signature);
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify_strict(&to_verify, &sig)
        .map_err(|_| VerifyBundleError::BadPayloadBinding {
            detail: "Ed25519 signature did not verify against trust JWKS key".into(),
        })?;
    Ok(())
}

/// Verify the Merkle anchor: STH signature + each inclusion proof,
/// plus the v2.1 witness-federation threshold check. Returns the
/// set of distinct trusted-witness pubkeys whose cosignatures
/// verified, so the caller can surface both the count and the
/// identities in the report.
fn verify_merkle_anchor(
    edges: &[LineageEdge],
    anchor: &crate::bundle::MerkleAnchor,
    trust: &TrustAnchor,
) -> Result<MerkleAnchorOutcome, VerifyBundleError> {
    // CRIT-3: cap cosignature count BEFORE any crypto work. Defends
    // the verifier from a hostile bundle ballooning the cosig list
    // to force O(cosigs × trusted) Ed25519 verifications.
    if anchor.sth.cosignatures.len() > MAX_COSIGNATURES_PER_STH {
        return Err(VerifyBundleError::CosignatureListTooLarge {
            got: anchor.sth.cosignatures.len(),
            max: MAX_COSIGNATURES_PER_STH,
        });
    }
    // Caller must supply the witness pubkey out-of-band — same trust
    // discipline as the JWKS. The bundle's *anchor* is producer-
    // controlled, so without an OOB witness key the anchor is just
    // self-claim, not provenance.
    let witness_bytes = trust
        .witness_pubkey
        .ok_or(VerifyBundleError::MissingWitnessKey)?;
    let witness = Ed25519Witness::verify_only(witness_bytes)
        .map_err(|e| VerifyBundleError::MerkleAnchorBadSignature(e.to_string()))?;
    anchor
        .sth
        .verify(&witness)
        .map_err(|e| VerifyBundleError::MerkleAnchorBadSignature(e.to_string()))?;

    if anchor.inclusion_proofs.len() != edges.len() {
        return Err(VerifyBundleError::MerkleAnchorLengthMismatch {
            got: anchor.inclusion_proofs.len(),
            expected: edges.len(),
        });
    }

    // **MED-4 (audit) fix.** Bound + uniqueness check on leaf_index
    // BEFORE per-proof crypto work. ct-merkle's `verify_inclusion`
    // would catch out-of-bounds via reconstruction failure, but the
    // failure message there is cryptic ("hash mismatch") and doesn't
    // explain that the producer's index was nonsensical. Worse: a
    // duplicate (leaf_index, audit_path) pair would verify N times
    // against the same root if the underlying leaf is identical,
    // double-counting in any downstream tally. Explicit check here.
    {
        let mut seen: std::collections::HashSet<u64> =
            std::collections::HashSet::with_capacity(anchor.inclusion_proofs.len());
        for (index, inc) in anchor.inclusion_proofs.iter().enumerate() {
            if inc.leaf_index >= anchor.sth.tree_size {
                return Err(VerifyBundleError::MerkleAnchorInclusionFailed {
                    index,
                    detail: format!(
                        "leaf_index {} is out of bounds for tree_size {}",
                        inc.leaf_index, anchor.sth.tree_size
                    ),
                });
            }
            if !seen.insert(inc.leaf_index) {
                return Err(VerifyBundleError::MerkleAnchorInclusionFailed {
                    index,
                    detail: format!(
                        "duplicate leaf_index {} (each edge must occupy a distinct leaf)",
                        inc.leaf_index
                    ),
                });
            }
        }
    }

    // Reconstruct the signed RootHash for ct-merkle verification.
    let root_bytes_vec = hex::decode(&anchor.sth.root_hash_hex).map_err(|e| {
        VerifyBundleError::MerkleAnchorBadSignature(format!("malformed root_hash_hex: {e}"))
    })?;
    if root_bytes_vec.len() != 32 {
        return Err(VerifyBundleError::MerkleAnchorBadSignature(
            "root_hash_hex must be exactly 32 bytes".into(),
        ));
    }
    let mut root_arr = [0u8; 32];
    root_arr.copy_from_slice(&root_bytes_vec);
    // `digest::Output<Sha256>` is `hybrid_array::Array<u8, U32>` in
    // digest 0.11 (the version ct-merkle 0.3 uses). The `From<[u8; 32]>`
    // impl gives us the conversion.
    let digest_output: sha2::digest::Output<Sha256> = root_arr.into();
    let root: RootHash<Sha256> = RootHash::new(digest_output, anchor.sth.tree_size);

    for (index, (edge, inc)) in edges.iter().zip(&anchor.inclusion_proofs).enumerate() {
        // The leaves the MerkleSink committed to are the edges'
        // canonical content hashes with `prev_hash = None` — pinning
        // this here matches the producer-side `MerkleSink::emit` leaf
        // encoding at crates/nucleus-lineage/src/merkle.rs.
        let leaf_hash = edge_content_hash(edge, None);
        let leaf_bytes: Vec<u8> = leaf_hash.to_vec();
        let path_bytes = hex::decode(&inc.audit_path_hex).map_err(|e| {
            VerifyBundleError::MerkleAnchorInclusionFailed {
                index,
                detail: format!("audit_path_hex decode: {e}"),
            }
        })?;
        let proof: InclusionProof<Sha256> =
            InclusionProof::try_from_bytes(path_bytes).map_err(|e| {
                VerifyBundleError::MerkleAnchorInclusionFailed {
                    index,
                    detail: format!("audit_path malformed: {e:?}"),
                }
            })?;
        root.verify_inclusion(&leaf_bytes, inc.leaf_index, &proof)
            .map_err(|e| VerifyBundleError::MerkleAnchorInclusionFailed {
                index,
                detail: format!("ct-merkle: {e:?}"),
            })?;
    }

    // v2.1.1 freshness: reject anchors whose STH is older than the
    // trust anchor allows. Off by default. Uses wall-clock; in
    // testing, callers should not rely on relative timing within
    // the threshold's resolution.
    if let Some(max_age) = trust.sth_max_age {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(u64::MAX);
        let age_ms = now_ms.saturating_sub(anchor.sth.timestamp_ms);
        let max_age_ms = max_age.as_millis() as u64;
        if age_ms > max_age_ms {
            return Err(VerifyBundleError::StaleSth { age_ms, max_age_ms });
        }
    }

    // v2.1 witness federation, extended for v2.3 dual-protocol
    // (Nucleus vs C2SP). For each cosignature, reconstruct the
    // bytes-being-signed per the cosignature's `kind` and try each
    // trusted-witness key not yet matched. Distinct-witness counting
    // (audit-3 CRIT-2 fix) is preserved.
    //
    // **v2.3b HIGH-1 fix.** Fail fast if the bundle has C2SP cosigs
    // but the trust anchor has no c2sp_origin — gives operators a
    // specific signal instead of the generic "verified: 0" they got
    // before. This must happen BEFORE the dispatch loop so a
    // misconfigured trust anchor returns MissingC2spOrigin even if
    // every cosig in the bundle is C2SP-kind.
    let c2sp_cosig_count = anchor
        .sth
        .cosignatures
        .iter()
        .filter(|c| matches!(c.kind, nucleus_lineage::CosignatureKind::C2sp))
        .count();
    if c2sp_cosig_count > 0 && trust.c2sp_origin.is_none() {
        return Err(VerifyBundleError::MissingC2spOrigin { c2sp_cosig_count });
    }

    let mut matched_witnesses: HashSet<[u8; 32]> = HashSet::new();
    // **v2.3b HIGH-2 diagnostic.** Track C2SP cosigs that ran the
    // signature check against the configured origin's body but didn't
    // match any trusted key. Non-zero = likely origin mismatch.
    let mut c2sp_cosigs_byte_mismatch: usize = 0;
    // **HIGH-5 (audit) diagnostic.** C2SP cosigs with non-64-byte
    // signatures — previously silently skipped. Surfacing means
    // operators can tell "wire corruption / proxy tampering" from
    // "config mismatch".
    let mut c2sp_cosigs_malformed_signature: usize = 0;
    if !anchor.sth.cosignatures.is_empty() {
        use ed25519_dalek::{Signature, VerifyingKey};
        let nucleus_canonical = nucleus_lineage::canonical_sth_bytes(
            anchor.sth.tree_size,
            anchor.sth.timestamp_ms,
            &root_arr,
        );
        // C2SP cosignatures sign the tlog-checkpoint body bytes. We
        // build this on demand only when a C2SP-kind cosig is found,
        // using the trust anchor's expected origin string. If a
        // C2SP cosig is present but the trust anchor doesn't specify
        // an origin, we can't reconstruct the signed bytes — the
        // cosig is silently uncountable. Operators federating with
        // C2SP witnesses must call `with_c2sp_origin(...)`.
        let c2sp_body: Option<Vec<u8>> = match &trust.c2sp_origin {
            Some(origin) => {
                nucleus_lineage::checkpoint_signed_bytes(origin, anchor.sth.tree_size, &root_arr)
                    .ok()
            }
            None => None,
        };

        for cosig in &anchor.sth.cosignatures {
            if cosig.signature.len() != 64 {
                // **HIGH-5 (audit) fix.** Count instead of silently
                // dropping. Only count C2SP cosigs (Nucleus-kind
                // wire bytes are produced by our own code paths and
                // shouldn't malform; if they do, it's a producer bug
                // not a federation diagnostic).
                if matches!(cosig.kind, nucleus_lineage::CosignatureKind::C2sp) {
                    c2sp_cosigs_malformed_signature += 1;
                }
                continue;
            }
            let mut sig_arr = [0u8; 64];
            sig_arr.copy_from_slice(&cosig.signature);
            let sig = Signature::from_bytes(&sig_arr);
            // Pick the bytes this cosig claims to cover. With the
            // HIGH-1 check above, a C2SP cosig + no origin is now
            // impossible at this point — c2sp_body is `Some` whenever
            // we reach a C2SP cosig.
            let signed_bytes: &[u8] = match cosig.kind {
                nucleus_lineage::CosignatureKind::Nucleus => &nucleus_canonical,
                nucleus_lineage::CosignatureKind::C2sp => match c2sp_body.as_deref() {
                    Some(b) => b,
                    None => continue, // defensive — should be unreachable post-HIGH-1
                },
            };
            let mut matched_this_cosig = false;
            for trusted in &trust.trusted_witnesses {
                if matched_witnesses.contains(trusted) {
                    continue;
                }
                if let Ok(vk) = VerifyingKey::from_bytes(trusted) {
                    if vk.verify_strict(signed_bytes, &sig).is_ok() {
                        matched_witnesses.insert(*trusted);
                        matched_this_cosig = true;
                        break;
                    }
                }
            }
            // HIGH-2 diagnostic: a C2SP-kind cosig that didn't match
            // any trusted key. Most common cause is `c2sp_origin`
            // string mismatch between producer and verifier; second
            // is wrong trusted-witness pubkey. Operators see the
            // count in the report.
            if !matched_this_cosig && matches!(cosig.kind, nucleus_lineage::CosignatureKind::C2sp) {
                c2sp_cosigs_byte_mismatch += 1;
            }
        }
    }

    if matched_witnesses.len() < trust.cosignature_threshold {
        return Err(VerifyBundleError::InsufficientCosignatures {
            verified: matched_witnesses.len(),
            required: trust.cosignature_threshold,
        });
    }
    Ok(MerkleAnchorOutcome {
        matched_witnesses: matched_witnesses.into_iter().collect(),
        c2sp_cosigs_byte_mismatch,
        c2sp_cosigs_malformed_signature,
    })
}

/// Walk the chain to compute the hash of the head (last) edge so it can
/// be reported / pinned. Uses the same `prev_hash` chaining the
/// signatures cover, so the head hash is a stable function of the chain
/// content.
fn compute_head_edge_hash_hex(edges: &[LineageEdge]) -> String {
    let mut prev: Option<[u8; 32]> = None;
    let mut last: [u8; 32] = [0u8; 32];
    for edge in edges {
        let h = nucleus_lineage::edge_content_hash(edge, prev.as_ref());
        last = h;
        prev = Some(h);
    }
    hex::encode(last)
}

fn spiffe_authority(s: &str) -> &str {
    s.strip_prefix("spiffe://")
        .and_then(|rest| rest.split_once('/').map(|(auth, _)| auth))
        .unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{BundleBuilder, EnvelopeMeta};
    use nucleus_lineage::{CallSpiffeId, EdgeKind, InMemorySink, Jwks, LineageEdge, LineageSink};

    fn pod() -> CallSpiffeId {
        CallSpiffeId::pod("prod.example.com", "agents", "summarizer").unwrap()
    }

    fn empty_anchor() -> TrustAnchor {
        TrustAnchor::from_jwks(Jwks { keys: vec![] })
    }

    #[test]
    fn schema_check_rejects_future_version() {
        let sink = InMemorySink::new();
        let p = pod();
        sink.emit(LineageEdge::pod_admit(p.clone())).unwrap();
        let mut bundle = BundleBuilder::new(p)
            .payload(serde_json::json!({}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .build()
            .unwrap();
        bundle.envelope.meta = EnvelopeMeta {
            schema_version: ENVELOPE_SCHEMA_VERSION + 1,
            created_at: bundle.envelope.meta.created_at,
        };
        let err = verify_bundle(&bundle, &empty_anchor()).unwrap_err();
        assert!(matches!(err, VerifyBundleError::UnsupportedSchema { .. }));
    }

    #[test]
    fn rejects_non_pod_session_root() {
        // Build a bundle, then mutate session_root to a non-pod id.
        let sink = InMemorySink::new();
        let p = pod();
        sink.emit(LineageEdge::pod_admit(p.clone())).unwrap();
        let mut bundle = BundleBuilder::new(p.clone())
            .payload(serde_json::json!({}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .build()
            .unwrap();
        bundle.envelope.session_root = p.derive_tool("Read", None).unwrap();
        let err = verify_bundle(&bundle, &empty_anchor()).unwrap_err();
        assert!(matches!(err, VerifyBundleError::SessionRootNotPod { .. }));
    }

    #[test]
    fn rejects_empty_envelope_by_default() {
        let sink = InMemorySink::new();
        let bundle = BundleBuilder::new(pod())
            .payload(serde_json::json!({}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .allow_empty()
            .build()
            .unwrap();
        let err = verify_bundle(&bundle, &empty_anchor()).unwrap_err();
        assert!(matches!(err, VerifyBundleError::EmptyEnvelope));
    }

    #[test]
    fn accepts_empty_envelope_with_allow_empty_opt_in() {
        let sink = InMemorySink::new();
        let bundle = BundleBuilder::new(pod())
            .payload(serde_json::json!({}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .allow_empty()
            .build()
            .unwrap();
        let report = verify_bundle(&bundle, &empty_anchor().allow_empty()).unwrap();
        assert_eq!(report.edge_count, 0);
        assert!(report.head_edge_hash_hex.is_empty());
    }

    #[test]
    fn rejects_head_edge_not_pod_admit() {
        let sink = InMemorySink::new();
        let p = pod();
        // Skip pod-admit; first edge is a tool call.
        sink.emit(LineageEdge::from_parent(
            p.derive_tool("Read", Some(b"x")).unwrap(),
            p.clone(),
            EdgeKind::ToolCall {
                tool: "Read".to_string(),
            },
        ))
        .unwrap();
        let bundle = BundleBuilder::new(p)
            .payload(serde_json::json!({}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .build()
            .unwrap();
        let err = verify_bundle(&bundle, &empty_anchor()).unwrap_err();
        assert!(matches!(err, VerifyBundleError::BadHead { .. }));
    }

    #[test]
    fn rejects_foreign_parent_via_merge() {
        // Construct a Merge edge whose child is under our root but whose
        // parents include a foreign-pod id. Tighter membership check must
        // catch this.
        let sink = InMemorySink::new();
        let mine = pod();
        let theirs = CallSpiffeId::pod("attacker.example.com", "evil", "evil-sa").unwrap();
        sink.emit(LineageEdge::pod_admit(mine.clone())).unwrap();
        let local_tool = mine.derive_tool("Read", Some(b"a")).unwrap();
        sink.emit(LineageEdge::from_parent(
            local_tool.clone(),
            mine.clone(),
            EdgeKind::ToolCall {
                tool: "Read".to_string(),
            },
        ))
        .unwrap();
        let attacker_tool = theirs.derive_tool("Read", Some(b"b")).unwrap();
        let merged = mine.derive_artifact(b"merged").unwrap();
        // Hand-craft the merge edge with a foreign parent.
        let bad_merge = LineageEdge {
            child: merged,
            parents: vec![local_tool, attacker_tool],
            kind: EdgeKind::Merge,
            content_hash_hex: None,
            ts: chrono::Utc::now(),
            attrs: Default::default(),
            proof: None,
            verifier_attestation: None,
        };
        sink.emit(bad_merge).unwrap();

        let bundle = BundleBuilder::new(mine)
            .payload(serde_json::json!({}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .build()
            .unwrap();
        let err = verify_bundle(&bundle, &empty_anchor()).unwrap_err();
        assert!(
            matches!(
                err,
                VerifyBundleError::OutsideRoot {
                    endpoint: "parent",
                    ..
                }
            ),
            "expected parent OutsideRoot, got {err:?}"
        );
    }

    #[test]
    fn self_check_only_flag_surfaces_in_report() {
        // Bundle with no signed edges, verified in self-check mode with
        // allow_empty — confirms the mode flag flows through to the report.
        let sink = InMemorySink::new();
        let bundle = BundleBuilder::new(pod())
            .payload(serde_json::json!({}))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .allow_empty()
            .build()
            .unwrap();
        let report = verify_bundle(&bundle, &TrustAnchor::self_check_only().allow_empty()).unwrap();
        assert!(report.trust_mode_self_check_only);
    }
}

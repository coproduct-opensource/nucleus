// SPDX-License-Identifier: MIT
//
//! `nucleus-federation` — keyless credentials, in both directions.
//!
//! A nucleus pod should be able to call an outside service with **no static
//! credential anywhere**: not in the guest, not in the pod spec, not in the
//! node's environment. And an outside agent runtime holding a token from its
//! own issuer should be able to reach nucleus the same way. This crate is the
//! vendor-neutral substrate for both. ADR 0010 ("a credential minted per
//! exchange, never stored") is the decision it implements; the wire contract a
//! provider implements is `docs/federated-upstream-profile.md`.
//!
//! # Outbound: an assertion the host signs, exchanged for a short token
//!
//! 1. [`assertion`] builds the claims for one exchange from an
//!    [`AssertionSubject`] — the pod identity the **host** observed. That type
//!    has no `Deserialize`, so nothing a guest sends can become a subject; the
//!    guest cannot choose whose name the assertion is in.
//! 2. An [`AssertionSigner`] signs it. The algorithm is ES256 and nothing
//!    else: the trait's only signing method returns a fixed 64-byte P-256
//!    `r||s`, so a signer for another algorithm cannot be written against it.
//!    One issuer, one pinned algorithm — the property
//!    `nucleus-oidc-provider/THREAT_MODEL.md` T04 relies on, kept here by a
//!    type rather than by review. The signer is a trait so a KMS-held key can
//!    replace the file-backed [`EcdsaP256Signer`] (ADR 0009).
//! 3. [`token_client::exchange`] presents it to the provider's token endpoint
//!    as an RFC 8693 `subject_token` or an RFC 7523 `assertion`, form- or
//!    JSON-encoded, and returns an [`ExchangedToken`] whose value cannot be
//!    printed and is wiped on drop. Its errors carry a status code at most —
//!    never the endpoint's body, which can echo the scopes asked for (ADR 0004
//!    forbids revealing those).
//!
//! Every assertion also states the node's platform tier and names the
//! evidence epoch it rests on ([`attestation`], ADR 0012 A3), so a relying
//! party can refuse a node that is not freshly `attested`.
//!
//! **Deciding whether to mint is not this crate's job.** The node mints only
//! after the policy decision point approved the request, only for an upstream
//! the pod was admitted to, and only with that upstream's audience. This crate
//! makes the assertion honest about who asked; the node makes it rare.
//!
//! # The issuer key: published, then rotated
//!
//! [`keyring`] owns the key's files and the only way they change: stage a next
//! key (published, never signing), promote it once providers have had time to
//! see it, retire the old one once nothing it signed can still be accepted.
//! The node's signer ([`keyring::KeyDirSigner`]) follows a promote without a
//! restart; the operator's `nucleus federation` CLI publishes the discovery
//! document and JWKS from the same files. Operator steps are in
//! `docs/federation-issuer-runbook.md`.
//!
//! # Inbound: a token from an issuer nucleus does not run
//!
//! [`inbound::ExternalIssuerValidator`] checks one outside issuer's tokens
//! against an operator binding: exact `iss` and `aud`, an algorithm set that
//! cannot contain `none` or an HMAC algorithm (the enum has no such variant),
//! a key whose type and curve agree with the header's algorithm (RFC 8725
//! §3.1), a lifetime cap, exact-match required claims, and a replay cache
//! keyed on the hash of the token's signed content — not the whole token,
//! whose ECDSA signature is malleable — because the issuers this serves often
//! send no `jti`. What the node does with a validated caller — the SVID and the
//! delegation certificate it mints — lives in the node.
//!
//! # Vendor neutrality
//!
//! No vendor name, host, token format or model identifier appears in this
//! crate. Every endpoint, audience and extra parameter is operator
//! configuration. `ci/no-vendor-strings.sh` and `ci/alg-pin-check.sh` both
//! scan this crate.
//!
//! It is also declared panic-free outside tests. A token validator or an
//! exchange client that can panic hands a malformed input a way to take down
//! the node that called it, so the whole `tot` family is denied here rather
//! than audited.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic,
        clippy::unreachable,
        clippy::todo
    )
)]

pub mod assertion;
pub mod attestation;
pub mod custody;
pub mod inbound;
pub mod keyring;
pub mod token_client;

mod net;

pub use assertion::{
    AssertionClaims, AssertionSigner, AssertionSubject, ClaimsError, CompactJwt, CurrentSigner,
    DEFAULT_TTL, EcdsaP256Signer, Es256Signature, MAX_TTL, OPERATOR_MAX_TTL, OperatorClaims,
    OperatorSubject, PublicJwk, SIGNING_ALG, SignError, SignableClaims, is_valid_issuer, jwks,
    mint,
};
pub use attestation::{
    ATTESTATION_CLAIMS, ClaimRefusal, ClaimedTier, EPOCH_CLAIM, EVIDENCE_CLAIM, EpochRef,
    EvidenceRef, HeldEvidence, NO_EVIDENCE, NodeAttestation, RELYING_PARTY_CONDITION, Reappraisal,
    RelyingPartyCheck, SelfAppraisal, TIER_CLAIM, TIME_CLAIM, VerifiedAttestation,
    read_attestation_claims, relying_party_condition_for, verify_attestation_claims,
};
pub use custody::{
    CustodyKind, FILE_CUSTODY_WAIVER_FLAG, FileCustody, KeyCustody, TpmCustody, TpmEndpoint,
};
pub use inbound::{
    ConfigError, ExternalIssuerConfig, ExternalIssuerValidator, InboundError, JwksSource,
    RefusalReason, ValidatedCaller, VerifyAlg,
};
pub use net::default_client;
pub use token_client::{Encoding, ExchangeError, ExchangedToken, Grant, TokenRequest, exchange};

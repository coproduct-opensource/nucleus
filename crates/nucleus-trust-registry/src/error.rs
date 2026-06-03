// SPDX-License-Identifier: MIT
//
//! Errors for the trust-registry enrollment + transparency-log paths.
//!
//! Every variant is a *fail-closed* outcome: a failure to verify, parse,
//! or prove inclusion ALWAYS means "this binding is NOT trusted", never
//! "trust it anyway". Negative tests assert on these variants by shape.

use thiserror::Error;

/// A failure during registry parse, proof-of-control verification,
/// compilation, or transparency-log handling.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// `metadata.toml` was missing, unreadable, or not valid TOML.
    #[error("metadata: {0}")]
    Metadata(String),

    /// A required SPIFFE-federation parameter (`trust_domain`,
    /// `bundle_endpoint_url`, or `profile`) was missing. Per the SPIFFE
    /// Federation spec these "cannot be securely inferred", so a missing
    /// one is a hard reject — never defaulted.
    #[error("missing federation parameter: {0}")]
    MissingFederationParam(&'static str),

    /// The endpoint host was merely derived from the trust domain (the
    /// host equals the trust domain, or otherwise looks inferred). SPIFFE
    /// forbids inferred bindings; the operator MUST pin an explicit,
    /// out-of-band endpoint.
    #[error("inferred binding rejected: endpoint host {host:?} is derived from trust domain {trust_domain:?}")]
    InferredBinding { host: String, trust_domain: String },

    /// The `profile` value was not a supported SPIFFE Federation profile
    /// (only `https_web` is implemented).
    #[error("unsupported federation profile: {0:?} (only \"https_web\" is supported)")]
    UnsupportedProfile(String),

    /// `bundle.json` was missing, unreadable, or not a valid SPIFFE
    /// bundle / JWK Set.
    #[error("bundle: {0}")]
    Bundle(String),

    /// The OIDC proof-of-control token failed verification: forged
    /// signature, wrong issuer, expired, wrong owner_id, or wrong owner
    /// org. The string carries the specific reason for diagnostics.
    #[error("OIDC proof-of-control rejected: {0}")]
    ProofOfControl(String),

    /// A required proof-of-control token was not supplied at all.
    #[error("OIDC proof-of-control is required but was not supplied")]
    MissingProof,

    /// The PR diff touched files outside the single claimed domain
    /// directory (diff-smuggling).
    #[error(
        "diff smuggling: change touches paths outside registry/domains/{claimed:?}: {offending:?}"
    )]
    DiffSmuggling {
        claimed: String,
        offending: Vec<String>,
    },

    /// A PR changes an existing domain's bundle but the new proof's
    /// numeric owner_id differs from the recorded incumbent owner_id
    /// (silent-rotation / takeover attempt).
    #[error("silent rotation rejected for {trust_domain:?}: incumbent owner_id {incumbent} != proof owner_id {proof}")]
    SilentRotation {
        trust_domain: String,
        incumbent: u64,
        proof: u64,
    },

    /// The transparency-log inclusion check failed: the binding's leaf is
    /// not present in the cosigned STH, or the inclusion proof does not
    /// verify against the STH root (e.g. a tampered bundle changed the
    /// leaf hash).
    #[error("transparency-log inclusion rejected: {0}")]
    NotInLog(String),

    /// The witness cosignature over the STH did not verify.
    #[error("witness cosignature rejected: {0}")]
    Cosignature(String),

    /// An I/O error walking the registry directory.
    #[error("registry io: {0}")]
    Io(String),

    /// A structural problem in the registry layout (e.g. a domain dir
    /// with no metadata, or a `trust_domain` that disagrees with its
    /// directory name).
    #[error("registry layout: {0}")]
    Layout(String),
}

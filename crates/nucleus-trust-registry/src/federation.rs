// SPDX-License-Identifier: MIT
//
//! Wiring the compiled [`FederationSet`] into the inbound validator's
//! [`FederationStore`] (`nucleus-oidc-core`).
//!
//! The registry RECORDS + DISTRIBUTES bindings; the [`FederationStore`]
//! is where a relying party CONSUMES them to validate inbound JWT-SVIDs.
//! This is the seam between "who is enrolled" (this crate) and "accept
//! this foreign token" (`nucleus-oidc-core::spiffe_federation`).
//!
//! # The trust rule is enforced HERE, not only described
//!
//! A binding reaches the store ONLY if the witness-cosigned transparency
//! log proves it (SECURITY_TODO #13). For each compiled binding we:
//! 1. re-derive its leaf and verify inclusion + cosignature against the
//!    [`SealedLog`] pinned in the [`LogAttestation`]
//!    ([`verify_binding_inclusion`]) — for EVERY binding, before touching
//!    the store, so a set with one bad binding federates nothing; then
//! 2. pin the trust domain with its out-of-band endpoint + profile via
//!    [`FederationStore::federate_with`], and
//! 3. ingest the bundle's keys via [`FederationStore::ingest_bundle`].
//!
//! There is deliberately no unverified entry point: whoever can write the
//! on-disk registry tree must ALSO get the binding into the cosigned log,
//! or the keys are never served for identity verification. A deployment
//! without a sealed log cannot build a store at all.
//!
//! The store's own anti-rollback rule still applies on ingest.

use nucleus_oidc_core::spiffe_federation::{FederatesWith, FederationStore};

use crate::compile::FederationSet;
use crate::error::RegistryError;
use crate::tlog::{SealedLog, verify_binding_inclusion};

/// What a consumer must hold to trust a [`FederationSet`]: the sealed,
/// witness-cosigned log and the OUT-OF-BAND pinned cosigner key.
///
/// The key is pinned by the consumer, never read from the artifact: the
/// artifact also embeds it, and [`verify_binding_inclusion`] cross-checks
/// the two, but trusting the embedded copy alone would let a forger ship
/// their own cosignature.
#[derive(Debug, Clone, Copy)]
pub struct LogAttestation<'a> {
    /// The cosigned STH + per-leaf inclusion proofs.
    pub sealed: &'a SealedLog,
    /// The witness's Ed25519 verifying key, distributed out of band.
    pub cosigner_pubkey: &'a [u8; 32],
}

/// Build a [`FederationStore`] for `expected_audience` from a compiled
/// [`FederationSet`], admitting only bindings the cosigned log proves.
pub fn build_federation_store(
    set: &FederationSet,
    expected_audience: impl Into<String>,
    attestation: LogAttestation<'_>,
) -> Result<FederationStore, RegistryError> {
    let store = FederationStore::new(expected_audience);
    apply_to_store(set, &store, attestation)?;
    Ok(store)
}

/// Apply a compiled [`FederationSet`] to an existing [`FederationStore`]:
/// verify every binding against the cosigned log, then pin + ingest each.
///
/// Atomic with respect to verification: if ANY binding fails the log
/// check, the store is left untouched and the first failure is returned.
/// (Ingest failures after that point are the store's own anti-rollback
/// rule and are reported as [`RegistryError::Bundle`].)
pub fn apply_to_store(
    set: &FederationSet,
    store: &FederationStore,
    attestation: LogAttestation<'_>,
) -> Result<(), RegistryError> {
    // Phase 1: prove every binding is in the cosigned log. No store writes.
    for (td, binding) in &set.bindings {
        verify_binding_inclusion(
            attestation.sealed,
            td,
            &binding.bundle_bytes,
            binding.metadata.owner_id,
            attestation.cosigner_pubkey,
        )?;
    }

    // Phase 2: every binding is proven; pin + ingest.
    for (td, binding) in &set.bindings {
        store.federate_with(FederatesWith {
            trust_domain: td.clone(),
            bundle_endpoint_url: binding.metadata.bundle_endpoint_url.clone(),
            profile: binding.metadata.typed_profile(),
        });
        store
            .ingest_bundle(td, &binding.bundle)
            .map_err(|e| RegistryError::Bundle(format!("ingest bundle for {td:?}: {e}")))?;
    }
    Ok(())
}

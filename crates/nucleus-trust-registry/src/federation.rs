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
//! For each compiled binding we:
//! 1. pin the trust domain with its out-of-band endpoint + profile via
//!    [`FederationStore::federate_with`], then
//! 2. ingest the bundle's keys via [`FederationStore::ingest_bundle`].
//!
//! The store's own anti-rollback rule still applies on ingest.

use nucleus_oidc_core::spiffe_federation::{FederatesWith, FederationStore};

use crate::compile::FederationSet;
use crate::error::RegistryError;

/// Build a [`FederationStore`] for `expected_audience` from a compiled
/// [`FederationSet`], pinning every binding + ingesting its keys.
pub fn build_federation_store(
    set: &FederationSet,
    expected_audience: impl Into<String>,
) -> Result<FederationStore, RegistryError> {
    let store = FederationStore::new(expected_audience);
    apply_to_store(set, &store)?;
    Ok(store)
}

/// Apply a compiled [`FederationSet`] to an existing [`FederationStore`]
/// (pins + ingests each binding).
pub fn apply_to_store(set: &FederationSet, store: &FederationStore) -> Result<(), RegistryError> {
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

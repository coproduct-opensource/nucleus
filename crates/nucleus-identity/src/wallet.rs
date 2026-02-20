//! Wallet mapping — bridges SPIFFE identity to payment addresses.
//!
//! This module defines a vendor-agnostic trait for mapping SPIFFE SVIDs
//! to payment wallet addresses. The actual payment protocol (x402, etc.)
//! is implemented by the orchestrator; nucleus only provides the identity
//! mapping interface.
//!
//! # Architecture
//!
//! ```text
//! SPIFFE SVID                         Payment Address
//! ┌──────────────────────────┐       ┌────────────────────────────┐
//! │ spiffe://domain/ns/x/sa/y│ ────► │ eip155:8453:0xABC...       │
//! │ (X.509, auto-rotated)    │       │ (CAIP-10 or opaque string) │
//! └──────────────────────────┘       └────────────────────────────┘
//! ```

use std::collections::HashMap;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

use crate::Identity;

/// A payment wallet address associated with a SPIFFE identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletAddress {
    /// The wallet address (e.g., "0xABC..." or CAIP-10 format).
    pub address: String,
    /// Optional chain identifier (e.g., "eip155:8453" for Base).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,
}

impl WalletAddress {
    /// Create a new wallet address.
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            chain_id: None,
        }
    }

    /// Set the chain identifier.
    pub fn with_chain(mut self, chain_id: impl Into<String>) -> Self {
        self.chain_id = Some(chain_id.into());
        self
    }

    /// Format as CAIP-10 if chain_id is present, otherwise just the address.
    pub fn to_caip10(&self) -> String {
        match &self.chain_id {
            Some(chain) => format!("{chain}:{}", self.address),
            None => self.address.clone(),
        }
    }
}

/// Trait for mapping SPIFFE identities to payment wallet addresses.
///
/// Implementors can use static lookup tables, SVID certificate metadata,
/// or external registries to resolve wallet addresses.
pub trait WalletMapping: Send + Sync {
    /// Look up the payment wallet for a SPIFFE identity.
    ///
    /// Returns `None` if no wallet is registered for this identity.
    fn wallet_for_identity(&self, identity: &Identity) -> Option<WalletAddress>;

    /// Register a wallet address for a SPIFFE identity.
    fn register_wallet(&self, identity: &Identity, wallet: WalletAddress);
}

/// In-memory lookup table mapping SPIFFE URIs to wallet addresses.
///
/// Thread-safe via `RwLock`. Suitable for single-node deployments.
/// For distributed deployments, use a persistent store implementation.
pub struct InMemoryWalletRegistry {
    wallets: RwLock<HashMap<String, WalletAddress>>,
}

impl InMemoryWalletRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            wallets: RwLock::new(HashMap::new()),
        }
    }

    /// Create a registry pre-populated from environment variables.
    ///
    /// Reads `NUCLEUS_WALLET_MAP` as a comma-separated list of `spiffe_uri=address` pairs.
    /// Example: `spiffe://domain/ns/x/sa/y=0xABC,spiffe://domain/ns/x/sa/z=0xDEF`
    pub fn from_env() -> Self {
        let registry = Self::new();
        if let Ok(map_str) = std::env::var("NUCLEUS_WALLET_MAP") {
            for pair in map_str.split(',') {
                let parts: Vec<&str> = pair.splitn(2, '=').collect();
                if parts.len() == 2 {
                    if let Ok(identity) = Identity::from_spiffe_uri(parts[0].trim()) {
                        registry.register_wallet(&identity, WalletAddress::new(parts[1].trim()));
                    }
                }
            }
        }
        registry
    }

    /// Number of registered wallets.
    pub fn len(&self) -> usize {
        self.wallets.read().unwrap().len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for InMemoryWalletRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl WalletMapping for InMemoryWalletRegistry {
    fn wallet_for_identity(&self, identity: &Identity) -> Option<WalletAddress> {
        let uri = identity.to_spiffe_uri();
        self.wallets.read().unwrap().get(&uri).cloned()
    }

    fn register_wallet(&self, identity: &Identity, wallet: WalletAddress) {
        let uri = identity.to_spiffe_uri();
        self.wallets.write().unwrap().insert(uri, wallet);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wallet_address_caip10_with_chain() {
        let w = WalletAddress::new("0xABC123").with_chain("eip155:8453");
        assert_eq!(w.to_caip10(), "eip155:8453:0xABC123");
    }

    #[test]
    fn wallet_address_caip10_without_chain() {
        let w = WalletAddress::new("0xABC123");
        assert_eq!(w.to_caip10(), "0xABC123");
    }

    #[test]
    fn in_memory_registry_crud() {
        let registry = InMemoryWalletRegistry::new();
        let id = Identity::new("nucleus.local", "default", "agent-1");
        let wallet = WalletAddress::new("0xDEAD").with_chain("eip155:8453");

        assert!(registry.wallet_for_identity(&id).is_none());
        assert!(registry.is_empty());

        registry.register_wallet(&id, wallet.clone());
        assert_eq!(registry.len(), 1);

        let found = registry.wallet_for_identity(&id).unwrap();
        assert_eq!(found.address, "0xDEAD");
        assert_eq!(found.chain_id, Some("eip155:8453".into()));
    }

    #[test]
    fn registry_overwrites_on_re_register() {
        let registry = InMemoryWalletRegistry::new();
        let id = Identity::new("nucleus.local", "default", "agent-1");

        registry.register_wallet(&id, WalletAddress::new("0xOLD"));
        registry.register_wallet(&id, WalletAddress::new("0xNEW"));

        let found = registry.wallet_for_identity(&id).unwrap();
        assert_eq!(found.address, "0xNEW");
    }

    #[test]
    fn wallet_address_json_roundtrip() {
        let w = WalletAddress::new("0xABC").with_chain("eip155:84532");
        let json = serde_json::to_string(&w).unwrap();
        let parsed: WalletAddress = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, w);
    }

    #[test]
    fn wallet_address_json_no_chain() {
        let w = WalletAddress::new("0xABC");
        let json = serde_json::to_string(&w).unwrap();
        assert!(!json.contains("chain_id")); // skip_serializing_if
        let parsed: WalletAddress = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, w);
    }
}

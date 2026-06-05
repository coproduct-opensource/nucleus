//! ERC-8004 anchoring — bind each verified-clearing receipt to the on-chain
//! **Validation Registry** so the IFC-in-bounds decision is independently
//! checkable from chain reads. Identity + Reputation registries are canonical on
//! Base Sepolia; the Validation Registry is our self-deploy (see
//! `contracts/src/ValidationRegistry.sol`).
//!
//! Flow per receipt: `requestHash = keccak256(receipt JSON)` →
//! `validationRequest(validator, agentId, requestURI, requestHash)` → (as the
//! validator) `validationResponse(requestHash, 100, …, "clearing/in-bounds")`.
//! These are **gasful** writes (need Base Sepolia ETH) — unlike gasless x402.
//!
//! Honesty: `response = 100` means "the gate allowed this flow and a receipt was
//! issued" — a model-level, declared-input in-bounds attestation, not an
//! end-to-end exfiltration proof. The on-chain record points at the off-chain
//! receipt; a verifier re-derives the hash and re-checks the receipt.

use alloy::network::EthereumWallet;
use alloy::primitives::{keccak256, Address, B256, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::sol;
use alloy_signer_local::PrivateKeySigner;
use anyhow::{anyhow, Context};
use async_trait::async_trait;

/// Canonical ERC-8004 Identity Registry on Base Sepolia (84532).
pub const IDENTITY_REGISTRY_BASE_SEPOLIA: Address =
    alloy::primitives::address!("8004A818BFB912233c491871b3d84c89A494BD9e");
/// Canonical ERC-8004 Reputation Registry on Base Sepolia (84532).
pub const REPUTATION_REGISTRY_BASE_SEPOLIA: Address =
    alloy::primitives::address!("8004B663056A597Dffe9eCcC1965A193B7388713");

sol! {
    #[sol(rpc)]
    interface IIdentityRegistry {
        function register(string agentURI) external returns (uint256);
        event Registered(uint256 indexed agentId, string agentURI, address indexed owner);
    }

    #[sol(rpc)]
    interface IValidationRegistry {
        function validationRequest(address validatorAddress, uint256 agentId, string requestURI, bytes32 requestHash) external;
        function validationResponse(bytes32 requestHash, uint8 response, string responseURI, bytes32 responseHash, string tag) external;
        function getValidationStatus(bytes32 requestHash) external view returns (uint8);
    }
}

/// The on-chain anchor result for one receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorOutcome {
    /// `keccak256(receipt)` committed on-chain (hex `0x…`).
    pub request_hash: String,
    /// The `validationResponse` tx hash (hex `0x…`).
    pub validation_tx: String,
    /// The 0–100 validation score posted (100 = in-bounds).
    pub response: u8,
}

/// Anchors a verified-clearing receipt on-chain. Abstracted so tests can use a
/// fake and the binary can swap implementations.
#[async_trait]
pub trait Anchorer: Send + Sync {
    /// Register an agent identity (once), returning its ERC-8004 `agentId`.
    async fn register_agent(&self, agent_uri: &str) -> anyhow::Result<u64>;

    /// Anchor a receipt: commit `keccak256(receipt_json)` to the Validation
    /// Registry and post the in-bounds verdict.
    async fn anchor(
        &self,
        agent_id: u64,
        request_uri: &str,
        receipt_json: &str,
        in_bounds: bool,
    ) -> anyhow::Result<AnchorOutcome>;
}

/// Compute the ERC-8004 `requestHash` for a receipt payload: `keccak256(bytes)`.
pub fn request_hash(receipt_json: &str) -> B256 {
    keccak256(receipt_json.as_bytes())
}

/// Real ERC-8004 anchorer over Base Sepolia (gasful writes via a wallet provider).
pub struct AlloyAnchor {
    provider: DynProvider,
    identity: Address,
    validation: Address,
    /// The validator address that posts `validationResponse` (= our signer).
    validator: Address,
}

impl AlloyAnchor {
    /// Build from the (same) keystore signer used for x402. The signer's address
    /// is the validator + tx sender; writes need Base Sepolia ETH for gas.
    pub fn new(
        signer: PrivateKeySigner,
        rpc_url: &str,
        identity: Address,
        validation: Address,
    ) -> anyhow::Result<Self> {
        let validator = signer.address();
        let wallet = EthereumWallet::from(signer);
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .connect_http(rpc_url.parse()?)
            .erased();
        Ok(Self {
            provider,
            identity,
            validation,
            validator,
        })
    }
}

#[async_trait]
impl Anchorer for AlloyAnchor {
    async fn register_agent(&self, agent_uri: &str) -> anyhow::Result<u64> {
        let registry = IIdentityRegistry::new(self.identity, &self.provider);
        let receipt = registry
            .register(agent_uri.to_string())
            .send()
            .await
            .context("sending Identity.register")?
            .get_receipt()
            .await
            .context("awaiting Identity.register receipt")?;
        // The agentId is emitted in the Registered event.
        for log in receipt.inner.logs() {
            if let Ok(decoded) = log.log_decode::<IIdentityRegistry::Registered>() {
                return Ok(u64::try_from(decoded.inner.agentId).unwrap_or(u64::MAX));
            }
        }
        Err(anyhow!("Identity.register did not emit a Registered event"))
    }

    async fn anchor(
        &self,
        agent_id: u64,
        request_uri: &str,
        receipt_json: &str,
        in_bounds: bool,
    ) -> anyhow::Result<AnchorOutcome> {
        let registry = IValidationRegistry::new(self.validation, &self.provider);
        let rhash = request_hash(receipt_json);
        let agent = U256::from(agent_id);

        // 1) Commit the request (requestURI points at the off-chain receipt).
        registry
            .validationRequest(self.validator, agent, request_uri.to_string(), rhash)
            .send()
            .await
            .context("sending validationRequest")?
            .get_receipt()
            .await
            .context("awaiting validationRequest receipt")?;

        // 2) Post the verdict (we are the named validator). 100 = in-bounds.
        let response: u8 = if in_bounds { 100 } else { 0 };
        let resp_receipt = registry
            .validationResponse(
                rhash,
                response,
                request_uri.to_string(),
                rhash,
                "clearing/in-bounds".to_string(),
            )
            .send()
            .await
            .context("sending validationResponse")?
            .get_receipt()
            .await
            .context("awaiting validationResponse receipt")?;

        Ok(AnchorOutcome {
            request_hash: format!("{rhash:#x}"),
            validation_tx: format!("{:#x}", resp_receipt.transaction_hash),
            response,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_hash_is_deterministic_keccak() {
        let a = request_hash(r#"{"resource":"/v1/x","tx":"0xabc"}"#);
        let b = request_hash(r#"{"resource":"/v1/x","tx":"0xabc"}"#);
        assert_eq!(a, b);
        // keccak256 of empty differs from non-empty.
        assert_ne!(request_hash(""), a);
        // 32-byte digest.
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn canonical_registry_addresses_parse() {
        // Compile-time `address!` already validates; assert they're non-zero.
        assert_ne!(IDENTITY_REGISTRY_BASE_SEPOLIA, Address::ZERO);
        assert_ne!(REPUTATION_REGISTRY_BASE_SEPOLIA, Address::ZERO);
    }
}

//! [`X402Facilitator`] — a real Base Sepolia (testnet) implementation of
//! [`nucleus_marketplace_dashboard::Facilitator`].
//!
//! `settle()` makes a REAL x402 payment (via `x402-reqwest`) against a local x402
//! seller route; the facilitator settles EIP-3009 `transferWithAuthorization`
//! on-chain and returns the settlement in the `X-PAYMENT-RESPONSE` header, from
//! which we extract the **on-chain tx hash** → `SettlementOutcome::Confirmed`
//! tagged `BalanceSource::OnChainTestnet`. `balance_of()` reads the real USDC
//! `balanceOf` via alloy. A timeout or any failure resolves to
//! `SettlementOutcome::Timeout` — terminal, so the orchestrator never re-settles
//! (the real x402 failure mode, per the design research).
//!
//! Honesty: real funds move (small). One shared key funds every agent, so signing
//! is serialised (`Semaphore(1)`) and balances reflect the single funding wallet.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::primitives::{Address, U256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::sol;
use alloy_signer_local::PrivateKeySigner;
use async_trait::async_trait;
use reqwest_middleware::ClientWithMiddleware;
use serde::Deserialize;
use tokio::sync::{Mutex, Semaphore};
use x402_chain_eip155::V1Eip155ExactClient;
use x402_reqwest::{ReqwestWithPayments, ReqwestWithPaymentsBuild, X402Client};

use nucleus_marketplace_dashboard::{
    AgentId, BalanceSource, Facilitator, MicroUsd, SettleRequest, SettlementOutcome,
};

sol! {
    #[sol(rpc)]
    interface IERC20 {
        function balanceOf(address account) external view returns (uint256);
    }
}

/// The settlement payload the facilitator returns in `X-PAYMENT-RESPONSE`
/// (base64(JSON)). We define our own decode struct to avoid coupling to the SDK.
#[derive(Debug, Deserialize)]
struct SettleResponse {
    #[serde(default)]
    success: bool,
    /// The on-chain tx hash (x402 calls this `transaction`).
    #[serde(default, alias = "transactionHash", alias = "txHash")]
    transaction: Option<String>,
}

/// Decode an `X-PAYMENT-RESPONSE` header into a confirmed on-chain tx hash, if
/// the settlement succeeded. `None` ⇒ unresolved (treated as a timeout).
pub fn decode_settlement(header_value: &str) -> Option<String> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(header_value.trim())
        .ok()?;
    let resp: SettleResponse = serde_json::from_slice(&bytes).ok()?;
    if resp.success {
        resp.transaction.filter(|t| !t.is_empty())
    } else {
        None
    }
}

/// Real x402 facilitator over Base Sepolia testnet.
pub struct X402Facilitator {
    http: ClientWithMiddleware,
    provider: DynProvider,
    usdc: Address,
    payer: Address,
    /// `seller_base/paid` is the x402-protected route every allowed call pays.
    seller_base: String,
    settle_timeout: Duration,
    min_interval: Duration,
    /// Serialises signing so one key never signs two authorizations at once.
    gate: Semaphore,
    last_settle: Mutex<Option<Instant>>,
    confirmed: AtomicU64,
}

impl X402Facilitator {
    /// Build the facilitator. `signer` funds every payment; `payer` is its
    /// address (derived from the key). `seller_base` is the URL of the local x402
    /// seller (e.g. `http://127.0.0.1:4040`).
    pub fn new(
        signer: PrivateKeySigner,
        rpc_url: &str,
        seller_base: impl Into<String>,
        usdc: Address,
        payer: Address,
    ) -> anyhow::Result<Self> {
        let x402 = X402Client::new().register(V1Eip155ExactClient::new(Arc::new(signer)));
        let http = reqwest::Client::new().with_payments(x402).build();
        let provider = ProviderBuilder::new()
            .connect_http(rpc_url.parse()?)
            .erased();
        Ok(Self {
            http,
            provider,
            usdc,
            payer,
            seller_base: seller_base.into(),
            settle_timeout: Duration::from_secs(30),
            min_interval: Duration::from_secs(3),
            gate: Semaphore::new(1),
            last_settle: Mutex::new(None),
            confirmed: AtomicU64::new(0),
        })
    }

    /// Count of confirmed on-chain settlements (drives the `--max-settlements`
    /// drain cap).
    pub fn confirmed_count(&self) -> u64 {
        self.confirmed.load(Ordering::SeqCst)
    }

    /// The funding wallet address.
    pub fn payer(&self) -> Address {
        self.payer
    }
}

#[async_trait]
impl Facilitator for X402Facilitator {
    async fn settle(&self, _req: &SettleRequest) -> SettlementOutcome {
        // Single-flight: one key, one authorization in flight at a time.
        let _permit = match self.gate.acquire().await {
            Ok(p) => p,
            Err(_) => return SettlementOutcome::Timeout,
        };
        // Slow pacing so the faucet wallet is not drained / the facilitator is not
        // rate-limited.
        {
            let mut last = self.last_settle.lock().await;
            if let Some(prev) = *last {
                let elapsed = prev.elapsed();
                if elapsed < self.min_interval {
                    tokio::time::sleep(self.min_interval - elapsed).await;
                }
            }
            *last = Some(Instant::now());
        }

        let url = format!("{}/paid", self.seller_base);
        let send = self.http.get(&url).send();
        match tokio::time::timeout(self.settle_timeout, send).await {
            Ok(Ok(resp)) => {
                let tx = resp
                    .headers()
                    .get("x-payment-response")
                    .and_then(|v| v.to_str().ok())
                    .and_then(decode_settlement);
                match tx {
                    Some(tx_hash) => {
                        self.confirmed.fetch_add(1, Ordering::SeqCst);
                        SettlementOutcome::Confirmed { tx_hash }
                    }
                    // Paid but the tx hash wasn't surfaced (async facilitator) ⇒
                    // unresolved; the orchestrator stops (no double-settle).
                    None => SettlementOutcome::Timeout,
                }
            }
            // Transport error or deadline ⇒ terminal timeout.
            _ => SettlementOutcome::Timeout,
        }
    }

    async fn balance_of(&self, _agent: &AgentId) -> Option<MicroUsd> {
        // One funding wallet backs every agent; report its real USDC balance.
        // USDC has 6 decimals, so base units == micro-USD exactly.
        let erc20 = IERC20::new(self.usdc, &self.provider);
        let bal: U256 = erc20.balanceOf(self.payer).call().await.ok()?;
        Some(MicroUsd(u64::try_from(bal).unwrap_or(u64::MAX) as i64))
    }

    fn source(&self) -> BalanceSource {
        BalanceSource::OnChainTestnet
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn b64(json: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(json.as_bytes())
    }

    #[test]
    fn decode_confirmed_settlement() {
        let h = b64(r#"{"success":true,"transaction":"0xabc123","network":"base-sepolia"}"#);
        assert_eq!(decode_settlement(&h), Some("0xabc123".to_string()));
    }

    #[test]
    fn decode_alias_tx_hash() {
        let h = b64(r#"{"success":true,"transactionHash":"0xdead"}"#);
        assert_eq!(decode_settlement(&h), Some("0xdead".to_string()));
    }

    #[test]
    fn decode_failed_or_missing_is_none() {
        assert_eq!(
            decode_settlement(&b64(
                r#"{"success":false,"errorReason":"insufficient_funds"}"#
            )),
            None
        );
        assert_eq!(decode_settlement(&b64(r#"{"success":true}"#)), None);
        assert_eq!(decode_settlement("not-base64!!!"), None);
        assert_eq!(
            decode_settlement(&b64(r#"{"success":true,"transaction":""}"#)),
            None
        );
    }
}

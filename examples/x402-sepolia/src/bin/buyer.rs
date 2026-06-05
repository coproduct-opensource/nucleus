//! x402 buyer on **Base Sepolia (testnet)**: auto-pays a 402 and prints the
//! response. Testnet only.
//!
//! Env:
//! - `X402_PRIVATE_KEY` — a **TESTNET** private key holding Base Sepolia USDC
//!   (0x-hex). Never use a mainnet key. Not stored anywhere by this program.
//! - `TARGET_URL`       — the paid endpoint (default: http://127.0.0.1:4021/paid)

use std::sync::Arc;

use alloy_signer_local::PrivateKeySigner;
use reqwest::Client;
use x402_chain_eip155::V1Eip155ExactClient;
// `ReqwestWithPayments` adds `.with_payments(..)`; `ReqwestWithPaymentsBuild` adds `.build()`.
use x402_reqwest::{ReqwestWithPayments, ReqwestWithPaymentsBuild, X402Client};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let key = std::env::var("X402_PRIVATE_KEY")
        .map_err(|_| anyhow::anyhow!("set X402_PRIVATE_KEY (a TESTNET key with Base Sepolia USDC)"))?;
    let target =
        std::env::var("TARGET_URL").unwrap_or_else(|_| "http://127.0.0.1:4021/paid".into());

    let signer = Arc::new(key.trim().parse::<PrivateKeySigner>()?);
    let x402 = X402Client::new().register(V1Eip155ExactClient::new(signer));
    let http = Client::new().with_payments(x402).build();

    println!("paying {target} on Base Sepolia (TESTNET)…");
    let resp = http.get(&target).send().await?;
    println!("status: {}", resp.status());
    println!("{}", resp.text().await?);
    Ok(())
}

//! Serving the node's HTTP API over mTLS using the node's own SPIFFE
//! identity.
//!
//! Extracted from `main.rs`'s boot sequence to stay under the line ratchet,
//! and because this reads more clearly as its own small decision than as
//! one more block in an already-long function.
//!
//! Move B: this used to have a plaintext default (HMAC auth) and an opt-in
//! `--http-mtls-self-issued` mTLS mode. HMAC has no fallback any more, so
//! mTLS is the only mode left — the flag that used to select it is gone.

use crate::{ApiError, NodeState};
use axum::Router;
use tracing::info;

/// Binds `listen_addr` and serves `app` on it over the node's self-issued
/// mTLS. `state.identity_manager` is unconditionally constructed in `main`
/// now (Move B), so this cannot fail for lack of one.
pub async fn serve(state: &NodeState, listen_addr: &str, app: Router) -> Result<(), ApiError> {
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    let manager = state
        .identity_manager
        .as_ref()
        .expect("identity_manager is unconditionally constructed in main (Move B)");
    let node_identity = manager.node_identity().to_spiffe_uri();
    let mtls_listener = manager
        .self_issued_http_mtls_listener(listener)
        .await
        .map_err(ApiError::Driver)?;
    info!(%node_identity, "nucleus-node HTTP API listening on {listen_addr} (mTLS)");
    axum::serve(
        mtls_listener,
        app.into_make_service_with_connect_info::<nucleus_identity::mtls::MtlsConnectInfo>(),
    )
    .await?;
    Ok(())
}

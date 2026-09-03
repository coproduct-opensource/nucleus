//! Serving the node's HTTP API: the plaintext default, or self-issued mTLS.
//!
//! Extracted from `main.rs`'s boot sequence to stay under the line ratchet,
//! and because the choice between the two transports reads more clearly as
//! its own small decision than as one more block in an already-long
//! function.

use crate::{ApiError, NodeState};
use axum::Router;
use tracing::info;

/// Binds `listen_addr` and serves `app` on it — over the node's self-issued
/// mTLS if `http_mtls_self_issued` is set (requires `state.identity_manager`
/// to be configured), otherwise the plaintext default.
///
/// See [`crate::identity::IdentityManager::self_issued_http_mtls_listener`]
/// for why the mTLS path is opt-in rather than the new default: it is full
/// mTLS (a client certificate is required), so no existing caller can
/// connect until the CLI has an SVID of its own.
pub async fn serve(
    state: &NodeState,
    listen_addr: &str,
    http_mtls_self_issued: bool,
    app: Router,
) -> Result<(), ApiError> {
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    if http_mtls_self_issued {
        let manager = state.identity_manager.as_ref().ok_or_else(|| {
            ApiError::Driver(
                "--http-mtls-self-issued requires --identity-workload-api-socket \
                 (no identity manager configured)"
                    .to_string(),
            )
        })?;
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
    } else {
        info!("nucleus-node listening on {listen_addr}");
        axum::serve(listener, app).await?;
    }
    Ok(())
}

//! Serving the node's HTTP API over mTLS using the node's own SPIFFE
//! identity.
//!
//! Extracted from `main.rs`'s boot sequence to stay under the line ratchet,
//! and because this reads more clearly as its own small decision than as
//! one more block in an already-long function.
//!
//! Move B: this used to have a plaintext default (HMAC auth) and an opt-in
//! `--http-mtls-self-issued` mTLS mode. HMAC has no fallback any more, so // hmac-allow: historical, flag removed by Move B
//! mTLS is the only mode left — the flag that used to select it is gone.

use crate::{ApiError, NodeState};
use axum::Router;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Keeps the live listener's certificate ahead of its own expiry.
///
/// # Why this exists
///
/// The listener used to be built from one snapshot of the node's certificate and
/// keep presenting it for the life of the process. With the default
/// `--identity-cert-ttl-secs` of 3600 that made the HTTPS API unreachable exactly
/// one hour after start, while `systemctl is-active` still said `active` and the
/// node's own journal said nothing (#2722). The certificate WAS being refreshed —
/// `start_refresh_loop` maintains it — the listener just never looked again.
///
/// # Why a third of the TTL
///
/// Rotating once per TTL leaves no room for a rotation to fail: one transient
/// error and the certificate expires before the next attempt. A third gives two
/// further attempts inside the validity window, so a single failure is survivable
/// and a persistent one is visible in the log well before clients notice. The
/// floor keeps a very short TTL (tests use seconds) from becoming a busy loop.
fn spawn_certificate_rotation(
    state: &NodeState,
    resolver: Arc<nucleus_identity::tls::RotatingServerCert>,
) {
    let Some(manager) = state.identity_manager.clone() else {
        return;
    };
    let period = (manager.cert_ttl() / 3).max(Duration::from_secs(5));
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(period);
        // `interval` fires immediately; the certificate was just minted, so the
        // first tick has nothing to do.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if let Err(e) = manager.rotate_http_server_certificate(&resolver).await {
                // Not fatal: the listener keeps serving the certificate it has,
                // which is still valid for the rest of this window. Two more
                // attempts remain before it is not.
                warn!(error = %e, "failed to rotate the node's HTTPS certificate");
            }
        }
    });
}

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
    let (mtls_listener, rotating_cert) = manager
        .self_issued_http_mtls_listener(listener)
        .await
        .map_err(ApiError::Driver)?;
    spawn_certificate_rotation(state, rotating_cert);
    info!(%node_identity, "nucleus-node HTTP API listening on {listen_addr} (mTLS)");
    axum::serve(
        mtls_listener,
        app.into_make_service_with_connect_info::<nucleus_identity::mtls::MtlsConnectInfo>(),
    )
    .await?;
    Ok(())
}

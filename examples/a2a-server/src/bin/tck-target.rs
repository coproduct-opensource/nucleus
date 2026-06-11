//! Transport-conformance target for external A2A tooling.
//!
//! ```bash
//! cd examples/a2a-server && cargo run --bin tck-target
//! ```
//!
//! Serves the SAME official-SDK routers and executor as the demo server
//! (`cargo run`), but WITHOUT the nucleus verify→serve→receipt gate, on a
//! fixed port (9999). It exists for exactly one reason: external
//! transport-conformance tooling — the [A2A TCK] — speaks pure A2A
//! (§9 JSON-RPC, §11 HTTP+JSON) and has no way to attach the signed
//! `X-Agent-Card` header the gated server requires, so the gated server
//! 401s every TCK request before the protocol binding is ever exercised.
//!
//! Scope, stated plainly:
//!
//! - **This is not a deployment mode.** The demo server always gates and
//!   has no flag to disable its gate.
//! - The verification gate and receipt issuance are covered by the e2e
//!   suite (`tests/e2e.rs`); this binary covers nothing they cover.
//! - What runs here is the protocol-binding surface only: discovery
//!   (§8.2 well-known card), JSON-RPC binding, HTTP+JSON binding. gRPC is
//!   not served — the example does not implement it.
//!
//! [A2A TCK]: https://github.com/a2aproject/a2a-tck

use nucleus_a2a_server_example::{
    build_transport_conformance_app, serve_normalized, ServerIdentity,
};

/// Fixed port; conformance harnesses point `--sut-host` here.
const PORT: u16 = 9999;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base = format!("http://localhost:{PORT}");
    let identity = ServerIdentity::generate_demo(&base)?;

    println!("A2A transport-conformance target (UNGATED — not a deployment mode)");
    println!("  card:      {base}/.well-known/agent-card.json");
    println!("  JSON-RPC:  {base}/jsonrpc");
    println!("  REST:      {base}/rest");

    let app = build_transport_conformance_app(identity);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", PORT)).await?;
    serve_normalized(listener, app).await?;
    Ok(())
}

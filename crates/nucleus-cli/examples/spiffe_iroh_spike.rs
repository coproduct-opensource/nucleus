//! SPIKE — "call SPIFFE agents anywhere" over iroh.
//!
//! Proves the core binding: over a live iroh P2P connection (dial-by-key, works
//! behind NAT via relays), a client authenticates the peer as a **SPIFFE principal**
//! by verifying a signed statement that the principal's passport key controls the
//! peer's iroh transport key (`NodeId`) — reusing the existing, tested
//! `nucleus-node-binding` primitive.
//!
//! Chain of trust demonstrated here:
//!   passport key P  --sign_binding-->  "spiffe://demo/agent-x controls NodeId N"
//!   iroh connection to N            -->  proves control of transport key N
//!   => the peer reachable at this iroh connection IS spiffe://demo/agent-x
//!
//! In production, P's ownership of the SPIFFE principal comes from a verified SVID
//! (nucleus-identity), and the TPM DevID work can attest P is hardware-resident.
//! This spike isolates the novel part: the NodeId<->principal binding over real
//! iroh transport. Run: `cargo run -p nucleus-cli --example spiffe_iroh_spike`.

use ed25519_dalek::SigningKey;
use iroh::{endpoint::presets, Endpoint, SecretKey};
use nucleus_node_binding::{sign_binding, verify_binding, NodeBinding};

const ALPN: &[u8] = b"nucleus-spiffe-hail/0";
const PRINCIPAL: &str = "spiffe://demo/agent-x";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // The agent's stable SPIFFE identity ("passport") key. In production this is the
    // key its SVID certifies; here we just trust its public key as the principal.
    let passport_sk = SigningKey::from_bytes(&[7u8; 32]);
    let passport_pk = passport_sk.verifying_key().to_bytes();

    // ── Server: an iroh endpoint whose NodeId is bound to the SPIFFE principal ──
    let server_secret = SecretKey::from_bytes(&[11u8; 32]);
    let server_endpoint = Endpoint::builder(presets::N0)
        .secret_key(server_secret.clone())
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;
    let server_node_id = server_secret.public();
    let server_node_bytes: [u8; 32] = *server_node_id.as_bytes();

    // The agent signs: "my passport controls this iroh transport key".
    let binding = sign_binding(&server_node_bytes, PRINCIPAL, &passport_sk);
    let binding_json = serde_json::to_vec(&binding)?;

    let server_addr = server_endpoint.addr();
    println!("server iroh NodeId: {server_node_id}");

    // Accept one connection and hand over the binding.
    let server_task = tokio::spawn(async move {
        let incoming = server_endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("no incoming connection"))?;
        let conn = incoming.await?;
        let (mut send, _recv) = conn.accept_bi().await?;
        send.write_all(&binding_json).await?;
        send.finish()?;
        // Keep the connection alive briefly so the client can read.
        conn.closed().await;
        Ok::<_, anyhow::Error>(())
    });

    // ── Client: dial by NodeId, receive + verify the binding ──
    let client_endpoint = Endpoint::builder(presets::N0).bind().await?;
    let conn = client_endpoint.connect(server_addr, ALPN).await?;

    // The transport key we actually connected to (iroh authenticates this).
    let connected_node: [u8; 32] = *conn.remote_id().as_bytes();

    let (mut send, mut recv) = conn.open_bi().await?;
    send.finish()?;
    let received = recv.read_to_end(64 * 1024).await?;
    let got: NodeBinding = serde_json::from_slice(&received)?;

    // VERIFY — two independent checks:
    // 1. the passport actually signed this binding (fail-closed);
    verify_binding(&got, &passport_pk)?;
    // 2. the binding is for the NodeId we are actually talking to (anti-misbinding:
    //    a binding for some *other* node must not authenticate this connection).
    if got.node_id != connected_node {
        anyhow::bail!("binding is for a different NodeId than the live connection");
    }

    println!("✅ authenticated peer over iroh as: {}", got.principal);
    println!(
        "   (passport {}… vouches for this exact transport key)",
        hex8(&passport_pk)
    );

    // ── Negative control: a binding for a DIFFERENT node must be rejected ──
    let foreign = sign_binding(&[0xAB; 32], PRINCIPAL, &passport_sk);
    let rejected =
        verify_binding(&foreign, &passport_pk).is_ok() && foreign.node_id == connected_node;
    assert!(
        !rejected,
        "a foreign-node binding must not authenticate this connection"
    );
    println!("✅ negative control: a valid binding for a *different* NodeId is refused");

    server_task.await??;
    Ok(())
}

fn hex8(b: &[u8; 32]) -> String {
    b[..4].iter().map(|x| format!("{x:02x}")).collect()
}

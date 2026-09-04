//! Test-only harness: mint a client certificate signed by an ALREADY
//! -PERSISTED local CA — a `nucleus-node` process's own `<state-dir>/ca/`
//! — with no `Tier2Host`/SSH involved.
//!
//! # Why this exists (C2 auth-bootstrap gap)
//!
//! Move B (HMAC deletion) made the node's HTTP/gRPC APIs mTLS-only, with no
//! fallback. `nucleus-cli/src/provision.rs::mint_cli_identity` already mints
//! exactly this kind of client identity, but only via `provision_mtls_identity`
//! — which is coupled to a `Tier2Host` (a real, SSH-provisioned machine or
//! Lima VM). `scripts/cross-pod-lineage-check.sh`/`cross-pod-scoped-check.sh`
//! boot a bare LOCAL `nucleus-node` process directly (no VM, no SSH) for a
//! fast CI check, so neither existing path fits: there was no lightweight way
//! for a separately-invoked CLI process to learn the trust root a
//! same-machine node process had already minted for itself.
//!
//! This harness is that missing lightweight path. It does NOT mint a new CA
//! (that would create a SEPARATE trust root the node doesn't recognize) — it
//! LOADS the CA the node already persisted (`SelfSignedCa::load_or_create`,
//! the same function `nucleus-node` itself calls, given the same
//! `--state-dir/ca` directory), so ordering matters: the node must already
//! be running (or have run at least once) against that state dir before this
//! is invoked, or it will mint a fresh, node-UNRECOGNIZED root instead of
//! loading the real one — silently producing a client cert that will never
//! verify against the live node's CA.
//!
//! # Usage
//!
//! ```bash
//! cargo run -p nucleus-identity --example mint_test_client_cert -- \
//!   --ca-dir "$STATE_DIR/ca" \
//!   --trust-domain nucleus.local \
//!   --service-account cli \
//!   --out-dir /tmp/cli-identity
//! ```
//!
//! Writes `<out-dir>/{cert.pem,key.pem,trust-bundle.pem}` — pass those
//! straight to `nucleus node --tls-cert --tls-key --trust-bundle`.

use std::path::PathBuf;
use std::time::Duration;

use nucleus_identity::{CaClient, CsrOptions, Identity, SelfSignedCa};

fn arg(flag: &str) -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == flag {
            return args.next();
        }
    }
    None
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ca_dir = PathBuf::from(arg("--ca-dir").ok_or("missing --ca-dir")?);
    let trust_domain = arg("--trust-domain").ok_or("missing --trust-domain")?;
    let namespace = arg("--namespace").unwrap_or_else(|| "system".to_string());
    let service_account = arg("--service-account").unwrap_or_else(|| "cli".to_string());
    let out_dir = PathBuf::from(arg("--out-dir").ok_or("missing --out-dir")?);
    let ttl_secs: u64 = arg("--ttl-secs")
        .map(|s| s.parse::<u64>())
        .transpose()?
        .unwrap_or(3600);

    if !ca_dir.join("ca-cert.pem").is_file() {
        return Err(format!(
            "{} has no ca-cert.pem yet — start the node against this state dir \
             and wait for it to become healthy before minting a client cert, \
             or this would mint a fresh root the running node doesn't recognize",
            ca_dir.display()
        )
        .into());
    }

    // Loads the CA already persisted at `ca_dir` — the SAME function
    // `nucleus-node` itself calls (`IdentityManager::new_with_persistent_ca`).
    // The `ca-cert.pem` check above turns "would silently mint a fresh,
    // unrecognized root" into a loud error instead.
    let ca = SelfSignedCa::load_or_create(&trust_domain, &ca_dir)?;

    let identity = Identity::new(&trust_domain, &namespace, &service_account);
    let csr = CsrOptions::new(identity.to_spiffe_uri()).generate()?;
    let cert = ca
        .sign_csr(
            csr.csr(),
            csr.private_key(),
            &identity,
            Duration::from_secs(ttl_secs),
        )
        .await?;

    std::fs::create_dir_all(&out_dir)?;
    let cert_path = out_dir.join("cert.pem");
    let key_path = out_dir.join("key.pem");
    let bundle_path = out_dir.join("trust-bundle.pem");
    std::fs::write(&cert_path, cert.chain_pem())?;
    std::fs::write(&key_path, cert.private_key_pem())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }
    // The trust bundle IS the CA's own root cert, matching
    // `mint_cli_identity`'s own convention — a single-entry bundle here
    // because this CA never issues more than one root, not because
    // `--trust-bundle` cannot accept a concatenated multi-entry PEM.
    std::fs::write(&bundle_path, ca.root_cert_pem())?;

    println!("cert:   {}", cert_path.display());
    println!("key:    {}", key_path.display());
    println!("bundle: {}", bundle_path.display());
    Ok(())
}

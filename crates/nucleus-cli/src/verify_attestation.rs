//! Relying-party verification of an attested SVID (North Star C9).
//!
//! `nucleus verify-attestation` is the *outside* verifier: given the PEM certificate
//! chain a pod serves over `FETCH_SVID` and the measurements an operator expects, it
//! decides whether to trust the pod. This is the production caller for
//! [`nucleus_identity::verify_attested_svid`] — the shipped library entrypoint that
//! extracts the launch attestation from the leaf certificate and checks it.
//!
//! Two teeth, matching the library:
//! * **fail-closed on absent** — `--require-attestation` (default) makes a served
//!   cert that carries no attestation extension an error, not a vacuous pass.
//! * **drift** — a measurement outside the `--expect-*` allow-lists is an error.
//!
//! # Trust boundary (read this)
//!
//! The measurement is the *node's own* SHA-256 of the kernel+rootfs it launched,
//! signed by the node's CA key — first-party **software** launch attestation, NOT
//! hardware-rooted. There is no TPM/SEV-SNP/TDX quote and no UDS-in-ROM DICE
//! identity, so the guarantee is conditional: *IF you trust this node's key, THEN
//! the pod ran an artifact with these measurements.*

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use nucleus_identity::{
    AttestationRequirements, Claim, SelfMeasuredBackend, SvidAttestationBackend,
};
use std::collections::BTreeSet;

#[derive(Args)]
pub struct VerifyAttestationArgs {
    /// Path to the served SVID certificate chain (PEM).
    #[arg(long)]
    cert: std::path::PathBuf,

    /// Expected kernel measurement (hex SHA-256). Repeatable; any listed value passes.
    #[arg(long = "expect-kernel")]
    expect_kernel: Vec<String>,

    /// Expected rootfs measurement (hex SHA-256). Repeatable; any listed value passes.
    #[arg(long = "expect-rootfs")]
    expect_rootfs: Vec<String>,

    /// Expected config measurement (hex SHA-256). Repeatable; any listed value passes.
    #[arg(long = "expect-config")]
    expect_config: Vec<String>,

    /// Fail closed if the served cert carries no attestation extension (default on).
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    require_attestation: bool,
}

fn parse_hash(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim())
        .with_context(|| format!("invalid hex measurement '{hex_str}'"))?;
    bytes.as_slice().try_into().map_err(|_| {
        anyhow!(
            "measurement must be 32 bytes (64 hex chars), got {}",
            bytes.len()
        )
    })
}

pub fn execute(args: VerifyAttestationArgs) -> Result<()> {
    let chain = std::fs::read_to_string(&args.cert)
        .with_context(|| format!("reading cert chain {}", args.cert.display()))?;

    let mut req = AttestationRequirements::any();
    for h in &args.expect_kernel {
        req = req.allow_kernel(parse_hash(h)?);
    }
    for h in &args.expect_rootfs {
        req = req.allow_rootfs(parse_hash(h)?);
    }
    for h in &args.expect_config {
        req = req.allow_config(parse_hash(h)?);
    }

    // Verify through the attestation-backend seam. Today the only root is the
    // node's self-measurement; other roots (TPM DevID, Apple App Attest, cloud IID)
    // will plug in behind the same `SvidAttestationBackend` + normalized result.
    let backend = SelfMeasuredBackend;
    match backend.verify_svid(&chain, &req, args.require_attestation) {
        Ok(Some(va)) => {
            let measurement = va
                .launch
                .as_ref()
                .map(|l| l.to_hex_summary())
                .unwrap_or_default();
            println!(
                "OK: attested SVID verified via '{}' (assurance L{}) — {}",
                va.backend,
                va.assurance().as_u8(),
                measurement
            );
            println!("  proves:     {}", fmt_claims(&va.proves));
            println!("  not proven: {}", fmt_claims(&va.not_proven));
            println!(
                "NOTE: node-signed SOFTWARE launch attestation (no hardware root); \
                 trust is conditional on the node's signing key."
            );
            Ok(())
        }
        Ok(None) => {
            println!("OK: served SVID carries no attestation and none was required.");
            Ok(())
        }
        Err(e) => bail!("attestation verification FAILED: {e}"),
    }
}

/// Render a closed claim set as a readable list (or `(none)`).
fn fmt_claims(claims: &BTreeSet<Claim>) -> String {
    if claims.is_empty() {
        return "(none)".to_string();
    }
    claims
        .iter()
        .map(|c| format!("{c:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_identity::{CaClient, CsrOptions, Identity, LaunchAttestation, SelfSignedCa};
    use std::io::Write;
    use std::time::Duration;

    /// Mint a real leaf cert via the shipping SelfSignedCa, optionally attested.
    async fn mint(attested: bool) -> (tempfile::NamedTempFile, LaunchAttestation) {
        let ca = SelfSignedCa::new("test.local").unwrap();
        let identity = Identity::for_pod("test.local", "pod-1");
        let cs = CsrOptions::new(identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let att = LaunchAttestation::from_hashes([1u8; 32], [2u8; 32], [3u8; 32]);
        let cert = if attested {
            ca.sign_attested_csr(
                cs.csr(),
                cs.private_key(),
                &identity,
                Duration::from_secs(3600),
                &att,
            )
            .await
            .unwrap()
        } else {
            ca.sign_csr(
                cs.csr(),
                cs.private_key(),
                &identity,
                Duration::from_secs(3600),
            )
            .await
            .unwrap()
        };
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(cert.chain_pem().as_bytes()).unwrap();
        (f, att)
    }

    fn args(
        f: &tempfile::NamedTempFile,
        k: &[u8; 32],
        r: &[u8; 32],
        c: &[u8; 32],
    ) -> VerifyAttestationArgs {
        VerifyAttestationArgs {
            cert: f.path().to_path_buf(),
            expect_kernel: vec![hex::encode(k)],
            expect_rootfs: vec![hex::encode(r)],
            expect_config: vec![hex::encode(c)],
            require_attestation: true,
        }
    }

    // The CLI production entrypoint verifies a correct attested cert, reds on
    // measurement drift, and fails closed on an absent extension (C9 Inc 1).
    #[tokio::test]
    async fn cli_verifies_attested_and_reds_on_drift_and_absent() {
        let (f, att) = mint(true).await;

        // Positive control — correct measurement verifies (non-vacuous).
        assert!(execute(args(
            &f,
            att.kernel_hash(),
            att.rootfs_hash(),
            att.config_hash()
        ))
        .is_ok());

        // Drift — one wrong expected hash reds the CLI verdict.
        let mut wrong = *att.kernel_hash();
        wrong[0] ^= 0x01;
        assert!(execute(args(&f, &wrong, att.rootfs_hash(), att.config_hash())).is_err());

        // Absent — a plain cert with require_attestation fails closed.
        let (plain, _) = mint(false).await;
        assert!(execute(args(
            &plain,
            att.kernel_hash(),
            att.rootfs_hash(),
            att.config_hash()
        ))
        .is_err());
    }

    #[test]
    fn rejects_malformed_hex_measurement() {
        assert!(parse_hash("not-hex").is_err());
        assert!(parse_hash("ab").is_err()); // too short
    }
}

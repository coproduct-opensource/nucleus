// SPDX-License-Identifier: MIT
//
//! `nucleus-trust-registry` CLI — the enrollment gate.
//!
//! Subcommands:
//! - `verify-pr`  — the fail-closed PR gate: check the diff touches only
//!   the claimed domain, verify the GitHub-OIDC proof-of-control (numeric
//!   owner_id pin), reject silent rotation against the incumbent set.
//! - `compile`    — deterministically compile the registry into a
//!   federation set and print it (sorted; reproducible).
//! - `log-append` — append the claimed binding to the transparency log,
//!   seal a cosigned STH, and write the sealed-log artifact.
//!
//! The OIDC token REQUEST (minting) is the enroller-side workflow's job
//! (config, not code); this binary holds the VERIFIER logic.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use nucleus_lineage::checkpoint::Ed25519Witness;
use nucleus_oidc_core::Jwks;
use nucleus_trust_registry::{
    check_no_silent_rotation, check_pr_diff, compile, verify_proof_of_control, DomainEnrollment,
    SealedLog, TrustLog,
};
use nucleus_witness::cosign::WitnessKey;

#[derive(Parser)]
#[command(
    name = "nucleus-trust-registry",
    about = "PR-rooted, GitHub-OIDC-attested, transparency-logged SPIFFE federation enrollment (non-custodial verifier)."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fail-closed PR enrollment gate.
    VerifyPr {
        /// Registry root (contains `domains/`). Defaults to `registry`.
        #[arg(long, default_value = "registry")]
        registry_dir: PathBuf,
        /// Repo-relative prefix of the registry tree (for diff scoping).
        #[arg(long, default_value = "registry")]
        registry_prefix: String,
        /// The single trust domain this PR claims to enroll/update.
        #[arg(long)]
        claimed_domain: String,
        /// File of changed paths (one per line; e.g. `git diff --name-only`).
        #[arg(long)]
        changed_paths_file: PathBuf,
        /// File holding the GitHub Actions OIDC proof-of-control token.
        #[arg(long)]
        oidc_token_file: PathBuf,
        /// File holding GitHub's JWKS JSON (fetched out-of-band; the
        /// workflow supplies it from token.actions.githubusercontent.com).
        #[arg(long)]
        github_jwks_file: PathBuf,
    },
    /// Compile the registry into a deterministic federation set.
    Compile {
        #[arg(long, default_value = "registry")]
        registry_dir: PathBuf,
    },
    /// Append the claimed binding to the transparency log + seal it.
    LogAppend {
        #[arg(long, default_value = "registry")]
        registry_dir: PathBuf,
        /// The trust domain whose binding is being logged.
        #[arg(long)]
        claimed_domain: String,
        /// The verified numeric GitHub owner id (from the proof).
        #[arg(long)]
        owner_id: u64,
        /// Unix-seconds timestamp to bind into the leaf + cosignature.
        #[arg(long)]
        timestamp: u64,
        /// Hex of the 32-byte STH witness signing seed.
        #[arg(long)]
        witness_seed_hex: String,
        /// Hex of the 32-byte cosigner (witness) signing seed.
        #[arg(long)]
        cosigner_seed_hex: String,
        /// C2SP name for the cosigning witness.
        #[arg(long, default_value = "nucleus.trust-registry/witness-1")]
        cosigner_name: String,
        /// Where to write the sealed-log JSON artifact.
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::VerifyPr {
            registry_dir,
            registry_prefix,
            claimed_domain,
            changed_paths_file,
            oidc_token_file,
            github_jwks_file,
        } => {
            // 1. Diff scoping (reject diff-smuggling).
            let changed_raw = std::fs::read_to_string(&changed_paths_file)
                .map_err(|e| format!("read changed paths: {e}"))?;
            let changed: Vec<String> = changed_raw
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect();
            check_pr_diff(&changed, &claimed_domain, &registry_prefix)
                .map_err(|e| e.to_string())?;

            // 2. Load + validate the claimed enrollment.
            let dir = registry_dir
                .join(nucleus_trust_registry::DOMAINS_SUBDIR)
                .join(&claimed_domain);
            let enrollment = DomainEnrollment::load(&dir).map_err(|e| e.to_string())?;

            // 3. Verify GitHub-OIDC proof-of-control (numeric owner_id pin).
            let token = std::fs::read_to_string(&oidc_token_file)
                .map_err(|e| format!("read oidc token: {e}"))?;
            let jwks_bytes =
                std::fs::read(&github_jwks_file).map_err(|e| format!("read github jwks: {e}"))?;
            let jwks: Jwks = serde_json::from_slice(&jwks_bytes)
                .map_err(|e| format!("parse github jwks: {e}"))?;
            let claims = verify_proof_of_control(token.trim(), &enrollment.metadata, &jwks)
                .map_err(|e| e.to_string())?;

            // 4. Silent-rotation guard against the CURRENTLY-MERGED set
            //    (the registry on disk minus this PR's change). We compile
            //    the on-disk tree; for an existing domain a different
            //    proof owner_id is a takeover. (In CI the base ref is
            //    checked out into `registry_dir` for this comparison; the
            //    workflow wires that.)
            let incumbent = compile(&registry_dir).map_err(|e| e.to_string())?;
            check_no_silent_rotation(&incumbent, &claimed_domain, claims.repository_owner_id)
                .map_err(|e| e.to_string())?;

            println!(
                "OK: enrollment for {claimed_domain:?} verified — GitHub owner_id {} (org {:?}) attested; diff scoped; no silent rotation.",
                claims.repository_owner_id, claims.repository_owner
            );
            Ok(())
        }

        Command::Compile { registry_dir } => {
            let set = compile(&registry_dir).map_err(|e| e.to_string())?;
            println!("compiled {} binding(s) (sorted):", set.len());
            for (td, b) in &set.bindings {
                println!(
                    "  {td}  owner_id={}  endpoint={}  profile={}",
                    b.metadata.owner_id, b.metadata.bundle_endpoint_url, b.metadata.profile
                );
            }
            Ok(())
        }

        Command::LogAppend {
            registry_dir,
            claimed_domain,
            owner_id,
            timestamp,
            witness_seed_hex,
            cosigner_seed_hex,
            cosigner_name,
            out,
        } => {
            let dir = registry_dir
                .join(nucleus_trust_registry::DOMAINS_SUBDIR)
                .join(&claimed_domain);
            let enrollment = DomainEnrollment::load(&dir).map_err(|e| e.to_string())?;

            let witness_seed = parse_seed(&witness_seed_hex)?;
            let cosigner_seed = parse_seed(&cosigner_seed_hex)?;
            let witness = Ed25519Witness::from_seed(witness_seed);
            let cosigner = WitnessKey::from_seed(cosigner_seed, cosigner_name);

            let mut log = TrustLog::new();
            log.append_binding(
                &claimed_domain,
                &enrollment.bundle_bytes,
                owner_id,
                timestamp,
            )
            .map_err(|e| e.to_string())?;
            let sealed: SealedLog = log
                .seal(&witness, &cosigner, timestamp)
                .map_err(|e| e.to_string())?;

            let json = serde_json::to_vec_pretty(&sealed)
                .map_err(|e| format!("serialize sealed log: {e}"))?;
            std::fs::write(&out, json).map_err(|e| format!("write {out:?}: {e}"))?;
            println!(
                "appended {claimed_domain:?} to transparency log; sealed cosigned STH (size {}) → {out:?}",
                sealed.sth.tree_size
            );
            Ok(())
        }
    }
}

fn parse_seed(hex_str: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| format!("bad seed hex: {e}"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| "seed must be exactly 32 bytes (64 hex chars)".to_string())
}

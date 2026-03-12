//! `nucleus token` — manage attenuation tokens for delegation.
//!
//! Attenuation tokens are compact, cryptographic delegation credentials.
//! Each token carries a certificate chain proving that authority was
//! delegated from a root to a leaf, with permissions that can only
//! tighten at each hop.
//!
//! ## Subcommands
//!
//! - `nucleus token mint` — create a root token from a profile
//! - `nucleus token delegate` — attenuate a token to a child
//! - `nucleus token inspect` — show token contents
//! - `nucleus token verify` — cryptographically verify a token chain

use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::Engine;
use chrono::{Duration, Utc};
use clap::{Args, Subcommand};
use ring::signature::{Ed25519KeyPair, KeyPair};

use portcullis::certificate::LatticeCertificate;
use portcullis::profile::ProfileRegistry;
use portcullis::token::AttenuationToken;
use portcullis::PermissionLattice;

// ── CLI args ─────────────────────────────────────────────────────────

/// Manage attenuation tokens for delegation.
#[derive(Args)]
pub struct TokenArgs {
    #[command(subcommand)]
    pub command: TokenCommand,
}

#[derive(Subcommand)]
pub enum TokenCommand {
    /// Create a root token from a profile with a new keypair.
    Mint(MintArgs),

    /// Attenuate an existing token to a child identity with tighter permissions.
    Delegate(DelegateArgs),

    /// Show the contents of a token without verification.
    Inspect(InspectArgs),

    /// Cryptographically verify a token's delegation chain.
    Verify(VerifyArgs),
}

#[derive(Args)]
pub struct MintArgs {
    /// Profile name to use as root permissions (e.g., codegen, local-dev).
    #[arg(short, long)]
    pub profile: String,

    /// Root identity (e.g., spiffe://nucleus.local/human/alice).
    #[arg(short, long)]
    pub identity: String,

    /// Token expiry in hours from now.
    #[arg(long, default_value = "8")]
    pub expires_hours: u64,

    /// Write token to file instead of stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Also write the root signing key (PKCS#8 PEM) for later delegation.
    /// WARNING: Keep this key secure — it is the root of trust.
    #[arg(long)]
    pub write_key: Option<PathBuf>,
}

#[derive(Args)]
pub struct DelegateArgs {
    /// Path to parent token file (or "-" for stdin).
    #[arg(short, long)]
    pub token: PathBuf,

    /// Path to parent's signing key (PKCS#8 PEM).
    #[arg(short, long)]
    pub key: PathBuf,

    /// Child identity to delegate to.
    #[arg(short, long)]
    pub identity: String,

    /// Profile to attenuate to (must be ≤ parent permissions).
    #[arg(short, long)]
    pub profile: String,

    /// Token expiry in hours from now (must be ≤ parent expiry).
    #[arg(long, default_value = "8")]
    pub expires_hours: u64,

    /// Write delegated token to file instead of stdout.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Write the child's signing key for further delegation.
    #[arg(long)]
    pub write_key: Option<PathBuf>,
}

#[derive(Args)]
pub struct InspectArgs {
    /// Path to token file (or "-" for stdin).
    #[arg(short, long)]
    pub token: PathBuf,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// Path to token file (or "-" for stdin).
    #[arg(short, long)]
    pub token: PathBuf,

    /// Maximum allowed chain depth.
    #[arg(long, default_value = "10")]
    pub max_depth: usize,
}

// ── Helpers ──────────────────────────────────────────────────────────

fn read_token_file(path: &PathBuf) -> Result<String> {
    if path.to_str() == Some("-") {
        use std::io::Read;
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .context("Failed to read token from stdin")?;
        Ok(buf.trim().to_string())
    } else {
        std::fs::read_to_string(path)
            .map(|s| s.trim().to_string())
            .with_context(|| format!("Failed to read token from {}", path.display()))
    }
}

fn write_output(data: &str, path: Option<&PathBuf>) -> Result<()> {
    match path {
        Some(p) => {
            std::fs::write(p, data)
                .with_context(|| format!("Failed to write to {}", p.display()))?;
            eprintln!("Written to {}", p.display());
        }
        None => {
            println!("{}", data);
        }
    }
    Ok(())
}

/// Encode a PKCS#8 key as PEM.
fn pkcs8_to_pem(pkcs8_bytes: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(pkcs8_bytes);
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    pem
}

/// Decode a PEM key to PKCS#8 DER bytes.
fn pem_to_pkcs8(pem: &str) -> Result<Vec<u8>> {
    let b64: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .context("Failed to decode PEM key")
}

fn resolve_profile(name: &str) -> Result<PermissionLattice> {
    let registry =
        ProfileRegistry::canonical().context("Failed to load canonical profile registry")?;
    registry
        .resolve(name)
        .map_err(|e| anyhow::anyhow!("Unknown profile '{}': {}", name, e))
}

// ── Subcommand implementations ───────────────────────────────────────

fn mint(args: MintArgs) -> Result<()> {
    let permissions = resolve_profile(&args.profile)?;
    let not_after = Utc::now() + Duration::hours(args.expires_hours as i64);
    let rng = ring::rand::SystemRandom::new();

    // Generate root keypair
    let root_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| anyhow::anyhow!("Failed to generate key: {}", e))?;
    let root_key = Ed25519KeyPair::from_pkcs8(root_pkcs8.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to parse generated key: {}", e))?;
    let root_pub = root_key.public_key().as_ref().to_vec();

    // Mint root certificate
    let (cert, _holder_key) = LatticeCertificate::mint(
        permissions,
        args.identity.clone(),
        not_after,
        &root_key,
        &rng,
    );

    // Seal into token
    let token = AttenuationToken::seal(cert, root_pub);
    let encoded = token
        .to_base64()
        .map_err(|e| anyhow::anyhow!("Failed to encode token: {}", e))?;

    write_output(&encoded, args.output.as_ref())?;

    // Optionally write the signing key
    if let Some(key_path) = &args.write_key {
        let pem = pkcs8_to_pem(root_pkcs8.as_ref());
        std::fs::write(key_path, &pem)
            .with_context(|| format!("Failed to write key to {}", key_path.display()))?;
        eprintln!("Root signing key written to {}", key_path.display());
    }

    eprintln!(
        "Minted token: profile={}, identity={}, expires={}",
        args.profile, args.identity, not_after
    );

    Ok(())
}

fn delegate(args: DelegateArgs) -> Result<()> {
    // Read parent token
    let token_str = read_token_file(&args.token)?;
    let parent_token = AttenuationToken::from_base64(&token_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse parent token: {}", e))?;

    // Read parent signing key
    let key_pem = std::fs::read_to_string(&args.key)
        .with_context(|| format!("Failed to read key from {}", args.key.display()))?;
    let key_bytes = pem_to_pkcs8(&key_pem)?;
    let holder_key = Ed25519KeyPair::from_pkcs8(&key_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse signing key: {}", e))?;

    // Resolve child profile and attenuate
    let child_permissions = resolve_profile(&args.profile)?;
    let not_after = Utc::now() + Duration::hours(args.expires_hours as i64);
    let rng = ring::rand::SystemRandom::new();

    let cert = parent_token.certificate().clone();
    let (child_cert, _child_key) = cert
        .delegate(
            &child_permissions,
            args.identity.clone(),
            not_after,
            &holder_key,
            &rng,
        )
        .map_err(|e| anyhow::anyhow!("Delegation failed: {}", e))?;

    // Seal child token with same root public key
    let child_token = AttenuationToken::seal(child_cert, parent_token.root_public_key().to_vec());
    let encoded = child_token
        .to_base64()
        .map_err(|e| anyhow::anyhow!("Failed to encode token: {}", e))?;

    write_output(&encoded, args.output.as_ref())?;

    // Optionally write child key
    if let Some(key_path) = &args.write_key {
        // Generate a new ephemeral key for the child
        let child_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| anyhow::anyhow!("Failed to generate child key: {}", e))?;
        let pem = pkcs8_to_pem(child_pkcs8.as_ref());
        std::fs::write(key_path, &pem)
            .with_context(|| format!("Failed to write key to {}", key_path.display()))?;
        eprintln!("Child signing key written to {}", key_path.display());
    }

    eprintln!(
        "Delegated: identity={}, profile={}, chain_depth={}",
        args.identity,
        args.profile,
        child_token.chain_depth()
    );

    Ok(())
}

fn inspect(args: InspectArgs) -> Result<()> {
    let token_str = read_token_file(&args.token)?;
    let token = AttenuationToken::from_base64(&token_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse token: {}", e))?;

    let fingerprint = hex::encode(token.fingerprint());

    println!("Token Inspection");
    println!("{}", "=".repeat(50));
    println!("Version:       {}", token.version());
    println!("Chain depth:   {}", token.chain_depth());
    println!("Root identity: {}", token.root_identity());
    println!("Leaf identity: {}", token.leaf_identity());
    println!("Fingerprint:   {}", fingerprint);
    println!("Root key:      {}", hex::encode(token.root_public_key()));

    Ok(())
}

fn verify(args: VerifyArgs) -> Result<()> {
    let token_str = read_token_file(&args.token)?;
    let token = AttenuationToken::from_base64(&token_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse token: {}", e))?;

    let now = Utc::now();
    match token.verify(now, args.max_depth) {
        Ok(verified) => {
            let fingerprint = hex::encode(token.fingerprint());
            println!("Token VERIFIED");
            println!("{}", "=".repeat(50));
            println!("Chain depth:       {}", verified.chain_depth);
            println!("Root identity:     {}", verified.root_identity);
            println!("Leaf identity:     {}", verified.leaf_identity);
            println!("Fingerprint:       {}", fingerprint);
            println!("Effective perms:");
            println!(
                "  read_files:      {:?}",
                verified.effective.capabilities.read_files
            );
            println!(
                "  write_files:     {:?}",
                verified.effective.capabilities.write_files
            );
            println!(
                "  edit_files:      {:?}",
                verified.effective.capabilities.edit_files
            );
            println!(
                "  run_bash:        {:?}",
                verified.effective.capabilities.run_bash
            );
            println!(
                "  glob_search:     {:?}",
                verified.effective.capabilities.glob_search
            );
            println!(
                "  grep_search:     {:?}",
                verified.effective.capabilities.grep_search
            );
            println!(
                "  web_search:      {:?}",
                verified.effective.capabilities.web_search
            );
            println!(
                "  web_fetch:       {:?}",
                verified.effective.capabilities.web_fetch
            );
            println!(
                "  git_commit:      {:?}",
                verified.effective.capabilities.git_commit
            );
            println!(
                "  git_push:        {:?}",
                verified.effective.capabilities.git_push
            );
            println!(
                "  create_pr:       {:?}",
                verified.effective.capabilities.create_pr
            );
            println!(
                "  manage_pods:     {:?}",
                verified.effective.capabilities.manage_pods
            );
            Ok(())
        }
        Err(e) => {
            eprintln!("Token VERIFICATION FAILED: {}", e);
            std::process::exit(1);
        }
    }
}

// ── Main entry ───────────────────────────────────────────────────────

pub fn execute(args: TokenArgs) -> Result<()> {
    match args.command {
        TokenCommand::Mint(a) => mint(a),
        TokenCommand::Delegate(a) => delegate(a),
        TokenCommand::Inspect(a) => inspect(a),
        TokenCommand::Verify(a) => verify(a),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup_dir() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn test_pkcs8_pem_roundtrip() {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pem = pkcs8_to_pem(pkcs8.as_ref());
        let decoded = pem_to_pkcs8(&pem).unwrap();
        assert_eq!(pkcs8.as_ref(), decoded.as_slice());
    }

    #[test]
    fn test_mint_creates_valid_token() {
        let dir = setup_dir();
        let token_path = dir.path().join("token.b64");
        let key_path = dir.path().join("root.pem");

        let args = MintArgs {
            profile: "read-only".to_string(),
            identity: "spiffe://test/human/alice".to_string(),
            expires_hours: 2,
            output: Some(token_path.clone()),
            write_key: Some(key_path.clone()),
        };

        mint(args).unwrap();

        // Token file should exist and be valid base64
        let token_str = std::fs::read_to_string(&token_path).unwrap();
        let token = AttenuationToken::from_base64(token_str.trim()).unwrap();
        assert_eq!(token.root_identity(), "spiffe://test/human/alice");
        assert_eq!(token.chain_depth(), 0);

        // Key file should exist and be valid PEM
        let key_pem = std::fs::read_to_string(&key_path).unwrap();
        assert!(key_pem.contains("-----BEGIN PRIVATE KEY-----"));

        // Token should verify
        let verified = token.verify_default(Utc::now()).unwrap();
        assert_eq!(verified.root_identity, "spiffe://test/human/alice");
    }

    #[test]
    fn test_mint_with_profile() {
        let dir = setup_dir();
        let token_path = dir.path().join("token.b64");

        let args = MintArgs {
            profile: "local-dev".to_string(),
            identity: "spiffe://test/dev".to_string(),
            expires_hours: 1,
            output: Some(token_path.clone()),
            write_key: None,
        };

        mint(args).unwrap();

        let token_str = std::fs::read_to_string(&token_path).unwrap();
        let token = AttenuationToken::from_base64(token_str.trim()).unwrap();
        let verified = token.verify_default(Utc::now()).unwrap();

        // local-dev profile should have read_files=Always
        assert_eq!(
            verified.effective.capabilities.read_files,
            portcullis::CapabilityLevel::Always
        );
        // local-dev should NOT have web_fetch
        assert_eq!(
            verified.effective.capabilities.web_fetch,
            portcullis::CapabilityLevel::Never
        );
    }

    #[test]
    fn test_mint_unknown_profile_fails() {
        let args = MintArgs {
            profile: "nonexistent-profile".to_string(),
            identity: "spiffe://test/x".to_string(),
            expires_hours: 1,
            output: None,
            write_key: None,
        };

        assert!(mint(args).is_err());
    }

    #[test]
    fn test_inspect_output() {
        let dir = setup_dir();
        let token_path = dir.path().join("token.b64");

        // Mint a token first
        let mint_args = MintArgs {
            profile: "test-runner".to_string(),
            identity: "spiffe://test/runner".to_string(),
            expires_hours: 1,
            output: Some(token_path.clone()),
            write_key: None,
        };
        mint(mint_args).unwrap();

        // Inspect should not panic
        let inspect_args = InspectArgs { token: token_path };
        inspect(inspect_args).unwrap();
    }

    #[test]
    fn test_verify_valid_token() {
        let dir = setup_dir();
        let token_path = dir.path().join("token.b64");

        let mint_args = MintArgs {
            profile: "read-only".to_string(),
            identity: "spiffe://test/verifier".to_string(),
            expires_hours: 1,
            output: Some(token_path.clone()),
            write_key: None,
        };
        mint(mint_args).unwrap();

        let verify_args = VerifyArgs {
            token: token_path,
            max_depth: 10,
        };
        verify(verify_args).unwrap();
    }

    #[test]
    fn test_verify_corrupted_token_fails() {
        let dir = setup_dir();
        let token_path = dir.path().join("bad.b64");
        std::fs::write(&token_path, "not-a-valid-token").unwrap();

        let verify_args = VerifyArgs {
            token: token_path,
            max_depth: 10,
        };
        assert!(verify(verify_args).is_err());
    }

    #[test]
    fn test_resolve_profile_canonical_names() {
        // All canonical profiles should resolve
        let profiles = [
            "read-only",
            "local-dev",
            "codegen",
            "safe-pr-fixer",
            "test-runner",
            "doc-editor",
            "triage-bot",
            "code-review",
            "release",
            "research-web",
        ];
        for name in &profiles {
            let result = resolve_profile(name);
            assert!(result.is_ok(), "Profile '{}' should resolve", name);
        }
    }
}

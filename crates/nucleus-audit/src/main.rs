use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use clap::Parser;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Parser, Debug)]
#[command(name = "nucleus-audit")]
#[command(about = "Verify nucleus audit log signatures and hash chain")]
struct Args {
    /// Audit log path to verify.
    #[arg(long, env = "NUCLEUS_AUDIT_LOG")]
    log: PathBuf,
    /// Audit log signing secret.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_AUDIT_SECRET")]
    secret: Option<String>,
    /// Read the audit secret from a file.
    #[arg(long)]
    secret_file: Option<PathBuf>,
    /// Fallback to tool-proxy auth secret if audit secret is omitted.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_AUTH_SECRET")]
    auth_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuditEntry {
    timestamp_unix: u64,
    actor: Option<String>,
    event: String,
    subject: String,
    result: String,
    prev_hash: String,
    hash: String,
    signature: String,
}

#[derive(thiserror::Error, Debug)]
enum VerifyError {
    #[error("missing audit secret (use --secret, --secret-file, or env)")]
    MissingSecret,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse audit entry at line {line}: {source}")]
    Json {
        line: usize,
        source: serde_json::Error,
    },
    #[error("invalid audit log at line {line}: {message}")]
    Invalid { line: usize, message: String },
}

fn main() -> Result<(), VerifyError> {
    let args = Args::parse();
    let secret = resolve_secret(&args)?;
    let count = verify_log(&args.log, secret.as_bytes())?;
    println!("ok: verified {count} entries");
    Ok(())
}

fn resolve_secret(args: &Args) -> Result<String, VerifyError> {
    if let Some(secret) = args.secret.as_ref() {
        return Ok(secret.clone());
    }
    if let Some(path) = args.secret_file.as_ref() {
        return read_secret_file(path);
    }
    if let Some(secret) = args.auth_secret.as_ref() {
        return Ok(secret.clone());
    }
    Err(VerifyError::MissingSecret)
}

fn read_secret_file(path: &Path) -> Result<String, VerifyError> {
    let secret = std::fs::read_to_string(path)?.trim().to_string();
    if secret.is_empty() {
        return Err(VerifyError::MissingSecret);
    }
    Ok(secret)
}

fn verify_log(path: &Path, secret: &[u8]) -> Result<usize, VerifyError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut prev_hash = String::new();
    let mut count = 0usize;

    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let line_no = idx + 1;
        let entry: AuditEntry =
            serde_json::from_str(line).map_err(|source| VerifyError::Json {
                line: line_no,
                source,
            })?;
        if entry.prev_hash != prev_hash {
            return Err(VerifyError::Invalid {
                line: line_no,
                message: format!(
                    "prev_hash mismatch (expected {}, got {})",
                    prev_hash, entry.prev_hash
                ),
            });
        }
        let actor = entry.actor.clone().unwrap_or_default();
        let message = format!(
            "{}|{}|{}|{}|{}|{}",
            entry.timestamp_unix, actor, entry.event, entry.subject, entry.result, prev_hash
        );
        let signature = sign_message(secret, message.as_bytes());
        if signature != entry.signature {
            return Err(VerifyError::Invalid {
                line: line_no,
                message: "signature mismatch".to_string(),
            });
        }
        let hash = sha256_hex(&format!("{}|{}", message, signature));
        if hash != entry.hash {
            return Err(VerifyError::Invalid {
                line: line_no,
                message: "hash mismatch".to_string(),
            });
        }
        prev_hash = entry.hash.clone();
        count += 1;
    }

    Ok(count)
}

fn sign_message(secret: &[u8], message: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
    mac.update(message);
    let result = mac.finalize().into_bytes();
    hex::encode(result)
}

fn sha256_hex(message: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    hex::encode(hasher.finalize())
}

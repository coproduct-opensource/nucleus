use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Parser, Debug)]
#[command(name = "nucleus-audit")]
#[command(about = "Verify and inspect nucleus audit logs")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Verify a tool-proxy JSONL audit log (HMAC signatures + hash chain).
    Verify {
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
    },
    /// Verify a lattice-guard permission audit log (hash chain only).
    VerifyChain {
        /// Audit log path (JSONL, each line is a lattice-guard AuditEntry).
        #[arg(long)]
        log: PathBuf,
        /// HMAC secret (required if entries were written with FileAuditBackend).
        #[arg(long, env = "NUCLEUS_AUDIT_SECRET")]
        secret: Option<String>,
    },
    /// Print a summary of audit events grouped by identity.
    Summary {
        /// Audit log path (tool-proxy JSONL format).
        #[arg(long, env = "NUCLEUS_AUDIT_LOG")]
        log: PathBuf,
    },
    /// Export audit log entries as formatted JSON.
    Export {
        /// Audit log path (tool-proxy JSONL format).
        #[arg(long, env = "NUCLEUS_AUDIT_LOG")]
        log: PathBuf,
        /// Output format.
        #[arg(long, default_value = "json")]
        format: ExportFormat,
    },
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum ExportFormat {
    Json,
    Jsonl,
}

#[derive(Debug, Deserialize)]
struct ToolProxyEntry {
    timestamp_unix: u64,
    actor: Option<String>,
    event: String,
    subject: String,
    result: String,
    prev_hash: String,
    hash: String,
    signature: String,
}

/// Signed line from FileAuditBackend.
#[derive(Debug, Deserialize)]
struct SignedLine {
    entry: serde_json::Value,
    hmac: String,
}

#[derive(thiserror::Error, Debug)]
enum AuditError {
    #[error("missing audit secret (use --secret, --secret-file, or env)")]
    MissingSecret,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse entry at line {line}: {source}")]
    Json {
        line: usize,
        source: serde_json::Error,
    },
    #[error("invalid audit log at line {line}: {message}")]
    Invalid { line: usize, message: String },
    #[error("lattice-guard backend error: {0}")]
    Backend(String),
}

fn main() -> Result<(), AuditError> {
    let cli = Cli::parse();

    match cli.command {
        Command::Verify {
            log,
            secret,
            secret_file,
            auth_secret,
        } => {
            let resolved = resolve_secret(
                secret.as_deref(),
                secret_file.as_deref(),
                auth_secret.as_deref(),
            )?;
            let count = verify_tool_proxy_log(&log, resolved.as_bytes())?;
            println!("ok: verified {} tool-proxy entries", count);
        }
        Command::VerifyChain { log, secret } => {
            let count = verify_lattice_guard_chain(&log, secret.as_deref())?;
            println!("ok: verified {} lattice-guard entries", count);
        }
        Command::Summary { log } => {
            print_summary(&log)?;
        }
        Command::Export { log, format } => {
            export_log(&log, &format)?;
        }
    }

    Ok(())
}

// --- verify (tool-proxy) ---

fn resolve_secret(
    secret: Option<&str>,
    secret_file: Option<&Path>,
    auth_secret: Option<&str>,
) -> Result<String, AuditError> {
    if let Some(s) = secret {
        return Ok(s.to_string());
    }
    if let Some(path) = secret_file {
        let s = std::fs::read_to_string(path)?.trim().to_string();
        if s.is_empty() {
            return Err(AuditError::MissingSecret);
        }
        return Ok(s);
    }
    if let Some(s) = auth_secret {
        return Ok(s.to_string());
    }
    Err(AuditError::MissingSecret)
}

fn verify_tool_proxy_log(path: &Path, secret: &[u8]) -> Result<usize, AuditError> {
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
        let entry: ToolProxyEntry =
            serde_json::from_str(line).map_err(|source| AuditError::Json {
                line: line_no,
                source,
            })?;
        if entry.prev_hash != prev_hash {
            return Err(AuditError::Invalid {
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
            return Err(AuditError::Invalid {
                line: line_no,
                message: "signature mismatch".to_string(),
            });
        }
        let hash = sha256_hex(&format!("{}|{}", message, signature));
        if hash != entry.hash {
            return Err(AuditError::Invalid {
                line: line_no,
                message: "hash mismatch".to_string(),
            });
        }
        prev_hash = entry.hash.clone();
        count += 1;
    }

    Ok(count)
}

// --- verify-chain (lattice-guard) ---

fn verify_lattice_guard_chain(path: &Path, secret: Option<&str>) -> Result<usize, AuditError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut entries: Vec<lattice_guard::AuditEntry> = Vec::new();

    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let line_no = idx + 1;

        // Try signed format first (FileAuditBackend), then raw entry
        let entry: lattice_guard::AuditEntry =
            if let Ok(signed) = serde_json::from_str::<SignedLine>(line) {
                // Verify HMAC if secret provided
                if let Some(secret) = secret {
                    let entry_str = serde_json::to_string(&signed.entry)
                        .map_err(|e| AuditError::Backend(e.to_string()))?;
                    let expected = hmac_hex(secret.as_bytes(), entry_str.as_bytes());
                    if expected != signed.hmac {
                        return Err(AuditError::Invalid {
                            line: line_no,
                            message: "HMAC verification failed".to_string(),
                        });
                    }
                }
                serde_json::from_value(signed.entry).map_err(|source| AuditError::Json {
                    line: line_no,
                    source,
                })?
            } else {
                serde_json::from_str(line).map_err(|source| AuditError::Json {
                    line: line_no,
                    source,
                })?
            };

        entries.push(entry);
    }

    // Verify hash chain linkage
    if !entries.is_empty() {
        if entries[0].prev_hash.is_some() {
            return Err(AuditError::Invalid {
                line: 1,
                message: "genesis entry has non-None prev_hash".to_string(),
            });
        }

        for i in 1..entries.len() {
            let expected = entries[i - 1].content_hash();
            match &entries[i].prev_hash {
                Some(actual) if *actual == expected => {}
                Some(actual) => {
                    return Err(AuditError::Invalid {
                        line: i + 1,
                        message: format!(
                            "hash chain broken: expected {}, got {}",
                            expected, actual
                        ),
                    });
                }
                None => {
                    return Err(AuditError::Invalid {
                        line: i + 1,
                        message: "missing prev_hash on non-genesis entry".to_string(),
                    });
                }
            }
        }
    }

    Ok(entries.len())
}

// --- summary ---

fn print_summary(path: &Path) -> Result<(), AuditError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut by_event: HashMap<String, usize> = HashMap::new();
    let mut by_actor: HashMap<String, usize> = HashMap::new();
    let mut by_result: HashMap<String, usize> = HashMap::new();
    let mut total = 0usize;

    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry: ToolProxyEntry =
            serde_json::from_str(line).map_err(|source| AuditError::Json {
                line: idx + 1,
                source,
            })?;

        *by_event.entry(entry.event).or_insert(0) += 1;
        let actor = entry.actor.unwrap_or_else(|| "<none>".to_string());
        *by_actor.entry(actor).or_insert(0) += 1;
        let result_key = if entry.result.starts_with("denied") {
            "denied".to_string()
        } else {
            entry.result
        };
        *by_result.entry(result_key).or_insert(0) += 1;
        total += 1;
    }

    println!("=== Audit Log Summary ===");
    println!("Total entries: {}", total);
    println!();

    println!("By event type:");
    let mut events: Vec<_> = by_event.into_iter().collect();
    events.sort_by(|a, b| b.1.cmp(&a.1));
    for (event, count) in &events {
        println!("  {:<30} {}", event, count);
    }
    println!();

    println!("By actor:");
    let mut actors: Vec<_> = by_actor.into_iter().collect();
    actors.sort_by(|a, b| b.1.cmp(&a.1));
    for (actor, count) in &actors {
        println!("  {:<30} {}", actor, count);
    }
    println!();

    println!("By result:");
    let mut results: Vec<_> = by_result.into_iter().collect();
    results.sort_by(|a, b| b.1.cmp(&a.1));
    for (result, count) in &results {
        println!("  {:<30} {}", result, count);
    }

    Ok(())
}

// --- export ---

fn export_log(path: &Path, format: &ExportFormat) -> Result<(), AuditError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut entries: Vec<serde_json::Value> = Vec::new();

    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry: serde_json::Value =
            serde_json::from_str(line).map_err(|source| AuditError::Json {
                line: idx + 1,
                source,
            })?;
        entries.push(entry);
    }

    match format {
        ExportFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&entries).unwrap());
        }
        ExportFormat::Jsonl => {
            for entry in &entries {
                println!("{}", serde_json::to_string(entry).unwrap());
            }
        }
    }

    Ok(())
}

// --- crypto helpers ---

fn sign_message(secret: &[u8], message: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
    mac.update(message);
    hex::encode(mac.finalize().into_bytes())
}

fn hmac_hex(secret: &[u8], message: &[u8]) -> String {
    sign_message(secret, message)
}

fn sha256_hex(message: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    hex::encode(hasher.finalize())
}

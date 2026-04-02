//! Receipt persistence — append-only JSONL audit trail.
//!
//! Extracted from `main.rs` to reduce module size.

use portcullis::receipt_sign::receipt_hash;
use portcullis::Operation;
use serde::Serialize;

use crate::session::{sanitize_session_id, session_dir};

// ---------------------------------------------------------------------------
// Receipt persistence — append-only JSONL audit trail
// ---------------------------------------------------------------------------

/// Serializable receipt entry for the JSONL audit file.
#[derive(Serialize)]
struct ReceiptEntry {
    /// Unix timestamp
    timestamp: u64,
    /// Operation name
    operation: String,
    /// Subject (file path, URL, command, etc.)
    subject: String,
    /// "allow", "deny", or "ask"
    verdict: String,
    /// Flow rule that fired (for denials)
    rule: String,
    /// Action node label
    action_label: String,
    /// Causal ancestors (node kind + label summary)
    ancestors: Vec<String>,
    /// Ed25519 signature (hex)
    signature: String,
    /// Previous receipt hash (hex) — chain link
    prev_hash: String,
    /// This receipt's hash (hex) — for the next receipt's prev_hash
    receipt_hash: String,
    /// Parent agent's session ID (if this is a child session)
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_session_id: Option<String>,
    /// Parent agent's chain hash at spawn time (if child session)
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_chain_hash: Option<String>,
    /// Active compartment when this decision was made
    #[serde(skip_serializing_if = "Option::is_none")]
    compartment: Option<String>,
    /// Previous compartment (if this entry records a transition)
    #[serde(skip_serializing_if = "Option::is_none")]
    compartment_transition_from: Option<String>,
    /// True if signing was attempted but failed (#902).
    /// An unsigned receipt in a chain that should be signed indicates
    /// key corruption, low entropy, or sandboxed environment.
    #[serde(default, skip_serializing_if = "is_false")]
    signing_failed: bool,
}

fn is_false(v: &bool) -> bool {
    !v
}

/// Persist a signed receipt to `.nucleus/receipts/<session-id>.jsonl`.
///
/// Append-only JSONL — one receipt per line. Creates the directory
/// and file if they don't exist. Failures are silent (audit is
/// best-effort, not on the critical path).
#[allow(clippy::too_many_arguments)]
pub(crate) fn persist_receipt(
    session_id: &str,
    receipt: &portcullis_core::receipt::FlowReceipt,
    operation: Operation,
    subject: &str,
    parent_session_id: &Option<String>,
    parent_chain_hash: &Option<String>,
    compartment: Option<&str>,
    signing_failed: bool,
) {
    let safe_id = sanitize_session_id(session_id);
    let receipts_dir = session_dir().join("receipts");
    std::fs::create_dir_all(&receipts_dir).ok();
    let path = receipts_dir.join(format!("{safe_id}.jsonl"));

    let entry = ReceiptEntry {
        timestamp: receipt.created_at(),
        operation: operation.to_string(),
        subject: subject.to_string(),
        verdict: format!("{:?}", receipt.verdict()),
        rule: receipt.rule_name().to_string(),
        action_label: format!(
            "conf={:?} integ={:?} auth={:?}",
            receipt.action().label.confidentiality,
            receipt.action().label.integrity,
            receipt.action().label.authority,
        ),
        ancestors: receipt
            .ancestors()
            .iter()
            .map(|a| {
                format!(
                    "{:?} conf={:?} integ={:?} auth={:?}",
                    a.kind, a.label.confidentiality, a.label.integrity, a.label.authority,
                )
            })
            .collect(),
        signature: hex::encode(receipt.signature_bytes()),
        prev_hash: hex::encode(receipt.prev_hash()),
        receipt_hash: hex::encode(receipt_hash(receipt)),
        parent_session_id: parent_session_id.clone(),
        parent_chain_hash: parent_chain_hash.clone(),
        compartment: compartment.map(|s| s.to_string()),
        compartment_transition_from: None,
        signing_failed,
    };

    if let Ok(json) = serde_json::to_string(&entry) {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            writeln!(file, "{json}").ok();
        }
    }
}

/// Emit a signed receipt for a compartment transition (#898).
///
/// Unlike the old version, this receipt is properly chained: it uses the
/// session's `chain_head_hash` as `prev_hash`, computes a `receipt_hash`,
/// signs with the session key, and updates `chain_head_hash` in session state.
pub(crate) fn persist_transition_receipt(
    session_id: &str,
    from: Option<&str>,
    to: &str,
    direction: &str,
) {
    use crate::session::with_session;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let subject = format!("{} -> {} ({direction})", from.unwrap_or("none"), to);

    // Atomically load session, compute chain link, sign, and update chain head.
    let mut built_entry: Option<ReceiptEntry> = None;
    let target = to.to_string();
    let from_str = from.map(|s| s.to_string());

    let result = with_session(session_id, |s| {
        let prev_hash = s.chain_head_hash;

        // Compute receipt hash over canonical fields.
        let hash: [u8; 32] = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(now.to_le_bytes());
            h.update(b"compartment_transition");
            h.update(subject.as_bytes());
            h.update(b"Allow");
            h.update(prev_hash);
            h.finalize().into()
        };

        // Sign the hash with the session key.
        let signature = if !s.signing_key_pkcs8.is_empty() {
            use ring::signature::Ed25519KeyPair;
            if let Ok(key) = Ed25519KeyPair::from_pkcs8(&s.signing_key_pkcs8) {
                let sig = key.sign(&hash);
                hex::encode(sig.as_ref())
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        // Update chain head.
        s.chain_head_hash = hash;
        let sign_failed = signature.is_empty();

        built_entry = Some(ReceiptEntry {
            timestamp: now,
            operation: "compartment_transition".to_string(),
            subject: subject.clone(),
            verdict: "Allow".to_string(),
            rule: "compartment_transition".to_string(),
            action_label: String::new(),
            ancestors: vec![],
            signature,
            prev_hash: hex::encode(prev_hash),
            receipt_hash: hex::encode(hash),
            parent_session_id: None,
            parent_chain_hash: None,
            compartment: Some(target.clone()),
            compartment_transition_from: from_str.clone(),
            signing_failed: sign_failed,
        });
    });

    let Some(entry) = result.and(built_entry) else {
        return;
    };

    let safe_id = sanitize_session_id(session_id);
    let receipts_dir = session_dir().join("receipts");
    std::fs::create_dir_all(&receipts_dir).ok();
    let path = receipts_dir.join(format!("{safe_id}.jsonl"));

    if let Ok(json) = serde_json::to_string(&entry) {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            writeln!(file, "{json}").ok();
        }
    }
}

/// Display receipts for a session (`--receipts` CLI handler).
pub(crate) fn show_receipts(session_id: &str) {
    let safe_id = sanitize_session_id(session_id);
    let receipts_dir = session_dir().join("receipts");
    let path = receipts_dir.join(format!("{safe_id}.jsonl"));

    if !path.exists() {
        println!("No receipts found for session '{session_id}'");
        return;
    }

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            println!("Failed to read receipts: {e}");
            return;
        }
    };

    let mut count = 0u32;
    let mut allowed = 0u32;
    let mut denied = 0u32;
    let mut unsigned = 0u32;
    let mut chain_breaks = 0u32;
    let mut expected_prev_hash = String::new(); // empty for the first receipt

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) {
            let op = entry["operation"].as_str().unwrap_or("?");
            let subject = entry["subject"].as_str().unwrap_or("?");
            let verdict = entry["verdict"].as_str().unwrap_or("?");
            let comp = entry["compartment"].as_str().unwrap_or("");
            let sig = entry["signature"].as_str().unwrap_or("");
            let prev = entry["prev_hash"].as_str().unwrap_or("");
            let hash = entry["receipt_hash"].as_str().unwrap_or("");
            let sign_failed = entry["signing_failed"].as_bool().unwrap_or(false);

            // Chain verification (#897): check prev_hash links to prior receipt_hash.
            let chain_ok = if count == 0 {
                true // first receipt has no predecessor
            } else {
                prev == expected_prev_hash
            };
            if !chain_ok {
                chain_breaks += 1;
            }
            expected_prev_hash = hash.to_string();

            // Signature check: empty or all-zero means unsigned.
            let is_unsigned = sig.is_empty() || sig.chars().all(|c| c == '0') || sign_failed;
            if is_unsigned {
                unsigned += 1;
            }

            let verdict_icon = if verdict.contains("Deny") {
                denied += 1;
                "\x1b[31m\u{2717}\x1b[0m"
            } else {
                allowed += 1;
                "\x1b[32m\u{2713}\x1b[0m"
            };

            let chain_icon = if !chain_ok {
                " \x1b[31m[CHAIN BREAK]\x1b[0m"
            } else {
                ""
            };

            let sig_icon = if is_unsigned {
                " \x1b[33m[UNSIGNED]\x1b[0m"
            } else {
                ""
            };

            let comp_tag = if comp.is_empty() {
                String::new()
            } else {
                format!(" [{comp}]")
            };

            let short = if subject.len() > 50 {
                format!("{}...", &subject[..47])
            } else {
                subject.to_string()
            };

            println!("  {verdict_icon} {op:<25} {short}{comp_tag}{chain_icon}{sig_icon}");
            count += 1;
        }
    }

    println!();
    println!("Total: {count} receipts ({allowed} allowed, {denied} denied)");

    // Chain integrity summary (#897).
    if chain_breaks > 0 {
        println!("\x1b[31mChain integrity: BROKEN — {chain_breaks} break(s) detected\x1b[0m");
    } else if count > 0 {
        println!("\x1b[32mChain integrity: intact ({count} linked receipts)\x1b[0m");
    }
    if unsigned > 0 {
        println!("\x1b[33mSignature status: {unsigned}/{count} receipts unsigned\x1b[0m");
    } else if count > 0 {
        println!("\x1b[32mSignature status: all {count} receipts signed\x1b[0m");
    }

    println!("Chain file: {}", path.display());
}

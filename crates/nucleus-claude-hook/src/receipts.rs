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
}

/// Persist a signed receipt to `.nucleus/receipts/<session-id>.jsonl`.
///
/// Append-only JSONL — one receipt per line. Creates the directory
/// and file if they don't exist. Failures are silent (audit is
/// best-effort, not on the critical path).
pub(crate) fn persist_receipt(
    session_id: &str,
    receipt: &portcullis_core::receipt::FlowReceipt,
    operation: Operation,
    subject: &str,
    parent_session_id: &Option<String>,
    parent_chain_hash: &Option<String>,
    compartment: Option<&str>,
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

/// Emit a synthetic receipt for a compartment transition.
pub(crate) fn persist_transition_receipt(
    session_id: &str,
    from: Option<&str>,
    to: &str,
    direction: &str,
) {
    let safe_id = sanitize_session_id(session_id);
    let receipts_dir = session_dir().join("receipts");
    std::fs::create_dir_all(&receipts_dir).ok();
    let path = receipts_dir.join(format!("{safe_id}.jsonl"));

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let entry = ReceiptEntry {
        timestamp: now,
        operation: "compartment_transition".to_string(),
        subject: format!("{} -> {} ({direction})", from.unwrap_or("none"), to),
        verdict: "Allow".to_string(),
        rule: "compartment_transition".to_string(),
        action_label: String::new(),
        ancestors: vec![],
        signature: String::new(),
        prev_hash: String::new(),
        receipt_hash: String::new(),
        parent_session_id: None,
        parent_chain_hash: None,
        compartment: Some(to.to_string()),
        compartment_transition_from: from.map(|s| s.to_string()),
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

    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) {
            let op = entry["operation"].as_str().unwrap_or("?");
            let subject = entry["subject"].as_str().unwrap_or("?");
            let verdict = entry["verdict"].as_str().unwrap_or("?");
            let comp = entry["compartment"].as_str().unwrap_or("");

            let icon = if verdict.contains("Deny") {
                denied += 1;
                "\x1b[31m\u{2717}\x1b[0m"
            } else {
                allowed += 1;
                "\x1b[32m\u{2713}\x1b[0m"
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

            println!("  {icon} {op:<25} {short}{comp_tag}");
            count += 1;
        }
    }

    println!();
    println!("Total: {count} receipts ({allowed} allowed, {denied} denied)");
    println!("Chain file: {}", path.display());
}

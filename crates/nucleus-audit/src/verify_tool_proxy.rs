//! `nucleus-audit verify`: the tool-proxy's HMAC-chained audit log.
//!
//! Moved out of `main.rs` unchanged apart from reading lines through
//! [`crate::record_lines`], so a torn tail and an altered line are told apart.

use std::path::Path;

use crate::{AuditError, ToolProxyEntry, sha256_hex, sign_message};

pub(crate) fn verify_tool_proxy_log(path: &Path, secret: &[u8]) -> Result<usize, AuditError> {
    let mut lines = crate::record_lines::open(path)?;
    let mut prev_hash = String::new();
    let mut count = 0usize;

    for item in &mut lines {
        let (line_no, line) = item?;
        let entry: ToolProxyEntry = crate::record_lines::parse(line_no, &line)?;
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
        // MUST mirror the writer's preimage exactly (`AuditLog::log` in
        // nucleus-tool-proxy): the drand round, when present, is appended as
        // `|drand:{round}` and IS signed. Reconstructing without it is what made
        // every drand-anchored log fail verification.
        let drand_part = entry
            .drand_round
            .map(|r| format!("|drand:{r}"))
            .unwrap_or_default();
        let message = format!(
            "{}|{}|{}|{}|{}|{}{}",
            entry.timestamp_unix,
            actor,
            entry.event,
            entry.subject,
            entry.result,
            prev_hash,
            drand_part
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

    lines.finish(count)?;
    Ok(count)
}

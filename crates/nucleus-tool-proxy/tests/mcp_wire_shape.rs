//! The bytes an MCP client reads from `nucleus-tool-proxy --mcp`.
//!
//! Every tool in `src/mcp.rs` answers with `CallToolResult::success` or
//! `CallToolResult::error` over a single `ContentBlock::text`. rmcp 2.x renamed
//! the 1.x `Content` to `ContentBlock`, and the rename is meant to be
//! wire-compatible. This pins that: the legacy JSON below is what rmcp 1.8's
//! `Content::text` produced, so a dependency bump that adds a field or renames
//! a tag reds here rather than in a client.
//!
//! rmcp 3.x added `"resultType": "complete"` to every result, which protocol
//! version 2026-07-28 requires. Its server handler removes the field again
//! (`ServerResult::strip_result_type_for_legacy_peer`) before answering a peer
//! that negotiated an older version, so those clients keep the 1.8 bytes. Both
//! shapes are pinned: the legacy one after the step the handler applies, and
//! the current one as constructed.
//!
//! It lives outside `src/mcp.rs` because that file sits at its line ceiling.
#![cfg(feature = "mcp")]

use rmcp::model::{CallToolResult, ContentBlock, ServerResult};
use serde_json::{Value, json};

/// What a peer on a protocol version before 2026-07-28 receives.
fn legacy_wire(result: CallToolResult) -> Value {
    let mut result = ServerResult::CallToolResult(result);
    result.strip_result_type_for_legacy_peer();
    serde_json::to_value(result).expect("ServerResult serializes")
}

/// What a peer on protocol version 2026-07-28 or later receives.
fn current_wire(result: CallToolResult) -> Value {
    serde_json::to_value(result).expect("CallToolResult serializes")
}

#[test]
fn an_error_result_is_one_text_block_flagged_as_error() {
    let err = || CallToolResult::error(vec![ContentBlock::text("denied")]);
    assert_eq!(
        legacy_wire(err()),
        json!({
            "content": [{"type": "text", "text": "denied"}],
            "isError": true,
        })
    );
    assert_eq!(
        current_wire(err()),
        json!({
            "resultType": "complete",
            "content": [{"type": "text", "text": "denied"}],
            "isError": true,
        })
    );
}

#[test]
fn a_success_result_is_one_text_block_not_flagged() {
    let ok = || CallToolResult::success(vec![ContentBlock::text("ok")]);
    assert_eq!(
        legacy_wire(ok()),
        json!({
            "content": [{"type": "text", "text": "ok"}],
            "isError": false,
        })
    );
    assert_eq!(
        current_wire(ok()),
        json!({
            "resultType": "complete",
            "content": [{"type": "text", "text": "ok"}],
            "isError": false,
        })
    );
}

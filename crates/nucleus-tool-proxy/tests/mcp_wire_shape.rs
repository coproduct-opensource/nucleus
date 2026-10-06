//! The bytes an MCP client reads from `nucleus-tool-proxy --mcp`.
//!
//! Every tool in `src/mcp.rs` answers with `CallToolResult::success` or
//! `CallToolResult::error` over a single `ContentBlock::text`. rmcp 2.x renamed
//! the 1.x `Content` to `ContentBlock`, and the rename is meant to be
//! wire-compatible. This pins that: the JSON below is what rmcp 1.8's
//! `Content::text` produced, so a dependency bump that adds a field or renames
//! a tag reds here rather than in a client.
//!
//! It lives outside `src/mcp.rs` because that file sits at its line ceiling.
#![cfg(feature = "mcp")]

use rmcp::model::{CallToolResult, ContentBlock};
use serde_json::json;

#[test]
fn an_error_result_is_one_text_block_flagged_as_error() {
    let err = serde_json::to_value(CallToolResult::error(vec![ContentBlock::text("denied")]))
        .expect("CallToolResult serializes");
    assert_eq!(
        err,
        json!({
            "content": [{"type": "text", "text": "denied"}],
            "isError": true,
        })
    );
}

#[test]
fn a_success_result_is_one_text_block_not_flagged() {
    let ok = serde_json::to_value(CallToolResult::success(vec![ContentBlock::text("ok")]))
        .expect("CallToolResult serializes");
    assert_eq!(
        ok,
        json!({
            "content": [{"type": "text", "text": "ok"}],
            "isError": false,
        })
    );
}

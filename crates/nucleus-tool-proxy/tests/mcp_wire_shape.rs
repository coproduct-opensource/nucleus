//! The bytes an MCP client reads from `nucleus-tool-proxy --mcp`.
//!
//! Every tool in `src/mcp.rs` answers with `CallToolResult::success` or
//! `CallToolResult::error` over a single `ContentBlock::text`. Patched rmcp 3.9
//! adds the complete-result discriminator while retaining content and isError.
//! The earlier exact-shape test caught that additive change during the security
//! upgrade. Pin the complete result explicitly; task/input-required results
//! must not be mistaken for a completed tool operation.
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
            "resultType": "complete",
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
            "resultType": "complete",
            "content": [{"type": "text", "text": "ok"}],
            "isError": false,
        })
    );
}

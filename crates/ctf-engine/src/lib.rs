//! CTF Engine — "The Vault"
//!
//! A browser-native CTF where players try to exfiltrate secrets from
//! a formally verified permission lattice. Runs entirely in WASM.
//!
//! Each level uses a real portcullis `PermissionLattice` profile and
//! tracks exposure via the same `ExposureSet` that production nucleus
//! uses. Verdicts are backed by Verus SMT proofs.

mod level;
mod sandbox;
mod engine;

pub use engine::CtfEngine;
pub use level::{Defense, Level, LevelMeta};
pub use sandbox::{ToolCall, Verdict, StepResult, AttackResult};

use wasm_bindgen::prelude::*;

// ── WASM API ────────────────────────────────────────────────────────────

/// Get metadata for all levels as JSON.
#[wasm_bindgen]
pub fn get_levels() -> JsValue {
    let metas: Vec<LevelMeta> = (1..=7).map(|n| Level::new(n).meta()).collect();
    serde_wasm_bindgen::to_value(&metas).unwrap_or(JsValue::NULL)
}

/// Get metadata for a single level as JSON.
#[wasm_bindgen]
pub fn get_level(level: u8) -> JsValue {
    let meta = Level::new(level).meta();
    serde_wasm_bindgen::to_value(&meta).unwrap_or(JsValue::NULL)
}

/// Run an attack sequence against a level.
///
/// `tool_calls_json` is a JSON array of `{"tool": "...", "args": {...}}` objects.
/// Returns an `AttackResult` as JSON.
#[wasm_bindgen]
pub fn submit_attack(level: u8, tool_calls_json: &str) -> JsValue {
    let tool_calls: Vec<ToolCall> = match serde_json::from_str(tool_calls_json) {
        Ok(tc) => tc,
        Err(e) => {
            let err = AttackResult::parse_error(format!("Invalid JSON: {e}"));
            return serde_wasm_bindgen::to_value(&err).unwrap_or(JsValue::NULL);
        }
    };
    let lvl = Level::new(level);
    let mut eng = CtfEngine::new(&lvl);
    let result = eng.run_attack(&tool_calls);
    serde_wasm_bindgen::to_value(&result).unwrap_or(JsValue::NULL)
}

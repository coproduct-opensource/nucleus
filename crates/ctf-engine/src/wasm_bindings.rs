//! WASM bindings for the CTF engine.
//!
//! Only compiled when the `wasm` feature is enabled.
//! Called by trunk's auto-init after WASM loads.

use wasm_bindgen::prelude::*;

use crate::{AttackResult, CtfEngine, Level, LevelMeta, ToolCall};

/// Called by trunk's auto-init after WASM loads.
/// Bridges WASM bindings to the external ctf.js app script via window.__initCtf.
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    let ctf = js_sys::Object::new();

    let gl = wasm_bindgen::closure::Closure::wrap(Box::new(get_levels) as Box<dyn Fn() -> JsValue>);
    js_sys::Reflect::set(&ctf, &"get_levels".into(), gl.as_ref().unchecked_ref()).ok();
    gl.forget();

    let sa = wasm_bindgen::closure::Closure::wrap(Box::new(|level: u8, json: String| {
        submit_attack(level, &json)
    }) as Box<dyn Fn(u8, String) -> JsValue>);
    js_sys::Reflect::set(&ctf, &"submit_attack".into(), sa.as_ref().unchecked_ref()).ok();
    sa.forget();

    // Always store the ctf object so ctf.js can pick it up after DOM is ready.
    js_sys::Reflect::set(&js_sys::global(), &"__ctf".into(), &ctf).ok();

    if let Ok(init_fn) = js_sys::Reflect::get(&js_sys::global(), &"__initCtf".into()) {
        if init_fn.is_function() {
            let f: js_sys::Function = init_fn.unchecked_into();
            f.call1(&JsValue::NULL, &ctf).ok();
        }
    }
}

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

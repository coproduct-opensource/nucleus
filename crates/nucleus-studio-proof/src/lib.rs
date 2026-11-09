//! Independent, credential-free Studio change proof checking.
//! Certificate production and checking are distinct: generated Lean text is
//! untrusted until its exact statement and proof have been checked.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
mod codec;
pub mod envelope;
pub mod export;
pub mod producer;
#[cfg(test)]
mod tests;

/// Compressed transport bounds do not enlarge the 16 MiB app packet limit.
/// Malformed proof terms may trap in nanoda: browser callers must discard the
/// worker and report refusal, never reuse the trapped Wasm instance.
pub fn verify_compressed(
    base: &[u8],
    delta: &[u8],
    packet: &[u8],
) -> Result<export::VerifiedContract, String> {
    use std::io::Read as _;
    fn inflate(bytes: &[u8], limit: usize) -> Result<Vec<u8>, String> {
        let mut out = vec![];
        flate2::read::GzDecoder::new(bytes)
            .take((limit + 1) as u64)
            .read_to_end(&mut out)
            .map_err(|e| format!("proof compression: {e}"))?;
        if out.len() > limit {
            return Err("expanded proof byte budget".into());
        }
        Ok(out)
    }
    if base.len() > 8 * 1024 * 1024
        || delta.len() > MAX_PACKET_BYTES
        || packet.len() > MAX_PACKET_BYTES
    {
        return Err("compressed certificate byte budget".into());
    }
    let base = inflate(base, export::MAX_BASE_BYTES)?;
    let mut proof = base.clone();
    proof.extend_from_slice(&inflate(delta, MAX_PACKET_BYTES)?);
    export::verify(&base, &proof, packet)
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn check_studio_change(
    base_gzip: &[u8],
    delta_gzip: &[u8],
    packet: &[u8],
) -> Result<String, wasm_bindgen::JsValue> {
    let checked = verify_compressed(base_gzip, delta_gzip, packet)
        .map_err(|e| wasm_bindgen::JsValue::from_str(&e))?;
    serde_json::to_string(&checked).map_err(|e| wasm_bindgen::JsValue::from_str(&e.to_string()))
}

pub const MAX_PACKET_BYTES: usize = 16 * 1024 * 1024;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn check_signed_studio_change(
    base_gzip: &[u8],
    envelope_json: &[u8],
    expected_origin: &str,
    expected_rp_id: &str,
) -> Result<String, wasm_bindgen::JsValue> {
    let checked = envelope::verify_bytes(
        base_gzip,
        envelope_json,
        envelope::Context {
            origin: expected_origin,
            rp_id: expected_rp_id,
        },
    )
    .map_err(|e| wasm_bindgen::JsValue::from_str(&e))?;
    serde_json::to_string(&checked).map_err(|e| wasm_bindgen::JsValue::from_str(&e.to_string()))
}

/// Public contracts and captured authority hashes; never business records.
/// Literal decoding is a wire boundary; Lean checks visible recipe meaning.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Packet {
    pub old_recipe: Value,
    pub new_recipe: Value,
    pub before: Value,
    pub after: Value,
    pub authority_before: String,
    pub authority_after: String,
}

pub fn canonical_packet(bytes: &[u8]) -> Result<String, String> {
    if bytes.len() > MAX_PACKET_BYTES {
        return Err("packet exceeds 16 MiB".into());
    }
    let packet: Packet = serde_json::from_slice(bytes).map_err(|e| format!("packet: {e}"))?;
    let value = serde_json::to_value(&packet).map_err(|e| format!("packet: {e}"))?;
    String::from_utf8(canonical_bytes(&value)?).map_err(|e| format!("canonical packet: {e}"))
}

/// This protocol's numeric fields are natural safe integers. Reject values
/// before JCS can round them into a different contract or signed subject.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>, String> {
    fn check(value: &Value) -> Result<(), String> {
        match value {
            Value::Number(n) => {
                let n = n
                    .as_u64()
                    .ok_or("natural integer required for canonical commitment")?;
                if n > 9_007_199_254_740_991 {
                    return Err("integer exceeds canonical commitment range".into());
                }
            }
            Value::Array(values) => {
                for value in values {
                    check(value)?;
                }
            }
            Value::Object(values) => {
                for value in values.values() {
                    check(value)?;
                }
            }
            Value::Null | Value::Bool(_) | Value::String(_) => {}
        }
        Ok(())
    }
    check(value)?;
    serde_jcs::to_vec(value).map_err(|e| format!("canonical commitment: {e}"))
}

fn lean_string(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{{{:x}}}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Produces a closed decision term. `decide`, rather than `native_decide`,
/// leaves reduction to the independent kernel; no compiler-trust axiom.
pub fn witness_source(packet: &[u8]) -> Result<String, String> {
    let canonical = canonical_packet(packet)?;
    let packet: Packet = serde_json::from_str(&canonical).map_err(|e| format!("packet: {e}"))?;
    let typed = typed_packet(&packet)?;
    let literal = codec::quote("TypedPacket", &typed, 0)?;
    Ok(format!(
        "import StudioCertificate\n\nset_option maxRecDepth 100000\nset_option maxHeartbeats 10000000\nnamespace StudioCertificateWitness\ntheorem accepted : StudioCertificate.checkTyped {} = true := by decide +kernel\n#print axioms accepted\nend StudioCertificateWitness\n",
        literal
    ))
}

fn only_keys(value: &Value, allowed: &[&str]) -> Result<(), String> {
    let object = value.as_object().ok_or("object required")?;
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("unknown recipe field".into());
    }
    Ok(())
}

fn visible(recipe: &Value) -> Result<Value, String> {
    only_keys(
        recipe,
        &[
            "slug",
            "title",
            "category",
            "description",
            "record_name",
            "prefix",
            "pattern",
            "fields",
            "stages",
            "checks",
            "accent",
            "sample",
        ],
    )?;
    if recipe["pattern"] != "equipment"
        || recipe["stages"] != json!(["available", "checked_out"])
        || recipe["checks"] != json!([])
    {
        return Err("Equipment recipe required".into());
    }
    let fields = recipe["fields"]
        .as_array()
        .ok_or("visible fields required")?;
    if fields.is_empty() || fields.len() > 16 {
        return Err("visible field limit".into());
    }
    let mut names = std::collections::BTreeSet::new();
    let mut typed = vec![];
    for field in fields {
        only_keys(field, &["key", "label", "kind", "help"])?;
        only_keys(
            &field["kind"],
            if field["kind"]["type"] == "choice" {
                &["type", "options"]
            } else {
                &["type"]
            },
        )?;
        let key = field["key"].as_str().ok_or("field key required")?;
        let label = field["label"].as_str().ok_or("field label required")?;
        let kind = field["kind"]["type"]
            .as_str()
            .ok_or("field kind required")?;
        if !names.insert(key)
            || !["text", "note", "money", "number", "day", "time", "choice"].contains(&kind)
        {
            return Err("unknown or repeated visible field".into());
        }
        if key == "email" && !["text", "note", "choice"].contains(&kind) {
            return Err("email kind differs".into());
        }
        let choices = if kind == "choice" {
            let values = field["kind"]["options"]
                .as_array()
                .ok_or("choice values required")?;
            let mut unique = std::collections::BTreeSet::new();
            for value in values {
                if !unique.insert(value.as_str().ok_or("choice string required")?) {
                    return Err("duplicate choice".into());
                }
            }
            if values.is_empty() {
                return Err("choice values required".into());
            }
            Value::Array(values.clone())
        } else {
            json!([])
        };
        typed.push(json!({"key":key,"label":label,"kind":kind,"choices":choices}));
    }
    let stem = recipe["prefix"].as_str().ok_or("prefix required")?;
    if stem.is_empty() || stem.len() > 8 || !names.contains("tag") {
        return Err("invalid Equipment fields or prefix".into());
    }
    Ok(json!({"stem":stem,"fields":typed}))
}

fn typed_packet(packet: &Packet) -> Result<Value, String> {
    Ok(json!({
        "oldVisible":visible(&packet.old_recipe)?, "newVisible":visible(&packet.new_recipe)?,
        "before":packet.before, "after":packet.after,
        "authorityBefore":packet.authority_before, "authorityAfter":packet.authority_after
    }))
}

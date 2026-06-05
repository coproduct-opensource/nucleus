//! x402 transport helpers.
//!
//! x402 carries the payment payload in a base64-encoded JSON `X-PAYMENT` header.
//! [`parse_payment_header`] decodes it into a [`PaymentProof`]. The exact field
//! names of the x402 payload evolve with the spec version, so the extraction is
//! intentionally tolerant (and documented) rather than pinned to one shape — a
//! deployment can always construct [`PaymentProof`] directly instead.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::Value;

use crate::{CommerceError, PaymentProof};

/// Parse a base64-encoded x402 `X-PAYMENT` header value into a [`PaymentProof`].
///
/// Decodes base64 → JSON, then reads:
/// - `scheme` (top level), defaulting to `"x402"` if absent;
/// - a settlement reference from the first present of
///   `reference`, `transaction`, `txHash`, `nonce`, or
///   `payload.authorization.nonce`.
///
/// Returns [`CommerceError::Backend`] if the header is not valid base64/JSON, or
/// [`CommerceError::Unverified`] if no reference field is present (a payment
/// payload with no reference can't bind a receipt).
pub fn parse_payment_header(header_value: &str) -> Result<PaymentProof, CommerceError> {
    let raw = STANDARD
        .decode(header_value.trim())
        .map_err(|e| CommerceError::Backend(format!("X-PAYMENT not valid base64: {e}")))?;
    let json: Value = serde_json::from_slice(&raw)
        .map_err(|e| CommerceError::Backend(format!("X-PAYMENT not valid JSON: {e}")))?;

    let scheme = json
        .get("scheme")
        .and_then(Value::as_str)
        .unwrap_or("x402")
        .to_string();

    let reference = first_str(&json, &["reference", "transaction", "txHash", "nonce"])
        .or_else(|| {
            json.get("payload")
                .and_then(|p| p.get("authorization"))
                .and_then(|a| a.get("nonce"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .ok_or_else(|| {
            CommerceError::Unverified("X-PAYMENT carries no settlement reference".to_string())
        })?;

    Ok(PaymentProof { scheme, reference })
}

/// First top-level string field present among `keys`.
fn first_str(json: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| json.get(*k).and_then(Value::as_str).map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(json: serde_json::Value) -> String {
        STANDARD.encode(serde_json::to_vec(&json).unwrap())
    }

    #[test]
    fn parses_scheme_and_top_level_reference() {
        let h = b64(serde_json::json!({ "scheme": "x402", "reference": "0xabc" }));
        let p = parse_payment_header(&h).unwrap();
        assert_eq!(p.scheme, "x402");
        assert_eq!(p.reference, "0xabc");
    }

    #[test]
    fn defaults_scheme_and_reads_nested_nonce() {
        let h = b64(serde_json::json!({
            "payload": { "authorization": { "nonce": "n-123" } }
        }));
        let p = parse_payment_header(&h).unwrap();
        assert_eq!(p.scheme, "x402");
        assert_eq!(p.reference, "n-123");
    }

    #[test]
    fn rejects_non_base64() {
        assert!(matches!(
            parse_payment_header("@@@not base64@@@"),
            Err(CommerceError::Backend(_))
        ));
    }

    #[test]
    fn rejects_payload_without_a_reference() {
        let h = b64(serde_json::json!({ "scheme": "x402" }));
        assert!(matches!(
            parse_payment_header(&h),
            Err(CommerceError::Unverified(_))
        ));
    }
}

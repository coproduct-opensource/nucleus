//! Receipts as an A2A v1.0 **spec extension** (§4.6.2 extension data).
//!
//! Extension URI: [`RECEIPT_EXTENSION_URI`]. The receipt bundle travels in
//! the spec's own extension-data carriage point — the `metadata` of the
//! Task / status-update / message / artifact-update object in the response
//! — keyed by the extension URI, exactly like the §4.6.2 examples.
//!
//! ## What bytes does a receipt bind?
//!
//! A receipt cannot bind bytes that contain the receipt itself, so the
//! signed `body_sha256` covers a deterministic **pre-image**, not the raw
//! wire bytes:
//!
//! > RFC 8785 (JCS) canonicalization of the payload JSON with the receipt
//! > entry removed from the carrier object's `metadata` (and `metadata`
//! > itself removed if that leaves it empty).
//!
//! For a non-streaming response the payload is the whole response body
//! JSON. For SSE, receipts are **per event**: the payload is that event's
//! `data:` JSON, and the receipt's `resource` is `"<path>#sse-<n>"` where
//! `n` is the zero-based position of the data event in the stream — so a
//! receipt also attests WHERE in the stream its event appeared. SSE
//! framing (`data: ` prefixes, newlines) and HTTP headers are NOT covered.
//!
//! Verification (any party, offline): parse the payload, remove the
//! receipt entry, `serde_jcs::to_vec`, then check the bundle with
//! `nucleus_verify_commerce::verify_receipt_bundle` (or `verify_receipt_js`
//! in a browser) and compare its `body_sha256` against the SHA-256 of
//! those bytes. See `docs/a2a-receipt-extension.md`.

use std::sync::Arc;

use axum::body::{Body, Bytes};
use futures::StreamExt as _;
use serde_json::Value;

/// The receipt extension URI — both the AgentCard declaration
/// (`capabilities.extensions[].uri`, §4.6.1) and the metadata key the
/// bundle rides under (§4.6.2).
pub const RECEIPT_EXTENSION_URI: &str = "https://coproduct.one/a2a/ext/receipt/v1";

/// Issues a receipt bundle over a pre-image. The `u64` is the zero-based
/// SSE event index (`0` for non-streaming bodies, which have exactly one
/// payload).
pub type IssueReceipt = dyn Fn(&[u8], u64) -> anyhow::Result<Value> + Send + Sync;

/// JSON pointer to the A2A object that carries extension `metadata` in
/// `payload`, if there is one.
///
/// Handles the shapes the SDK's two bindings produce:
/// - JSON-RPC envelopes: `{"result": {"task" | "statusUpdate" | … : {…}}}`
/// - REST / SSE payloads: `{"task" | "statusUpdate" | … : {…}}`
/// - a bare Task object served directly (REST `GetTask`)
///
/// Error envelopes and list responses have no carrier → `None` (the
/// receipt then travels in the header only).
pub fn carrier_pointer(payload: &Value) -> Option<String> {
    fn within(obj: &serde_json::Map<String, Value>, base: &str) -> Option<String> {
        // ProtoJSON oneof keys of SendMessageResponse / StreamResponse.
        for key in ["task", "statusUpdate", "artifactUpdate", "message", "msg"] {
            if obj.get(key).is_some_and(Value::is_object) {
                return Some(format!("{base}/{key}"));
            }
        }
        // A bare Task (REST GetTask returns the Task object directly).
        if obj.contains_key("id") && obj.contains_key("status") {
            return Some(base.to_string());
        }
        None
    }
    let obj = payload.as_object()?;
    if let Some(result) = obj.get("result").and_then(Value::as_object) {
        return within(result, "/result");
    }
    within(obj, "")
}

/// Remove the receipt entry from the carrier's `metadata`; drop `metadata`
/// entirely if that leaves it empty. Exact inverse of [`inject_receipt`].
fn strip_receipt(payload: &mut Value) {
    let Some(ptr) = carrier_pointer(payload) else {
        return;
    };
    let Some(carrier) = payload.pointer_mut(&ptr).and_then(Value::as_object_mut) else {
        return;
    };
    let emptied = match carrier.get_mut("metadata") {
        // A ProtoJSON `null` metadata normalizes to absent — injection
        // replaces it with a map, so stripping must converge the same way.
        Some(Value::Null) => true,
        Some(Value::Object(meta)) => {
            meta.remove(RECEIPT_EXTENSION_URI);
            meta.is_empty()
        }
        _ => false,
    };
    if emptied {
        carrier.remove("metadata");
    }
}

/// The exact bytes a receipt binds: RFC 8785 (JCS) canonical form of
/// `payload` with the receipt entry stripped. Deterministic on both sides
/// — the issuer computes it before injection, a verifier recovers it from
/// the received payload by removing the entry and re-canonicalizing.
pub fn receipt_preimage(payload: &Value) -> anyhow::Result<Vec<u8>> {
    let mut stripped = payload.clone();
    strip_receipt(&mut stripped);
    serde_jcs::to_vec(&stripped).map_err(|e| anyhow::anyhow!("JCS canonicalization: {e}"))
}

/// Place `bundle` into the carrier's `metadata` under the extension URI
/// (§4.6.2). Returns `false` when `payload` has no carrier — error
/// envelopes and list responses keep the header-only receipt.
pub fn inject_receipt(payload: &mut Value, bundle: &Value) -> bool {
    let Some(ptr) = carrier_pointer(payload) else {
        return false;
    };
    let Some(carrier) = payload.pointer_mut(&ptr).and_then(Value::as_object_mut) else {
        return false;
    };
    if let Some(Value::Object(meta)) = carrier.get_mut("metadata") {
        meta.insert(RECEIPT_EXTENSION_URI.to_string(), bundle.clone());
    } else {
        // Absent or ProtoJSON `null` metadata: start a fresh map.
        carrier.insert(
            "metadata".to_string(),
            serde_json::json!({ RECEIPT_EXTENSION_URI: bundle }),
        );
    }
    true
}

/// Wrap an SSE response body so every `data:` event carries its own
/// receipt in the event object's `metadata` (§4.6.2), issued over that
/// event's [`receipt_preimage`].
///
/// The wrapper re-frames events it receipts (`data: <json>\n\n`); frames
/// it cannot parse — or whose payload has no carrier, e.g. mid-stream
/// JSON-RPC error envelopes — pass through byte-for-byte unmodified and
/// simply carry no receipt. Absence of a receipt proves nothing; presence
/// proves the binding.
pub fn per_event_receipts(body: Body, issue: Arc<IssueReceipt>) -> Body {
    let framer = Framer {
        buf: Vec::new(),
        index: 0,
        issue,
    };
    let stream = futures::stream::unfold(
        (body.into_data_stream(), framer, false),
        |(mut input, mut framer, mut ended)| async move {
            loop {
                if let Some(out) = framer.take_complete_frames() {
                    return Some((Ok(out), (input, framer, ended)));
                }
                if ended {
                    // Trailing bytes that never formed a full frame: flush
                    // unmodified rather than swallow them.
                    let rest = framer.take_rest()?;
                    return Some((Ok(rest), (input, framer, ended)));
                }
                match input.next().await {
                    Some(Ok(chunk)) => framer.buf.extend_from_slice(&chunk),
                    Some(Err(e)) => return Some((Err(e), (input, framer, true))),
                    None => ended = true,
                }
            }
        },
    );
    Body::from_stream(stream)
}

/// Buffers SSE bytes, slices complete `\n\n`-terminated frames, and
/// receipts each data event.
struct Framer {
    buf: Vec<u8>,
    /// Zero-based position among data-bearing SSE events — stamped into
    /// each receipt's `resource` as `#sse-<n>`.
    index: u64,
    issue: Arc<IssueReceipt>,
}

impl Framer {
    /// Drain every complete frame currently buffered, processed. `None`
    /// when no full frame is available yet (never an empty chunk — an
    /// empty data frame could terminate a chunked HTTP body early).
    fn take_complete_frames(&mut self) -> Option<Bytes> {
        let mut out = Vec::new();
        while let Some(end) = self.buf.windows(2).position(|w| w == b"\n\n") {
            let frame: Vec<u8> = self.buf.drain(..end + 2).collect();
            out.extend_from_slice(&self.process_frame(&frame));
        }
        (!out.is_empty()).then(|| Bytes::from(out))
    }

    fn take_rest(&mut self) -> Option<Bytes> {
        (!self.buf.is_empty()).then(|| Bytes::from(std::mem::take(&mut self.buf)))
    }

    /// Receipt one SSE frame. Any frame this cannot handle passes through
    /// unmodified (and unreceipted) — never corrupt a live stream.
    fn process_frame(&mut self, frame: &[u8]) -> Vec<u8> {
        let Ok(text) = std::str::from_utf8(frame) else {
            return frame.to_vec();
        };
        // Per the SSE grammar, the event's data is the `data:` lines joined
        // with `\n`; other fields (`event:`, `id:`, comments) pass through.
        let mut data_lines: Vec<&str> = Vec::new();
        let mut other_lines: Vec<&str> = Vec::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("data:") {
                data_lines.push(rest.strip_prefix(' ').unwrap_or(rest));
            } else if !line.is_empty() {
                other_lines.push(line);
            }
        }
        if data_lines.is_empty() {
            return frame.to_vec();
        }
        let event_index = self.index;
        self.index += 1; // every data event occupies a stream position

        let Ok(mut payload) = serde_json::from_str::<Value>(&data_lines.join("\n")) else {
            return frame.to_vec();
        };
        if carrier_pointer(&payload).is_none() {
            return frame.to_vec();
        }
        let Ok(preimage) = receipt_preimage(&payload) else {
            return frame.to_vec();
        };
        let Ok(bundle) = (self.issue)(&preimage, event_index) else {
            return frame.to_vec();
        };
        if !inject_receipt(&mut payload, &bundle) {
            return frame.to_vec();
        }
        let Ok(json) = serde_json::to_string(&payload) else {
            return frame.to_vec();
        };
        let mut out = String::new();
        for line in other_lines {
            out.push_str(line);
            out.push('\n');
        }
        out.push_str("data: ");
        out.push_str(&json);
        out.push_str("\n\n");
        out.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn carrier_pointer_finds_jsonrpc_task() {
        let v = json!({"jsonrpc": "2.0", "id": 1, "result": {"task": {"id": "t1"}}});
        assert_eq!(carrier_pointer(&v).as_deref(), Some("/result/task"));
    }

    #[test]
    fn carrier_pointer_finds_jsonrpc_status_update() {
        let v = json!({"jsonrpc": "2.0", "id": 1, "result": {"statusUpdate": {"taskId": "t1"}}});
        assert_eq!(carrier_pointer(&v).as_deref(), Some("/result/statusUpdate"));
    }

    #[test]
    fn carrier_pointer_finds_rest_shapes() {
        let v = json!({"task": {"id": "t1"}});
        assert_eq!(carrier_pointer(&v).as_deref(), Some("/task"));
        // Bare Task served directly (REST GetTask).
        let v = json!({"id": "t1", "status": {"state": "TASK_STATE_COMPLETED"}});
        assert_eq!(carrier_pointer(&v).as_deref(), Some(""));
    }

    #[test]
    fn error_envelopes_have_no_carrier() {
        // JSON-RPC error envelope: the top-level `id` is the REQUEST id,
        // not a Task id — must not be mistaken for a bare Task.
        let v = json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32009, "message": "x"}});
        assert_eq!(carrier_pointer(&v), None);
        let v = json!({"error": {"code": 400, "message": "x"}});
        assert_eq!(carrier_pointer(&v), None);
    }

    /// The contract everything rests on: pre-image(payload) is invariant
    /// under injection — a verifier stripping the receipt recovers the
    /// exact bytes the issuer signed over.
    #[test]
    fn preimage_is_invariant_under_injection() {
        let bundle = json!({"envelope": {"edges": []}, "payload": {"k": "v"}});
        for payload in [
            json!({"jsonrpc": "2.0", "id": 7, "result": {"task": {"id": "t1", "status": {}}}}),
            json!({"task": {"id": "t1", "status": {}, "metadata": {"keep": 1}}}),
            json!({"result": {"statusUpdate": {"taskId": "t1", "metadata": null}}}),
        ] {
            let before = receipt_preimage(&payload).unwrap();
            let mut injected = payload.clone();
            assert!(inject_receipt(&mut injected, &bundle));
            assert_ne!(payload, injected, "injection must change the payload");
            let after = receipt_preimage(&injected).unwrap();
            assert_eq!(before, after, "stripping must recover the signed bytes");
        }
    }

    #[test]
    fn injection_preserves_existing_metadata() {
        let bundle = json!({"b": 1});
        let mut v = json!({"task": {"id": "t1", "status": {}, "metadata": {"keep": true}}});
        assert!(inject_receipt(&mut v, &bundle));
        assert_eq!(v["task"]["metadata"]["keep"], json!(true));
        assert_eq!(v["task"]["metadata"][RECEIPT_EXTENSION_URI], bundle);
    }

    #[test]
    fn no_carrier_means_no_injection() {
        let bundle = json!({"b": 1});
        let mut v = json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32009}});
        assert!(!inject_receipt(&mut v, &bundle));
    }

    /// SSE frames arriving split across arbitrary chunk boundaries are
    /// reassembled; each data event gets exactly one receipt at its
    /// stream position.
    #[tokio::test]
    async fn per_event_receipts_handles_split_frames() {
        use http_body_util::BodyExt as _;

        let e0 = r#"{"result":{"statusUpdate":{"taskId":"t1","status":{}}}}"#;
        let e1 = r#"{"result":{"task":{"id":"t1","status":{}}}}"#;
        let wire = format!("data: {e0}\n\ndata: {e1}\n\n");
        let (a, b) = wire.split_at(wire.len() / 2 + 3); // split mid-frame
        let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
            Ok(Bytes::copy_from_slice(a.as_bytes())),
            Ok(Bytes::copy_from_slice(b.as_bytes())),
        ];
        let body = Body::from_stream(futures::stream::iter(chunks));

        let issue: Arc<IssueReceipt> =
            Arc::new(|preimage, index| Ok(json!({"index": index, "len": preimage.len()})));
        let out = per_event_receipts(body, issue)
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let text = std::str::from_utf8(&out).unwrap();
        let events: Vec<Value> = text
            .split("\n\n")
            .filter(|f| !f.is_empty())
            .map(|f| serde_json::from_str(f.strip_prefix("data: ").unwrap()).unwrap())
            .collect();
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[0]["result"]["statusUpdate"]["metadata"][RECEIPT_EXTENSION_URI]["index"],
            json!(0)
        );
        assert_eq!(
            events[1]["result"]["task"]["metadata"][RECEIPT_EXTENSION_URI]["index"],
            json!(1)
        );
        // Each receipt was issued over that event's pre-image.
        let pre0 = receipt_preimage(&events[0]).unwrap();
        assert_eq!(
            events[0]["result"]["statusUpdate"]["metadata"][RECEIPT_EXTENSION_URI]["len"],
            json!(pre0.len())
        );
    }
}

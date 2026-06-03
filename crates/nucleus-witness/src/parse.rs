//! Byte-level parsers for the C2SP `POST /add-checkpoint` request body.
//!
//! The request body (per [c2sp.org/tlog-witness]) is:
//!
//! ```text
//! old <N>\n
//! <0..=63 base64 consistency-proof-hash lines, each \n-terminated>
//! \n                                  ← blank line separator
//! <checkpoint signed-note>            ← origin / size / base64(root) / [ext...] / blank / sig lines
//! ```
//!
//! The checkpoint itself is a [c2sp.org/signed-note]: a body (origin
//! line, decimal size, base64 root hash, optional extension lines)
//! followed by a blank line then one or more `— <name> <base64>`
//! signature lines.
//!
//! We REUSE [`nucleus_lineage::parse_signature_line`] for the signature
//! lines and [`nucleus_lineage::SIG_LINE_PREFIX`] for the em-dash
//! detection — no crypto or signed-note logic is reinvented here.
//!
//! [c2sp.org/tlog-witness]: https://c2sp.org/tlog-witness
//! [c2sp.org/signed-note]: https://c2sp.org/signed-note

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use nucleus_lineage::{parse_signature_line, ParsedSignatureLine, SIG_LINE_PREFIX};
use thiserror::Error;

/// The maximum number of consistency-proof lines a client may send
/// (C2SP `tlog-witness`: "MUST NOT send more than 63").
pub const MAX_CONSISTENCY_PROOF_LINES: usize = 63;

/// Errors raised while parsing an add-checkpoint request body. These map
/// to `400 Bad Request` at the HTTP layer (malformed input) UNLESS the
/// status matrix assigns a more specific code; see `server::handle`.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("request body is not valid UTF-8")]
    NotUtf8,
    #[error("request body is missing the `old <N>` line")]
    MissingOldLine,
    #[error("`old` line malformed: expected `old <decimal>`, got {0:?}")]
    BadOldLine(String),
    #[error("request body is missing the blank line separating proof from checkpoint")]
    MissingBlankSeparator,
    #[error("consistency proof has {got} lines; spec caps at {MAX_CONSISTENCY_PROOF_LINES}")]
    TooManyProofLines { got: usize },
    #[error("consistency proof line {line} is not valid base64: {source}")]
    BadProofBase64 {
        line: usize,
        #[source]
        source: base64::DecodeError,
    },
    #[error("consistency proof line {line} decoded to {got} bytes; expected 32")]
    BadProofHashLen { line: usize, got: usize },
    #[error("checkpoint is empty")]
    EmptyCheckpoint,
    #[error("checkpoint body is missing the blank line before the signature lines")]
    MissingCheckpointSigSeparator,
    #[error("checkpoint origin line is empty")]
    EmptyOrigin,
    #[error("checkpoint size line is not a decimal: {0:?}")]
    BadSize(String),
    #[error("checkpoint root-hash line is not valid base64: {0:?}")]
    BadRootBase64(String),
    #[error("checkpoint root hash decoded to {got} bytes; expected 32")]
    BadRootLen { got: usize },
    #[error("checkpoint has no signature lines")]
    NoSignatureLines,
    #[error("checkpoint signature line malformed: {0}")]
    BadSignatureLine(String),
}

/// A parsed add-checkpoint request.
#[derive(Debug, Clone)]
pub struct AddCheckpointRequest {
    /// The `old <N>` size the producer claims the witness last cosigned.
    pub old_size: u64,
    /// Consistency-proof hashes (each 32 bytes), in wire order.
    pub consistency_proof: Vec<[u8; 32]>,
    /// The parsed checkpoint signed-note.
    pub checkpoint: Checkpoint,
}

/// A parsed C2SP checkpoint signed-note.
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Origin line (log identifier).
    pub origin: String,
    /// Tree size (decimal).
    pub size: u64,
    /// 32-byte root hash.
    pub root: [u8; 32],
    /// Optional extension lines between the root and the blank/sig
    /// separator (kept verbatim for completeness; not interpreted).
    pub extensions: Vec<String>,
    /// Signature lines parsed into `(key_name, key_id, signature)`.
    pub signatures: Vec<ParsedSignatureLine>,
    /// The exact note BODY bytes (origin..=last extension line, INCLUDING
    /// the final `\n`, EXCLUDING the blank line and signature lines).
    /// This is what the log key signed AND what the cosignature/v1
    /// message appends — keep it byte-exact.
    pub body_bytes: Vec<u8>,
}

/// Parse a full add-checkpoint request body.
pub fn parse_add_checkpoint(body: &[u8]) -> Result<AddCheckpointRequest, ParseError> {
    let text = std::str::from_utf8(body).map_err(|_| ParseError::NotUtf8)?;

    // Split off the first line: `old <N>`.
    let (old_line, rest) = text.split_once('\n').ok_or(ParseError::MissingOldLine)?;
    let old_size = parse_old_line(old_line)?;

    // The remainder is: <proof lines>\n<blank>\n<checkpoint>. The blank
    // line is the FIRST empty line, which separates the (possibly empty)
    // proof block from the checkpoint. We scan line-by-line until the
    // first empty line; everything before is a proof line.
    let mut consistency_proof = Vec::new();
    let mut checkpoint_start = None;
    let mut cursor = 0usize;
    let mut proof_line_no = 0usize;
    let mut found_blank = false;
    for line in split_keep_offsets(rest) {
        let (content, next_offset) = line;
        if content.is_empty() {
            // Blank separator found. Checkpoint begins after it.
            checkpoint_start = Some(next_offset);
            found_blank = true;
            break;
        }
        proof_line_no += 1;
        if proof_line_no > MAX_CONSISTENCY_PROOF_LINES {
            return Err(ParseError::TooManyProofLines { got: proof_line_no });
        }
        let raw = B64
            .decode(content)
            .map_err(|source| ParseError::BadProofBase64 {
                line: proof_line_no,
                source,
            })?;
        let hash: [u8; 32] =
            raw.as_slice()
                .try_into()
                .map_err(|_| ParseError::BadProofHashLen {
                    line: proof_line_no,
                    got: raw.len(),
                })?;
        consistency_proof.push(hash);
        cursor = next_offset;
    }
    let _ = cursor;

    if !found_blank {
        return Err(ParseError::MissingBlankSeparator);
    }
    let checkpoint_text = &rest[checkpoint_start.unwrap()..];
    if checkpoint_text.trim().is_empty() {
        return Err(ParseError::EmptyCheckpoint);
    }
    let checkpoint = parse_checkpoint(checkpoint_text)?;

    Ok(AddCheckpointRequest {
        old_size,
        consistency_proof,
        checkpoint,
    })
}

/// Parse the `old <N>` line.
fn parse_old_line(line: &str) -> Result<u64, ParseError> {
    let line = line.trim_end_matches('\r');
    let rest = line
        .strip_prefix("old ")
        .ok_or_else(|| ParseError::BadOldLine(line.to_string()))?;
    rest.trim()
        .parse::<u64>()
        .map_err(|_| ParseError::BadOldLine(line.to_string()))
}

/// Parse a checkpoint signed-note: body lines, blank separator, sig
/// lines. The body is `origin\n<size>\n<base64 root>\n[ext\n...]`.
fn parse_checkpoint(text: &str) -> Result<Checkpoint, ParseError> {
    // The signed-note body and signature lines are separated by the
    // FIRST blank line. Everything before is body; everything after is
    // signature lines.
    //
    // We must preserve the EXACT body bytes (including the trailing \n
    // of the last body line) because the log key + cosignature sign over
    // them. We reconstruct body_bytes from the original slice rather than
    // re-joining parsed lines so a stray \r or formatting nuance can't
    // diverge our reconstruction from the producer's signed bytes.

    let mut lines = Vec::new();
    let mut blank_at = None;
    for (content, _next) in split_keep_offsets(text) {
        if content.is_empty() {
            blank_at = Some(lines.len());
            break;
        }
        lines.push(content);
    }
    let blank_at = blank_at.ok_or(ParseError::MissingCheckpointSigSeparator)?;
    let (body_lines, _) = lines.split_at(blank_at);

    if body_lines.len() < 3 {
        // Need at least origin, size, root.
        return Err(ParseError::EmptyOrigin);
    }
    let origin = body_lines[0].to_string();
    if origin.is_empty() {
        return Err(ParseError::EmptyOrigin);
    }
    let size: u64 = body_lines[1]
        .parse()
        .map_err(|_| ParseError::BadSize(body_lines[1].to_string()))?;
    let root_raw = B64
        .decode(body_lines[2])
        .map_err(|_| ParseError::BadRootBase64(body_lines[2].to_string()))?;
    let root: [u8; 32] = root_raw
        .as_slice()
        .try_into()
        .map_err(|_| ParseError::BadRootLen {
            got: root_raw.len(),
        })?;
    let extensions: Vec<String> = body_lines[3..].iter().map(|s| s.to_string()).collect();

    // Reconstruct the exact body bytes: each body line + its '\n'. The
    // blank-line scan above stops at the first empty line, so the body
    // is exactly `origin\nsize\nroot\n[ext\n...]`.
    let mut body_bytes = Vec::new();
    for l in body_lines {
        body_bytes.extend_from_slice(l.as_bytes());
        body_bytes.push(b'\n');
    }

    // Signature lines: every line after the blank that begins with the
    // em-dash prefix. Reuse the lineage parser (handles key_id/sig
    // split, NBSP/control-char rejection, base64 decode).
    let sig_block_start = body_bytes.len() + 1; // +1 for the blank line's \n
    let sig_text = &text[sig_block_start.min(text.len())..];
    let mut signatures = Vec::new();
    for line in sig_text.lines() {
        if !line.starts_with(SIG_LINE_PREFIX) {
            continue;
        }
        let parsed =
            parse_signature_line(line).map_err(|e| ParseError::BadSignatureLine(e.to_string()))?;
        signatures.push(parsed);
    }
    if signatures.is_empty() {
        return Err(ParseError::NoSignatureLines);
    }

    Ok(Checkpoint {
        origin,
        size,
        root,
        extensions,
        signatures,
        body_bytes,
    })
}

/// Iterate `\n`-separated lines, yielding `(line_without_newline,
/// offset_of_next_line)`. A trailing `\r` is stripped. Unlike
/// [`str::lines`], this lets us recover byte offsets so we can slice the
/// checkpoint sub-body exactly.
fn split_keep_offsets(s: &str) -> Vec<(&str, usize)> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' {
            let mut end = i;
            if end > start && bytes[end - 1] == b'\r' {
                end -= 1;
            }
            out.push((&s[start..end], i + 1));
            start = i + 1;
        }
    }
    if start < s.len() {
        let mut end = s.len();
        if end > start && bytes[end - 1] == b'\r' {
            end -= 1;
        }
        out.push((&s[start..end], s.len()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_lineage::{
        ed25519_key_id, format_checkpoint_body, format_signature_line, Ed25519Witness,
        SIG_TYPE_ED25519,
    };

    /// Build a well-formed add-checkpoint body signed by `log_key` under
    /// `key_name`, with the given old_size + proof lines.
    pub(crate) fn build_body(
        log_key: &Ed25519Witness,
        key_name: &str,
        origin: &str,
        size: u64,
        root: &[u8; 32],
        old_size: u64,
        proof: &[[u8; 32]],
    ) -> Vec<u8> {
        let cp_body = format_checkpoint_body(origin, size, root).unwrap();
        let sig = log_key.sign_message(cp_body.as_bytes());
        let key_id = ed25519_key_id(key_name, SIG_TYPE_ED25519, &log_key.verifying_key_bytes());
        let sig_line = format_signature_line(key_name, &key_id, &sig).unwrap();

        let mut body = Vec::new();
        body.extend_from_slice(format!("old {old_size}\n").as_bytes());
        for h in proof {
            body.extend_from_slice(B64.encode(h).as_bytes());
            body.push(b'\n');
        }
        body.push(b'\n'); // blank separator
        body.extend_from_slice(cp_body.as_bytes());
        body.push(b'\n'); // body/sig separator
        body.extend_from_slice(sig_line.as_bytes());
        body.push(b'\n');
        body
    }

    #[test]
    fn parses_minimal_first_submission() {
        let log_key = Ed25519Witness::from_seed([1u8; 32]);
        let body = build_body(
            &log_key,
            "nucleus.example/log",
            "nucleus.example/log",
            5,
            &[0x42u8; 32],
            0,
            &[],
        );
        let req = parse_add_checkpoint(&body).unwrap();
        assert_eq!(req.old_size, 0);
        assert!(req.consistency_proof.is_empty());
        assert_eq!(req.checkpoint.origin, "nucleus.example/log");
        assert_eq!(req.checkpoint.size, 5);
        assert_eq!(req.checkpoint.root, [0x42u8; 32]);
        assert_eq!(req.checkpoint.signatures.len(), 1);
    }

    #[test]
    fn body_bytes_match_signed_checkpoint_body() {
        let log_key = Ed25519Witness::from_seed([2u8; 32]);
        let origin = "nucleus.example/log";
        let body = build_body(&log_key, origin, origin, 9, &[0x11u8; 32], 0, &[]);
        let req = parse_add_checkpoint(&body).unwrap();
        let expected = format_checkpoint_body(origin, 9, &[0x11u8; 32]).unwrap();
        assert_eq!(req.checkpoint.body_bytes, expected.into_bytes());
    }

    #[test]
    fn parses_proof_lines() {
        let log_key = Ed25519Witness::from_seed([3u8; 32]);
        let origin = "nucleus.example/log";
        let proof = [[0xAAu8; 32], [0xBBu8; 32]];
        let body = build_body(&log_key, origin, origin, 7, &[0x33u8; 32], 4, &proof);
        let req = parse_add_checkpoint(&body).unwrap();
        assert_eq!(req.old_size, 4);
        assert_eq!(req.consistency_proof, proof);
    }

    #[test]
    fn rejects_too_many_proof_lines() {
        let log_key = Ed25519Witness::from_seed([4u8; 32]);
        let origin = "nucleus.example/log";
        let proof: Vec<[u8; 32]> = (0..64).map(|i| [i as u8; 32]).collect();
        let body = build_body(&log_key, origin, origin, 100, &[0u8; 32], 4, &proof);
        let err = parse_add_checkpoint(&body).unwrap_err();
        assert!(matches!(err, ParseError::TooManyProofLines { got: 64 }));
    }

    #[test]
    fn rejects_missing_old_line() {
        let err = parse_add_checkpoint(b"").unwrap_err();
        assert!(matches!(err, ParseError::MissingOldLine));
    }

    #[test]
    fn rejects_no_signature_lines() {
        // old 0\n\norigin\n5\n<root>\n  (no blank+sig)
        let cp = format_checkpoint_body("origin", 5, &[0u8; 32]).unwrap();
        let mut body = Vec::new();
        body.extend_from_slice(b"old 0\n\n");
        body.extend_from_slice(cp.as_bytes());
        body.push(b'\n'); // blank, but no sig line follows
        let err = parse_add_checkpoint(&body).unwrap_err();
        assert!(matches!(
            err,
            ParseError::NoSignatureLines | ParseError::MissingCheckpointSigSeparator
        ));
    }
}

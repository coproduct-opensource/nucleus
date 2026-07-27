//! The C2SP `tlog-witness` status matrix + axum wiring.
//!
//! The whole security value of a witness is that it ONLY cosigns a
//! checkpoint that is (a) signed by a trusted log key, (b) consistent
//! with the last checkpoint it cosigned, and (c) not a rollback. The
//! status matrix (per [c2sp.org/tlog-witness]) encodes those rules:
//!
//! | Code | Condition |
//! |------|-----------|
//! | 404  | checkpoint origin is unknown (not trusted) |
//! | 403  | no signature from a trusted key for the origin, OR a sig line whose name+ID match a trusted key but fails to verify |
//! | 400  | old size > checkpoint size |
//! | 409  | old size ≠ witness's last-cosigned size; OR old size == checkpoint size but roots differ |
//! | 422  | the Merkle consistency proof does not verify (old→new) |
//! | 200  | otherwise: update last-cosigned, return cosignature line(s) |
//!
//! The pure decision is computed in [`decide`] so it can be unit-tested
//! without HTTP. The axum handler in [`add_checkpoint_handler`] maps the
//! [`Decision`] to a status code + body.
//!
//! [c2sp.org/tlog-witness]: https://c2sp.org/tlog-witness

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use ct_merkle::{digest::Output, ConsistencyProof, RootHash};
use ed25519_dalek::{Signature, VerifyingKey};
use nucleus_lineage::{checkpoint_signed_bytes, ed25519_key_id, SIG_TYPE_ED25519};
use sha2::Sha256;

use crate::cosign::WitnessKey;
use crate::parse::{parse_add_checkpoint, AddCheckpointRequest, Checkpoint, ParseError};
use crate::store::{CosignedPosition, OriginRecord, OriginStore};

/// Shared witness state for the axum handler.
#[derive(Clone)]
pub struct WitnessState {
    pub store: Arc<dyn OriginStore>,
    pub witness_key: Arc<WitnessKey>,
}

/// The outcome of evaluating an add-checkpoint request against the
/// status matrix. Each variant maps to exactly one HTTP status.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// 200 — cosign. Carries the freshly-minted cosignature line(s).
    Ok { cosignature_lines: Vec<String> },
    /// 400 — old size > checkpoint size.
    BadRequest(String),
    /// 403 — no trusted-key signature, or a matching-key sig failed to
    /// verify.
    Forbidden(String),
    /// 404 — origin not trusted.
    NotFound(String),
    /// 409 — rollback / conflict. Body is the witness's actual
    /// last-cosigned size (decimal), per spec Content-Type
    /// `text/x.tlog.size`.
    Conflict { last_cosigned_size: u64 },
    /// 422 — consistency proof did not verify.
    Unprocessable(String),
    /// 400 — request body was malformed (could not parse).
    Malformed(ParseError),
}

impl Decision {
    pub fn status(&self) -> StatusCode {
        match self {
            Decision::Ok { .. } => StatusCode::OK,
            Decision::BadRequest(_) | Decision::Malformed(_) => StatusCode::BAD_REQUEST,
            Decision::Forbidden(_) => StatusCode::FORBIDDEN,
            Decision::NotFound(_) => StatusCode::NOT_FOUND,
            Decision::Conflict { .. } => StatusCode::CONFLICT,
            Decision::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }
}

/// Pure status-matrix evaluation. Parses the body, walks the matrix in
/// the spec-mandated order, and (on 200) mints the cosignature and
/// CAS-advances the store. No HTTP types beyond [`Decision`].
///
/// `now_unix` is injected so tests can pin the cosignature timestamp;
/// production passes the real clock via [`add_checkpoint_handler`].
pub fn decide(state: &WitnessState, body: &[u8], now_unix: u64) -> Decision {
    let req = match parse_add_checkpoint(body) {
        Ok(r) => r,
        Err(e) => return Decision::Malformed(e),
    };
    let AddCheckpointRequest {
        old_size,
        consistency_proof,
        checkpoint,
    } = req;

    // ── 404: origin must be trusted. ──────────────────────────────
    let record = match state.store.get(&checkpoint.origin) {
        Some(r) => r,
        None => {
            return Decision::NotFound(format!("unknown origin {:?}", checkpoint.origin));
        }
    };

    // ── 403: a valid signature from a trusted key for the origin
    //    MUST be present. A sig line whose key name+ID match a trusted
    //    key but whose signature fails to verify is ALSO 403 (forgery).
    if let Err(reason) = check_trusted_signature(&checkpoint, &record) {
        return Decision::Forbidden(reason);
    }

    // ── 400: old size MUST be ≤ checkpoint size. ──────────────────
    if old_size > checkpoint.size {
        return Decision::BadRequest(format!(
            "old size {old_size} > checkpoint size {}",
            checkpoint.size
        ));
    }

    // ── 409: old size MUST equal the witness's last-cosigned size for
    //    the origin. Also: if old size == checkpoint size but the roots
    //    differ, that's a conflicting view of the same tree → 409.
    let last = record.last_cosigned;
    let last_size = last.map(|p| p.size).unwrap_or(0);
    if old_size != last_size {
        return Decision::Conflict {
            last_cosigned_size: last_size,
        };
    }
    if old_size == checkpoint.size {
        // No extension. The producer is re-presenting a checkpoint at
        // the same size we already cosigned; the roots MUST match or
        // it's a split-view conflict.
        if let Some(prev) = last {
            if prev.root != checkpoint.root {
                return Decision::Conflict {
                    last_cosigned_size: last_size,
                };
            }
        }
        // old_size == size == last_size with matching root (or
        // old_size == size == 0 first-submission empty-tree edge case):
        // idempotent re-cosign, no consistency proof needed.
    } else {
        // ── 422: the consistency proof (old→new) MUST verify. Only
        //    required when there IS an extension (old_size < size).
        //    For the very first submission (old_size == 0) there is no
        //    prior root to extend from; per spec, `old 0` carries no
        //    proof and we simply cosign the new tree.
        if old_size > 0 {
            let prev = last.expect("old_size>0 ⇒ last_size==old_size>0 ⇒ Some");
            if let Err(reason) = verify_consistency(
                old_size,
                &prev.root,
                checkpoint.size,
                &checkpoint.root,
                &consistency_proof,
            ) {
                return Decision::Unprocessable(reason);
            }
        }
    }

    // ── 200: mint the cosignature over the checkpoint note body and
    //    CAS-advance the store. The CAS uses the position we read as
    //    `expected`; if a concurrent writer advanced first, we surface
    //    409 rather than cosigning over a stale view.
    let cosig_line = state
        .witness_key
        .cosign_line(&checkpoint.body_bytes, now_unix);
    let new_pos = CosignedPosition {
        size: checkpoint.size,
        root: checkpoint.root,
    };
    if !state.store.advance(&checkpoint.origin, last, new_pos) {
        // Lost the race; the store moved under us.
        let now_last = state
            .store
            .get(&checkpoint.origin)
            .and_then(|r| r.last_cosigned)
            .map(|p| p.size)
            .unwrap_or(0);
        return Decision::Conflict {
            last_cosigned_size: now_last,
        };
    }

    Decision::Ok {
        cosignature_lines: vec![cosig_line],
    }
}

/// Enforce the 403 rule: at least one signature line whose `(key_name,
/// key_id)` match a trusted log key for the origin, AND whose Ed25519
/// signature verifies over the checkpoint body.
///
/// Returns `Ok(())` if such a signature exists; `Err(reason)` (→ 403)
/// otherwise. Critically, a line that NAMES a trusted key but carries a
/// bad signature is a forgery attempt and yields 403 — never a silent
/// pass.
fn check_trusted_signature(checkpoint: &Checkpoint, record: &OriginRecord) -> Result<(), String> {
    // The bytes a log key signs are the C2SP checkpoint body
    // (origin\nsize\nbase64(root)\n). We recompute them from the parsed
    // fields rather than trusting the raw body slice so an attacker can't
    // smuggle a divergent body. For an extension-free checkpoint
    // body_bytes == this, but recomputing is the defensive choice.
    let signed_body =
        match checkpoint_signed_bytes(&checkpoint.origin, checkpoint.size, &checkpoint.root) {
            Ok(b) => b,
            Err(e) => return Err(format!("checkpoint body invalid: {e}")),
        };
    // If the producer included extension lines, the true signed body is
    // the parsed body_bytes (which includes extensions). Prefer that
    // when it differs — it is the exact bytes the producer hashed.
    let signed_body: Vec<u8> = if checkpoint.extensions.is_empty() {
        signed_body
    } else {
        checkpoint.body_bytes.clone()
    };

    let mut saw_matching_key_bad_sig = false;
    for sig in &checkpoint.signatures {
        for trusted in &record.trusted_log_keys {
            // Match a trusted key by BOTH name and the C2SP key_id
            // (derived from name+pubkey under the Ed25519 sig type).
            if sig.key_name != trusted.key_name {
                continue;
            }
            let expected_id = ed25519_key_id(&trusted.key_name, SIG_TYPE_ED25519, &trusted.pubkey);
            if sig.key_id != expected_id {
                continue;
            }
            // Name + ID match a trusted key. Now the signature itself
            // MUST verify, else it's a forgery → 403.
            let vk = match VerifyingKey::from_bytes(&trusted.pubkey) {
                Ok(vk) => vk,
                Err(_) => continue,
            };
            let sig_arr: [u8; 64] = match sig.signature.as_slice().try_into() {
                Ok(a) => a,
                Err(_) => {
                    saw_matching_key_bad_sig = true;
                    continue;
                }
            };
            let signature = Signature::from_bytes(&sig_arr);
            if vk.verify_strict(&signed_body, &signature).is_ok() {
                return Ok(()); // a trusted key validly signed.
            }
            saw_matching_key_bad_sig = true;
        }
    }
    if saw_matching_key_bad_sig {
        Err("a signature line matched a trusted key name+ID but failed to verify".to_string())
    } else {
        Err("no signature from a trusted key for the origin".to_string())
    }
}

/// Verify the RFC 6962 consistency proof from `(old_size, old_root)` to
/// `(new_size, new_root)`. Returns `Ok(())` on success, `Err(reason)`
/// (→ 422) otherwise.
fn verify_consistency(
    old_size: u64,
    old_root: &[u8; 32],
    new_size: u64,
    new_root: &[u8; 32],
    proof_hashes: &[[u8; 32]],
) -> Result<(), String> {
    let old_rh: RootHash<Sha256> = RootHash::new(Output::<Sha256>::from(*old_root), old_size);
    let new_rh: RootHash<Sha256> = RootHash::new(Output::<Sha256>::from(*new_root), new_size);
    let outputs: Vec<Output<Sha256>> = proof_hashes
        .iter()
        .map(|h| Output::<Sha256>::from(*h))
        .collect();
    let proof: ConsistencyProof<Sha256> = ConsistencyProof::from_digests(outputs.iter());
    new_rh
        .verify_consistency(&old_rh, &proof)
        .map_err(|e| format!("consistency proof did not verify: {e}"))
}

/// `POST /add-checkpoint` axum handler. Reads the raw body, evaluates
/// the status matrix via [`decide`], and renders the response.
pub async fn add_checkpoint_handler(State(state): State<WitnessState>, body: Bytes) -> Response {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1); // never 0; the spec forbids a zero timestamp.
    let now = now.max(1);
    let decision = decide(&state, &body, now);
    render(decision)
}

/// Map a [`Decision`] to an axum [`Response`].
fn render(decision: Decision) -> Response {
    let status = decision.status();
    match decision {
        Decision::Ok { cosignature_lines } => {
            let mut body = String::new();
            for line in cosignature_lines {
                body.push_str(&line);
                body.push('\n');
            }
            (
                status,
                [(
                    axum::http::header::CONTENT_TYPE,
                    "text/plain; charset=utf-8",
                )],
                body,
            )
                .into_response()
        }
        Decision::Conflict { last_cosigned_size } => (
            status,
            // Per spec: 409 body is the witness's last-cosigned size in
            // decimal, Content-Type text/x.tlog.size.
            [(axum::http::header::CONTENT_TYPE, "text/x.tlog.size")],
            format!("{last_cosigned_size}\n"),
        )
            .into_response(),
        Decision::BadRequest(m)
        | Decision::Forbidden(m)
        | Decision::NotFound(m)
        | Decision::Unprocessable(m) => (status, m).into_response(),
        Decision::Malformed(e) => (status, e.to_string()).into_response(),
    }
}

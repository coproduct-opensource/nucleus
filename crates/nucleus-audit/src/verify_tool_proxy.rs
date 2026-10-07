//! `nucleus-audit verify`: the tool-proxy's signed, hash-chained audit log.
//!
//! Reads lines through [`crate::record_lines`], so a torn tail and an altered
//! line are told apart, and each record through the one declaration the writer
//! uses ([`nucleus_spec::tool_proxy_audit`]), so the preimage cannot drift.
//!
//! # What a pass means (#3293)
//!
//! A **signed** record passes only under a signer the caller pinned: a key
//! given with `--signer-pubkey`, or the chain head given with `--tail-hash`
//! (the node-signed receipt's `audit_tail_hash`, which commits to every
//! record's signer). A signature under a key the log names for itself, with
//! nothing pinning that key, is refused ([`AuditError::UnpinnedSigner`]).
//!
//! A **legacy** record (a shared-secret MAC, written before #3293) passes only
//! against a non-empty secret, and the report counts it as legacy. No secret,
//! or an empty one, is [`AuditError::LegacyMacUnkeyed`]: on vsock and on the
//! peer-verified socket those records were keyed with the empty secret, which
//! anyone can compute, and "could not authenticate" must not read as
//! "authenticated" (ADR 0007 A-1). A legacy record after a signed one is a
//! downgrade and is refused.

use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, Mac, digest::KeyInit};
use nucleus_spec::tool_proxy_audit::{AuditRecord, RecordForm};
use sha2::Sha256;

use crate::AuditError;

/// What the caller trusts. Built only by [`Pins::parse`].
#[derive(Debug)]
pub(crate) struct Pins {
    signers: Vec<VerifyingKey>,
    tail_hash: Option<String>,
    legacy_secret: Option<Vec<u8>>,
}

impl Pins {
    /// # Errors
    /// A signer that is not a 32-byte hex Ed25519 key.
    pub(crate) fn parse(
        signers: &[String],
        tail_hash: Option<String>,
        legacy_secret: Option<String>,
    ) -> Result<Self, AuditError> {
        let signers = signers
            .iter()
            .map(|hex| parse_key(hex).ok_or_else(|| bad_arg(format!("--signer-pubkey {hex:?}"))))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            signers,
            tail_hash,
            legacy_secret: legacy_secret.map(String::into_bytes),
        })
    }
}

fn bad_arg(what: String) -> AuditError {
    AuditError::Invalid {
        line: 0,
        message: format!("{what} is not a 32-byte Ed25519 public key in hex"),
    }
}

fn parse_key(hex_key: &str) -> Option<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(hex_key.trim()).ok()?.try_into().ok()?;
    VerifyingKey::from_bytes(&bytes).ok()
}

/// The legacy secret, from the first source given. `None` when none was; an
/// empty FILE is an error, as it always was. An empty `--secret` comes back as
/// given and is refused when a legacy record needs it, by name.
///
/// # Errors
/// An unreadable or empty secret file.
pub(crate) fn legacy_secret(
    secret: Option<&str>,
    secret_file: Option<&Path>,
    auth_secret: Option<&str>,
) -> Result<Option<String>, AuditError> {
    if let Some(s) = secret {
        return Ok(Some(s.to_string()));
    }
    if let Some(path) = secret_file {
        let s = std::fs::read_to_string(path)?.trim().to_string();
        if s.is_empty() {
            return Err(AuditError::MissingSecret);
        }
        return Ok(Some(s));
    }
    Ok(auth_secret.map(str::to_string))
}

/// What a passing run established.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Verified {
    pub(crate) signed: usize,
    pub(crate) legacy: usize,
    /// Distinct signers, in first-seen order.
    pub(crate) signers: Vec<String>,
    pub(crate) head: String,
}

impl Verified {
    pub(crate) fn print(&self) {
        println!(
            "ok: verified {} tool-proxy entries ({} signed, {} legacy)",
            self.signed + self.legacy,
            self.signed,
            self.legacy
        );
        for s in &self.signers {
            println!("  signer: {s}");
        }
        if self.legacy > 0 {
            println!(
                "  note: legacy records carry a shared-secret MAC; it shows only that no party \
                 WITHOUT that secret altered them"
            );
        }
    }
}

/// Verify the log at `path` against `pins`.
///
/// # Errors
/// The first record that fails to parse, chain or verify, naming its line.
pub(crate) fn verify_tool_proxy_log(path: &Path, pins: &Pins) -> Result<Verified, AuditError> {
    let mut lines = crate::record_lines::open(path)?;
    let mut prev_hash = String::new();
    let mut out = Verified {
        signed: 0,
        legacy: 0,
        signers: Vec::new(),
        head: String::new(),
    };

    for item in &mut lines {
        let (line_no, line) = item?;
        let rec: AuditRecord = crate::record_lines::parse(line_no, &line)?;
        let invalid = |message: String| AuditError::Invalid {
            line: line_no,
            message,
        };
        if rec.prev_hash != prev_hash {
            return Err(invalid(format!(
                "prev_hash mismatch (expected {}, got {})",
                prev_hash, rec.prev_hash
            )));
        }
        let form = rec.form().map_err(|e| invalid(e.to_string()))?;
        let bytes = rec.signed_bytes().map_err(|e| invalid(e.to_string()))?;
        match form {
            RecordForm::LegacyMac => {
                if out.signed > 0 {
                    return Err(invalid(
                        "a legacy shared-secret record after a signed one: a downgrade".into(),
                    ));
                }
                let secret = match pins.legacy_secret.as_deref() {
                    None => {
                        return Err(AuditError::LegacyMacUnkeyed {
                            line: line_no,
                            why: "no legacy secret was given",
                        });
                    }
                    Some(s) if s.iter().all(u8::is_ascii_whitespace) => {
                        return Err(AuditError::LegacyMacUnkeyed {
                            line: line_no,
                            why: "the legacy secret given is empty",
                        });
                    }
                    Some(s) => s,
                };
                let tag = hex::decode(&rec.signature)
                    .map_err(|_| invalid("signature mismatch (not hex)".into()))?;
                let mut mac = Hmac::<Sha256>::new_from_slice(secret)
                    .map_err(|_| invalid("unusable legacy secret".into()))?;
                mac.update(&bytes);
                mac.verify_slice(&tag)
                    .map_err(|_| invalid("signature mismatch".into()))?;
                out.legacy += 1;
            }
            RecordForm::Signed { signer } => {
                let key = parse_key(signer)
                    .ok_or_else(|| invalid(format!("signer {signer:?} is not an Ed25519 key")))?;
                if pins.signers.is_empty() && pins.tail_hash.is_none() {
                    return Err(AuditError::UnpinnedSigner { line: line_no });
                }
                if !pins.signers.is_empty() && !pins.signers.contains(&key) {
                    return Err(invalid(format!(
                        "signed by {signer}, which is not a pinned --signer-pubkey"
                    )));
                }
                let sig: [u8; 64] = hex::decode(&rec.signature)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| invalid("signature is not 64 hex-encoded bytes".into()))?;
                // STRICT (audit finding M-3): one signature must bind one key.
                key.verify_strict(&bytes, &Signature::from_bytes(&sig))
                    .map_err(|_| invalid(format!("signature does not verify under {signer}")))?;
                if !out.signers.iter().any(|s| s == signer) {
                    out.signers.push(signer.to_string());
                }
                out.signed += 1;
            }
        }
        let hash = rec.chain_hash().map_err(|e| invalid(e.to_string()))?;
        if hash != rec.hash {
            return Err(invalid("hash mismatch".into()));
        }
        prev_hash = rec.hash;
    }

    lines.finish(out.signed + out.legacy)?;
    if let Some(pinned) = pins.tail_hash.as_deref()
        && pinned.trim() != prev_hash
    {
        return Err(AuditError::Invalid {
            line: 0,
            message: format!(
                "the receipt pins chain head {pinned} but this log computes {prev_hash}: the log \
                 is not the one the receipt was issued for"
            ),
        });
    }
    out.head = prev_hash;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use nucleus_spec::tool_proxy_audit::AuditEvent;

    const SECRET: &[u8] = b"art12-regression-secret";

    fn event(ts: u64, subject: &str) -> AuditEvent {
        AuditEvent {
            timestamp_unix: ts,
            actor: Some("n".into()),
            event: "call".into(),
            subject: subject.into(),
            result: "ok".into(),
            spiffe_id: None,
            policy_rule: None,
        }
    }

    /// A signed record exactly as `AuditLog::log` writes it.
    fn signed(key: &SigningKey, ts: u64, prev: &str, round: Option<u64>) -> AuditRecord {
        let unsigned = event(ts, "s").unsigned(
            prev.to_string(),
            round,
            hex::encode(key.verifying_key().to_bytes()),
        );
        let sig = hex::encode(key.sign(&unsigned.signed_bytes().unwrap()).to_bytes());
        unsigned.with_signature(sig).unwrap()
    }

    /// A legacy record exactly as the pre-#3293 writer made it: HMAC over the
    /// `|`-joined preimage under `secret`.
    fn legacy(secret: &[u8], ts: u64, prev: &str, round: Option<u64>) -> AuditRecord {
        let mut rec = event(ts, "s").unsigned(prev.to_string(), round, String::new());
        rec.sig_alg = None;
        rec.signer = None;
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(&rec.signed_bytes().unwrap());
        rec.with_signature(hex::encode(mac.finalize().into_bytes()))
            .unwrap()
    }

    fn write(dir: &tempfile::TempDir, recs: &[AuditRecord]) -> std::path::PathBuf {
        let path = dir.path().join("audit.log");
        let body: String = recs
            .iter()
            .map(|r| serde_json::to_string(r).unwrap() + "\n")
            .collect();
        std::fs::write(&path, body).unwrap();
        path
    }

    fn pins(keys: &[&SigningKey], tail: Option<&str>, secret: Option<&[u8]>) -> Pins {
        let keys: Vec<String> = keys
            .iter()
            .map(|k| hex::encode(k.verifying_key().to_bytes()))
            .collect();
        Pins::parse(
            &keys,
            tail.map(str::to_string),
            secret.map(|s| String::from_utf8(s.to_vec()).unwrap()),
        )
        .unwrap()
    }

    /// #3293, A-19: a record forged by a party holding NO key is rejected in
    /// every shape it can take: appended as a legacy record under a shared secret
    /// the forger could read (a pre-#3290 container gave every process its key),
    /// with the verifier holding that secret for an older segment; as a signed
    /// record claiming the pinned signer; and as one signed by the forger's own key.
    #[test]
    fn a_record_forged_without_the_key_is_rejected() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let forger = SigningKey::from_bytes(&[66; 32]);
        let dir = tempfile::tempdir().unwrap();
        let first = signed(&key, 100, "", None);

        let downgrade = legacy(SECRET, 101, &first.hash, None);
        let path = write(&dir, &[first.clone(), downgrade]);
        let err = verify_tool_proxy_log(&path, &pins(&[&key], None, Some(SECRET))).unwrap_err();
        assert!(err.to_string().contains("downgrade"), "{err}");

        let claims_key = {
            let mut rec = signed(&forger, 101, &first.hash, None);
            rec.signer = first.signer.clone();
            let forged = std::mem::take(&mut rec.signature);
            rec.with_signature(forged).unwrap()
        };
        let path = write(&dir, &[first.clone(), claims_key]);
        let err = verify_tool_proxy_log(&path, &pins(&[&key], None, None)).unwrap_err();
        assert!(err.to_string().contains("does not verify"), "{err}");

        let own_key = signed(&forger, 101, &first.hash, None);
        let path = write(&dir, &[first.clone(), own_key.clone()]);
        let err = verify_tool_proxy_log(&path, &pins(&[&key], None, None)).unwrap_err();
        assert!(err.to_string().contains("not a pinned"), "{err}");
        // Pinned by the receipt's head instead: the forger's record moved it.
        let err = verify_tool_proxy_log(&path, &pins(&[], Some(&first.hash), None)).unwrap_err();
        assert!(err.to_string().contains("receipt pins chain head"), "{err}");

        let path = write(&dir, &[first]);
        assert_eq!(
            verify_tool_proxy_log(&path, &pins(&[&key], None, None))
                .unwrap()
                .signed,
            1
        );
    }

    /// A whole log written under the empty key, as every vsock and socket pod
    /// wrote before #3293, is refused BY NAME with or without an empty secret.
    #[test]
    fn a_legacy_log_keyed_with_nothing_is_refused_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let a = legacy(b"", 100, "", None);
        let b = legacy(b"", 101, &a.hash, None);
        let path = write(&dir, &[a, b]);
        for secret in [None, Some(&b""[..]), Some(&b"  "[..])] {
            let err = verify_tool_proxy_log(&path, &pins(&[], None, secret)).unwrap_err();
            assert!(
                matches!(err, AuditError::LegacyMacUnkeyed { line: 1, .. }),
                "{err}"
            );
        }
    }

    /// A legacy log with a real key still verifies, and is counted as legacy.
    #[test]
    fn a_legacy_log_with_its_secret_verifies_as_legacy() {
        let dir = tempfile::tempdir().unwrap();
        let a = legacy(SECRET, 100, "", Some(42));
        let b = legacy(SECRET, 101, &a.hash, None);
        let c = signed(&SigningKey::from_bytes(&[1; 32]), 102, &b.hash, None);
        let path = write(&dir, &[a, b, c]);
        let v = verify_tool_proxy_log(
            &path,
            &pins(&[&SigningKey::from_bytes(&[1; 32])], None, Some(SECRET)),
        )
        .unwrap();
        assert_eq!((v.legacy, v.signed), (2, 1));
    }

    /// A signed log with nothing pinning its signer is refused, not passed.
    #[test]
    fn an_unpinned_signer_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            &dir,
            &[signed(&SigningKey::from_bytes(&[1; 32]), 1, "", None)],
        );
        let err = verify_tool_proxy_log(&path, &pins(&[], None, None)).unwrap_err();
        assert!(
            matches!(err, AuditError::UnpinnedSigner { line: 1 }),
            "{err}"
        );
    }

    /// The receipt's tail hash alone pins a log a restarted proxy continued
    /// under a second key.
    #[test]
    fn the_receipt_head_pins_every_signer_in_the_chain() {
        let (k1, k2) = (
            SigningKey::from_bytes(&[1; 32]),
            SigningKey::from_bytes(&[2; 32]),
        );
        let a = signed(&k1, 1, "", Some(9));
        let b = signed(&k2, 2, &a.hash, None);
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, &[a, b.clone()]);
        let v = verify_tool_proxy_log(&path, &pins(&[], Some(&b.hash), None)).unwrap();
        assert_eq!(v.signers.len(), 2);
        assert_eq!(v.head, b.hash);
    }

    /// Re-anchoring a record to another drand round breaks its signature: the
    /// round is signed, in both forms.
    #[test]
    fn a_tampered_drand_round_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[1; 32]);
        for mut rec in [
            signed(&key, 1, "", Some(42)),
            legacy(SECRET, 1, "", Some(42)),
        ] {
            rec.drand_round = Some(43);
            let path = write(&dir, &[rec]);
            let err = verify_tool_proxy_log(&path, &pins(&[&key], None, Some(SECRET))).unwrap_err();
            assert!(err.to_string().contains("signature"), "{err}");
        }
    }

    /// A crash mid-append tears the last entry: the chain before it verifies and the
    /// tear is named as a torn tail, not as the altered line it would be mid-log.
    #[test]
    fn a_torn_tail_is_named() {
        let key = SigningKey::from_bytes(&[1; 32]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("torn.log");
        let a = serde_json::to_string(&signed(&key, 1, "", None)).unwrap();
        let first = signed(&key, 1, "", None);
        let b = serde_json::to_string(&signed(&key, 2, &first.hash, None)).unwrap();
        let torn = &b[..b.len() / 2];
        std::fs::write(&path, format!("{a}\n{torn}")).unwrap();
        let err = verify_tool_proxy_log(&path, &pins(&[&key], None, None)).unwrap_err();
        assert!(
            matches!(
                err,
                AuditError::TornTail {
                    line: 2,
                    verified: 1
                }
            ),
            "{err}"
        );
        std::fs::write(&path, format!("{a}\n{torn}\n{b}\n")).unwrap();
        let err = verify_tool_proxy_log(&path, &pins(&[&key], None, None)).unwrap_err();
        assert!(
            matches!(err, AuditError::NotARecord { line: 2, .. }),
            "{err}"
        );
    }
}

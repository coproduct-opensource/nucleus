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
//!
//! The per-record check is [`crate::signed_chain`]'s, shared with
//! `verify-art12` (#3309).

use std::path::Path;

use nucleus_spec::tool_proxy_audit::AuditRecord;

use crate::AuditError;
pub(crate) use crate::signed_chain::legacy_secret;
use crate::signed_chain::{Pins, Tally};

/// The flags that pin this log's signer, named when none was given.
const HOW_TO_PIN: &str = "--signer-pubkey (the NUCLEUS-AUDIT-SIGNER key the proxy printed at \
                          boot) or --tail-hash (the pod receipt's audit_tail_hash)";

/// What the caller trusts for this log.
///
/// # Errors
/// A signer that is not a 32-byte hex Ed25519 key.
pub(crate) fn pins(
    signers: &[String],
    tail_hash: Option<String>,
    legacy_secret: Option<String>,
) -> Result<Pins, AuditError> {
    Pins::parse(signers, tail_hash, legacy_secret, HOW_TO_PIN)
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
    let mut tally = Tally::default();

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
        pins.check(line_no, form, &bytes, &rec.signature, &mut tally)?;
        let hash = rec.chain_hash().map_err(|e| invalid(e.to_string()))?;
        if hash != rec.hash {
            return Err(invalid("hash mismatch".into()));
        }
        prev_hash = rec.hash;
    }

    lines.finish(tally.signed + tally.legacy)?;
    pins.check_head(&prev_hash, "the receipt")?;
    Ok(Verified {
        signed: tally.signed,
        legacy: tally.legacy,
        signers: tally.signers,
        head: prev_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use hmac::{Hmac, Mac, digest::KeyInit};
    use nucleus_spec::tool_proxy_audit::AuditEvent;
    use sha2::Sha256;

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
        super::pins(
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
        assert!(
            err.to_string().contains("the receipt pins chain head"),
            "{err}"
        );

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
            matches!(err, AuditError::UnpinnedSigner { line: 1, .. }),
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

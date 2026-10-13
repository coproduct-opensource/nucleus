//! The one check of a signed-or-legacy record, for both of the tool-proxy's
//! logs (#3293, #3309).
//!
//! `verify` (the audit log) and `verify-art12` (the Article 12 log) read
//! records of different shapes, but each record is in one of the same two forms
//! ([`portcullis::signed_record`]) and is signed by the same key. What a pass
//! means for a form is decided here, once (ADR 0007 G-1), so the two verifiers
//! cannot drift into accepting different things:
//!
//! - A **signed** record passes only under a signer the caller pinned: a key
//!   given with `--signer-pubkey`, or a chain head the caller trusts (the
//!   receipt's `audit_tail_hash`, or the executor-attested Article 12 head),
//!   which commits to every record's signer. A signature under a key the log
//!   names for itself, with nothing pinning that key, is refused
//!   ([`AuditError::UnpinnedSigner`]). Verification is strict (M-3).
//! - A **legacy** record (a shared-secret MAC) passes only against a non-empty
//!   secret and is counted as legacy. No secret, or an empty or whitespace one,
//!   is [`AuditError::LegacyMacUnkeyed`]: "could not authenticate" never reads
//!   as "authenticated" (ADR 0007 A-1).
//! - A legacy record after a signed one is a downgrade and is refused.

use std::path::Path;

use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, Mac, digest::KeyInit};
use portcullis::signed_record::RecordForm;
use sha2::Sha256;

use crate::AuditError;

/// What the caller trusts. Built only by [`Pins::parse`].
#[derive(Debug)]
pub(crate) struct Pins {
    signers: Vec<VerifyingKey>,
    head: Option<String>,
    legacy_secret: Option<Vec<u8>>,
    /// The flags that pin a signer for this log, named in the refusal.
    how_to_pin: &'static str,
}

impl Pins {
    /// # Errors
    /// A signer that is not a 32-byte hex Ed25519 key.
    pub(crate) fn parse(
        signers: &[String],
        head: Option<String>,
        legacy_secret: Option<String>,
        how_to_pin: &'static str,
    ) -> Result<Self, AuditError> {
        let signers = signers
            .iter()
            .map(|hex| parse_key(hex).ok_or_else(|| bad_arg(format!("--signer-pubkey {hex:?}"))))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            signers,
            head,
            legacy_secret: legacy_secret.map(String::into_bytes),
            how_to_pin,
        })
    }

    /// Check one record's `signature` over `bytes`, in `form`, and count it.
    ///
    /// # Errors
    /// The refusals in the module docs, naming `line`.
    pub(crate) fn check(
        &self,
        line: usize,
        form: RecordForm<'_>,
        bytes: &[u8],
        signature: &str,
        tally: &mut Tally,
    ) -> Result<(), AuditError> {
        let invalid = |message: String| AuditError::Invalid { line, message };
        match form {
            RecordForm::LegacyMac => {
                if tally.signed > 0 {
                    return Err(invalid(
                        "a legacy shared-secret record after a signed one: a downgrade".into(),
                    ));
                }
                let secret = match self.legacy_secret.as_deref() {
                    None => {
                        return Err(AuditError::LegacyMacUnkeyed {
                            line,
                            why: "no legacy secret was given",
                        });
                    }
                    Some(s) if s.iter().all(u8::is_ascii_whitespace) => {
                        return Err(AuditError::LegacyMacUnkeyed {
                            line,
                            why: "the legacy secret given is empty",
                        });
                    }
                    Some(s) => s,
                };
                let tag = hex::decode(signature)
                    .map_err(|_| invalid("signature mismatch (not hex)".into()))?;
                let mut mac = Hmac::<Sha256>::new_from_slice(secret)
                    .map_err(|_| invalid("unusable legacy secret".into()))?;
                mac.update(bytes);
                mac.verify_slice(&tag)
                    .map_err(|_| invalid("signature mismatch".into()))?;
                tally.legacy += 1;
            }
            RecordForm::Signed { signer } => {
                let key = parse_key(signer)
                    .ok_or_else(|| invalid(format!("signer {signer:?} is not an Ed25519 key")))?;
                if self.signers.is_empty() && self.head.is_none() {
                    return Err(AuditError::UnpinnedSigner {
                        line,
                        how: self.how_to_pin,
                    });
                }
                if !self.signers.is_empty() && !self.signers.contains(&key) {
                    return Err(invalid(format!(
                        "signed by {signer}, which is not a pinned --signer-pubkey"
                    )));
                }
                let sig: [u8; 64] = hex::decode(signature)
                    .ok()
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| invalid("signature is not 64 hex-encoded bytes".into()))?;
                // STRICT (audit finding M-3): one signature must bind one key.
                key.verify_strict(bytes, &Signature::from_bytes(&sig))
                    .map_err(|_| invalid(format!("signature does not verify under {signer}")))?;
                if !tally.signers.iter().any(|s| s == signer) {
                    tally.signers.push(signer.to_string());
                }
                tally.signed += 1;
            }
        }
        Ok(())
    }

    /// After the last record: the head the log computes must be the pinned one.
    ///
    /// # Errors
    /// When a head was pinned and this log does not end at it.
    pub(crate) fn check_head(&self, computed: &str, pinned_by: &str) -> Result<(), AuditError> {
        match self.head.as_deref() {
            Some(pinned) if pinned.trim() != computed => Err(AuditError::Invalid {
                line: 0,
                message: format!(
                    "{pinned_by} pins chain head {pinned} but this log computes {computed}: the \
                     log is not the one it was issued for, or was rewritten after"
                ),
            }),
            _ => Ok(()),
        }
    }
}

/// How the records that passed were authenticated.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Tally {
    pub(crate) signed: usize,
    pub(crate) legacy: usize,
    /// Distinct signers, in first-seen order.
    pub(crate) signers: Vec<String>,
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

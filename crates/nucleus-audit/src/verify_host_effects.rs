//! Verify host authorization, never relabel it as proof of execution.
use crate::AuditError;
use ed25519_dalek::{Signature, VerifyingKey};
use nucleus_spec::host_effect::{SignedAuthorization, VERSION, record_hash, signing_bytes};
use std::path::PathBuf;
mod outcomes;

#[derive(clap::Subcommand, Debug)]
pub(crate) enum Command {
    /// Verify a prefix of the host's signed effect-authorization journal.
    VerifyHostEffects {
        #[arg(long)]
        log: PathBuf,
        /// Optional host outcome journal; missing outcomes remain unknown.
        #[arg(long)]
        outcomes: Option<PathBuf>,
        /// Independently pinned node certificate-root key (32-byte hex).
        #[arg(long)]
        host_pubkey: String,
        /// Expected pod UUID, from the admission being audited.
        #[arg(long)]
        pod: String,
    },
}

fn invalid(line: usize, message: impl Into<String>) -> AuditError {
    AuditError::Invalid {
        line,
        message: message.into(),
    }
}

impl Command {
    pub(crate) fn run(self) -> Result<(), AuditError> {
        let Self::VerifyHostEffects {
            log,
            outcomes,
            host_pubkey,
            pod,
        } = self;
        let bytes: [u8; 32] = hex::decode(host_pubkey)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| invalid(0, "--host-pubkey must be a 32-byte hex key"))?;
        let key =
            VerifyingKey::from_bytes(&bytes).map_err(|_| invalid(0, "invalid host public key"))?;
        let mut lines = crate::record_lines::open(&log)?;
        let mut chain = Chain::new(&pod, &key);
        let mut authorizations = std::collections::BTreeSet::new();
        for line in &mut lines {
            let (number, text) = line?;
            let record = crate::record_lines::parse(number, &text)?;
            chain.accept(number, &record)?;
            authorizations.insert(chain.previous.clone());
        }
        lines.finish(chain.count)?;
        if chain.count == 0 {
            return Err(invalid(0, "no host authorizations to verify"));
        }
        println!(
            "Verified {} host authorizations for pod {}; head {}",
            chain.count, pod, chain.previous
        );
        if let Some(path) = outcomes {
            let count = outcomes::verify(&path, &pod, &key, &authorizations)?;
            println!(
                "Verified {count} host transport outcomes; {} authorizations have unknown outcomes.",
                authorizations.len() - count
            );
            println!(
                "Response observations do not prove remote action success, guest-claim truth, or session completeness."
            );
        }
        println!(
            "Establishes an authorized prefix, not execution success, guest-claim truth, or session completeness."
        );
        Ok(())
    }
}

struct Chain<'a> {
    pod: &'a str,
    key: &'a VerifyingKey,
    count: usize,
    previous: String,
}
impl<'a> Chain<'a> {
    fn new(pod: &'a str, key: &'a VerifyingKey) -> Self {
        Self {
            pod,
            key,
            count: 0,
            previous: String::new(),
        }
    }
    fn accept(&mut self, line: usize, record: &SignedAuthorization) -> Result<(), AuditError> {
        let claim = &record.authorization;
        if claim.version != VERSION
            || claim.pod_id != self.pod
            || claim.sequence != self.count as u64 + 1
            || claim.previous_record_sha256 != self.previous
        {
            return Err(invalid(
                line,
                "wrong schema, pod, sequence or preceding record",
            ));
        }
        let signature = hex::decode(&record.signature)
            .map_err(|_| invalid(line, "invalid signature encoding"))?;
        let signature = Signature::from_slice(&signature)
            .map_err(|_| invalid(line, "invalid signature length"))?;
        let preimage = signing_bytes(claim).map_err(|e| invalid(line, e.to_string()))?;
        self.key
            .verify_strict(&preimage, &signature)
            .map_err(|_| invalid(line, "host signature does not verify"))?;
        self.previous = record_hash(record).map_err(|e| invalid(line, e.to_string()))?;
        self.count += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use nucleus_spec::host_effect::Authorization;

    fn signed(key: &SigningKey, sequence: u64, previous: String) -> SignedAuthorization {
        let authorization = Authorization {
            version: VERSION,
            pod_id: "pod-a".into(),
            sequence,
            effect_sha256: "ab".repeat(32),
            operation: "web_fetch".into(),
            subject: "https://upstream.invalid".into(),
            authorized_unix: 123,
            call_charge_micro_usd: 0,
            previous_record_sha256: previous,
        };
        let signature = hex::encode(key.sign(&signing_bytes(&authorization).unwrap()).to_bytes());
        SignedAuthorization {
            authorization,
            signature,
        }
    }

    #[test]
    fn independently_pinned_key_pod_and_chain_are_all_required() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let public = key.verifying_key();
        let first = signed(&key, 1, String::new());
        let second = signed(&key, 2, record_hash(&first).unwrap());
        let mut chain = Chain::new("pod-a", &public);
        chain.accept(1, &first).unwrap();
        chain.accept(2, &second).unwrap();
        assert_eq!(chain.count, 2);
        assert!(chain.accept(3, &second).is_err(), "replay");
        assert!(
            Chain::new("pod-a", &public).accept(1, &second).is_err(),
            "removed prefix"
        );
        assert!(
            Chain::new("pod-b", &public).accept(1, &first).is_err(),
            "other pod"
        );
        let other = SigningKey::from_bytes(&[8; 32]).verifying_key();
        assert!(
            Chain::new("pod-a", &other).accept(1, &first).is_err(),
            "guest key"
        );
        for changed in [
            "payload",
            "subject",
            "time",
            "version",
            "operation",
            "charge",
        ] {
            let mut tampered = first.clone();
            match changed {
                "payload" => tampered.authorization.effect_sha256 = "cd".repeat(32),
                "subject" => tampered.authorization.subject.push_str("/different"),
                "time" => tampered.authorization.authorized_unix += 1,
                "version" => tampered.authorization.version += 1,
                "operation" => tampered.authorization.operation = "git_commit".into(),
                "charge" => tampered.authorization.call_charge_micro_usd = 1,
                _ => unreachable!(),
            }
            assert!(
                Chain::new("pod-a", &public).accept(1, &tampered).is_err(),
                "{changed}"
            );
        }
    }

    #[test]
    fn command_requires_nonempty_untorn_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("host.jsonl");
        let key = SigningKey::from_bytes(&[7; 32]);
        let command = || Command::VerifyHostEffects {
            log: log.clone(),
            outcomes: None,
            host_pubkey: hex::encode(key.verifying_key().to_bytes()),
            pod: "pod-a".into(),
        };
        std::fs::write(&log, "").unwrap();
        assert!(command().run().is_err());
        let record = serde_json::to_string(&signed(&key, 1, String::new())).unwrap();
        std::fs::write(&log, &record).unwrap();
        assert!(matches!(command().run(), Err(AuditError::TornTail { .. })));
        std::fs::write(&log, format!("{record}\n")).unwrap();
        command().run().unwrap();
    }
}

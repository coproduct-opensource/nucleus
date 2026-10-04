//! Durable host-only authorization records. The signing key is never included
//! in PodMaterial, guest environment, or a workload-API reply.
use std::path::Path;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use nucleus_decision_protocol::ArgsDigest;
use nucleus_spec::host_effect::{
    Authorization, LOG_FILE, SignedAuthorization, VERSION, record_hash, signing_bytes,
};
use portcullis::Operation;
use uuid::Uuid;

const MAX_RECORDS: u64 = 65_536;
pub(crate) mod outcomes;

pub(crate) struct Evidence {
    key: Arc<SigningKey>,
    pod: Uuid,
    sequence: u64,
    previous: String,
    sink: Sink,
    faulted: bool,
    outcomes: outcomes::Journal,
}

enum Sink {
    Durable(std::path::PathBuf),
    #[cfg(test)]
    Memory(Vec<SignedAuthorization>),
}

impl Evidence {
    /// A fresh admitted pod gets a new journal; never truncate an existing one.
    pub(crate) fn create(pod: Uuid, dir: &Path, key: Arc<SigningKey>) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(LOG_FILE))?;
        file.sync_all()?;
        std::fs::File::open(dir)?.sync_all()?;
        let outcomes = outcomes::Journal::create(dir)?;
        Ok(Self {
            key,
            pod,
            sequence: 0,
            previous: String::new(),
            sink: Sink::Durable(dir.join(LOG_FILE)),
            faulted: false,
            outcomes,
        })
    }

    #[cfg(test)]
    pub(crate) fn memory() -> Self {
        Self {
            key: Arc::new(SigningKey::from_bytes(&[61; 32])),
            pod: Uuid::new_v4(),
            sequence: 0,
            previous: String::new(),
            sink: Sink::Memory(Vec::new()),
            faulted: false,
            outcomes: outcomes::Journal::memory(),
        }
    }

    /// Called only after current host policy and genuine one-shot approvals
    /// permit the effect. Durable evidence precedes minting the executable right.
    pub(super) fn available(&self) -> Result<(), String> {
        if self.faulted || self.sequence >= MAX_RECORDS {
            Err("host authorization evidence unavailable".into())
        } else {
            Ok(())
        }
    }

    pub(super) fn commit(
        &mut self,
        effect: ArgsDigest,
        operation: Operation,
        subject: &str,
        now: u64,
    ) -> Result<Recorded, String> {
        self.available()?;
        let claim = Authorization {
            version: VERSION,
            pod_id: self.pod.to_string(),
            sequence: self.sequence + 1,
            effect_sha256: hex::encode(effect.as_bytes()),
            operation: portcullis::grant_usage::operation_name(operation).into(),
            subject: subject.into(),
            authorized_unix: now,
            previous_record_sha256: self.previous.clone(),
        };
        let bytes = signing_bytes(&claim).map_err(|_| "cannot encode host authorization")?;
        let record = SignedAuthorization {
            authorization: claim,
            signature: hex::encode(self.key.sign(&bytes).to_bytes()),
        };
        let hash = record_hash(&record).map_err(|_| "cannot hash host authorization")?;
        let line = serde_json::to_string(&record).map_err(|_| "cannot encode host evidence")?;
        match &mut self.sink {
            Sink::Durable(path) => match nucleus_jsonl::append_line_synced(path, &line) {
                Ok(proof) if proof.proves(path, &line) => {}
                Ok(_) | Err(_) => {
                    self.faulted = true;
                    return Err("host authorization evidence storage failed".into());
                }
            },
            #[cfg(test)]
            Sink::Memory(records) => records.push(record),
        }
        self.sequence += 1;
        self.previous = hash.clone();
        Ok(Recorded {
            authorization: hash,
        })
    }
}

/// Minted only after the exact authorization is recorded durably.
#[derive(Debug)]
#[must_use]
pub(super) struct Recorded {
    authorization: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_decide::PodPolicy;
    use portcullis::{PermissionLattice, kernel::Kernel};

    #[test]
    fn only_committed_authorizations_enter_the_durable_host_signed_chain() {
        let dir = tempfile::tempdir().unwrap();
        let key = Arc::new(SigningKey::from_bytes(&[73; 32]));
        let pod = Uuid::new_v4();
        let evidence = Evidence::create(pod, dir.path(), key.clone()).unwrap();
        let policy = PodPolicy::new(Kernel::new(PermissionLattice::permissive()), evidence);
        let mut policy = policy.lock().unwrap();
        let digest = ArgsDigest::new([5; 32]);
        policy
            .preflight_effect(digest, Operation::WebFetch, "https://upstream.invalid", 5)
            .unwrap();
        let path = dir.path().join(LOG_FILE);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        let _first = policy
            .authorize_effect(digest, Operation::WebFetch, "https://upstream.invalid", 6)
            .unwrap();
        let _second = policy
            .authorize_effect(
                ArgsDigest::new([6; 32]),
                Operation::WebFetch,
                "https://upstream.invalid",
                7,
            )
            .unwrap();
        let records: Vec<SignedAuthorization> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].authorization.pod_id, pod.to_string());
        assert_eq!(
            records[0].authorization.effect_sha256,
            hex::encode(digest.as_bytes())
        );
        assert_eq!(records[0].authorization.sequence, 1);
        assert_eq!(records[1].authorization.sequence, 2);
        assert_eq!(
            records[1].authorization.previous_record_sha256,
            record_hash(&records[0]).unwrap()
        );
        for record in &records {
            let signature =
                ed25519_dalek::Signature::from_slice(&hex::decode(&record.signature).unwrap())
                    .unwrap();
            key.verifying_key()
                .verify_strict(&signing_bytes(&record.authorization).unwrap(), &signature)
                .unwrap();
            assert!(
                SigningKey::from_bytes(&[74; 32])
                    .verifying_key()
                    .verify_strict(&signing_bytes(&record.authorization).unwrap(), &signature)
                    .is_err()
            );
        }
        assert!(
            Evidence::create(pod, dir.path(), key).is_err(),
            "never overwrite a journal"
        );
    }

    #[test]
    fn failed_persistence_latches_refusal_even_when_storage_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let evidence = Evidence::create(
            Uuid::new_v4(),
            dir.path(),
            Arc::new(SigningKey::from_bytes(&[3; 32])),
        )
        .unwrap();
        let policy = PodPolicy::new(Kernel::new(PermissionLattice::permissive()), evidence);
        let path = dir.path().join(LOG_FILE);
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let mut policy = policy.lock().unwrap();
        assert!(
            policy
                .authorize_effect(
                    ArgsDigest::new([1; 32]),
                    Operation::WebFetch,
                    "https://upstream.invalid",
                    1
                )
                .unwrap_err()
                .contains("storage failed")
        );
        std::fs::remove_dir(&path).unwrap();
        assert!(
            policy
                .preflight_effect(
                    ArgsDigest::new([1; 32]),
                    Operation::WebFetch,
                    "https://upstream.invalid",
                    1
                )
                .is_err()
        );
        assert!(
            policy
                .authorize_effect(
                    ArgsDigest::new([1; 32]),
                    Operation::WebFetch,
                    "https://upstream.invalid",
                    1
                )
                .is_err()
        );
        assert!(!path.exists());
    }

    #[test]
    fn journal_capacity_is_a_refusal_not_silent_evidence_loss() {
        let mut evidence = Evidence::memory();
        evidence.sequence = MAX_RECORDS;
        assert!(
            evidence
                .commit(
                    ArgsDigest::new([1; 32]),
                    Operation::WebFetch,
                    "https://upstream.invalid",
                    1
                )
                .is_err()
        );
    }
}

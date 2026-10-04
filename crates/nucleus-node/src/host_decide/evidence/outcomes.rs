//! An affine observer accompanies every executable broker call. Cancellation
//! records an interrupted observation; abrupt host death leaves a missing outcome.
use crate::host_decide::SharedPodPolicy;
use ed25519_dalek::Signer;
use nucleus_spec::host_effect::outcome::{self, Outcome, Response, SignedOutcome, Termination};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::Instant,
};

pub(super) struct Journal {
    sink: Sink,
    sequence: u64,
    previous: String,
}

enum Sink {
    Durable(PathBuf),
    #[cfg(test)]
    Memory,
}

impl Journal {
    pub(super) fn create(dir: &Path) -> std::io::Result<Self> {
        let path = dir.join(outcome::LOG_FILE);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?
            .sync_all()?;
        std::fs::File::open(dir)?.sync_all()?;
        Ok(Self {
            sink: Sink::Durable(path),
            sequence: 0,
            previous: String::new(),
        })
    }

    #[cfg(test)]
    pub(super) fn memory() -> Self {
        Self {
            sink: Sink::Memory,
            sequence: 0,
            previous: String::new(),
        }
    }
}

impl super::Evidence {
    fn finish(
        &mut self,
        authorization: String,
        response: Option<Response>,
        termination: Termination,
        now: u64,
    ) -> Result<(), String> {
        if self.faulted {
            return Err("host outcome evidence unavailable".into());
        }
        let result = (|| {
            let journal = &mut self.outcomes;
            let outcome = Outcome {
                version: outcome::VERSION,
                pod_id: self.pod.to_string(),
                sequence: journal.sequence + 1,
                authorization_record_sha256: authorization,
                observed_unix: now,
                termination,
                response,
                previous_record_sha256: journal.previous.clone(),
            };
            let bytes = outcome::signing_bytes(&outcome).map_err(|e| e.to_string())?;
            let record = SignedOutcome {
                outcome,
                signature: hex::encode(self.key.sign(&bytes).to_bytes()),
            };
            let hash = outcome::record_hash(&record).map_err(|e| e.to_string())?;
            let line = serde_json::to_string(&record).map_err(|e| e.to_string())?;
            match &journal.sink {
                Sink::Durable(path) => {
                    let proof = nucleus_jsonl::append_line_synced(path, &line)
                        .map_err(|e| e.to_string())?;
                    if !proof.proves(path, &line) {
                        return Err("outcome append unproven".into());
                    }
                }
                #[cfg(test)]
                Sink::Memory => {}
            }
            journal.sequence += 1;
            journal.previous = hash;
            Ok(())
        })();
        if result.is_err() {
            self.faulted = true;
        }
        result
    }
}

#[must_use]
pub(crate) struct Pending {
    policy: SharedPodPolicy,
    authorization: Option<String>,
    status: Option<u16>,
    body: Sha256,
    bytes: u64,
    complete: bool,
    start_unix: u64,
    started: Instant,
}

impl super::Recorded {
    pub(in crate::host_decide) fn observe(self, policy: SharedPodPolicy, now: u64) -> Pending {
        Pending {
            policy,
            authorization: Some(self.authorization),
            status: None,
            body: Sha256::new(),
            bytes: 0,
            complete: false,
            start_unix: now,
            started: Instant::now(),
        }
    }
}

impl Pending {
    pub(crate) fn response(&mut self, status: u16) {
        self.status = Some(status);
    }
    pub(crate) fn bytes(&mut self, bytes: &[u8]) {
        self.body.update(bytes);
        self.bytes = self.bytes.saturating_add(bytes.len() as u64);
    }
    pub(crate) fn body_complete(&mut self) {
        self.complete = true;
    }
    pub(crate) fn finish(mut self, termination: Termination) -> Result<(), String> {
        self.record(termination)
    }
    fn record(&mut self, termination: Termination) -> Result<(), String> {
        let Some(authorization) = self.authorization.take() else {
            return Ok(());
        };
        let response = self.status.map(|status| Response {
            status,
            body_sha256: hex::encode(self.body.clone().finalize()),
            body_bytes: self.bytes,
            body_complete: self.complete,
        });
        let now = self
            .start_unix
            .saturating_add(self.started.elapsed().as_secs());
        let mut policy = self.policy.lock().map_err(|_| "host policy unavailable")?;
        policy
            .evidence
            .finish(authorization, response, termination, now)
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        // The evidence store latches failures; later effects cannot proceed.
        // A killed process cannot run Drop, so missing outcomes remain unknown.
        let _ = self.record(Termination::Interrupted);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_decide::{PodPolicy, evidence::Evidence};
    use nucleus_decision_protocol::ArgsDigest;
    use portcullis::{Operation, PermissionLattice, kernel::Kernel};
    use std::sync::Arc;

    fn fixture() -> (
        tempfile::TempDir,
        SharedPodPolicy,
        ed25519_dalek::SigningKey,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[27; 32]);
        let evidence =
            Evidence::create(uuid::Uuid::new_v4(), dir.path(), Arc::new(key.clone())).unwrap();
        (
            dir,
            PodPolicy::new(Kernel::new(PermissionLattice::permissive()), evidence),
            key,
        )
    }

    fn pending(policy: &SharedPodPolicy) -> Pending {
        let permit = policy
            .lock()
            .unwrap()
            .authorize_effect(
                ArgsDigest::new([7; 32]),
                Operation::WebFetch,
                "https://upstream.invalid",
                100,
                crate::upstreams::CallCharge::free(),
            )
            .unwrap();
        let (_call, pending) = permit.observe(policy.clone(), 100);
        pending
    }

    fn records(dir: &Path) -> Vec<SignedOutcome> {
        std::fs::read_to_string(dir.join(outcome::LOG_FILE))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn outcomes_bind_the_authorization_response_and_host_key() {
        let (dir, policy, key) = fixture();
        let mut observation = pending(&policy);
        observation.response(201);
        observation.bytes(b"first");
        observation.bytes(b"second");
        observation.body_complete();
        observation.finish(Termination::ResponseRead).unwrap();
        let auth: nucleus_spec::host_effect::SignedAuthorization = serde_json::from_str(
            std::fs::read_to_string(dir.path().join(nucleus_spec::host_effect::LOG_FILE))
                .unwrap()
                .trim(),
        )
        .unwrap();
        let records = records(dir.path());
        assert_eq!(
            records.len(),
            1,
            "Drop must not duplicate an explicit outcome"
        );
        let record = &records[0];
        assert_eq!(
            record.outcome.authorization_record_sha256,
            nucleus_spec::host_effect::record_hash(&auth).unwrap()
        );
        let response = record.outcome.response.as_ref().unwrap();
        assert_eq!(response.status, 201);
        assert_eq!(response.body_bytes, 11);
        assert_eq!(
            response.body_sha256,
            hex::encode(Sha256::digest(b"firstsecond"))
        );
        assert!(response.body_complete);
        let signature =
            ed25519_dalek::Signature::from_slice(&hex::decode(&record.signature).unwrap()).unwrap();
        key.verifying_key()
            .verify_strict(
                &outcome::signing_bytes(&record.outcome).unwrap(),
                &signature,
            )
            .unwrap();
        let mut changed = record.outcome.clone();
        changed.termination = Termination::Interrupted;
        assert!(
            key.verifying_key()
                .verify_strict(&outcome::signing_bytes(&changed).unwrap(), &signature)
                .is_err()
        );
    }

    #[test]
    fn interrupted_calls_keep_partial_observations_and_chain_in_finish_order() {
        let (dir, policy, _) = fixture();
        let mut first = pending(&policy);
        let second = pending(&policy);
        second.finish(Termination::TransportFailure).unwrap();
        first.response(200);
        first.bytes(b"partial");
        drop(first);
        let records = records(dir.path());
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].outcome.termination,
            Termination::TransportFailure
        );
        assert!(records[0].outcome.response.is_none());
        assert_eq!(records[1].outcome.termination, Termination::Interrupted);
        assert!(!records[1].outcome.response.as_ref().unwrap().body_complete);
        assert_eq!(
            records[1].outcome.previous_record_sha256,
            outcome::record_hash(&records[0]).unwrap()
        );
        assert_ne!(
            records[0].outcome.authorization_record_sha256,
            records[1].outcome.authorization_record_sha256
        );
    }

    #[test]
    fn lost_outcome_storage_refuses_later_effects_even_after_repair() {
        let (dir, policy, _) = fixture();
        let observation = pending(&policy);
        let path = dir.path().join(outcome::LOG_FILE);
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(observation.finish(Termination::TransportFailure).is_err());
        std::fs::remove_dir(&path).unwrap();
        assert!(
            policy
                .lock()
                .unwrap()
                .authorize_effect(
                    ArgsDigest::new([7; 32]),
                    Operation::WebFetch,
                    "https://upstream.invalid",
                    101,
                    crate::upstreams::CallCharge::free()
                )
                .is_err()
        );
        assert!(!path.exists());
    }
}

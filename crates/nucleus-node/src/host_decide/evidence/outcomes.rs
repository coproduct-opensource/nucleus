//! An affine observer accompanies every executable broker call. Cancellation
//! records an interrupted observation; abrupt host death leaves a missing outcome.
use crate::host_decide::SharedPodPolicy;
use ed25519_dalek::Signer;
use nucleus_spec::host_effect::outcome::{
    self, Outcome, Response, Settlement, SignedOutcome, Termination,
};
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
        settlement: Option<Settlement>,
        now: u64,
    ) -> Result<(), String> {
        if self.faulted {
            return Err("host outcome evidence unavailable".into());
        }
        let result = (|| {
            let journal = &mut self.outcomes;
            // A record with no version-2 field stays version 1, byte for byte, so an
            // auditor that predates version 2 still verifies unmetered history.
            let v2 = settlement.is_some()
                || response
                    .as_ref()
                    .is_some_and(|r| r.provider_error.is_some());
            let outcome = Outcome {
                version: if v2 { outcome::VERSION } else { 1 },
                pod_id: self.pod.to_string(),
                sequence: journal.sequence + 1,
                authorization_record_sha256: authorization,
                observed_unix: now,
                termination,
                response,
                previous_record_sha256: journal.previous.clone(),
                settlement,
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
    /// Set only for a metered upstream: its metering, the tariff already debited,
    /// and the request's size in bytes (which bounds its input tokens).
    metering: Option<(crate::metering::Metering, u64, u64)>,
    /// The body, kept only when metered, up to `metering::CAPTURE_MAX`.
    captured: Vec<u8>,
    overflow: bool,
    /// Micro-USD of the ceiling reserved beyond the tariff at authorization,
    /// released when this outcome settles.
    hold: u64,
}

impl super::Recorded {
    pub(in crate::host_decide) fn observe(
        self,
        policy: SharedPodPolicy,
        now: u64,
        hold: u64,
    ) -> Pending {
        Pending {
            policy,
            authorization: Some(self.authorization),
            status: None,
            body: Sha256::new(),
            bytes: 0,
            complete: false,
            start_unix: now,
            started: Instant::now(),
            metering: None,
            captured: Vec::new(),
            overflow: false,
            hold,
        }
    }
}

impl Pending {
    pub(crate) fn response(&mut self, status: u16) {
        self.status = Some(status);
    }
    /// Meter this call: keep a bounded copy of the body to read usage and any
    /// refusal reason from. `tariff` is the flat charge already debited;
    /// `request_bytes` is the size of what was sent.
    pub(crate) fn meter(
        &mut self,
        metering: &crate::metering::Metering,
        tariff: u64,
        request_bytes: u64,
    ) {
        self.metering = Some((metering.clone(), tariff, request_bytes));
    }
    pub(crate) fn bytes(&mut self, bytes: &[u8]) {
        self.body.update(bytes);
        self.bytes = self.bytes.saturating_add(bytes.len() as u64);
        if self.metering.is_some() && !self.overflow {
            if self.captured.len().saturating_add(bytes.len()) <= crate::metering::CAPTURE_MAX {
                self.captured.extend_from_slice(bytes);
            } else {
                self.overflow = true;
                self.captured = Vec::new();
            }
        }
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
        let refused = self.status.is_some_and(|s| s >= 400);
        let provider_error = match &self.metering {
            Some((m, ..)) if refused && m.reads_errors() && !self.overflow => {
                m.provider_error(&self.captured)
            }
            _ => None,
        };
        let response = self.status.map(|status| Response {
            status,
            body_sha256: hex::encode(self.body.clone().finalize()),
            body_bytes: self.bytes,
            body_complete: self.complete,
            provider_error,
        });
        // A successful metered response is priced. A refusal (a status the upstream
        // answered with, 300 and up) is not billed beyond the tariff. A call sent
        // with no status read back (transport failure, interruption) may still
        // have been billed upstream, so it is charged its ceiling: with a zero
        // tariff it would otherwise be free.
        let settlement = match (&self.metering, self.status) {
            (Some((m, tariff, sent)), Some(s)) if (200..300).contains(&s) => {
                Some(m.settle(&self.captured, self.overflow, self.complete, *tariff, *sent))
            }
            (Some((m, tariff, sent)), None) => {
                Some(m.unreadable("no response status was read", *sent, *tariff))
            }
            _ => None,
        };
        let now = self
            .start_unix
            .saturating_add(self.started.elapsed().as_secs());
        let mut policy = self.policy.lock().map_err(|_| "host policy unavailable")?;
        // Settle the hold and sign the outcome under one lock, so the ledger and the
        // record cannot disagree. The call reserved its ceiling before it ran
        // (`CallCharge::reserving`), so its charge fits the hold and the unused part
        // is refunded. A charge beyond the hold is an alarm, never a silent clamp
        // (`SharedBudget::settle`).
        let debit = match &settlement {
            Some(Settlement::Priced {
                top_up_micro_usd, ..
            }) => *top_up_micro_usd,
            // The ceiling is the whole charge; the tariff was debited already.
            Some(Settlement::UsageUnreadable {
                ceiling_micro_usd,
                tariff_micro_usd,
                ..
            }) => ceiling_micro_usd.saturating_sub(*tariff_micro_usd),
            None => 0,
        };
        if debit > 0 || self.hold > 0 {
            policy.budget.settle(self.hold, debit)?;
        }
        policy
            .evidence
            .finish(authorization, response, termination, settlement, now)
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
                false,
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

    fn metering() -> crate::metering::Metering {
        crate::metering::Metering::from_file(
            "model",
            toml::from_str(
                r#"
                input_micro_usd_per_million_tokens = 300000
                output_micro_usd_per_million_tokens = 2500000
                input_tokens = ["/meta/in"]
                output_tokens = ["/meta/out"]
                ceiling_output_tokens = 1000
                error_status = "/error/status"
                error_message = "/error/message"
                "#,
            )
            .unwrap(),
        )
        .unwrap()
    }

    /// 2026-10-27: a flat 0.10 USD tariff per call stood in for real spend, and
    /// the provider's own refusal reason was kept only as a hash for five days.
    #[test]
    fn a_metered_call_is_priced_topped_up_and_signed_under_one_lock() {
        let (dir, policy, key) = fixture();
        let before = policy.lock().unwrap().budget.available().unwrap();
        let mut observation = pending(&policy);
        observation.meter(&metering(), 0, 0);
        observation.response(200);
        observation.bytes(br#"{"text":"ok","meta":{"in":1000000,"out":200000}}"#);
        observation.body_complete();
        observation.finish(Termination::ResponseRead).unwrap();
        let record = &records(dir.path())[0];
        assert_eq!(record.outcome.version, outcome::VERSION);
        assert!(record.outcome.schema_valid());
        // 1,000,000 x 0.3 + 200,000 x 2.5 = 800,000 micro-USD over a zero tariff.
        assert_eq!(
            record.outcome.settlement,
            Some(Settlement::Priced {
                usage: outcome::Usage {
                    input_tokens: 1_000_000,
                    output_tokens: 200_000
                },
                priced_micro_usd: 800_000,
                tariff_micro_usd: 0,
                top_up_micro_usd: 800_000,
            })
        );
        let after = policy.lock().unwrap().budget.available().unwrap();
        assert_eq!(
            before - after,
            rust_decimal::Decimal::new(800_000, 6),
            "the ledger carries the top-up"
        );
        let signature =
            ed25519_dalek::Signature::from_slice(&hex::decode(&record.signature).unwrap()).unwrap();
        key.verifying_key()
            .verify_strict(
                &outcome::signing_bytes(&record.outcome).unwrap(),
                &signature,
            )
            .unwrap();
    }

    #[test]
    fn a_refusal_keeps_its_bounded_reason_and_is_not_priced() {
        let (dir, policy, _) = fixture();
        let before = policy.lock().unwrap().budget.available().unwrap();
        let mut observation = pending(&policy);
        observation.meter(&metering(), 0, 0);
        observation.response(403);
        observation.bytes(br#"{"error":{"code":403,"status":"PERMISSION_DENIED","message":"Spend cap breached for project","debug":"hidden"}}"#);
        observation.body_complete();
        observation.finish(Termination::ResponseRead).unwrap();
        let record = &records(dir.path())[0];
        let error = record
            .outcome
            .response
            .as_ref()
            .unwrap()
            .provider_error
            .clone()
            .unwrap();
        assert_eq!(
            (error.status.as_str(), error.message.as_str()),
            ("PERMISSION_DENIED", "Spend cap breached for project")
        );
        assert_eq!(error.code, None, "only operator-named fields are kept");
        assert!(!serde_json::to_string(record).unwrap().contains("hidden"));
        assert!(
            record.outcome.settlement.is_none(),
            "a refusal is not priced"
        );
        assert_eq!(policy.lock().unwrap().budget.available().unwrap(), before);
    }

    /// A metered call sent with no response read may have been billed upstream: it
    /// is charged its ceiling, never nothing (2026-10-29, the zero tariff that makes
    /// every read call cost its price would otherwise make this one free).
    #[test]
    fn a_call_with_no_response_is_charged_its_ceiling() {
        let (dir, policy, _) = fixture();
        let before = policy.lock().unwrap().budget.available().unwrap();
        let mut observation = pending(&policy);
        observation.meter(&metering(), 0, 4000);
        observation.finish(Termination::TransportFailure).unwrap();
        let record = &records(dir.path())[0];
        // 4,000 request bytes x 0.3 + 1,000 output x 2.5 = 1,200 + 2,500.
        assert!(
            matches!(
                &record.outcome.settlement,
                Some(Settlement::UsageUnreadable {
                    ceiling_micro_usd: 3700,
                    tariff_micro_usd: 0,
                    ..
                })
            ),
            "{:?}",
            record.outcome.settlement
        );
        let after = policy.lock().unwrap().budget.available().unwrap();
        assert_eq!(
            before - after,
            rust_decimal::Decimal::new(3700, 6),
            "the ledger carries the ceiling"
        );
    }

    #[test]
    fn unmetered_calls_record_exactly_what_they_did_before() {
        let (dir, policy, _) = fixture();
        let mut observation = pending(&policy);
        observation.response(403);
        observation.bytes(br#"{"error":{"status":"PERMISSION_DENIED"}}"#);
        observation.body_complete();
        observation.finish(Termination::ResponseRead).unwrap();
        let line = std::fs::read_to_string(dir.path().join(outcome::LOG_FILE)).unwrap();
        assert!(
            !line.contains("provider_error") && !line.contains("settlement"),
            "{line}"
        );
        let record: SignedOutcome = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(
            record.outcome.version, 1,
            "unmetered records stay version 1"
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
                    crate::upstreams::CallCharge::free(),
                    false
                )
                .is_err()
        );
        assert!(!path.exists());
    }

    /// An observation of a metered call that reserved its ceiling for
    /// `request_bytes`, as the broker authorizes one.
    fn reserved(policy: &SharedPodPolicy, request_bytes: u64) -> Pending {
        let charge =
            crate::upstreams::CallCharge::free().reserving(metering().ceiling(request_bytes, 0));
        let permit = policy
            .lock()
            .unwrap()
            .authorize_effect(
                ArgsDigest::new([8; 32]),
                Operation::WebFetch,
                "https://upstream.invalid",
                100,
                charge,
                false,
            )
            .unwrap();
        let (_call, mut pending) = permit.observe(policy.clone(), 100);
        pending.meter(&metering(), 0, request_bytes);
        pending
    }

    fn balance(policy: &SharedPodPolicy) -> rust_decimal::Decimal {
        policy.lock().unwrap().budget.available().unwrap()
    }

    /// 2026-10-31, reserve then refund: the ceiling is held while the call runs,
    /// and the balance after it is the start less the real price.
    #[test]
    fn a_reserved_call_settles_down_to_its_price() {
        let (_dir, policy, _) = fixture();
        let start = balance(&policy);
        // 4,000 request bytes x 0.3 + 1,000 output x 2.5 = 3,700.
        let mut observation = reserved(&policy, 4000);
        assert_eq!(
            start - balance(&policy),
            rust_decimal::Decimal::new(3700, 6)
        );
        assert_eq!(policy.lock().unwrap().budget.held_micro().unwrap(), 3700);
        observation.response(200);
        observation.bytes(br#"{"meta":{"in":1000,"out":100}}"#);
        observation.body_complete();
        observation.finish(Termination::ResponseRead).unwrap();
        // 1,000 x 0.3 + 100 x 2.5 = 550.
        assert_eq!(start - balance(&policy), rust_decimal::Decimal::new(550, 6));
        let budget = &policy.lock().unwrap().budget;
        assert_eq!(budget.held_micro().unwrap(), 0, "the hold is released");
        assert_eq!(budget.overrun_micro().unwrap(), 0);
    }

    /// An unread call keeps its whole reservation: it is charged its ceiling.
    /// A call dropped mid-flight (`Interrupted`) settles the same way.
    #[test]
    fn an_unread_reserved_call_is_charged_its_ceiling() {
        let (_dir, policy, _) = fixture();
        let start = balance(&policy);
        let observation = reserved(&policy, 4000);
        observation.finish(Termination::TransportFailure).unwrap();
        assert_eq!(
            start - balance(&policy),
            rust_decimal::Decimal::new(3700, 6)
        );
        drop(reserved(&policy, 4000));
        assert_eq!(
            start - balance(&policy),
            rust_decimal::Decimal::new(7400, 6)
        );
        assert_eq!(policy.lock().unwrap().budget.held_micro().unwrap(), 0);
    }

    /// A price beyond the reserved ceiling should be impossible. If it happens it
    /// is charged, and the excess is kept as an alarm, never clamped away.
    #[test]
    fn a_price_beyond_its_reservation_is_an_alarm_not_a_clamp() {
        let (dir, policy, _) = fixture();
        let start = balance(&policy);
        let mut observation = reserved(&policy, 4000);
        observation.response(200);
        // 200,000 output tokens, far past the 1,000-token ceiling: 800,000 micro-USD.
        observation.bytes(br#"{"meta":{"in":1000000,"out":200000}}"#);
        observation.body_complete();
        observation.finish(Termination::ResponseRead).unwrap();
        assert_eq!(
            start - balance(&policy),
            rust_decimal::Decimal::new(800_000, 6)
        );
        assert_eq!(
            policy.lock().unwrap().budget.overrun_micro().unwrap(),
            800_000 - 3700
        );
        assert!(matches!(
            records(dir.path())[0].outcome.settlement,
            Some(Settlement::Priced {
                priced_micro_usd: 800_000,
                ..
            })
        ));
    }
}

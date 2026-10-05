// Constructed only from the Firecracker launch path, which is
// `cfg(target_os = "linux")`. Same pattern as `net`.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

//! The host's per-pod egress meter: one [`EgressLedger`] behind a lock, and
//! the audit record exhaustion owes (#2905).
//!
//! # Why on the host
//!
//! The guest can rewrite anything it runs, so a counter inside it is advisory.
//! Broker sends reserve bytes before host I/O. Direct guest IP packets stay
//! queued in the kernel until this meter authorizes their packet length.
//! Both paths share total and fixed-window allowances before accepting sends.
//!
//! # One per pod, shared by every path
//!
//! [`EgressMeter`] is built once per pod and handed, as the same `Arc`, to every
//! egress path that pod has (ADR 0007 G). Today that is the credential broker's
//! PERFORM and streaming paths plus namespace packet admission. All reserve
//! from this ledger before sending. Two meters for one pod would
//! each admit up to the ceiling.
//!
//! # Exhaustion leaves a record
//!
//! FM-3: no effect without a receipt, and a pod losing its egress is an effect.
//! The FIRST refusal of each kind — the call that latched the ceiling, or the
//! first pace refusal in a window — is appended to the pod's `lifecycle.log`
//! with the dimension and the counts. Repeats are not, so a workload hammering
//! a latched ledger cannot grow the host's log without bound.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub mod body;
mod upload;
pub use upload::UploadCharge;

use portcullis::{
    EgressBytes, EgressCeiling, EgressDecision, EgressHold, EgressLedger, EgressNovelty,
    EgressRefusal, EgressSettlement,
};

/// One pod's egress balance, as the host holds it.
#[derive(Debug)]
pub struct EgressMeter {
    // None means accounting failed; it never means an unlimited balance (B-2).
    ledger: Mutex<Option<EgressLedger>>,
    /// Where the exhaustion record goes: this pod's directory.
    pod_dir: PathBuf,
    /// The pod, as the record names it.
    pod_id: String,
}

impl EgressMeter {
    /// A meter for a pod granted `ceiling`, recording into `pod_dir`.
    #[must_use]
    pub fn new(ceiling: EgressCeiling, pod_dir: PathBuf, pod_id: String) -> Arc<Self> {
        Arc::new(Self {
            ledger: Mutex::new(Some(EgressLedger::new(ceiling))),
            pod_dir,
            pod_id,
        })
    }

    /// The meter for a pod whose spec is `spec`: its declared
    /// `network.egress`, or the finite default when it declared none.
    #[must_use]
    pub fn for_pod(spec: &nucleus_spec::PodSpec, pod_dir: PathBuf, id: uuid::Uuid) -> Arc<Self> {
        Self::new(
            nucleus_spec::NetworkSpec::egress_ceiling(spec.spec.network.as_ref()),
            pod_dir,
            id.to_string(),
        )
    }

    /// Charge `bytes` for a send the host is about to perform.
    ///
    /// On refusal the record is written before this returns, so a caller that
    /// relays the refusal has already left the evidence behind it.
    pub async fn admit(
        &self,
        bytes: EgressBytes,
        now_unix: u64,
    ) -> Result<EgressCharge<'_>, EgressRefusal> {
        // A poisoned lock means a holder panicked mid-update: the balance
        // cannot be trusted, and "could not look" is a refusal (ADR 0007 A-1).
        let decision = match self.ledger.lock() {
            Ok(mut ledger) => match ledger.as_mut() {
                Some(ledger) => ledger.reserve(bytes, now_unix),
                None => EgressDecision::Refused(EgressRefusal::LedgerFault, EgressNovelty::Repeat),
            },
            Err(_) => EgressDecision::Refused(EgressRefusal::LedgerFault, EgressNovelty::First),
        };
        match decision {
            EgressDecision::Admitted(hold) => Ok(EgressCharge {
                meter: self,
                hold: Some(hold),
            }),
            EgressDecision::Refused(refusal, novelty) => {
                if novelty == EgressNovelty::First {
                    self.record(&refusal).await;
                }
                Err(refusal)
            }
        }
    }

    /// A packet-accounting failure disables new sends through every path (A-2).
    pub async fn fault(&self) {
        let first = self
            .ledger
            .lock()
            .map(|mut ledger| ledger.take().is_some())
            .unwrap_or(true);
        if first {
            self.record(&EgressRefusal::LedgerFault).await;
        }
    }

    pub async fn record_packets(&self, bytes: u64, rejected: u64) {
        crate::lifecycle::write_lifecycle_audit(
            &self.pod_dir,
            "egress_packet_queue_closed",
            &self.pod_id,
            &format!(
                "accepted IP bytes: {bytes}; rejected packets: {rejected}; pre-send reservations"
            ),
        )
        .await;
    }

    /// Bytes this pod has sent or has in flight.
    #[cfg(test)]
    pub fn counted(&self) -> EgressBytes {
        self.ledger
            .lock()
            .ok()
            .and_then(|l| l.as_ref().map(EgressLedger::counted))
            .unwrap_or(EgressBytes::MAX)
    }

    async fn record(&self, refusal: &EgressRefusal) {
        let event = match refusal {
            EgressRefusal::CeilingExhausted { .. } => "egress_budget_exhausted",
            EgressRefusal::RateExceeded { .. } => "egress_rate_exceeded",
            EgressRefusal::TooManyInFlight { .. } => "egress_in_flight_full",
            EgressRefusal::LedgerFault => "egress_ledger_fault",
        };
        tracing::warn!(pod = %self.pod_id, dimension = refusal.dimension(), "{refusal}");
        crate::lifecycle::write_lifecycle_audit(
            &self.pod_dir,
            event,
            &self.pod_id,
            &refusal.to_string(),
        )
        .await;
    }

    /// Record one host-performed call this meter charged, in the pod's
    /// `lifecycle.log` (FM-3: an effect leaves a record).
    ///
    /// On the meter because the meter is what already owns this pod's egress
    /// record and where it is written; a second writer naming the same pod
    /// directory would be a second place to get that path wrong.
    pub async fn record_call(&self, detail: &str) {
        crate::lifecycle::write_lifecycle_audit(
            &self.pod_dir,
            "egress_stream_call",
            &self.pod_id,
            detail,
        )
        .await;
    }

    fn settle(&self, hold: EgressHold, outcome: EgressSettlement) {
        // Poisoned: the hold cannot be settled, so its bytes stay reserved —
        // counted as sent, the fail-closed reading.
        if let Ok(mut state) = self.ledger.lock() {
            let Some(ledger) = state.as_mut() else { return };
            // Unreachable from `EgressCharge`, which borrows the meter that
            // decided its hold. Reported rather than dropped: the bytes stay
            // reserved (fail-closed), and a fault here is a defect to find.
            if let Err(e) = ledger.settle(hold, outcome) {
                tracing::error!(pod = %self.pod_id, "egress settle refused: {e}");
            }
        }
    }
}

/// Bytes reserved for one send. Settle it with what happened.
///
/// Dropped unsettled — a panic, a cancelled task — it settles as
/// [`EgressSettlement::Sent`]: the host cannot know the bytes did not leave,
/// and refunding them would let a workload that can cancel its own requests
/// mid-flight send for free.
#[must_use = "an egress charge must be settled with what happened to the send"]
pub struct EgressCharge<'a> {
    meter: &'a EgressMeter,
    hold: Option<EgressHold>,
}

impl EgressCharge<'_> {
    /// The send went out, or may have.
    pub fn sent(mut self) {
        if let Some(hold) = self.hold.take() {
            self.meter.settle(hold, EgressSettlement::Sent);
        }
    }

    /// Provably nothing left the host: refund the bytes.
    #[cfg(test)]
    pub fn not_sent(mut self) {
        if let Some(hold) = self.hold.take() {
            self.meter.settle(hold, EgressSettlement::NotSent);
        }
    }
}

impl Drop for EgressCharge<'_> {
    fn drop(&mut self) {
        if let Some(hold) = self.hold.take() {
            self.meter.settle(hold, EgressSettlement::Sent);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis::EgressPace;

    fn meter(max: u64, dir: &std::path::Path) -> Arc<EgressMeter> {
        EgressMeter::new(
            EgressCeiling::new(max, EgressPace::Unpaced),
            dir.to_path_buf(),
            "pod-1".to_string(),
        )
    }

    fn lifecycle(dir: &std::path::Path) -> String {
        std::fs::read_to_string(dir.join("lifecycle.log")).unwrap_or_default()
    }

    /// Exhaustion is refused, named, and recorded — once.
    #[tokio::test]
    async fn exhaustion_is_refused_and_recorded_exactly_once() {
        let dir = tempfile::tempdir().unwrap();
        let m = meter(100, dir.path());
        m.admit(80, 0).await.expect("fits").sent();

        let refusal = m.admit(30, 0).await.err().expect("past the ceiling");
        assert_eq!(refusal.dimension(), "egress.max_bytes");
        let _ = m.admit(1, 0).await.err().expect("latched");

        let log = lifecycle(dir.path());
        assert_eq!(
            log.matches("egress_budget_exhausted").count(),
            1,
            "the latch is recorded once, not per refusal: {log}"
        );
        assert!(log.contains("80 of 100 bytes"), "{log}");
    }

    #[tokio::test]
    async fn a_dropped_charge_counts_as_sent_and_not_sent_refunds() {
        let dir = tempfile::tempdir().unwrap();
        let m = meter(100, dir.path());
        drop(m.admit(40, 0).await.expect("fits"));
        assert_eq!(m.counted(), 40, "an unsettled charge is fail-closed");
        m.admit(60, 0).await.expect("fits").not_sent();
        assert_eq!(m.counted(), 40);
    }
}

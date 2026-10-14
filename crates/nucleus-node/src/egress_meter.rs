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
//! with the dimension and the counts, as an [`EgressRecord`] signed by the
//! node's root key: the key that signs the pod's receipt (#2905). Repeats are
//! not, so a workload hammering a latched ledger cannot grow the host's log
//! without bound.

use std::path::PathBuf;
use std::sync::Arc;

pub mod body;
pub mod link_record;
pub mod record;
mod upload;
pub use link_record::LinkRecord;
pub use record::EgressRecord;
pub use upload::UploadCharge;

use portcullis::{
    EgressBytes, EgressDecision, EgressHold, EgressNovelty, EgressRefusal, EgressSettlement,
};

use crate::pod_authority::egress::EgressChain;

/// One pod's egress balance, as the host holds it.
#[derive(Debug)]
pub struct EgressMeter {
    /// The pod's own egress account and every ancestor's: each send reserves from all of them
    /// (`pod_authority::egress`, #2905).
    chain: EgressChain,
    /// Where the exhaustion record goes: this pod's directory.
    pod_dir: PathBuf,
    /// The pod, as the record names it.
    pod_id: String,
    /// Signs the exhaustion record with the node's root key (#2905).
    signer: crate::pod_authority::EgressRecordSigner,
}

impl EgressMeter {
    /// A meter drawing on `chain`, recording into `pod_dir` and signing its
    /// records with `signer`.
    #[must_use]
    fn signed(
        chain: EgressChain,
        pod_dir: PathBuf,
        pod_id: String,
        signer: crate::pod_authority::EgressRecordSigner,
    ) -> Arc<Self> {
        Arc::new(Self {
            chain,
            pod_dir,
            pod_id,
            signer,
        })
    }

    /// The meter for an admitted pod: the egress chain its admission issued
    /// (`PodAuthority::egress_chain`), never its spec read again — the
    /// admitted ceiling is the meet of the spec and the parent's remaining
    /// bytes (#2905). Its records are signed by the node's root key, through
    /// `signer`.
    #[must_use]
    pub fn for_pod(
        chain: EgressChain,
        pod_dir: PathBuf,
        id: uuid::Uuid,
        signer: crate::pod_authority::EgressRecordSigner,
    ) -> Arc<Self> {
        Self::signed(chain, pod_dir, id.to_string(), signer)
    }

    /// A meter for tests over one account nothing restores, signing with
    /// [`test_authority`]'s key.
    #[cfg(test)]
    #[must_use]
    pub fn new(ceiling: portcullis::EgressCeiling, pod_dir: PathBuf, pod_id: String) -> Arc<Self> {
        Self::signed(
            EgressChain::root(crate::pod_authority::egress::EgressAccount::memory(ceiling)),
            pod_dir,
            pod_id,
            test_authority().egress_record_signer(),
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
        // Every account on the chain, own first, all or nothing: a byte this
        // pod sends is a byte each ancestor has spent too (#2905). A faulted or
        // poisoned account refuses (ADR 0007 A-1).
        let mut holds = Vec::with_capacity(self.chain.accounts().len());
        for account in self.chain.accounts() {
            match account.reserve(bytes, now_unix).await {
                EgressDecision::Admitted(hold) => holds.push(hold),
                EgressDecision::Refused(refusal, novelty) => {
                    // Nothing left the host: the nearer accounts' holds go back.
                    for (account, hold) in self.chain.accounts().iter().zip(holds) {
                        account.settle(hold, EgressSettlement::NotSent);
                    }
                    if novelty == EgressNovelty::First {
                        self.record(&refusal).await;
                    }
                    return Err(refusal);
                }
            }
        }
        Ok(EgressCharge { meter: self, holds })
    }

    /// A packet-accounting failure disables new sends through every path (A-2).
    /// Only this pod's own account: its ancestors and siblings keep theirs.
    pub async fn fault(&self) {
        if self.chain.own().fault() {
            self.record(&EgressRefusal::LedgerFault).await;
        }
    }

    /// The pod's link check cut its egress: the kernel counted more leaving the link than this
    /// ledger admitted (`cut` is [`LinkCut::Bypass`]), or the counters could not be read
    /// ([`LinkCut::CouldNotCheck`]). Every path is refused from here on, as for [`Self::fault`],
    /// and the cut leaves a [`LinkRecord`] signed by the node's root key (#2905).
    ///
    /// Recorded every time it is called, not once per latch: the detector calls it at most once
    /// per pod, because it stops checking when it cuts.
    pub async fn cut_link(&self, cut: link_record::LinkCut, finding: &str) {
        // This pod's own account: the bypass is on its link. Its ancestors keep theirs.
        self.chain.own().fault();
        tracing::error!(pod = %self.pod_id, dimension = "egress.link", "{finding}");
        let record = LinkRecord::signed(
            &self.signer,
            crate::lifecycle::now_unix(),
            cut,
            &self.pod_id,
            finding.to_string(),
        );
        crate::lifecycle::write_lifecycle_record(&self.pod_dir, &record).await;
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
        self.chain.own().counted().unwrap_or(EgressBytes::MAX)
    }

    async fn record(&self, refusal: &EgressRefusal) {
        let event = match refusal {
            EgressRefusal::CeilingExhausted { .. } => "egress_budget_exhausted",
            EgressRefusal::RateExceeded { .. } => "egress_rate_exceeded",
            EgressRefusal::TooManyInFlight { .. } => "egress_in_flight_full",
            EgressRefusal::LedgerFault => "egress_ledger_fault",
        };
        tracing::warn!(pod = %self.pod_id, dimension = refusal.dimension(), "{refusal}");
        let now = crate::lifecycle::now_unix();
        let record = EgressRecord::signed(&self.signer, now, event, &self.pod_id, refusal);
        crate::lifecycle::write_lifecycle_record(&self.pod_dir, &record).await;
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

    /// Settle `holds`, one per account on the chain in order, as the charge
    /// that borrowed this meter made them.
    fn settle(&self, holds: Vec<EgressHold>, outcome: EgressSettlement) {
        for (account, hold) in self.chain.accounts().iter().zip(holds) {
            account.settle(hold, outcome);
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
    /// One hold per account on the meter's chain, in order. Empty once settled.
    holds: Vec<EgressHold>,
}

impl EgressCharge<'_> {
    /// The send went out, or may have.
    pub fn sent(mut self) {
        self.meter
            .settle(std::mem::take(&mut self.holds), EgressSettlement::Sent);
    }

    /// Provably nothing left the host: refund the bytes.
    #[cfg(test)]
    pub fn not_sent(mut self) {
        self.meter
            .settle(std::mem::take(&mut self.holds), EgressSettlement::NotSent);
    }
}

impl Drop for EgressCharge<'_> {
    fn drop(&mut self) {
        self.meter
            .settle(std::mem::take(&mut self.holds), EgressSettlement::Sent);
    }
}

/// The node authority every test meter signs with: one per test process, over
/// a state directory kept for the process's life.
#[cfg(test)]
pub(crate) fn test_authority() -> &'static Arc<crate::pod_authority::PodAuthority> {
    static AUTHORITY: std::sync::OnceLock<Arc<crate::pod_authority::PodAuthority>> =
        std::sync::OnceLock::new();
    AUTHORITY.get_or_init(|| {
        let dir = tempfile::tempdir().expect("tempdir").keep();
        Arc::new(
            crate::pod_authority::PodAuthority::new(
                &crate::pod_authority::AuthorityArgs {
                    root_minter_spiffe_id: None,
                    cert_trust_anchors: Vec::new(),
                    max_children_per_pod: 8,
                    upstreams: None,
                    upstreams_poll_secs: 0,
                    federation_issuer: None,
                    ingress: Default::default(),
                    approvals: crate::host_decide::effects::ApprovalTimingArgs::HUMAN,
                },
                "nucleus.local",
                &dir,
                &crate::pod_authority::NO_TPM,
            )
            .expect("a test authority"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis::{EgressCeiling, EgressPace};

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

    /// #2905: the exhaustion record is a receipt, not a log line. It carries the node's
    /// signature and the key that made it, so a reader holding the node's pinned root key can
    /// tell a record the node wrote from one anybody with write access to the pod directory
    /// appended.
    #[tokio::test]
    async fn the_exhaustion_record_is_signed_by_the_node() {
        let dir = tempfile::tempdir().unwrap();
        let m = meter(10, dir.path());
        let _ = m.admit(11, 0).await.err().expect("past the ceiling");

        let log = lifecycle(dir.path());
        let line = log
            .lines()
            .find(|l| l.contains("egress_budget_exhausted"))
            .unwrap_or_else(|| panic!("the exhaustion is recorded: {log}"));
        let entry: serde_json::Value = serde_json::from_str(line).expect("one JSON record");
        for field in ["signature", "signer_pubkey"] {
            assert!(
                entry
                    .get(field)
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|v| !v.is_empty()),
                "the exhaustion record carries no {field}: {line}"
            );
        }

        // The key is the node's root key — the one that signs its pod receipts — and the
        // reader checks against the key it pinned, not the one the record names.
        let node_key = test_authority().root_pubkey_hex();
        let record: EgressRecord = serde_json::from_str(line).expect("an EgressRecord");
        assert_eq!(record.dimension, "egress.max_bytes");
        assert!(record.result.contains("0 of 10 bytes"), "{}", record.result);
        assert!(
            record.verifies_under(&node_key),
            "the node's key verifies it"
        );

        // Every committed field is covered: moving the counts breaks the signature.
        let mut forged = record.clone();
        forged.result = forged.result.replace("10 bytes", "10000 bytes");
        assert!(
            !forged.verifies_under(&node_key),
            "a rewritten count verifies"
        );
        let mut forged = record.clone();
        forged.subject = "pod:another".into();
        assert!(
            !forged.verifies_under(&node_key),
            "a re-attributed record verifies"
        );

        // A record naming some other key is not the node's, whatever it says.
        assert!(!record.verifies_under(&"00".repeat(32)));

        // Domain-separated from the pod receipt the same key signs: the exhaustion signature
        // is not a receipt signature over the same bytes.
        assert!(!crate::pod_authority::verify_pod_receipt(
            &node_key,
            &record.preimage(),
            &record.signature
        ));
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

//! The guest half of host-side spend accounting (#2541).
//!
//! When an authority round is won, the Clarke pivot is debited from the proxy's
//! own ledger — inside the guest, where the node cannot see it. This module
//! signs a `SpendReceipt` for every such charge with the pod's mediation key
//! (served once by the node before any workload existed) and ships it to the
//! node over the workload-API vsock as `SHIP_SPEND`. The node verifies it under
//! its OWN record of that key and, at release, folds `min(allocation, Σ
//! verified)` into the parent's budget instead of the whole allocation.
//!
//! Each debit and receipt issuance occurs under the same lock that closes
//! accounting. Cancellation of a bidder cannot suppress its receipt. Closure
//! prevents new debits, drains receipt deliveries, then ships a signed terminal
//! count and total. Missing deliveries (including a lost tail) cannot earn a
//! refund because the host requires that terminal commitment.

use nucleus_authority_exchange::scheduler::ChargeError;
use std::sync::Arc;
use std::sync::Mutex;

use ed25519_dalek::SigningKey;
use portcullis::spend_receipt::SpendReceipt;

/// The only scheduler debit path when host accounting is provisioned.
struct RecordedCharger {
    ledger: Box<dyn nucleus_authority_exchange::Charger>,
    shipper: Arc<SpendShipper>,
}

impl nucleus_authority_exchange::Charger for RecordedCharger {
    fn charge(
        &self,
        _: &nucleus_econ_types::AgentId,
        _: nucleus_econ_types::MicroUsd,
    ) -> Result<(), ChargeError> {
        Err(ChargeError::Ledger(
            "a recorded charge requires clearing evidence".into(),
        ))
    }

    fn charge_clearing(
        &self,
        payer: &nucleus_econ_types::AgentId,
        price: nucleus_econ_types::MicroUsd,
        clearing: &nucleus_recompute::ClearingReceipt,
    ) -> Result<(), ChargeError> {
        self.shipper
            .record_charge(payer.as_str(), price.get(), clearing, || {
                self.ledger.charge(payer, price)
            })
            .map(|_| ())
    }
}

/// Signs and ships spend receipts for this pod.
pub(crate) struct SpendShipper {
    key: SigningKey,
    spiffe_id: String,
    pod_id: String,
    port: u32,
    accounting: Mutex<Accounting>,
}

struct Accounting {
    seq: u64,
    total: u64,
    closed: bool,
    pending: tokio::task::JoinSet<()>,
}

/// Bound detached delivery work; capacity exhaustion refuses before charging.
const MAX_PENDING: usize = 1024;

impl std::fmt::Debug for SpendShipper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the key.
        f.debug_struct("SpendShipper")
            .field("spiffe_id", &self.spiffe_id)
            .field("pod_id", &self.pod_id)
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

/// Why no shipper could be built. Each names the variable that was missing so
/// the startup log says which half of the plumbing is absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unavailable {
    /// `NUCLEUS_MEDIATION_SIGNING_KEY` unset or malformed: nothing to sign with.
    MediationKey,
    /// `NUCLEUS_MEDIATION_SPIFFE_ID` unset.
    MediatorId,
    /// `NUCLEUS_POD_ID` unset: a receipt must name the pod it charges.
    PodId,
    /// `NUCLEUS_WORKLOAD_API_PORT` unset or not a port: nowhere to ship to.
    WorkloadApiPort,
}

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MediationKey => "NUCLEUS_MEDIATION_SIGNING_KEY is unset or malformed",
            Self::MediatorId => "NUCLEUS_MEDIATION_SPIFFE_ID is unset",
            Self::PodId => "NUCLEUS_POD_ID is unset",
            Self::WorkloadApiPort => "NUCLEUS_WORKLOAD_API_PORT is unset or not a port",
        })
    }
}

impl SpendShipper {
    /// Build from the environment guest-init exported, or say which piece is
    /// missing. Reads the mediation seed through the one parser for it
    /// (`art12_sink::mediation_seed_from_env`).
    pub(crate) fn from_env() -> Result<Self, Unavailable> {
        let seed = crate::art12_sink::mediation_seed_from_env().ok_or(Unavailable::MediationKey)?;
        let spiffe_id =
            std::env::var("NUCLEUS_MEDIATION_SPIFFE_ID").map_err(|_| Unavailable::MediatorId)?;
        let pod_id = std::env::var("NUCLEUS_POD_ID").map_err(|_| Unavailable::PodId)?;
        let port = std::env::var("NUCLEUS_WORKLOAD_API_PORT")
            .ok()
            .and_then(|p| p.trim().parse::<u32>().ok())
            .ok_or(Unavailable::WorkloadApiPort)?;
        Ok(Self::new(
            SigningKey::from_bytes(&seed),
            spiffe_id,
            pod_id,
            port,
        ))
    }

    pub(crate) fn new(key: SigningKey, spiffe_id: String, pod_id: String, port: u32) -> Self {
        Self {
            key,
            spiffe_id,
            pod_id,
            port,
            accounting: Mutex::new(Accounting {
                seq: 0,
                total: 0,
                closed: false,
                pending: tokio::task::JoinSet::new(),
            }),
        }
    }

    pub(crate) fn wrap_charger(
        self: &Arc<Self>,
        ledger: Box<dyn nucleus_authority_exchange::Charger>,
    ) -> Box<dyn nucleus_authority_exchange::Charger> {
        Box::new(RecordedCharger {
            ledger,
            shipper: Arc::clone(self),
        })
    }

    /// Charge and record atomically with respect to closure. This runs in the
    /// scheduler's closer, not in the request awaiting its verdict.
    pub(crate) fn record_charge(
        self: &Arc<Self>,
        payer: &str,
        amount: u64,
        clearing: &nucleus_recompute::ClearingReceipt,
        debit: impl FnOnce() -> Result<(), ChargeError>,
    ) -> Result<SpendReceipt, ChargeError> {
        tokio::runtime::Handle::try_current().map_err(|e| ChargeError::Ledger(e.to_string()))?;
        let clearing_line =
            serde_json::to_string(clearing).map_err(|e| ChargeError::Ledger(e.to_string()))?;
        if !nucleus_recompute::authority_spend::payment_matches(clearing, payer, amount) {
            return Err(ChargeError::Ledger(
                "the debit does not match the clearing's payer and payment".into(),
            ));
        }
        let basis = nucleus_recompute::authority_spend::basis(clearing, payer);
        let mut state = self
            .accounting
            .lock()
            .map_err(|_| ChargeError::Ledger("spend accounting lock is poisoned".into()))?;
        while state.pending.try_join_next().is_some() {}
        if state.closed || state.pending.len() >= MAX_PENDING {
            return Err(ChargeError::Ledger(
                "spend accounting is closed or delivery capacity is exhausted".into(),
            ));
        }
        let seq = state
            .seq
            .checked_add(1)
            .filter(|n| *n < u64::MAX)
            .ok_or_else(|| ChargeError::Ledger("spend sequence exhausted".into()))?;
        let receipt = SpendReceipt::issue(
            &self.spiffe_id,
            &self.pod_id,
            seq,
            amount,
            &basis,
            &self.key,
        );
        let line =
            serde_json::to_string(&receipt).map_err(|e| ChargeError::Ledger(e.to_string()))?;
        debit()?;
        state.seq = seq;
        state.total = state.total.saturating_add(amount);
        let port = self.port;
        state.pending.spawn(async move {
            // The corpus must precede the spend that cites it. A failed send
            // leaves incomplete evidence, which the terminal count exposes.
            if let Err(e) = send_checked(port, "SHIP_CLEARING", &clearing_line).await {
                tracing::warn!(error = %e, "clearing receipt delivery failed");
            }
            if let Err(e) = send_checked(port, "SHIP_SPEND", &line).await {
                tracing::warn!(error = %e, "spend receipt delivery failed");
            }
        });
        Ok(receipt)
    }

    /// The closed bit and final count are written under the debit lock. Even a
    /// detached auction that closes later cannot debit after this statement.
    fn close(&self) -> Option<(SpendReceipt, tokio::task::JoinSet<()>)> {
        let mut state = self.accounting.lock().ok()?;
        if state.closed {
            return None;
        }
        state.closed = true;
        let seal = SpendReceipt::seal(
            &self.spiffe_id,
            &self.pod_id,
            state.seq.checked_add(1)?,
            state.total,
            &self.key,
        );
        Some((seal, std::mem::take(&mut state.pending)))
    }

    pub(crate) async fn finish(&self) {
        let Some((seal, mut pending)) = self.close() else {
            return;
        };
        while let Some(result) = pending.join_next().await {
            if let Err(error) = result {
                tracing::warn!(%error, "receipt delivery task did not finish");
            }
        }
        let line = match serde_json::to_string(&seal) {
            Ok(line) => line,
            Err(error) => {
                tracing::warn!(%error, "cannot serialize terminal spend evidence");
                return;
            }
        };
        if let Err(error) = send_checked(self.port, "SHIP_SPEND", &line).await {
            tracing::warn!(%error, "terminal spend evidence was not collected; no refund is proven");
        }
    }

    /// Finish before the supervisor publishes exit (the host may immediately
    /// kill the guest on observing it), then run the existing exit-report hook.
    pub(crate) fn before_exit(
        shipper: Option<Arc<Self>>,
        next: crate::workload_supervisor::ExitHook,
    ) -> crate::workload_supervisor::ExitHook {
        Box::new(move || {
            Box::pin(async move {
                if let Some(shipper) = shipper {
                    shipper.finish().await;
                }
                next().await;
            })
        })
    }
}

async fn send_checked(port: u32, command: &str, line: &str) -> std::io::Result<()> {
    let reply = ship(port, command, line).await?;
    let value: serde_json::Value = serde_json::from_str(&reply)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    if value.get("status").and_then(serde_json::Value::as_str) == Some("collected") {
        Ok(())
    } else {
        Err(std::io::Error::other("host refused the receipt"))
    }
}

/// Largest reply the guest will read back — an ack or a refusal line.
const MAX_REPLY_BYTES: u64 = 4096;
/// How long a ship may take before it is given up (the host is local).
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// `SHIP_SPEND` over vsock to the host: the command frame, then the receipt
/// line, then one reply line. `cfg`-split rather than gated, for the reason
/// `broker_client::ask` gives.
#[cfg(target_os = "linux")]
async fn ship(port: u32, command: &str, line: &str) -> std::io::Result<String> {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    let fut = async {
        let mut stream = tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(
            crate::pod_mgmt::VMADDR_CID_HOST,
            port,
        ))
        .await?;
        stream.write_all(command.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.write_all(line.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;
        let (reader, _writer) = tokio::io::split(stream);
        let mut reply = String::new();
        let mut limited = BufReader::new(reader).take(MAX_REPLY_BYTES);
        limited.read_line(&mut reply).await?;
        Ok::<_, std::io::Error>(reply)
    };
    match tokio::time::timeout(REQUEST_TIMEOUT, fut).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "the host did not acknowledge the spend receipt within the timeout",
        )),
    }
}

#[cfg(not(target_os = "linux"))]
async fn ship(_port: u32, _command: &str, _line: &str) -> std::io::Result<String> {
    let _ = MAX_REPLY_BYTES;
    let _ = REQUEST_TIMEOUT;
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "vsock is Linux-only; a spend receipt cannot be shipped from this host",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shipper() -> SpendShipper {
        SpendShipper::new(
            SigningKey::from_bytes(&[5u8; 32]),
            "spiffe://t/mediator".into(),
            "pod-1".into(),
            15012,
        )
    }

    fn clearing() -> nucleus_recompute::ClearingReceipt {
        use nucleus_recompute::{IntegerBid, IntegerProposal};
        nucleus_recompute::issue_vcg(
            vec![
                IntegerBid {
                    bidder: "a".into(),
                    proposal_id: "slot".into(),
                    effective_value_micro_usd: 20,
                },
                IntegerBid {
                    bidder: "b".into(),
                    proposal_id: "slot".into(),
                    effective_value_micro_usd: 10,
                },
            ],
            vec![IntegerProposal {
                id: "slot".into(),
                cost_micro_usd: 1,
            }],
            1,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn every_successful_debit_is_in_the_seal_and_closure_refuses_later_debits() {
        use portcullis::spend_receipt::{SpendKind, VerifiedSpend};
        let s = Arc::new(shipper());
        let mut debits = 0;
        let first = s
            .record_charge("a", 10, &clearing(), || {
                debits += 1;
                Ok(())
            })
            .unwrap();
        let second = s
            .record_charge("a", 10, &clearing(), || {
                debits += 1;
                Ok(())
            })
            .unwrap();
        let (seal, pending) = s.close().unwrap();
        assert_eq!((first.seq, second.seq, seal.seq), (1, 2, 3));
        assert_eq!(seal.kind, SpendKind::Final);
        for r in [&first, &second, &seal] {
            assert_eq!(r.verify_strict(&s.key.verifying_key()), Ok(()));
        }
        assert_eq!(
            VerifiedSpend::fold([&first, &second, &seal]),
            VerifiedSpend::Complete {
                count: 2,
                total_micro: 20
            }
        );
        assert!(
            s.record_charge("a", 10, &clearing(), || {
                debits += 1;
                Ok(())
            })
            .is_err()
        );
        assert_eq!(debits, 2, "a post-seal round must not debit");
        assert!(s.close().is_none(), "a terminal record is issued once");
        drop(pending);
    }

    #[tokio::test]
    async fn refused_debits_do_not_issue_receipts_or_inflate_the_seal() {
        let s = Arc::new(shipper());
        assert!(
            s.record_charge("a", 10, &clearing(), || Err(ChargeError::Ledger(
                "refused".into()
            )))
            .is_err()
        );
        let first = s.record_charge("a", 10, &clearing(), || Ok(())).unwrap();
        let (seal, pending) = s.close().unwrap();
        assert_eq!((first.seq, seal.seq, seal.amount_micro), (1, 2, 10));
        drop(pending);
    }

    #[tokio::test]
    async fn a_payment_mismatch_is_refused_before_the_debit() {
        let s = Arc::new(shipper());
        for (payer, amount) in [("a", 9), ("b", 10), ("unknown", 10)] {
            let mut debited = false;
            assert!(
                s.record_charge(payer, amount, &clearing(), || {
                    debited = true;
                    Ok(())
                })
                .is_err()
            );
            assert!(!debited);
        }
        let (seal, pending) = s.close().unwrap();
        assert_eq!((seal.seq, seal.amount_micro), (1, 0));
        drop(pending);
    }

    #[tokio::test]
    async fn delivery_capacity_refuses_before_the_debit() {
        let s = Arc::new(shipper());
        {
            let mut state = s.accounting.lock().unwrap();
            for _ in 0..MAX_PENDING {
                state.pending.spawn(std::future::pending());
            }
        }
        let mut debited = false;
        assert!(
            s.record_charge("a", 10, &clearing(), || {
                debited = true;
                Ok(())
            })
            .is_err()
        );
        assert!(!debited);
        let (seal, pending) = s.close().unwrap();
        assert_eq!((seal.seq, seal.amount_micro), (1, 0));
        drop(pending);
    }

    #[tokio::test]
    async fn sequence_exhaustion_refuses_before_the_debit_and_keeps_room_for_the_seal() {
        let s = Arc::new(shipper());
        s.accounting.lock().unwrap().seq = u64::MAX - 1;
        let mut debited = false;
        assert!(
            s.record_charge("a", 10, &clearing(), || {
                debited = true;
                Ok(())
            })
            .is_err()
        );
        assert!(!debited);
        let (seal, pending) = s.close().unwrap();
        assert_eq!(seal.seq, u64::MAX);
        drop(pending);
    }

    #[tokio::test]
    async fn exit_hook_waits_for_delivery_tasks_before_publishing_exit() {
        let s = Arc::new(shipper());
        let (release, wait) = tokio::sync::oneshot::channel::<()>();
        s.accounting.lock().unwrap().pending.spawn(async move {
            let _ = wait.await;
        });
        let (published, observe) = tokio::sync::oneshot::channel();
        let hook = SpendShipper::before_exit(
            Some(Arc::clone(&s)),
            Box::new(move || {
                Box::pin(async move {
                    published.send(()).unwrap();
                })
            }),
        );
        let task = tokio::spawn(hook());
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        assert!(s.accounting.lock().unwrap().closed);
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(6), task)
            .await
            .unwrap()
            .unwrap();
        observe.await.unwrap();
    }

    #[test]
    fn debug_never_prints_the_key() {
        let s = shipper();
        let text = format!("{s:?}");
        assert!(!text.contains("key"), "{text}");
        assert!(text.contains("pod-1"));
    }
}

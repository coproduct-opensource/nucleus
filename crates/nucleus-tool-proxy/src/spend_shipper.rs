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
//! # Failure runs in the pod's disfavour, never the parent's
//!
//! A receipt that fails to ship is warned about and dropped. The node then
//! sees a gap in the sequence and folds the FULL allocation — the same outcome
//! as before this module existed. So a shipping failure can only make the pod
//! look more expensive, never cheaper, and the request that won the round is
//! not refused for it: the charge was made, the slot is the pod's, and the bill
//! is the node's to settle conservatively.
//!
//! # Sequence numbers are issued here, in charge order
//!
//! `issue` takes the next `seq` synchronously in the request handler, so the
//! order of receipts is the order of charges even though shipping is spawned.
//! The node's fold is order-independent (it sorts by `seq`), so arrival order
//! does not matter; a missing number does.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::SigningKey;
use portcullis::spend_receipt::SpendReceipt;

/// Signs and ships spend receipts for this pod.
pub(crate) struct SpendShipper {
    key: SigningKey,
    spiffe_id: String,
    pod_id: String,
    port: u32,
    seq: AtomicU64,
}

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
            seq: AtomicU64::new(0),
        }
    }

    /// Sign the next receipt. Takes the sequence number NOW, in the caller's
    /// order; see the module docs.
    pub(crate) fn issue(&self, amount_micro: u64, basis: &str) -> SpendReceipt {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        SpendReceipt::issue(
            &self.spiffe_id,
            &self.pod_id,
            seq,
            amount_micro,
            basis,
            &self.key,
        )
    }

    /// Issue and ship in the background. The returned receipt is what was
    /// signed; the ship's outcome is logged, never awaited by the request.
    /// Issue and ship the spend receipt, AND ship the clearing receipt its
    /// `basis` names.
    ///
    /// Both, or the discount is not earned: the host credits a spend only when
    /// it holds a clearing receipt that recomputes for every basis. Shipping
    /// the amount without the evidence used to leave the node with a hash
    /// pointing at a receipt that died with this guest's tmpfs.
    ///
    /// The clearing receipt goes FIRST, so a host that sees the spend has
    /// already seen what justifies it; if the clearing ship fails the spend is
    /// still sent, and the host's refusal to credit it is the correct outcome
    /// rather than a silent discount.
    pub(crate) fn charge(
        self: &Arc<Self>,
        amount_micro: u64,
        basis: &str,
        clearing: &nucleus_recompute::ClearingReceipt,
    ) -> SpendReceipt {
        match serde_json::to_string(clearing) {
            Ok(line) => self.send("SHIP_CLEARING", line, 0),
            Err(e) => tracing::error!(
                error = %e,
                "could not serialize a ClearingReceipt; the host will not credit the spend"
            ),
        }
        let receipt = self.issue(amount_micro, basis);
        let me = Arc::clone(self);
        let line = match serde_json::to_string(&receipt) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(error = %e, "could not serialize a SpendReceipt; the host will fold the full allocation");
                return receipt;
            }
        };
        let _ = me;
        self.send("SHIP_SPEND", line, receipt.seq);
        receipt
    }

    /// Ship one line under one command, in the background.
    ///
    /// One sender for both receipt kinds: the only difference between them is
    /// the command word and how the host verifies the body, and neither is the
    /// guest's business. A failure is logged and never refuses the request —
    /// the charge was made, the slot is the pod's, and an unshipped receipt
    /// costs the POD (the host folds the full allocation), which is the right
    /// direction for the incentive to point.
    fn send(self: &Arc<Self>, command: &'static str, line: String, seq: u64) {
        let me = Arc::clone(self);
        tokio::spawn(async move {
            match ship(me.port, command, &line).await {
                Ok(reply) if reply.contains("\"collected\"") => {
                    tracing::debug!(
                        command,
                        seq,
                        event = "receipt_shipped",
                        "receipt collected by the host"
                    );
                }
                Ok(reply) => tracing::warn!(
                    command,
                    seq,
                    reply = %reply.trim(),
                    "the host refused a receipt; it will fold the full allocation"
                ),
                Err(e) => tracing::warn!(
                    command,
                    seq,
                    error = %e,
                    "could not ship a receipt; the host will fold the full allocation"
                ),
            }
        });
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

    #[test]
    fn receipts_are_numbered_from_one_in_issue_order() {
        let s = shipper();
        let a = s.issue(10, "authority-round:a");
        let b = s.issue(20, "authority-round:b");
        assert_eq!((a.seq, b.seq), (1, 2));
        assert_eq!(a.amount_micro, 10);
        assert_eq!(a.pod_id, "pod-1");
    }

    #[test]
    fn an_issued_receipt_verifies_under_the_shipper_key() {
        let s = shipper();
        let r = s.issue(10, "authority-round:a");
        let pubkey = SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        assert_eq!(r.verify_strict(&pubkey), Ok(()));
    }

    #[test]
    fn debug_never_prints_the_key() {
        let s = shipper();
        let text = format!("{s:?}");
        assert!(!text.contains("key"), "{text}");
        assert!(text.contains("pod-1"));
    }
}

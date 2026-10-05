//! Admit direct pod IP packets against the same ledger used by the broker.
//!
//! A namespace-local NFQUEUE holds outbound packets before forwarding. Each
//! accepted packet consumes a host reservation for its kernel-reported IP
//! length. Replies are not queued, while outgoing ACKs and retransmissions are.
//! No queue-bypass or fail-open mode is installed. A missing listener, full
//! queue or receiver failure drops traffic rather than bypassing accounting.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

#[cfg(all(test, target_os = "linux"))]
mod linux_tests;
#[cfg(target_os = "linux")]
mod queue;
#[cfg(test)]
mod tests;

use crate::{
    ApiError,
    egress_meter::{EgressCharge, EgressMeter},
    net::NetPlan,
};
use std::{io, sync::Arc, time::Duration};
use tokio::{sync::oneshot, task::JoinHandle};

#[tonic::async_trait]
trait PacketQueue: Send + 'static {
    type Packet: Send;
    fn bytes(packet: &Self::Packet) -> u64;
    async fn next(&mut self) -> io::Result<Self::Packet>;
    // NF_ACCEPT is reachable only with the consumed reservation (C-4, H-1).
    async fn accept(&mut self, packet: Self::Packet, charge: EgressCharge<'_>) -> io::Result<()>;
    async fn reject(&mut self, packet: Self::Packet) -> io::Result<()>;
}

/// Owns the packet receiver from before VMM spawn through teardown.
#[derive(Debug)]
pub(crate) struct LinkMonitor {
    task: Option<JoinHandle<()>>,
    stop: Option<oneshot::Sender<()>>,
}

impl LinkMonitor {
    #[cfg(target_os = "linux")]
    pub async fn start(plan: &NetPlan, meter: Arc<EgressMeter>) -> Result<Self, ApiError> {
        let queue = queue::Queue::open(&plan.netns).await.map_err(|err| {
            ApiError::Driver(format!(
                "prepare pod packet accounting (requires CONFIG_NETFILTER_NETLINK_QUEUE): {err}"
            ))
        })?;
        // Queue binding is acknowledged before installing either rule. The
        // private namespace owns these rules until network cleanup removes it.
        // Failures drop the binding; any installed rule continues to drop.
        for program in ["iptables", "ip6tables"] {
            let output = tokio::process::Command::new("ip")
                .args([
                    "netns",
                    "exec",
                    &plan.netns,
                    program,
                    "-w",
                    "-t",
                    "mangle",
                    "-A",
                    "POSTROUTING",
                    "-o",
                    &plan.peer_veth,
                    "-j",
                    "NFQUEUE",
                    "--queue-num",
                    "0",
                ])
                .kill_on_drop(true)
                .output()
                .await?;
            if !output.status.success() {
                return Err(ApiError::Driver(format!(
                    "install {program} packet accounting: {}",
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
        }
        Ok(Self::serve(queue, meter))
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn start(_plan: &NetPlan, _meter: Arc<EgressMeter>) -> Result<Self, ApiError> {
        Err(ApiError::Driver("packet accounting requires Linux".into()))
    }

    fn serve(queue: impl PacketQueue, meter: Arc<EgressMeter>) -> Self {
        Self::serve_with_clock(queue, meter, crate::now_unix)
    }

    fn serve_with_clock(
        queue: impl PacketQueue,
        meter: Arc<EgressMeter>,
        clock: impl Fn() -> u64 + Send + 'static,
    ) -> Self {
        let (stop, receiver) = oneshot::channel();
        Self {
            task: Some(tokio::spawn(run(queue, meter, receiver, clock))),
            stop: Some(stop),
        }
    }

    pub async fn shutdown(&mut self) -> Result<(), ApiError> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let result = match self.task.as_mut() {
            Some(task) => tokio::time::timeout(Duration::from_secs(6), task)
                .await
                .map_err(|_| ApiError::Driver("packet receiver is still stopping".into()))?
                .map_err(|err| ApiError::Driver(format!("packet receiver failed: {err}"))),
            None => Ok(()),
        };
        self.task.take();
        result
    }
}

/// Keep ownership if teardown is cancelled or needs another attempt.
pub(crate) async fn shutdown(
    slot: &tokio::sync::Mutex<Option<LinkMonitor>>,
) -> Result<(), ApiError> {
    let mut slot = slot.lock().await;
    if let Some(monitor) = slot.as_mut() {
        monitor.shutdown().await?;
    }
    slot.take();
    Ok(())
}

impl Drop for LinkMonitor {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn run<Q: PacketQueue>(
    mut queue: Q,
    meter: Arc<EgressMeter>,
    mut stop: oneshot::Receiver<()>,
    clock: impl Fn() -> u64,
) {
    let mut accepted_bytes = 0u64;
    let mut rejected_packets = 0u64;
    loop {
        let received = tokio::select! {
            biased;
            _ = &mut stop => break,
            received = queue.next() => received,
        };
        let packet = match received {
            Ok(packet) => packet,
            Err(err) => {
                tracing::error!(error = %err, "pod packet receiver failed");
                meter.fault().await;
                break;
            }
        };
        let bytes = Q::bytes(&packet);
        // Reservation, pace and broker calls all use this one ledger and clock.
        match meter.admit(bytes, clock()).await {
            Ok(charge) => {
                if let Err(err) = queue.accept(packet, charge).await {
                    tracing::error!(error = %err, "pod packet verdict failed");
                    meter.fault().await;
                    break;
                }
                accepted_bytes = accepted_bytes.saturating_add(bytes);
            }
            Err(refusal) => {
                rejected_packets = rejected_packets.saturating_add(1);
                if let Err(err) = queue.reject(packet).await {
                    tracing::error!(error = %err, "pod packet refusal failed");
                    meter.fault().await;
                    break;
                }
                match refusal {
                    portcullis::EgressRefusal::RateExceeded { .. }
                    | portcullis::EgressRefusal::TooManyInFlight { .. } => {}
                    portcullis::EgressRefusal::CeilingExhausted { .. }
                    | portcullis::EgressRefusal::LedgerFault => break,
                }
            }
        }
    }
    // Closing the socket flushes queued packets and leaves the no-bypass rule
    // dropping new traffic. Close before awaiting the final audit write.
    drop(queue);
    meter.record_packets(accepted_bytes, rejected_packets).await;
}

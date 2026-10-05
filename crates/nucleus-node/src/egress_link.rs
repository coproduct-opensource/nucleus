//! Fold the pod's outgoing veth traffic into its broker's byte ledger.
//!
//! Host-veth RX is traffic arriving FROM the pod namespace. Host broker
//! requests use the host's own routes and do not traverse this link. Download
//! bodies use host-veth TX and are not charged (their outgoing ACKs are).
//! Sampling includes packet overhead and can overshoot the ceiling between
//! samples. This is accounting and eventual cutoff, not packet admission or
//! pacing. A kernel admission mechanism is still required for those guarantees.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::{io, sync::Arc, time::Duration};
use tokio::{sync::oneshot, task::JoinHandle};

use crate::{ApiError, egress_meter::EgressMeter, net::NetPlan};

const INTERVAL: Duration = Duration::from_millis(100);

#[tonic::async_trait]
trait LinkIo: Send + 'static {
    async fn uploaded(&mut self) -> io::Result<u64>;
    async fn close(&mut self) -> io::Result<()>;
}

struct HostLink {
    name: String,
    counter: std::path::PathBuf,
}

#[tonic::async_trait]
impl LinkIo for HostLink {
    async fn uploaded(&mut self) -> io::Result<u64> {
        let text = tokio::fs::read_to_string(&self.counter).await?;
        text.trim().parse().map_err(io::Error::other)
    }

    async fn close(&mut self) -> io::Result<()> {
        match tokio::fs::metadata(&self.counter).await {
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err),
            Ok(_) => {}
        }
        // Link state is independent of the iptables drift baseline. Names are
        // derived from the pod UUID, not a reusable network allocation index.
        let output = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::process::Command::new("ip")
                .args(["link", "set", "dev", &self.name, "down"])
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(io::Error::other)??;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "close link {}: {}",
                self.name,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(())
    }
}

/// Owned from before guest spawn through network teardown. Dropping a failed
/// launch aborts the task; normal teardown closes and samples before deleting
/// the link. No detached monitor can outlive its owning pod.
#[derive(Debug)]
pub(crate) struct LinkMonitor {
    task: Option<JoinHandle<()>>,
    stop: Option<oneshot::Sender<()>>,
}

impl LinkMonitor {
    pub async fn start(plan: &NetPlan, meter: Arc<EgressMeter>) -> Result<Self, ApiError> {
        Self::prepare(
            HostLink {
                name: plan.host_veth.clone(),
                counter: std::path::Path::new("/sys/class/net")
                    .join(&plan.host_veth)
                    .join("statistics/rx_bytes"),
            },
            meter,
        )
        .await
        .map_err(|err| ApiError::Driver(format!("prepare egress accounting: {err}")))
    }

    async fn prepare(mut link: impl LinkIo, meter: Arc<EgressMeter>) -> io::Result<Self> {
        // This read must succeed before the VMM starts. Count the entire new
        // link, including setup traffic, rather than subtracting a baseline.
        let initial = link.uploaded().await?;
        let (stop, receiver) = oneshot::channel();
        let task = tokio::spawn(run(link, meter, initial, receiver));
        Ok(Self {
            task: Some(task),
            stop: Some(stop),
        })
    }

    pub async fn shutdown(&mut self) -> Result<(), ApiError> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let result = match self.task.as_mut() {
            Some(task) => tokio::time::timeout(Duration::from_secs(6), task)
                .await
                .map_err(|_| ApiError::Driver("egress link cutoff is still retrying".into()))?
                .map_err(|err| ApiError::Driver(format!("egress monitor failed: {err}"))),
            None => Ok(()),
        };
        self.task.take();
        result
    }
}

/// Keep ownership if teardown is cancelled or cutoff needs another attempt.
/// The reaper retries before returning the pod's resource reservations.
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

async fn account(meter: &EgressMeter, previous: &mut u64, current: u64) -> bool {
    let Some(delta) = current.checked_sub(*previous) else {
        // A reset/wrap is not an empty sample. Accounting cannot be recovered
        // by accepting a fresh baseline halfway through a pod lifetime.
        meter.fault().await;
        return false;
    };
    *previous = current;
    // Even a zero delta observes exhaustion caused by a concurrent broker.
    meter.observe(delta).await.is_ok()
}

async fn run(
    mut link: impl LinkIo,
    meter: Arc<EgressMeter>,
    initial: u64,
    mut stop: oneshot::Receiver<()>,
) {
    let mut previous = 0;
    let mut open = account(&meter, &mut previous, initial).await;
    let mut ticker = tokio::time::interval(INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    while open {
        tokio::select! {
            _ = &mut stop => break,
            _ = ticker.tick() => {}
        }
        match link.uploaded().await {
            Ok(current) => open = account(&meter, &mut previous, current).await,
            Err(err) => {
                tracing::error!(error = %err, "outbound link accounting failed");
                meter.fault().await;
                break;
            }
        }
    }
    let mut reported = false;
    loop {
        match link.close().await {
            Ok(()) => break,
            Err(err) => {
                meter.fault().await;
                if !reported {
                    tracing::error!(error = %err, "outbound link cutoff failed; retrying");
                    reported = true;
                }
                tokio::time::sleep(INTERVAL).await;
            }
        }
    }
    // Include traffic sent while the cutoff command was running. The raw
    // counter in the audit record remains useful if the ledger has clamped.
    match link.uploaded().await {
        Ok(current) => {
            account(&meter, &mut previous, current).await;
        }
        Err(_) => meter.fault().await,
    }
    meter.record_link(previous).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis::{EgressCeiling, EgressPace};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    #[derive(Default)]
    struct State {
        bytes: AtomicU64,
        closed: AtomicBool,
        unreadable: AtomicBool,
        close_failures: AtomicU64,
    }

    struct Fixture(Arc<State>);

    #[tonic::async_trait]
    impl LinkIo for Fixture {
        async fn uploaded(&mut self) -> io::Result<u64> {
            if self.0.unreadable.load(Ordering::SeqCst) {
                Err(io::Error::other("counter unavailable"))
            } else {
                Ok(self.0.bytes.load(Ordering::SeqCst))
            }
        }

        async fn close(&mut self) -> io::Result<()> {
            if self
                .0
                .close_failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                return Err(io::Error::other("temporary close failure"));
            }
            self.0.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    fn meter(dir: &std::path::Path) -> Arc<EgressMeter> {
        EgressMeter::new(
            EgressCeiling::new(100, EgressPace::Unpaced),
            dir.to_path_buf(),
            "link-test".into(),
        )
    }

    async fn until(mut done: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while !done() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn link_and_concurrent_broker_reservations_share_one_balance() {
        let dir = tempfile::tempdir().unwrap();
        let meter = meter(dir.path());
        let state = Arc::new(State::default());
        state.bytes.store(20, Ordering::SeqCst);
        let mut monitor = LinkMonitor::prepare(Fixture(state.clone()), meter.clone())
            .await
            .unwrap();
        until(|| meter.counted() == 20).await;
        let first = meter.admit(30, 0).await.unwrap();
        let second = meter.admit(10, 0).await.unwrap();
        state.bytes.store(40, Ordering::SeqCst);
        until(|| meter.counted() == 80).await;
        second.not_sent();
        first.sent();
        assert_eq!(meter.counted(), 70);
        meter.admit(30, 0).await.unwrap().sent();
        until(|| state.closed.load(Ordering::SeqCst)).await;
        assert!(meter.admit(1, 0).await.is_err());
        monitor.shutdown().await.unwrap();
        let log = std::fs::read_to_string(dir.path().join("lifecycle.log")).unwrap();
        assert_eq!(log.matches("egress_budget_exhausted").count(), 1);
        assert!(log.contains("outbound link bytes: 40"));
    }

    #[tokio::test]
    async fn ordinary_shutdown_accounts_last_sample_and_closes_link() {
        let dir = tempfile::tempdir().unwrap();
        let meter = meter(dir.path());
        let state = Arc::new(State::default());
        let mut monitor = LinkMonitor::prepare(Fixture(state.clone()), meter.clone())
            .await
            .unwrap();
        state.bytes.store(35, Ordering::SeqCst);
        monitor.shutdown().await.unwrap();
        assert_eq!(meter.counted(), 35);
        assert!(state.closed.load(Ordering::SeqCst));
        meter.admit(65, 0).await.unwrap().sent();
    }

    #[tokio::test]
    async fn unavailable_counter_refuses_broker_and_retries_link_close() {
        let dir = tempfile::tempdir().unwrap();
        let meter = meter(dir.path());
        let state = Arc::new(State::default());
        let mut monitor = LinkMonitor::prepare(Fixture(state.clone()), meter.clone())
            .await
            .unwrap();
        state.close_failures.store(1, Ordering::SeqCst);
        state.unreadable.store(true, Ordering::SeqCst);
        until(|| state.closed.load(Ordering::SeqCst)).await;
        assert!(matches!(
            meter.admit(1, 0).await,
            Err(portcullis::EgressRefusal::LedgerFault)
        ));
        monitor.shutdown().await.unwrap();
        let log = std::fs::read_to_string(dir.path().join("lifecycle.log")).unwrap();
        assert_eq!(log.matches("egress_ledger_fault").count(), 1);
    }

    #[tokio::test]
    async fn cancelled_teardown_keeps_monitor_owned_for_retry() {
        let dir = tempfile::tempdir().unwrap();
        let meter = meter(dir.path());
        let state = Arc::new(State::default());
        state.close_failures.store(100, Ordering::SeqCst);
        let monitor = LinkMonitor::prepare(Fixture(state.clone()), meter.clone())
            .await
            .unwrap();
        let slot = Arc::new(tokio::sync::Mutex::new(Some(monitor)));
        let owned = slot.clone();
        let teardown = tokio::spawn(async move { shutdown(&owned).await });
        until(|| state.close_failures.load(Ordering::SeqCst) < 100).await;
        teardown.abort();
        assert!(teardown.await.unwrap_err().is_cancelled());
        assert!(slot.lock().await.is_some());
        state.close_failures.store(0, Ordering::SeqCst);
        shutdown(&slot).await.unwrap();
        assert!(state.closed.load(Ordering::SeqCst));
        assert!(slot.lock().await.is_none());
    }

    #[tokio::test]
    async fn initial_read_is_required_and_counter_reset_is_not_a_refund() {
        let dir = tempfile::tempdir().unwrap();
        let meter = meter(dir.path());
        let state = Arc::new(State::default());
        state.unreadable.store(true, Ordering::SeqCst);
        assert!(
            LinkMonitor::prepare(Fixture(state.clone()), meter.clone())
                .await
                .is_err()
        );
        state.unreadable.store(false, Ordering::SeqCst);
        state.bytes.store(50, Ordering::SeqCst);
        let mut monitor = LinkMonitor::prepare(Fixture(state.clone()), meter.clone())
            .await
            .unwrap();
        until(|| meter.counted() == 50).await;
        state.bytes.store(10, Ordering::SeqCst);
        until(|| state.closed.load(Ordering::SeqCst)).await;
        assert!(matches!(
            meter.admit(1, 0).await,
            Err(portcullis::EgressRefusal::LedgerFault)
        ));
        monitor.shutdown().await.unwrap();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;
    use portcullis::{EgressCeiling, EgressPace};

    struct Network(crate::net::NetPlan);

    impl Drop for Network {
        fn drop(&mut self) {
            let _ = std::process::Command::new("ip")
                .args(["link", "del", &self.0.host_veth])
                .status();
            let _ = std::process::Command::new("ip")
                .args(["netns", "del", &self.0.netns])
                .status();
        }
    }

    async fn ip(args: &[&str]) {
        let output = tokio::process::Command::new("ip")
            .args(args)
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "ip {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "subprocess helper for the namespace test"]
    fn namespace_upload_fixture() {
        let destination = std::env::var("NUCLEUS_LINK_FIXTURE").expect("fixture destination");
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        socket.send_to(b"ordinary upload", destination).unwrap();
    }

    /// Ordinary UDP traffic on a real namespace/veth, with the production
    /// sysfs reader and link cutoff. Requires root and iproute2.
    #[tokio::test]
    #[ignore = "requires Linux network namespace privileges"]
    async fn real_link_uploads_share_broker_budget_and_close_at_exhaustion() {
        let id = uuid::Uuid::new_v4();
        let net = Network(
            crate::net::NetworkAllocator::new()
                .allocate(id, crate::net::netns_name(id))
                .unwrap(),
        );
        let plan = &net.0;
        ip(&["netns", "add", &plan.netns]).await;
        ip(&[
            "link",
            "add",
            &plan.host_veth,
            "type",
            "veth",
            "peer",
            "name",
            &plan.peer_veth,
            "netns",
            &plan.netns,
        ])
        .await;
        ip(&["addr", "add", "198.18.0.1/30", "dev", &plan.host_veth]).await;
        ip(&["link", "set", &plan.host_veth, "up"]).await;
        ip(&[
            "-n",
            &plan.netns,
            "addr",
            "add",
            "198.18.0.2/30",
            "dev",
            &plan.peer_veth,
        ])
        .await;
        ip(&["-n", &plan.netns, "link", "set", &plan.peer_veth, "up"]).await;
        let dir = tempfile::tempdir().unwrap();
        let ceiling = 1 << 20;
        let meter = EgressMeter::new(
            EgressCeiling::new(ceiling, EgressPace::Unpaced),
            dir.path().into(),
            id.to_string(),
        );
        let mut monitor = LinkMonitor::start(plan, meter.clone()).await.unwrap();
        let counter = std::path::Path::new("/sys/class/net")
            .join(&plan.host_veth)
            .join("statistics/rx_bytes");
        let before: u64 = tokio::fs::read_to_string(&counter)
            .await
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let sink = tokio::net::UdpSocket::bind("198.18.0.1:0").await.unwrap();
        let output = tokio::process::Command::new("ip")
            .args(["netns", "exec", &plan.netns])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "egress_link::linux_tests::namespace_upload_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env(
                "NUCLEUS_LINK_FIXTURE",
                sink.local_addr().unwrap().to_string(),
            )
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let mut body = [0; 128];
        let (len, _) = tokio::time::timeout(Duration::from_secs(3), sink.recv_from(&mut body))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&body[..len], b"ordinary upload");
        tokio::time::timeout(Duration::from_secs(3), async {
            while meter.counted() <= before {
                tokio::time::sleep(INTERVAL).await;
            }
        })
        .await
        .unwrap();
        let uploaded = meter.counted();
        assert!(uploaded < ceiling);
        // A normal broker send consumes the remaining allowance. The link
        // monitor sees exhaustion even if no further link packet is sent.
        meter.admit(ceiling - uploaded, 0).await.unwrap().sent();
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let flags = tokio::fs::read_to_string(
                    counter.parent().unwrap().parent().unwrap().join("flags"),
                )
                .await
                .unwrap();
                let flags = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).unwrap();
                if flags & 1 == 0 {
                    break;
                }
                tokio::time::sleep(INTERVAL).await;
            }
        })
        .await
        .unwrap();
        monitor.shutdown().await.unwrap();
        let log = std::fs::read_to_string(dir.path().join("lifecycle.log")).unwrap();
        assert!(log.contains("egress_budget_exhausted"));
        assert!(log.contains("egress_link_closed"));
        println!(
            "ordinary link traffic charged {uploaded} bytes; broker filled remainder; kernel link is down"
        );
    }
}

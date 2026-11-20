use super::*;
use portcullis::{EgressCeiling, EgressPace, EgressRefusal};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::mpsc;

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Accept(u64),
    Drop(u64),
}

struct Fixture {
    input: mpsc::Receiver<io::Result<u64>>,
    output: mpsc::Sender<Verdict>,
    closed: Arc<AtomicBool>,
    hold_accept: Option<oneshot::Receiver<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::SeqCst);
    }
}

#[tonic::async_trait]
impl PacketQueue for Fixture {
    type Packet = u64;
    fn bytes(packet: &u64) -> u64 {
        *packet
    }
    async fn next(&mut self) -> io::Result<u64> {
        self.input
            .recv()
            .await
            .ok_or_else(|| io::Error::other("receiver stopped"))?
    }
    async fn accept(&mut self, bytes: u64, charge: EgressCharge<'_>) -> io::Result<()> {
        self.output
            .send(Verdict::Accept(bytes))
            .await
            .map_err(io::Error::other)?;
        if let Some(hold) = self.hold_accept.take() {
            hold.await.map_err(io::Error::other)?;
        }
        charge.sent();
        Ok(())
    }
    async fn reject(&mut self, bytes: u64) -> io::Result<()> {
        self.output
            .send(Verdict::Drop(bytes))
            .await
            .map_err(io::Error::other)
    }
}

struct Harness {
    meter: Arc<EgressMeter>,
    input: mpsc::Sender<io::Result<u64>>,
    output: mpsc::Receiver<Verdict>,
    closed: Arc<AtomicBool>,
    clock: Arc<AtomicU64>,
    dir: tempfile::TempDir,
    /// A fake `/sys/class/net`, holding the host end of the pod's link.
    sysfs: tempfile::TempDir,
}

/// The fake link's name under [`Harness::sysfs`].
const LINK: &str = "vh-packet-test";

/// How often the harness's detector checks: short, so a test waits milliseconds.
const PERIOD: Duration = Duration::from_millis(5);

impl Harness {
    fn new(pace: EgressPace) -> (Self, Fixture) {
        let dir = tempfile::tempdir().unwrap();
        let meter = EgressMeter::new(
            EgressCeiling::new(1000, pace),
            dir.path().into(),
            "packet-test".into(),
        );
        let (input, rx) = mpsc::channel(16);
        let (tx, output) = mpsc::channel(16);
        let closed = Arc::new(AtomicBool::new(false));
        let queue = Fixture {
            input: rx,
            output: tx,
            closed: closed.clone(),
            hold_accept: None,
        };
        let sysfs = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(sysfs.path().join(LINK).join("statistics")).unwrap();
        let harness = Self {
            meter,
            input,
            output,
            closed,
            clock: Arc::new(AtomicU64::new(100)),
            dir,
            sysfs,
        };
        harness.set_link(0, 0);
        (harness, queue)
    }
    /// Set what the kernel says crossed the link since it came up.
    fn set_link(&self, bytes: u64, packets: u64) {
        let stats = self.sysfs.path().join(LINK).join("statistics");
        // Whole-file replace, so a concurrent read sees the old count or the new.
        for (name, value) in [("rx_bytes", bytes), ("rx_packets", packets)] {
            let tmp = stats.join(format!("{name}.tmp"));
            std::fs::write(&tmp, format!("{value}\n")).unwrap();
            std::fs::rename(&tmp, stats.join(name)).unwrap();
        }
    }
    fn serve(&self, queue: Fixture) -> LinkMonitor {
        let clock = self.clock.clone();
        let detector = bypass::Detector::start(
            bypass::SysfsCounters::receive(self.sysfs.path(), LINK),
            PERIOD,
        )
        .expect("the fake link has a baseline");
        LinkMonitor::serve_with_clock(queue, self.meter.clone(), detector, move || {
            clock.load(Ordering::SeqCst)
        })
    }
    fn lifecycle(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("lifecycle.log")).unwrap_or_default()
    }
    /// Wait until the meter refuses with a ledger fault: the cut.
    async fn until_cut(&self) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !matches!(
                self.meter.admit(0, 100).await,
                Err(EgressRefusal::LedgerFault)
            ) {
                tokio::time::sleep(PERIOD).await;
            }
        })
        .await
        .expect("the link check cut the pod's egress");
    }
    async fn send(&mut self, bytes: u64) -> Verdict {
        self.input.send(Ok(bytes)).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), self.output.recv())
            .await
            .unwrap()
            .unwrap()
    }
}

#[tokio::test]
async fn packet_and_broker_reservations_share_the_total_before_acceptance() {
    let (mut h, queue) = Harness::new(EgressPace::Unpaced);
    let mut monitor = h.serve(queue);
    let meter = h.meter.clone();
    let held = meter.admit(600, 100).await.unwrap();
    assert_eq!(h.send(300).await, Verdict::Accept(300));
    assert_eq!(meter.counted(), 900);
    held.not_sent();
    let held = meter.admit(650, 100).await.unwrap();
    assert_eq!(h.send(51).await, Verdict::Drop(51));
    assert_eq!(meter.counted(), 950);
    held.sent();
    monitor.shutdown().await.unwrap();
    assert!(h.closed.load(Ordering::SeqCst));
    assert!(meter.admit(1, 100).await.is_err());
    let log = std::fs::read_to_string(h.dir.path().join("lifecycle.log")).unwrap();
    assert_eq!(log.matches("egress_budget_exhausted").count(), 1);
    assert!(log.contains("accepted IP bytes: 300; rejected packets: 1"));
}

#[tokio::test]
async fn paced_packets_resume_in_the_next_shared_window() {
    let (mut h, queue) = Harness::new(EgressPace::PerWindow {
        bytes: 100,
        window_secs: 10.try_into().unwrap(),
    });
    let mut monitor = h.serve(queue);
    h.meter.admit(40, 100).await.unwrap().sent();
    assert_eq!(h.send(60).await, Verdict::Accept(60));
    assert_eq!(h.send(40).await, Verdict::Drop(40));
    assert!(matches!(
        h.meter.admit(1, 100).await,
        Err(EgressRefusal::RateExceeded { .. })
    ));
    h.clock.store(110, Ordering::SeqCst);
    assert_eq!(h.send(70).await, Verdict::Accept(70));
    h.meter.admit(30, 110).await.unwrap().sent();
    monitor.shutdown().await.unwrap();
    assert_eq!(h.meter.counted(), 200);
}

#[tokio::test]
async fn receiver_failure_closes_queue_and_refuses_new_broker_sends() {
    let (h, queue) = Harness::new(EgressPace::Unpaced);
    let mut monitor = h.serve(queue);
    h.input
        .send(Err(io::Error::other("socket unavailable")))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !h.closed.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    monitor.shutdown().await.unwrap();
    assert!(matches!(
        h.meter.admit(1, 100).await,
        Err(EgressRefusal::LedgerFault)
    ));
}

#[tokio::test]
async fn cancelled_teardown_keeps_queue_and_pending_charge_owned() {
    let (mut h, mut queue) = Harness::new(EgressPace::Unpaced);
    let (release, held) = oneshot::channel();
    queue.hold_accept = Some(held);
    let slot = Arc::new(tokio::sync::Mutex::new(Some(h.serve(queue))));
    assert_eq!(h.send(50).await, Verdict::Accept(50));
    let owned = slot.clone();
    let teardown = tokio::spawn(async move { shutdown(&owned).await });
    tokio::task::yield_now().await;
    teardown.abort();
    assert!(teardown.await.unwrap_err().is_cancelled());
    assert!(slot.lock().await.is_some());
    assert!(!h.closed.load(Ordering::SeqCst));
    assert_eq!(h.meter.counted(), 50);
    release.send(()).unwrap();
    shutdown(&slot).await.unwrap();
    assert!(h.closed.load(Ordering::SeqCst));
    assert!(slot.lock().await.is_none());
    assert_eq!(h.meter.counted(), 50);
}

/// #2905: the kernel counted more leaving the pod's link than the queue
/// admitted. Something sent without a reservation, so every path is cut and the
/// cut is a record the node signed.
#[tokio::test]
async fn a_link_that_sent_more_than_the_ledger_admitted_is_cut_and_signed() {
    let (mut h, queue) = Harness::new(EgressPace::Unpaced);
    let mut monitor = h.serve(queue);
    assert_eq!(h.send(100).await, Verdict::Accept(100));
    // The admitted packet's frame (100 + 14), and a full-size frame the queue
    // never saw.
    h.set_link(114 + 1_514, 2);
    h.until_cut().await;
    assert!(
        matches!(h.meter.admit(1, 100).await, Err(EgressRefusal::LedgerFault)),
        "a broker send is refused too"
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while !h.closed.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the packet queue is closed, so its rule drops what follows");
    monitor.shutdown().await.unwrap();

    let log = h.lifecycle();
    assert_eq!(log.matches("egress_link_bypass").count(), 1, "{log}");
    let line = log
        .lines()
        .find(|l| l.contains("egress_link_bypass"))
        .unwrap_or_else(|| panic!("the bypass is recorded: {log}"));
    let record: crate::egress_meter::LinkRecord =
        serde_json::from_str(line).expect("a signed link record");
    assert_eq!(record.dimension, "egress.link");
    assert!(
        record.result.contains("1628 bytes in 2 frames")
            && record.result.contains("admitted 100 bytes in 1 packets"),
        "the record carries the counts: {}",
        record.result
    );
    let node_key = crate::egress_meter::test_authority().root_pubkey_hex();
    assert!(
        record.verifies_under(&node_key),
        "signed by the node's root key"
    );
    let mut forged = record.clone();
    forged.result = forged.result.replace("1628", "114");
    assert!(
        !forged.verifies_under(&node_key),
        "a rewritten count verifies"
    );
    // Its own signature space: not an exhaustion record, not a pod receipt.
    assert!(!crate::pod_authority::verify_record(
        crate::pod_authority::SignedRecord::EgressExhaustion,
        &node_key,
        &record.preimage(),
        &record.signature
    ));
    assert!(!crate::pod_authority::verify_pod_receipt(
        &node_key,
        &record.preimage(),
        &record.signature
    ));
}

/// A kernel count that is exactly what was admitted, plus one Ethernet header
/// per packet, is consistent: nothing is cut and nothing is recorded.
#[tokio::test]
async fn a_link_whose_kernel_count_matches_the_ledger_is_left_alone() {
    let (mut h, queue) = Harness::new(EgressPace::Unpaced);
    let mut monitor = h.serve(queue);
    assert_eq!(h.send(100).await, Verdict::Accept(100));
    assert_eq!(h.send(200).await, Verdict::Accept(200));
    h.set_link(300 + 2 * bypass::ETH_HLEN, 2);
    // Many periods: a cut, if there were one, would have happened by now.
    tokio::time::sleep(PERIOD * 20).await;
    assert_eq!(
        h.send(50).await,
        Verdict::Accept(50),
        "the link still admits"
    );
    h.meter
        .admit(1, 100)
        .await
        .expect("and so does the broker")
        .sent();
    monitor.shutdown().await.unwrap();
    assert_eq!(h.meter.counted(), 351);
    let log = h.lifecycle();
    assert!(!log.contains("egress_link"), "{log}");
}

/// Counters that cannot be read are reported as a check that could not be made,
/// by name — never as "no bypass" — and the pod's egress is cut (fail-closed).
#[tokio::test]
async fn an_unreadable_link_counter_is_reported_as_could_not_check() {
    let (mut h, queue) = Harness::new(EgressPace::Unpaced);
    let mut monitor = h.serve(queue);
    assert_eq!(h.send(100).await, Verdict::Accept(100));
    std::fs::remove_file(
        h.sysfs
            .path()
            .join(LINK)
            .join("statistics")
            .join("rx_bytes"),
    )
    .unwrap();
    h.until_cut().await;
    monitor.shutdown().await.unwrap();

    let log = h.lifecycle();
    assert!(!log.contains("egress_link_bypass"), "not a finding: {log}");
    let line = log
        .lines()
        .find(|l| l.contains("egress_link_unchecked"))
        .unwrap_or_else(|| panic!("the unread check is recorded by name: {log}"));
    let record: crate::egress_meter::LinkRecord =
        serde_json::from_str(line).expect("a signed link record");
    assert!(
        record.result.contains("could not be made")
            && record.result.contains("not a finding of no bypass"),
        "{}",
        record.result
    );
    assert!(
        record.result.contains("rx_bytes"),
        "names the counter: {}",
        record.result
    );
    assert!(record.verifies_under(&crate::egress_meter::test_authority().root_pubkey_hex()));
}

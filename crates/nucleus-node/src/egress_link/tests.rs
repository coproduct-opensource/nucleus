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
}

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
        (
            Self {
                meter,
                input,
                output,
                closed,
                clock: Arc::new(AtomicU64::new(100)),
                dir,
            },
            queue,
        )
    }
    fn serve(&self, queue: Fixture) -> LinkMonitor {
        let clock = self.clock.clone();
        LinkMonitor::serve_with_clock(queue, self.meter.clone(), move || {
            clock.load(Ordering::SeqCst)
        })
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

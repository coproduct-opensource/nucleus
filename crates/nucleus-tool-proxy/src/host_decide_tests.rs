//! The shadow client against an in-memory host.
//!
//! The host here is a double that speaks the P7 frames with the protocol
//! crate's own codec and ledger, and decides by a rule the test picks. It is
//! not the node's decision service — that one, and the agreement corpus run
//! through it, are tested in `nucleus-node`'s `host_decide_tests`. What is
//! tested here is this side: what it sends, in what order, what it counts, and
//! that nothing it does can hold up the decision it shadows.

use std::sync::Mutex;

use nucleus::portcullis::{CapabilityLevel, PermissionLattice};
use nucleus_decision_protocol::host::DecisionLedger;
use nucleus_decision_protocol::{DenyReason, body_len};
use tokio::io::DuplexStream;

use super::*;

/// What the double was sent, by frame kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sent {
    Observe,
    Decide(Operation),
    Shadow,
}

/// How the double behaves.
#[derive(Clone, Copy)]
enum HostRule {
    /// Decide as this function says.
    Decide(fn(Operation) -> Outcome),
    /// Answer a Decide with an Observed — not its answer.
    Garble,
}

#[derive(Default)]
struct Seen {
    frames: Mutex<Vec<Sent>>,
    dials: AtomicU64,
}

async fn double(mut io: DuplexStream, rule: HostRule, seen: Arc<Seen>) {
    let mut ledger = DecisionLedger::new(7);
    let mut pending = None;
    loop {
        let mut prefix = [0u8; LEN_PREFIX];
        if io.read_exact(&mut prefix).await.is_err() {
            return;
        }
        let mut body = vec![0u8; body_len(prefix).unwrap()];
        io.read_exact(&mut body).await.unwrap();
        let reply = match GuestFrame::decode_body(&body).unwrap() {
            GuestFrame::Observe { seq, .. } => {
                seen.frames.lock().unwrap().push(Sent::Observe);
                HostFrame::Observed { seq }
            }
            GuestFrame::Decide {
                seq,
                op,
                subject,
                args_digest,
            } => {
                assert_eq!(
                    args_digest,
                    nucleus_decision_protocol::kernel::args_digest(op, &subject)
                );
                seen.frames.lock().unwrap().push(Sent::Decide(op));
                let decide = match rule {
                    HostRule::Decide(f) => f,
                    HostRule::Garble => {
                        io.write_all(&HostFrame::Observed { seq }.encode().unwrap())
                            .await
                            .unwrap();
                        continue;
                    }
                };
                let outcome = decide(op);
                pending = Some(outcome);
                let verdict = match outcome {
                    Outcome::Allowed => Verdict::Allowed {
                        decision_id: ledger.allow(args_digest).unwrap(),
                    },
                    Outcome::Denied { reason } => Verdict::Denied { reason },
                    Outcome::ApprovalRequired => Verdict::ApprovalRequired {
                        approval_id: ledger.require_approval(args_digest).unwrap(),
                    },
                };
                HostFrame::Verdict { seq, verdict }
            }
            GuestFrame::Shadow { seq, local, .. } => {
                seen.frames.lock().unwrap().push(Sent::Shadow);
                let host = pending.take().expect("a Shadow follows its Decide");
                HostFrame::Compared {
                    seq,
                    agreement: Agreement::of(host, local),
                }
            }
            GuestFrame::Redeem { .. } => panic!("the shadow client never redeems"),
        };
        io.write_all(&reply.encode().unwrap()).await.unwrap();
    }
}

fn dialer(rule: HostRule, seen: Arc<Seen>) -> Dialer {
    Arc::new(move || {
        seen.dials.fetch_add(1, Ordering::SeqCst);
        let (client, server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(double(server, rule, Arc::clone(&seen)));
        Box::pin(async move { Ok(Box::new(client) as Box<dyn Duplex>) })
    })
}

/// The host decides as an honest kernel under `permissive` would — which is
/// what the local kernel in these tests is.
fn allow_all(_: Operation) -> Outcome {
    Outcome::Allowed
}

/// A host whose policy refuses commands.
fn no_commands(op: Operation) -> Outcome {
    match op {
        Operation::RunBash => Outcome::Denied {
            reason: DenyReason::NotGranted,
        },
        _ => Outcome::Allowed,
    }
}

fn decide(kernel: &mut Kernel, graph: &FlowGraph, op: Operation, subject: &str) -> KernelVerdict {
    let term = nucleus::portcullis::ActionTerm::from_operation(op, subject);
    kernel.decide_term_with_flow(term, Some(graph)).0.verdict
}

fn permissive_kernel() -> Kernel {
    Kernel::new(PermissionLattice::permissive())
}

#[tokio::test]
async fn off_counts_nothing_and_says_off() {
    let off = HostDecide::Off;
    let k = permissive_kernel();
    off.submit(
        &k,
        &FlowGraph::new(),
        Operation::ReadFiles,
        "a",
        &KernelVerdict::Allow,
    );
    assert_eq!(off.snapshot(), None);
    assert_eq!(off.health_json()["mode"], "off");
    // Off is what a proxy that serves no vsock gets: it is not in a guest.
    assert!(matches!(HostDecide::for_transport(false), HostDecide::Off));
}

/// The host's `Agreement` is what is counted, both ways.
#[tokio::test]
async fn agreement_is_counted_as_the_host_reports_it() {
    let seen = Arc::new(Seen::default());
    let hd = HostDecide::start(dialer(HostRule::Decide(no_commands), Arc::clone(&seen)));
    let mut k = permissive_kernel();
    let g = FlowGraph::new();
    for (op, subject) in [
        (Operation::ReadFiles, "src/main.rs"),
        (Operation::RunBash, "cargo test"),
        (Operation::WriteFiles, "out.txt"),
    ] {
        let v = decide(&mut k, &g, op, subject);
        hd.submit(&k, &g, op, subject, &v);
    }
    hd.flush().await;
    let s = hd.snapshot().expect("on");
    assert_eq!((s.agree, s.disagree, s.unavailable), (2, 1, 0));
    assert_eq!(hd.health_json()["disagree"], 1);
    // One channel for the one kernel session; the taint went once, first.
    assert_eq!(seen.dials.load(Ordering::SeqCst), 1);
    assert_eq!(
        *seen.frames.lock().unwrap(),
        vec![
            Sent::Observe,
            Sent::Decide(Operation::ReadFiles),
            Sent::Shadow,
            Sent::Decide(Operation::RunBash),
            Sent::Shadow,
            Sent::Decide(Operation::WriteFiles),
            Sent::Shadow,
        ]
    );
}

/// The taint is re-reported when — and only when — the graph's report changes.
#[tokio::test]
async fn the_taint_goes_when_it_moves() {
    let seen = Arc::new(Seen::default());
    let hd = HostDecide::start(dialer(HostRule::Decide(allow_all), Arc::clone(&seen)));
    let mut k = permissive_kernel();
    let mut g = FlowGraph::new();
    let v = decide(&mut k, &g, Operation::ReadFiles, "a");
    hd.submit(&k, &g, Operation::ReadFiles, "a", &v);
    g.insert_observation(nucleus::portcullis::NodeKind::WebContent, &[], 1)
        .unwrap();
    let v = decide(&mut k, &g, Operation::ReadFiles, "b");
    hd.submit(&k, &g, Operation::ReadFiles, "b", &v);
    let v = decide(&mut k, &g, Operation::ReadFiles, "c");
    hd.submit(&k, &g, Operation::ReadFiles, "c", &v);
    hd.flush().await;
    let observes = seen
        .frames
        .lock()
        .unwrap()
        .iter()
        .filter(|f| **f == Sent::Observe)
        .count();
    assert_eq!(observes, 2, "{:?}", seen.frames.lock().unwrap());
}

/// Two kernel sessions, two channels: the host must not see one kernel's
/// history interleaved with another's.
#[tokio::test]
async fn each_kernel_session_gets_its_own_channel() {
    let seen = Arc::new(Seen::default());
    let hd = HostDecide::start(dialer(HostRule::Decide(allow_all), Arc::clone(&seen)));
    let g = FlowGraph::new();
    let (mut a, mut b) = (permissive_kernel(), permissive_kernel());
    for first in [true, false, true] {
        let k = if first { &mut a } else { &mut b };
        let v = decide(k, &g, Operation::ReadFiles, "x");
        hd.submit(k, &g, Operation::ReadFiles, "x", &v);
    }
    hd.flush().await;
    assert_eq!(seen.dials.load(Ordering::SeqCst), 2);
    assert_eq!(hd.snapshot().unwrap().agree, 3);
}

/// An unreachable host is a typed `HostUnavailable`, counted, and the
/// decision point never waited for it.
#[tokio::test]
async fn an_unreachable_host_is_counted_and_never_waited_for() {
    let refused: Dialer = Arc::new(|| {
        Box::pin(async { Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)) })
    });
    let hd = HostDecide::start(refused);
    let k = permissive_kernel();
    hd.submit(
        &k,
        &FlowGraph::new(),
        Operation::ReadFiles,
        "a",
        &KernelVerdict::Allow,
    );
    hd.flush().await;
    let s = hd.snapshot().unwrap();
    assert_eq!((s.agree, s.disagree, s.unavailable), (0, 0, 1));
    assert_eq!(s.last_unavailable, Some(HostUnavailable::Connect));

    // A host that never answers the dial: `submit` still returns at once.
    let hangs: Dialer = Arc::new(|| Box::pin(std::future::pending()));
    let hd = HostDecide::start(hangs);
    let started = std::time::Instant::now();
    for _ in 0..10 {
        hd.submit(
            &k,
            &FlowGraph::new(),
            Operation::ReadFiles,
            "a",
            &KernelVerdict::Allow,
        );
    }
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "submit waited on the host"
    );
}

/// A full queue drops the shadow, never blocks the decision, and says why.
#[tokio::test]
async fn a_full_queue_is_backlog_not_a_wait() {
    let hangs: Dialer = Arc::new(|| Box::pin(std::future::pending()));
    let hd = HostDecide::start(hangs);
    let k = permissive_kernel();
    let g = FlowGraph::new();
    for _ in 0..(QUEUE + 64) {
        hd.submit(&k, &g, Operation::ReadFiles, "a", &KernelVerdict::Allow);
    }
    let s = hd.snapshot().unwrap();
    assert!(s.unavailable >= 63, "{s:?}");
    assert_eq!(s.last_unavailable, Some(HostUnavailable::Backlog));
}

/// A host that answers the wrong frame is a protocol failure; the channel is
/// dropped, and the next decision opens a fresh one.
#[tokio::test]
async fn a_garbled_answer_drops_the_channel() {
    let seen = Arc::new(Seen::default());
    let hd = HostDecide::start(dialer(HostRule::Garble, Arc::clone(&seen)));
    let k = permissive_kernel();
    let g = FlowGraph::new();
    for _ in 0..2 {
        hd.submit(&k, &g, Operation::ReadFiles, "a", &KernelVerdict::Allow);
    }
    hd.flush().await;
    let s = hd.snapshot().unwrap();
    assert_eq!(
        (s.unavailable, s.last_unavailable),
        (2, Some(HostUnavailable::Protocol))
    );
    assert_eq!(seen.dials.load(Ordering::SeqCst), 2);
}

/// The HTTP chokepoint shadows every decision it records — a refusal as much
/// as an allow — and still returns its OWN answer.
#[tokio::test]
async fn the_http_chokepoint_shadows_and_still_enforces_its_own_answer() {
    let seen = Arc::new(Seen::default());
    // The host would allow commands; the local policy refuses them.
    let hd = HostDecide::start(dialer(HostRule::Decide(allow_all), Arc::clone(&seen)));
    let mut policy = PermissionLattice::permissive();
    policy.capabilities.run_bash = CapabilityLevel::Never;
    let mut k = Kernel::new(policy);
    let g = FlowGraph::new();
    struct Discard;
    impl nucleus::portcullis::verdict_sink::VerdictSink for Discard {
        fn record(
            &self,
            _: nucleus::portcullis::verdict_sink::VerdictContext,
        ) -> Result<(), nucleus::portcullis::verdict_sink::SinkError> {
            Ok(())
        }
        fn preflight(
            &self,
            _: Operation,
        ) -> Result<(), nucleus::portcullis::verdict_sink::SinkError> {
            Ok(())
        }
    }
    let sink = Discard;
    let env = || crate::mediation::MediationEnv {
        sink: &sink,
        actor: nucleus::portcullis::verdict_sink::ActorIdentity::Unknown,
        transport: "http",
        grants: &crate::mediation::NoGrants,
        shadow: &hd,
    };
    let run = crate::mediation::decide_and_record(env(), &mut k, &g, Operation::RunBash, "ls");
    assert!(run.is_err(), "the local refusal is what the caller gets");
    let read = crate::mediation::decide_and_record(env(), &mut k, &g, Operation::ReadFiles, "a");
    assert!(read.is_ok());
    hd.flush().await;
    let s = hd.snapshot().unwrap();
    assert_eq!((s.agree, s.disagree), (1, 1));
    assert!(
        seen.frames
            .lock()
            .unwrap()
            .contains(&Sent::Decide(Operation::RunBash))
    );
}

#[tokio::test]
async fn an_oversized_subject_is_unavailable_never_a_comparison_of_its_prefix() {
    let seen = Arc::new(Seen::default());
    let hd = HostDecide::start(dialer(HostRule::Decide(allow_all), Arc::clone(&seen)));
    let k = Kernel::new(PermissionLattice::permissive());
    let g = FlowGraph::new();
    let subject = "é".repeat(nucleus_decision_protocol::MAX_SUBJECT_LEN);
    hd.submit(
        &k,
        &g,
        Operation::ReadFiles,
        &subject,
        &KernelVerdict::Allow,
    );
    hd.flush().await;
    let s = hd.snapshot().unwrap();
    assert_eq!((s.agree, s.disagree, s.unavailable), (0, 0, 1));
    assert_eq!(s.last_unavailable, Some(HostUnavailable::SubjectTooLong));
    assert!(seen.frames.lock().unwrap().is_empty());
}

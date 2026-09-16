//! Which guest-API commands commute — measured, not declared.
//!
//! Treat the command alphabet as the axes of a cube. A 2-face `(a, b)` is FILLED
//! when `a ; b` and `b ; a` are indistinguishable to the host, and HOLLOW when
//! some reachable state tells them apart. That is the higher-dimensional
//! automaton view of concurrent effects (Pratt 1991): independent effects fill
//! squares, conflicts leave them hollow. The hollow faces ARE the grammar's
//! sequencing laws; the filled ones are what a walk may skip, one interleaving per
//! class (partial-order reduction).
//!
//! # What "indistinguishable" means here
//!
//! From the same starting state, on two fresh copies of the pod's host material:
//! each command's reply is the same in both orders, and the host's record after
//! both is the same — the one-shot latches, personalisation, the snapshot
//! barrier, and the receipts collected. A reply whose bytes differ between two
//! runs of the SAME command from the SAME state (a freshly issued certificate)
//! is compared by outcome only, and the census reports which commands those are.
//!
//! # The host is in the alphabet
//!
//! Guest commands alone barely conflict: personalising and `SNAPSHOT_READY`
//! touch different state, so their final states agree in either order. A5's
//! non-commutation is between the guest and the HOST'S snapshot decision. So the
//! alphabet includes [`Letter::HostSnapshotQuery`], whose reply is the
//! `clone_safety` verdict at that moment. A5 must then be rediscovered by the
//! census, which is what makes the census's own answer non-vacuous.
//!
//! # What is asserted
//!
//! The measured hollow faces equal [`declared_hollow`], in both directions: a
//! new hollow face (a new sequencing law nobody wrote down) fails, and so does a
//! declared face that has filled (a law that stopped holding, or a stale entry).
//! Same for which commands are not idempotent.
//!
//! # What this does not reach
//!
//! - Which commands personalise is read from `personalizes_the_vm` on both
//!   sides, so the census cannot catch that classification being wrong — only
//!   the laws that follow from it. The walk makes the same choice (ADR 0007 G).
//! - Starting states are every reachable host state under full and under empty
//!   provisioning. Mixed provisioning (one command provisioned, the other not)
//!   is not enumerated.
//! - Squares, not higher cubes: an interaction only three commands together
//!   produce is not looked for.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::Ordering;

use super::*;
use crate::effect_footprint::{self, Footprint};

/// One axis of the cube.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Letter {
    Guest(usize),
    Unknown,
    HostSnapshotQuery,
}

impl Letter {
    fn all() -> Vec<Letter> {
        (0..COMMANDS.len())
            .map(Letter::Guest)
            .chain([Letter::Unknown, Letter::HostSnapshotQuery])
            .collect()
    }

    fn name(self) -> &'static str {
        match self {
            Letter::Guest(i) => COMMANDS.get(i).map(|c| wire_name(*c)).unwrap_or("?"),
            Letter::Unknown => "UNKNOWN",
            Letter::HostSnapshotQuery => "host:snapshot?",
        }
    }
}

/// What the host saw a letter do. `Served` keeps the body; whether the body is
/// compared depends on whether the command's body is stable (see module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Served(String),
    Refused(Refusal),
    Verdict(SnapshotSafety),
}

impl Seen {
    fn outcome_only(&self) -> Seen {
        match self {
            Seen::Served(_) => Seen::Served(String::new()),
            other => other.clone(),
        }
    }
}

/// The host's record of a pod, after a sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Record {
    personalized: bool,
    at_barrier: bool,
    broker_served: bool,
    mediation_key_served: bool,
    audit_served: bool,
    receipts: Vec<String>,
}

impl Record {
    fn initial() -> Record {
        Record {
            personalized: false,
            at_barrier: false,
            broker_served: false,
            mediation_key_served: false,
            audit_served: false,
            receipts: Vec::new(),
        }
    }

    /// Every host state reachable under `p`.
    fn reachable(p: Provision) -> Vec<Record> {
        let bits: u32 = if p.broker_secret { 5 } else { 2 };
        let receipt_options: &[bool] = if p.receipts { &[false, true] } else { &[false] };
        let mut out = Vec::new();
        for mask in 0..(1u32 << bits) {
            for &receipt in receipt_options {
                let bit = |i: u32| mask & (1 << i) != 0;
                out.push(Record {
                    personalized: bit(0),
                    at_barrier: bit(1),
                    broker_served: bits > 2 && bit(2),
                    mediation_key_served: bits > 3 && bit(3),
                    audit_served: bits > 4 && bit(4),
                    receipts: if receipt {
                        vec!["{\"receipt\":\"earlier\"}".to_string()]
                    } else {
                        Vec::new()
                    },
                });
            }
        }
        out
    }
}

const FULL: Provision = Provision {
    broker_secret: true,
    mediation_key: true,
    mediation_spiffe_id: true,
    audit_creds: true,
    pod_spec: true,
    dlc_admission: true,
    pod_certificate: true,
    task_token: true,
    caller_token: true,
    receipts: true,
};

const EMPTY: Provision = Provision {
    broker_secret: false,
    mediation_key: false,
    mediation_spiffe_id: false,
    audit_creds: false,
    pod_spec: false,
    dlc_admission: false,
    pod_certificate: false,
    task_token: false,
    caller_token: false,
    receipts: false,
};

/// Run `letters` on fresh host material; what each did, and the record after.
async fn run(
    manager: &IdentityManager,
    provision: Provision,
    start: &Record,
    letters: &[Letter],
) -> (Vec<Seen>, Record) {
    let dir = tempfile::tempdir().expect("tempdir");
    let material = material_for(provision, dir.path());
    // Put the pod in `start`: this record is the whole of its mutable host state.
    material
        .personalized
        .store(start.personalized, Ordering::SeqCst);
    material
        .at_snapshot_barrier
        .store(start.at_barrier, Ordering::SeqCst);
    material
        .broker_secret_served
        .store(start.broker_served, Ordering::SeqCst);
    material
        .mediation_key_served
        .store(start.mediation_key_served, Ordering::SeqCst);
    material
        .audit_creds_served
        .store(start.audit_served, Ordering::SeqCst);
    if !start.receipts.is_empty() {
        let mut lines = start.receipts.join("\n");
        lines.push('\n');
        std::fs::write(dir.path().join("collected-receipts.jsonl"), lines).expect("receipts");
    }
    let pod_id = uuid::Uuid::nil();
    let mut seen = Vec::with_capacity(letters.len());
    for letter in letters {
        let s = match letter {
            Letter::HostSnapshotQuery => Seen::Verdict(clone_safety(
                CLEAN_BOOT_ARGS,
                material.at_snapshot_barrier.load(Ordering::SeqCst),
                material.personalized.load(Ordering::SeqCst),
                &MountState::NeverMounted,
            )),
            Letter::Guest(i) => {
                let frame = format!("{}\n", wire_name(COMMANDS[*i]));
                let mut rest: &[u8] = b"{\"receipt\":\"census\"}\n";
                match serve_frame(frame.as_bytes(), &mut rest, manager, pod_id, &material).await {
                    Ok(body) => Seen::Served(body),
                    Err(r) => Seen::Refused(r),
                }
            }
            Letter::Unknown => {
                let frame = format!("{UNKNOWN_TOKEN}\n");
                let mut rest: &[u8] = b"";
                match serve_frame(frame.as_bytes(), &mut rest, manager, pod_id, &material).await {
                    Ok(body) => Seen::Served(body),
                    Err(r) => Seen::Refused(r),
                }
            }
        };
        seen.push(s);
    }
    let receipts = std::fs::read_to_string(dir.path().join("collected-receipts.jsonl"))
        .map(|s| s.lines().map(str::to_string).collect())
        .unwrap_or_default();
    let record = Record {
        personalized: material.personalized.load(Ordering::SeqCst),
        at_barrier: material.at_snapshot_barrier.load(Ordering::SeqCst),
        broker_served: material.broker_secret_served.load(Ordering::SeqCst),
        mediation_key_served: material.mediation_key_served.load(Ordering::SeqCst),
        audit_served: material.audit_creds_served.load(Ordering::SeqCst),
        receipts,
    };
    (seen, record)
}

/// The census result.
#[derive(Debug, Default)]
struct Census {
    /// Hollow faces, each with one witness: the starting state and what differed.
    hollow: BTreeMap<(Letter, Letter), String>,
    filled: usize,
    /// Commands whose `a ; a` differs from `a` to the host.
    not_idempotent: BTreeMap<Letter, String>,
    /// Commands whose served body differs between two identical runs.
    unstable_bodies: BTreeSet<Letter>,
}

async fn take_census() -> Census {
    let manager = IdentityManager::new("census.local", std::time::Duration::from_secs(3600))
        .expect("identity manager");
    let letters = Letter::all();
    let mut census = Census::default();

    // Which bodies are stable: the same command from the same state, twice.
    for &p in &[FULL, EMPTY] {
        for &l in &letters {
            let (a, _) = run(&manager, p, &Record::initial(), &[l]).await;
            let (b, _) = run(&manager, p, &Record::initial(), &[l]).await;
            if a != b {
                census.unstable_bodies.insert(l);
            }
        }
    }
    let compare = |l: Letter, s: &Seen| {
        if census.unstable_bodies.contains(&l) {
            s.outcome_only()
        } else {
            s.clone()
        }
    };

    // Starting states: EVERY reachable host state, not a sample. With everything
    // provisioned, all 32 flag combinations are reachable, with and without a
    // collected receipt; with nothing provisioned, no one-shot can be served and
    // no receipt collected, leaving the 4 personalised/barrier combinations.
    for &p in &[FULL, EMPTY] {
        for start in Record::reachable(p) {
            let at = |extra: &str| {
                format!(
                    "from {} provision, state {start:?}: {extra}",
                    if p.broker_secret { "full" } else { "empty" },
                )
            };
            for (i, &a) in letters.iter().enumerate() {
                // Idempotence: `a ; a` against `a`, by the record and a's first reply.
                let (once_seen, once) = run(&manager, p, &start, &[a]).await;
                let (twice_seen, twice) = run(&manager, p, &start, &[a, a]).await;
                let first = compare(a, &once_seen[0]);
                let second = compare(a, &twice_seen[1]);
                if (once != twice || first != second) && !census.not_idempotent.contains_key(&a) {
                    census.not_idempotent.insert(
                        a,
                        at(&format!(
                            "once {first:?} / again {second:?}; record equal={}",
                            once == twice
                        )),
                    );
                }

                for &b in &letters[i + 1..] {
                    let (ab_seen, ab) = run(&manager, p, &start, &[a, b]).await;
                    let (ba_seen, ba) = run(&manager, p, &start, &[b, a]).await;
                    let k = 0;
                    let (ab_a, ab_b) = (compare(a, &ab_seen[k]), compare(b, &ab_seen[k + 1]));
                    let (ba_b, ba_a) = (compare(b, &ba_seen[k]), compare(a, &ba_seen[k + 1]));
                    let differs = if ab_a != ba_a {
                        Some(format!(
                            "{} answered {ab_a:?} first, {ba_a:?} second",
                            a.name()
                        ))
                    } else if ab_b != ba_b {
                        Some(format!(
                            "{} answered {ba_b:?} first, {ab_b:?} second",
                            b.name()
                        ))
                    } else if ab != ba {
                        Some(format!("records differ: {ab:?} vs {ba:?}"))
                    } else {
                        None
                    };
                    match differs {
                        Some(why) => {
                            census.hollow.entry((a, b)).or_insert_with(|| at(&why));
                        }
                        None => census.filled += 1,
                    }
                }
            }
        }
    }
    census
}

/// What the host keeps about a guest, as resources a letter reads or writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Resource {
    /// Whether anything that names this pod has been handed over.
    Personalized,
    /// Whether the guest announced its snapshot barrier.
    AtBarrier,
    /// Whether a one-shot has been served.
    Served(OneShot),
    /// The collected receipt log.
    ReceiptLog,
}

/// Each letter's footprint. Personalisation is read from the production
/// `personalizes_the_vm`, so the code stays the one decider of that fact; the rest
/// is an exhaustive match, so a new command is a decision here.
fn footprint(letter: Letter) -> Footprint<Resource> {
    match letter {
        Letter::Guest(i) => {
            let Some(cmd) = COMMANDS.get(i) else {
                return Footprint::pure();
            };
            let fp = if cmd.personalizes_the_vm() {
                Footprint::pure().set(Resource::Personalized)
            } else {
                Footprint::pure()
            };
            match cmd {
                Cmd::SnapshotReady => fp.set(Resource::AtBarrier),
                Cmd::FetchBrokerSecret => fp.update(Resource::Served(OneShot::BrokerSecret)),
                Cmd::FetchMediationKey => fp.update(Resource::Served(OneShot::MediationKey)),
                Cmd::FetchAuditCredentials => {
                    fp.update(Resource::Served(OneShot::AuditCredentials))
                }
                Cmd::ShipReceipt => fp.update(Resource::ReceiptLog),
                Cmd::FetchSvid
                | Cmd::FetchBundle
                | Cmd::Ping
                | Cmd::FetchPodCallerToken
                | Cmd::FetchTaskToken
                | Cmd::FetchPodCertificate
                | Cmd::FetchDlcAdmission
                | Cmd::FetchPodSpec
                | Cmd::PodList => fp,
            }
        }
        Letter::Unknown => Footprint::pure(),
        // A5: the snapshot decision reads both facts it decides on.
        Letter::HostSnapshotQuery => Footprint::pure()
            .read(Resource::Personalized)
            .read(Resource::AtBarrier),
    }
}

/// The order-dependent faces, DERIVED from the footprints (see `effect_footprint`).
///
/// A5 falls out: the host's snapshot decision reads what every personalising
/// command and the barrier announcement write.
fn declared_hollow() -> BTreeSet<(&'static str, &'static str)> {
    effect_footprint::hollow_faces(&Letter::all(), footprint)
        .into_iter()
        .map(|(a, b)| (a.name(), b.name()))
        .collect()
}

/// A2 and the receipt log, derived: the letters that update what they read.
fn declared_not_idempotent() -> BTreeSet<&'static str> {
    effect_footprint::not_idempotent(&Letter::all(), footprint)
        .into_iter()
        .map(Letter::name)
        .collect()
}

/// Partial-order reduction of the guest walk, grounded on this census.
mod por;

#[test]
fn the_guest_api_commutes_exactly_where_the_design_says() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let census = runtime.block_on(take_census());

    let letters = Letter::all();
    let faces = letters.len() * (letters.len() - 1) / 2;
    eprintln!(
        "census: {} letters, {faces} faces; filled (across all starting states) {} checks; hollow faces {}",
        letters.len(),
        census.filled,
        census.hollow.len()
    );
    eprintln!(
        "  faces filled from every reachable state (explorable in one order): {}/{faces}",
        faces - census.hollow.len()
    );
    for ((a, b), why) in &census.hollow {
        eprintln!("  hollow  {} ; {}  —  {why}", a.name(), b.name());
    }
    for (a, why) in &census.not_idempotent {
        eprintln!("  not idempotent  {}  —  {why}", a.name());
    }
    eprintln!(
        "  bodies compared by outcome only: {:?}",
        census
            .unstable_bodies
            .iter()
            .map(|l| l.name())
            .collect::<Vec<_>>()
    );

    // Non-vacuity: the census must find the law it was built to find.
    assert!(
        census
            .hollow
            .contains_key(&(Letter::Guest(0), Letter::HostSnapshotQuery)),
        "A5 was not rediscovered: FETCH_SVID ; host:snapshot? came out filled"
    );

    // Keys are (earlier letter, later letter) and the host query is the last
    // letter, so a guest-against-host face already reads (guest, host), as declared.
    let measured: BTreeSet<(&str, &str)> = census
        .hollow
        .keys()
        .map(|(a, b)| (a.name(), b.name()))
        .collect();
    let declared = declared_hollow();
    let undeclared: Vec<_> = measured.difference(&declared).collect();
    let stale: Vec<_> = declared.difference(&measured).collect();
    assert!(
        undeclared.is_empty() && stale.is_empty(),
        "hollow faces nobody declared: {undeclared:?}; declared faces that filled: {stale:?}"
    );

    let measured: BTreeSet<&str> = census.not_idempotent.keys().map(|l| l.name()).collect();
    let declared = declared_not_idempotent();
    assert_eq!(
        measured, declared,
        "non-idempotent commands differ from the declaration"
    );
}

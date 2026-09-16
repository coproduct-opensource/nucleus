//! A9 of the command walk (`docs/design/command-walk.md`): lineage is append-only.
//!
//! `vchain(extend(c, e)) = Ok` whenever `vchain(c) = Ok`, and `vchain(c') = Refusal`
//! for every `c' != c` reachable by a tamper. Here `vchain` is [`verify_log`] over a
//! [`JsonlSink`] and the checkpoints [`read_checkpoints`] finds — the composition
//! `nucleus lineage-verify-chain` runs — and the log is produced by a real
//! [`MerkleSink`] cutting signed tree heads at an interval.
//!
//! # The laws
//!
//! - **Extension.** Appending edges and sealing keeps the log verifying, against the
//!   new checkpoints AND against the old ones alone: a signed prefix stays signed.
//! - **Every tamper is refused, for the reason that names it.** Against the log's
//!   bytes: a flipped byte in an edge, two edges swapped, an edge dropped, an edge
//!   duplicated into the signed prefix, an edge substituted, the log truncated.
//!   Against the checkpoints: a field edited without the key, a wrong root or size
//!   signed WITH the key (an equivocating witness), a checkpoint signed by another
//!   key — with its own kid, and wearing the real one.
//!
//! Before any refusal is asserted, the generated log verifies, carries at least two
//! checkpoints, and the tamper is checked to have changed the input. A duplicate
//! that leaves the original log as a prefix is an append, not a tamper, and is
//! asserted to verify.
//!
//! Positions are sampled, so a check that fails only for some bytes — a root
//! compared on its first byte — can slip past 48 generated logs. The deterministic
//! sweep flips every byte of one log, and that is the test that catches it.
//!
//! # What is derived and what is written down
//!
//! Chain length, checkpoint interval and every tamper position are generated. The
//! log's bytes are the sink's own. Which edge field a byte flip changed is derived
//! by an exhaustive destructure of [`LineageEdge`], so a field added to the edge
//! stops this file compiling until it is classified.
//!
//! What is written down is [`OUTSIDE_THE_LEAF`]: the edge fields a Merkle leaf does
//! not commit to, each cited. A flip there verifies, and that is the design — the
//! deterministic sweep asserts each entry is actually reached, so the list cannot
//! outlive the encoding.
//!
//! # What is NOT reached
//!
//! - The tail after the last checkpoint. No signed tree head covers it, so a tamper
//!   there verifies by construction; every generated log is sealed, so the whole log
//!   is covered and the extension law is the statement about the tail.
//! - Dropping a whole checkpoint: [`verify_log`] verifies the checkpoints it is given
//!   and cannot know one is missing. Freshness is the reader's problem.
//! - Edge signatures and the `prev_hash` chain: that is `verify_chain`, and A8 walks
//!   it through the envelope. The fixture's edges are unsigned.
//! - Consistency proofs between tree heads, and cosignatures.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::path::Path;

use nucleus_lineage::{
    CallSpiffeId, Ed25519Witness, EdgeKind, JsonlSink, LineageEdge, LineageSink, MerkleConfig,
    MerkleError, MerkleSink, SignedTreeHead, SinkError, TreeWitness, VerifierAttestation,
    WitnessError, canonical_sth_bytes, read_checkpoints, verify_log,
};
use proptest::prelude::*;
use proptest::sample::Index;
use proptest::test_runner::TestRunner;
use tempfile::TempDir;

const WITNESS_SEED: [u8; 32] = [9u8; 32];
const FOREIGN_SEED: [u8; 32] = [77u8; 32];

/// Edge fields a Merkle leaf (`edge_content_hash(edge, None)`) does not commit to.
const OUTSIDE_THE_LEAF: &[(Field, &str)] = &[
    (
        Field::KindPayload,
        "canonical_edge_bytes signs the kind tag only (proof.rs; pinned by \
         settlement_tx_ref_and_attrs_are_outside_the_signature)",
    ),
    (
        Field::Attrs,
        "free-form metadata, intentionally outside canonical_edge_bytes (proof.rs)",
    ),
];

/// A field of [`LineageEdge`], as the classification of a tamper sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Field {
    Child,
    Parents,
    KindTag,
    KindPayload,
    ContentHash,
    Ts,
    Attrs,
    Proof,
    VerifierAttestation,
}

fn kind_tag(kind: &EdgeKind) -> String {
    serde_json::to_value(kind).expect("kind serializes")["kind"].to_string()
}

/// Which fields differ. No `..`: a new field must be classified here (E-1).
fn changed_fields(a: &LineageEdge, b: &LineageEdge) -> Vec<Field> {
    let LineageEdge {
        child,
        parents,
        kind,
        content_hash_hex,
        ts,
        attrs,
        proof,
        verifier_attestation,
    } = a;
    let mut out = Vec::new();
    let mut note = |differs: bool, f: Field| {
        if differs {
            out.push(f);
        }
    };
    note(child != &b.child, Field::Child);
    note(parents != &b.parents, Field::Parents);
    note(kind_tag(kind) != kind_tag(&b.kind), Field::KindTag);
    note(
        kind != &b.kind && kind_tag(kind) == kind_tag(&b.kind),
        Field::KindPayload,
    );
    note(content_hash_hex != &b.content_hash_hex, Field::ContentHash);
    note(ts != &b.ts, Field::Ts);
    note(attrs != &b.attrs, Field::Attrs);
    note(proof != &b.proof, Field::Proof);
    note(
        verifier_attestation != &b.verifier_attestation,
        Field::VerifierAttestation,
    );
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// A real log

/// A sealed log: the sink that wrote it is kept, so it can be extended.
struct Log {
    _dir: TempDir,
    sink: MerkleSink<JsonlSink, Ed25519Witness>,
    log_path: std::path::PathBuf,
    checkpoint_dir: std::path::PathBuf,
    pod: CallSpiffeId,
    emitted: usize,
}

impl Log {
    fn new(interval: u64) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("lineage.jsonl");
        let checkpoint_dir = dir.path().join("checkpoints");
        let sink = MerkleSink::new(
            JsonlSink::open(&log_path).expect("jsonl sink"),
            Ed25519Witness::from_seed(WITNESS_SEED),
            MerkleConfig::new(&checkpoint_dir).with_interval(interval),
        )
        .expect("merkle sink");
        let pod = CallSpiffeId::pod("prod.example.com", "agents", "lineage-walk").expect("pod");
        Log {
            _dir: dir,
            sink,
            log_path,
            checkpoint_dir,
            pod,
            emitted: 0,
        }
    }

    /// The `i`-th edge a producer would emit: every shape the leaf encodes.
    fn edge(&self, i: usize, salt: &str) -> LineageEdge {
        let payload = format!("{salt}-{i}");
        if i == 0 {
            return LineageEdge::pod_admit(self.pod.clone());
        }
        let tool = self
            .pod
            .derive_tool("Read", Some(payload.as_bytes()))
            .expect("tool id");
        match i % 3 {
            0 => LineageEdge::from_parent(
                tool,
                self.pod.clone(),
                EdgeKind::ToolCall {
                    tool: "Read".into(),
                },
            )
            .with_attr("exit_code", "0"),
            1 => LineageEdge::from_parent(
                tool.derive_artifact(payload.as_bytes()).expect("artifact"),
                tool,
                EdgeKind::ArtifactProduced,
            )
            .with_content_hash(format!("{:064x}", i)),
            _ => LineageEdge::from_parent(
                tool.derive_artifact(payload.as_bytes()).expect("artifact"),
                self.pod.clone(),
                EdgeKind::Merge,
            )
            .with_verifier_attestation(
                VerifierAttestation::new().with_verifier_binary_hash(format!("{:064x}", i + 7)),
            ),
        }
    }

    /// Emit `n` more edges and seal them with a checkpoint.
    fn extend(&mut self, n: usize) {
        for _ in 0..n {
            let e = self.edge(self.emitted, "edge");
            self.sink.emit(e).expect("emit");
            self.emitted += 1;
        }
        self.sink.force_checkpoint().expect("seal");
    }

    fn lines(&self) -> Vec<String> {
        std::fs::read_to_string(&self.log_path)
            .expect("read log")
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn checkpoints(&self) -> Vec<SignedTreeHead> {
        read_checkpoints(&self.checkpoint_dir).expect("read checkpoints")
    }
}

/// `vchain`: the CLI's composition over the given bytes and checkpoints.
fn vchain(lines: &[String], checkpoints: &[SignedTreeHead]) -> Result<(), MerkleError> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("lineage.jsonl");
    let mut body = lines.join("\n");
    if !lines.is_empty() {
        body.push('\n');
    }
    std::fs::write(&path, body).expect("write log");
    let sink = JsonlSink::open(Path::new(&path)).expect("open log");
    let auditor =
        Ed25519Witness::verify_only(Ed25519Witness::from_seed(WITNESS_SEED).verifying_key_bytes())
            .expect("verify-only witness");
    verify_log(&sink, checkpoints, &auditor)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tampers

/// The refusal a tamper must produce, as a class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    Unparseable,
    RootMismatch,
    AheadOfLog,
    BadSignature,
    KidMismatch,
}

fn refusal(result: &Result<(), MerkleError>) -> Option<Refusal> {
    match result {
        Ok(()) => None,
        Err(MerkleError::Sink(SinkError::Json(_))) => Some(Refusal::Unparseable),
        Err(MerkleError::RootMismatch { .. }) => Some(Refusal::RootMismatch),
        Err(MerkleError::CheckpointAheadOfLog { .. }) => Some(Refusal::AheadOfLog),
        Err(MerkleError::Witness(WitnessError::InvalidSignature(_))) => Some(Refusal::BadSignature),
        Err(MerkleError::Witness(WitnessError::KidMismatch { .. })) => Some(Refusal::KidMismatch),
        Err(other) => panic!("a refusal the walk does not classify: {other}"),
    }
}

/// Refused, for one of `expected`, over input that really changed.
fn assert_refused(
    what: &str,
    (lines, cps): (&[String], &[SignedTreeHead]),
    (orig_lines, orig_cps): (&[String], &[SignedTreeHead]),
    expected: &[Refusal],
) {
    assert!(
        lines != orig_lines || cps != orig_cps,
        "{what}: the tamper did not change the input — the refusal would be vacuous"
    );
    let result = vchain(lines, cps);
    match refusal(&result) {
        Some(r) if expected.contains(&r) => {}
        got => panic!("{what}: expected a refusal in {expected:?}, got {got:?} ({result:?})"),
    }
}

/// One character from the same alphabet, so a hex string stays hex.
fn same_alphabet(b: u8) -> Option<u8> {
    Some(match b {
        b'0'..=b'8' | b'a'..=b'e' => b + 1,
        b'9' => b'0',
        b'f' => b'a',
        b'g'..=b'y' | b'A'..=b'Y' => b + 1,
        b'z' => b'g',
        b'Z' => b'A',
        _ => return None,
    })
}

/// A tree head over `(tree_size, root)` at `sth`'s timestamp, signed by `key`.
fn resign(
    sth: &SignedTreeHead,
    key: &Ed25519Witness,
    tree_size: u64,
    root_hex: &str,
) -> SignedTreeHead {
    let root: [u8; 32] = hex::decode(root_hex)
        .expect("hex root")
        .try_into()
        .expect("32 bytes");
    let canonical = canonical_sth_bytes(tree_size, sth.timestamp_ms, &root);
    SignedTreeHead {
        tree_size,
        timestamp_ms: sth.timestamp_ms,
        root_hash_hex: root_hex.to_string(),
        witness_kid: key.kid().to_string(),
        witness_sig: key.sign_message(&canonical).to_vec(),
        cosignatures: Vec::new(),
    }
}

/// Positions for every tamper kind, drawn once per generated log.
#[derive(Debug, Clone)]
struct Positions {
    flip_line: Index,
    flip_byte: Index,
    a: Index,
    b: Index,
    at: Index,
    truncate: Index,
    cp: Index,
    other_cp: Index,
}

fn positions() -> impl Strategy<Value = Positions> {
    (
        any::<Index>(),
        any::<Index>(),
        any::<Index>(),
        any::<Index>(),
        any::<Index>(),
        any::<Index>(),
        any::<Index>(),
        any::<Index>(),
    )
        .prop_map(
            |(flip_line, flip_byte, a, b, at, truncate, cp, other_cp)| Positions {
                flip_line,
                flip_byte,
                a,
                b,
                at,
                truncate,
                cp,
                other_cp,
            },
        )
}

/// Every tamper kind against one sealed log. Returns how many of each ran.
fn tamper_all(log: &Log, p: &Positions, counts: &mut BTreeMap<&'static str, usize>) {
    let lines = log.lines();
    let cps = log.checkpoints();
    let n = lines.len();
    let orig = (lines.as_slice(), cps.as_slice());
    let mut tick = |k: &'static str| *counts.entry(k).or_default() += 1;

    // Byte flip in an edge: refused, or it landed only outside the leaf.
    {
        let li = p.flip_line.index(n);
        let mut t = lines.clone();
        let mut bytes = t[li].clone().into_bytes();
        let bi = p.flip_byte.index(bytes.len());
        bytes[bi] ^= 0x01;
        if let Ok(s) = String::from_utf8(bytes) {
            t[li] = s;
            let outcome = vchain(&t, &cps);
            match refusal(&outcome) {
                Some(Refusal::Unparseable | Refusal::RootMismatch) => {}
                Some(other) => panic!("flip {li}:{bi}: unexpected refusal {other:?}"),
                None => {
                    assert_outside_leaf(&lines[li], &t[li], &format!("flip {li}:{bi}"));
                }
            }
            tick("edge: byte flip");
        }
    }

    // Swap two distinct edges.
    let (a, b) = (p.a.index(n), p.b.index(n));
    if a != b {
        let mut t = lines.clone();
        t.swap(a, b);
        assert_refused("swap", (&t, &cps), orig, &[Refusal::RootMismatch]);
        tick("edge: swap two");
    }

    // Drop one edge.
    let mut t = lines.clone();
    t.remove(a);
    assert_refused("drop", (&t, &cps), orig, &[Refusal::AheadOfLog]);
    tick("edge: drop one");

    // Duplicate an edge. Inserting the last edge beside itself leaves the original
    // log as a prefix — that is an append, and the extension law says it verifies.
    // Anything else rewrites the signed prefix.
    let at = p.at.index(n);
    let mut t = lines.clone();
    t.insert(at, lines[a].clone());
    if t.starts_with(&lines) {
        vchain(&t, &cps).expect("a duplicate appended after the prefix is an extension");
        tick("edge: duplicate appended (extension, verifies)");
    } else {
        assert_refused("duplicate", (&t, &cps), orig, &[Refusal::RootMismatch]);
        tick("edge: duplicate into prefix");
    }

    // Substitute a different, well-formed edge.
    let mut t = lines.clone();
    t[a] = serde_json::to_string(&log.edge(a.max(1), "substitute")).expect("serialize");
    assert_refused("substitute", (&t, &cps), orig, &[Refusal::RootMismatch]);
    tick("edge: substitute");

    // Truncate.
    let keep = p.truncate.index(n);
    assert_refused(
        "truncate",
        (&lines[..keep], &cps),
        orig,
        &[Refusal::AheadOfLog],
    );
    tick("log: truncate");

    let c = p.cp.index(cps.len());
    let witness = Ed25519Witness::from_seed(WITNESS_SEED);

    // Edit a checkpoint field without the key.
    let edits: [(&str, fn(&mut SignedTreeHead)); 4] = [
        ("timestamp", |s| s.timestamp_ms += 1),
        ("root", |s| {
            let mut r = s.root_hash_hex.clone().into_bytes();
            r[0] = same_alphabet(r[0]).expect("hex digit");
            s.root_hash_hex = String::from_utf8(r).expect("ascii");
        }),
        ("size", |s| s.tree_size += 1),
        ("signature", |s| s.witness_sig[0] ^= 0x01),
    ];
    for (field, edit) in edits {
        let mut t = cps.clone();
        edit(&mut t[c]);
        assert_refused(
            &format!("checkpoint {field} edited"),
            (&lines, &t),
            orig,
            &[Refusal::BadSignature, Refusal::AheadOfLog],
        );
        tick("checkpoint: field edited without key");
    }

    // An equivocating witness: a wrong root, or a wrong size, signed with the key.
    let other = p.other_cp.index(cps.len());
    if cps[other].root_hash_hex != cps[c].root_hash_hex {
        let mut t = cps.clone();
        t[c] = resign(
            &cps[c],
            &witness,
            cps[c].tree_size,
            &cps[other].root_hash_hex,
        );
        assert_refused(
            "wrong root signed",
            (&lines, &t),
            orig,
            &[Refusal::RootMismatch],
        );
        tick("checkpoint: wrong root, signed");
    }
    for size in [cps[c].tree_size - 1, n as u64 + 1] {
        if size == 0 {
            continue;
        }
        let mut t = cps.clone();
        t[c] = resign(&cps[c], &witness, size, &cps[c].root_hash_hex);
        assert_refused(
            "wrong size signed",
            (&lines, &t),
            orig,
            &[Refusal::RootMismatch, Refusal::AheadOfLog],
        );
        tick("checkpoint: wrong size, signed");
    }

    // Another key: under its own kid, and wearing the real one.
    let foreign = Ed25519Witness::from_seed(FOREIGN_SEED);
    let mut t = cps.clone();
    t[c] = resign(&cps[c], &foreign, cps[c].tree_size, &cps[c].root_hash_hex);
    assert_refused("foreign key", (&lines, &t), orig, &[Refusal::KidMismatch]);
    tick("checkpoint: other key");
    t[c].witness_kid = witness.kid().to_string();
    assert_refused(
        "foreign key, real kid",
        (&lines, &t),
        orig,
        &[Refusal::BadSignature],
    );
    tick("checkpoint: other key, real kid");
}

/// A flip that verified must have changed only fields outside the leaf.
fn assert_outside_leaf(original: &str, tampered: &str, what: &str) -> Vec<Field> {
    let a: LineageEdge = serde_json::from_str(original).expect("original parses");
    let b: LineageEdge = serde_json::from_str(tampered).expect("an accepted tamper parsed");
    let changed = changed_fields(&a, &b);
    let inside: Vec<&Field> = changed
        .iter()
        .filter(|f| !OUTSIDE_THE_LEAF.iter().any(|(o, _)| o == *f))
        .collect();
    assert!(
        inside.is_empty(),
        "A9 violated — {what} changed {inside:?}, which the leaf commits to, and verified:\n\
         {original}\n{tampered}"
    );
    changed
}

// ─────────────────────────────────────────────────────────────────────────────
// The walks

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    #[test]
    fn a9_extension_keeps_the_log_verifying(
        interval in 1u64..=4,
        periods in 2usize..=4,
        remainder in 0usize..4,
        more in 1usize..=6,
    ) {
        let mut log = Log::new(interval);
        log.extend(usize::try_from(interval).expect("a small interval") * periods + remainder);
        let (lines, cps) = (log.lines(), log.checkpoints());
        prop_assert!(cps.len() >= 2, "non-vacuity: {} checkpoint(s)", cps.len());
        vchain(&lines, &cps).expect("the generated log must verify");

        log.extend(more);
        let (grown, grown_cps) = (log.lines(), log.checkpoints());
        prop_assert!(grown.len() > lines.len() && grown_cps.len() > cps.len());
        prop_assert_eq!(&grown[..lines.len()], &lines[..], "extension rewrote the prefix");
        vchain(&grown, &grown_cps).expect("an extended log verifies against every checkpoint");
        vchain(&grown, &cps).expect("an extended log verifies against the old checkpoints alone");
    }
}

/// Generated logs, every tamper kind against each. Driven through a [`TestRunner`]
/// rather than `proptest!` so the counts are reported once, for the whole run.
#[test]
fn a9_every_tamper_is_refused() {
    let mut runner = TestRunner::new(ProptestConfig {
        cases: 48,
        // An integration test has no source file for proptest to key a persistence
        // file on; the failing input is printed in the panic instead.
        failure_persistence: None,
        ..ProptestConfig::default()
    });
    let counts = RefCell::new(BTreeMap::new());
    let logs = Cell::new(0usize);
    let strategy = (1u64..=4, 2usize..=4, 0usize..4, positions());
    runner
        .run(&strategy, |(interval, periods, remainder, p)| {
            let mut log = Log::new(interval);
            log.extend(usize::try_from(interval).expect("a small interval") * periods + remainder);
            let cps = log.checkpoints();
            prop_assert!(cps.len() >= 2, "non-vacuity: {} checkpoint(s)", cps.len());
            vchain(&log.lines(), &cps).expect("the untampered log must verify");
            tamper_all(&log, &p, &mut counts.borrow_mut());
            logs.set(logs.get() + 1);
            Ok(())
        })
        .expect("A9: every tamper of a valid log is refused");
    let counts = counts.into_inner();
    eprintln!("A9 tampers over {} generated logs: {counts:#?}", logs.get());
    assert!(counts.len() >= 11, "tamper kinds exercised: {counts:?}");
}

/// Every byte of every edge in one sealed log, flipped and substituted: each is
/// refused, or verifies having changed only [`OUTSIDE_THE_LEAF`] — and each entry
/// there is reached.
#[test]
fn a9_every_byte_of_the_log_is_covered() {
    let mut log = Log::new(2);
    log.extend(7);
    let (lines, cps) = (log.lines(), log.checkpoints());
    assert!(cps.len() >= 2, "non-vacuity: {} checkpoint(s)", cps.len());
    vchain(&lines, &cps).expect("the untampered log must verify");

    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    let mut reached: BTreeMap<Field, usize> = BTreeMap::new();
    for (li, line) in lines.iter().enumerate() {
        for bi in 0..line.len() {
            let original = line.as_bytes()[bi];
            for (pass, sub) in [
                ("xor", Some(original ^ 0x01)),
                ("alphabet", same_alphabet(original)),
            ] {
                let Some(sub) = sub else { continue };
                let mut bytes = line.clone().into_bytes();
                bytes[bi] = sub;
                let Ok(tampered) = String::from_utf8(bytes) else {
                    continue;
                };
                let mut t = lines.clone();
                t[li] = tampered;
                let outcome = vchain(&t, &cps);
                let class = match refusal(&outcome) {
                    Some(Refusal::Unparseable) => "refused: unparseable".to_string(),
                    Some(Refusal::RootMismatch) => "refused: root mismatch".to_string(),
                    Some(other) => panic!("{pass} {li}:{bi}: unexpected refusal {other:?}"),
                    None => {
                        let changed =
                            assert_outside_leaf(line, &t[li], &format!("{pass} {li}:{bi}"));
                        if changed.is_empty() {
                            "verified: same edge".to_string()
                        } else {
                            for f in changed {
                                *reached.entry(f).or_default() += 1;
                            }
                            "verified: outside the leaf".to_string()
                        }
                    }
                };
                *tally.entry(format!("{pass}: {class}")).or_default() += 1;
            }
        }
    }
    eprintln!(
        "A9 byte sweep over {} edges: {tally:#?}\nreached outside the leaf: {reached:?}",
        lines.len()
    );
    assert!(
        tally.keys().any(|k| k.ends_with("root mismatch")),
        "no flip reached the Merkle check — the sweep only tested the parser"
    );
    for (field, why) in OUTSIDE_THE_LEAF {
        assert!(
            reached.contains_key(field),
            "{field:?} is declared outside the leaf ({why}) but no flip there verified — \
             covered now? remove the entry"
        );
    }
}

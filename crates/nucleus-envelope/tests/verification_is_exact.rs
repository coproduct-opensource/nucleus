//! A8 of the command walk (`docs/design/command-walk.md`): verification is exact.
//!
//! `verify(sign(m, k), k) = Ok`, and `verify(tamper(sign(m, k), i), k) = Refusal`
//! for every byte index `i`. Two signed artifacts are walked, through one harness:
//!
//! - a [`Bundle`] built the strongest way a producer can build one — signed edges,
//!   a Merkle anchor with a witness-signed tree head, one external cosignature, a
//!   payload binding, contemporaneous checkpoints — and verified by [`verify_bundle`]
//!   against an out-of-band [`TrustAnchor`] that requires all of it;
//! - a [`Receipt`], verified by [`Receipt::verify_strict`].
//!
//! Both are small enough to walk **exhaustively**: every byte is tampered, twice.
//!
//! # A tamper that dies at the parser proves nothing about the signature
//!
//! Flipping a bit in JSON mostly produces JSON that does not parse, and a walk
//! whose every tamper dies there says nothing about verification. So every
//! outcome is classified, and the classes are counted separately:
//!
//! - **syntax** — no longer JSON;
//! - **schema** — JSON, but not the artifact's type;
//! - **same artifact** — parses to the identical artifact (an unknown key serde
//!   drops, a reordered object). There is nothing different to verify;
//! - **refused** — parsed to a different artifact and verification said no. This
//!   is the class the law is about, and the walk asserts it is reached;
//! - **accepted** — parsed to a different artifact and verification said yes.
//!
//! The second byte pass substitutes a character from the same alphabet (a hex
//! digit for a hex digit, a base64 character for a base64 character), which keeps
//! a string a string and a number a number, so most of those tampers reach
//! verification. Then the semantic tampers, which always parse: one character of
//! every string leaf, every number, every boolean; every array reordered; an
//! unknown key in every object; every object's keys reversed.
//!
//! # What is derived and what is written down
//!
//! The tampers are DERIVED: the bytes and the JSON tree of the real artifact are
//! walked, so a field added to either artifact enters the walk the moment it
//! serializes. Where an accepted tamper landed is DERIVED too — the tampered
//! artifact is parsed, re-serialized and diffed against the original, so the
//! region is named by the type, not guessed from a byte offset.
//!
//! What is written down is [`UNCOVERED`]: the regions verification does not
//! cover, each with the reason, each marked [`Why::ByDesign`] or [`Why::Finding`].
//! A by-design entry cites the code or doc that says so. A finding is a region
//! nothing says should be unauthenticated; its `#[ignore]`d test asserts the law
//! over it and is red today. Both are stale-checked: an entry no accepted tamper
//! reaches fails the walk, so a fix cannot leave its allowlist line behind.
//!
//! # Found along the way, and not asserted
//!
//! Reversing the keys of every object is the same artifact, and the receipt verifies
//! it in every build. The bundle does not in all of them: the payload binding hashes
//! `serde_json::to_vec(&payload)`, whose key order follows `serde_json/preserve_order`.
//! Under `--all-features` that feature is unified on and a reordered payload is
//! refused (`BadPayloadBinding`); in a package-only build it verifies. That is a
//! false refusal, not a false acceptance, so the walk records either outcome — but
//! it is the signer/verifier split `nucleus-receipt` moved to RFC 8785 to escape.
//!
//! # What is NOT reached
//!
//! - `Bundle::attestation` (the OP attestation): `verify_bundle` does not read it,
//!   and building one needs an OIDC OP. It is absent from the fixture.
//! - C2SP-kind cosignatures and self-check trust mode — a different signed-bytes
//!   path and a mode that is documented to prove less.
//! - The per-projection lifter verifiers a receipt's bodies may additionally have.
//! - Anything off the wire: key compromise, a JWKS obtained insecurely.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

use ed25519_dalek::SigningKey;
use nucleus_envelope::{Bundle, BundleBuilder, TrustAnchor, verify_bundle};
use nucleus_lineage::{
    CallSpiffeId, Ed25519Witness, EdgeKind, EdgeSigner, InMemorySink, InProcessWitness, Jwks,
    LineageEdge, LineageSink, LocalIssuer, MerkleConfig, MerkleSink, Proof, VerifierAttestation,
    WitnessClient, canonical_edge_bytes, edge_content_hash, read_checkpoints,
};
use nucleus_receipt::{Projection, Receipt, Session};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

// ─────────────────────────────────────────────────────────────────────────────
// What verification does not cover

/// Why a region is outside verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Why {
    /// The code or its documentation says so, deliberately.
    ByDesign(&'static str),
    /// Nothing says so. The `#[ignore]`d `finding_*` test is red over it.
    Finding(&'static str),
}

/// A region of an artifact, as a JSON-pointer prefix with `*` for any array index.
struct Uncovered {
    artifact: &'static str,
    prefix: &'static str,
    why: Why,
}

const UNCOVERED: &[Uncovered] = &[
    Uncovered {
        artifact: "bundle",
        prefix: "/envelope/jwks",
        why: Why::ByDesign(
            "the embedded JWKS is producer-controlled; out-of-band trust mode verifies \
             against the anchor's JWKS and ignores this one (verify.rs, trust model)",
        ),
    },
    Uncovered {
        artifact: "bundle",
        prefix: "/envelope/edges/*/tool",
        why: Why::ByDesign(
            "canonical_edge_bytes signs the kind tag, not the kind's payload \
             (proof.rs; pinned by settlement_tx_ref_and_attrs_are_outside_the_signature)",
        ),
    },
    Uncovered {
        artifact: "bundle",
        prefix: "/envelope/edges/*/attrs",
        why: Why::ByDesign(
            "attrs is free-form metadata, intentionally outside canonical_edge_bytes (proof.rs)",
        ),
    },
    Uncovered {
        artifact: "bundle",
        prefix: "/envelope/edges/*/proof/prev_hash",
        why: Why::ByDesign(
            "a redundant claim: verify_proof signs over the prev hash it recomputes, and \
             checks this field only when present, so dropping it leaves the signed bytes \
             unchanged (a changed value is refused)",
        ),
    },
    Uncovered {
        artifact: "bundle",
        prefix: "/envelope/merkle_anchor/sth/cosignatures/*/timestamp_ms",
        why: Why::ByDesign("\"Metadata only — NOT covered by `signature`\" (cosign.rs)"),
    },
    Uncovered {
        artifact: "bundle",
        prefix: "/envelope/merkle_anchor/sth/cosignatures/*/witness_kid",
        why: Why::ByDesign(
            "a label the verifier never reads: a cosignature counts by verifying against \
             each trusted witness key in turn (verify_merkle_anchor)",
        ),
    },
    Uncovered {
        artifact: "bundle",
        prefix: "/envelope/checkpoints",
        why: Why::Finding(
            "verify_bundle never verifies a checkpoint's signature or root; it only counts \
             them into VerificationReport::checkpoint_count, while the crate doc lists signed \
             tree heads as a composition layer",
        ),
    },
    Uncovered {
        artifact: "bundle",
        prefix: "/envelope/meta",
        why: Why::Finding(
            "created_at is unauthenticated, and schema_version is compared only with `>`, so \
             a downgrade verifies",
        ),
    },
    Uncovered {
        artifact: "receipt",
        prefix: "/version",
        why: Why::Finding(
            "canonical_signing_bytes signs the RECEIPT_VERSION constant and verify_strict \
             never compares the wire field with it, so any version verifies",
        ),
    },
];

fn uncovered(artifact: &str, path: &str) -> Option<&'static Uncovered> {
    UNCOVERED.iter().find(|u| {
        u.artifact == artifact
            && (path == u.prefix
                || path
                    .strip_prefix(u.prefix)
                    .is_some_and(|rest| rest.starts_with('/')))
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// The harness

/// What one tamper did.
#[derive(Debug)]
enum Outcome {
    Syntax,
    Schema,
    SameArtifact,
    Refused(String),
    /// Verified, over a different artifact. The paths are where it differs.
    Accepted(BTreeSet<String>),
}

/// One artifact under the law: its canonical wire bytes and its verifier.
struct Subject<'a, T> {
    name: &'static str,
    wire: Vec<u8>,
    verify: &'a dyn Fn(&T) -> Result<(), String>,
}

impl<T: Serialize + DeserializeOwned> Subject<'_, T> {
    fn original(&self) -> Value {
        let parsed: T = serde_json::from_slice(&self.wire).expect("the wire bytes parse");
        serde_json::to_value(&parsed).expect("the artifact serializes")
    }

    fn run(&self, tampered: &[u8]) -> Outcome {
        let Ok(value) = serde_json::from_slice::<Value>(tampered) else {
            return Outcome::Syntax;
        };
        let Ok(parsed) = serde_json::from_value::<T>(value) else {
            return Outcome::Schema;
        };
        // Diff the artifact as the type sees it, so a key serde drops is not a change
        // and a dropped optional field is named by its real path.
        let seen = serde_json::to_value(&parsed).expect("a parsed artifact serializes");
        let mut changed = BTreeSet::new();
        diff(&self.original(), &seen, String::new(), &mut changed);
        match (self.verify)(&parsed) {
            Err(reason) => Outcome::Refused(reason),
            Ok(()) if changed.is_empty() => Outcome::SameArtifact,
            Ok(()) => Outcome::Accepted(changed),
        }
    }
}

/// Paths at which `a` and `b` differ, array indices written `*`.
fn diff(a: &Value, b: &Value, path: String, out: &mut BTreeSet<String>) {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let keys: BTreeSet<&String> = x.keys().chain(y.keys()).collect();
            for k in keys {
                match (x.get(k), y.get(k)) {
                    (Some(p), Some(q)) => diff(p, q, format!("{path}/{k}"), out),
                    _ => {
                        out.insert(format!("{path}/{k}"));
                    }
                }
            }
        }
        (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
            for (p, q) in x.iter().zip(y) {
                diff(p, q, format!("{path}/*"), out);
            }
        }
        _ if a != b => {
            out.insert(path);
        }
        _ => {}
    }
}

/// The counts one pass produced, and every accepted path.
#[derive(Default)]
struct Tally {
    tampers: usize,
    syntax: usize,
    schema: usize,
    same: usize,
    refused: BTreeMap<String, usize>,
    accepted: BTreeMap<String, usize>,
}

impl Tally {
    fn record(&mut self, outcome: Outcome) {
        self.tampers += 1;
        match outcome {
            Outcome::Syntax => self.syntax += 1,
            Outcome::Schema => self.schema += 1,
            Outcome::SameArtifact => self.same += 1,
            Outcome::Refused(reason) => *self.refused.entry(reason).or_default() += 1,
            Outcome::Accepted(paths) => {
                for p in paths {
                    *self.accepted.entry(p).or_default() += 1;
                }
            }
        }
    }

    fn refused(&self) -> usize {
        self.refused.values().sum()
    }

    fn line(&self, subject: &str, pass: &str) -> String {
        format!(
            "{subject:<8} {pass:<22} tampers={:<5} syntax={:<5} schema={:<5} same={:<4} \
             refused={:<5} accepted-paths={} reasons={:?}",
            self.tampers,
            self.syntax,
            self.schema,
            self.same,
            self.refused(),
            self.accepted.len(),
            self.refused
        )
    }
}

/// A character from the same alphabet, never the same character: keeps a hex
/// digit hex, a base64 character base64, a digit a digit.
fn same_alphabet(b: u8) -> Option<u8> {
    Some(match b {
        b'0'..=b'8' => b + 1,
        b'9' => b'0',
        b'a'..=b'e' => b + 1,
        b'f' => b'a',
        b'g'..=b'y' => b + 1,
        b'z' => b'g',
        b'A'..=b'Y' => b + 1,
        b'Z' => b'A',
        b'+' => b'/',
        b'/' => b'+',
        _ => return None,
    })
}

fn string_edits(s: &str) -> Vec<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    for i in [0, bytes.len().saturating_sub(1)] {
        if let Some(&b) = bytes.get(i)
            && let Some(sub) = same_alphabet(b)
        {
            let mut edited = bytes.to_vec();
            edited[i] = sub;
            if let Ok(e) = String::from_utf8(edited) {
                out.push(e);
            }
        }
    }
    if out.is_empty() {
        out.push(format!("{s}x"));
    }
    out
}

/// Every semantic tamper of `root`, each still valid JSON.
fn semantic_tampers(root: &Value) -> Vec<(&'static str, Value)> {
    fn go(node: &Value, rebuild: &dyn Fn(Value) -> Value, out: &mut Vec<(&'static str, Value)>) {
        match node {
            Value::String(s) => {
                for e in string_edits(s) {
                    out.push(("leaf: string char", rebuild(Value::String(e))));
                }
            }
            Value::Number(n) => {
                let bumped = match (n.as_u64(), n.as_i64(), n.as_f64()) {
                    (Some(u), _, _) => Value::from(u.wrapping_add(1)),
                    (_, Some(i), _) => Value::from(i.wrapping_add(1)),
                    (_, _, Some(f)) => Value::from(f + 1.0),
                    _ => return,
                };
                out.push(("leaf: number", rebuild(bumped)));
            }
            Value::Bool(b) => out.push(("leaf: bool", rebuild(Value::Bool(!b)))),
            Value::Null => {}
            Value::Array(items) => {
                if items.len() >= 2 && items[0] != items[1] {
                    let mut swapped = items.clone();
                    swapped.swap(0, 1);
                    out.push(("array: reorder", rebuild(Value::Array(swapped))));
                }
                for (i, item) in items.iter().enumerate() {
                    let inner = |v: Value| {
                        let mut copy = items.clone();
                        copy[i] = v;
                        rebuild(Value::Array(copy))
                    };
                    go(item, &inner, out);
                }
            }
            Value::Object(map) => {
                let mut extra = map.clone();
                extra.insert("walk_unknown_field".into(), Value::from(0));
                out.push(("object: unknown field", rebuild(Value::Object(extra))));
                for (k, v) in map {
                    let inner = |replacement: Value| {
                        let mut copy = map.clone();
                        copy.insert(k.clone(), replacement);
                        rebuild(Value::Object(copy))
                    };
                    go(v, &inner, out);
                }
            }
        }
    }
    let mut out = Vec::new();
    go(root, &|v| v, &mut out);
    out
}

/// JSON with every object's keys in reverse order — the same artifact, other bytes.
fn reversed_keys(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let fields: Vec<String> = map
                .iter()
                .rev()
                .map(|(k, v)| format!("{}:{}", Value::String(k.clone()), reversed_keys(v)))
                .collect();
            format!("{{{}}}", fields.join(","))
        }
        Value::Array(items) => {
            let items: Vec<String> = items.iter().map(reversed_keys).collect();
            format!("[{}]", items.join(","))
        }
        leaf => leaf.to_string(),
    }
}

/// Walk `subject` and return every pass's tally. Asserts the control first.
fn walk<T: Serialize + DeserializeOwned>(subject: &Subject<'_, T>) -> Vec<(&'static str, Tally)> {
    // Non-vacuity: the untampered artifact verifies, before any tamper is judged.
    let parsed: T = serde_json::from_slice(&subject.wire).expect("the control parses");
    if let Err(reason) = (subject.verify)(&parsed) {
        panic!(
            "{}: the untampered artifact must verify, got {reason}",
            subject.name
        );
    }
    assert!(
        matches!(subject.run(&subject.wire), Outcome::SameArtifact),
        "{}: the control must classify as the same artifact",
        subject.name
    );

    let mut passes = Vec::new();

    let mut flip = Tally::default();
    for i in 0..subject.wire.len() {
        let mut t = subject.wire.clone();
        t[i] ^= 0x01;
        flip.record(subject.run(&t));
    }
    passes.push(("byte: xor 0x01", flip));

    let mut alpha = Tally::default();
    for i in 0..subject.wire.len() {
        if let Some(sub) = same_alphabet(subject.wire[i]) {
            let mut t = subject.wire.clone();
            t[i] = sub;
            alpha.record(subject.run(&t));
        }
    }
    passes.push(("byte: same alphabet", alpha));

    let original: Value = serde_json::from_slice(&subject.wire).expect("the control is JSON");
    let mut by_kind: BTreeMap<&'static str, Tally> = BTreeMap::new();
    for (kind, tampered) in semantic_tampers(&original) {
        assert_ne!(tampered, original, "a semantic tamper must change the JSON");
        let bytes = serde_json::to_vec(&tampered).expect("a tamper serializes");
        by_kind.entry(kind).or_default().record(subject.run(&bytes));
    }
    let reordered = reversed_keys(&original).into_bytes();
    assert_ne!(
        reordered, subject.wire,
        "reversing keys must change the bytes"
    );
    by_kind
        .entry("object: keys reversed")
        .or_default()
        .record(subject.run(&reordered));
    passes.extend(by_kind);
    passes
}

/// The law, over every pass: nothing is accepted outside [`UNCOVERED`], every
/// entry for this artifact is reached, and verification itself refused tampers.
fn assert_exact(name: &str, passes: &[(&'static str, Tally)]) {
    let mut reached: BTreeSet<&'static str> = BTreeSet::new();
    let mut violations = Vec::new();
    for (pass, tally) in passes {
        eprintln!("{}", tally.line(name, pass));
        for (path, n) in &tally.accepted {
            match uncovered(name, path) {
                Some(u) => {
                    reached.insert(u.prefix);
                }
                None => violations.push(format!("{pass}: {n} tamper(s) at {path} VERIFIED")),
            }
        }
    }
    assert!(
        violations.is_empty(),
        "A8 violated for {name} — a tamper outside every declared region verified:\n{}",
        violations.join("\n")
    );

    let stale: Vec<&str> = UNCOVERED
        .iter()
        .filter(|u| u.artifact == name && !reached.contains(u.prefix))
        .map(|u| u.prefix)
        .collect();
    assert!(
        stale.is_empty(),
        "{name}: declared uncovered but no tamper verified there — covered now? remove the \
         entry (and un-ignore its finding test): {stale:?}"
    );

    let refused: usize = passes.iter().map(|(_, t)| t.refused()).sum();
    let alpha_refused = passes
        .iter()
        .find(|(p, _)| *p == "byte: same alphabet")
        .map(|(_, t)| t.refused())
        .unwrap_or(0);
    assert!(
        refused > 0 && alpha_refused > 0,
        "{name}: no tamper reached a verification refusal — the walk only tested the parser"
    );
}

/// Every tamper that verified inside a [`Why::Finding`] region.
fn findings(name: &str, passes: &[(&'static str, Tally)]) -> Vec<String> {
    passes
        .iter()
        .flat_map(|(pass, t)| t.accepted.iter().map(move |(p, n)| (pass, p, n)))
        .filter_map(
            |(pass, path, n)| match uncovered(name, path).map(|u| u.why) {
                Some(Why::Finding(why)) => Some(format!("{pass}: {n} at {path} VERIFIED — {why}")),
                _ => None,
            },
        )
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// The artifacts

fn signed(issuer: &LocalIssuer, mut edge: LineageEdge, prev: Option<&[u8; 32]>) -> LineageEdge {
    let sig = issuer
        .sign(&canonical_edge_bytes(&edge, prev))
        .expect("the issuer signs");
    let mut proof = Proof::new(issuer.kid(), issuer.alg(), sig);
    if let Some(h) = prev {
        proof = proof.with_prev_hash(*h);
    }
    edge.proof = Some(proof);
    edge
}

/// A bundle carrying every verifiable layer, and a trust anchor requiring each.
fn bundle_subject() -> (Vec<u8>, TrustAnchor) {
    let dir = tempfile::tempdir().expect("tempdir");
    let witness = Ed25519Witness::from_seed([7u8; 32]);
    let witness_pub = witness.verifying_key_bytes();
    // Interval 2 over three edges: one contemporaneous checkpoint, at size 2.
    let sink = MerkleSink::new(
        InMemorySink::new(),
        witness,
        MerkleConfig::new(dir.path()).with_interval(2),
    )
    .expect("merkle sink");
    let issuer = LocalIssuer::from_signing_key(
        SigningKey::from_bytes(&[3u8; 32]),
        "nucleus-local://walk".into(),
        std::time::Duration::from_secs(300),
    )
    .expect("issuer");
    let pod = CallSpiffeId::pod("prod.example.com", "agents", "walker").expect("pod id");

    let e1 = signed(&issuer, LineageEdge::pod_admit(pod.clone()), None);
    let h1 = edge_content_hash(&e1, None);
    sink.emit(e1).expect("emit");
    let tool = pod.derive_tool("Read", Some(b"input")).expect("tool id");
    let e2 = LineageEdge::from_parent(
        tool.clone(),
        pod.clone(),
        EdgeKind::ToolCall {
            tool: "Read".into(),
        },
    )
    .with_attr("exit_code", "0");
    let e2 = signed(&issuer, e2, Some(&h1));
    let h2 = edge_content_hash(&e2, Some(&h1));
    sink.emit(e2).expect("emit");
    let leaf = tool.derive_artifact(b"out").expect("artifact id");
    let e3 = LineageEdge::from_parent(leaf, tool, EdgeKind::ArtifactProduced)
        .with_content_hash("ab".repeat(32))
        .with_verifier_attestation(
            VerifierAttestation::new()
                .with_verifier_binary_hash("cd".repeat(32))
                .with_wasmtime_version("1.2.3"),
        );
    let e3 = signed(&issuer, e3, Some(&h2));
    sink.emit(e3).expect("emit");

    let checkpoints = read_checkpoints(dir.path()).expect("checkpoints");
    assert_eq!(checkpoints.len(), 1, "the fixture carries a checkpoint");
    let cosigner = InProcessWitness::from_seed([11u8; 32]);
    let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).expect("jwks");
    let cosigners: Vec<&dyn WitnessClient> = vec![&cosigner];
    let bundle = BundleBuilder::new(pod)
        .payload(
            serde_json::json!({"summary": "walked", "count": 3, "ok": true, "tags": ["a", "b"]}),
        )
        .sink(&sink)
        .jwks(jwks.clone())
        .checkpoints(checkpoints)
        .require_signed()
        .with_merkle_prover(&sink)
        .with_cosignatures(cosigners)
        .with_binding_signer(&issuer)
        .build()
        .expect("the bundle builds");
    let trust = TrustAnchor::from_jwks(jwks)
        .with_witness_pubkey(witness_pub)
        .with_trusted_witness(cosigner.verifying_key_bytes())
        .cosignature_threshold(1)
        .require_payload_binding();
    (serde_json::to_vec(&bundle).expect("serializes"), trust)
}

fn bundle_passes() -> Vec<(&'static str, Tally)> {
    let (wire, trust) = bundle_subject();
    let verify = |b: &Bundle| match verify_bundle(b, &trust) {
        Ok(report) => {
            // A bundle that verifies without exercising the layers proves less than it
            // looks like; the control would be vacuous for them.
            assert!(report.merkle_verified && report.payload_binding_verified);
            Ok(())
        }
        Err(e) => Err(variant(&e)),
    };
    walk(&Subject {
        name: "bundle",
        wire,
        verify: &verify,
    })
}

fn receipt_passes() -> Vec<(&'static str, Tally)> {
    let key = SigningKey::from_bytes(&[42u8; 32]);
    let vk = key.verifying_key().to_bytes();
    let session = Session {
        session_id: "spiffe://prod.example.com/ns/agents/sa/walker".into(),
        issuer_kid: "walk-kid-1".into(),
        issued_at_micros: 1_717_000_000_123_456,
        parent_chain: vec![
            "spiffe://prod.example.com/ns/agents/sa/root".into(),
            "spiffe://prod.example.com/ns/agents/sa/middle".into(),
        ],
    };
    let projections = vec![
        Projection::Identity(
            serde_json::json!({"sub": "spiffe://prod.example.com/ns/agents/sa/walker", "aud": "walk"}),
        ),
        Projection::Flow(
            serde_json::json!({"node_count": 3, "any_adversarial": false, "labels": ["public", "internal"]}),
        ),
        Projection::Economic(
            serde_json::json!({"bid_micro_usd": 1500, "payments": [{"to": "a", "amount": -2}]}),
        ),
    ];
    let receipt = Receipt::sign(session, projections, &key);
    let verify = |r: &Receipt| r.verify_strict(&vk).map_err(|e| variant(&e));
    walk(&Subject {
        name: "receipt",
        wire: serde_json::to_vec(&receipt).expect("serializes"),
        verify: &verify,
    })
}

/// The refusal's variant name, so the tally counts reasons rather than messages.
fn variant(e: &impl Debug) -> String {
    let full = format!("{e:?}");
    full.split(['(', ' ', '{'])
        .next()
        .unwrap_or(&full)
        .to_string()
}

#[test]
fn a8_bundle_verification_is_exact() {
    assert_exact("bundle", &bundle_passes());
}

#[test]
fn a8_receipt_verification_is_exact() {
    assert_exact("receipt", &receipt_passes());
}

/// FINDING: see the [`Why::Finding`] entries for `bundle` in [`UNCOVERED`]. Red
/// until `verify_bundle` authenticates the checkpoints it reports and the envelope
/// metadata — or until the design says they are unauthenticated, at which point
/// the entries become [`Why::ByDesign`] and this test is deleted.
#[test]
#[ignore = "FINDING: bundle checkpoints and meta verify when tampered"]
fn finding_bundle_checkpoints_and_meta_are_unauthenticated() {
    let found = findings("bundle", &bundle_passes());
    assert!(found.is_empty(), "{}", found.join("\n"));
}

/// FINDING: a receipt's wire `version` is not bound by its signature. Red until
/// `verify_strict` refuses a version other than the one it signs.
#[test]
#[ignore = "FINDING: receipt version field verifies when tampered"]
fn finding_receipt_version_is_unauthenticated() {
    let found = findings("receipt", &receipt_passes());
    assert!(found.is_empty(), "{}", found.join("\n"));
}

#[test]
fn walk_classifies_outcomes_by_type_not_by_bytes() {
    // The diff the classification rests on: an object reorder is no change, a leaf
    // is named by path with indices collapsed, and a length change names the array.
    let a = serde_json::json!({"x": [{"y": 1}, {"y": 2}], "z": "s"});
    let b: Value = serde_json::from_str(r#"{"z":"s","x":[{"y":1},{"y":3}]}"#).unwrap();
    let mut d = BTreeSet::new();
    diff(&a, &b, String::new(), &mut d);
    assert_eq!(d, BTreeSet::from(["/x/*/y".to_string()]));
    let c = serde_json::json!({"x": [{"y": 1}], "z": "s"});
    let mut d = BTreeSet::new();
    diff(&a, &c, String::new(), &mut d);
    assert_eq!(d, BTreeSet::from(["/x".to_string()]));
    assert!(uncovered("bundle", "/envelope/metadata").is_none());
    assert!(uncovered("bundle", "/envelope/meta/created_at").is_some());
}

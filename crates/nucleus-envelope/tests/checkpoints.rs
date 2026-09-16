//! `Envelope::checkpoints` are verified, each refusal for its named reason.
//!
//! The A8 walk (`verification_is_exact.rs`) tampers bytes without keys, which
//! reaches the signature check. These tests hold the witness key, the way an
//! equivocating or careless producer does, so they reach the checks behind it:
//! equivocation, agreement with the Merkle anchor, and roots recomputed from the
//! bundle's own edges.

use nucleus_envelope::{
    Bundle, BundleBuilder, CheckpointVerification, MIN_SUPPORTED_ENVELOPE_SCHEMA_VERSION,
    TrustAnchor, VerifyBundleError, verify_bundle,
};
use nucleus_lineage::{
    CallSpiffeId, Cosignature, CosignatureKind, Ed25519Witness, EdgeKind, EdgeSigner, InMemorySink,
    Jwks, LineageEdge, LineageSink, LocalIssuer, MerkleConfig, MerkleSink, Proof, SignedTreeHead,
    TreeWitness, canonical_edge_bytes, canonical_sth_bytes, edge_content_hash, read_checkpoints,
};

const WITNESS_SEED: [u8; 32] = [21u8; 32];

fn pod() -> CallSpiffeId {
    CallSpiffeId::pod("prod.example.com", "agents", "checkpointed").unwrap()
}

fn signed(issuer: &LocalIssuer, mut edge: LineageEdge, prev: Option<&[u8; 32]>) -> LineageEdge {
    let sig = issuer.sign(&canonical_edge_bytes(&edge, prev)).unwrap();
    let mut proof = Proof::new(issuer.kid(), issuer.alg(), sig);
    if let Some(h) = prev {
        proof = proof.with_prev_hash(*h);
    }
    edge.proof = Some(proof);
    edge
}

/// A bundle over a 4-edge log with a checkpoint every 1 edge (sizes 1..=4) and a
/// Merkle anchor at size 4. `foreign_first` puts one other pod's edge at the
/// front of the log, so the bundle no longer carries the whole log.
fn fixture(foreign_first: bool) -> (Bundle, TrustAnchor) {
    let dir = tempfile::tempdir().unwrap();
    let witness = Ed25519Witness::from_seed(WITNESS_SEED);
    let witness_pub = witness.verifying_key_bytes();
    let sink = MerkleSink::new(
        InMemorySink::new(),
        witness,
        MerkleConfig::new(dir.path()).with_interval(1),
    )
    .unwrap();
    if foreign_first {
        let other = CallSpiffeId::pod("prod.example.com", "agents", "other").unwrap();
        sink.emit(LineageEdge::pod_admit(other)).unwrap();
    }
    let issuer = LocalIssuer::random().unwrap();
    let p = pod();
    let mut prev: Option<[u8; 32]> = None;
    for i in 0..3 {
        let edge = if i == 0 {
            LineageEdge::pod_admit(p.clone())
        } else {
            LineageEdge::from_parent(
                p.derive_tool("Read", Some(format!("in-{i}").as_bytes()))
                    .unwrap(),
                p.clone(),
                EdgeKind::ToolCall {
                    tool: "Read".into(),
                },
            )
        };
        let e = signed(&issuer, edge, prev.as_ref());
        prev = Some(edge_content_hash(&e, prev.as_ref()));
        sink.emit(e).unwrap();
    }
    if !foreign_first {
        let tool = p.derive_tool("Write", Some(b"out")).unwrap();
        let e = signed(
            &issuer,
            LineageEdge::from_parent(
                tool,
                p.clone(),
                EdgeKind::ToolCall {
                    tool: "Write".into(),
                },
            ),
            prev.as_ref(),
        );
        sink.emit(e).unwrap();
    }
    let checkpoints = read_checkpoints(dir.path()).unwrap();
    let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
    let bundle = BundleBuilder::new(p)
        .payload(serde_json::json!({"n": 1}))
        .sink(&sink)
        .jwks(jwks.clone())
        .checkpoints(checkpoints)
        .with_merkle_prover(&sink)
        .build()
        .unwrap();
    let trust = TrustAnchor::from_jwks(jwks).with_witness_pubkey(witness_pub);
    (bundle, trust)
}

/// Re-sign `sth` over `(tree_size, root)` with the witness key.
fn resign(sth: &SignedTreeHead, tree_size: u64, root_hex: &str) -> SignedTreeHead {
    let key = Ed25519Witness::from_seed(WITNESS_SEED);
    let root: [u8; 32] = hex::decode(root_hex).unwrap().try_into().unwrap();
    SignedTreeHead {
        tree_size,
        timestamp_ms: sth.timestamp_ms,
        root_hash_hex: root_hex.to_string(),
        witness_kid: key.kid().to_string(),
        witness_sig: key
            .sign_message(&canonical_sth_bytes(tree_size, sth.timestamp_ms, &root))
            .to_vec(),
        cosignatures: Vec::new(),
    }
}

#[test]
fn a_whole_log_bundle_verifies_every_checkpoint_against_its_own_edges() {
    let (bundle, trust) = fixture(false);
    assert_eq!(bundle.envelope.checkpoints.len(), 4);
    let report = verify_bundle(&bundle, &trust).expect("control verifies");
    assert_eq!(
        report.checkpoints,
        CheckpointVerification::Verified {
            count: 4,
            recomputed_from_edges: 4,
        }
    );
}

#[test]
fn a_partial_log_bundle_verifies_checkpoints_without_recomputing() {
    let (bundle, trust) = fixture(true);
    let report = verify_bundle(&bundle, &trust).expect("control verifies");
    assert_eq!(
        report.checkpoints,
        CheckpointVerification::Verified {
            count: 4,
            recomputed_from_edges: 0,
        },
        "the bundle does not hold leaf 0, so no root can be recomputed"
    );
}

#[test]
fn a_root_signed_with_the_key_but_not_the_edges_is_refused() {
    let (mut bundle, trust) = fixture(false);
    // Size 2, signed with size 3's root: the witness key vouches, the edges do not.
    let wrong = bundle.envelope.checkpoints[2].root_hash_hex.clone();
    bundle.envelope.checkpoints[1] = resign(&bundle.envelope.checkpoints[1], 2, &wrong);
    let err = verify_bundle(&bundle, &trust).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyBundleError::CheckpointRootMismatch {
                index: 1,
                tree_size: 2,
                ..
            }
        ),
        "{err:?}"
    );
}

#[test]
fn two_roots_for_one_size_are_an_equivocation() {
    let (mut bundle, trust) = fixture(true);
    let mut split = bundle.envelope.checkpoints[0].clone();
    let other_root = bundle.envelope.checkpoints[1].root_hash_hex.clone();
    split = resign(&split, split.tree_size, &other_root);
    bundle.envelope.checkpoints.push(split);
    let err = verify_bundle(&bundle, &trust).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyBundleError::CheckpointEquivocation {
                index: 4,
                other: 0,
                tree_size: 1
            }
        ),
        "{err:?}"
    );
}

#[test]
fn a_checkpoint_past_the_anchor_or_disagreeing_at_its_size_is_refused() {
    let (bundle, trust) = fixture(true);
    let anchor = bundle.envelope.merkle_anchor.clone().unwrap().sth;

    let mut beyond = bundle.clone();
    beyond.envelope.checkpoints[3] = resign(
        &anchor,
        anchor.tree_size + 1,
        &beyond.envelope.checkpoints[3].root_hash_hex.clone(),
    );
    let err = verify_bundle(&beyond, &trust).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyBundleError::CheckpointBeyondAnchor { index: 3, .. }
        ),
        "{err:?}"
    );

    let mut disagree = bundle.clone();
    let other_root = disagree.envelope.checkpoints[0].root_hash_hex.clone();
    disagree.envelope.checkpoints[3] = resign(&anchor, anchor.tree_size, &other_root);
    let err = verify_bundle(&disagree, &trust).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyBundleError::CheckpointRootMismatch { index: 3, .. }
        ),
        "{err:?}"
    );
}

#[test]
fn checkpoints_need_a_witness_key_carry_no_cosignatures_and_are_skipped_only_in_self_check() {
    let (bundle, trust) = fixture(false);
    let jwks = bundle.envelope.jwks.clone();

    // No witness key: refused, not reported as unverified. (A bundle with no Merkle
    // anchor, so MissingWitnessKey cannot fire first.)
    let mut unanchored = bundle.clone();
    unanchored.envelope.merkle_anchor = None;
    let err = verify_bundle(&unanchored, &TrustAnchor::from_jwks(jwks)).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyBundleError::CheckpointWithoutWitnessKey { count: 4 }
        ),
        "{err:?}"
    );

    let mut cosigned = bundle.clone();
    cosigned.envelope.checkpoints[0]
        .cosignatures
        .push(Cosignature {
            witness_kid: "anyone".into(),
            signature: vec![0u8; 64],
            timestamp_ms: 0,
            kind: CosignatureKind::Nucleus,
        });
    let err = verify_bundle(&cosigned, &trust).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyBundleError::CheckpointCosignaturesUnsupported { index: 0 }
        ),
        "{err:?}"
    );

    let report = verify_bundle(&bundle, &TrustAnchor::self_check_only()).expect("self-check");
    assert_eq!(
        report.checkpoints,
        CheckpointVerification::NotChecked { count: 4 }
    );
}

#[test]
fn a_schema_version_below_the_minimum_is_refused() {
    let (mut bundle, trust) = fixture(false);
    bundle.envelope.meta.schema_version = MIN_SUPPORTED_ENVELOPE_SCHEMA_VERSION - 1;
    let err = verify_bundle(&bundle, &trust).unwrap_err();
    assert!(
        matches!(err, VerifyBundleError::SchemaTooOld { got, minimum }
            if got == MIN_SUPPORTED_ENVELOPE_SCHEMA_VERSION - 1
                && minimum == MIN_SUPPORTED_ENVELOPE_SCHEMA_VERSION),
        "{err:?}"
    );
}

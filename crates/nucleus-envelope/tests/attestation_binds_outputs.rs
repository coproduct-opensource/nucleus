//! The standard attestation exports name what the session PRODUCED, and say
//! the content is AI-generated, from fields the lineage already signs.
//!
//! Before this file the in-toto Statement's only subject was the bundle's own
//! payload hash: an attestation no consumer holding an output file could find
//! by that file's digest. And the predicate was the raw envelope, so "this was
//! produced by an AI agent" was something a reader had to infer.
//!
//! - H2: one subject per `ArtifactProduced` edge, digest = the artifact bytes'
//!   SHA-256 as the signed child id records it. A consumer finds the
//!   attestation by the file's digest; a tampered file is found by nothing.
//! - H3: a typed `aiGeneration` record in a versioned predicate, carrying the
//!   agent identity (session root) and the model providers the signed
//!   lineage names.
//! - A-1: an artifact edge with no recorded digest, or one whose two digest
//!   fields disagree, is refused — "could not bind" is never exported as
//!   "bound".

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use nucleus_envelope::{Bundle, BundleBuilder};
use nucleus_lineage::{
    CallSpiffeId, EdgeKind, EdgeSigner, InMemorySink, Jwks, LineageEdge, LineageSink, LocalIssuer,
    Proof, canonical_edge_bytes, edge_content_hash,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The bytes the agent produced — what a downstream consumer holds as a file.
const ARTIFACT: &[u8] = b"quarterly summary: revenue up, costs flat\n";
const MODEL: &str = "example-model";

fn pod() -> CallSpiffeId {
    CallSpiffeId::pod("prod.example.com", "agents", "summarizer").unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Emit `edges` into a sink, each signed by `issuer` and chained.
fn signed_sink(issuer: &LocalIssuer, edges: Vec<LineageEdge>) -> InMemorySink {
    let sink = InMemorySink::new();
    let mut prev: Option<[u8; 32]> = None;
    for mut edge in edges {
        let bytes = canonical_edge_bytes(&edge, prev.as_ref());
        let mut proof = Proof::new(issuer.kid(), issuer.alg(), issuer.sign(&bytes).unwrap());
        if let Some(h) = prev {
            proof = proof.with_prev_hash(h);
        }
        edge.proof = Some(proof);
        prev = Some(edge_content_hash(&edge, prev.as_ref()));
        sink.emit(edge).unwrap();
    }
    sink
}

fn bundle_from(issuer: &LocalIssuer, edges: Vec<LineageEdge>) -> Bundle {
    let sink = signed_sink(issuer, edges);
    let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
    BundleBuilder::new(pod())
        .payload(serde_json::json!({"summary": "revenue up, costs flat"}))
        .sink(&sink)
        .jwks(jwks)
        .build()
        .unwrap()
}

/// pod_admit → Read → model prompt → model response → ArtifactProduced(ARTIFACT).
fn session_edges() -> Vec<LineageEdge> {
    let p = pod();
    let read = p.derive_tool("Read", Some(b"q3.csv bytes")).unwrap();
    let prompt = read.derive_llm(MODEL, "prompt", b"summarize").unwrap();
    let response = prompt.derive_llm(MODEL, "response", ARTIFACT).unwrap();
    let artifact = response.derive_artifact(ARTIFACT).unwrap();
    vec![
        LineageEdge::pod_admit(p.clone()),
        LineageEdge::from_parent(
            read.clone(),
            p,
            EdgeKind::ToolCall {
                tool: "Read".to_string(),
            },
        ),
        LineageEdge::from_parent(
            prompt.clone(),
            read,
            EdgeKind::LlmCall {
                provider: MODEL.to_string(),
                direction: "prompt".to_string(),
            },
        ),
        LineageEdge::from_parent(
            response.clone(),
            prompt,
            EdgeKind::LlmCall {
                provider: MODEL.to_string(),
                direction: "response".to_string(),
            },
        ),
        LineageEdge::from_parent(artifact, response, EdgeKind::ArtifactProduced),
    ]
}

fn statement_json(bundle: &Bundle) -> Value {
    serde_json::to_value(bundle.to_in_toto_statement().unwrap()).unwrap()
}

/// Every `sha256` digest the Statement's subject list names.
fn subject_digests(statement: &Value) -> Vec<String> {
    statement["subject"]
        .as_array()
        .expect("subject is a list")
        .iter()
        .map(|s| s["digest"]["sha256"].as_str().unwrap().to_string())
        .collect()
}

// ── H2: the outputs are subjects ────────────────────────────────────────────

#[test]
fn in_toto_subjects_name_every_produced_artifact_by_its_content_digest() {
    let issuer = LocalIssuer::random().unwrap();
    let bundle = bundle_from(&issuer, session_edges());
    let stmt = statement_json(&bundle);
    let digests = subject_digests(&stmt);

    assert!(
        digests.contains(&sha256_hex(ARTIFACT)),
        "the produced artifact's digest must be a subject; got {digests:?}"
    );
    // The bundle-payload subject is kept, and it is the JCS payload hash —
    // the same decider the payload binding signs.
    let payload = hex::encode(nucleus_envelope::payload_hash(&bundle.payload).unwrap());
    assert!(
        digests.contains(&payload),
        "payload subject kept: {digests:?}"
    );
    assert_eq!(digests.len(), 2, "payload + one artifact: {digests:?}");
}

#[test]
fn slsa_subjects_also_name_the_produced_artifacts() {
    let issuer = LocalIssuer::random().unwrap();
    let bundle = bundle_from(&issuer, session_edges());
    let stmt = serde_json::to_value(bundle.to_slsa_statement().unwrap()).unwrap();
    assert!(subject_digests(&stmt).contains(&sha256_hex(ARTIFACT)));
}

/// The consumer's path end to end: hold a file, hash it, find the subject in a
/// DSSE envelope whose signature verifies. Tamper the file and nothing matches.
#[test]
fn a_consumer_finds_the_attestation_by_the_files_digest_and_a_tampered_file_finds_nothing() {
    let issuer = LocalIssuer::random().unwrap();
    let bundle = bundle_from(&issuer, session_edges());
    let dsse = bundle.to_in_toto_dsse(&issuer).unwrap();

    // 1. The envelope signature verifies over PAE(payloadType, payload).
    let statement_bytes = B64.decode(&dsse.payload).unwrap();
    let pae = nucleus_envelope::binding::pae_bytes(&dsse.payload_type, &[&statement_bytes]);
    let sig: [u8; 64] = B64
        .decode(&dsse.signatures[0].sig)
        .unwrap()
        .try_into()
        .unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&issuer.verifying_key_bytes()).unwrap();
    ed25519_dalek::Verifier::verify(&vk, &pae, &ed25519_dalek::Signature::from_bytes(&sig))
        .expect("DSSE signature verifies");

    // 2. The file the consumer holds is named by digest.
    let stmt: Value = serde_json::from_slice(&statement_bytes).unwrap();
    let file = ARTIFACT.to_vec();
    assert!(subject_digests(&stmt).contains(&sha256_hex(&file)));

    // 3. One flipped byte: the attestation no longer covers the file.
    let mut tampered = file;
    tampered[0] ^= 0x01;
    assert!(
        !subject_digests(&stmt).contains(&sha256_hex(&tampered)),
        "a tampered artifact must match no subject"
    );
}

// ── A-1: an artifact that cannot be bound is refused, not omitted ───────────

#[test]
fn an_artifact_edge_with_no_recorded_digest_refuses_export() {
    let issuer = LocalIssuer::random().unwrap();
    let p = pod();
    // A tool id with no content → no `/sha256:` suffix, and no content field.
    let child = p.derive_tool("Write", None).unwrap();
    let edges = vec![
        LineageEdge::pod_admit(p.clone()),
        LineageEdge::from_parent(child, p, EdgeKind::ArtifactProduced),
    ];
    let bundle = bundle_from(&issuer, edges);
    assert!(
        bundle.to_in_toto_statement().is_err(),
        "an unbindable artifact must refuse export, not drop out of the subject list"
    );
    assert!(bundle.to_slsa_statement().is_err());
}

#[test]
fn an_artifact_whose_id_and_content_field_disagree_refuses_export() {
    let issuer = LocalIssuer::random().unwrap();
    let p = pod();
    let child = p.derive_artifact(ARTIFACT).unwrap();
    let edges = vec![
        LineageEdge::pod_admit(p.clone()),
        LineageEdge::from_parent(child, p, EdgeKind::ArtifactProduced)
            .with_content_hash(sha256_hex(b"some other bytes")),
    ];
    let bundle = bundle_from(&issuer, edges);
    assert!(bundle.to_in_toto_statement().is_err());
}

#[test]
fn an_artifact_named_only_by_its_content_field_is_a_subject() {
    let issuer = LocalIssuer::random().unwrap();
    let p = pod();
    let child = p.derive_tool("Write", None).unwrap();
    let edges = vec![
        LineageEdge::pod_admit(p.clone()),
        LineageEdge::from_parent(child, p, EdgeKind::ArtifactProduced)
            .with_content_hash(sha256_hex(ARTIFACT)),
    ];
    let bundle = bundle_from(&issuer, edges);
    assert!(subject_digests(&statement_json(&bundle)).contains(&sha256_hex(ARTIFACT)));
}

// ── H3: the AI-generated marking is explicit and typed ──────────────────────

#[test]
fn the_predicate_marks_the_content_ai_generated_with_agent_and_model_identity() {
    let issuer = LocalIssuer::random().unwrap();
    let bundle = bundle_from(&issuer, session_edges());
    let stmt = statement_json(&bundle);

    assert_eq!(
        stmt["predicateType"], "https://nucleus.coproduct.io/agent-provenance/v2",
        "the predicate's shape changed, so its type URI is versioned"
    );
    let ai = &stmt["predicate"]["aiGeneration"];
    assert_eq!(ai["origin"], "ai-agent-under-nucleus-enforcement");
    assert_eq!(ai["agent"], pod().as_str());
    assert_eq!(ai["modelProviders"], serde_json::json!([MODEL]));
    // The envelope still rides along, verbatim, for independent re-verification.
    assert_eq!(
        stmt["predicate"]["envelope"]["session_root"],
        pod().as_str()
    );
}

#[test]
fn a_model_edge_whose_kind_disagrees_with_its_signed_id_refuses_export() {
    // `EdgeKind::LlmCall.provider` is not in the signed bytes; the child id
    // is. A provider name that differs from the id is unsigned data
    // pretending to be identity.
    let issuer = LocalIssuer::random().unwrap();
    let p = pod();
    let prompt = p.derive_llm(MODEL, "prompt", b"x").unwrap();
    let edges = vec![
        LineageEdge::pod_admit(p.clone()),
        LineageEdge::from_parent(
            prompt,
            p,
            EdgeKind::LlmCall {
                provider: "a-different-model".to_string(),
                direction: "prompt".to_string(),
            },
        ),
    ];
    let bundle = bundle_from(&issuer, edges);
    assert!(bundle.to_in_toto_statement().is_err());
}

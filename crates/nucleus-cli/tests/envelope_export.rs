//! `nucleus envelope-export` — the standard attestation formats, from a binary.
//!
//! The in-toto / SLSA / Sigstore adapters in `nucleus-envelope` were
//! library-only: no binary emitted them, so nothing a consumer ran could
//! produce one. These tests drive the real `nucleus` binary:
//!
//! - every format is emitted, signed by the `--signing-key`, and names the
//!   produced artifact by its digest;
//! - a bundle that does not verify against `--trust-jwks` is NOT attested —
//!   the exporter refuses rather than vouching for an unverified record;
//! - `cosign_*` (ignored by default) hands the output to an independent
//!   verifier. Run with `NUCLEUS_COSIGN=/path/to/cosign`; it fails, never
//!   skips, when the variable is unset.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey, spki::der::pem::LineEnding};
use nucleus_envelope::BundleBuilder;
use nucleus_lineage::{
    CallSpiffeId, EdgeKind, EdgeSigner, InMemorySink, Jwks, LineageEdge, LineageSink,
    Pkcs8FileSigner, Proof, SigningProvider, canonical_edge_bytes, edge_content_hash,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const ARTIFACT: &[u8] = b"generated report body\n";
const NUCLEUS_PREDICATE: &str = "https://nucleus.coproduct.io/agent-provenance/v2";
const SLSA_PREDICATE: &str = "https://slsa.dev/provenance/v1";

fn nucleus() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_nucleus"));
    c.env_remove("RUST_LOG");
    c
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

struct Fixture {
    _dir: tempfile::TempDir,
    bundle: PathBuf,
    jwks: PathBuf,
    key: PathBuf,
    public_pem: PathBuf,
    artifact: PathBuf,
    verifying_key: ed25519_dalek::VerifyingKey,
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

/// A signed session pod_admit → model response → ArtifactProduced(ARTIFACT),
/// its bundle, the JWKS that verifies it, and the PKCS#8 key that signed it.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let sk = SigningKey::from_bytes(&[42u8; 32]);
    let pem = sk.to_pkcs8_pem(LineEnding::LF).unwrap();
    let signer = Pkcs8FileSigner::from_pkcs8_pem(&pem).unwrap();

    let pod = CallSpiffeId::pod("prod.example.com", "agents", "writer").unwrap();
    let response = pod
        .derive_llm("example-model", "response", ARTIFACT)
        .unwrap();
    let artifact = response.derive_artifact(ARTIFACT).unwrap();
    let edges = vec![
        LineageEdge::pod_admit(pod.clone()),
        LineageEdge::from_parent(
            response.clone(),
            pod.clone(),
            EdgeKind::LlmCall {
                provider: "example-model".to_string(),
                direction: "response".to_string(),
            },
        ),
        LineageEdge::from_parent(artifact, response, EdgeKind::ArtifactProduced),
    ];
    let sink = InMemorySink::new();
    let mut prev: Option<[u8; 32]> = None;
    for mut edge in edges {
        let bytes = canonical_edge_bytes(&edge, prev.as_ref());
        let mut proof = Proof::new(signer.kid(), signer.alg(), signer.sign(&bytes).unwrap());
        if let Some(h) = prev {
            proof = proof.with_prev_hash(h);
        }
        edge.proof = Some(proof);
        prev = Some(edge_content_hash(&edge, prev.as_ref()));
        sink.emit(edge).unwrap();
    }
    let jwks_value = signer.publish_jwks();
    let jwks: Jwks = serde_json::from_value(jwks_value.clone()).unwrap();
    let bundle = BundleBuilder::new(pod)
        .payload(serde_json::json!({"report": "generated report body"}))
        .sink(&sink)
        .jwks(jwks)
        .build()
        .unwrap();

    let vk = sk.verifying_key();
    let public_pem = vk.to_public_key_pem(LineEnding::LF).unwrap();
    Fixture {
        bundle: write(
            dir.path(),
            "bundle.json",
            &serde_json::to_vec(&bundle).unwrap(),
        ),
        jwks: write(
            dir.path(),
            "jwks.json",
            &serde_json::to_vec(&jwks_value).unwrap(),
        ),
        key: write(dir.path(), "key.pem", pem.as_bytes()),
        public_pem: write(dir.path(), "key.pub.pem", public_pem.as_bytes()),
        artifact: write(dir.path(), "report.txt", ARTIFACT),
        verifying_key: vk,
        _dir: dir,
    }
}

fn export(f: &Fixture, format: &str, trust_jwks: &Path) -> Output {
    nucleus()
        .arg("envelope-export")
        .arg(&f.bundle)
        .args(["--format", format])
        .arg("--signing-key")
        .arg(&f.key)
        .arg("--trust-jwks")
        .arg(trust_jwks)
        .output()
        .unwrap()
}

/// Verify a DSSE envelope's signature and return its decoded Statement.
fn open_dsse(dsse: &Value, vk: &ed25519_dalek::VerifyingKey) -> Value {
    let payload_type = dsse["payloadType"].as_str().unwrap();
    assert_eq!(payload_type, "application/vnd.in-toto+json");
    let payload = B64.decode(dsse["payload"].as_str().unwrap()).unwrap();
    let pae = nucleus_envelope::binding::pae_bytes(payload_type, &[&payload]);
    let sig: [u8; 64] = B64
        .decode(dsse["signatures"][0]["sig"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    ed25519_dalek::Verifier::verify(vk, &pae, &ed25519_dalek::Signature::from_bytes(&sig))
        .expect("DSSE signature verifies against the signing key");
    serde_json::from_slice(&payload).unwrap()
}

fn subject_digests(stmt: &Value) -> Vec<String> {
    stmt["subject"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["digest"]["sha256"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn every_format_is_emitted_signed_and_names_the_artifact() {
    let f = fixture();
    for (format, sigstore, predicate) in [
        ("in-toto", false, NUCLEUS_PREDICATE),
        ("slsa", false, SLSA_PREDICATE),
        ("sigstore", true, NUCLEUS_PREDICATE),
        ("sigstore-slsa", true, SLSA_PREDICATE),
    ] {
        let out = export(&f, format, &f.jwks);
        assert!(
            out.status.success(),
            "{format}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
        let dsse = if sigstore {
            assert_eq!(
                doc["mediaType"],
                "application/vnd.dev.sigstore.bundle.v0.3+json"
            );
            &doc["dsseEnvelope"]
        } else {
            &doc
        };
        let stmt = open_dsse(dsse, &f.verifying_key);
        assert_eq!(stmt["predicateType"], predicate, "{format}");
        assert!(
            subject_digests(&stmt).contains(&sha256_hex(ARTIFACT)),
            "{format}: the artifact must be a subject"
        );
        if predicate == NUCLEUS_PREDICATE {
            assert_eq!(
                stmt["predicate"]["aiGeneration"]["origin"],
                "ai-agent-under-nucleus-enforcement"
            );
        }
    }
}

#[test]
fn a_bundle_that_does_not_verify_against_the_trust_jwks_is_not_attested() {
    let f = fixture();
    let stranger = Pkcs8FileSigner::from_pkcs8_pem(
        &SigningKey::from_bytes(&[9u8; 32])
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap(),
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let other = write(
        dir.path(),
        "other.json",
        &serde_json::to_vec(&stranger.publish_jwks()).unwrap(),
    );
    let out = export(&f, "in-toto", &other);
    assert!(!out.status.success(), "must refuse an unverified bundle");
    assert!(out.stdout.is_empty(), "no attestation may be written");
}

#[test]
fn an_unknown_format_is_refused() {
    let f = fixture();
    let out = export(&f, "c2pa", &f.jwks);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
}

/// Hand each export to `cosign verify-blob-attestation` with the public key.
/// cosign checks the DSSE signature, the predicate type, AND that the blob's
/// SHA-256 is one of the Statement's subjects. The real artifact must verify;
/// a one-byte change to it must fail, and fail for the digest — not for some
/// other reason a broken invocation would also produce.
fn cosign_round_trip(formats: [(&str, &str); 2], bundle_flags: &[&str], digest_refusal: &str) {
    let cosign = std::env::var("NUCLEUS_COSIGN")
        .expect("NUCLEUS_COSIGN must name a cosign binary; this test never skips silently");
    let f = fixture();
    let dir = tempfile::tempdir().unwrap();
    let mut tampered = ARTIFACT.to_vec();
    tampered[0] ^= 0x01;
    let tampered = write(dir.path(), "tampered.txt", &tampered);
    for (format, predicate) in formats {
        let out = export(&f, format, &f.jwks);
        assert!(out.status.success(), "{format}");
        let att = write(dir.path(), &format!("{format}.json"), &out.stdout);
        let run = |blob: &Path| {
            Command::new(&cosign)
                .arg("verify-blob-attestation")
                .arg("--key")
                .arg(&f.public_pem)
                .arg(bundle_flags[0])
                .arg(&att)
                .args(&bundle_flags[1..])
                .args(["--type", predicate])
                .arg("--insecure-ignore-tlog=true")
                .arg(blob)
                .output()
                .unwrap()
        };
        let good = run(&f.artifact);
        assert!(
            good.status.success(),
            "{format}: cosign must verify: {}",
            String::from_utf8_lossy(&good.stderr)
        );
        let bad = run(&tampered);
        let stderr = String::from_utf8_lossy(&bad.stderr);
        assert!(
            !bad.status.success(),
            "{format}: tampered artifact must fail"
        );
        assert!(
            stderr.contains(digest_refusal),
            "{format}: must fail on the subject digest, got: {stderr}"
        );
    }
}

/// The bare DSSE forms (`in-toto`, `slsa`) via `--signature`.
#[test]
#[ignore = "needs an external cosign binary: NUCLEUS_COSIGN=/path/to/cosign"]
fn cosign_verifies_the_dsse_attestation_against_the_artifact() {
    cosign_round_trip(
        [("in-toto", NUCLEUS_PREDICATE), ("slsa", SLSA_PREDICATE)],
        &["--signature"],
        "no matching subject digest found",
    );
}

/// The Sigstore Bundle v0.3 forms via cosign's bundle reader.
#[test]
#[ignore = "needs an external cosign binary: NUCLEUS_COSIGN=/path/to/cosign"]
fn cosign_verifies_the_sigstore_bundle_against_the_artifact() {
    cosign_round_trip(
        [
            ("sigstore", NUCLEUS_PREDICATE),
            ("sigstore-slsa", SLSA_PREDICATE),
        ],
        &["--bundle", "--new-bundle-format"],
        "unable to confirm artifact digest is present in subject digests",
    );
}

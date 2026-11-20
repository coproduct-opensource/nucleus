//! #3320: `verify_chain` admits an honestly signed chain and refuses every way
//! of breaking one, at the index of the first broken edge.
//!
//! The chain is signed here with a plain Ed25519 key resolved through
//! [`StaticKeyResolver`], so the test needs no demo-issuer feature. Each break
//! is applied to a copy of the honest chain, and the honest chain verifying
//! first is what makes each refusal the check firing rather than a verifier
//! that refuses everything.

use ed25519_dalek::{Signer, SigningKey};
use nucleus_lineage::{
    CallSpiffeId, EdgeKind, Jwks, LineageEdge, Proof, StaticKeyResolver, VerifyError,
    canonical_edge_bytes, edge_content_hash, verify_chain,
};

const KID: &str = "chain-test-key";

fn sign(
    key: &SigningKey,
    kid: &str,
    mut edge: LineageEdge,
    prev: Option<&[u8; 32]>,
) -> LineageEdge {
    let sig = key
        .sign(&canonical_edge_bytes(&edge, prev))
        .to_bytes()
        .to_vec();
    let mut proof = Proof::new(kid, "EdDSA", sig);
    if let Some(h) = prev {
        proof = proof.with_prev_hash(*h);
    }
    edge.proof = Some(proof);
    edge
}

/// pod_admit → ToolCall → ArtifactProduced, each edge chained to the last.
fn chain(key: &SigningKey, kid: &str) -> Vec<LineageEdge> {
    let pod = CallSpiffeId::pod("prod.example.com", "agents", "summarizer").unwrap();
    let tool = pod.derive_tool("Read", Some(b"input")).unwrap();
    let leaf = tool.derive_artifact(b"output").unwrap();

    let e1 = sign(key, kid, LineageEdge::pod_admit(pod.clone()), None);
    let h1 = edge_content_hash(&e1, None);
    let e2 = sign(
        key,
        kid,
        LineageEdge::from_parent(
            tool.clone(),
            pod,
            EdgeKind::ToolCall {
                tool: "Read".to_string(),
            },
        ),
        Some(&h1),
    );
    let h2 = edge_content_hash(&e2, Some(&h1));
    let e3 = sign(
        key,
        kid,
        LineageEdge::from_parent(leaf, tool, EdgeKind::ArtifactProduced),
        Some(&h2),
    );
    vec![e1, e2, e3]
}

fn jwks_for(key: &SigningKey) -> Jwks {
    StaticKeyResolver::new()
        .insert(KID, key.verifying_key())
        .into_jwks()
}

#[test]
fn verify_chain_admits_the_signed_chain_and_refuses_every_break() {
    let key = SigningKey::from_bytes(&[11u8; 32]);
    let jwks = jwks_for(&key);
    let honest = chain(&key, KID);
    verify_chain(&honest, &jwks).expect("the honestly signed chain verifies");

    let broken = |edit: &dyn Fn(&mut Vec<LineageEdge>)| {
        let mut edges = honest.clone();
        edit(&mut edges);
        verify_chain(&edges, &jwks).expect_err("a broken chain must not verify")
    };

    // A middle edge's proof stripped.
    let (index, err) = broken(&|e: &mut Vec<LineageEdge>| e[1].proof = None);
    assert_eq!(index, 1);
    assert!(matches!(err, VerifyError::Unsigned), "{err:?}");

    // A middle edge dropped: the next edge's claimed prev_hash no longer
    // matches the edge now before it.
    let (index, err) = broken(&|e: &mut Vec<LineageEdge>| {
        e.remove(1);
    });
    assert_eq!(index, 1);
    assert!(matches!(err, VerifyError::BrokenChain { .. }), "{err:?}");

    // Two edges swapped.
    let (index, err) = broken(&|e: &mut Vec<LineageEdge>| e.swap(1, 2));
    assert_eq!(index, 1);
    assert!(matches!(err, VerifyError::BrokenChain { .. }), "{err:?}");

    // An edge's content edited after signing.
    let (index, err) = broken(&|e: &mut Vec<LineageEdge>| {
        e[2].kind = EdgeKind::ToolCall {
            tool: "Bash".to_string(),
        }
    });
    assert_eq!(index, 2);
    assert!(matches!(err, VerifyError::BadSignature { .. }), "{err:?}");

    // A middle edge dropped AND the claim that would expose it deleted: the
    // signature covers the prev_hash the verifier computes itself, not the
    // claimed one, so the splice still fails.
    let (index, err) = broken(&|e: &mut Vec<LineageEdge>| {
        e.remove(1);
        if let Some(p) = e[1].proof.as_mut() {
            p.prev_hash = None;
        }
    });
    assert_eq!(index, 1);
    assert!(matches!(err, VerifyError::BadSignature { .. }), "{err:?}");

    // The whole chain re-signed by a key the JWKS does not name, under its
    // own kid and wearing the trusted one.
    let stranger = SigningKey::from_bytes(&[12u8; 32]);
    let (index, err) = verify_chain(&chain(&stranger, "stranger"), &jwks).expect_err("unknown kid");
    assert_eq!(index, 0);
    assert!(matches!(err, VerifyError::UnknownKid { .. }), "{err:?}");
    let (index, err) =
        verify_chain(&chain(&stranger, KID), &jwks).expect_err("a stranger wearing the kid");
    assert_eq!(index, 0);
    assert!(matches!(err, VerifyError::BadSignature { .. }), "{err:?}");
}

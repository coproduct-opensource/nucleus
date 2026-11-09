use super::*;
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer as _},
    pkcs8::{EncodePublicKey as _, LineEnding},
};
use std::io::{Read as _, Write as _};

fn context() -> Context<'static> {
    Context {
        origin: "https://studio.example",
        rp_id: "studio.example",
    }
}
fn fixture() -> Envelope {
    let mut packet: Packet =
        serde_json::from_slice(include_bytes!("../../fixtures/equipment.packet.json")).unwrap();
    packet.authority_before = hex::encode(Sha256::digest(b"captured authority"));
    packet.authority_after = packet.authority_before.clone();
    let blueprint = json!({"version":1,"spec":packet.new_recipe});
    let subject = Subject {
        workspace: "test-workspace".into(),
        app: blueprint["spec"]["slug"].as_str().unwrap().into(),
        source_definition: digest_json(&packet.before).unwrap(),
        source_state: hex::encode(Sha256::digest(b"retained state")),
        source_binding: hex::encode(Sha256::digest(b"private binding")),
        candidate: candidate_digest(&blueprint, &packet.after, &packet).unwrap(),
        agent_key: B64.encode([42; 32]),
        expires: 600,
    };
    let subject_sha256 = subject_digest(&subject).unwrap();
    let challenge = B64.encode(hash32(&subject_sha256).unwrap());
    let signing = SigningKey::from_bytes((&[17u8; 32]).into()).unwrap();
    let public_key = signing
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    let credential_id = B64.encode(b"test credential");
    let client=serde_json::to_vec(&json!({"type":"webauthn.get","origin":context().origin,"challenge":challenge,"crossOrigin":false})).unwrap();
    let mut auth = Sha256::digest(context().rp_id.as_bytes()).to_vec();
    auth.push(nucleus_passkey_proof::FLAG_UP | nucleus_passkey_proof::FLAG_UV);
    auth.extend_from_slice(&1u32.to_be_bytes());
    let mut message = auth.clone();
    message.extend_from_slice(&Sha256::digest(&client));
    let signature: Signature = signing.sign(&message);
    let assertion = nucleus_passkey_proof::Assertion {
        credential_id: credential_id.clone(),
        client_data_json: B64.encode(client),
        authenticator_data: B64.encode(auth),
        signature: B64.encode(signature.to_der().as_bytes()),
        user_handle: None,
    };
    let approval = Approval {
        signed_by: "test approver".into(),
        challenge_id: "test ceremony".into(),
        challenge,
        assertion,
        credential: CredentialKey {
            kid: nucleus_passkey_proof::kid_for(&public_key),
            public_key,
            credential_id,
            rp_id: context().rp_id.into(),
            origin: context().origin.into(),
        },
        sign_count: 1,
    };
    let mut base = Vec::new();
    flate2::read::GzDecoder::new(include_bytes!("../../fixtures/base.ndjson.gz").as_slice())
        .read_to_end(&mut base)
        .unwrap();
    let delta =
        crate::producer::propose_delta(&base, &serde_json::to_vec(&packet).unwrap()).unwrap();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&delta).unwrap();
    Envelope {
        version: 2,
        after_state_sha256: subject.source_state.clone(),
        subject,
        subject_sha256,
        packet,
        blueprint,
        approval,
        applied_at: 1,
        delta_gzip: gzip.finish().unwrap(),
    }
}

#[test]
fn exact_signed_packet_rechecks_and_substitutions_refuse() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let original = fixture();
            let stored: serde_json::Value =
                serde_json::from_slice(include_bytes!("../../fixtures/equipment.signed.json"))
                    .unwrap();
            assert_eq!(
                serde_json::to_value(&original).unwrap(),
                stored,
                "public browser fixture drifted"
            );
            let checked = verify(
                include_bytes!("../../fixtures/base.ndjson.gz"),
                &original,
                context(),
            )
            .unwrap();
            let report = serde_json::to_value(checked).unwrap();
            assert_eq!(
                report["tiers"]["approval_signature"],
                "independently-rechecked"
            );
            assert_eq!(report["tiers"]["enrollment_and_membership"], "trusted");
            for mutation in 0..15 {
                let mut e = original.clone();
                match mutation {
                    0 => e.version = 1,
                    1 => e.subject.workspace.push('x'),
                    2 => e.subject.app.push('x'),
                    3 => e.packet.authority_after = hex::encode([0; 32]),
                    4 => e.blueprint["spec"]["slug"] = json!("other-app"),
                    5 => e.subject.source_definition = hex::encode([0; 32]),
                    6 => e.applied_at = e.subject.expires,
                    7 => e.after_state_sha256 = hex::encode([0; 32]),
                    8 => e.approval.challenge = B64.encode([0; 32]),
                    9 => e.approval.credential.origin = "https://attacker.example".into(),
                    10 => e.approval.credential.rp_id = "attacker.example".into(),
                    11 => e.approval.credential.kid.push('x'),
                    12 => e.approval.sign_count = 2,
                    13 => e.approval.assertion.signature = "AAAA".into(),
                    _ => {
                        e.subject.agent_key = B64.encode([0; 32]);
                        e.subject_sha256 = subject_digest(&e.subject).unwrap();
                        e.approval.challenge = B64.encode(hash32(&e.subject_sha256).unwrap());
                    }
                }
                assert!(
                    bind(&e, context()).is_err(),
                    "substitution {mutation} accepted"
                );
            }
            assert!(
                bind(
                    &original,
                    Context {
                        origin: "https://attacker.example",
                        rp_id: "attacker.example"
                    }
                )
                .is_err()
            );
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn canonical_commitments_reject_lossy_and_non_natural_numbers() {
    for value in [
        json!(u64::MAX),
        json!(9_007_199_254_740_992u64),
        json!(-1),
        json!(1.5),
    ] {
        assert!(canonical_bytes(&json!({"nested":[value]})).is_err());
    }
    assert!(canonical_bytes(&json!(9_007_199_254_740_991u64)).is_ok());
}

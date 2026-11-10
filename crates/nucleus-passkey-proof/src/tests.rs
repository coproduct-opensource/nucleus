use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

#[derive(Clone, Deserialize)]
struct StoredKey {
    public_key: String,
    rp_id: String,
    origin: String,
    credential_id: String,
}
impl StoredKey {
    fn borrowed(&self) -> Key<'_> {
        Key {
            public_key: &self.public_key,
            rp_id: &self.rp_id,
            origin: &self.origin,
            credential_id: &self.credential_id,
        }
    }
}
#[derive(Clone, Deserialize)]
struct Fixture {
    key: StoredKey,
    challenge_hex: String,
    assertion: Assertion,
    sign_count: u32,
    kid: String,
}
fn fixture() -> Fixture {
    serde_json::from_slice(include_bytes!("../fixtures/browser-assertion.json")).unwrap()
}
fn challenge(f: &Fixture) -> [u8; 32] {
    hex::decode(&f.challenge_hex).unwrap().try_into().unwrap()
}

#[test]
fn actual_browser_subject_assertion_verifies_without_a_host() {
    let f = fixture();
    let checked = verify_assertion(f.key.borrowed(), &challenge(&f), &f.assertion).unwrap();
    assert_eq!(checked.sign_count(), f.sign_count);
    assert_eq!(checked.flags() & (FLAG_UP | FLAG_UV), FLAG_UP | FLAG_UV);
    assert_eq!(kid_for(&f.key.public_key), f.kid);
    assert!(sign_count_ok(0, 0));
    assert!(sign_count_ok(0, 1));
    assert!(!sign_count_ok(1, 0));
    assert!(!sign_count_ok(1, 1));
    assert!(sign_count_ok(1, 2));
}

#[test]
fn wrong_subject_key_rp_origin_credential_signature_and_presence_refuse() {
    let original = fixture();
    for mutation in 0..13 {
        let mut f = original.clone();
        let mut expected = challenge(&f);
        match mutation {
            0 => expected[0] ^= 1,
            1 => f.key.origin = "https://elsewhere.example".into(),
            2 => f.key.rp_id = "elsewhere.example".into(),
            3 => f.key.credential_id = B64.encode([0]),
            4 => f.assertion.signature = "AAAA".into(),
            5 => f.assertion.authenticator_data = B64.encode([0; 36]),
            6 | 7 => {
                let mut bytes = B64.decode(&f.assertion.authenticator_data).unwrap();
                bytes[32] &= if mutation == 6 { !FLAG_UP } else { !FLAG_UV };
                f.assertion.authenticator_data = B64.encode(bytes);
            }
            8 | 9 => {
                let bytes = B64.decode(&f.assertion.client_data_json).unwrap();
                let mut client: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                if mutation == 8 {
                    client["type"] = serde_json::json!("webauthn.create");
                } else {
                    client["crossOrigin"] = serde_json::json!(true);
                }
                f.assertion.client_data_json = B64.encode(serde_json::to_vec(&client).unwrap());
            }
            10 => {
                let mut bytes = B64.decode(&f.assertion.authenticator_data).unwrap();
                bytes[36] ^= 1;
                f.assertion.authenticator_data = B64.encode(bytes);
            }
            11 => f.key.public_key = "not a public key".into(),
            _ => f.assertion.client_data_json = "! invalid base64".into(),
        }
        let refused = verify_assertion(f.key.borrowed(), &expected, &f.assertion).unwrap_err();
        match mutation {
            0 => assert!(matches!(refused, Refusal::ChallengeMismatch)),
            1 => assert!(matches!(refused, Refusal::OriginMismatch(_))),
            2 => assert!(matches!(refused, Refusal::RpIdMismatch)),
            3 => assert!(matches!(refused, Refusal::WrongCredential)),
            4 | 10 => assert!(matches!(refused, Refusal::BadSignature)),
            6 => assert!(matches!(refused, Refusal::UserNotPresent)),
            7 => assert!(matches!(refused, Refusal::UserNotVerified)),
            8 => assert!(matches!(refused, Refusal::ClientDataType(_))),
            9 => assert!(matches!(refused, Refusal::CrossOrigin)),
            _ => assert!(matches!(refused, Refusal::Malformed(_))),
        }
    }
}

#[test]
fn short_and_malformed_untrusted_fields_return_refusals() {
    let f = fixture();
    for length in 0..128 {
        let mut assertion = f.assertion.clone();
        assertion.authenticator_data = B64.encode(vec![0; length]);
        assert!(verify_assertion(f.key.borrowed(), &challenge(&f), &assertion).is_err());
    }
    let mut a = f.assertion.clone();
    a.signature = "x".repeat(MAX_FIELD_BYTES + 1);
    assert!(verify_assertion(f.key.borrowed(), &challenge(&f), &a).is_err());
    for text in ["", "=", "!", "\n", "null", "[]", "{}", "AAAA"] {
        let mut a = f.assertion.clone();
        a.client_data_json = text.into();
        assert!(verify_assertion(f.key.borrowed(), &challenge(&f), &a).is_err());
    }
}

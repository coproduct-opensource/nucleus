//! Verify an exact subject's WebAuthn signature without a controller or account.
//! The caller supplies an independently enrolled key and expected origin/RP.
//! Key-to-human enrollment, role membership and replay storage are not inferred
//! from the assertion. This module grants no application authority.
#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic,
        clippy::unreachable,
        clippy::todo
    )
)]

use base64::Engine as _;
use p256::{
    ecdsa::{DerSignature, VerifyingKey, signature::Verifier as _},
    pkcs8::DecodePublicKey as _,
};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

pub const FLAG_UP: u8 = 0x01;
pub const FLAG_UV: u8 = 0x04;
pub const MAX_FIELD_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    pub credential_id: String,
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_handle: Option<String>,
}
impl Assertion {
    pub fn sha256(&self) -> String {
        let mut h = sha2::Sha256::new();
        for value in [
            &self.credential_id,
            &self.authenticator_data,
            &self.client_data_json,
            &self.signature,
        ] {
            h.update(value.trim().as_bytes());
            h.update(b"\n");
        }
        hex::encode(h.finalize())
    }
}

/// Registry facts supplied by the caller, never obtained from assertion claims.
#[derive(Debug)]
pub struct Key<'a> {
    pub public_key: &'a str,
    pub rp_id: &'a str,
    pub origin: &'a str,
    pub credential_id: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Malformed(String),
    WrongCredential,
    ClientDataType(String),
    ChallengeMismatch,
    OriginMismatch(String),
    CrossOrigin,
    RpIdMismatch,
    UserNotPresent,
    UserNotVerified,
    BadSignature,
}
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "malformed assertion: {why}"),
            Self::WrongCredential => f.write_str("wrong credential"),
            Self::ClientDataType(kind) => write!(f, "wrong client data type: {kind}"),
            Self::ChallengeMismatch => f.write_str("subject challenge mismatch"),
            Self::OriginMismatch(origin) => write!(f, "origin mismatch: {origin}"),
            Self::CrossOrigin => f.write_str("cross-origin assertion refused"),
            Self::RpIdMismatch => f.write_str("relying-party hash mismatch"),
            Self::UserNotPresent => f.write_str("user presence flag missing"),
            Self::UserNotVerified => f.write_str("user verification flag missing"),
            Self::BadSignature => f.write_str("signature does not verify"),
        }
    }
}
impl std::error::Error for Refusal {}

/// Sealed signature evidence. It does not attest who enrolled the key.
#[derive(Debug, PartialEq, Eq)]
pub struct Verified {
    sign_count: u32,
    flags: u8,
}
impl Verified {
    pub fn sign_count(&self) -> u32 {
        self.sign_count
    }
    pub fn flags(&self) -> u8 {
        self.flags
    }
}

pub fn kid_for(pem: &str) -> String {
    hex::encode(sha2::Sha256::digest(pem.trim().as_bytes()))
        .chars()
        .take(16)
        .collect()
}
pub fn sign_count_ok(last: u32, now: u32) -> bool {
    (last == 0 && now == 0) || now > last
}
fn decode(field: &str, value: &str) -> Result<Vec<u8>, Refusal> {
    if value.len() > MAX_FIELD_BYTES {
        return Err(Refusal::Malformed(format!("{field} exceeds byte budget")));
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value.trim())
        .map_err(|e| Refusal::Malformed(format!("{field} is not base64url: {e}")))
}
#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: Option<bool>,
}

pub fn verify_assertion(
    key: Key<'_>,
    challenge: &[u8; 32],
    a: &Assertion,
) -> Result<Verified, Refusal> {
    if [&key.public_key, &key.rp_id, &key.origin]
        .iter()
        .any(|value| value.len() > MAX_FIELD_BYTES)
        || a.user_handle
            .as_ref()
            .is_some_and(|value| value.len() > MAX_FIELD_BYTES)
    {
        return Err(Refusal::Malformed(
            "key or user handle exceeds byte budget".into(),
        ));
    }
    if decode("credential_id", &a.credential_id)?
        != decode("registered credential_id", key.credential_id)?
    {
        return Err(Refusal::WrongCredential);
    }
    let client_data = decode("client_data_json", &a.client_data_json)?;
    let cd: ClientData = serde_json::from_slice(&client_data)
        .map_err(|e| Refusal::Malformed(format!("clientDataJSON: {e}")))?;
    if cd.kind != "webauthn.get" {
        return Err(Refusal::ClientDataType(cd.kind));
    }
    if decode("clientDataJSON.challenge", &cd.challenge)? != challenge.as_slice() {
        return Err(Refusal::ChallengeMismatch);
    }
    if cd.origin != key.origin {
        return Err(Refusal::OriginMismatch(cd.origin));
    }
    if cd.cross_origin == Some(true) {
        return Err(Refusal::CrossOrigin);
    }
    let auth_data = decode("authenticator_data", &a.authenticator_data)?;
    let short = || Refusal::Malformed("authenticatorData is shorter than 37 bytes".into());
    let header = auth_data.get(..37).ok_or_else(short)?;
    let rp_hash: [u8; 32] = sha2::Sha256::digest(key.rp_id.as_bytes()).into();
    if header.get(..32).ok_or_else(short)? != rp_hash {
        return Err(Refusal::RpIdMismatch);
    }
    let flags = *header.get(32).ok_or_else(short)?;
    if flags & FLAG_UP == 0 {
        return Err(Refusal::UserNotPresent);
    }
    if flags & FLAG_UV == 0 {
        return Err(Refusal::UserNotVerified);
    }
    let counter: [u8; 4] = header
        .get(33..37)
        .ok_or_else(short)?
        .try_into()
        .map_err(|_| short())?;
    let sign_count = u32::from_be_bytes(counter);
    let pk = VerifyingKey::from_public_key_pem(key.public_key)
        .map_err(|e| Refusal::Malformed(format!("approver key: {e}")))?;
    let signature = decode("signature", &a.signature)?;
    let signature =
        DerSignature::try_from(signature.as_slice()).map_err(|_| Refusal::BadSignature)?;
    let mut signed = auth_data;
    signed.extend_from_slice(&sha2::Sha256::digest(&client_data));
    pk.verify(&signed, &signature)
        .map_err(|_| Refusal::BadSignature)?;
    Ok(Verified { sign_count, flags })
}

#[cfg(test)]
mod tests;

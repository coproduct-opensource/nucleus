//! Bind the mathematical decision to the exact passkey-signed app change.
//! Host enrollment, roles, storage and claimed application time stay explicit.
use crate::{Packet, canonical_bytes, export::VerifiedContract};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

pub const CANDIDATE_DOMAIN: &[u8] = b"nucleus/studio/change-candidate/v2\n";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    pub workspace: String,
    pub app: String,
    pub source_definition: String,
    pub source_state: String,
    pub source_binding: String,
    pub candidate: String,
    pub agent_key: String,
    pub expires: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialKey {
    pub kid: String,
    pub credential_id: String,
    pub public_key: String,
    pub rp_id: String,
    pub origin: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub signed_by: String,
    pub challenge_id: String,
    pub challenge: String,
    pub assertion: nucleus_passkey_proof::Assertion,
    pub credential: CredentialKey,
    pub sign_count: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub version: u32,
    pub subject: Subject,
    pub subject_sha256: String,
    pub packet: Packet,
    pub blueprint: Value,
    pub approval: Approval,
    pub applied_at: u64,
    pub after_state_sha256: String,
    pub delta_gzip: Vec<u8>,
}

/// Expected first-party values supplied by the verifier, not the certificate.
pub struct Context<'a> {
    pub origin: &'a str,
    pub rp_id: &'a str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Tier {
    IndependentlyRechecked,
    Trusted,
}
#[derive(Debug, Serialize)]
struct Tiers {
    compilation: Tier,
    effects: Tier,
    migration: Tier,
    approval_signature: Tier,
    captured_authority_equality: Tier,
    actual_host_authority: Tier,
    enrollment_and_membership: Tier,
    storage_correspondence: Tier,
    claimed_time: Tier,
}

/// Constructed only after binding, cryptographic verification and independent
/// kernel checking. This result is not an execution or publication right.
#[derive(Debug, Serialize)]
pub struct VerifiedEnvelope {
    subject_sha256: String,
    contract: VerifiedContract,
    signature_kid: String,
    signature_counter: u32,
    tiers: Tiers,
    host_claims: Value,
    exclusions: Vec<&'static str>,
}

pub fn digest_json(value: &Value) -> Result<String, String> {
    Ok(hex::encode(Sha256::digest(canonical_bytes(value)?)))
}
pub fn packet_digest(packet: &Packet) -> Result<String, String> {
    digest_json(&serde_json::to_value(packet).map_err(|e| format!("packet: {e}"))?)
}
pub fn candidate_digest(
    blueprint: &Value,
    compiled: &Value,
    packet: &Packet,
) -> Result<String, String> {
    if !blueprint.as_object().is_some_and(|fields| {
        fields.len() == 2 && fields.contains_key("spec") && fields.contains_key("version")
    }) || compiled != &packet.after
        || blueprint.get("spec") != Some(&packet.new_recipe)
        || blueprint["version"] != json!(1)
    {
        return Err("candidate blueprint/contract differs from packet".into());
    }
    let body = json!({"blueprint":blueprint,"compiled":compiled,"certificate_packet_sha256":packet_digest(packet)?});
    let mut hash = Sha256::new();
    hash.update(CANDIDATE_DOMAIN);
    hash.update(canonical_bytes(&body)?);
    Ok(hex::encode(hash.finalize()))
}
pub fn subject_digest(subject: &Subject) -> Result<String, String> {
    digest_json(&serde_json::to_value(subject).map_err(|e| format!("subject: {e}"))?)
}
fn hash32(text: &str) -> Result<[u8; 32], String> {
    let bytes: [u8; 32] = hex::decode(text)
        .map_err(|e| format!("digest: {e}"))?
        .try_into()
        .map_err(|_| "32-byte digest required")?;
    if hex::encode(bytes) != text {
        return Err("canonical digest required".into());
    }
    Ok(bytes)
}

struct Bound<'a> {
    envelope: &'a Envelope,
    packet: Vec<u8>,
    counter: u32,
}
fn bind<'a>(envelope: &'a Envelope, context: Context<'_>) -> Result<Bound<'a>, String> {
    if envelope.version != 2 {
        return Err("signed envelope version 2 required".into());
    }
    let subject = &envelope.subject;
    let approval = &envelope.approval;
    if subject.workspace.is_empty()
        || subject.app.is_empty()
        || approval.signed_by.is_empty()
        || approval.challenge_id.is_empty()
    {
        return Err("subject/provenance fields required".into());
    }
    for hash in [
        &subject.source_definition,
        &subject.source_state,
        &subject.source_binding,
        &subject.candidate,
        &envelope.subject_sha256,
        &envelope.after_state_sha256,
        &envelope.packet.authority_before,
        &envelope.packet.authority_after,
    ] {
        hash32(hash)?;
    }
    let agent_key = B64
        .decode(&subject.agent_key)
        .map_err(|e| format!("agent key: {e}"))?;
    if agent_key.len() != 32 || B64.encode(&agent_key) != subject.agent_key {
        return Err("canonical agent key thumbprint required".into());
    }
    if envelope
        .blueprint
        .pointer("/spec/slug")
        .and_then(Value::as_str)
        != Some(subject.app.as_str())
    {
        return Err("subject app differs".into());
    }
    if digest_json(&envelope.packet.before)? != subject.source_definition {
        return Err("source contract commitment differs".into());
    }
    if candidate_digest(
        &envelope.blueprint,
        &envelope.packet.after,
        &envelope.packet,
    )? != subject.candidate
    {
        return Err("candidate/packet commitment differs".into());
    }
    if subject_digest(subject)? != envelope.subject_sha256 {
        return Err("subject digest differs".into());
    }
    if envelope.applied_at >= subject.expires {
        return Err("claimed application is outside signed expiry".into());
    }
    if envelope.after_state_sha256 != subject.source_state {
        return Err("identity migration changed retained state digest".into());
    }
    if approval.challenge != B64.encode(hash32(&envelope.subject_sha256)?) {
        return Err("approval challenge differs from exact subject".into());
    }
    if approval.credential.origin != context.origin || approval.credential.rp_id != context.rp_id {
        return Err("approval belongs to another first-party origin/RP".into());
    }
    if approval.credential.kid != nucleus_passkey_proof::kid_for(&approval.credential.public_key) {
        return Err("signature key ID differs".into());
    }
    let signature = nucleus_passkey_proof::verify_assertion(
        nucleus_passkey_proof::Key {
            public_key: &approval.credential.public_key,
            rp_id: context.rp_id,
            origin: context.origin,
            credential_id: &approval.credential.credential_id,
        },
        &hash32(&envelope.subject_sha256)?,
        &approval.assertion,
    )
    .map_err(|e| format!("subject signature: {e}"))?;
    if signature.sign_count() != approval.sign_count {
        return Err("signed counter metadata differs".into());
    }
    let packet = crate::canonical_packet(
        &serde_json::to_vec(&envelope.packet).map_err(|e| format!("packet: {e}"))?,
    )?
    .into_bytes();
    Ok(Bound {
        envelope,
        packet,
        counter: signature.sign_count(),
    })
}

pub fn verify(
    base_gzip: &[u8],
    envelope: &Envelope,
    context: Context<'_>,
) -> Result<VerifiedEnvelope, String> {
    let bound = bind(envelope, context)?;
    let contract = crate::verify_compressed(base_gzip, &envelope.delta_gzip, &bound.packet)?;
    Ok(VerifiedEnvelope {
        subject_sha256: envelope.subject_sha256.clone(),
        contract,
        signature_kid: envelope.approval.credential.kid.clone(),
        signature_counter: bound.counter,
        tiers: Tiers {
            compilation: Tier::IndependentlyRechecked,
            effects: Tier::IndependentlyRechecked,
            migration: Tier::IndependentlyRechecked,
            approval_signature: Tier::IndependentlyRechecked,
            captured_authority_equality: Tier::IndependentlyRechecked,
            actual_host_authority: Tier::Trusted,
            enrollment_and_membership: Tier::Trusted,
            storage_correspondence: Tier::Trusted,
            claimed_time: Tier::Trusted,
        },
        host_claims: json!({"signer":bound.envelope.approval.signed_by,
            "challenge_id":bound.envelope.approval.challenge_id,"applied_at":bound.envelope.applied_at,
            "source_binding":bound.envelope.subject.source_binding,"state":bound.envelope.subject.source_state}),
        exclusions: vec![
            "host enrollment, membership and authority capture",
            "serving implementation and storage correspondence",
            "claimed wall time",
            "wire codecs and cryptographic primitive implementations",
            "whether the visible definition is human intent",
        ],
    })
}

/// Bounded public wire entry point. Proof checking must run in a disposable
/// worker/process with a deadline: malformed kernel terms can trap.
pub fn verify_bytes(
    base_gzip: &[u8],
    bytes: &[u8],
    context: Context<'_>,
) -> Result<VerifiedEnvelope, String> {
    if bytes.len() > crate::MAX_PACKET_BYTES {
        return Err("signed envelope exceeds 16 MiB".into());
    }
    let envelope: Envelope =
        serde_json::from_slice(bytes).map_err(|e| format!("signed envelope: {e}"))?;
    verify(base_gzip, &envelope, context)
}

/// Check the exact-subject binding before spending work on proof production.
/// This is not a contract verdict and grants no right to install a change.
pub fn check_binding(envelope: &Envelope, context: Context<'_>) -> Result<(), String> {
    bind(envelope, context).map(|_| ())
}

#[cfg(test)]
mod tests;

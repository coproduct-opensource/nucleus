//! Mint one federation assertion on a real TPM the way a node does, and show
//! what it states about the platform (ADR 0012 addendum A3).
//!
//! ```text
//! attested_assertion <tpm device> <state dir> <reference.json> <anchor source> <ak pin> tpm|file
//! ```
//!
//! In `<state dir>` it keeps the issuer key (`tpm`: created in the TPM, bound
//! to the boot PCRs; `file`: a PKCS#8 file, the waived custody) and the epoch
//! counter. Each run, as a node's epoch and mint would:
//!
//! 1. quotes the boot with the AK of the cloud template at NV `0x01c10003`,
//!    bound to a fixed test executor key and the SHA-256 of the issuer's JWKS,
//!    and stores the evidence document by its digest;
//! 2. appraises that document with `NodeAttestation::of_current_evidence`,
//!    the node's own path, against `<reference.json>` and the operator pin;
//! 3. mints an assertion carrying the claims with the issuer key;
//! 4. evaluates the relying party's CEL condition on the payload, and runs the
//!    relying party's verifier with re-appraisal of the named document.
//!
//! It prints one JSON object. A key the TPM refuses to use prints the refusal
//! and mints nothing.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use base64::Engine as _;
use nucleus_federation::keyring::{KeyDir, KeyDirSigner};
use nucleus_federation::{
    AssertionClaims, AssertionSubject, CurrentSigner, DEFAULT_TTL, FileCustody, HeldEvidence,
    KeyCustody, NodeAttestation, RELYING_PARTY_CONDITION, Reappraisal, RelyingPartyCheck,
    SelfAppraisal, TpmCustody, TpmEndpoint, mint, verify_attestation_claims,
};
use nucleus_node_evidence::attester::{
    AkTemplate, Attester, DeviceTransport, LogSources, Tpm, default_pcrs,
};
use nucleus_node_evidence::tpm::AkPublic;
use nucleus_node_evidence::{
    AkAnchorClaim, AnchorPolicy, ExecutorKey, Federation, Freshness, KeyBinding, OperatorPin,
    ReferenceManifest, evidence_digest,
};
use serde_json::{Value, json};

type Error = Box<dyn std::error::Error>;

/// JSON as a CEL-evaluating provider sees it: numbers are doubles.
fn cel_value(v: &Value) -> cel_interpreter::Value {
    use cel_interpreter::Value as C;
    match v {
        Value::Null => C::Null,
        Value::Bool(b) => C::Bool(*b),
        Value::Number(n) => C::Float(n.as_f64().unwrap_or(f64::NAN)),
        Value::String(s) => C::String(s.clone().into()),
        Value::Array(a) => C::List(a.iter().map(cel_value).collect::<Vec<_>>().into()),
        Value::Object(o) => {
            let m: HashMap<String, C> = o.iter().map(|(k, v)| (k.clone(), cel_value(v))).collect();
            m.into()
        }
    }
}

fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().collect();
    let [_, device, state, reference, source, pin, custody] = args.as_slice() else {
        return Err(
            "usage: attested_assertion <tpm device> <state dir> <reference.json> \
                    <anchor source> <ak pin> tpm|file"
                .into(),
        );
    };
    let device = PathBuf::from(device);
    let state = PathBuf::from(state);
    std::fs::create_dir_all(&state)?;
    let custody = match custody.as_str() {
        "tpm" => KeyCustody::Tpm(TpmCustody::new(TpmEndpoint::Device(device.clone()))),
        "file" => KeyCustody::File(FileCustody::Waived),
        other => return Err(format!("custody {other:?}: tpm or file").into()),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    // The issuer key, created once per state directory.
    let keys = KeyDir::new(&state);
    if keys.state(now).is_err() {
        keys.create_current(&custody)?;
    }
    let jwks = serde_json::to_vec(&keys.state(now)?.jwks())?;
    let binding = KeyBinding {
        executor_key: ExecutorKey::Ed25519([0x5e; 32]),
        federation: Federation::JwksSha256(evidence_digest(&jwks)),
    };

    // 1. The epoch quote, as the node takes it.
    let counter_file = state.join("epoch");
    let counter = std::fs::read_to_string(&counter_file)
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
        .saturating_add(1);
    let mut attester = Attester::new(
        Tpm::new(DeviceTransport::open(&device)?),
        AkTemplate::NvIndex(0x01c1_0003),
        default_pcrs(),
        LogSources::linux(),
        AkAnchorClaim::OperatorFetched {
            source: source.clone(),
        },
    );
    let ak_spki_sha256 =
        hex::encode(AkPublic::from_tpm2b_public(&attester.ak_public()?)?.spki_sha256());
    let evidence = attester.attest(
        &binding,
        Freshness::Epoch {
            counter,
            iat: i64::try_from(now)?,
        },
    )?;
    let document = serde_json::to_vec_pretty(&evidence)?;
    let digest = hex::encode(evidence_digest(&document));
    std::fs::write(state.join(format!("{digest}.json")), &document)?;
    std::fs::write(&counter_file, counter.to_string())?;

    // 2. The node's own appraisal of it, at the mint time.
    let reference: ReferenceManifest = serde_json::from_slice(&std::fs::read(reference)?)?;
    let anchors = AnchorPolicy {
        software_tpm_pins: Vec::new(),
        trust_roots: vec![],
        operator_pins: vec![OperatorPin {
            source: source.clone(),
            ak_spki_sha256: pin.to_ascii_lowercase(),
        }],
    };
    let attestation = NodeAttestation::of_current_evidence(
        &document,
        Some(&SelfAppraisal {
            binding: &binding,
            reference: &reference,
            anchors: &anchors,
            max_age_secs: SelfAppraisal::max_age_for_epoch(300),
        }),
        i64::try_from(now)?,
    );

    // 3. The assertion.
    let claims = AssertionClaims::new(
        &AssertionSubject::new(
            "spiffe://nodes.example.invalid/ns/pods/sa/pod-a",
            "tenant-a.example.invalid",
            "spiffe://tenant-a.example.invalid/ns/ci/sa/release",
            "ab".repeat(32),
        )?,
        "https://federation.nodes.example.invalid",
        "https://sts.example.invalid/provider",
        "model-api",
        now,
        DEFAULT_TTL,
        &attestation,
    )?;
    let signer = Arc::new(KeyDirSigner::open(keys, custody.clone())?).current()?;
    let base = json!({
        "custody": custody.kind().to_string(),
        "epoch": counter,
        "evidence_sha256": digest,
        "ak_spki_sha256": ak_spki_sha256,
        "self_appraisal": attestation.note(),
    });
    let jwt = match mint(&claims, signer.as_ref()) {
        Ok(jwt) => jwt,
        Err(e) => {
            let mut out = base;
            out["mint"] = json!(format!("REFUSED: {e}"));
            println!("{}", serde_json::to_string_pretty(&out)?);
            return Ok(());
        }
    };
    let payload: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(jwt.expose().split('.').nth(1).ok_or("not a JWS")?)?,
    )?;
    let payload = payload.as_object().ok_or("payload")?.clone();

    // 4. What a relying party does with it.
    let program = cel_interpreter::Program::compile(RELYING_PARTY_CONDITION)?;
    let mut ctx = cel_interpreter::Context::default();
    ctx.add_variable_from_value("assertion", cel_value(&Value::Object(payload.clone())));
    let admitted = matches!(
        program.execute(&ctx),
        Ok(cel_interpreter::Value::Bool(true))
    );
    let verified = verify_attestation_claims(
        &payload,
        &RelyingPartyCheck {
            now: i64::try_from(now)?,
            max_age_secs: 900,
            reappraisal: Reappraisal::Evidence(HeldEvidence {
                document: &document,
                binding: &binding,
                reference: &reference,
                anchors: &anchors,
            }),
        },
    );
    let mut out = base;
    out["mint"] = json!("signed");
    out["kid"] = json!(signer.kid());
    out["claims"] = json!({
        "nucleus_att_tier": payload.get("nucleus_att_tier"),
        "nucleus_att_epoch": payload.get("nucleus_att_epoch"),
        "nucleus_att_time": payload.get("nucleus_att_time"),
        "nucleus_evidence_digest": payload.get("nucleus_evidence_digest"),
        "iat": payload.get("iat"),
        "exp": payload.get("exp"),
    });
    out["relying_party_condition_admits"] = json!(admitted);
    out["relying_party_verifier"] = match verified {
        Ok(v) => json!({ "ok": v.tier.as_str(), "reappraised": v.reappraised.map(|t| t.as_str()) }),
        Err(e) => json!({ "refused": e.to_string() }),
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

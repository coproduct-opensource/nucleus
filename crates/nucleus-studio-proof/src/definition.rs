//! Definition-only evidence, distinct from an approved change or Keep consent.
//! Expected hashes come from the recipient's reviewed subject, never this file.
use crate::{Packet, envelope::digest_json, export::VerifiedContract};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const PURPOSE: &str = "studio-app-definition-v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub purpose: String,
    pub blueprint: Value,
    pub packet: Packet,
    pub delta_gzip: Vec<u8>,
}

/// Supply these from the selected app in the independently reviewed Keep
/// subject. Matching a certificate's own hashes would establish no such link.
#[derive(Clone, Copy)]
pub struct Expected<'a> {
    pub blueprint_sha256: &'a str,
    pub contract_sha256: &'a str,
}

#[derive(Debug, Serialize)]
pub struct VerifiedDefinition {
    purpose: &'static str,
    blueprint_sha256: String,
    contract_sha256: String,
    contract: VerifiedContract,
    tiers: Value,
    exclusions: Vec<&'static str>,
}

pub fn check_binding(c: &Certificate, expected: Expected<'_>) -> Result<(), String> {
    if c.purpose != PURPOSE {
        return Err("definition-only certificate purpose required".into());
    }
    // Use an identity packet solely to instantiate the existing independent
    // compiler theorem. It is not evidence for an earlier edit or transfer.
    if c.packet.old_recipe != c.packet.new_recipe
        || c.packet.before != c.packet.after
        || c.packet.authority_before != c.packet.authority_after
    {
        return Err("definition-only certificate requires an identity packet".into());
    }
    crate::envelope::candidate_digest(&c.blueprint, &c.packet.after, &c.packet)?;
    if digest_json(&c.blueprint)? != expected.blueprint_sha256
        || digest_json(&c.packet.after)? != expected.contract_sha256
    {
        return Err("definition certificate differs from reviewed commitments".into());
    }
    Ok(())
}

pub fn verify_bytes(
    base: &[u8],
    bytes: &[u8],
    expected: Expected<'_>,
) -> Result<VerifiedDefinition, String> {
    if bytes.len() > crate::MAX_PACKET_BYTES {
        return Err("definition certificate byte budget".into());
    }
    let c: Certificate =
        serde_json::from_slice(bytes).map_err(|e| format!("definition certificate: {e}"))?;
    check_binding(&c, expected)?;
    let packet = serde_json::to_vec(&c.packet).map_err(|e| format!("packet: {e}"))?;
    let contract = crate::verify_compressed(base, &c.delta_gzip, &packet)?;
    Ok(VerifiedDefinition {
        purpose: PURPOSE,
        blueprint_sha256: digest_json(&c.blueprint)?,
        contract_sha256: digest_json(&c.packet.after)?,
        contract,
        tiers: json!({"compilation":"independently-rechecked",
            "reviewed_subject_correspondence":"caller-supplied",
            "live_storage_correspondence":"trusted"}),
        exclusions: vec![
            "approval and ownership transfer",
            "prior edits and migrations",
            "live records and authority",
            "host and storage",
            "human intent",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    #[test]
    fn definition_only_evidence_binds_reviewed_app_and_rechecks_the_actual_kernel() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let mut packet: Packet =
                    serde_json::from_slice(include_bytes!("../fixtures/equipment.packet.json"))
                        .unwrap();
                packet.new_recipe = packet.old_recipe.clone();
                packet.after = packet.before.clone();
                packet.authority_after = packet.authority_before.clone();
                let mut c = Certificate {
                    purpose: PURPOSE.into(),
                    blueprint: json!({"version":1,"spec":packet.new_recipe}),
                    packet,
                    delta_gzip: vec![],
                };
                let blueprint = digest_json(&c.blueprint).unwrap();
                let contract = digest_json(&c.packet.after).unwrap();
                let expected = Expected {
                    blueprint_sha256: &blueprint,
                    contract_sha256: &contract,
                };
                check_binding(&c, expected).unwrap();
                let base_gzip = include_bytes!("../fixtures/base.ndjson.gz");
                let mut base = vec![];
                flate2::read::GzDecoder::new(base_gzip.as_slice())
                    .read_to_end(&mut base)
                    .unwrap();
                let wire = serde_json::to_vec(&c.packet).unwrap();
                let delta = crate::producer::propose_delta(&base, &wire).unwrap();
                let mut gzip =
                    flate2::write::GzEncoder::new(vec![], flate2::Compression::default());
                gzip.write_all(&delta).unwrap();
                c.delta_gzip = gzip.finish().unwrap();
                let report =
                    verify_bytes(base_gzip, &serde_json::to_vec(&c).unwrap(), expected).unwrap();
                let report = serde_json::to_value(report).unwrap();
                assert_eq!(report["tiers"]["compilation"], "independently-rechecked");
                assert!(report.get("approval_signature").is_none());
                assert!(
                    check_binding(
                        &c,
                        Expected {
                            blueprint_sha256: &contract,
                            contract_sha256: &contract
                        }
                    )
                    .is_err()
                );
                assert!(
                    check_binding(
                        &c,
                        Expected {
                            blueprint_sha256: &blueprint,
                            contract_sha256: &blueprint
                        }
                    )
                    .is_err()
                );
                let mut swapped = c.clone();
                swapped.purpose = "studio-approved-change-v2".into();
                assert!(check_binding(&swapped, expected).is_err());
                let mut edited = c.clone();
                edited.packet.old_recipe["title"] = json!("Earlier app");
                assert!(check_binding(&edited, expected).is_err());
                let mut missing = c;
                missing.delta_gzip.clear();
                assert!(
                    verify_bytes(base_gzip, &serde_json::to_vec(&missing).unwrap(), expected)
                        .is_err()
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }
}

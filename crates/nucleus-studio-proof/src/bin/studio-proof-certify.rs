//! Untrusted producer plus independent checker, isolated from the app server.
//! No authority, network, storage or installation effect. The caller must pin
//! this executable and enforce a deadline before consuming its bounded output.
use nucleus_studio_proof::{
    MAX_PACKET_BYTES,
    envelope::{self, Context, Envelope},
};
use std::io::{Read as _, Write as _};
const BASE: &[u8] = include_bytes!("../../fixtures/base.ndjson.gz");

fn run() -> Result<Vec<u8>, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !(matches!(args.as_slice(), [_, _]) || args.len() == 3 && args[0] == "--definition") {
        return Err(
            "expected ORIGIN RP_ID or --definition BLUEPRINT_SHA256 CONTRACT_SHA256".into(),
        );
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_PACKET_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("input: {e}"))?;
    if bytes.len() > MAX_PACKET_BYTES {
        return Err("input exceeds 16 MiB".into());
    }
    let output = if args[0] == "--definition" {
        if args.len() != 3 {
            return Err("definition commitments required".into());
        }
        definition(&bytes, &args[1], &args[2])?
    } else {
        approved_change(&bytes, &args[0], &args[1])?
    };
    if output.len() > MAX_PACKET_BYTES {
        return Err("output exceeds 16 MiB".into());
    }
    Ok(output)
}

fn definition(bytes: &[u8], blueprint: &str, contract: &str) -> Result<Vec<u8>, String> {
    use nucleus_studio_proof::definition::{self, Certificate, Expected};
    let mut certificate: Certificate =
        serde_json::from_slice(bytes).map_err(|e| format!("definition certificate: {e}"))?;
    if !certificate.delta_gzip.is_empty() {
        return Err("producer input must not contain a proof".into());
    }
    let expected = Expected {
        blueprint_sha256: blueprint,
        contract_sha256: contract,
    };
    definition::check_binding(&certificate, expected)?;
    certificate.delta_gzip = produce_proof(&certificate.packet)?;
    let wire = serde_json::to_vec(&certificate).map_err(|e| format!("certificate: {e}"))?;
    let checked = definition::verify_bytes(BASE, &wire, expected)?;
    serde_json::to_vec(&serde_json::json!({"certificate":certificate,"checked":checked}))
        .map_err(|e| format!("output: {e}"))
}

fn approved_change(bytes: &[u8], origin: &str, rp_id: &str) -> Result<Vec<u8>, String> {
    let mut envelope: Envelope =
        serde_json::from_slice(bytes).map_err(|e| format!("envelope: {e}"))?;
    if !envelope.delta_gzip.is_empty() {
        return Err("producer input must not contain a proof".into());
    }
    envelope::check_binding(&envelope, Context { origin, rp_id })?;
    envelope.delta_gzip = produce_proof(&envelope.packet)?;
    let wire = serde_json::to_vec(&envelope).map_err(|e| format!("envelope: {e}"))?;
    let checked = envelope::verify_bytes(BASE, &wire, Context { origin, rp_id })?;
    serde_json::to_vec(&serde_json::json!({"envelope":envelope,"checked":checked}))
        .map_err(|e| format!("output: {e}"))
}

fn produce_proof(packet: &nucleus_studio_proof::Packet) -> Result<Vec<u8>, String> {
    let mut base = Vec::new();
    flate2::read::GzDecoder::new(BASE)
        .take((nucleus_studio_proof::export::MAX_BASE_BYTES + 1) as u64)
        .read_to_end(&mut base)
        .map_err(|e| format!("semantic base: {e}"))?;
    if base.len() > nucleus_studio_proof::export::MAX_BASE_BYTES {
        return Err("semantic base exceeds budget".into());
    }
    let packet = serde_json::to_vec(packet).map_err(|e| format!("packet: {e}"))?;
    let delta = nucleus_studio_proof::producer::propose_delta(&base, &packet)?;
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&delta)
        .map_err(|e| format!("proof compression: {e}"))?;
    gzip.finish().map_err(|e| format!("proof compression: {e}"))
}
fn main() {
    match run() {
        Ok(bytes) => {
            if let Err(error) = std::io::stdout().write_all(&bytes) {
                eprintln!("certificate output: {error}");
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("certificate refused: {error}");
            std::process::exit(1);
        }
    }
}

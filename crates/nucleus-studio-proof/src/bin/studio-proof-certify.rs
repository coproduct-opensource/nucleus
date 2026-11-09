//! Untrusted producer plus independent checker, isolated from the app server.
//! No authority, network, storage or installation effect. The caller must pin
//! this executable and enforce a deadline before consuming its bounded output.
use nucleus_studio_proof::{
    MAX_PACKET_BYTES,
    envelope::{self, Context, Envelope},
};
use std::io::{Read as _, Write as _};

fn run() -> Result<Vec<u8>, String> {
    let mut args = std::env::args().skip(1);
    let origin = args.next().ok_or("expected origin required")?;
    let rp_id = args.next().ok_or("expected relying-party ID required")?;
    if args.next().is_some() {
        return Err("unexpected argument".into());
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take((MAX_PACKET_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("input: {e}"))?;
    if bytes.len() > MAX_PACKET_BYTES {
        return Err("input exceeds 16 MiB".into());
    }
    let mut envelope: Envelope =
        serde_json::from_slice(&bytes).map_err(|e| format!("envelope: {e}"))?;
    if !envelope.delta_gzip.is_empty() {
        return Err("producer input must not contain a proof".into());
    }
    envelope::check_binding(
        &envelope,
        Context {
            origin: &origin,
            rp_id: &rp_id,
        },
    )?;
    let base_gzip = include_bytes!("../../fixtures/base.ndjson.gz");
    let mut base = Vec::new();
    flate2::read::GzDecoder::new(base_gzip.as_slice())
        .take((nucleus_studio_proof::export::MAX_BASE_BYTES + 1) as u64)
        .read_to_end(&mut base)
        .map_err(|e| format!("semantic base: {e}"))?;
    if base.len() > nucleus_studio_proof::export::MAX_BASE_BYTES {
        return Err("semantic base exceeds budget".into());
    }
    let packet = serde_json::to_vec(&envelope.packet).map_err(|e| format!("packet: {e}"))?;
    let delta = nucleus_studio_proof::producer::propose_delta(&base, &packet)?;
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&delta)
        .map_err(|e| format!("proof compression: {e}"))?;
    envelope.delta_gzip = gzip
        .finish()
        .map_err(|e| format!("proof compression: {e}"))?;
    let wire = serde_json::to_vec(&envelope).map_err(|e| format!("envelope: {e}"))?;
    let checked = envelope::verify_bytes(
        base_gzip,
        &wire,
        Context {
            origin: &origin,
            rp_id: &rp_id,
        },
    )?;
    let output = serde_json::to_vec(&serde_json::json!({"envelope":envelope,"checked":checked}))
        .map_err(|e| format!("output: {e}"))?;
    if output.len() > MAX_PACKET_BYTES {
        return Err("output exceeds 16 MiB".into());
    }
    Ok(output)
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

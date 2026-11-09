//! Offline native front end; the browser will call the same pure checker.
use std::{fs, io::Read as _};
fn bounded(path: &std::ffi::OsStr, limit: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = vec![];
    fs::File::open(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("input byte budget".into());
    }
    Ok(bytes)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 {
        return Err("usage: studio-proof-check BASE_NDJSON PROOF_NDJSON PACKET_JSON".into());
    }
    let base = bounded(&args[0], nucleus_studio_proof::export::MAX_BASE_BYTES)?;
    let proof = bounded(&args[1], nucleus_studio_proof::export::MAX_PROOF_BYTES)?;
    let packet = bounded(&args[2], nucleus_studio_proof::MAX_PACKET_BYTES)?;
    let checked = nucleus_studio_proof::export::verify(&base, &proof, &packet)?;
    println!("{}", serde_json::to_string(&checked)?);
    Ok(())
}

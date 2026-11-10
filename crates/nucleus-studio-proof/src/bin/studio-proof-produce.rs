//! Construct and independently verify a closed decision before writing its
//! compressed per-app proof. No per-app Lean compiler or network is required.
use std::{
    fs,
    io::{Read as _, Write as _},
};
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
        return Err("usage: studio-proof-produce BASE_NDJSON PACKET_JSON NEW_DELTA_GZIP".into());
    }
    let base = bounded(&args[0], nucleus_studio_proof::export::MAX_BASE_BYTES)?;
    let packet = bounded(&args[1], nucleus_studio_proof::MAX_PACKET_BYTES)?;
    let delta = nucleus_studio_proof::producer::propose_delta(&base, &packet)?;
    let mut proof = base.clone();
    proof.extend_from_slice(&delta);
    let checked = nucleus_studio_proof::export::verify(&base, &proof, &packet)?;
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[2])?;
    let mut gzip = flate2::GzBuilder::new()
        .mtime(0)
        .write(file, flate2::Compression::best());
    gzip.write_all(&delta)?;
    gzip.finish()?;
    println!("{}", serde_json::to_string(&checked)?);
    Ok(())
}

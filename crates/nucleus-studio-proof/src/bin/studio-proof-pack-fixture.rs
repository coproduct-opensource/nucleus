//! Preserve a checked semantic base and only the per-app suffix as bounded
//! deterministic fixtures. No certificate verification is implied by packing.
use std::{
    fs,
    io::{Read as _, Write as _},
    path::Path,
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
fn compressed(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    let mut gzip = flate2::GzBuilder::new()
        .mtime(0)
        .write(file, flate2::Compression::best());
    gzip.write_all(bytes)?;
    gzip.finish()?;
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 4 {
        return Err("usage: studio-proof-pack-fixture BASE PROOF PACKET OUTPUT_DIR".into());
    }
    let base = bounded(&args[0], nucleus_studio_proof::export::MAX_BASE_BYTES)?;
    let proof = bounded(&args[1], nucleus_studio_proof::export::MAX_PROOF_BYTES)?;
    let packet = bounded(&args[2], nucleus_studio_proof::MAX_PACKET_BYTES)?;
    if !proof.starts_with(&base) {
        return Err("proof does not extend base".into());
    }
    fs::create_dir_all(&args[3])?;
    let out = Path::new(&args[3]);
    compressed(&out.join("base.ndjson.gz"), &base)?;
    compressed(&out.join("equipment.delta.ndjson.gz"), &proof[base.len()..])?;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out.join("equipment.packet.json"))?
        .write_all(&packet)?;
    Ok(())
}

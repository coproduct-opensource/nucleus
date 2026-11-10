//! Produce untrusted closed Lean input for the independent certificate checker.
use std::{fs, io::Read as _};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: studio-proof-witness PACKET_JSON WITNESS_LEAN".into());
    }
    let mut input = Vec::new();
    fs::File::open(&args[0])?
        .take((nucleus_studio_proof::MAX_PACKET_BYTES + 1) as u64)
        .read_to_end(&mut input)?;
    let source = nucleus_studio_proof::witness_source(&input)?;
    fs::write(&args[1], source)?;
    Ok(())
}

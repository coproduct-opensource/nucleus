//! Reading the existing key a host signs its probe with. Never created or rotated here.
use std::io::Read as _;
use std::path::Path;

use ed25519_dalek::{SigningKey, pkcs8::DecodePrivateKey as _};
use zeroize::Zeroizing;

pub(super) fn read(path: &Path) -> Result<SigningKey, String> {
    let file =
        std::fs::File::open(path).map_err(|error| format!("opening the signing key: {error}"))?;
    let mut der = Zeroizing::new(Vec::new());
    file.take(4097)
        .read_to_end(&mut der)
        .map_err(|error| format!("reading the signing key: {error}"))?;
    if der.len() > 4096 {
        return Err("Ed25519 PKCS#8 key exceeds 4096 bytes".into());
    }
    SigningKey::from_pkcs8_der(&der)
        .map_err(|error| format!("decoding the Ed25519 PKCS#8 signing key: {error}"))
}

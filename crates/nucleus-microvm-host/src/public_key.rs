//! Read-only enrollment from the host's existing key, without exporting or
//! retaining its signing material. No load-or-create path is reachable here.
use std::io::Read as _;
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey, pkcs8::DecodePrivateKey as _};
use zeroize::Zeroizing;

pub(super) fn read(path: &Path) -> Result<VerifyingKey, String> {
    // A persisted Ed25519 key is small. Bound this operator-supplied input and
    // scrub the raw DER on every return, including incomplete reads.
    let file =
        std::fs::File::open(path).map_err(|error| format!("opening the existing key: {error}"))?;
    let mut der = Zeroizing::new(Vec::new());
    file.take(4097)
        .read_to_end(&mut der)
        .map_err(|error| format!("reading the existing key: {error}"))?;
    if der.len() > 4096 {
        return Err("Ed25519 PKCS#8 key exceeds 4096 bytes".into());
    }
    let key = SigningKey::from_pkcs8_der(&der)
        .map_err(|error| format!("decoding the existing Ed25519 PKCS#8 key: {error}"))?;
    Ok(key.verifying_key())
}

// Fuzz JWK JSON deserialization + `public_key()` extraction. The OP
// trust-bundle path parses JWKS docs from arbitrary upstream IdPs; a
// malformed JWK that crashes the parser amounts to a denial-of-trust
// on every workload in the trust domain.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nucleus_oidc_core::Jwk;

fuzz_target!(|data: &[u8]| {
    if let Ok(jwk) = serde_json::from_slice::<Jwk>(data) {
        let _ = jwk.public_key();
    }
});

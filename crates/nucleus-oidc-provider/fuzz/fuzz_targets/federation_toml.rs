// Fuzz the federation-rules TOML parser. The OP reads this file on
// startup + SIGHUP; a panic in `toml::from_str` is a deploy-time DoS.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nucleus_oidc_provider::federation::FederationRules;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = FederationRules::parse_toml(s);
    }
});

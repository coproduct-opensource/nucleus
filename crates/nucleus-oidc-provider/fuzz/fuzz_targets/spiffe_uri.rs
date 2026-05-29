// Fuzz SPIFFE / WIMSE URI parsing. The OP parses the `sub` claim of
// every subject_token as a CallSpiffeId; a parser panic is reachable
// from any external caller that hits /oauth/token.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nucleus_lineage::CallSpiffeId;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Both entry points exercised in case wimse:// normalization
        // changes the failure mode.
        let _ = CallSpiffeId::parse(s.to_string());
        let _ = CallSpiffeId::from_wimse_uri(s);
    }
});

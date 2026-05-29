// Fuzz the `application/x-www-form-urlencoded` token-exchange request
// parser. Exercises the same `serde_urlencoded` path the live `/oauth/token`
// endpoint uses, so any panic / OOM / infinite-loop in form parsing is
// directly exploitable as a DoS.
//
// Acceptance per task #51 (a): one fuzz target per parsing boundary.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nucleus_oidc_provider::token::TokenExchangeRequest;

fuzz_target!(|data: &[u8]| {
    // We only care that the parser never panics. Result is dropped.
    let _: Result<TokenExchangeRequest, _> = serde_urlencoded::from_bytes(data);
});

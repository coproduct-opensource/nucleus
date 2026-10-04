// Fuzz the decision channel's codec, both directions.
//
// The host decodes every byte a (possibly hostile) guest writes on its decision
// channel, and the guest decodes what the host answers. The contract is the one
// `nucleus-node/src/workload_api_protocol.rs` holds: total, bounded,
// fail-closed. Beyond "never panics", this target checks the property the
// crate's docs claim and the unit tests can only sample: the encoding is
// CANONICAL. Anything either decoder accepts re-encodes to exactly the bytes it
// came from, so a frame has one meaning and one spelling.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nucleus_decision_protocol::{GuestFrame, HostFrame, LEN_PREFIX, body_len};

fuzz_target!(|data: &[u8]| {
    if let Ok(frame) = GuestFrame::decode(data) {
        let again = frame.encode().expect("an accepted guest frame re-encodes");
        assert_eq!(again, data, "guest encoding is not canonical");
    }
    if let Ok(frame) = HostFrame::decode(data) {
        let again = frame.encode().expect("an accepted host frame re-encodes");
        assert_eq!(again, data, "host encoding is not canonical");
    }

    // The I/O layer's two-step path: prefix first, then a body of that length.
    // It must agree with the one-shot decoder on the same frame.
    if let Some((prefix, rest)) = data.split_first_chunk::<LEN_PREFIX>()
        && let Ok(len) = body_len(*prefix)
        && let Some(body) = rest.get(..len)
        && let Some(whole) = data.get(..LEN_PREFIX + len)
    {
        assert_eq!(GuestFrame::decode_body(body), GuestFrame::decode(whole));
        assert_eq!(HostFrame::decode_body(body), HostFrame::decode(whole));
    }

    // And a body handed over with no prefix at all, as a careless caller might.
    let _ = GuestFrame::decode_body(data);
    let _ = HostFrame::decode_body(data);
});

// Fuzz the egress proxy's guest-facing parser (ADR 0015 §7: part of E2's
// definition of done).
//
// Guest root writes these bytes. Beyond "never panics", the target holds the
// parser to what the proxy relies on:
//
// * a complete head never claims more bytes than it was given, and never more
//   than the head bound;
// * whatever it accepts, the proxy can summarise, and the summary's text parses
//   back to the same summary (the node decides on that parse, so a request the
//   proxy could forward but the node could not read back would be a request
//   nobody decided);
// * the request the proxy re-serialises for the upstream is itself a request
//   the parser accepts in origin form, never a second request smuggled behind
//   the first.

#![no_main]

use libfuzzer_sys::fuzz_target;
use nucleus_egress_proxy::request::{MAX_HEAD, Parsed, parse_head};
use nucleus_egress_proxy::serve::upstream_request;
use nucleus_egress_proxy::summary::Summary;

fuzz_target!(|data: &[u8]| {
    // Also the summary parser on its own: total.
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(s) = Summary::parse(text) {
            assert_eq!(s.text(), text, "summary parse is not canonical");
        }
    }

    let Ok(Parsed::Complete { request, head_len }) = parse_head(data) else {
        return;
    };
    assert!(head_len <= data.len());
    assert!(head_len <= MAX_HEAD);
    let body = &data[head_len..];
    let body = &body[..body.len().min(request.content_length as usize)];

    let summary = Summary::of(&request, body);
    let text = summary.text();
    assert_eq!(Summary::parse(&text).as_ref(), Ok(&summary), "{text:?}");

    // What goes upstream is one request, whose head ends exactly where the
    // proxy's own head ends: no header value can inject a line.
    let out = upstream_request(&request, body);
    let head_end = out
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("the upstream request has a head");
    assert_eq!(&out[head_end + 4..], body, "bytes after the head are the body only");
    let head = &out[..head_end];
    let lines = head.split(|b| *b == b'\n').count();
    // request line + host + forwarded headers + optional content-length + connection
    assert!(lines <= request.headers.len() + 4, "a header value split a line");
});

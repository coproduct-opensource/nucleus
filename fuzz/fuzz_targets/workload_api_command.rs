// Fuzz the host-side Workload API vsock command parser.
//
// This parser is the trusted edge of the guest->host AF_VSOCK channel: every
// byte string a (possibly compromised) guest sends is interpreted here on the
// host. A panic, unbounded loop, or OOM in this function is reachable from
// inside any sandboxed pod, so the contract is total + bounded + fail-closed.
//
// We pull the parser module in directly via `#[path]` because `nucleus-node` is
// a binary crate (no lib target) and the module is deliberately std-only, so it
// compiles standalone without dragging tokio/firecracker/etc. into the fuzz
// build. The exact same source is exercised by the in-tree `proptest` suite and
// by the runtime in `workload_api_vsock::read_command_frame` -> `parse_command`.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

#[path = "../../crates/nucleus-node/src/workload_api_protocol.rs"]
mod proto;

use proto::{parse_command, CommandParseError, MAX_COMMAND_LEN};

/// Structure-aware input generator. Biases the corpus toward the interesting
/// boundaries (valid commands, near-misses, oversized frames, raw garbage)
/// instead of relying on the raw byte stream alone.
#[derive(Debug, Arbitrary)]
enum FrameInput {
    /// Raw attacker bytes, verbatim.
    Raw(Vec<u8>),
    /// A real command, optionally wrapped in whitespace + a trailing newline.
    Known {
        which: u8,
        lead: Vec<u8>,
        trail: Vec<u8>,
    },
    /// A `FETCH_`-prefixed near-miss token (exercises the unknown-command path).
    NearMiss(Vec<u8>),
    /// A deliberately oversized frame (exercises the OOM/length guard).
    Oversized(Vec<u8>),
}

impl FrameInput {
    fn into_frame(self) -> Vec<u8> {
        match self {
            FrameInput::Raw(bytes) => bytes,
            FrameInput::Known { which, lead, trail } => {
                let cmd = match which % 3 {
                    0 => "FETCH_SVID",
                    1 => "FETCH_BUNDLE",
                    _ => "PING",
                };
                let mut frame = lead;
                frame.extend_from_slice(cmd.as_bytes());
                frame.extend_from_slice(&trail);
                frame.push(b'\n');
                frame
            }
            FrameInput::NearMiss(mut suffix) => {
                let mut frame = b"FETCH_".to_vec();
                frame.append(&mut suffix);
                frame.push(b'\n');
                frame
            }
            FrameInput::Oversized(mut tail) => {
                let mut frame = vec![b'A'; MAX_COMMAND_LEN + 1];
                frame.append(&mut tail);
                frame
            }
        }
    }
}

/// Drive the parser and assert the isolation contract. Any violation panics,
/// which libFuzzer reports as a crash.
fn exercise(frame: &[u8]) {
    match parse_command(frame) {
        Ok(cmd) => {
            // Anything accepted must round-trip through its canonical wire form
            // (no hidden aliases) and must have been within the size bound.
            assert!(
                frame.len() <= MAX_COMMAND_LEN,
                "accepted a frame larger than the bound"
            );
            assert_eq!(
                parse_command(cmd.as_wire().as_bytes()),
                Ok(cmd),
                "canonical re-parse diverged"
            );
        }
        Err(CommandParseError::TooLong { len }) => {
            // The length verdict must agree with reality and only fire above the
            // cap.
            assert_eq!(len, frame.len());
            assert!(len > MAX_COMMAND_LEN);
        }
        Err(_) => {}
    }
}

fuzz_target!(|data: &[u8]| {
    // 1. Feed the raw attacker bytes straight to the parser.
    exercise(data);

    // 2. And a structure-aware frame derived from the same entropy for depth.
    let mut u = Unstructured::new(data);
    if let Ok(input) = FrameInput::arbitrary(&mut u) {
        let frame = input.into_frame();
        exercise(&frame);
    }
});

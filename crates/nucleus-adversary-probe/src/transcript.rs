//! `nucleus-adversary-probe transcript` — a guest that talks to the host at
//! random, for A6/A7 of the command walk (`docs/design/command-walk.md`).
//!
//! A6: nothing a guest SAYS over the workload API changes what the host
//! concludes. A7: a receipt a guest ships is data, never authority. Both are
//! checked from the host, by booting the same pod several times: each boot
//! draws a different random transcript here, and the host's conclusions must
//! come out identical anyway (`nucleus-perf guest-transcript`).
//!
//! # What this must not do
//!
//! Put anything about the transcript where the host observes it. stdout and
//! stderr are hashed into the execution claim, so they are FIXED: one line, the
//! same every run. The host learns what was sent from its own record (the
//! node's per-command log), not from this process's word — the same reason the
//! adversary stages report booleans only.
//!
//! The randomness is drawn inside the guest, from `/dev/urandom`, so no field
//! of the pod spec differs between runs; A4 would otherwise make every run a
//! different program before a single command was sent.
//!
//! # Optional: `--forge-exit-report`
//!
//! Writes a forged `.nucleus-exit-report.json` into the workspace before the
//! transcript. That file is not part of A6's transcript — it is a file, not a
//! command — but it is the other way a guest can put words in front of the host,
//! and `pod_receipt` reads it back. The harness measures whether the host's
//! receipt repeats the forgery.

use std::io::Read;

/// The workload API commands, spelled as the guest sends them. Kept here, not
/// imported: this binary is the adversary and must not share the host's parser.
const COMMANDS: [&str; 14] = [
    "FETCH_SVID",
    "FETCH_BUNDLE",
    "PING",
    "FETCH_TASK_TOKEN",
    "FETCH_DLC_ADMISSION",
    "FETCH_BROKER_SECRET",
    "FETCH_POD_CALLER_TOKEN",
    "FETCH_POD_CERTIFICATE",
    "FETCH_AUDIT_CREDENTIALS",
    "FETCH_MEDIATION_KEY",
    "POD_LIST",
    "FETCH_POD_SPEC",
    "SHIP_RECEIPT",
    "SNAPSHOT_READY",
];

/// The fixed line every run prints, whatever it sent.
pub const DONE: &str = "NUCLEUS_TRANSCRIPT: done";

/// The forged exit report's marker values, so the harness can recognise them.
pub const FORGED_WORKSPACE_HASH: &str = "forged-by-the-guest";

/// One step of a transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// A real command token.
    Command(&'static str),
    /// A token the host must refuse to parse.
    Unknown,
    /// A frame longer than the host's command bound.
    Oversized,
    /// `SHIP_RECEIPT` followed by an adversarial body (A7).
    Ship(Body),
}

/// Adversarial receipt bodies. None of these is signed by a trusted mediator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Body {
    /// Not JSON at all.
    Garbage,
    /// A receipt-shaped object cut off mid-way.
    Truncated,
    /// Well-formed JSON in a receipt's shape with a signature that verifies
    /// against nothing.
    ForgedSignature,
    /// Longer than the host's receipt-body bound.
    Oversized,
}

/// A small deterministic generator, seeded from the kernel. Not cryptographic;
/// it only has to make runs differ.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next().checked_rem(n).unwrap_or(0)
    }
}

/// Up to this many steps per run. Zero is a possible draw: the empty transcript
/// is the baseline A6 compares against.
pub const MAX_STEPS: u64 = 12;

/// Draw a transcript from `seed`.
pub fn draw(seed: u64) -> Vec<Step> {
    let mut rng = XorShift(seed | 1);
    let n = rng.below(MAX_STEPS.saturating_add(1));
    // Every command, then an unknown token, an oversized frame, and one more
    // forged-signature ship so A7 gets drawn often.
    let kinds = COMMANDS.len().saturating_add(3) as u64;
    (0..n)
        .map(
            |_| match usize::try_from(rng.below(kinds)).unwrap_or(usize::MAX) {
                i if i < COMMANDS.len() => {
                    let cmd = COMMANDS.get(i).copied().unwrap_or("PING");
                    if cmd == "SHIP_RECEIPT" {
                        Step::Ship(match rng.below(4) {
                            0 => Body::Garbage,
                            1 => Body::Truncated,
                            2 => Body::ForgedSignature,
                            _ => Body::Oversized,
                        })
                    } else {
                        Step::Command(cmd)
                    }
                }
                i if i == COMMANDS.len() => Step::Unknown,
                i if i == COMMANDS.len().saturating_add(1) => Step::Oversized,
                _ => Step::Ship(Body::ForgedSignature),
            },
        )
        .collect()
}

/// The bytes put on the wire for one step: the command frame, and for a ship,
/// the body frame after it.
// Only a Linux guest has vsock to put them on; the unit tests still read them.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn frames(step: &Step) -> Vec<Vec<u8>> {
    match step {
        Step::Command(c) => vec![format!("{c}\n").into_bytes()],
        Step::Unknown => vec![b"FETCH_EVERYTHING\n".to_vec()],
        Step::Oversized => vec![{
            let mut v = vec![b'A'; 1024];
            v.push(b'\n');
            v
        }],
        Step::Ship(body) => vec![b"SHIP_RECEIPT\n".to_vec(), body_bytes(*body)],
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn body_bytes(body: Body) -> Vec<u8> {
    let mut v = match body {
        Body::Garbage => b"\x01\x02not a receipt\xff".to_vec(),
        Body::Truncated => br#"{"session_id":"s","sequence":0,"operation":"read_fi"#.to_vec(),
        Body::ForgedSignature => format!(
            r#"{{"session_id":"forged","sequence":0,"operation":"write_files","verdict":"allow","signature":"{}","signer":"{}"}}"#,
            "00".repeat(64),
            "11".repeat(32)
        )
        .into_bytes(),
        Body::Oversized => vec![b'{'; 16 * 1024],
    };
    v.push(b'\n');
    v
}

fn seed_from_kernel() -> Option<u64> {
    let mut buf = [0u8; 8];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .ok()?;
    Some(u64::from_le_bytes(buf))
}

/// The forged report written by `--forge-exit-report`.
pub fn forged_exit_report() -> String {
    format!(
        r#"{{"workspace_hash":"{FORGED_WORKSPACE_HASH}","audit_tail_hash":"forged","audit_entry_count":424242,"timestamp_unix":1,"cost_usd":0.0}}"#
    )
}

/// Run the transcript mode. Returns the process exit code.
pub fn run(args: &[String]) -> i32 {
    if args.iter().any(|a| a == "--forge-exit-report") {
        let dir = std::env::var("NUCLEUS_TRANSCRIPT_WORK_DIR").unwrap_or_else(|_| "/work".into());
        // Whether this succeeds is the host's to find out, not this line's to
        // announce: nothing about it goes to stdout.
        let _ = std::fs::write(
            std::path::Path::new(&dir).join(".nucleus-exit-report.json"),
            forged_exit_report(),
        );
    }
    let Some(seed) = seed_from_kernel() else {
        println!("{DONE}");
        return 0;
    };
    for step in draw(seed) {
        send(&step);
    }
    println!("{DONE}");
    0
}

#[cfg(target_os = "linux")]
fn send(step: &Step) {
    use std::io::{BufRead, BufReader, Write};
    use std::time::Duration;
    const VMADDR_CID_HOST: u32 = 2;
    let port = std::env::var("NUCLEUS_TRANSCRIPT_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(15012);
    let Ok(mut stream) = vsock::VsockStream::connect_with_cid_port(VMADDR_CID_HOST, port) else {
        return;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    for frame in frames(step) {
        if stream.write_all(&frame).is_err() {
            return;
        }
    }
    let _ = stream.flush();
    let mut reply = String::new();
    let _ = BufReader::new(&mut stream).read_line(&mut reply);
}

#[cfg(not(target_os = "linux"))]
fn send(_step: &Step) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The draw reaches every kind of step, the empty transcript included, so a
    /// fleet of runs is not silently all-PING or all-empty.
    #[test]
    fn the_draw_reaches_every_step_kind_and_the_empty_transcript() {
        let mut empty = false;
        let mut kinds = std::collections::BTreeSet::new();
        for seed in 1..4000u64 {
            let t = draw(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
            empty |= t.is_empty();
            for s in t {
                kinds.insert(match s {
                    Step::Command(c) => c.to_string(),
                    Step::Unknown => "unknown".into(),
                    Step::Oversized => "oversized".into(),
                    Step::Ship(b) => format!("ship:{b:?}"),
                });
            }
        }
        assert!(empty, "the empty transcript must be drawable");
        for c in COMMANDS.iter().filter(|c| **c != "SHIP_RECEIPT") {
            assert!(kinds.contains(*c), "{c} never drawn");
        }
        for k in [
            "unknown",
            "oversized",
            "ship:Garbage",
            "ship:Truncated",
            "ship:ForgedSignature",
            "ship:Oversized",
        ] {
            assert!(kinds.contains(k), "{k} never drawn");
        }
    }

    #[test]
    fn a_ship_step_puts_a_body_frame_after_the_command() {
        let f = frames(&Step::Ship(Body::Truncated));
        assert_eq!(f.len(), 2);
        assert_eq!(f[0], b"SHIP_RECEIPT\n");
        assert!(f[1].ends_with(b"\n"));
    }

    /// The harness recognises a repeated forgery by this marker, so it must be in
    /// the report the guest writes.
    #[test]
    fn the_forged_report_carries_the_marker() {
        let r = forged_exit_report();
        assert!(r.starts_with('{') && r.ends_with('}'));
        assert!(r.contains(FORGED_WORKSPACE_HASH));
    }
}

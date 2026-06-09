//! Pure, dependency-free parser for the Workload API vsock command protocol.
//!
//! This is the **trusted host-side edge** of the guest→host vsock channel: bytes
//! that a (potentially compromised) guest sends over its AF_VSOCK connection are
//! turned into a host-side command here. Because the input is fully attacker
//! controlled, this parser is held to a hard contract:
//!
//! * **Total** — it returns a value for *every* `&[u8]` input; it never panics,
//!   never wraps an `unwrap`/`expect`/indexing that could trip, and never enters
//!   an unbounded loop.
//! * **Bounded** — it allocates at most `MAX_COMMAND_LEN` bytes of guest data
//!   (the rejection threshold is checked *before* any UTF-8 conversion), so a
//!   guest that streams junk cannot drive host OOM through this function.
//! * **Fail-closed** — malformed, oversized, non-UTF-8, or unknown input yields
//!   `Err(_)`, never a silently-accepted command.
//!
//! The module is intentionally `std`-only (no tokio, no serde, no `thiserror`)
//! so it can be compiled standalone: the `cargo-fuzz` harness pulls this exact
//! source in via `#[path]` without dragging the rest of `nucleus-node` along,
//! and the in-tree `proptest` suite exercises the same code the runtime uses.
//!
//! The async I/O layer in [`crate::workload_api_vsock`] is responsible only for
//! framing (reading up to a newline, bounded by [`MAX_COMMAND_LEN`]); it then
//! delegates *all* interpretation to [`parse_command`].

/// Maximum length, in bytes, of a single Workload API command frame.
///
/// The protocol's longest legal command (`FETCH_BUNDLE`) is 12 bytes; this cap
/// is generous enough for forward-compatible commands while bounding the host
/// memory a single frame can consume. The async reader refuses to buffer beyond
/// this, and [`parse_command`] independently re-checks it (defense in depth, and
/// so the fuzz/property harness reaches the bound without the I/O layer).
pub const MAX_COMMAND_LEN: usize = 256;

/// A successfully parsed Workload API command.
///
/// Adding a variant here is the *only* way to teach the host a new command;
/// every byte string that does not map to one of these is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadApiCommand {
    /// `FETCH_SVID` — request this pod's X.509 SVID (cert chain + private key).
    FetchSvid,
    /// `FETCH_BUNDLE` — request the trust bundle (root CA certificates).
    FetchBundle,
    /// `PING` — liveness probe.
    Ping,
}

impl WorkloadApiCommand {
    /// The canonical, on-the-wire spelling of this command (no trailing newline).
    ///
    /// Round-trip law: `parse_command(cmd.as_wire().as_bytes()) == Ok(cmd)`.
    // Exercised by the round-trip unit/proptests and the cargo-fuzz target, not
    // the node's runtime path (which only parses inbound frames) — hence dead in
    // the plain `bin` build.
    #[allow(dead_code)]
    pub const fn as_wire(self) -> &'static str {
        match self {
            WorkloadApiCommand::FetchSvid => "FETCH_SVID",
            WorkloadApiCommand::FetchBundle => "FETCH_BUNDLE",
            WorkloadApiCommand::Ping => "PING",
        }
    }
}

/// Why a guest-supplied command frame was rejected.
///
/// Display output is safe to surface (e.g. embedded in a JSON error response) as
/// long as the caller escapes it; [`CommandParseError::Unknown`] carries the
/// trimmed guest token, which is bounded by [`MAX_COMMAND_LEN`] but is still
/// attacker-controlled text and MUST be escaped (e.g. via `serde_json`) before
/// being written back to any channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandParseError {
    /// The frame was empty (or only whitespace) after trimming.
    Empty,
    /// The frame exceeded [`MAX_COMMAND_LEN`]; rejected without UTF-8 decoding.
    TooLong { len: usize },
    /// The frame was not valid UTF-8.
    NotUtf8,
    /// The frame was a well-formed token but not a recognized command.
    Unknown(String),
}

impl std::fmt::Display for CommandParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandParseError::Empty => write!(f, "empty command"),
            CommandParseError::TooLong { len } => {
                write!(f, "command too long: {len} bytes (max {MAX_COMMAND_LEN})")
            }
            CommandParseError::NotUtf8 => write!(f, "command is not valid UTF-8"),
            CommandParseError::Unknown(cmd) => write!(f, "unknown command: {cmd}"),
        }
    }
}

impl std::error::Error for CommandParseError {}

/// Parse a single Workload API command frame from raw, guest-supplied bytes.
///
/// `frame` is one newline-delimited unit as produced by the framing layer; a
/// trailing `\r`/`\n` and surrounding ASCII whitespace are tolerated and
/// trimmed. See the module docs for the total/bounded/fail-closed contract this
/// function upholds for *arbitrary* input.
pub fn parse_command(frame: &[u8]) -> Result<WorkloadApiCommand, CommandParseError> {
    // Bound BEFORE allocating/decoding so an oversized frame never materializes
    // as a `String`. This is the OOM guard the fuzz target asserts against.
    if frame.len() > MAX_COMMAND_LEN {
        return Err(CommandParseError::TooLong { len: frame.len() });
    }

    let text = std::str::from_utf8(frame).map_err(|_| CommandParseError::NotUtf8)?;
    let command = text.trim();

    if command.is_empty() {
        return Err(CommandParseError::Empty);
    }

    match command {
        "FETCH_SVID" => Ok(WorkloadApiCommand::FetchSvid),
        "FETCH_BUNDLE" => Ok(WorkloadApiCommand::FetchBundle),
        "PING" => Ok(WorkloadApiCommand::Ping),
        other => Err(CommandParseError::Unknown(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn known_commands_round_trip() {
        for cmd in [
            WorkloadApiCommand::FetchSvid,
            WorkloadApiCommand::FetchBundle,
            WorkloadApiCommand::Ping,
        ] {
            assert_eq!(parse_command(cmd.as_wire().as_bytes()), Ok(cmd));
            // Trailing newline (the on-wire form) and surrounding whitespace
            // must not change the verdict.
            let framed = format!("  {}\r\n", cmd.as_wire());
            assert_eq!(parse_command(framed.as_bytes()), Ok(cmd));
        }
    }

    #[test]
    fn empty_and_whitespace_are_rejected() {
        assert_eq!(parse_command(b""), Err(CommandParseError::Empty));
        assert_eq!(parse_command(b"   \r\n\t "), Err(CommandParseError::Empty));
    }

    #[test]
    fn unknown_command_is_rejected_not_executed() {
        assert_eq!(
            parse_command(b"FETCH_EVERYTHING\n"),
            Err(CommandParseError::Unknown("FETCH_EVERYTHING".to_string()))
        );
        // Case sensitivity: the protocol is exact-match, lower-case must fail.
        assert!(matches!(
            parse_command(b"ping\n"),
            Err(CommandParseError::Unknown(_))
        ));
    }

    #[test]
    fn oversized_frame_rejected_before_utf8_decode() {
        // One byte over the cap, and crucially invalid UTF-8 too: TooLong must
        // win, proving the length guard runs before any decode/allocation.
        let frame = vec![0xFFu8; MAX_COMMAND_LEN + 1];
        assert_eq!(
            parse_command(&frame),
            Err(CommandParseError::TooLong {
                len: MAX_COMMAND_LEN + 1
            })
        );
    }

    #[test]
    fn invalid_utf8_within_bound_is_rejected() {
        assert_eq!(
            parse_command(&[0xC3, 0x28]),
            Err(CommandParseError::NotUtf8)
        );
    }

    proptest! {
        // INVARIANT (totality): the parser returns for every input and never
        // panics. A panic here aborts the test process -> failure.
        #[test]
        fn never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let _ = parse_command(&bytes);
        }

        // INVARIANT (bounded): any frame longer than the cap is rejected as
        // TooLong, regardless of its contents. This is the OOM/DoS guard.
        #[test]
        fn oversized_is_always_too_long(
            bytes in proptest::collection::vec(any::<u8>(), (MAX_COMMAND_LEN + 1)..2048)
        ) {
            prop_assert_eq!(
                parse_command(&bytes),
                Err(CommandParseError::TooLong { len: bytes.len() })
            );
        }

        // INVARIANT (fail-closed): an arbitrary in-bounds token that is not a
        // known command is NEVER parsed into a command — it must be an Err.
        // Structure-aware: a valid-shaped token + random suffix.
        #[test]
        fn unknown_tokens_never_become_commands(
            suffix in "[A-Za-z0-9_]{1,32}"
        ) {
            let candidate = format!("FETCH_{suffix}");
            prop_assume!(candidate != "FETCH_SVID" && candidate != "FETCH_BUNDLE");
            prop_assert!(parse_command(candidate.as_bytes()).is_err());
        }

        // INVARIANT (round-trip): a known command, surrounded by arbitrary ASCII
        // whitespace and a trailing newline (the realistic framed form), still
        // parses back to exactly that command. Truncation/garbage in the
        // whitespace must not flip the decision.
        #[test]
        fn known_command_survives_whitespace_framing(
            idx in 0usize..3,
            lead in "[ \t\r\n]{0,8}",
            trail in "[ \t\r\n]{0,8}",
        ) {
            let cmd = [
                WorkloadApiCommand::FetchSvid,
                WorkloadApiCommand::FetchBundle,
                WorkloadApiCommand::Ping,
            ][idx];
            let framed = format!("{lead}{}{trail}", cmd.as_wire());
            prop_assert_eq!(parse_command(framed.as_bytes()), Ok(cmd));
        }

        // INVARIANT (parser is the sole authority): whatever parse_command
        // returns Ok for must re-serialize to its canonical wire form and
        // re-parse identically — no hidden aliases.
        #[test]
        fn ok_results_round_trip_through_wire(bytes in proptest::collection::vec(any::<u8>(), 0..300)) {
            if let Ok(cmd) = parse_command(&bytes) {
                prop_assert_eq!(parse_command(cmd.as_wire().as_bytes()), Ok(cmd));
            }
        }
    }
}

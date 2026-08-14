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
    /// `FETCH_TASK_TOKEN` — request this pod's live-path session capability
    /// token.
    ///
    /// # Why this rides the workload API rather than the broker
    ///
    /// The broker socket is better engineered — identity-bound at the listener,
    /// fail-closed, TTL'd — but its frame is a credential *request envelope*,
    /// and a token fetch is not that; it would need a second operation kind
    /// inside a protocol that has one job. This channel already serves per-pod
    /// artifacts over a per-pod socket, so the extension is a variant rather
    /// than a protocol inside a protocol.
    ///
    /// # What it replaces
    ///
    /// The token rides the **kernel command line** today, as
    /// `nucleus.task_token_hex`/`_nonce`/`_issuer`. That is world-readable
    /// inside the guest, and — the reason this exists — it is *per-pod material
    /// baked into a boot artifact*, so every clone restored from a snapshot
    /// would inherit one pod's token. Three of the five keys blocking a
    /// snapshottable base are these.
    ///
    /// The token is **not a secret** (a scoped capability plus a public issuer
    /// key, with anti-replay resting on a host-pinned nonce), so this is not
    /// about confidentiality. It is about uniqueness surviving a restore.
    FetchTaskToken,
    /// `FETCH_DLC_ADMISSION` — request this pod's DLC-D verified-admission
    /// provisioning (trusted issuer keys, issuer, per-operation credentials).
    ///
    /// Rides this channel for the same reasons as `FETCH_TASK_TOKEN`: per-pod
    /// material over the per-pod socket, fetched after boot so it is neither
    /// baked into a snapshot base nor subject to the kernel cmdline's capacity
    /// (which a credential set exceeds — observed live). The values are a
    /// public keyset plus the pod's OWN capability grants; possession is
    /// exactly the authority intended.
    FetchDlcAdmission,
    /// `FETCH_POD_CALLER_TOKEN` — request this pod's caller-identity token for
    /// the node's management API.
    ///
    /// # Why this rides the workload API
    ///
    /// Same reasoning `FetchTaskToken` records: this channel already serves
    /// per-pod artifacts over a per-pod socket the HOST creates per VM, so the
    /// pod does not name itself — the socket does. That is exactly the property
    /// a caller-identity token needs. Any other delivery (a spec field, a
    /// kernel cmdline value, an environment variable set before the pod is
    /// known) would be something the guest could restate.
    FetchPodCallerToken,
    /// `FETCH_BROKER_SECRET` — request this pod's credential-broker capability.
    ///
    /// # Served exactly ONCE per pod, and that is the security property
    ///
    /// Its neighbours may be fetched repeatedly: a task token and an admission
    /// keyset are per-pod material whose possession is the authority intended,
    /// so serving them twice changes nothing. This one is different. It exists
    /// to distinguish the mediating tool-proxy from every OTHER process in the
    /// guest, and a secret served twice cannot do that.
    ///
    /// # What it defends against, concretely
    ///
    /// Any guest process can open `AF_VSOCK` — verified by experiment, and NOT
    /// preventable by permissions on `/dev/vsock`, which does not gate the
    /// socket family. So a workload can reach the broker directly. The broker
    /// enforces the pod's capability lattice but has no taint state (the
    /// `FlowTracker` lives in the tool-proxy), so a direct connection would
    /// bypass the kernel decision, the session taint ceiling, the
    /// lethal-trifecta guard and the flow cross-check.
    ///
    /// One-shot delivery closes that: `nucleus-guest-init` fetches this before
    /// `exec_proxy`, so before any workload exists, and a workload that asks
    /// later is refused. Combined with the uid boundary the tool-proxy already
    /// requires when a credential is being withheld — same-uid processes can
    /// read each other's `/proc/<pid>/environ` — the secret is reachable only by
    /// the proxy.
    ///
    /// # Why not the kernel command line
    ///
    /// `/proc/cmdline` is world-readable in the guest, which is where
    /// `nucleus.auth_secret` and `nucleus.approval_secret` once arrived —
    /// neither was a proxy-only capability for exactly that reason, and both
    /// are gone from the command line now (the transport peer check replaced
    /// one, signature-based approvals the other).
    FetchBrokerSecret,
    /// `FETCH_AUDIT_CREDENTIALS` — request the cloud credentials for this pod's
    /// S3 audit sink.
    ///
    /// # Served exactly ONCE per pod, like `FETCH_BROKER_SECRET`
    ///
    /// These are real, long-lived cloud credentials the host holds so the
    /// in-guest tool-proxy can ship its audit log to S3. They used to ride the
    /// kernel command line (`nucleus.aws_access_key_id` etc.), where
    /// `/proc/cmdline` made them readable by the very workload the audit trail
    /// is meant to witness — the C1 exposure. Moving them here restores the
    /// intended split: `nucleus-guest-init` fetches before `exec_proxy`, so
    /// before any workload exists, and the one-shot refuses whoever asks
    /// second. A workload that steals the audit creds can erase its own trail,
    /// so this gets the broker secret's delivery discipline, not the task
    /// token's.
    FetchAuditCredentials,
    /// `FETCH_MEDIATION_KEY` — the per-pod signing key the tool-proxy signs
    /// forensic `MediationReceipt`s with. Served with the broker secret's
    /// delivery discipline: exactly once, before any workload exists, value never
    /// logged. Possession lets the holder sign receipts as this mediator, so a
    /// workload that grabbed it could forge them — the one-shot before-workload
    /// delivery is what keeps it out of the workload's reach.
    FetchMediationKey,
    /// `POD_LIST` — request the pod summaries THIS pod is entitled to manage:
    /// itself and its direct children, never a sibling.
    ///
    /// # This is the one command that ANSWERS rather than provisions
    ///
    /// Every command above serves this pod its OWN material. `POD_LIST` is
    /// different in kind — it reports on OTHER pods — so it is the one that
    /// widens what a guest can learn about the node, and it is gated accordingly:
    ///
    /// * **The socket is the authority.** The host creates one vsock socket per
    ///   VM and knows which pod owns it; the caller is bound to THAT pod id, not
    ///   to anything the guest sends. So no caller token and no node secret ride
    ///   this channel — unlike the HTTP `/v1/pods` path, nothing authenticating
    ///   is delivered into the guest at all.
    /// * **The answer is lineage-scoped.** It is served through `PodListView`,
    ///   which applies the identical `pod_api::caller_may_manage` filter the
    ///   HTTP listing uses, frozen to the socket's pod id. A pod sees its own
    ///   row and its direct children — the exact `PodInfo`s it could already
    ///   obtain over `/v1/pods` with its own token — and a sibling is excluded.
    ///
    /// It exists so a booted orchestrator pod can make the scoped management
    /// call on the real Firecracker path (C2 cross-pod), which the HTTP route
    /// cannot reach from inside a default-deny netns.
    PodList,
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
            WorkloadApiCommand::FetchTaskToken => "FETCH_TASK_TOKEN",
            WorkloadApiCommand::FetchDlcAdmission => "FETCH_DLC_ADMISSION",
            WorkloadApiCommand::FetchBrokerSecret => "FETCH_BROKER_SECRET",
            WorkloadApiCommand::FetchPodCallerToken => "FETCH_POD_CALLER_TOKEN",
            WorkloadApiCommand::FetchAuditCredentials => "FETCH_AUDIT_CREDENTIALS",
            WorkloadApiCommand::FetchMediationKey => "FETCH_MEDIATION_KEY",
            WorkloadApiCommand::PodList => "POD_LIST",
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
        "FETCH_TASK_TOKEN" => Ok(WorkloadApiCommand::FetchTaskToken),
        "FETCH_DLC_ADMISSION" => Ok(WorkloadApiCommand::FetchDlcAdmission),
        "FETCH_BROKER_SECRET" => Ok(WorkloadApiCommand::FetchBrokerSecret),
        "FETCH_POD_CALLER_TOKEN" => Ok(WorkloadApiCommand::FetchPodCallerToken),
        "FETCH_AUDIT_CREDENTIALS" => Ok(WorkloadApiCommand::FetchAuditCredentials),
        "FETCH_MEDIATION_KEY" => Ok(WorkloadApiCommand::FetchMediationKey),
        "POD_LIST" => Ok(WorkloadApiCommand::PodList),
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
            WorkloadApiCommand::FetchTaskToken,
            WorkloadApiCommand::FetchPodCallerToken,
            WorkloadApiCommand::FetchSvid,
            WorkloadApiCommand::FetchBundle,
            WorkloadApiCommand::Ping,
            WorkloadApiCommand::FetchAuditCredentials,
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

    // ── THE GUEST-TO-HOST REQUEST SURFACE ───────────────────────────────────
    //
    // vsock is the channel a guest uses to reach the host, which makes it the
    // classic escape vector: 2026 brought CVE-2026-46234 and CVE-2026-23086
    // against the Linux vsock transport itself, where a malicious guest
    // advertises a large buffer and reads slowly to force host allocation. That
    // class lives in the host kernel and is EXTERNAL to us (see
    // sandbox-trusted-base.txt); the frame reader already bounds what a guest
    // can make us allocate via MAX_COMMAND_LEN.
    //
    // What was NOT written down anywhere is the request surface itself — which
    // commands the host will act on for a guest. This pins it.
    //
    // TWO PINS, and the compile-time one is the point:
    //
    //   * `guest_request_surface_is_exhaustive` cannot COMPILE if a variant is
    //     added to WorkloadApiCommand. A runtime assertion can be forgotten by
    //     someone adding a variant; a non-exhaustive match cannot.
    //   * `the_guest_request_surface_is_exactly_the_declared_set` pins the whole
    //     set of wire spellings, so adding, removing or renaming one is a visible
    //     diff. (It once listed only three of the commands and silently stopped
    //     covering the five added since; it now enumerates the whole surface, and
    //     the compile-time pin above is what forces that list to stay complete.)
    //
    // IS THE FIRST ONE REDUNDANT? The dispatcher in workload_api_vsock.rs
    // already matches exhaustively, so a new variant fails to compile there too
    // — and a second gate that agrees with the first buys nothing. It is NOT
    // redundant, and the difference was established by bite rather than by
    // argument: adding a catch-all `Ok(_) =>` arm to the dispatcher blinds it
    // silently, and with the dispatcher blinded THIS test still refuses to
    // compile. It is a backstop against the dispatcher acquiring a wildcard,
    // which is the one way the compile-time guarantee can be lost without
    // anyone noticing.
    #[test]
    fn guest_request_surface_is_exhaustive() {
        // Deliberately written WITHOUT a wildcard arm. Adding a variant to
        // WorkloadApiCommand makes this fail to compile, which is the strongest
        // form this pin can take: the surface cannot grow silently.
        fn assert_known(cmd: WorkloadApiCommand) -> &'static str {
            match cmd {
                WorkloadApiCommand::FetchSvid => "FETCH_SVID",
                WorkloadApiCommand::FetchBundle => "FETCH_BUNDLE",
                WorkloadApiCommand::Ping => "PING",
                WorkloadApiCommand::FetchTaskToken => "FETCH_TASK_TOKEN",
                WorkloadApiCommand::FetchDlcAdmission => "FETCH_DLC_ADMISSION",
                WorkloadApiCommand::FetchBrokerSecret => "FETCH_BROKER_SECRET",
                WorkloadApiCommand::FetchPodCallerToken => "FETCH_POD_CALLER_TOKEN",
                WorkloadApiCommand::FetchAuditCredentials => "FETCH_AUDIT_CREDENTIALS",
                WorkloadApiCommand::FetchMediationKey => "FETCH_MEDIATION_KEY",
                WorkloadApiCommand::PodList => "POD_LIST",
            }
        }
        for cmd in [
            WorkloadApiCommand::FetchSvid,
            WorkloadApiCommand::FetchBundle,
            WorkloadApiCommand::FetchDlcAdmission,
            WorkloadApiCommand::FetchBrokerSecret,
            WorkloadApiCommand::FetchAuditCredentials,
            WorkloadApiCommand::PodList,
            WorkloadApiCommand::Ping,
        ] {
            assert_eq!(assert_known(cmd), cmd.as_wire());
        }
    }

    #[test]
    fn the_guest_request_surface_is_exactly_the_declared_set() {
        // Every variant the host accepts. Kept in lockstep with the exhaustive
        // match above — a new variant fails THAT test's compile, which is what
        // stops this list from silently going stale (as its 3-command ancestor
        // did while five commands were added past it).
        let surface = [
            WorkloadApiCommand::FetchSvid,
            WorkloadApiCommand::FetchBundle,
            WorkloadApiCommand::Ping,
            WorkloadApiCommand::FetchTaskToken,
            WorkloadApiCommand::FetchDlcAdmission,
            WorkloadApiCommand::FetchBrokerSecret,
            WorkloadApiCommand::FetchPodCallerToken,
            WorkloadApiCommand::FetchAuditCredentials,
            WorkloadApiCommand::FetchMediationKey,
            WorkloadApiCommand::PodList,
        ];
        let accepted: std::collections::BTreeSet<String> =
            surface.iter().map(|c| c.as_wire().to_string()).collect();
        let want: std::collections::BTreeSet<String> = [
            "FETCH_SVID",
            "FETCH_BUNDLE",
            "PING",
            "FETCH_TASK_TOKEN",
            "FETCH_DLC_ADMISSION",
            "FETCH_BROKER_SECRET",
            "FETCH_POD_CALLER_TOKEN",
            "FETCH_AUDIT_CREDENTIALS",
            "FETCH_MEDIATION_KEY",
            "POD_LIST",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            accepted, want,
            "the guest-to-host request surface changed — a command a guest can \
             make the host act on was added, removed or renamed"
        );
        // No two commands collapsed onto one wire spelling (9 variants → 9 forms).
        assert_eq!(
            accepted.len(),
            surface.len(),
            "two commands share a wire spelling"
        );
        // The set is the REAL accepted surface: each declared spelling parses
        // back to its command, so this pins what the host acts on, not just text.
        for cmd in surface {
            assert_eq!(parse_command(cmd.as_wire().as_bytes()), Ok(cmd));
        }
    }
}

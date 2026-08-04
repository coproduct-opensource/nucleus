//! Completeness by 2-safety: boot twice, differ only in a secret, compare.
//!
//! # Why this exists, and why it is not another leak scan
//!
//! A security property is an uninhabitedness claim, and it splits in two.
//! *Soundness* — every mechanism in the flow model has an implementation — is
//! greppable, lintable, and increasingly type-level. *Completeness* — every
//! mechanism that moves information appears IN the model — is not reachable by
//! any static analysis, because the whole problem is that nobody wrote the edge
//! down. That is what missed `execve`'s environment inheritance, and an
//! unchowned socket, and a leak-site dump that could not run.
//!
//! Noninterference is not a property. It is a **2-safety hyperproperty**: any
//! two executions agreeing on low inputs must agree on low outputs. Such a
//! property reduces to a safety property of the self-composition — run the
//! system twice and compare. So this module stops enumerating mechanisms and
//! compares two executions instead. **A channel nobody thought of shows up as a
//! difference.**
//!
//! Completeness stops being an unbounded list and becomes a property of one
//! object: the observation function below.
//!
//! # The honest bound, stated here rather than in a footnote
//!
//! This is complete **relative to what [`Observation`] captures**. seL4's
//! information-flow proof — the strongest result of this kind — records the same
//! shape of limitation: its machine model does not model time, so it says little
//! about covert timing channels. Anything outside the observation (timing, cache
//! residency, power) is outside this too.
//!
//! That is still a large advance on a mechanism list, because the bound is ONE
//! reviewable object rather than an open-ended enumeration nobody maintains.

use std::fmt;

/// Everything the host holds that the guest could have influenced or seen.
///
/// Deliberately a struct of named components rather than one opaque blob: a
/// divergence must be attributable to a component, and a component that stops
/// being collected should be visible as a field, not as a silently shorter
/// string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// The Firecracker machine configuration as serialised for this pod —
    /// devices, drives, vsock, and the kernel command line. `sandbox-trusted-base.txt`
    /// already pins this surface (`firecracker_device_surface_is_exactly_pinned`).
    pub machine_config: String,
    /// The guest console, i.e. what the guest actually emitted.
    pub console: String,
}

/// An [`Observation`] with run-to-run nondeterminism normalised away.
///
/// A distinct type from `Observation` on purpose: comparing two raw observations
/// is always a false positive, and comparing a raw against a canonical one is a
/// mistake the type system can prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canonical {
    machine_config: String,
    console: String,
}

impl Canonical {
    /// Does either component contain `needle`?
    ///
    /// Exists for [`control`], which must confirm the value it PLANTED survived
    /// into the observation — a divergence that is not attributable to the plant
    /// is not a positive control, it is noise that happens to be red.
    ///
    /// Deliberately not part of the leak comparison: [`canonicalise`] still
    /// cannot name the secret, and nothing on the `check` path calls this.
    fn contains(&self, needle: &str) -> bool {
        self.machine_config.contains(needle) || self.console.contains(needle)
    }
}

/// Structural facts about a run that differ between boots and carry no secret.
///
/// Passed in rather than discovered, so the canonicaliser erases only what a
/// caller has explicitly declared to be run-scoped.
#[derive(Debug, Clone)]
pub struct RunFacts {
    /// The pod's UUID. Minted before any secret is read, so it cannot encode one.
    pub pod_id: String,
    /// The guest CID.
    ///
    /// The previous comment here said "allocated from a counter", which is not
    /// true of any path: `firecracker_config.rs` takes it from the `--vsock-cid`
    /// argument, and [`crate::twosafety_boot`] passes a compile-time constant.
    /// A doc comment asserting a provenance nothing enforces is the weakest form
    /// of the guarantee, so it now says what is actually the case.
    pub guest_cid: u32,
}

// ---------------------------------------------------------------------------
// WHY `RunFacts` MAY BE ERASED AT ALL — the load-bearing assumption.
//
// The comparison is not `f s₁` against `f s₂`. It is `h_{r₁}(f s₁)` against
// `h_{r₂}(f s₂)`: two observations put through two DIFFERENT erasure functions,
// one per run. That is only sound if `r` — the run facts — is uncorrelated with
// the secret. If a fact could be a function of the secret, the erasure keyed on
// it could cancel exactly the difference the experiment exists to find, and the
// harness would go quiet precisely when it mattered.
//
// Both fields are secret-independent BY CONSTRUCTION, which is a stronger answer
// than a correlation test could give — a test can fail to detect a correlation,
// never establish its absence:
//
// * `guest_cid` — `twosafety_boot::GUEST_CID`, a compile-time constant. The two
//   runs pass literally the same value, so it cannot carry a per-run anything,
//   let alone a per-secret one.
// * `pod_id` — `Uuid::new_v4()`, minted node-side from the CSPRNG. Random bytes
//   are not a function of the request that triggered them.
//
// If either ever becomes derived — a CID allocated from pod content, a v5 UUID
// namespaced on the spec — this argument dies silently and the erasures keyed
// on them become unsound. That is the thing to re-check before changing how
// either is minted, and it is stated here rather than in a commit message
// because the commit message is not where anyone will look.
// ---------------------------------------------------------------------------

/// Where two runs disagreed. Carries the component and a bounded excerpt of the
/// FIRST differing line — never the whole content, and never a value the caller
/// supplied as secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Divergence {
    /// Which component of the observation differed.
    pub component: &'static str,
    /// The first differing line number within that component.
    pub line: usize,
    /// A bounded excerpt, for locating the difference in a log.
    pub excerpt: String,
}

impl fmt::Display for Divergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "two runs differing only in a secret produced different {} at line {}: {}",
            self.component, self.line, self.excerpt
        )
    }
}

/// How much of a differing line to report.
const EXCERPT_BYTES: usize = 120;

/// Normalise run-to-run nondeterminism.
///
/// # The signature is the security property
///
/// **This does not take the secret.** It cannot, and that is deliberate: a
/// canonicaliser with access to the secret could erase exactly the bytes that
/// would have revealed a leak, and no test of its output would notice. Every
/// erasure here is therefore blind — it removes a syntactic class, not a value.
///
/// This is the same construction as `store_from_node_environment` not taking a
/// `PodSpec`: the guarantee is that a function cannot reach what it cannot name.
///
/// # Every rule is an erasure, so every rule needs a reason
///
/// Anything normalised away is something this harness can no longer see. A
/// canonicaliser that erased enough would make the whole comparison pass
/// vacuously — which is why `a_planted_secret_survives_canonicalisation` exists
/// and runs on every execution.
///
/// The rules, each with why the erased field cannot carry a secret:
///
/// * **pod UUID** — minted by the node before any secret is read.
/// * **guest CID** — allocated from a counter; `lowering_preserves_distinct_cids`
///   pins that it is a function of allocation order, not pod content.
/// * **leading log timestamps** — wall clock. NOT a blanket timestamp strip:
///   only a leading `[...]` or ISO-8601 prefix, so a secret that happened to
///   contain digits is untouched.
/// * **socket paths under the pod dir** — contain the pod UUID, already covered.
/// * **the embedded audit boot clock** — see [`strip_embedded_audit_clock`].
/// * **the RTC wall clock** — see [`strip_rtc_wall_clock`].
/// * **the session task token's run-scoped fields** — see
///   [`canonicalise_task_token_hex`]. The token is DECODED, not blanked: its
///   `scope.allowed_operations` / `scope.allowed_paths` stay compared, because
///   that is exactly where a policy-derived leak would land.
///
/// Nothing else is erased. In particular the rest of the kernel command line is
/// compared in full, because it is where `nucleus.auth_secret` already rides and
/// is the most likely place for a real leak.
#[must_use]
pub fn canonicalise(obs: &Observation, facts: &RunFacts) -> Canonical {
    // The warrant is derived from the machine config and ONLY from the machine
    // config, because that is the component the guest cannot write. See
    // [`Warrant`] for why that asymmetry is the whole point.
    let warrant = Warrant::from_host(&obs.machine_config);
    Canonical {
        // The host-authored component IS the warrant's source, so it needs none.
        machine_config: scrub(&obs.machine_config, facts, None),
        console: scrub(&obs.console, facts, Some(&warrant)),
    }
}

/// The high-integrity facts that authorise erasing something from the
/// comparison — and the reason rule 3c cannot be written wrongly again.
///
/// # Every canonicalisation rule is a declassification
///
/// A rule decides that some bytes will not be compared, which is a deliberate
/// release of the harness from noticing them. Robust declassification
/// (Zdancewic & Myers 2001) asks for exactly one thing of such a decision: an
/// attacker may influence **neither the decision to declassify nor the choice of
/// what is declassified**. The enforcement they give is to require the
/// *decision* to have **high integrity**.
///
/// # The rule that violated it
///
/// `normalise_truncated_cmdline_echo` erased the kernel's echo of the command
/// line on the strength of `line.starts_with("Kernel command line: ")`. The
/// console is **guest-writable** — real logs carry unprefixed guest lines such
/// as `fetched identity: spiffe://...` — so the guest chose whether the erasure
/// fired, and could hide an arbitrary value behind a forged prefix. That is not
/// a pattern that was too broad. It is a declassification whose trigger the
/// attacker controls.
///
/// # What this type does about it
///
/// A `Warrant` is constructible **only** from the machine configuration, which
/// only the node writes into the jail. There is no constructor taking console
/// text, so a rule cannot base its firing decision on guest-authored bytes by
/// reaching for one — the value it would need does not exist on that path.
///
/// The asymmetry is the invariant, so it is worth stating plainly:
///
/// * `machine_config` — written by `firecracker_config.rs`, inside the jail,
///   before the guest exists. HIGH integrity. May authorise an erasure.
/// * `console` — whatever came off `console=ttyS0`, which includes anything the
///   guest chose to print. LOW integrity. May be erased, may never authorise.
///
/// # What it still does not do
///
/// It does not stop a future rule pattern-matching guest text directly; the
/// line is still a `&str`. What it removes is the *need* to, and it makes the
/// wrong version visibly wrong — a rule that erases guest bytes without
/// consulting a warrant is now the odd one out rather than the norm.
/// `a_guest_forged_cmdline_echo_is_not_erased` pins the specific attack.
struct Warrant {
    /// The session task token exactly as the HOST wrote it into `boot_args`.
    ///
    /// `None` when the config carries no token, in which case every rule that
    /// needs one declines — failing closed, so a missing warrant erases less
    /// rather than more.
    task_token_hex: Option<String>,
}

impl Warrant {
    /// Derive the warrant from the host-authored machine configuration.
    ///
    /// Deliberately the only constructor, and deliberately private.
    fn from_host(machine_config: &str) -> Self {
        Warrant {
            task_token_hex: hex_value_of_key(machine_config, TOKEN_HEX_KEY),
        }
    }

    /// Is `candidate` the kernel's echo of the token the HOST wrote?
    ///
    /// A byte-exact prefix, because that is what a truncated echo of a value is
    /// and what a forgery is not. Verified on real artifacts: the kernel echoes
    /// 968 of the token's 1762 bytes, and the echo is a byte-exact prefix of the
    /// value in `boot_args`.
    ///
    /// Empty candidates are refused: the empty string is a prefix of everything,
    /// which would authorise erasing anything.
    fn authorises_cmdline_echo(&self, candidate: &str) -> bool {
        match &self.task_token_hex {
            Some(token) => !candidate.is_empty() && token.starts_with(candidate),
            None => false,
        }
    }
}

fn scrub(s: &str, facts: &RunFacts, warrant: Option<&Warrant>) -> String {
    s.lines()
        .map(|line| {
            let line = strip_leading_timestamp(line);
            // ORDER IS LOAD-BEARING. The task token is hex-encoded, and the pod
            // UUID rides INSIDE it as `task_id`. Decoding first is what lets the
            // pod-UUID rule below reach it; run the other way round, the hex
            // hides the UUID and every pair of boots diverges here forever.
            // `decoding_the_token_first_is_what_lets_the_pod_id_rule_reach_it`
            // pins the order.
            let line = canonicalise_task_token_hex(line);
            // Only reachable when the rule above DECLINED, i.e. the token was
            // truncated by the kernel's own echo. A complete token is decoded
            // and compared field-wise; this never sees it.
            let line = normalise_truncated_cmdline_echo(&line, warrant);
            let line = canonicalise_task_token_nonce(&line);
            // The pod UUID is long and structurally unique, so a plain
            // replacement is safe.
            let line = line.replace(&facts.pod_id, "<POD-ID>");
            // The CID is a SMALL INTEGER, so replacing it bare would corrupt any
            // text that happens to contain that digit — including a secret. It
            // is erased only in the structural position it occupies.
            // `a_secret_containing_the_cid_digit_survives` pins this; the first
            // version replaced the bare digit and would have gone blind to any
            // secret containing it.
            //
            // BOTH SPACINGS, because the shipped rule matched only the compact
            // one and the real artifact is pretty-printed. Firecracker's
            // `config.json` in the jail contains `    "guest_cid": 3,` WITH a
            // space, so this rule had NEVER FIRED on a real observation — it was
            // green only because every boot measured so far happened to be
            // allocated cid 3, making the erasure a no-op that nothing needed.
            // The first pair of boots with different CIDs would have reported a
            // permanent false divergence. Same shape as a gate that hardcodes a
            // dimension: correct-looking, and untested by construction.
            // `the_cid_rule_fires_on_a_real_pretty_printed_config` pins the
            // pretty form against a fixture copied out of a live VM.
            let line = line.replace(
                &format!("\"guest_cid\":{}", facts.guest_cid),
                "\"guest_cid\":<CID>",
            );
            let line = line.replace(
                &format!("\"guest_cid\": {}", facts.guest_cid),
                "\"guest_cid\": <CID>",
            );
            let line = strip_embedded_audit_clock(&line);
            strip_rtc_wall_clock(&line)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Remove only a LEADING timestamp, in the two forms this runtime emits.
///
/// Narrow on purpose. A blanket "strip anything that looks like a number" would
/// erase parts of a leaked secret, and the harness would go quiet exactly when
/// it mattered.
fn strip_leading_timestamp(line: &str) -> &str {
    // `[   1.234567] ...` — the kernel's printk clock.
    if let Some(rest) = line.strip_prefix('[') {
        if let Some((clock, tail)) = rest.split_once(']') {
            if !clock.is_empty()
                && clock
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '.' || c == ' ')
            {
                return tail.trim_start();
            }
        }
    }
    // `2026-08-03T12:34:56.789Z ...` — the node's structured logs.
    let b = line.as_bytes();
    if b.len() > 20 && b[4] == b'-' && b[7] == b'-' && b[10] == b'T' {
        if let Some(sp) = line.find(' ') {
            return line[sp + 1..].trim_start();
        }
    }
    line
}

// ---------------------------------------------------------------------------
// RULE 1 — the EMBEDDED boot clock.
// ---------------------------------------------------------------------------

/// The literal that opens an audit record header.
/// An Ed25519 signature is 64 bytes, the widest number array this erases.
const MAX_ERASED_ARRAY_LEN: usize = 64;

const AUDIT_OPEN: &str = "audit(";

/// The literal a kernel audit record line begins with. The rule is anchored to
/// it so a guest-authored line merely CONTAINING `audit(` is not eligible.
const AUDIT_RECORD: &str = "audit: ";
/// Widest plausible uptime in seconds (~317 years).
const BOOT_CLOCK_SECS_MAX: usize = 10;
/// `%03lu` — always three.
const BOOT_CLOCK_FRAC_LEN: usize = 3;
/// `%u` — a 32-bit serial is at most 10 digits.
const AUDIT_SERIAL_MAX: usize = 10;

/// Erase the boot-clock reading inside an `audit(SECS.MSECS:SERIAL)` header.
///
/// Measured on two real boots five days apart, this is one of exactly three
/// console lines that survived the pre-existing canonicaliser:
///
/// ```text
/// audit: type=2000 audit(0.280:1): state=initialized audit_enabled=0 res=1
/// audit: type=2000 audit(0.310:1): state=initialized audit_enabled=0 res=1
/// ```
///
/// [`strip_leading_timestamp`] cannot reach it: this clock is not in leading
/// position, it is a second reading embedded mid-line.
///
/// # WHY A SECRET CANNOT REACH THIS POSITION
///
/// Not "because it is a timestamp". Two independent reasons, and the rule is
/// sound if either holds:
///
/// 1. **Nothing can write there.** The bytes between `audit(` and `:` are
///    emitted by the guest kernel's audit subsystem, which formats every record
///    header itself from `audit_log_start` — a clock read plus a kernel-global
///    serial counter, through purely NUMERIC format specifiers. There is no
///    `%s` in that position, so no byte-string from the host, the pod spec, the
///    credential set, or the workload can be routed into it. A leak has no
///    mechanism to land between those two delimiters.
/// 2. **Only a numeric shape is erased anyway.** The replacement fires only
///    when the delimited span is `digits '.' digits` — one dot, digits on both
///    sides, nothing else. This is a syntactic class in a structural position,
///    never a value: the erasure does not know, and cannot be told, what the
///    secret is.
///
/// The record BODY (`state=initialized …`) and the serial (`:1`) are left
/// compared in full. If the serial ever diverges, this reports it rather than
/// absorbing it.
///
/// # WHAT THIS BLINDS THE HARNESS TO
///
/// A leak whose entire text is `digits.digits`, positioned immediately after a
/// literal `audit(` and immediately before a `:`. Nothing else.
fn strip_embedded_audit_clock(line: &str) -> String {
    // ANCHOR. The justification is about a kernel audit record header, so
    // require the line to BE one. Without this the rule fired on any line
    // containing the substring `audit(`, which a guest can print.
    if !line.starts_with(AUDIT_RECORD) {
        return line.to_string();
    }
    // ONE occurrence, not every match on the line. `audit_log_start` emits
    // exactly one header; looping invited a crafted line to present several
    // erasable spans.
    let Some(i) = line.find(AUDIT_OPEN) else {
        return line.to_string();
    };
    let (head, tail) = line.split_at(i + AUDIT_OPEN.len());
    // DELIMIT BY `)`, the close of the header, not by the first `:` anywhere on
    // the line. The old span ran to a colon that might belong to the record
    // body, so an arbitrarily long run could be swallowed — 93 digits in the
    // audit's demonstration.
    let Some(close) = tail.find(')') else {
        return line.to_string();
    };
    let (inner, after) = tail.split_at(close);
    let Some((clock, serial)) = inner.split_once(':') else {
        return line.to_string();
    };
    // The serial is VALIDATED as a shape check that this really is a header,
    // and then left COMPARED. Erasing it would have been a widening dressed as
    // a narrowing: if the serial ever diverges we want that reported, not
    // absorbed. The existing test caught this.
    if is_boot_clock_reading(clock) && is_bounded_digits(serial, AUDIT_SERIAL_MAX) {
        format!("{head}<BOOT-CLOCK>:{serial}{after}")
    } else {
        line.to_string()
    }
}

/// Digits, at least one, at most `max` — the width bound that turns "looks
/// numeric" into "is the field the kernel actually emits".
fn is_bounded_digits(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.bytes().all(|b| b.is_ascii_digit())
}

/// `digits '.' digits` — exactly one dot, at least one digit either side.
fn is_boot_clock_reading(s: &str) -> bool {
    match s.split_once('.') {
        // WIDTH-BOUNDED. The kernel emits `audit(%llu.%03lu:%u)` — three
        // fraction digits, always — so an unbounded run on either side was a
        // channel of unbounded width wearing a numeric costume.
        Some((secs, frac)) => {
            is_bounded_digits(secs, BOOT_CLOCK_SECS_MAX) && frac.len() == BOOT_CLOCK_FRAC_LEN
        }
        None => false,
    }
}

// ---------------------------------------------------------------------------
// RULE 2 — the RTC wall clock.
// ---------------------------------------------------------------------------

/// The driver-emitted literal that introduces the wall-clock reading.
const RTC_PREFIX: &str = ": setting system clock to ";

/// The RTC driver that emits the hand-off line. Anchoring to it is what stops
/// `anything at all: setting system clock to ...` being eligible.
const RTC_DRIVER: &str = "rtc-";
/// A Unix second is 10 digits, and 11 from the year 33658.
const RTC_EPOCH_MAX: usize = 11;

/// Erase the wall-clock reading in the RTC hand-off line.
///
/// The second of the three surviving console lines:
///
/// ```text
/// rtc-pl031 40001000.rtc: setting system clock to 2026-07-30T21:08:39 UTC (1785445719)
/// rtc-pl031 40001000.rtc: setting system clock to 2026-08-04T10:45:20 UTC (1785840320)
/// ```
///
/// # WHY A SECRET CANNOT REACH THIS POSITION
///
/// Again two independent reasons:
///
/// 1. **Nothing can write there.** The line is emitted by the guest kernel's
///    RTC-to-system-clock hand-off (`drivers/rtc/hctosys.c`) from a fixed format
///    string whose arguments are a decoded `struct rtc_time` and a `time64_t` —
///    both NUMERIC. The value originates in the emulated RTC device, which the
///    VMM backs with the host clock. No pod spec field, credential, or guest
///    byte-string has a path into that format argument.
/// 2. **Only a timestamp shape is erased anyway.** The tail must be exactly
///    `YYYY-MM-DDTHH:MM:SS UTC (digits)` and must run to end of line. A tail
///    that is one character off — including a leak appended after the reading —
///    is left compared in full, so the harness fail-LOUDS rather than absorbing.
///
/// The device prefix (`rtc-pl031 40001000.rtc`) is left compared: a leak into
/// the device name still surfaces.
///
/// # WHAT THIS BLINDS THE HARNESS TO
///
/// A leak that is byte-for-byte an ISO-8601 second-resolution timestamp followed
/// by ` UTC (digits)`, occupying the whole tail of a line that already contains
/// the literal `: setting system clock to `. Nothing else.
fn strip_rtc_wall_clock(line: &str) -> String {
    // ANCHOR. `hctosys.c` emits this through the RTC driver, so require the
    // driver name. Without it ANY line of the shape `<anything>: setting system
    // clock to ...` was eligible, and the head is guest-writable text.
    if !line.starts_with(RTC_DRIVER) {
        return line.to_string();
    }
    let Some(i) = line.find(RTC_PREFIX) else {
        return line.to_string();
    };
    let (head, tail) = line.split_at(i + RTC_PREFIX.len());
    if is_rtc_reading(tail) {
        format!("{head}<RTC-WALL-CLOCK>")
    } else {
        line.to_string()
    }
}

/// `YYYY-MM-DDTHH:MM:SS UTC (<digits>)`, and nothing after it.
fn is_rtc_reading(s: &str) -> bool {
    let Some((iso, epoch)) = s.split_once(" UTC (") else {
        return false;
    };
    let Some(digits) = epoch.strip_suffix(')') else {
        return false;
    };
    // WIDTH-BOUNDED epoch: a Unix second is 10 digits and will be 11 in the
    // year 33658. Unbounded, it absorbed 93 digits in the audit's demonstration.
    is_iso8601_second(iso) && is_bounded_digits(digits, RTC_EPOCH_MAX)
}

/// Exactly `YYYY-MM-DDTHH:MM:SS` — fixed width, fixed separators, digits
/// everywhere else. Deliberately not a date PARSER: a parser accepts a family of
/// shapes, and every extra shape it accepts is another shape a leak could wear.
fn is_iso8601_second(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 19
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18]
            .iter()
            .all(|&i| b[i].is_ascii_digit())
}

// ---------------------------------------------------------------------------
// RULE 3 — the session task token. THE ONE WITH A REAL DESIGN QUESTION.
// ---------------------------------------------------------------------------

/// The kernel-cmdline key carrying the hex-encoded session task token.
const TOKEN_HEX_KEY: &str = "nucleus.task_token_hex=";

/// The kernel-cmdline key carrying the hex-encoded effective block nonce.
const TOKEN_NONCE_KEY: &str = "nucleus.task_token_nonce=";

/// Hex width of the 16-byte block nonce (`NONCE_LEN` in the node's mint site).
const TOKEN_NONCE_HEX_LEN: usize = 32;

/// Normalise the run-scoped fields of the session task token, **by decoding it**.
///
/// This is the third surviving difference, and it accounts for two of them: the
/// `boot_args` in the machine config, and the kernel's own `Kernel command line:`
/// echo on the console — the same bytes, so one rule covers both.
///
/// # The easy answer is wrong
///
/// Blanking `nucleus.task_token_hex=<hex>` wholesale would take one line of code
/// and would make this harness permanently unable to see a leak into
/// `scope.allowed_operations` or `scope.allowed_paths` — which the token
/// carries, which are derived from the pod's resolved policy, and which are
/// therefore the single most plausible place in this token for a real leak. That
/// is an erasure of the interesting part to normalise away the boring part.
///
/// So the token is hex-decoded to its JSON, and only three fields are erased,
/// each in a fixed STRUCTURAL position and only when it wears the expected
/// syntactic class:
///
/// | field                    | position                  | erased when it is |
/// |--------------------------|---------------------------|-------------------|
/// | `nonce`                  | `blocks[i].claim.nonce`   | an array of numbers |
/// | `issued_at`              | `blocks[i].claim.issued_at` | a number        |
/// | `sig`                    | `blocks[i].sig`           | an array of numbers |
///
/// Everything else stays COMPARED: `task_id`, `scope.allowed_operations`,
/// `scope.allowed_paths`, `ttl`, `issuer_vk`, and `parent_hash`.
///
/// # WHY NONE OF THE THREE CAN CARRY THE POD SECRET
///
/// * **`nonce`** — the mint site draws it straight from the OS CSPRNG
///   (`OsRng.fill_bytes`) into a fresh `[u8; 16]` *before it reads any of its
///   arguments*, and its arguments are `(task_id, policy, ttl, now, issuer)`.
///   The pod secret is not among them. This is the same construction as
///   [`canonicalise`] not taking the secret: **a function cannot reach what it
///   cannot name.** It is also fixed-width — 16 bytes, deserialised from exactly
///   16 JSON numbers — so it is not a channel of unbounded width.
/// * **`issued_at`** — a `u64` of UNIX seconds read from the spawn site's clock.
///   The erasure fires only on a JSON *number*, so the position cannot hold a
///   string at all; a leak would have to be pre-encoded into a single 64-bit
///   integer by something that already had the secret and a channel out.
/// * **`sig`** — this one needs no trust in the mint site at all. Ed25519 is
///   DETERMINISTIC (RFC 8032): the signature is a pure function of the issuer's
///   key and `signing_bytes(task_id, claim)`, which is a serialisation of
///   `task_id` and *the whole claim*. Every input to `sig` other than `nonce`
///   and `issued_at` is a field this rule leaves compared. So `sig` carries no
///   information the harness has not already compared elsewhere, and erasing it
///   removes exactly zero comparison power. It differs between boots only
///   BECAUSE `nonce` and `issued_at` do.
///
/// # Fail-loud, never fail-quiet
///
/// If the value is not valid hex, or does not decode to UTF-8, or does not parse
/// as JSON, the ORIGINAL hex is left in place and compared in full. A malformed
/// token becomes a reported divergence, not a silent pass.
///
/// # WHAT THIS BLINDS THE HARNESS TO
///
/// A leak into the 16 CSPRNG nonce bytes, into the 64-bit `issued_at`, or — only
/// by way of those two — into the signature. Nothing in the scope, the task id,
/// the TTL, or the issuer key.
fn canonicalise_task_token_hex(line: &str) -> String {
    rewrite_hex_valued_key(line, TOKEN_HEX_KEY, |hex_value| {
        let bytes = hex::decode(hex_value).ok()?;
        let text = String::from_utf8(bytes).ok()?;
        let token: serde_json::Value = serde_json::from_str(&text).ok()?;
        // ROUND-TRIP FIDELITY, checked BEFORE any erasure.
        //
        // Decoding through `serde_json::Value` silently discards the entire
        // ENCODING layer: key order, whitespace, escape form, and — the one that
        // matters — DUPLICATE KEYS, of which the last silently wins. A token
        // carrying `{"task_id":"CANARY-AAAA","task_id":"t",...}` re-serialised
        // to the same bytes as one carrying CANARY-BBBB, so a secret smuggled
        // into the first of two duplicate keys was invisible in exactly the
        // fields this rule decodes the token in order to KEEP compared.
        //
        // So: re-serialise the UNMODIFIED token and require it to be byte-equal
        // to what was decoded. A token this runtime minted round-trips (it was
        // produced by the same serialiser); one that does not is carrying
        // information in its encoding, and this declines rather than erase it.
        // Fail-closed: declining leaves the raw hex COMPARED.
        if serde_json::to_string(&token).ok()? != text {
            return None;
        }
        let mut token = token;
        erase_run_scoped_token_fields(&mut token);
        // Compact serialisation: no interior newline can ever be produced (JSON
        // escapes them inside strings), so the line structure the whole
        // comparison rests on survives decoding.
        serde_json::to_string(&token).ok()
    })
}

/// Erase `nucleus.task_token_nonce=<hex>` whole.
///
/// # WHY THIS ONE MAY BE ERASED WHOLE
///
/// Unlike the token, this value has no interior structure to preserve: it is the
/// lowercase hex of *the very same 16 CSPRNG bytes* that
/// [`canonicalise_task_token_hex`] erases as `blocks[i].claim.nonce`. Erasing it
/// is therefore not a second erasure — it removes the duplicate encoding of one
/// already-argued field. The provenance argument is the nonce argument above:
/// drawn from `OsRng` at a call site whose arguments do not include the secret.
///
/// Still narrow: the value must be exactly 32 hex characters, the width the mint
/// site pins. A value of any other width — including one a leak lengthened — is
/// left compared in full.
///
/// # WHAT THIS BLINDS THE HARNESS TO
///
/// A leak that is exactly 32 hexadecimal characters occupying the whole value of
/// `nucleus.task_token_nonce`.
fn canonicalise_task_token_nonce(line: &str) -> String {
    rewrite_hex_valued_key(line, TOKEN_NONCE_KEY, |hex_value| {
        (hex_value.len() == TOKEN_NONCE_HEX_LEN).then(|| "<TASK-TOKEN-NONCE>".to_string())
    })
}

/// Normalise the task token in the guest kernel's **truncated** command-line
/// echo. Measured cause of the single residual difference left after rule 3.
///
/// # What is actually going on, because it is not obvious
///
/// The guest kernel echoes its command line, and truncates that echo at a fixed
/// byte width (1004 bytes on both measured boots). The cut therefore lands at a
/// **content-dependent field offset**: the run-scoped `nonce` and `issued_at`
/// serialise to different widths on different boots, so the two runs end their
/// echo holding different FRAGMENTS of the field that follows. After rule 3 has
/// erased every run-scoped field, the two lines still differ — one ends
/// `"issuer_vk":[143,178,249,216,11,158,32,167,19` and the other
/// `…,167,19,14`.
///
/// No field-wise rule can fix that, because there is no field there: there is
/// half of one. Rule 3 correctly declines (its fail-loud path), leaving the raw
/// hex compared, and the two boots diverge forever on this one line.
///
/// # WHY ERASING IT COSTS THE HARNESS NOTHING
///
/// Same shape of argument as `sig` in rule 3: **this value is a strictly lossy
/// duplicate of bytes the same [`Observation`] already compares in full.** The
/// echo is the guest kernel printing back `image.boot_args` from the machine
/// config — the very field `machine_config` carries untruncated, and which rule
/// 3 decodes there and compares field by field including
/// `scope.allowed_operations` and `scope.allowed_paths`. A leak into the token
/// is caught in `machine_config`; erasing the truncated copy of it removes no
/// comparison the harness was making.
///
/// # Narrowness
///
/// Three independent conditions, all of which must hold:
///
/// 1. the line must start with the kernel's own `Kernel command line: ` literal;
/// 2. the value must still be raw hexadecimal, i.e. rule 3 must have DECLINED to
///    decode it — a complete, parseable token was already decoded and had only
///    its run-scoped fields erased, and is left exactly as rule 3 left it;
/// 3. only the `nucleus.task_token_hex` value is touched. Everything else on the
///    echoed line — `nucleus.approval_secret`, `nucleus.workload_api_port`,
///    `console`, `init`, `panic`, `pci`, `reboot`, `ipv6.disable` — stays
///    compared in full, which is where a leak into the command line would land.
///
/// # WHAT THIS BLINDS THE HARNESS TO
///
/// Stated precisely, because it is the widest erasure in this module: a guest
/// that echoed a task token DIFFERENT from the one the host wrote into
/// `boot_args`, in the truncated region only, and only on a boot long enough to
/// truncate. Nothing about the token's own content, which `machine_config`
/// compares untruncated. If you would rather not buy that, delete this rule; the
/// residual becomes exactly one line and the other three rules are unaffected.
fn normalise_truncated_cmdline_echo(line: &str, warrant: Option<&Warrant>) -> String {
    // NO WARRANT, NO ERASURE. The host-authored component is scrubbed without
    // one — it is the warrant's own source — and nothing there needs this rule,
    // because a complete token is decoded and compared field-wise upstream.
    let Some(warrant) = warrant else {
        return line.to_string();
    };
    // The `starts_with` that used to gate this rule is deliberately gone. It was
    // a guest-forgeable string prefix, and the console is guest-writable, so it
    // let the guest decide whether the erasure fired. The gate is now the
    // warrant: does this hex match what the HOST actually wrote? A guest-authored
    // blob is not a prefix of the host's token, so the rule declines and the
    // line stays compared — which is the failure mode we want, since a line that
    // is compared can at worst produce a divergence to investigate, while a line
    // that is erased is invisible forever.
    rewrite_hex_valued_key(line, TOKEN_HEX_KEY, |hex_value| {
        warrant
            .authorises_cmdline_echo(hex_value)
            .then(|| "<TRUNCATED-CMDLINE-TOKEN-ECHO>".to_string())
    })
}

/// The first `key=<hex…>` value in `text`, using the same delimiting rule as
/// [`rewrite_hex_valued_key`].
///
/// Reads rather than rewrites, so a [`Warrant`] can be built from the
/// host-authored config without that config being modified.
fn hex_value_of_key(text: &str, key: &str) -> Option<String> {
    let i = text.find(key)?;
    let tail = &text[i + key.len()..];
    let end = tail
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(tail.len());
    let value = &tail[..end];
    (!value.is_empty()).then(|| value.to_string())
}

/// Rewrite the value of every `key=<hex…>` occurrence in `line`.
///
/// The value is delimited by the first NON-hex character, which is what makes
/// this safe on both surfaces the token appears on: the whitespace-delimited
/// kernel command line, and the same command line embedded in a JSON string in
/// `config.json` (where the closing `"` terminates it). `f` returning `None`
/// leaves the original bytes untouched — the fail-loud path.
fn rewrite_hex_valued_key(line: &str, key: &str, f: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    let mut consumed = 0usize;
    while let Some(i) = rest.find(key) {
        let (head, tail) = rest.split_at(i + key.len());
        out.push_str(head);
        // POSITIONAL ANCHOR. The key must start a command-line token — i.e. sit
        // at the start of the line or immediately after a delimiter — rather
        // than appear anywhere inside one. Unanchored, `...=x nucleus.task_token_hex=`
        // occurring INSIDE another value was eligible, so the erasure composed
        // across a line an attacker partly controls.
        let abs = consumed + i;
        let preceded_ok = abs == 0
            || line[..abs]
                .chars()
                .next_back()
                .is_some_and(|c| c == ' ' || c == '"' || c == '\t');
        consumed = abs + key.len();
        if !preceded_ok {
            rest = tail;
            continue;
        }
        let end = tail
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(tail.len());
        let (value, after) = tail.split_at(end);
        match f(value) {
            Some(replacement) => out.push_str(&replacement),
            None => out.push_str(value),
        }
        consumed += value.len();
        rest = after;
    }
    out.push_str(rest);
    out
}

/// Erase the three run-scoped token fields, each at a fixed structural path and
/// only when it wears the expected syntactic class.
///
/// Walks the path explicitly rather than searching for field NAMES, so a
/// `"nonce"` that appeared as an allowed path or an operation name — i.e. in the
/// part a leak would reach — is untouched.
fn erase_run_scoped_token_fields(token: &mut serde_json::Value) {
    let Some(blocks) = token
        .get_mut("blocks")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return;
    };
    for block in blocks.iter_mut() {
        erase_number_array(block.get_mut("sig"), "<TASK-TOKEN-SIG>");
        let Some(claim) = block.get_mut("claim") else {
            continue;
        };
        erase_number_array(claim.get_mut("nonce"), "<TASK-TOKEN-NONCE>");
        if let Some(issued_at) = claim.get_mut("issued_at") {
            if issued_at.is_number() {
                *issued_at = serde_json::Value::String("<TASK-TOKEN-ISSUED-AT>".to_string());
            }
        }
    }
}

/// Replace `slot` with `marker` iff it is a JSON array whose every element is a
/// number — the wire form of a fixed-width byte array. Anything else (a string,
/// an object, a mixed array) is left compared.
fn erase_number_array(slot: Option<&mut serde_json::Value>, marker: &str) {
    if let Some(value) = slot {
        // WIDTH-BOUNDED. `sig` is a `Vec<u8>` — unbounded at the type level — and
        // `nonce` a fixed 16 bytes, so an unbounded "all numbers" test was a
        // channel of unbounded width. An Ed25519 signature is 64 bytes; the bound
        // is the widest field this erases, so anything larger is not one of them.
        if value.as_array().is_some_and(|a| {
            a.len() <= MAX_ERASED_ARRAY_LEN && a.iter().all(serde_json::Value::is_number)
        }) {
            *value = serde_json::Value::String(marker.to_string());
        }
    }
}

/// Compare two canonical observations from runs differing only in a secret.
///
/// # Errors
/// The first component and line at which they disagree.
pub fn compare(a: &Canonical, b: &Canonical) -> Result<(), Divergence> {
    for (component, x, y) in [
        ("machine_config", &a.machine_config, &b.machine_config),
        ("console", &a.console, &b.console),
    ] {
        if let Some(d) = first_difference(component, x, y) {
            return Err(d);
        }
    }
    Ok(())
}

/// EVERY differing line, not just the first.
///
/// # "First divergence" is not "only divergence"
///
/// [`compare`] short-circuits, which is right for a gate but wrong for judging a
/// canonicalisation rule: a rule that fixes line 39 and leaves lines 112 and 185
/// alone looks identical, through `compare`, to a rule that fixed everything —
/// the reported line number just moves. Every claim in this module's rule
/// documentation about how many differences a rule removes is measured with
/// this, and a residual of zero means this returned empty, not that `compare`
/// stopped early.
#[must_use]
pub fn all_differences(a: &Canonical, b: &Canonical) -> Vec<Divergence> {
    let mut out = Vec::new();
    for (component, x, y) in [
        ("machine_config", &a.machine_config, &b.machine_config),
        ("console", &a.console, &b.console),
    ] {
        let xl: Vec<&str> = x.lines().collect();
        let yl: Vec<&str> = y.lines().collect();
        for i in 0..xl.len().max(yl.len()) {
            let (p, q) = (xl.get(i).copied(), yl.get(i).copied());
            if p != q {
                out.push(divergence_at(
                    component,
                    i + 1,
                    p.or(q).unwrap_or("<absent>"),
                ));
            }
        }
    }
    out
}

fn divergence_at(component: &'static str, line: usize, shown: &str) -> Divergence {
    let mut excerpt: String = shown.chars().take(EXCERPT_BYTES).collect();
    if shown.len() > excerpt.len() {
        excerpt.push('…');
    }
    Divergence {
        component,
        line,
        excerpt,
    }
}

fn first_difference(component: &'static str, x: &str, y: &str) -> Option<Divergence> {
    let (mut xl, mut yl) = (x.lines(), y.lines());
    let mut n = 0usize;
    loop {
        n += 1;
        match (xl.next(), yl.next()) {
            (None, None) => return None,
            (a, b) if a == b => continue,
            (a, b) => {
                return Some(divergence_at(component, n, a.or(b).unwrap_or("<absent>")));
            }
        }
    }
}

/// Read an [`Observation`] off a pod the host has already run.
///
/// # The two components, and where they come from
///
/// * `config.json` inside the jail — the machine configuration Firecracker was
///   launched with (`--config-file`, see `firecracker_config.rs`). It carries the
///   kernel command line, the drives, and the vsock device: everything the guest
///   is handed at boot.
/// * `firecracker.log` under the pod's state directory — what the guest actually
///   emitted, which is the channel `check_guest_facts` already reads.
///
/// # A missing component is an ERROR, never an empty string
///
/// An observation that silently defaulted to `""` would compare equal to another
/// empty one, and two failed boots would report "no divergence" — the
/// absence-satisfied-by-silence shape that has produced four separate defects in
/// this repo. If a component cannot be read, this fails and says which.
///
/// # Errors
/// If either component is missing or unreadable.
pub fn collect(
    config_path: &std::path::Path,
    console_path: &std::path::Path,
) -> std::io::Result<Observation> {
    let read = |p: &std::path::Path, what: &str| -> std::io::Result<String> {
        let body = std::fs::read_to_string(p).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("cannot read the {what} at {}: {e}", p.display()),
            )
        })?;
        if body.trim().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "the {what} at {} is empty; an empty observation compares equal to \
                     another empty one, so two failed boots would report no divergence",
                    p.display()
                ),
            ));
        }
        Ok(body)
    };
    Ok(Observation {
        machine_config: read(config_path, "machine config")?,
        console: read(console_path, "guest console")?,
    })
}

/// What one boot leaves behind for collection.
pub struct RunArtifacts {
    /// Path to the machine configuration Firecracker was launched with.
    pub config: std::path::PathBuf,
    /// Path to the guest console log.
    pub console: std::path::PathBuf,
    /// The run-scoped facts to canonicalise against.
    pub facts: RunFacts,
}

/// Why a 2-safety check failed.
#[derive(Debug)]
pub enum TwoSafetyError {
    /// A boot or collection failed. Distinguished from a divergence because
    /// "the experiment did not run" and "the experiment found a leak" are
    /// different answers and only one is about the system.
    Harness(String),
    /// The positive control did NOT find a planted secret, so the comparison is
    /// blind and every passing result above it is meaningless.
    ControlDidNotFire,
    /// The control runs DID diverge, but not because of the planted secret.
    ///
    /// A distinct outcome from [`Self::ControlDidNotFire`] because it is a
    /// distinct failure: the harness produced a red for a reason it cannot
    /// attribute, which certifies nothing. Against a real pod this is the
    /// likely shape — two boots differ in run-scoped values anyway — and
    /// collapsing it into "the control fired" is exactly the confound this
    /// variant exists to name.
    ControlNotAttributable(String),
}

impl fmt::Display for TwoSafetyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TwoSafetyError::Harness(m) => write!(f, "the 2-safety harness could not run: {m}"),
            TwoSafetyError::ControlDidNotFire => write!(
                f,
                "the positive control did not fire: a secret planted directly in the kernel \
                 command line was NOT detected. The comparison is blind, so a clean result \
                 from it means nothing."
            ),
            TwoSafetyError::ControlNotAttributable(m) => write!(
                f,
                "the positive control diverged but NOT because of the plant: {m}. A \
                 divergence the harness cannot attribute to the value it planted is noise \
                 that happens to be red, and certifies nothing."
            ),
        }
    }
}

/// Boot once with the given secret and hand back what it left.
///
/// Injected rather than called directly so the orchestration below is testable
/// without `/dev/kvm` — the same reason `handle_perform` takes its upstream
/// caller. Only the actual boot is CI-only; the logic is not.
pub trait Boot {
    /// Run a pod whose node environment carries `secret`, optionally planting it
    /// into the kernel command line.
    ///
    /// # Errors
    /// If the pod could not be booted or its artifacts are unavailable.
    fn boot(&mut self, secret: &str, plant_in_cmdline: bool) -> std::io::Result<RunArtifacts>;
}

fn observe(b: &mut dyn Boot, secret: &str, plant: bool) -> Result<Canonical, TwoSafetyError> {
    let a = b
        .boot(secret, plant)
        .map_err(|e| TwoSafetyError::Harness(e.to_string()))?;
    let obs = collect(&a.config, &a.console).map_err(|e| TwoSafetyError::Harness(e.to_string()))?;
    Ok(canonicalise(&obs, &a.facts))
}

/// **The positive control, and it runs FIRST.**
///
/// Plants the secret directly into the kernel command line — `image.boot_args`,
/// which is host-consumed by `firecracker_config.rs` and reaches `/proc/cmdline`
/// — and requires the comparison to find it.
///
/// Without this, a canonicaliser that erased too much, an observation that
/// collected the wrong files, or a comparison with an inverted condition would
/// all report "no leak" forever. Running it first means a blind harness is
/// reported as blind rather than as clean.
///
/// # A divergence is not evidence. An ATTRIBUTABLE divergence is.
///
/// The first version of this accepted ANY divergence between the two control
/// runs. That is a valid control against the fake `Boot`, whose two runs are
/// otherwise byte-identical, so any difference must be the plant. It is NOT
/// valid against a real pod: two boots differing in nothing still differ in
/// `nucleus.task_token_hex` and `nucleus.task_token_nonce` on the same
/// `boot_args` line, so `compare` returned `Err` at `machine_config` line 4
/// whether the plant worked or not.
///
/// It was caught by perturbation, not by reading: with the plant **completely
/// removed**, `control()` still returned `Ok`. The gate went red at the right
/// line for the wrong cause — so it certified a harness it had not tested.
///
/// The contract it needs is therefore not "the two runs differ" but "the two
/// runs differ **because of the value this function planted**". That is checked
/// three ways, and every one of them must hold:
///
/// 1. each run's canonical observation CONTAINS the value planted into it —
///    otherwise the plant never reached the observation at all;
/// 2. neither run contains the OTHER's value — which rules out a constant echo
///    that would satisfy (1) while carrying no per-run information;
/// 3. the two observations then differ.
///
/// No boot-to-boot noise can satisfy (1) and (2): nondeterminism cannot invent
/// the exact byte string this function chose, in the run that chose it and not
/// in the other.
///
/// **This does not weaken [`canonicalise`]'s guarantee.** The canonicaliser
/// still cannot name the secret. Only the control can, and only because it is
/// the thing that planted it — knowing what you planted is the definition of a
/// positive control.
///
/// # Errors
/// [`TwoSafetyError::ControlDidNotFire`] if the planted secret is not detected,
/// or is detected but not attributable to the plant.
pub fn control(b: &mut dyn Boot) -> Result<(), TwoSafetyError> {
    const PLANT_A: &str = "twosafety-control-aaaaaaaa";
    const PLANT_B: &str = "twosafety-control-bbbbbbbb";

    let a = observe(b, PLANT_A, true)?;
    let c = observe(b, PLANT_B, true)?;

    // (1) the plant reached the observation.
    if !a.contains(PLANT_A) {
        return Err(TwoSafetyError::ControlNotAttributable(
            "run A's planted value never reached its canonical observation".into(),
        ));
    }
    if !c.contains(PLANT_B) {
        return Err(TwoSafetyError::ControlNotAttributable(
            "run B's planted value never reached its canonical observation".into(),
        ));
    }
    // (2) it is per-run, not a constant echo.
    if a.contains(PLANT_B) || c.contains(PLANT_A) {
        return Err(TwoSafetyError::ControlNotAttributable(
            "each control run carries BOTH planted values, so the observation is not a \
             function of the run's own secret"
                .into(),
        ));
    }
    // (3) and it actually produces a divergence.
    match compare(&a, &c) {
        Err(_) => Ok(()),
        Ok(()) => Err(TwoSafetyError::ControlDidNotFire),
    }
}

/// Why [`check_all`] did not come back clean.
#[derive(Debug)]
pub enum CheckFailure {
    /// The experiment could not be run.
    Harness(TwoSafetyError),
    /// Every region in which the two runs disagreed — never just the first.
    Diverged(Vec<Divergence>),
}

/// [`check`], but reporting EVERY residual difference rather than the first.
///
/// # Why the first one is not enough
///
/// While a residual is being worked down, `compare`'s single answer is
/// ambiguous in the worst way: a canonicalisation rule that fixes one of three
/// differing regions is indistinguishable from one that fixes all three,
/// because either way the next run reports "a divergence" and only the line
/// number moves. That turns a partial fix into something that reads like
/// progress, and a complete fix into something that reads like failure.
///
/// It is also how a residual gets miscounted downward: measuring only the first
/// difference on two real boots reported "1 line" where the honest answer was
/// three, and the two that were not looked at were the two nobody had a rule
/// for.
///
/// # Errors
/// [`CheckFailure::Diverged`] with every differing region, or
/// [`CheckFailure::Harness`] if a boot or collection failed.
pub fn check_all(b: &mut dyn Boot) -> Result<(), CheckFailure> {
    let a = observe(b, "twosafety-secret-aaaaaaaa", false).map_err(CheckFailure::Harness)?;
    let c = observe(b, "twosafety-secret-bbbbbbbb", false).map_err(CheckFailure::Harness)?;
    let ds = all_differences(&a, &c);
    if ds.is_empty() {
        Ok(())
    } else {
        Err(CheckFailure::Diverged(ds))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The literal the guest kernel uses to echo its own command line.
    ///
    /// TEST-ONLY, and that it is test-only is the point. It used to gate rule
    /// 3c in production code — `line.starts_with(CMDLINE_ECHO)` — which handed
    /// the guest the decision to declassify, since the guest can print this
    /// prefix. The gate is now the [`Warrant`], so the literal survives only as
    /// scaffolding for building realistic console lines. The dead-code gate is
    /// what forced it here, which is the wiring check confirming the forgeable
    /// trigger really left the decision path rather than merely being bypassed.
    const CMDLINE_ECHO: &str = "Kernel command line: ";

    const SECRET_A: &str = "nucleus-e2e-canary-aaaaaaaaaaaa";
    const SECRET_B: &str = "nucleus-e2e-canary-bbbbbbbbbbbb";

    fn facts() -> RunFacts {
        RunFacts {
            pod_id: "11111111-2222-3333-4444-555555555555".into(),
            guest_cid: 3,
        }
    }

    fn other_facts() -> RunFacts {
        RunFacts {
            pod_id: "99999999-8888-7777-6666-555555555555".into(),
            guest_cid: 4,
        }
    }

    /// The machine config must reflect the RunFacts it will be canonicalised
    /// against — a fixture whose cid disagrees with its facts makes every
    /// comparison diverge for a reason that has nothing to do with the secret.
    /// The control test caught exactly that.
    fn obs_for(f: &RunFacts, cmdline: &str, console: &str) -> Observation {
        Observation {
            machine_config: format!(
                "{{\"boot_args\":\"{cmdline}\",\"vsock\":{{\"guest_cid\":{}}}}}",
                f.guest_cid
            ),
            console: console.into(),
        }
    }

    /// **The control, and it must come first.** Everything below asserts a
    /// divergence IS found; a comparator that reported one unconditionally would
    /// satisfy all of them while being useless.
    #[test]
    fn two_clean_runs_compare_equal() {
        let a = canonicalise(
            &obs_for(
                &facts(),
                "console=ttyS0",
                "[    0.100000] boot\n[    1.200000] ready",
            ),
            &facts(),
        );
        let b = canonicalise(
            &obs_for(
                &other_facts(),
                "console=ttyS0",
                "[    0.999999] boot\n[    2.500000] ready",
            ),
            &other_facts(),
        );
        assert_eq!(compare(&a, &b), Ok(()), "only nondeterminism differed");
    }

    /// **The property.** A secret reaching the kernel command line — where
    /// `nucleus.auth_secret` already rides — must surface as a divergence, with
    /// no enumeration of mechanisms anywhere in this module.
    #[test]
    fn a_secret_in_the_kernel_cmdline_is_caught() {
        let a = canonicalise(
            &obs_for(&facts(), &format!("console=ttyS0 x={SECRET_A}"), "boot"),
            &facts(),
        );
        let b = canonicalise(
            &obs_for(
                &other_facts(),
                &format!("console=ttyS0 x={SECRET_B}"),
                "boot",
            ),
            &other_facts(),
        );
        let d = compare(&a, &b).expect_err("the secret differs between runs");
        assert_eq!(d.component, "machine_config");
    }

    /// A secret reaching the guest console is caught too — the channel is not
    /// named anywhere, only the observation is.
    #[test]
    fn a_secret_on_the_console_is_caught() {
        let a = canonicalise(
            &obs_for(&facts(), "console=ttyS0", &format!("leaked {SECRET_A}")),
            &facts(),
        );
        let b = canonicalise(
            &obs_for(
                &other_facts(),
                "console=ttyS0",
                &format!("leaked {SECRET_B}"),
            ),
            &other_facts(),
        );
        let d = compare(&a, &b).expect_err("the secret differs");
        assert_eq!(d.component, "console");
    }

    /// **NON-VACUITY OF THE CANONICALISER — the one this design can die on.**
    ///
    /// Every rule in `canonicalise` is an erasure, so a canonicaliser that
    /// normalised too much would make every comparison pass. This asserts a
    /// planted secret SURVIVES canonicalisation, in each component.
    #[test]
    fn a_planted_secret_survives_canonicalisation() {
        let c = canonicalise(
            &obs_for(
                &facts(),
                &format!("console=ttyS0 x={SECRET_A}"),
                &format!("s={SECRET_A}"),
            ),
            &facts(),
        );
        assert!(
            c.machine_config.contains(SECRET_A),
            "canonicalisation erased the secret from the machine config; the harness \
             would now be blind to a real leak there"
        );
        assert!(
            c.console.contains(SECRET_A),
            "canonicalisation erased the secret from the console"
        );
    }

    /// **A secret containing the CID digit must survive.**
    ///
    /// The first canonicaliser replaced `guest_cid.to_string()` — a bare "3" —
    /// everywhere, so a secret containing a 3 would have been partially erased
    /// and the harness would have gone quiet about a real leak. The erasure is
    /// context-bound now, and this is what holds it there.
    #[test]
    fn a_secret_containing_the_cid_digit_survives() {
        let f = facts(); // guest_cid = 3
        let secret = "canary-3333-with-threes";
        let c = canonicalise(&obs_for(&f, &format!("x={secret}"), secret), &f);
        assert!(
            c.machine_config.contains(secret) && c.console.contains(secret),
            "erasing the bare CID digit corrupted a secret containing it: {} / {}",
            c.machine_config,
            c.console
        );
        assert!(
            c.machine_config.contains("\"guest_cid\":<CID>"),
            "and the structural CID must still be normalised"
        );
    }

    /// The canonicaliser CANNOT target the secret, because it never receives it.
    ///
    /// Checked against the signature rather than the behaviour: a behavioural
    /// test passes for as long as nobody adds the parameter and says nothing the
    /// moment somebody does.
    #[test]
    fn the_canonicaliser_cannot_name_the_secret() {
        let src = include_str!("twosafety.rs");
        let sig = src
            .split("pub fn canonicalise(")
            .nth(1)
            .and_then(|s| s.split(')').next())
            .expect("canonicalise signature");
        assert!(
            !sig.contains("secret") && !sig.contains("canary"),
            "canonicalise can now name the secret, so it could erase exactly the bytes \
             that would reveal a leak: {sig}"
        );
    }

    /// A timestamp difference alone is not a leak. Narrow stripping, so a secret
    /// containing digits is untouched.
    #[test]
    fn timestamps_are_stripped_but_digits_inside_a_secret_are_not() {
        assert_eq!(strip_leading_timestamp("[    1.234567] hello"), "hello");
        assert_eq!(
            strip_leading_timestamp("2026-08-03T12:34:56.789Z hello"),
            "hello"
        );
        // Not a timestamp: left alone in full.
        assert_eq!(strip_leading_timestamp("x=12345 hello"), "x=12345 hello");
        assert_eq!(
            strip_leading_timestamp("[not-a-clock] hello"),
            "[not-a-clock] hello"
        );
    }

    /// A truncated run must not compare equal to a complete one — otherwise a
    /// crashed boot passes.
    #[test]
    fn a_truncated_run_is_a_divergence() {
        let a = canonicalise(
            &obs_for(&facts(), "console=ttyS0", "boot\nready\ndone"),
            &facts(),
        );
        let b = canonicalise(
            &obs_for(&other_facts(), "console=ttyS0", "boot\nready"),
            &other_facts(),
        );
        assert!(compare(&a, &b).is_err(), "a short run is not a clean run");
    }

    /// **`compare` short-circuits; judging a canonicalisation rule must not.**
    /// Three differing lines must be reported as three, or a rule that fixed one
    /// of them would be indistinguishable from a rule that fixed all three.
    #[test]
    fn all_differences_sees_past_the_first() {
        let a = canonicalise(
            &obs_for(&facts(), "console=ttyS0", "p\nQ\nr\nS\nt\nU"),
            &facts(),
        );
        let b = canonicalise(
            &obs_for(&other_facts(), "console=ttyS0", "p\nq\nr\ns\nt\nu"),
            &other_facts(),
        );
        let all = all_differences(&a, &b);
        assert_eq!(all.len(), 3, "three differing lines: {all:?}");
        assert_eq!(
            all.iter().map(|d| d.line).collect::<Vec<_>>(),
            vec![2, 4, 6]
        );
        assert_eq!(
            compare(&a, &b).expect_err("differs").line,
            all[0].line,
            "and the first one agrees with compare"
        );
        assert!(
            all_differences(&a, &a).is_empty(),
            "an identical pair has no differences"
        );
    }

    // -----------------------------------------------------------------
    // RULE 1 — embedded audit boot clock.
    // -----------------------------------------------------------------

    /// The two lines as they actually appeared on two real boots five days
    /// apart. Verbatim, so if the kernel's format ever changes this test is what
    /// notices rather than a mystery divergence in CI.
    const AUDIT_A: &str =
        "audit: type=2000 audit(0.280:1): state=initialized audit_enabled=0 res=1";
    const AUDIT_B: &str =
        "audit: type=2000 audit(0.310:1): state=initialized audit_enabled=0 res=1";

    #[test]
    fn the_embedded_audit_boot_clock_is_normalised() {
        assert_eq!(
            strip_embedded_audit_clock(AUDIT_A),
            strip_embedded_audit_clock(AUDIT_B),
            "two real boots must agree here after the rule"
        );
        assert!(
            strip_embedded_audit_clock(AUDIT_A).contains("audit(<BOOT-CLOCK>:1)"),
            "the serial stays compared: {}",
            strip_embedded_audit_clock(AUDIT_A)
        );
        assert!(
            strip_embedded_audit_clock(AUDIT_A).contains("state=initialized audit_enabled=0 res=1"),
            "the record body stays compared in full"
        );
    }

    /// **NON-VACUITY OF RULE 1.** A secret that is itself digit-and-dot shaped —
    /// the exact class this rule erases — must survive everywhere except the one
    /// structural slot. Each case names the exact substring that must survive:
    /// the first version of this test asserted on `planted.rsplit(' ')`, which is
    /// a token no rule was ever going to touch, so it passed with the syntactic
    /// class check ripped out. A survival test that survives the mutation it
    /// exists to catch is worse than no test.
    #[test]
    fn a_planted_secret_survives_the_audit_clock_rule() {
        for (planted, must_survive) in [
            // the erased syntactic class, but NOT in the structural position
            ("audit: leak=0.310 tail", "leak=0.310"),
            // inside the record body, right of the delimiter
            (
                "audit: type=2000 audit(0.280:1): cred=0.280 res=1",
                "cred=0.280",
            ),
            // the literal is there, but the span is not the numeric class
            ("audit(canary-1234-secret:1) tail", "canary-1234-secret"),
            // a numeric-looking secret with no `audit(` in front of it
            ("leaked 10.0.0.7 canary-3.14159", "10.0.0.7"),
            // and one that is EXACTLY the class, just not after the literal
            ("cred=0.280 audit: nothing here", "cred=0.280"),
        ] {
            let got = strip_embedded_audit_clock(planted);
            assert!(
                got.contains(must_survive),
                "rule 1 erased a secret it must not touch: {planted:?} -> {got:?} \
                 (expected {must_survive:?} to survive)"
            );
        }
        // And the structural erasure is still happening — otherwise this test
        // would pass with the rule deleted.
        assert!(strip_embedded_audit_clock(AUDIT_A).contains("<BOOT-CLOCK>"));
    }

    // -----------------------------------------------------------------
    // RULE 2 — RTC wall clock.
    // -----------------------------------------------------------------

    const RTC_A: &str =
        "rtc-pl031 40001000.rtc: setting system clock to 2026-07-30T21:08:39 UTC (1785445719)";
    const RTC_B: &str =
        "rtc-pl031 40001000.rtc: setting system clock to 2026-08-04T10:45:20 UTC (1785840320)";

    #[test]
    fn the_rtc_wall_clock_is_normalised() {
        assert_eq!(
            strip_rtc_wall_clock(RTC_A),
            strip_rtc_wall_clock(RTC_B),
            "two real boots must agree here after the rule"
        );
        assert!(
            strip_rtc_wall_clock(RTC_A).starts_with("rtc-pl031 40001000.rtc: setting system"),
            "the device prefix stays compared: {}",
            strip_rtc_wall_clock(RTC_A)
        );
    }

    /// **NON-VACUITY OF RULE 2.** The shape check must be exact: anything that is
    /// not byte-for-byte `<ISO> UTC (<digits>)` running to end of line is left
    /// compared, INCLUDING a leak appended after a genuine reading.
    #[test]
    fn a_planted_secret_survives_the_rtc_rule() {
        for planted in [
            // a leak appended after a real reading — the tail no longer matches
            "rtc-pl031 40001000.rtc: setting system clock to 2026-08-04T10:45:20 UTC (1785840320) canary-aaaa",
            // the same date shape, on a line without the driver prefix
            "hostinfo: built at 2026-08-04T10:45:20 UTC (1785840320)",
            // a secret in the device-name position
            "rtc-canary-aaaa 40001000.rtc: setting system clock to 2026-08-04T10:45:20 UTC (1785840320)",
        ] {
            let got = strip_rtc_wall_clock(planted);
            assert!(
                got.contains("canary-aaaa") || got == planted,
                "rule 2 erased a secret it must not touch: {planted:?} -> {got:?}"
            );
        }
        assert_eq!(
            strip_rtc_wall_clock("hostinfo: built at 2026-08-04T10:45:20 UTC (1785840320)"),
            "hostinfo: built at 2026-08-04T10:45:20 UTC (1785840320)",
            "no driver prefix, so nothing is erased"
        );
        assert!(strip_rtc_wall_clock(RTC_A).contains("<RTC-WALL-CLOCK>"));
    }

    // -----------------------------------------------------------------
    // RULE 3 — the session task token.
    // -----------------------------------------------------------------

    /// A token in the exact wire shape the node mints (`SignedTaskRef` through
    /// `serde_json`), parameterised on everything that could differ.
    fn token_json(
        task_id: &str,
        nonce_byte: u8,
        issued_at: u64,
        sig_byte: u8,
        paths: &str,
    ) -> String {
        let bytes = |b: u8, n: usize| (0..n).map(|_| b.to_string()).collect::<Vec<_>>().join(",");
        format!(
            "{{\"task_id\":\"{task_id}\",\"blocks\":[{{\"claim\":{{\"scope\":\
             {{\"allowed_operations\":[\"read_files\",\"run_bash\"],\"allowed_paths\":[{paths}]}},\
             \"parent_hash\":null,\"nonce\":[{}],\"issued_at\":{issued_at},\"ttl\":120,\
             \"issuer_vk\":[{}]}},\"sig\":[{}]}}]}}",
            bytes(nonce_byte, 16),
            bytes(7, 32),
            bytes(sig_byte, 64),
        )
    }

    fn cmdline_with_token(
        task_id: &str,
        nonce_byte: u8,
        issued_at: u64,
        sig: u8,
        paths: &str,
    ) -> String {
        format!(
            "console=ttyS0 nucleus.workload_api_port=15012 {TOKEN_HEX_KEY}{} \
             {TOKEN_NONCE_KEY}{} nucleus.task_token_issuer=8fb2f9d8",
            hex::encode(token_json(task_id, nonce_byte, issued_at, sig, paths)),
            hex::encode([nonce_byte; 16]),
        )
    }

    /// Two boots whose tokens differ ONLY in the run-scoped fields (and the pod
    /// UUID) compare equal — the measured cause of the `boot_args` divergence
    /// and of console line 39.
    #[test]
    fn the_task_token_run_scoped_fields_are_normalised() {
        let fa = facts();
        let fb = other_facts();
        let a = scrub(
            &cmdline_with_token(&fa.pod_id, 0x8e, 1_785_445_717, 0xd0, ""),
            &fa,
            None,
        );
        let b = scrub(
            &cmdline_with_token(&fb.pod_id, 0x30, 1_785_840_318, 0x89, ""),
            &fb,
            None,
        );
        assert_eq!(a, b, "only run-scoped token fields differed");
        assert!(a.contains("<TASK-TOKEN-NONCE>"), "nonce erased: {a}");
        assert!(
            a.contains("<TASK-TOKEN-ISSUED-AT>"),
            "issued_at erased: {a}"
        );
        assert!(a.contains("<TASK-TOKEN-SIG>"), "sig erased: {a}");
    }

    /// **THE POINT OF DECODING RATHER THAN BLANKING, AND THE NON-VACUITY OF
    /// RULE 3.**
    ///
    /// The one-line version of this rule — blank `nucleus.task_token_hex=<hex>`
    /// — would pass every other test in this file and would make the harness
    /// permanently blind to a leak into the token's scope. The scope is derived
    /// from the pod's resolved policy, so it is the most plausible leak site in
    /// the whole token. This asserts the scope is still COMPARED.
    #[test]
    fn a_secret_in_the_token_scope_survives_and_is_caught() {
        let fa = facts();
        let fb = other_facts();
        let a = scrub(
            &cmdline_with_token(&fa.pod_id, 0x8e, 1_785_445_717, 0xd0, "\"/x/canary-aaaa\""),
            &fa,
            None,
        );
        let b = scrub(
            &cmdline_with_token(&fb.pod_id, 0x30, 1_785_840_318, 0x89, "\"/x/canary-bbbb\""),
            &fb,
            None,
        );
        assert!(
            a.contains("canary-aaaa"),
            "the token scope was erased; the harness is now blind to a policy leak: {a}"
        );
        assert_ne!(a, b, "a leak into scope.allowed_paths must still diverge");
        // The operations dimension too — the other half of TokenScope.
        assert!(
            a.contains("read_files") && a.contains("run_bash"),
            "allowed_operations must stay compared: {a}"
        );
        // ...and the fields that are NOT run-scoped.
        assert!(a.contains("\"ttl\":120"), "ttl stays compared: {a}");
        assert!(a.contains("\"issuer_vk\""), "issuer_vk stays compared: {a}");
        assert!(
            a.contains("\"parent_hash\":null"),
            "parent_hash is deliberately NOT erased: {a}"
        );
    }

    /// **ORDER IS LOAD-BEARING.** The pod UUID rides inside the token as
    /// `task_id`, hex-encoded. If the token rule ran after the pod-UUID
    /// replacement instead of before it, the UUID would stay hidden in hex and
    /// every pair of boots would diverge here forever.
    #[test]
    fn decoding_the_token_first_is_what_lets_the_pod_id_rule_reach_it() {
        let f = facts();
        let out = scrub(&cmdline_with_token(&f.pod_id, 1, 1, 1, ""), &f, None);
        assert!(
            out.contains("\"task_id\":\"<POD-ID>\""),
            "the pod UUID inside the decoded token must be normalised: {out}"
        );
        assert!(
            !out.contains(&f.pod_id),
            "the raw pod UUID must not survive: {out}"
        );
    }

    /// **FAIL-LOUD, NOT FAIL-QUIET.** A token value that is not decodable hex, or
    /// not JSON, is left COMPARED IN FULL. A canonicaliser that swallowed
    /// malformed input would turn "the token was corrupted" into "no divergence".
    #[test]
    fn a_malformed_task_token_is_compared_not_erased() {
        for value in [
            format!("{TOKEN_HEX_KEY}deadbee"), // odd-length hex
            format!("{TOKEN_HEX_KEY}{}", hex::encode("not json")), // decodes, not JSON
            TOKEN_HEX_KEY.to_string(),         // empty value
        ] {
            assert_eq!(
                canonicalise_task_token_hex(&value),
                value,
                "a malformed token must be left compared in full"
            );
        }
    }

    /// The nonce key is erased only at its pinned width. A value a leak
    /// lengthened is left compared.
    #[test]
    fn the_task_token_nonce_is_erased_only_at_its_pinned_width() {
        assert_eq!(
            canonicalise_task_token_nonce(&format!("{TOKEN_NONCE_KEY}{}", "a".repeat(32))),
            format!("{TOKEN_NONCE_KEY}<TASK-TOKEN-NONCE>")
        );
        for wrong in ["a".repeat(31), "a".repeat(33), String::new()] {
            let line = format!("{TOKEN_NONCE_KEY}{wrong}");
            assert_eq!(
                canonicalise_task_token_nonce(&line),
                line,
                "width {} is not the pinned nonce width, so it stays compared",
                wrong.len()
            );
        }
        // A 32-hex-char value under a DIFFERENT key is untouched — the erasure
        // is bound to the structural position, not to the shape alone.
        let other = format!("nucleus.approval_secret={}", "a".repeat(32));
        assert_eq!(canonicalise_task_token_nonce(&other), other);
    }

    /// **RULE 3c fires only on a TRUNCATED echo, and only on the echo.** A
    /// complete token is decoded and compared field-wise wherever it appears; if
    /// this rule ever started firing on complete tokens it would silently take
    /// the scope out of the comparison, which is the exact failure rule 3 exists
    /// to avoid.
    #[test]
    fn the_truncated_echo_rule_never_touches_a_complete_token() {
        let f = facts();
        let complete = format!(
            "{CMDLINE_ECHO}{}",
            cmdline_with_token(&f.pod_id, 1, 1, 1, "\"/x/canary-aaaa\"")
        );
        let out = scrub(&complete, &f, None);
        assert!(
            out.contains("canary-aaaa"),
            "a COMPLETE echoed token must still be compared field-wise: {out}"
        );
        assert!(
            !out.contains("<TRUNCATED-CMDLINE-TOKEN-ECHO>"),
            "rule 3c must not fire on a complete token: {out}"
        );

        // Truncated: the hex is cut mid-JSON, so rule 3 declines and 3c fires —
        // but ONLY under a warrant derived from what the host actually wrote.
        let hex = hex::encode(token_json(&f.pod_id, 1, 1, 1, ""));
        let host_cfg = format!("\"boot_args\":\"{TOKEN_HEX_KEY}{hex}\"");
        let w = Warrant::from_host(&host_cfg);
        let truncated = format!(
            "{CMDLINE_ECHO}console=ttyS0 {TOKEN_HEX_KEY}{}",
            &hex[..hex.len() / 2]
        );
        let out = scrub(&truncated, &f, Some(&w));
        assert!(
            out.contains("<TRUNCATED-CMDLINE-TOKEN-ECHO>"),
            "a truncated token must be normalised: {out}"
        );
        assert!(
            out.contains("console=ttyS0"),
            "the rest of the echo stays compared: {out}"
        );

        // WITHOUT the warrant the rule declines. The host-authored component is
        // scrubbed with `None`, and failing closed there means erasing less.
        assert!(
            !scrub(&truncated, &f, None).contains("<TRUNCATED-CMDLINE-TOKEN-ECHO>"),
            "no warrant must mean no erasure"
        );
    }

    /// **The attack rule 3c used to permit, as a test.**
    ///
    /// The console is guest-writable — real logs carry unprefixed guest lines
    /// such as `fetched identity: spiffe://...` — and the old rule fired on
    /// `line.starts_with("Kernel command line: ")`, a string prefix the guest
    /// can forge. So a guest could emit that prefix followed by
    /// `nucleus.task_token_hex=<hex of anything>` and have its bytes erased
    /// from the comparison. Two runs carrying DIFFERENT smuggled values
    /// canonicalised IDENTICALLY, which is a leak the harness is blind to by
    /// construction.
    ///
    /// Robust declassification names the defect exactly: the decision to
    /// declassify must have high integrity, and a guest-authored prefix has
    /// none. The rule now asks the [`Warrant`] — derived only from the
    /// host-written machine config — whether the hex is a prefix of the token
    /// the host actually wrote. A forged blob is not, so the rule declines and
    /// the line stays compared.
    ///
    /// The two runs below differ ONLY in the smuggled value. If they
    /// canonicalise equal, the attack works.
    #[test]
    fn a_guest_forged_cmdline_echo_is_not_erased() {
        let f = facts();
        let real = hex::encode(token_json(&f.pod_id, 1, 1, 1, ""));
        let host_cfg = format!("\"boot_args\":\"{TOKEN_HEX_KEY}{real}\"");
        let w = Warrant::from_host(&host_cfg);

        // Guest-authored: the echo literal is forged, and the "token" is the
        // secret. `6161…`/`6262…` are hex for "aaaa…"/"bbbb…".
        let forged = |smuggled: &str| {
            format!(
                "{CMDLINE_ECHO}{TOKEN_HEX_KEY}{}",
                hex::encode(smuggled.as_bytes())
            )
        };
        let a = scrub(&forged("canary-aaaa"), &f, Some(&w));
        let b = scrub(&forged("canary-bbbb"), &f, Some(&w));

        assert_ne!(
            a, b,
            "a guest-forged echo must stay COMPARED; erasing it hides whatever the \
             guest chose to put there"
        );
        assert!(
            !a.contains("<TRUNCATED-CMDLINE-TOKEN-ECHO>"),
            "the erasure must not fire on a value the host never wrote: {a}"
        );
    }

    /// **The width and anchor attacks, as tests.**
    ///
    /// Both rules were gated on a SHAPE ("looks like a clock") while their
    /// justification was about POSITION and PROVENANCE ("the kernel emits this
    /// field, in this record, and nothing else can write there"). A shape gate
    /// with no width bound is a channel of unbounded width wearing a numeric
    /// costume; a shape gate with no anchor fires on any line a guest can print.
    #[test]
    fn the_clock_rules_are_anchored_and_width_bounded() {
        // A REAL uuid shape. An earlier version of this test used pod_id "p",
        // a single character that occurs in `type=2000`, so the pod-ID rule
        // rewrote the line and the assertions failed for a reason that had
        // nothing to do with the clocks. A fixture unlike the real input tests
        // something unlike the real system.
        let f = RunFacts {
            pod_id: "aeb31452-ce64-468b-abf4-ea5f23378519".into(),
            guest_cid: 3,
        };
        let long = "1".repeat(93);

        // UNANCHORED: a guest-authored line merely CONTAINING `audit(`.
        let forged = format!("fetched identity: audit({long}.123:1) x");
        assert_eq!(
            scrub(&forged, &f, None),
            forged,
            "the audit rule must require a real audit record, not a substring"
        );

        // WIDTH: even in a real record, an over-long run is not the field the
        // kernel emits and must not be absorbed.
        let wide = format!("audit: type=2000 audit({long}.123:1): x");
        assert_eq!(
            scrub(&wide, &f, None),
            wide,
            "an unbounded digit run is not a boot clock"
        );
        let frac = "audit: type=2000 audit(0.1234567:1): x";
        assert_eq!(
            scrub(frac, &f, None),
            frac,
            "the kernel emits exactly three fraction digits"
        );

        // The genuine article still normalises, or the assertions above pass
        // for the boring reason that the rule never fires at all.
        let real = "audit: type=2000 audit(0.310:1): state=initialized";
        let out = scrub(real, &f, None);
        assert!(
            out.contains("<BOOT-CLOCK>"),
            "the real header must normalise: {out}"
        );
        assert!(out.contains(":1)"), "the serial stays compared: {out}");

        // RTC: unanchored head, and an unbounded epoch.
        let rtc_forged =
            format!("fetched identity: setting system clock to 2026-08-04T10:45:20 UTC ({long})");
        assert_eq!(
            scrub(&rtc_forged, &f, None),
            rtc_forged,
            "the rtc rule must require the driver name"
        );
        let rtc_wide = format!(
            "rtc-pl031 40001000.rtc: setting system clock to 2026-08-04T10:45:20 UTC ({long})"
        );
        assert_eq!(
            scrub(&rtc_wide, &f, None),
            rtc_wide,
            "an unbounded epoch is not a Unix second"
        );
        let rtc_real =
            "rtc-pl031 40001000.rtc: setting system clock to 2026-08-04T10:45:20 UTC (1785840320)";
        assert!(
            scrub(rtc_real, &f, None).contains("<RTC-WALL-CLOCK>"),
            "the real rtc line must normalise"
        );
    }

    /// **The encoding-layer channel, as a test.**
    ///
    /// Decoding through `serde_json::Value` discards key order, whitespace and
    /// DUPLICATE KEYS — last wins. So a token carrying
    /// `{"task_id":"CANARY-AAAA","task_id":"t",...}` re-serialised to the same
    /// bytes as one carrying CANARY-BBBB, and the secret was invisible in
    /// exactly the field this rule decodes the token in order to KEEP compared.
    ///
    /// The round-trip fidelity check declines any token whose encoding carries
    /// information, leaving the raw hex compared. Fail-closed.
    #[test]
    fn a_secret_in_a_duplicate_key_is_not_swallowed() {
        let f = RunFacts {
            pod_id: "aeb31452-ce64-468b-abf4-ea5f23378519".into(),
            guest_cid: 3,
        };
        let dup = |smuggled: &str| {
            let json = format!("{{\"task_id\":\"{smuggled}\",\"task_id\":\"t\",\"blocks\":[]}}");
            format!("console=ttyS0 {TOKEN_HEX_KEY}{}", hex::encode(json))
        };
        let a = scrub(&dup("canary-aaaa"), &f, None);
        let b = scrub(&dup("canary-bbbb"), &f, None);
        assert_ne!(
            a, b,
            "a secret in the FIRST of two duplicate keys must stay compared; the \
             re-serialisation drops it and both runs collapse to the same bytes"
        );
    }

    /// An oversized number array is not one of the fields this erases.
    #[test]
    fn an_oversized_number_array_is_not_erased() {
        let f = RunFacts {
            pod_id: "aeb31452-ce64-468b-abf4-ea5f23378519".into(),
            guest_cid: 3,
        };
        let wide = |seed: u16| {
            let nums: Vec<String> = (0..200).map(|i| ((i + seed) % 251).to_string()).collect();
            let json = format!(
                "{{\"blocks\":[{{\"sig\":[{}],\"claim\":{{}}}}]}}",
                nums.join(",")
            );
            format!("console=ttyS0 {TOKEN_HEX_KEY}{}", hex::encode(json))
        };
        assert_ne!(
            scrub(&wide(1), &f, None),
            scrub(&wide(2), &f, None),
            "a 200-element array is not a signature and must stay compared"
        );
    }

    /// **Two rules each correct alone, wrong composed.**
    ///
    /// Rule 3 decodes the task token so `scope.allowed_paths` stays COMPARED —
    /// that is the whole reason it decodes rather than blanks. Rule 1 then runs
    /// over the same line, and before it was anchored it would eat a
    /// `digits.digits` span inside those very paths, re-introducing the
    /// blindness rule 3 exists to avoid.
    ///
    /// The `audit: ` anchor added to rule 1 fixes this for free: a decoded token
    /// rides a command-line, never a kernel audit record, so rule 1 cannot reach
    /// it. This pins that the composition stays safe.
    #[test]
    fn rule_1_does_not_eat_paths_that_rule_3_decoded_to_keep() {
        let f = RunFacts {
            pod_id: "aeb31452-ce64-468b-abf4-ea5f23378519".into(),
            guest_cid: 3,
        };
        let with_path = |p: &str| {
            let json = format!(
                "{{\"blocks\":[{{\"claim\":{{\"scope\":{{\"allowed_paths\":[\"{p}\"]}}}}}}]}}"
            );
            format!("console=ttyS0 {TOKEN_HEX_KEY}{}", hex::encode(json))
        };
        // The secret must sit INSIDE the span rule 1 erases, or this test passes
        // for the boring reason. A first version used "/data/audit(0.310:aaaa"
        // — no closing paren, so rule 1 declined whether or not it was anchored,
        // and removing the anchor did not turn the test red. The clock field
        // itself is the erased span, so that is where the secret goes.
        let a = scrub(&with_path("/data/audit(1.111:1)"), &f, None);
        let b = scrub(&with_path("/data/audit(2.222:1)"), &f, None);
        assert_ne!(
            a, b,
            "rule 1 must not reach inside a decoded token's allowed_paths"
        );
        assert!(
            !a.contains("<BOOT-CLOCK>"),
            "the boot-clock erasure fired inside a token path: {a}"
        );
    }

    /// The warrant refuses the empty string, which is a prefix of everything and
    /// would therefore authorise erasing anything.
    #[test]
    fn an_empty_candidate_is_not_warranted() {
        let w = Warrant::from_host("\"boot_args\":\"nucleus.task_token_hex=abcdef\"");
        assert!(!w.authorises_cmdline_echo(""));
        assert!(w.authorises_cmdline_echo("abc"));
        assert!(!w.authorises_cmdline_echo("abd"));
    }

    /// **NON-VACUITY OF RULE 3c.** Everything on the echoed command line other
    /// than the truncated token value is still compared — including the key a
    /// real secret already rides on.
    #[test]
    fn a_planted_secret_on_the_echoed_cmdline_survives_rule_3c() {
        let f = facts();
        let hex = hex::encode(token_json(&f.pod_id, 1, 1, 1, ""));
        let line = format!(
            "{CMDLINE_ECHO}console=ttyS0 nucleus.approval_secret=canary-aaaa \
             nucleus.leak=canary-bbbb {TOKEN_HEX_KEY}{}",
            &hex[..hex.len() / 2]
        );
        let out = scrub(&line, &f, None);
        assert!(
            out.contains("canary-aaaa") && out.contains("canary-bbbb"),
            "rule 3c erased more than the token value: {out}"
        );
    }

    /// A field NAMED `nonce` inside the part a leak would reach must survive —
    /// the erasure walks a structural path, it does not hunt for field names.
    #[test]
    fn a_secret_named_like_a_run_scoped_field_survives() {
        let f = facts();
        let out = scrub(
            &cmdline_with_token(&f.pod_id, 1, 1, 1, "\"/etc/nonce/canary-aaaa\",\"/sig\""),
            &f,
            None,
        );
        assert!(
            out.contains("/etc/nonce/canary-aaaa") && out.contains("/sig"),
            "name-based erasure would have eaten these: {out}"
        );
    }

    /// The report names the section and does not print the secret.
    #[test]
    fn a_divergence_report_locates_without_disclosing() {
        let long = format!("{SECRET_A}{}", "z".repeat(400));
        let a = canonicalise(&obs_for(&facts(), "console=ttyS0", &long), &facts());
        let b = canonicalise(
            &obs_for(&other_facts(), "console=ttyS0", "clean"),
            &other_facts(),
        );
        let d = compare(&a, &b).expect_err("differs");
        assert!(d.excerpt.chars().count() <= EXCERPT_BYTES + 1, "bounded");
        assert!(format!("{d}").contains("console"), "names the component");
    }
}

#[cfg(test)]
mod collection {
    use super::*;

    fn write(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).expect("write fixture");
        p
    }

    /// The control: a complete pair reads back exactly.
    #[test]
    fn a_complete_pair_is_collected() {
        let d = tempfile::tempdir().expect("tempdir");
        let c = write(d.path(), "config.json", "{\"boot_args\":\"console=ttyS0\"}");
        let l = write(d.path(), "firecracker.log", "[    0.1] boot");
        let o = collect(&c, &l).expect("both present");
        assert!(o.machine_config.contains("boot_args"));
        assert!(o.console.contains("boot"));
    }

    /// **A missing component must fail, not default to empty.** Two failed boots
    /// both yielding `""` would compare equal and report no divergence — which is
    /// the failure shape this whole harness exists to avoid.
    #[test]
    fn a_missing_component_is_an_error() {
        let d = tempfile::tempdir().expect("tempdir");
        let l = write(d.path(), "firecracker.log", "boot");
        let err = collect(&d.path().join("absent.json"), &l).expect_err("no config");
        assert!(
            format!("{err}").contains("machine config"),
            "names which: {err}"
        );
    }

    /// An EMPTY component is the same hazard wearing a different hat: the file
    /// exists, so a naive read succeeds, and the comparison goes quiet.
    #[test]
    fn an_empty_component_is_an_error() {
        let d = tempfile::tempdir().expect("tempdir");
        let c = write(d.path(), "config.json", "   \n");
        let l = write(d.path(), "firecracker.log", "boot");
        let err = collect(&c, &l).expect_err("empty config");
        assert!(
            format!("{err}").contains("no divergence"),
            "says why: {err}"
        );
    }

    /// End to end on fixtures: two runs differing only in a planted secret are
    /// collected, canonicalised, and the divergence is found. This is S4's
    /// positive control at the file level — the booted-pod version lands with
    /// the harness.
    #[test]
    fn a_planted_secret_is_found_end_to_end() {
        let d = tempfile::tempdir().expect("tempdir");
        let mk = |n: &str, secret: &str, cid: u32| {
            let c = write(
                d.path(),
                &format!("config{n}.json"),
                &format!("{{\"boot_args\":\"console=ttyS0 nucleus.x={secret}\",\"vsock\":{{\"guest_cid\":{cid}}}}}"),
            );
            let l = write(d.path(), &format!("log{n}.log"), "[    0.1] boot");
            (c, l)
        };
        let (ca, la) = mk("a", "secret-aaaa", 3);
        let (cb, lb) = mk("b", "secret-bbbb", 4);
        let fa = RunFacts {
            pod_id: "aaaaaaaa-0000-0000-0000-000000000000".into(),
            guest_cid: 3,
        };
        let fb = RunFacts {
            pod_id: "bbbbbbbb-0000-0000-0000-000000000000".into(),
            guest_cid: 4,
        };
        let a = canonicalise(&collect(&ca, &la).expect("a"), &fa);
        let b = canonicalise(&collect(&cb, &lb).expect("b"), &fb);
        let dv = compare(&a, &b).expect_err("the planted secret differs");
        assert_eq!(dv.component, "machine_config");
    }
}

#[cfg(test)]
mod orchestration {
    use super::*;
    use std::io;

    /// A booter backed by fixtures. `leak` decides whether the secret reaches
    /// the console — i.e. whether the system under test is broken.
    struct Fake {
        dir: tempfile::TempDir,
        n: u32,
        leak: bool,
        honour_plant: bool,
    }

    impl Fake {
        fn new(leak: bool, honour_plant: bool) -> Self {
            Fake {
                dir: tempfile::tempdir().expect("tempdir"),
                n: 0,
                leak,
                honour_plant,
            }
        }
    }

    impl Boot for Fake {
        fn boot(&mut self, secret: &str, plant: bool) -> io::Result<RunArtifacts> {
            self.n += 1;
            let cid = 2 + self.n;
            let cmd = if plant && self.honour_plant {
                format!("console=ttyS0 nucleus.x={secret}")
            } else {
                "console=ttyS0".to_string()
            };
            let config = self.dir.path().join(format!("c{}.json", self.n));
            std::fs::write(
                &config,
                format!("{{\"boot_args\":\"{cmd}\",\"vsock\":{{\"guest_cid\":{cid}}}}}"),
            )?;
            let console = self.dir.path().join(format!("l{}.log", self.n));
            let body = if self.leak {
                format!("[    0.1] boot\n[    0.2] cred={secret}")
            } else {
                format!("[    0.{}] boot\n[    0.2] ready", self.n)
            };
            std::fs::write(&console, body)?;
            Ok(RunArtifacts {
                config,
                console,
                facts: RunFacts {
                    pod_id: format!("{:08}-0000-0000-0000-000000000000", self.n),
                    guest_cid: cid,
                },
            })
        }
    }

    /// **The control, first.** A sound system passes the check.
    #[test]
    fn a_system_that_does_not_leak_passes() {
        let mut b = Fake::new(false, true);
        assert!(check_all(&mut b).is_ok());
    }

    /// A system that puts the secret on the console fails, with no mechanism
    /// named anywhere in this module.
    #[test]
    fn a_leak_to_the_console_is_caught() {
        let mut b = Fake::new(true, true);
        match check_all(&mut b) {
            Err(CheckFailure::Diverged(ds)) => assert_eq!(ds[0].component, "console"),
            other => panic!("expected a divergence, got {other:?}"),
        }
    }

    /// The positive control fires when the plant works.
    #[test]
    fn the_control_fires_on_a_planted_secret() {
        let mut b = Fake::new(false, true);
        assert!(control(&mut b).is_ok(), "a planted secret must be detected");
    }

    /// **The meta-check, and the reason `control` exists at all.** If planting is
    /// broken, the control must report BLINDNESS rather than passing — otherwise
    /// a harness that sees nothing looks exactly like a system that leaks
    /// nothing.
    #[test]
    fn a_broken_plant_is_reported_as_blindness_not_as_clean() {
        let mut b = Fake::new(false, /* honour_plant */ false);
        match control(&mut b) {
            Err(TwoSafetyError::ControlDidNotFire | TwoSafetyError::ControlNotAttributable(_)) => {}
            other => panic!("a blind harness must not look clean, got {other:?}"),
        }
    }

    /// **The confound that a fake `Boot` cannot exhibit, and the real system
    /// does.**
    ///
    /// `control` used to accept ANY divergence between its two runs. Against
    /// `Fake` that is sound — its two runs are otherwise byte-identical, so a
    /// difference must be the plant. Against a real pod it is not: two boots
    /// differing in NOTHING still differ in `nucleus.task_token_hex` and
    /// `nucleus.task_token_nonce`, so `compare` returned `Err` at
    /// `machine_config` line 4 whether the plant worked or not. With the plant
    /// completely removed, `control()` still returned `Ok`.
    ///
    /// `NoisyUnplanted` reproduces exactly that shape in-process: per-run noise
    /// that canonicalisation does NOT erase, and no plant. The old contract
    /// passes it. The attributable contract must not — the divergence is real
    /// and is not the plant's.
    ///
    /// This is the whole reason `Canonical::contains` exists.
    #[test]
    fn per_run_noise_is_not_mistaken_for_the_plant() {
        struct NoisyUnplanted {
            dir: tempfile::TempDir,
            n: u32,
        }
        impl Boot for NoisyUnplanted {
            fn boot(&mut self, _secret: &str, _plant: bool) -> io::Result<RunArtifacts> {
                self.n += 1;
                // Per-run token, exactly like the real `nucleus.task_token_nonce`:
                // differs every boot, is NOT the planted secret, and no rule here
                // erases it.
                let config = self.dir.path().join(format!("c{}.json", self.n));
                std::fs::write(
                    &config,
                    format!(
                        "{{\"boot_args\":\"console=ttyS0 run_nonce=deadbeef{:04}\",\
                          \"vsock\":{{\"guest_cid\":3}}}}",
                        self.n
                    ),
                )?;
                let console = self.dir.path().join(format!("l{}.log", self.n));
                std::fs::write(&console, "[    0.1] boot\n")?;
                Ok(RunArtifacts {
                    config,
                    console,
                    facts: RunFacts {
                        pod_id: format!("{:08}-0000-0000-0000-000000000000", self.n),
                        guest_cid: 3,
                    },
                })
            }
        }

        let mut b = NoisyUnplanted {
            dir: tempfile::tempdir().expect("tempdir"),
            n: 0,
        };
        // Sanity: the two runs really do diverge, so the OLD contract ("any
        // divergence means the control fired") would have returned Ok here.
        // Without this the test could pass for the boring reason.
        let a = observe(&mut b, "twosafety-control-aaaaaaaa", true).expect("run A");
        let c = observe(&mut b, "twosafety-control-bbbbbbbb", true).expect("run B");
        assert!(
            compare(&a, &c).is_err(),
            "premise: the two runs must diverge, or this test proves nothing"
        );

        let mut b2 = NoisyUnplanted {
            dir: tempfile::tempdir().expect("tempdir"),
            n: 0,
        };
        match control(&mut b2) {
            Err(TwoSafetyError::ControlNotAttributable(_)) => {}
            other => panic!(
                "a divergence that is NOT the plant must not certify the harness, got {other:?}"
            ),
        }
    }

    /// The CID rule must fire on the artifact Firecracker actually writes.
    ///
    /// The shipped rule matched only `"guest_cid":3`; the real jailed
    /// `config.json` is pretty-printed and contains `"guest_cid": 3` WITH a
    /// space, so the erasure had never once fired on a real observation. It
    /// looked correct and was untested by construction — every boot measured so
    /// far was allocated cid 3, which made the rule a no-op nothing needed.
    ///
    /// The two runs below differ ONLY in the CID, in the real spacing. If the
    /// rule does not fire they diverge, which is the permanent false positive
    /// this would have produced on the first pair of boots with different CIDs.
    #[test]
    fn the_cid_rule_fires_on_a_real_pretty_printed_config() {
        // Shape copied from a live pod's /srv/jailer/.../root/config.json.
        let pretty = |cid: u32| Observation {
            machine_config: format!(
                "{{\n    \"vsock\": {{\n        \"guest_cid\": {cid},\n        \
                 \"uds_path\": \"/v.sock\"\n    }}\n}}"
            ),
            console: String::new(),
        };
        let a = canonicalise(
            &pretty(3),
            &RunFacts {
                pod_id: "p".into(),
                guest_cid: 3,
            },
        );
        let b = canonicalise(
            &pretty(4),
            &RunFacts {
                pod_id: "p".into(),
                guest_cid: 4,
            },
        );
        assert!(
            compare(&a, &b).is_ok(),
            "the CID rule does not fire on the pretty-printed form Firecracker writes, \
             so two boots with different CIDs diverge forever"
        );
    }

    /// ...and the pretty form must not erase a secret that merely contains the
    /// digit, for the same reason the compact form must not.
    #[test]
    fn the_pretty_cid_rule_does_not_swallow_a_secret_containing_the_digit() {
        let obs = |cid: u32, secret: &str| Observation {
            machine_config: format!("{{\"guest_cid\": {cid}, \"x\": \"{secret}\"}}"),
            console: String::new(),
        };
        let f = RunFacts {
            pod_id: "p".into(),
            guest_cid: 3,
        };
        let a = canonicalise(&obs(3, "secret-3-aaa"), &f);
        let b = canonicalise(&obs(3, "secret-3-bbb"), &f);
        assert!(
            compare(&a, &b).is_err(),
            "a secret containing the cid digit must still be compared"
        );
    }

    /// A boot failure is a HARNESS error, not a clean result. "The experiment did
    /// not run" and "the experiment found nothing" are different answers.
    #[test]
    fn a_failed_boot_is_not_a_pass() {
        struct Broken;
        impl Boot for Broken {
            fn boot(&mut self, _: &str, _: bool) -> io::Result<RunArtifacts> {
                Err(io::Error::other("no /dev/kvm"))
            }
        }
        match check_all(&mut Broken) {
            Err(CheckFailure::Harness(TwoSafetyError::Harness(m))) => assert!(m.contains("kvm")),
            other => panic!("expected Harness, got {other:?}"),
        }
    }
}

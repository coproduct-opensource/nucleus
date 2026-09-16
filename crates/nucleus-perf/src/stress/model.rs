//! The sequential semantics of one session's calls, as MEASURED against the proxy
//! with `--clients 1` before being used to judge concurrent histories.

use super::Policy;
use super::linearize::SeqModel;

pub const INITIAL_A: &str = "alpha";
pub const INITIAL_B: &str = "bravo";

static MOCK_ADDR: std::sync::OnceLock<std::net::SocketAddr> = std::sync::OnceLock::new();

pub fn set_mock_addr(addr: std::net::SocketAddr) {
    let _ = MOCK_ADDR.set(addr);
}

pub fn mock_addr() -> std::net::SocketAddr {
    MOCK_ADDR
        .get()
        .copied()
        .unwrap_or_else(|| std::net::SocketAddr::from(([127, 0, 0, 1], 9)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum File {
    A,
    B,
    /// A path every profile blocks.
    Key,
}

impl File {
    pub fn path(self) -> &'static str {
        match self {
            File::A => "a.txt",
            File::B => "b.txt",
            File::Key => ".ssh/id_rsa",
        }
    }
}

/// The bytes written for value `v`. Padded to `STRESS_VALUE_BYTES` (default a few
/// bytes) so a non-atomic write has a window a concurrent read can land in.
pub fn contents(v: u8) -> String {
    let pad = std::env::var("STRESS_VALUE_BYTES")
        .ok()
        .and_then(|n| n.parse::<usize>().ok())
        .unwrap_or(0);
    format!("value-{v}{}", "x".repeat(pad))
}

#[derive(Debug, Clone, Copy)]
pub enum Op {
    Read(File),
    Write(File, u8),
    Glob,
    Run,
    /// Fetch from the local web server. On the wire one call; to the model, a
    /// decision (this op) and, if admitted, a later [`Op::Delivered`].
    Fetch,
    /// A fetch's untrusted content reaching the session. Not a request: every
    /// admitted fetch in a history is paired with one, sharing its interval.
    Delivered,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Out {
    pub status: u16,
    pub code: Option<String>,
    pub contents: Option<String>,
}

impl Out {
    fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
    fn refused(&self, kind: &str) -> bool {
        self.status == 403 && self.code.as_deref().is_some_and(|c| c.starts_with(kind))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Session {
    policy: Policy,
    a: String,
    b: String,
    /// A fetch was ADMITTED: the session holds the untrusted-content leg, so a
    /// write completes the trifecta and goes to approval — even before the
    /// content itself is delivered.
    exposed: bool,
    /// Untrusted web content has been DELIVERED into the session.
    tainted: bool,
    /// The denial circuit breaker tripped: consecutive denials put the whole
    /// process into lockdown, and mutating calls are refused until an operator
    /// restores it.
    locked: bool,
}

impl Session {
    pub fn initial(policy: Policy) -> Self {
        Self {
            policy,
            a: INITIAL_A.to_string(),
            b: INITIAL_B.to_string(),
            exposed: false,
            tainted: false,
            locked: false,
        }
    }

    fn file(&self, f: File) -> &str {
        match f {
            File::A => &self.a,
            File::B | File::Key => &self.b,
        }
    }
}

impl SeqModel for Session {
    type Op = Op;
    type Out = Out;

    fn step(&self, op: &Op, out: &Out) -> Option<Self> {
        // Failing closed is allowed anywhere and changes nothing: the session's
        // budget running out (measured at 8 clients, 480 calls), a request over the
        // body limit (measured with 8 MB values: every write 413, before any effect),
        // or rate limiting.
        if matches!(
            (out.status, out.code.as_deref()),
            (402, Some("budget_exhausted")) | (413, _) | (429, _)
        ) {
            return Some(self.clone());
        }
        let same = || Some(self.clone());
        // The circuit breaker. Its counter is not linearizable (an allow's reset
        // races concurrent denials), so WHEN it trips is not modelled: a mutating call
        // may be refused by lockdown at any point. What is modelled is that it is
        // sticky — once any call has seen lockdown, no later mutating call succeeds.
        let mutating = matches!(op, Op::Write(..) | Op::Run | Op::Fetch);
        if mutating && out.code.as_deref() == Some("lockdown") {
            return Some(Session {
                locked: true,
                ..self.clone()
            });
        }
        if mutating && self.locked {
            return None;
        }
        match (self.policy, op) {
            // The path lattice refuses a blocked path first, tainted or not.
            (_, Op::Read(File::Key) | Op::Write(File::Key, _)) => {
                out.refused("kernel_denied").then(same)?
            }
            (_, Op::Glob) => out.ok().then(same)?,

            // ── Under a compiled grant: no taint source, commands run. ──
            (Policy::Grant, Op::Read(f)) => {
                (out.ok() && out.contents.as_deref() == Some(self.file(*f))).then(same)?
            }
            (Policy::Grant, Op::Write(f, v)) => out.ok().then(|| self.written(*f, *v)),
            (Policy::Grant, Op::Run) => out.ok().then(same)?,
            (Policy::Grant, Op::Fetch) => (!out.ok()).then(same)?,

            // ── Trifecta. Taint takes effect when untrusted content is DELIVERED,
            //    not when its fetch is decided: two fetches decided before either
            //    delivers are both admitted (measured: concurrent fetches both 200).
            //    Once delivered, reads, writes, commands and further fetches are all
            //    refused by information flow control, and that never reverts. ──
            (_, Op::Delivered) => Some(Session {
                tainted: true,
                ..self.clone()
            }),
            (Policy::Trifecta, _) if self.tainted => out.refused("ifc_denied").then(same)?,
            // Measured only concurrently: a write decided after a fetch was
            // admitted but before its content was delivered. Private data, untrusted
            // content and an exfiltration vector are all present, and the kernel
            // defers to a person. Sequentially the content is always delivered
            // first, and taint's refusal wins.
            (Policy::Trifecta, Op::Write(..)) if self.exposed => {
                out.refused("approval_required").then(same)?
            }
            (Policy::Trifecta, Op::Read(f)) => {
                (out.ok() && out.contents.as_deref() == Some(self.file(*f))).then(same)?
            }
            (Policy::Trifecta, Op::Write(f, v)) => out.ok().then(|| self.written(*f, *v)),
            // `research-web` grants no commands: refused by the ceiling before taint.
            (Policy::Trifecta, Op::Run) => out.refused("kernel_denied").then(same)?,
            (Policy::Trifecta, Op::Fetch) => out.ok().then(|| Session {
                exposed: true,
                ..self.clone()
            }),
        }
    }

    /// Under a grant each file is its own register. Under the trifecta, taint couples
    /// every call that reads or writes session state, so they share one partition.
    fn partition(&self, op: &Op) -> Option<u64> {
        match (self.policy, op) {
            (_, Op::Glob | Op::Read(File::Key) | Op::Write(File::Key, _)) => None,
            (Policy::Trifecta, _) => Some(0),
            (Policy::Grant, Op::Read(File::A) | Op::Write(File::A, _)) => Some(0),
            (Policy::Grant, Op::Read(File::B) | Op::Write(File::B, _)) => Some(1),
            (Policy::Grant, Op::Run | Op::Fetch | Op::Delivered) => None,
        }
    }
}

impl Session {
    fn written(&self, f: File, v: u8) -> Self {
        let mut next = self.clone();
        match f {
            File::A => next.a = contents(v),
            File::B | File::Key => next.b = contents(v),
        }
        next
    }
}

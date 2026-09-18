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

#[cfg(test)]
mod tests {
    use super::*;

    /// A response the model can be stepped with. `status` is what the proxy
    /// returned; `code` its error name; `contents` the body a read saw.
    fn out(status: u16, code: Option<&str>, contents: Option<&str>) -> Out {
        Out {
            status,
            code: code.map(str::to_owned),
            contents: contents.map(str::to_owned),
        }
    }
    fn ok_body(body: &str) -> Out {
        out(200, None, Some(body))
    }
    fn ok() -> Out {
        out(200, None, None)
    }
    fn refusal(code: &str) -> Out {
        out(403, Some(code), None)
    }
    fn grant() -> Session {
        Session::initial(Policy::Grant)
    }
    fn trifecta() -> Session {
        Session::initial(Policy::Trifecta)
    }

    /// Failing closed is allowed anywhere and changes nothing. A model that
    /// refused these would call a busy proxy a violation.
    #[test]
    fn a_closed_failure_is_admissible_after_any_op_and_moves_nothing() {
        for o in [
            out(402, Some("budget_exhausted"), None),
            out(413, None, None),
            out(429, None, None),
        ] {
            let s = grant();
            assert_eq!(s.step(&Op::Write(File::A, 7), &o), Some(s.clone()), "{o:?}");
        }
    }

    /// The breaker's counter is not linearizable, so WHEN it trips is not
    /// modelled -- only that it is sticky. This is the half that has teeth: once
    /// lockdown has been seen, a later mutating success is a violation.
    #[test]
    fn lockdown_is_sticky_and_a_later_mutating_success_is_refused() {
        let locked = grant()
            .step(&Op::Run, &refusal("lockdown"))
            .expect("lockdown is admissible");
        assert!(locked.step(&Op::Write(File::A, 1), &ok()).is_none());
        assert!(locked.step(&Op::Run, &ok()).is_none());
        // A read is not mutating, so it is still judged on its own terms.
        assert!(
            locked
                .step(&Op::Read(File::A), &ok_body(INITIAL_A))
                .is_some()
        );
    }

    /// The path lattice is checked before anything else, under either policy.
    #[test]
    fn a_blocked_path_is_refused_first_whatever_the_policy() {
        for s in [grant(), trifecta()] {
            assert!(
                s.step(&Op::Read(File::Key), &refusal("kernel_denied"))
                    .is_some()
            );
            // Serving it would be the violation the whole harness exists to catch.
            assert!(s.step(&Op::Read(File::Key), &ok_body("secret")).is_none());
        }
    }

    #[test]
    fn under_a_grant_each_file_is_its_own_register() {
        let s = grant();
        assert!(s.step(&Op::Read(File::A), &ok_body(INITIAL_A)).is_some());
        // A read that returns something the model did not write is not linearizable.
        assert!(
            s.step(&Op::Read(File::A), &ok_body("something else"))
                .is_none()
        );
        let after = s
            .step(&Op::Write(File::A, 3), &ok())
            .expect("a write under a grant succeeds");
        assert!(
            after
                .step(&Op::Read(File::A), &ok_body(&contents(3)))
                .is_some()
        );
        // B is untouched by a write to A: separate registers, separate partitions.
        assert!(
            after
                .step(&Op::Read(File::B), &ok_body(INITIAL_B))
                .is_some()
        );
        assert_eq!(s.partition(&Op::Read(File::A)), Some(0));
        assert_eq!(s.partition(&Op::Read(File::B)), Some(1));
    }

    /// `research-web` grants no commands, and a grant profile has no taint source.
    #[test]
    fn a_grant_runs_commands_and_admits_no_fetch() {
        let s = grant();
        assert!(s.step(&Op::Run, &ok()).is_some());
        assert!(s.step(&Op::Fetch, &refusal("kernel_denied")).is_some());
        // An admitted fetch under a grant is a hole in the profile.
        assert!(s.step(&Op::Fetch, &ok()).is_none());
    }

    /// Taint takes effect when content is DELIVERED, not when its fetch is
    /// decided -- the distinction the concurrent measurement forced.
    #[test]
    fn taint_arrives_with_delivery_and_never_reverts() {
        let fetched = trifecta()
            .step(&Op::Fetch, &ok())
            .expect("a fetch is admitted under the trifecta");
        // Exposed but not yet tainted: a read still succeeds.
        assert!(
            fetched
                .step(&Op::Read(File::A), &ok_body(INITIAL_A))
                .is_some()
        );
        // A write in that window goes to a person, not to the file.
        assert!(
            fetched
                .step(&Op::Write(File::A, 1), &refusal("approval_required"))
                .is_some()
        );
        assert!(fetched.step(&Op::Write(File::A, 1), &ok()).is_none());

        let tainted = fetched
            .step(&Op::Delivered, &ok())
            .expect("delivery is always admissible");
        for op in [Op::Read(File::A), Op::Write(File::A, 2), Op::Fetch] {
            assert!(
                tainted.step(&op, &refusal("ifc_denied")).is_some(),
                "{op:?}"
            );
            assert!(
                tainted.step(&op, &ok()).is_none(),
                "{op:?} must not succeed"
            );
        }
        // Still tainted after another refusal: it never reverts.
        let later = tainted
            .step(&Op::Read(File::A), &refusal("ifc_denied"))
            .expect("refused");
        assert!(
            later
                .step(&Op::Read(File::A), &ok_body(INITIAL_A))
                .is_none()
        );
    }

    #[test]
    fn the_trifecta_shares_one_partition_and_refuses_commands_outright() {
        let s = trifecta();
        assert!(s.step(&Op::Run, &refusal("kernel_denied")).is_some());
        assert_eq!(s.partition(&Op::Read(File::A)), Some(0));
        assert_eq!(s.partition(&Op::Write(File::B, 1)), Some(0));
        // Ops with no session state are outside every partition.
        assert_eq!(s.partition(&Op::Glob), None);
        assert_eq!(s.partition(&Op::Read(File::Key)), None);
        assert_eq!(grant().partition(&Op::Run), None);
    }

    #[test]
    fn a_glob_is_judged_only_on_its_status() {
        assert!(grant().step(&Op::Glob, &ok()).is_some());
        assert!(grant().step(&Op::Glob, &refusal("kernel_denied")).is_none());
    }

    #[test]
    fn a_files_path_and_a_values_bytes_are_what_the_harness_writes() {
        assert_eq!(File::A.path(), "a.txt");
        assert_eq!(File::Key.path(), ".ssh/id_rsa");
        assert!(contents(5).starts_with("value-5"));
    }
}

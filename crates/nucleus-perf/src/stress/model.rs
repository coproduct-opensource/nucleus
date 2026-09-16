//! The sequential semantics of one session's calls — a HYPOTHESIS, calibrated
//! against the proxy with `--clients 1` before it is used to judge concurrency.

use super::linearize::SeqModel;

pub const INITIAL_A: &str = "alpha";
pub const INITIAL_B: &str = "bravo";

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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Out {
    pub status: u16,
    pub code: Option<String>,
    pub contents: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Session {
    a: String,
    b: String,
}

impl Session {
    pub fn initial() -> Self {
        Self {
            a: INITIAL_A.to_string(),
            b: INITIAL_B.to_string(),
        }
    }
}

impl SeqModel for Session {
    type Op = Op;
    type Out = Out;

    fn step(&self, op: &Op, out: &Out) -> Option<Self> {
        let ok = (200..300).contains(&out.status);
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
        match op {
            // Refused by the path lattice before anything is touched, whatever else
            // has happened in the session.
            Op::Read(File::Key) | Op::Write(File::Key, _) => (out.status == 403
                && out
                    .code
                    .as_deref()
                    .is_some_and(|c| c.starts_with("kernel_denied")))
            .then(|| self.clone()),
            Op::Read(File::A) => {
                (ok && out.contents.as_deref() == Some(&self.a)).then(|| self.clone())
            }
            Op::Read(File::B) => {
                (ok && out.contents.as_deref() == Some(&self.b)).then(|| self.clone())
            }
            Op::Write(f, v) => ok.then(|| {
                let mut next = self.clone();
                match f {
                    File::A => next.a = contents(*v),
                    File::B | File::Key => next.b = contents(*v),
                }
                next
            }),
            Op::Glob | Op::Run => ok.then(|| self.clone()),
        }
    }

    /// Each file is its own register; the blocked path, glob and run touch no
    /// modelled state.
    fn partition(op: &Op) -> Option<u64> {
        match op {
            Op::Read(File::A) | Op::Write(File::A, _) => Some(0),
            Op::Read(File::B) | Op::Write(File::B, _) => Some(1),
            Op::Read(File::Key) | Op::Write(File::Key, _) | Op::Glob | Op::Run => None,
        }
    }
}

//! `nucleus-action-key` — the key a CI gate's receipt is stored under.
//!
//! # Why a key at all
//!
//! `ci/fly-runner/README.md` measured one green merge-group run as 33 jobs
//! with **44 minutes of work and 401 minutes of queue wait** — 27 of them
//! finish in 90 seconds or less and waited 10 to 18 minutes each for a slot,
//! and 6-second gate jobs waited 44 to 60 minutes. Caching the *work* attacks
//! the 44 minutes. Only answering a check without taking a runner slot attacks
//! the 401, and answering requires knowing when a previous answer still holds.
//!
//! That is this key. Two runs with the same key must have the same verdict, or
//! a receipt reused under it is a green check for work nobody did on the code
//! in question.
//!
//! # What goes into it, and why each part is not optional
//!
//! * **The read-set** — the files the gate reads, enumerated by the host from
//!   the git tree, each with its blob digest. The gate never gets to say what
//!   it read; see "The assertion this does not take" below.
//! * **The gate itself** — the workflow file's own digest and every gate
//!   script it invokes. Without this a gate that was *weakened* keeps
//!   answering green out of its stronger self's history, which is the one
//!   failure that makes the whole scheme worse than no cache at all.
//! * **The toolchain** — the pinned compiler. A gate is a function of what
//!   runs it, and `cargo clippy` under two nightlies is two gates.
//!
//! Every part is absorbed tag-separated and length-prefixed, so no two
//! distinct inputs share a preimage by concatenation, and none of it goes
//! through `Debug` — `scripts/check-preimage-dylint.sh` is the standing gate
//! on that.
//!
//! # Where the read-set comes from
//!
//! The workflow's own `paths:` filter. This is not a new declaration invented
//! for caching: GitHub *already* uses it to decide whether to run the job at
//! all, so keying a receipt on it extends no trust the repository does not
//! already extend every day.
//!
//! It does make an existing silent defect loud. `dylint-separation.yml`
//! carries the comment that *egress has run in this job since #2348 and was
//! never in the filter, so a change confined to that lint did not trigger the
//! job that gates it.* Today nothing notices a wrong filter. Under a receipt
//! store it becomes a receipt reused when it should not have been — which is
//! exactly what the shadow lane is for, and why that lane ships before
//! anything answers a check.
//!
//! # The refusal
//!
//! A job with no `paths:` filter reads *everything*, and a key over everything
//! is a key that never hits. [`Refusal::Unfiltered`] says so by name rather
//! than inventing a filter, because an invented filter is a receipt that lies.
//! Naming them is the audit; guessing at them is the defect.
//!
//! # The assertion this does not take
//!
//! Gatehouse refuses a cross-tree hit outright — a receipt is a hit only at
//! the tree it was minted at — and `docs/hard-cut.md` gives the reason: its
//! scope hash is *the pod's own assertion*, and the tree binding is what
//! stands between a cache hit and a replay. This key is not that shape. The
//! host holds the tree and enumerates the selection itself; nothing the pod
//! says enters the key. That is the difference, and it is the only reason a
//! cross-tree hit is admissible here at all.
//!
//! It is still weaker in the other direction: gatehouse *proves* its selection
//! complete by exhibiting the directory under its git oid, and this trusts a
//! hand-written glob. The shadow lane measures that gap rather than asserting
//! it away.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};

/// Domain separator. Versioned: a change to how the parts are chosen is a new
/// key space, not a silent reinterpretation of the old one.
const DOMAIN: &str = "nucleus/ci-action-key/v1";

/// One file the gate reads, as the host enumerated it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReadEntry {
    /// Repo-relative path.
    pub path: String,
    /// The content digest of the file at that path.
    pub digest: [u8; 32],
}

/// What a gate reads, what it is, and what it runs on.
///
/// Fields are public and the struct is exhaustively destructured in
/// [`ActionKey::derive`], so a field added here is a compile error until
/// someone says whether it belongs in the key. That is the same discipline
/// `nucleus_spec::identity::program_digest` uses, and for the same reason: the
/// silent failure mode of a digest is a field that quietly stopped counting.
#[derive(Debug, Clone)]
pub struct Inputs {
    /// The status-check context this key is for.
    pub context: String,
    /// The files matching the job's `paths:` filter, with their digests.
    /// Sorted by path; [`ActionKey::derive`] sorts rather than trusting.
    pub read_set: Vec<ReadEntry>,
    /// The gate's own code: the workflow file and every gate script it runs.
    pub gate: Vec<ReadEntry>,
    /// The pinned toolchain, as `(name, value)` pairs.
    pub toolchain: Vec<(String, String)>,
}

/// Why a context has no key.
///
/// A refusal is a first-class result, not an error to be logged and stepped
/// past. Each variant names something a person has to decide; none of them has
/// a safe default that a program could pick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The job declares no `paths:` filter, so its read-set is the whole tree.
    Unfiltered { context: String, workflow: String },
    /// No job in any workflow produces this context.
    NoProducer { context: String },
    /// More than one job produces it, so "the gate" is ambiguous.
    ManyProducers {
        context: String,
        producers: Vec<String>,
    },
    /// The job declares only `paths-ignore:`. That is a read-set of
    /// *everything except*, which is unbounded in the same way as no filter at
    /// all: a file added anywhere outside the ignore list silently joins it.
    IgnoreOnly { context: String, workflow: String },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::Unfiltered { context, workflow } => write!(
                f,
                "{context}: {workflow} declares no `paths:` filter, so its read-set is the whole \
                 tree and a key over it would never hit. Declare what the job reads."
            ),
            Refusal::NoProducer { context } => {
                write!(f, "{context}: no job produces this context")
            }
            Refusal::ManyProducers { context, producers } => write!(
                f,
                "{context}: {} jobs produce it ({}), so which gate this key is about is ambiguous",
                producers.len(),
                producers.join(", ")
            ),
            Refusal::IgnoreOnly { context, workflow } => write!(
                f,
                "{context}: {workflow} declares only `paths-ignore:`. A read-set of \
                 everything-except grows silently whenever a file is added outside the ignore \
                 list, so it cannot key a receipt."
            ),
        }
    }
}

/// The key itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionKey([u8; 32]);

impl ActionKey {
    /// Derive the key from its inputs.
    ///
    /// The read-set and the gate set are sorted here rather than trusted to
    /// arrive sorted: the caller enumerates a filesystem, and directory order
    /// is not a property anyone should have to remember to normalise.
    #[must_use]
    pub fn derive(inputs: &Inputs) -> Self {
        // Exhaustive destructure: a new field is an E0027 here, which is the
        // point. See the doc comment on `Inputs`.
        let Inputs {
            context,
            read_set,
            gate,
            toolchain,
        } = inputs;

        let mut hasher = Sha256::new();
        let mut absorb = |tag: &str, bytes: &[u8]| {
            hasher.update(tag.as_bytes());
            hasher.update(b"\x00");
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        };

        absorb("domain", DOMAIN.as_bytes());
        absorb("context", context.as_bytes());

        let mut absorb_set =
            |tag_count: &str, tag_path: &str, tag_digest: &str, set: &[ReadEntry]| {
                let mut sorted = set.to_vec();
                sorted.sort();
                absorb(tag_count, &(sorted.len() as u64).to_be_bytes());
                for e in &sorted {
                    absorb(tag_path, e.path.as_bytes());
                    absorb(tag_digest, &e.digest);
                }
            };
        absorb_set("read_count", "read_path", "read_digest", read_set);
        absorb_set("gate_count", "gate_path", "gate_digest", gate);

        let mut pins = toolchain.to_vec();
        pins.sort();
        absorb("pin_count", &(pins.len() as u64).to_be_bytes());
        for (name, value) in &pins {
            absorb("pin_name", name.as_bytes());
            absorb("pin_value", value.as_bytes());
        }

        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        Self(out)
    }

    /// The key as lowercase hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// The raw digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for ActionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

pub mod census;
pub mod derive;

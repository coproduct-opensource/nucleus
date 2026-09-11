//! `Act` — one targeted vocabulary for the protected boundary (ADR 0006, C2).
//!
//! # The problem this solves
//!
//! [`Operation`] is thirteen untargeted verbs: `ReadFiles`, not `Read(path)`.
//! Because the verb carries no payload, the target travels beside it as a
//! `subject: &str` through gate after gate, and every gate that needs the
//! target parses the string again. For a URL that means several independent
//! parses of one request inside a single handler — and several parsers of one
//! URL are several chances to disagree about which host is being contacted.
//! That is a parse-differential surface, not untidiness.
//!
//! `Act` closes it by carrying the target in the variant. A boundary parses
//! once, builds the `Act`, and every gate downstream reads the carried target
//! instead of re-deriving it.
//!
//! # It wraps; it does not replace
//!
//! `Act` adds no variant to [`Operation`] or to
//! [`nucleus_ifc_kernel::SinkClass`]. Both projections are derived by
//! exhaustive match, so the two enums remain the single source of truth, the
//! hand-maintained Aeneas mirror in `nucleus-ifc-kernel` is untouched, and
//! nothing here can drift from what the kernel proves.
//!
//! # Only admissible pairs are representable
//!
//! `discharge::operation_allowed_for_sink` decides which of the 13 × 19 = 247
//! `(Operation, SinkClass)` pairs a bundle can be earned for. Exactly 27 pass.
//! That relation is a runtime predicate: nothing stops a caller from building
//! an [`ActionTerm`](nucleus_ifc_kernel::ActionTerm) naming one of the other
//! 220 and finding out at preflight.
//!
//! `Act` makes the relation structural. Where a verb admits more than one
//! sink, the variant carries a sink enum containing *only* that verb's
//! admissible sinks — [`ReadSink`], [`WriteSink`], [`EditSink`], [`PodSink`].
//! An inadmissible pair is not constructible, and
//! `act_projects_onto_exactly_the_admissible_pairs` proves the projection of
//! every shape is precisely the 27 the kernel admits — two computations of one
//! number, neither written down twice.
//!
//! # Why the sink is chosen, not defaulted
//!
//! There is an existing default, [`nucleus_ifc_kernel::default_sink_class`],
//! and `Act` deliberately does not use it: for `ReadFiles`, `GlobSearch` and
//! `GrepSearch` it returns `SecretRead`, a pair the kernel's own
//! `operation_allowed_for_sink` **refuses**, so `try_bundle_for(op,
//! default_sink_class(op))` is `None` for every read.
//! `the_default_sink_of_a_read_is_a_pair_the_kernel_refuses` pins that, and
//! the defect is real rather than theoretical: ten production callers inherit
//! the mapping. Both sides are covered by passing tests today — the default
//! has one, the relation has another — which is exactly why nothing failed.
//!
//! Fixing the default changes classification for every one of those callers
//! and belongs in its own change. What `Act` does here is refuse to inherit
//! it: a caller picks from a type that offers only sinks the kernel admits,
//! so no `Act` can carry the broken pairing forward.
//!
//! # Dependency-free, on purpose
//!
//! This crate is translated to Lean by Aeneas and carries no parser. So
//! [`Endpoint`] holds a URL's *already-extracted* components rather than a
//! `url::Url`. That is the design, not a limitation: the parse belongs at the
//! boundary that receives the request, exactly once, and what travels inward
//! is the result.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use nucleus_ifc_kernel::{Operation, SinkClass};

// ───────────────────────────────────────────────────────────────────────────
// Targets
// ───────────────────────────────────────────────────────────────────────────

/// A filesystem path, as the boundary received it.
///
/// Newtyped rather than a bare `String` so a path cannot be passed where a
/// pattern or a remote is expected — the confusion `subject: &str` allows.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FilePath(String);

/// A glob or regex pattern.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pattern(String);

/// A command as its argument vector, never as a shell string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Argv(Vec<String>);

/// A search query.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Query(String);

/// A git remote.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Remote(String);

/// A commit message or pull-request title.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Message(String);

/// The identifier of a pod or child agent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PodId(String);

/// An HTTP endpoint, parsed once.
///
/// The whole point of this type is that the parse happened at the boundary and
/// its result travels inward. A gate asking "which host is this?" reads
/// [`Endpoint::host`]; it does not parse [`Endpoint::as_str`] again and get a
/// second, possibly different answer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    method: String,
    scheme: String,
    host: String,
    port: u16,
    path: String,
    raw: String,
}

macro_rules! string_target {
    ($($t:ident),* $(,)?) => {$(
        impl $t {
            /// Wrap a target the boundary received.
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// The target as the boundary received it.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl core::fmt::Display for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(&self.0)
            }
        }
    )*};
}
string_target!(FilePath, Pattern, Query, Remote, Message, PodId);

impl Argv {
    /// Wrap an argument vector.
    #[must_use]
    pub fn new(args: impl Into<Vec<String>>) -> Self {
        Self(args.into())
    }

    /// The arguments.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.0
    }

    /// The program, when there is one.
    #[must_use]
    pub fn program(&self) -> Option<&str> {
        self.0.first().map(String::as_str)
    }
}

impl core::fmt::Display for Argv {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0.join(" "))
    }
}

impl Endpoint {
    /// Build from components a boundary parser already extracted.
    ///
    /// `method` is upper-cased here so a gate comparing it never has to decide
    /// whether to do so itself — the disagreement this type exists to prevent,
    /// in miniature.
    #[must_use]
    pub fn new(
        method: &str,
        scheme: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        path: impl Into<String>,
        raw: impl Into<String>,
    ) -> Self {
        Self {
            method: method.to_uppercase(),
            scheme: scheme.into(),
            host: host.into(),
            port,
            path: path.into(),
            raw: raw.into(),
        }
    }

    /// The HTTP method, upper-cased.
    #[must_use]
    pub fn method(&self) -> &str {
        &self.method
    }

    /// The scheme (`http`, `https`).
    #[must_use]
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The host, without the port.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port, defaulted by the boundary from the scheme when absent.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The path component.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// `host:port`, the shape a DNS allowlist matches.
    #[must_use]
    pub fn authority(&self) -> String {
        let mut s = String::with_capacity(self.host.len() + 6);
        s.push_str(&self.host);
        s.push(':');
        s.push_str(&self.port.to_string());
        s
    }

    /// The URL as the boundary received it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl core::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.raw)
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Per-verb sinks — the admissible sinks of one verb, and no others
// ───────────────────────────────────────────────────────────────────────────

/// Where reading can land.
///
/// A read structurally produces no write, but it can trigger an audit event,
/// populate a cache, or be persisted to agent memory. Those three are what
/// `operation_allowed_for_sink` accepts for `ReadFiles`, `GlobSearch` and
/// `GrepSearch`; every other sink is incoherent for a read and is therefore
/// absent here rather than rejected later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ReadSink {
    /// The read is recorded in the audit log.
    AuditLog,
    /// The read is persisted to agent memory (cross-session taint vector).
    Memory,
    /// The read populates a cache.
    Cache,
}

/// Where a file write can land.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WriteSink {
    /// A project file inside the workspace.
    Workspace,
    /// A system file outside the workspace.
    System,
    /// The proposed (unverified) storage lane.
    ProposedTable,
    /// The verified storage lane (requires witness / human promotion).
    VerifiedTable,
    /// A cache layer.
    Cache,
    /// A search index.
    SearchIndex,
    /// The audit log.
    AuditLog,
}

/// Where an in-place edit can land.
///
/// Narrower than [`WriteSink`]: an edit rewrites an existing file, so the
/// storage lanes, the cache and the index — which a write can create — are not
/// among its sinks. That asymmetry is the kernel's, mirrored here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EditSink {
    /// A project file inside the workspace.
    Workspace,
    /// A system file outside the workspace.
    System,
}

/// What managing a pod touches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PodSink {
    /// Mutating cloud infrastructure (deploy, scale, delete).
    Cloud,
    /// Bringing a child agent into being.
    AgentSpawn,
}

// ───────────────────────────────────────────────────────────────────────────
// The sum
// ───────────────────────────────────────────────────────────────────────────

/// A verb together with the thing it acts on.
///
/// One variant per [`Operation`], so [`Act::operation`] is total by
/// construction and no verb can be reached without naming a target.
///
/// Deliberately **not** `#[non_exhaustive]`. The point of this type is that
/// adding a verb breaks every match on it, so no gate can silently acquire a
/// case it does not handle — the compile error is the mechanism, and
/// `#[non_exhaustive]` would replace it with a `_` arm that swallows the new
/// verb in every downstream crate.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Act {
    /// Read a file.
    Read {
        /// The file being read.
        path: FilePath,
        /// Where the read lands.
        sink: ReadSink,
    },
    /// Write a file.
    Write {
        /// The file being written.
        path: FilePath,
        /// Where the write lands.
        sink: WriteSink,
    },
    /// Edit a file in place.
    Edit {
        /// The file being edited.
        path: FilePath,
        /// Where the edit lands.
        sink: EditSink,
    },
    /// Execute a command.
    Run {
        /// The command's argument vector.
        argv: Argv,
    },
    /// Search for files matching a pattern.
    Glob {
        /// The glob pattern.
        pattern: Pattern,
        /// Where the search's record lands.
        sink: ReadSink,
    },
    /// Search file contents.
    Grep {
        /// The regex pattern.
        pattern: Pattern,
        /// Where the search's record lands.
        sink: ReadSink,
    },
    /// Search the web.
    Search {
        /// The query.
        query: Query,
    },
    /// Fetch a URL.
    Fetch {
        /// The endpoint, parsed once at the boundary.
        endpoint: Endpoint,
    },
    /// Create a git commit.
    Commit {
        /// The commit message.
        message: Message,
    },
    /// Push to a git remote.
    Push {
        /// The remote being pushed to.
        remote: Remote,
    },
    /// Open a pull request.
    OpenPr {
        /// The pull request's title.
        title: Message,
    },
    /// Manage a pod.
    ManagePod {
        /// The pod being managed.
        pod: PodId,
        /// What the management touches.
        sink: PodSink,
    },
    /// Spawn a child agent.
    Spawn {
        /// The child's identifier.
        agent: PodId,
    },
}

impl Act {
    /// The verb, derived.
    #[must_use]
    pub fn operation(&self) -> Operation {
        match self {
            Act::Read { .. } => Operation::ReadFiles,
            Act::Write { .. } => Operation::WriteFiles,
            Act::Edit { .. } => Operation::EditFiles,
            Act::Run { .. } => Operation::RunBash,
            Act::Glob { .. } => Operation::GlobSearch,
            Act::Grep { .. } => Operation::GrepSearch,
            Act::Search { .. } => Operation::WebSearch,
            Act::Fetch { .. } => Operation::WebFetch,
            Act::Commit { .. } => Operation::GitCommit,
            Act::Push { .. } => Operation::GitPush,
            Act::OpenPr { .. } => Operation::CreatePr,
            Act::ManagePod { .. } => Operation::ManagePods,
            Act::Spawn { .. } => Operation::SpawnAgent,
        }
    }

    /// The sink, derived.
    ///
    /// Never a default and never a guess: where the verb admits a choice the
    /// caller made it, in a type that offers only admissible options.
    #[must_use]
    pub fn sink_class(&self) -> SinkClass {
        match self {
            Act::Read { sink, .. } | Act::Glob { sink, .. } | Act::Grep { sink, .. } => {
                match sink {
                    ReadSink::AuditLog => SinkClass::AuditLogAppend,
                    ReadSink::Memory => SinkClass::MemoryPersist,
                    ReadSink::Cache => SinkClass::CacheWrite,
                }
            }
            Act::Write { sink, .. } => match sink {
                WriteSink::Workspace => SinkClass::WorkspaceWrite,
                WriteSink::System => SinkClass::SystemWrite,
                WriteSink::ProposedTable => SinkClass::ProposedTableWrite,
                WriteSink::VerifiedTable => SinkClass::VerifiedTableWrite,
                WriteSink::Cache => SinkClass::CacheWrite,
                WriteSink::SearchIndex => SinkClass::SearchIndexWrite,
                WriteSink::AuditLog => SinkClass::AuditLogAppend,
            },
            Act::Edit { sink, .. } => match sink {
                EditSink::Workspace => SinkClass::WorkspaceWrite,
                EditSink::System => SinkClass::SystemWrite,
            },
            Act::Run { .. } => SinkClass::BashExec,
            Act::Search { .. } | Act::Fetch { .. } => SinkClass::HTTPEgress,
            Act::Commit { .. } => SinkClass::GitCommit,
            Act::Push { .. } => SinkClass::GitPush,
            Act::OpenPr { .. } => SinkClass::PRCommentWrite,
            Act::ManagePod { sink, .. } => match sink {
                PodSink::Cloud => SinkClass::CloudMutation,
                PodSink::AgentSpawn => SinkClass::AgentSpawn,
            },
            Act::Spawn { .. } => SinkClass::AgentSpawn,
        }
    }

    /// The audit subject: the target, rendered.
    ///
    /// This is the string that used to travel beside the verb as
    /// `subject: &str`. It is derived here so there is one rendering rather
    /// than one per call site.
    #[must_use]
    pub fn subject(&self) -> String {
        match self {
            Act::Read { path, .. } | Act::Write { path, .. } | Act::Edit { path, .. } => {
                path.as_str().to_string()
            }
            Act::Run { argv } => argv.to_string(),
            Act::Glob { pattern, .. } | Act::Grep { pattern, .. } => pattern.as_str().to_string(),
            Act::Search { query } => query.as_str().to_string(),
            Act::Fetch { endpoint } => endpoint.as_str().to_string(),
            Act::Commit { message } => message.as_str().to_string(),
            Act::Push { remote } => remote.as_str().to_string(),
            Act::OpenPr { title } => title.as_str().to_string(),
            Act::ManagePod { pod, .. } => pod.as_str().to_string(),
            Act::Spawn { agent } => agent.as_str().to_string(),
        }
    }

    /// The endpoint this act contacts, when it contacts one.
    ///
    /// A gate asking "which host?" calls this instead of parsing
    /// [`Act::subject`]. `None` is a structural answer — this act reaches no
    /// network endpoint — not "the parse failed".
    #[must_use]
    pub fn endpoint(&self) -> Option<&Endpoint> {
        match self {
            Act::Fetch { endpoint } => Some(endpoint),
            _ => None,
        }
    }

    /// The filesystem path this act touches, when it touches one.
    #[must_use]
    pub fn path(&self) -> Option<&FilePath> {
        match self {
            Act::Read { path, .. } | Act::Write { path, .. } | Act::Edit { path, .. } => Some(path),
            _ => None,
        }
    }
}

/// Placeholder-targeted constructors, for tests only.
///
/// **GATED** behind `test-helpers`. `#[cfg(test)]` alone cannot work here:
/// other crates' tests consume this across the crate boundary, where
/// `cfg(test)` is false because this crate is compiled as a dependency rather
/// than as the crate under test. A feature is the only gate that reaches them,
/// and it keeps the constructor out of any build that does not ask for it.
///
/// The gate is the point, not an accident of packaging. Production code must
/// name a real target — that requirement is what [`Act`] exists to impose, and
/// an ungated convenience constructor returning a fabricated one would be a
/// door straight back to the untargeted world these types replace.
#[cfg(any(test, feature = "test-helpers"))]
impl Act {
    /// An act for `op` with a placeholder target and its first admissible sink.
    ///
    /// For tests that exercise a gate's verb-level behaviour — exposure
    /// accumulation, capability level, the typestate protocol — and have no
    /// target to name because the target is not what they are testing.
    #[must_use]
    pub fn untargeted(op: Operation) -> Act {
        const T: &str = "untargeted-test-placeholder";
        match op {
            Operation::ReadFiles => Act::Read {
                path: FilePath::new(T),
                sink: ReadSink::AuditLog,
            },
            Operation::WriteFiles => Act::Write {
                path: FilePath::new(T),
                sink: WriteSink::Workspace,
            },
            Operation::EditFiles => Act::Edit {
                path: FilePath::new(T),
                sink: EditSink::Workspace,
            },
            Operation::RunBash => Act::Run {
                argv: Argv::new(alloc::vec![T.to_string()]),
            },
            Operation::GlobSearch => Act::Glob {
                pattern: Pattern::new(T),
                sink: ReadSink::AuditLog,
            },
            Operation::GrepSearch => Act::Grep {
                pattern: Pattern::new(T),
                sink: ReadSink::AuditLog,
            },
            Operation::WebSearch => Act::Search {
                query: Query::new(T),
            },
            Operation::WebFetch => Act::Fetch {
                endpoint: Endpoint::new("GET", "https", T, 443, "/", T),
            },
            Operation::GitCommit => Act::Commit {
                message: Message::new(T),
            },
            Operation::GitPush => Act::Push {
                remote: Remote::new(T),
            },
            Operation::CreatePr => Act::OpenPr {
                title: Message::new(T),
            },
            Operation::ManagePods => Act::ManagePod {
                pod: PodId::new(T),
                sink: PodSink::Cloud,
            },
            Operation::SpawnAgent => Act::Spawn {
                agent: PodId::new(T),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use std::collections::BTreeSet;

    /// Every shape the vocabulary can take, with the given target text.
    ///
    /// Parameterised by the placeholder so the totality test can run it twice
    /// with different targets and show the projection does not depend on them.
    fn every_shape(t: &str) -> Vec<Act> {
        let mut acts = Vec::new();
        for sink in [ReadSink::AuditLog, ReadSink::Memory, ReadSink::Cache] {
            acts.push(Act::Read {
                path: FilePath::new(t),
                sink,
            });
            acts.push(Act::Glob {
                pattern: Pattern::new(t),
                sink,
            });
            acts.push(Act::Grep {
                pattern: Pattern::new(t),
                sink,
            });
        }
        for sink in [
            WriteSink::Workspace,
            WriteSink::System,
            WriteSink::ProposedTable,
            WriteSink::VerifiedTable,
            WriteSink::Cache,
            WriteSink::SearchIndex,
            WriteSink::AuditLog,
        ] {
            acts.push(Act::Write {
                path: FilePath::new(t),
                sink,
            });
        }
        for sink in [EditSink::Workspace, EditSink::System] {
            acts.push(Act::Edit {
                path: FilePath::new(t),
                sink,
            });
        }
        for sink in [PodSink::Cloud, PodSink::AgentSpawn] {
            acts.push(Act::ManagePod {
                pod: PodId::new(t),
                sink,
            });
        }
        acts.push(Act::Run {
            argv: Argv::new(vec![t.to_string()]),
        });
        acts.push(Act::Search {
            query: Query::new(t),
        });
        acts.push(Act::Fetch {
            endpoint: Endpoint::new("get", "https", t, 443, "/", t),
        });
        acts.push(Act::Commit {
            message: Message::new(t),
        });
        acts.push(Act::Push {
            remote: Remote::new(t),
        });
        acts.push(Act::OpenPr {
            title: Message::new(t),
        });
        acts.push(Act::Spawn {
            agent: PodId::new(t),
        });
        acts
    }

    fn projection(t: &str) -> BTreeSet<(u8, u8)> {
        every_shape(t)
            .iter()
            .map(|a| (a.operation() as u8, a.sink_class() as u8))
            .collect()
    }

    /// Every variant reaches its verb, and the thirteen verbs are covered once
    /// each. `Act::operation` being total is what lets a gate take an `Act`
    /// where it took an `Operation`, with nothing lost.
    #[test]
    fn every_operation_has_exactly_one_variant() {
        let ops: Vec<u8> = every_shape("t")
            .iter()
            .map(|a| a.operation() as u8)
            .collect();
        let distinct: BTreeSet<u8> = ops.iter().copied().collect();
        assert_eq!(
            distinct.len(),
            Operation::ALL.len(),
            "every Operation must be reachable from some Act shape"
        );
        for op in Operation::ALL {
            assert!(
                distinct.contains(&(op as u8)),
                "{op:?} has no Act variant, so a gate taking an Act could not express it"
            );
        }
    }

    /// The projection does not depend on the target.
    ///
    /// If it did, "sweep every shape" below would be sweeping one arbitrary
    /// choice of targets rather than the vocabulary.
    #[test]
    fn the_projection_ignores_the_target() {
        assert_eq!(
            projection("/workspace/a.rs"),
            projection("totally-different-target"),
            "(operation, sink_class) must be a function of the shape alone"
        );
    }

    /// **Two computations of one number.**
    ///
    /// Sweeping every `Act` shape and projecting to `(Operation, SinkClass)`
    /// must produce exactly the pairs the kernel admits — the 27 of 247 that
    /// `operation_allowed_for_sink` accepts, probed here through the only
    /// public door onto it, `discharge::test_helpers::try_bundle_for`.
    ///
    /// Neither side is a written-down list, so this cannot pass by a stale
    /// copy of one of them. It fails in both directions: a shape that projects
    /// to a pair the kernel refuses (a sink enum that offered too much), and a
    /// pair the kernel admits that no shape can name (a sink enum that offered
    /// too little). Either would mean `Act` and the kernel disagree about what
    /// the boundary can express.
    ///
    /// 27 is also `EARNABLE_PAIRS` in `extracted/mediation.rs`, where it pins
    /// the domain the mediation proof covers. The same number arrived at from
    /// a third direction.
    #[test]
    fn act_projects_onto_exactly_the_admissible_pairs() {
        use nucleus_ifc_kernel::discharge::test_helpers::try_bundle_for;

        let mut admissible = BTreeSet::new();
        let mut swept = 0usize;
        for op in Operation::ALL {
            for sink in SinkClass::ALL {
                swept += 1;
                if try_bundle_for(op, sink).is_some() {
                    admissible.insert((op as u8, sink as u8));
                }
            }
        }
        assert_eq!(swept, 247, "the product of 13 verbs and 19 sinks");
        assert_eq!(
            admissible.len(),
            27,
            "the kernel's admissible set changed; `Act`'s per-verb sink enums \
             must change with it, and this number is the visible diff"
        );

        let projected = projection("t");
        assert_eq!(
            projected, admissible,
            "`Act`'s shapes and the kernel's admissible pairs must be the same \
             set. A pair only `Act` has is a shape the kernel will refuse at \
             preflight; a pair only the kernel has is an act the boundary \
             cannot express"
        );
    }

    /// **A known defect, pinned so it is visible rather than merely true.**
    ///
    /// `default_sink_class` maps every read verb to `SecretRead`, and
    /// `operation_allowed_for_sink` refuses that pair — reads admit only
    /// `AuditLogAppend`, `MemoryPersist` and `CacheWrite`. So the "conservative
    /// fail-closed default" for a read names a sink no bundle can ever be
    /// earned for. `SINKS_WITH_NO_OPERATION` in `discharge.rs` corroborates it
    /// from the other side, listing `SecretRead` first among the sinks no
    /// operation reaches.
    ///
    /// Nothing fails today because each side has its own passing test and
    /// nothing composed them. This composes them. It asserts the defect rather
    /// than the fix because the fix changes classification for the ten
    /// production callers of `default_sink_class` and belongs in its own
    /// change; when that lands, this test fails and is the place to record it.
    ///
    /// `Act` is unaffected either way: it never consults the default, which is
    /// the point of choosing the sink from a type that offers only admissible
    /// ones.
    #[test]
    fn the_default_sink_of_a_read_is_a_pair_the_kernel_refuses() {
        use nucleus_ifc_kernel::default_sink_class;
        use nucleus_ifc_kernel::discharge::test_helpers::try_bundle_for;

        for op in [
            Operation::ReadFiles,
            Operation::GlobSearch,
            Operation::GrepSearch,
        ] {
            let default = default_sink_class(op);
            assert_eq!(
                default,
                SinkClass::SecretRead,
                "{op:?}'s default sink changed; if it is now admissible, delete \
                 this test and say so"
            );
            assert!(
                try_bundle_for(op, default).is_none(),
                "{op:?}/{default:?} became earnable. That is the fix landing — \
                 delete this test with the change that lands it"
            );
        }

        // Non-vacuity: the defect is specific to the reads, not a claim that
        // no default is earnable.
        for op in [
            Operation::WriteFiles,
            Operation::RunBash,
            Operation::WebFetch,
            Operation::GitCommit,
        ] {
            let default = default_sink_class(op);
            assert!(
                try_bundle_for(op, default).is_some(),
                "{op:?}/{default:?} must still be earnable, or this test is \
                 measuring a broken helper rather than a broken default"
            );
        }
    }

    /// The test constructor must not lie about the verb.
    ///
    /// Every test that reaches for `untargeted` is asserting something about
    /// `op`; if the constructor returned a different verb those assertions
    /// would be about something else.
    #[test]
    fn untargeted_is_faithful_to_its_operation() {
        for op in Operation::ALL {
            let act = Act::untargeted(op);
            assert_eq!(act.operation(), op);
            assert!(
                !act.subject().is_empty(),
                "{op:?}: a placeholder target is still a target"
            );
        }
    }

    /// The one target type whose whole purpose is that it was parsed once.
    #[test]
    fn an_endpoint_answers_without_reparsing() {
        let e = Endpoint::new(
            "get",
            "https",
            "api.example.com",
            8443,
            "/v1/things",
            "https://api.example.com:8443/v1/things?q=1",
        );
        assert_eq!(e.method(), "GET", "the method is normalised on the way in");
        assert_eq!(e.host(), "api.example.com");
        assert_eq!(e.port(), 8443);
        assert_eq!(e.authority(), "api.example.com:8443");
        assert_eq!(e.path(), "/v1/things");
        assert_eq!(
            e.as_str(),
            "https://api.example.com:8443/v1/things?q=1",
            "the raw form is kept for the audit record"
        );

        let act = Act::Fetch { endpoint: e };
        assert!(act.endpoint().is_some());
        assert!(
            act.path().is_none(),
            "a fetch touches no filesystem path, and says so structurally"
        );
    }

    #[test]
    fn a_subject_is_derived_not_carried_alongside() {
        let act = Act::Run {
            argv: Argv::new(vec!["cargo".to_string(), "test".to_string()]),
        };
        assert_eq!(act.subject(), "cargo test");
        assert_eq!(act.operation(), Operation::RunBash);
        assert_eq!(act.sink_class(), SinkClass::BashExec);

        let act = Act::Read {
            path: FilePath::new("/workspace/main.rs"),
            sink: ReadSink::AuditLog,
        };
        assert_eq!(act.subject(), "/workspace/main.rs");
        assert_eq!(act.path().map(FilePath::as_str), Some("/workspace/main.rs"));
        assert!(
            act.endpoint().is_none(),
            "a read contacts no endpoint, and says so structurally"
        );
    }
}

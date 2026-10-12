//! Canonical 5-effect algebraic collapse (ADR 0006).
//!
//! # The 5 Primitives
//!
//! Rather than treating execution as an open-ended collection of ad-hoc tools,
//! nucleus collapses all consequential agent interactions into five canonical
//! algebraic primitives:
//!
//! 1. [`CanonicalEffectKind::FsRead`] — Observing the local filesystem (read, glob, grep).
//! 2. [`CanonicalEffectKind::FsWrite`] — Mutating the local filesystem (write, edit).
//! 3. [`CanonicalEffectKind::NetEgress`] — Exfiltrating data or reaching external networks (fetch, search, push, open PR).
//! 4. [`CanonicalEffectKind::ProcExec`] — Local subprocess invocation (argv execution, git commit).
//! 5. [`CanonicalEffectKind::AgentSpawn`] — Delegating authority or managing child workloads (spawn agent, manage pod).
//!
//! # Relationship to `Act` and `Operation`
//!
//! This type is an algebraic quotient over [`Act`] and [`Operation`].
//! It does not replace [`Operation`] or [`SinkClass`] (which remain the fieldless,
//! Aeneas-extracted theorem carriers), but provides a machine-checkable classification
//! of the whole effect surface into five closed primitives.
//!
//! Every [`Act`] maps bijectively to a [`CanonicalAct`], preserving the exact
//! `(Operation, SinkClass)` pair and subject target string.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use nucleus_ifc_kernel::{Operation, SinkClass};

use crate::act::{
    Act, Argv, EditSink, Endpoint, FilePath, Message, Pattern, PodId, PodSink, Query, ReadSink,
    Remote, WriteSink,
};

/// The five canonical effect classes that partition all agent I/O.
///
/// Deliberately does NOT implement `Default` (ADR 0007 Rule B-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CanonicalEffectKind {
    /// Reading files or querying directory structures (pure reads).
    FsRead,
    /// Creating, updating, or editing files in the workspace or system.
    FsWrite,
    /// Transmitting data across external network boundaries.
    NetEgress,
    /// Spawning or executing host/guest processes via argument vectors.
    ProcExec,
    /// Spawning, controlling, or observing sub-agents and pods.
    AgentSpawn,
}

impl CanonicalEffectKind {
    /// All five canonical effect kinds in canonical order.
    pub const ALL: [Self; 5] = [
        Self::FsRead,
        Self::FsWrite,
        Self::NetEgress,
        Self::ProcExec,
        Self::AgentSpawn,
    ];

    /// Classify an [`Operation`] into its canonical effect kind.
    #[must_use]
    pub const fn of_operation(op: Operation) -> Self {
        match op {
            Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch => Self::FsRead,
            Operation::WriteFiles | Operation::EditFiles => Self::FsWrite,
            Operation::WebFetch
            | Operation::WebSearch
            | Operation::GitPush
            | Operation::CreatePr => Self::NetEgress,
            Operation::RunBash | Operation::GitCommit => Self::ProcExec,
            Operation::SpawnAgent | Operation::ManagePods => Self::AgentSpawn,
        }
    }

    /// The list of [`Operation`]s that partition into this canonical effect kind.
    #[must_use]
    pub const fn operations(self) -> &'static [Operation] {
        match self {
            Self::FsRead => &[
                Operation::ReadFiles,
                Operation::GlobSearch,
                Operation::GrepSearch,
            ],
            Self::FsWrite => &[Operation::WriteFiles, Operation::EditFiles],
            Self::NetEgress => &[
                Operation::WebFetch,
                Operation::WebSearch,
                Operation::GitPush,
                Operation::CreatePr,
            ],
            Self::ProcExec => &[Operation::RunBash, Operation::GitCommit],
            Self::AgentSpawn => &[Operation::SpawnAgent, Operation::ManagePods],
        }
    }

    /// Human-readable label for this canonical effect.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FsRead => "fs_read",
            Self::FsWrite => "fs_write",
            Self::NetEgress => "net_egress",
            Self::ProcExec => "proc_exec",
            Self::AgentSpawn => "agent_spawn",
        }
    }

    /// Whether this effect is a pure read (does not mutate workspace, state, or egress data).
    #[must_use]
    pub const fn is_pure_read(self) -> bool {
        matches!(self, Self::FsRead)
    }

    /// Whether this effect mutates the guest filesystem or executes commands in the guest.
    #[must_use]
    pub const fn mutates_guest_state(self) -> bool {
        matches!(self, Self::FsWrite | Self::ProcExec)
    }

    /// Whether this effect transmits data across external network boundaries.
    #[must_use]
    pub const fn reaches_external_network(self) -> bool {
        matches!(self, Self::NetEgress)
    }

    /// Whether this effect alters the delegation tree or spawns child workloads.
    #[must_use]
    pub const fn modifies_delegation_topology(self) -> bool {
        matches!(self, Self::AgentSpawn)
    }
}

impl core::fmt::Display for CanonicalEffectKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The specific query or file being observed by [`CanonicalAct::FsRead`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ReadTarget {
    /// Read a specific file by path.
    File(FilePath),
    /// Search for files matching a glob pattern.
    Glob(Pattern),
    /// Search file contents matching a regex pattern.
    Grep(Pattern),
}

/// The mutation kind and destination sink for [`CanonicalAct::FsWrite`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum WriteKind {
    /// File write or overwrite to destination sink.
    Write(WriteSink),
    /// In-place file modification to destination sink.
    Edit(EditSink),
}

/// The destination and payload target for [`CanonicalAct::NetEgress`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EgressTarget {
    /// HTTP web fetch with parsed endpoint.
    Fetch(Endpoint),
    /// Web search query.
    Search(Query),
    /// Git push to remote.
    Push(Remote),
    /// Pull request creation.
    OpenPr(Message),
}

/// The execution payload for [`CanonicalAct::ProcExec`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ExecTarget {
    /// Subprocess execution with explicit argument vector (argv).
    Run(Argv),
    /// Git commit creation with commit message.
    Commit(Message),
}

/// A fully targeted canonical action across the 5 algebraic primitives.
///
/// Deliberately does NOT implement `Default` (ADR 0007 Rule B-1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CanonicalAct {
    /// Filesystem read or pattern search.
    FsRead {
        /// What is being read or searched.
        target: ReadTarget,
        /// Where the read event or cached result lands.
        sink: ReadSink,
    },
    /// Filesystem write or edit.
    FsWrite {
        /// Target filesystem path.
        path: FilePath,
        /// Payload content to write, if any.
        content: Vec<u8>,
        /// Write kind and destination sink.
        kind: WriteKind,
    },
    /// Outbound network egress.
    NetEgress {
        /// Network target and parameters.
        target: EgressTarget,
    },
    /// Process or subprocess execution.
    ProcExec {
        /// Execution target (argv or git commit).
        target: ExecTarget,
    },
    /// Sub-agent or pod lifecycle management.
    AgentSpawn {
        /// Pod or sub-agent identifier.
        pod: PodId,
        /// Lifecycle operation sink (creation, teardown, observe).
        sink: PodSink,
    },
}

impl CanonicalAct {
    /// The canonical effect kind of this action.
    #[must_use]
    pub fn kind(&self) -> CanonicalEffectKind {
        match self {
            Self::FsRead { .. } => CanonicalEffectKind::FsRead,
            Self::FsWrite { .. } => CanonicalEffectKind::FsWrite,
            Self::NetEgress { .. } => CanonicalEffectKind::NetEgress,
            Self::ProcExec { .. } => CanonicalEffectKind::ProcExec,
            Self::AgentSpawn { .. } => CanonicalEffectKind::AgentSpawn,
        }
    }

    /// The underlying [`Operation`] derived from this action.
    #[must_use]
    pub fn operation(&self) -> Operation {
        match self {
            Self::FsRead { target, .. } => match target {
                ReadTarget::File(_) => Operation::ReadFiles,
                ReadTarget::Glob(_) => Operation::GlobSearch,
                ReadTarget::Grep(_) => Operation::GrepSearch,
            },
            Self::FsWrite { kind, .. } => match kind {
                WriteKind::Write(_) => Operation::WriteFiles,
                WriteKind::Edit(_) => Operation::EditFiles,
            },
            Self::NetEgress { target } => match target {
                EgressTarget::Fetch(_) => Operation::WebFetch,
                EgressTarget::Search(_) => Operation::WebSearch,
                EgressTarget::Push(_) => Operation::GitPush,
                EgressTarget::OpenPr(_) => Operation::CreatePr,
            },
            Self::ProcExec { target } => match target {
                ExecTarget::Run(_) => Operation::RunBash,
                ExecTarget::Commit(_) => Operation::GitCommit,
            },
            Self::AgentSpawn { sink, .. } => match sink {
                PodSink::AgentSpawn => Operation::SpawnAgent,
                PodSink::Teardown | PodSink::Observe => Operation::ManagePods,
            },
        }
    }

    /// The destination [`SinkClass`] derived from this action.
    #[must_use]
    pub fn sink_class(&self) -> SinkClass {
        self.to_act().sink_class()
    }

    /// The subject string for this action, matching [`Act::subject`].
    #[must_use]
    pub fn subject(&self) -> String {
        self.to_act().subject()
    }

    /// Convert this canonical action to its standard [`Act`] representation.
    #[must_use]
    pub fn to_act(&self) -> Act {
        match self {
            Self::FsRead { target, sink } => match target {
                ReadTarget::File(path) => Act::Read {
                    path: path.clone(),
                    sink: *sink,
                },
                ReadTarget::Glob(pattern) => Act::Glob {
                    pattern: pattern.clone(),
                    sink: *sink,
                },
                ReadTarget::Grep(pattern) => Act::Grep {
                    pattern: pattern.clone(),
                    sink: *sink,
                },
            },
            Self::FsWrite { path, kind, .. } => match kind {
                WriteKind::Write(sink) => Act::Write {
                    path: path.clone(),
                    sink: *sink,
                },
                WriteKind::Edit(sink) => Act::Edit {
                    path: path.clone(),
                    sink: *sink,
                },
            },
            Self::NetEgress { target } => match target {
                EgressTarget::Fetch(endpoint) => Act::Fetch {
                    endpoint: endpoint.clone(),
                },
                EgressTarget::Search(query) => Act::Search {
                    query: query.clone(),
                },
                EgressTarget::Push(remote) => Act::Push {
                    remote: remote.clone(),
                },
                EgressTarget::OpenPr(title) => Act::OpenPr {
                    title: title.clone(),
                },
            },
            Self::ProcExec { target } => match target {
                ExecTarget::Run(argv) => Act::Run { argv: argv.clone() },
                ExecTarget::Commit(message) => Act::Commit {
                    message: message.clone(),
                },
            },
            Self::AgentSpawn { pod, sink } => match sink {
                PodSink::AgentSpawn => Act::Spawn { agent: pod.clone() },
                PodSink::Teardown | PodSink::Observe => Act::ManagePod {
                    pod: pod.clone(),
                    sink: *sink,
                },
            },
        }
    }

    /// Build a filesystem read action.
    #[must_use]
    pub fn read_file(path: impl Into<String>) -> Self {
        Self::FsRead {
            target: ReadTarget::File(FilePath::new(path)),
            sink: ReadSink::AuditLog,
        }
    }

    /// Build a filesystem write action.
    #[must_use]
    pub fn write_file(path: impl Into<String>, content: impl Into<Vec<u8>>) -> Self {
        Self::FsWrite {
            path: FilePath::new(path),
            content: content.into(),
            kind: WriteKind::Write(WriteSink::Workspace),
        }
    }

    /// Build a network fetch action.
    #[must_use]
    pub fn fetch(endpoint: Endpoint) -> Self {
        Self::NetEgress {
            target: EgressTarget::Fetch(endpoint),
        }
    }

    /// Build a command execution action from argv.
    #[must_use]
    pub fn run_argv(argv: impl Into<Vec<String>>) -> Self {
        Self::ProcExec {
            target: ExecTarget::Run(Argv::new(argv)),
        }
    }

    /// Build an agent spawn action.
    #[must_use]
    pub fn spawn_agent(agent: impl Into<String>) -> Self {
        Self::AgentSpawn {
            pod: PodId::new(agent),
            sink: PodSink::AgentSpawn,
        }
    }
}

impl From<&Act> for CanonicalAct {
    fn from(act: &Act) -> Self {
        match act {
            Act::Read { path, sink } => Self::FsRead {
                target: ReadTarget::File(path.clone()),
                sink: *sink,
            },
            Act::Glob { pattern, sink } => Self::FsRead {
                target: ReadTarget::Glob(pattern.clone()),
                sink: *sink,
            },
            Act::Grep { pattern, sink } => Self::FsRead {
                target: ReadTarget::Grep(pattern.clone()),
                sink: *sink,
            },
            Act::Write { path, sink } => Self::FsWrite {
                path: path.clone(),
                content: Vec::new(),
                kind: WriteKind::Write(*sink),
            },
            Act::Edit { path, sink } => Self::FsWrite {
                path: path.clone(),
                content: Vec::new(),
                kind: WriteKind::Edit(*sink),
            },
            Act::Run { argv } => Self::ProcExec {
                target: ExecTarget::Run(argv.clone()),
            },
            Act::Commit { message } => Self::ProcExec {
                target: ExecTarget::Commit(message.clone()),
            },
            Act::Fetch { endpoint } => Self::NetEgress {
                target: EgressTarget::Fetch(endpoint.clone()),
            },
            Act::Search { query } => Self::NetEgress {
                target: EgressTarget::Search(query.clone()),
            },
            Act::Push { remote } => Self::NetEgress {
                target: EgressTarget::Push(remote.clone()),
            },
            Act::OpenPr { title } => Self::NetEgress {
                target: EgressTarget::OpenPr(title.clone()),
            },
            Act::ManagePod { pod, sink } => Self::AgentSpawn {
                pod: pod.clone(),
                sink: *sink,
            },
            Act::Spawn { agent } => Self::AgentSpawn {
                pod: agent.clone(),
                sink: PodSink::AgentSpawn,
            },
        }
    }
}

impl From<Act> for CanonicalAct {
    fn from(act: Act) -> Self {
        Self::from(&act)
    }
}

impl From<CanonicalAct> for Act {
    fn from(c: CanonicalAct) -> Self {
        c.to_act()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_every_operation_partitions_into_canonical_kind() {
        let all_ops = [
            Operation::ReadFiles,
            Operation::WriteFiles,
            Operation::EditFiles,
            Operation::RunBash,
            Operation::GlobSearch,
            Operation::GrepSearch,
            Operation::WebSearch,
            Operation::WebFetch,
            Operation::GitCommit,
            Operation::GitPush,
            Operation::CreatePr,
            Operation::ManagePods,
            Operation::SpawnAgent,
        ];

        let mut seen = Vec::new();
        for kind in CanonicalEffectKind::ALL {
            for op in kind.operations() {
                assert_eq!(CanonicalEffectKind::of_operation(*op), kind);
                assert!(!seen.contains(op), "duplicate operation partition: {op:?}");
                seen.push(*op);
            }
        }

        assert_eq!(seen.len(), 13);
        for op in all_ops {
            assert!(seen.contains(&op), "missing operation in partition: {op:?}");
        }
    }

    #[test]
    fn test_canonical_act_roundtrip_all_thirteen_operations() {
        let all_ops = [
            Operation::ReadFiles,
            Operation::WriteFiles,
            Operation::EditFiles,
            Operation::RunBash,
            Operation::GlobSearch,
            Operation::GrepSearch,
            Operation::WebSearch,
            Operation::WebFetch,
            Operation::GitCommit,
            Operation::GitPush,
            Operation::CreatePr,
            Operation::ManagePods,
            Operation::SpawnAgent,
        ];

        for op in all_ops {
            let original = Act::untargeted(op);
            let canonical = CanonicalAct::from(&original);
            let restored = canonical.to_act();

            assert_eq!(canonical.operation(), original.operation());
            assert_eq!(canonical.sink_class(), original.sink_class());
            assert_eq!(canonical.subject(), original.subject());
            assert_eq!(restored.operation(), original.operation());
            assert_eq!(restored.sink_class(), original.sink_class());
            assert_eq!(restored.subject(), original.subject());
            assert_eq!(
                canonical.kind(),
                CanonicalEffectKind::of_operation(original.operation())
            );
        }
    }

    #[test]
    fn test_canonical_effect_kind_invariants() {
        assert!(CanonicalEffectKind::FsRead.is_pure_read());
        assert!(!CanonicalEffectKind::FsWrite.is_pure_read());
        assert!(!CanonicalEffectKind::NetEgress.is_pure_read());
        assert!(!CanonicalEffectKind::ProcExec.is_pure_read());
        assert!(!CanonicalEffectKind::AgentSpawn.is_pure_read());

        assert!(CanonicalEffectKind::FsWrite.mutates_guest_state());
        assert!(CanonicalEffectKind::ProcExec.mutates_guest_state());
        assert!(!CanonicalEffectKind::FsRead.mutates_guest_state());

        assert!(CanonicalEffectKind::NetEgress.reaches_external_network());
        assert!(!CanonicalEffectKind::FsRead.reaches_external_network());

        assert!(CanonicalEffectKind::AgentSpawn.modifies_delegation_topology());
        assert!(!CanonicalEffectKind::ProcExec.modifies_delegation_topology());
    }
}

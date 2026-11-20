//! Canonical 5-primitive effect execution surface (ADR 0006).
//!
//! Collapses the distributed trait interfaces ([`FileEffect`], [`WebEffect`],
//! [`ShellEffect`], [`GitEffect`], [`AgentSpawnEffect`]) into a single algebraic
//! dispatch handler.

use std::path::{Path, PathBuf};

pub use portcullis_core::canonical::{
    CanonicalAct, CanonicalEffectKind, EgressTarget, ExecTarget, ReadTarget, WriteKind,
};

use portcullis_core::act::PodSink;

use crate::authority::Authority;
use crate::{
    AgentSpawnEffect, DenyAllEffects, EffectError, FileEffect, GitEffect, PolicyEnforced,
    ShellEffect, ShellOutput, WebEffect,
};

/// Output produced by evaluating a [`CanonicalAct`].
#[derive(Debug, Clone)]
pub enum CanonicalOutput {
    /// Raw byte content returned by an effect (e.g. file read, HTTP fetch).
    Bytes(Vec<u8>),
    /// File paths returned by a search or directory enumeration.
    Paths(Vec<PathBuf>),
    /// Subprocess output including exit code, stdout, and stderr.
    Process(ShellOutput),
    /// Text content returned by an effect (e.g. git commit hash, search summary, pod ID).
    Text(String),
    /// Side-effect performed with no return payload (file write, git push, teardown).
    Empty,
}

impl CanonicalOutput {
    /// Extract byte content if variant is [`CanonicalOutput::Bytes`].
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Extract paths if variant is [`CanonicalOutput::Paths`].
    #[must_use]
    pub fn as_paths(&self) -> Option<&[PathBuf]> {
        match self {
            Self::Paths(p) => Some(p),
            _ => None,
        }
    }

    /// Extract process output if variant is [`CanonicalOutput::Process`].
    #[must_use]
    pub fn as_process(&self) -> Option<&ShellOutput> {
        match self {
            Self::Process(p) => Some(p),
            _ => None,
        }
    }

    /// Extract text if variant is [`CanonicalOutput::Text`].
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(t) => Some(t),
            _ => None,
        }
    }

    /// Whether the output was empty (unit).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }
}

/// Unified algebraic effect handler for the 5 canonical primitives.
///
/// Every method consumes an [`Authority`] **by value**, enforcing the affine
/// one-shot token guarantee (ADR 0007 Rule C-4).
pub trait CanonicalEffectHandler {
    /// Perform an action classified into one of the 5 canonical primitives.
    fn perform(
        &self,
        act: CanonicalAct,
        authority: Authority,
    ) -> Result<CanonicalOutput, EffectError>;
}

impl<E> CanonicalEffectHandler for PolicyEnforced<E>
where
    E: FileEffect + WebEffect + ShellEffect + GitEffect + AgentSpawnEffect,
{
    fn perform(
        &self,
        act: CanonicalAct,
        authority: Authority,
    ) -> Result<CanonicalOutput, EffectError> {
        match act {
            CanonicalAct::FsRead { target, .. } => match target {
                ReadTarget::File(path) => {
                    let bytes = self.read(Path::new(path.as_str()), authority)?;
                    Ok(CanonicalOutput::Bytes(bytes))
                }
                ReadTarget::Glob(pattern) => {
                    let paths = self.glob(pattern.as_str(), authority)?;
                    Ok(CanonicalOutput::Paths(paths))
                }
                // No effect trait performs a content search. Running `glob` on
                // the pattern instead would perform an operation the authority
                // was not minted for.
                ReadTarget::Grep(_) => Err(unperformable(authority, "grep")),
            },
            CanonicalAct::FsWrite {
                path,
                content,
                kind,
            } => match (kind, content) {
                (WriteKind::Write(_), Some(content)) => {
                    self.write(Path::new(path.as_str()), &content, authority)?;
                    Ok(CanonicalOutput::Empty)
                }
                // Classified from an `Act`, which carries no payload. Writing
                // empty bytes here would truncate the file.
                (WriteKind::Write(_), None) => {
                    Err(unperformable(authority, "write without content"))
                }
                // An edit is not a whole-file write; no effect trait performs it.
                (WriteKind::Edit(_), _) => Err(unperformable(authority, "edit")),
            },
            CanonicalAct::NetEgress { target } => match target {
                EgressTarget::Fetch(endpoint) => {
                    let bytes = self.fetch(endpoint.as_str(), authority)?;
                    Ok(CanonicalOutput::Bytes(bytes))
                }
                EgressTarget::Search(query) => {
                    let results = self.search(query.as_str(), authority)?;
                    let text = results
                        .into_iter()
                        .map(|r| format!("{}: {}", r.title, r.snippet))
                        .collect::<Vec<_>>()
                        .join("\n");
                    Ok(CanonicalOutput::Text(text))
                }
                EgressTarget::Push(remote) => {
                    self.push(remote.as_str(), "HEAD", authority)?;
                    Ok(CanonicalOutput::Empty)
                }
                // No effect trait opens a pull request. Returning success here
                // reported an effect that was never checked, receipted or run.
                EgressTarget::OpenPr(_) => Err(unperformable(authority, "open pull request")),
            },
            CanonicalAct::ProcExec { target } => match target {
                ExecTarget::Run(argv) => {
                    // Quoted, not space-joined: `run` re-splits with
                    // `shell_words`, so an argument containing a space must
                    // survive as one argument.
                    let output = self.run(&shell_words::join(argv.args()), authority)?;
                    Ok(CanonicalOutput::Process(output))
                }
                ExecTarget::Commit(message) => {
                    let hash = self.commit(message.as_str(), authority)?;
                    Ok(CanonicalOutput::Text(hash))
                }
            },
            CanonicalAct::AgentSpawn { pod, sink } => match sink {
                PodSink::AgentSpawn => {
                    let child_id = self.spawn(pod.as_str(), "{}", authority)?;
                    Ok(CanonicalOutput::Text(child_id))
                }
                // Observing or tearing down a pod is not a spawn.
                PodSink::Observe => Err(unperformable(authority, "observe pod")),
                PodSink::Teardown => Err(unperformable(authority, "tear down pod")),
            },
        }
    }
}

/// Refuse an action no effect trait can perform as named.
///
/// The authority is consumed unspent: it was minted for this action, and
/// dropping it is the only use a refused action has for it.
fn unperformable(authority: Authority, what: &'static str) -> EffectError {
    drop(authority);
    EffectError::NotImplemented(what)
}

impl CanonicalEffectHandler for DenyAllEffects {
    fn perform(
        &self,
        _act: CanonicalAct,
        _authority: Authority,
    ) -> Result<CanonicalOutput, EffectError> {
        Err(EffectError::PolicyDenied(
            "deny-all handler active".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authority::Authority;
    use crate::doubles::RecordingEffects;
    use portcullis_core::discharge::test_helpers::bundle_for;
    use portcullis_core::{CapabilityLattice, CapabilityLevel, Operation, SinkClass};
    use std::sync::Arc;

    fn make_test_handler(
        policy: CapabilityLattice,
        recording: RecordingEffects,
    ) -> PolicyEnforced<RecordingEffects> {
        PolicyEnforced {
            inner: recording,
            receipts: Arc::new(crate::receipt::ReceiptLog::new()),
            policy,
        }
    }

    #[test]
    fn test_canonical_perform_fs_read() {
        let recording =
            RecordingEffects::new().with_file_content(b"hello canonical world".to_vec());
        let policy = CapabilityLattice {
            read_files: CapabilityLevel::Always,
            ..CapabilityLattice::bottom()
        };
        let handler = make_test_handler(policy, recording);

        let authority = Authority::new(bundle_for(Operation::ReadFiles, SinkClass::AuditLogAppend));
        let act = CanonicalAct::read_file("test.txt");

        let output = handler
            .perform(act, authority)
            .expect("perform should succeed");
        assert_eq!(output.as_bytes(), Some(b"hello canonical world".as_slice()));
    }

    #[test]
    fn test_canonical_perform_fs_write() {
        let recording = RecordingEffects::new();
        let policy = CapabilityLattice {
            write_files: CapabilityLevel::Always,
            ..CapabilityLattice::bottom()
        };
        let handler = make_test_handler(policy, recording);

        let authority =
            Authority::new(bundle_for(Operation::WriteFiles, SinkClass::WorkspaceWrite));
        let act = CanonicalAct::write_file("output.txt", b"new content");

        let output = handler
            .perform(act, authority)
            .expect("perform should succeed");
        assert!(output.is_empty());
    }

    #[test]
    fn test_canonical_perform_proc_exec() {
        use portcullis_core::discharge::test_helpers::bundle_for_subject;
        let recording = RecordingEffects::new();
        let policy = CapabilityLattice {
            run_bash: CapabilityLevel::Always,
            ..CapabilityLattice::bottom()
        };
        let handler = make_test_handler(policy, recording);

        let authority = Authority::new(bundle_for_subject(
            Operation::RunBash,
            SinkClass::BashExec,
            "echo hi",
        ));
        let act = CanonicalAct::run_argv(vec!["echo".to_string(), "hi".to_string()]);

        let output = handler
            .perform(act, authority)
            .expect("perform should succeed");
        assert!(output.as_process().is_some());
    }

    #[test]
    fn test_canonical_perform_denied_by_policy() {
        let recording = RecordingEffects::new();
        let policy = CapabilityLattice::bottom();
        let handler = make_test_handler(policy, recording);

        let authority = Authority::new(bundle_for(Operation::ReadFiles, SinkClass::AuditLogAppend));
        let act = CanonicalAct::read_file("secret.txt");

        let err = handler
            .perform(act, authority)
            .expect_err("should be denied by policy");
        assert!(matches!(err, EffectError::PolicyDenied(_)));
    }

    fn permit_everything() -> CapabilityLattice {
        CapabilityLattice::top()
    }

    /// An act no effect trait can perform as named is refused, under a policy
    /// that would allow it, and nothing else runs in its place. Grep used to
    /// run as glob, an edit or a payload-less write as an empty write (a
    /// truncation), open-PR as an unchecked `Ok`, and observe/teardown as a
    /// spawn.
    #[test]
    fn unperformable_acts_are_refused_and_run_nothing() {
        use portcullis_core::act::PodId;
        use portcullis_core::act::{Act, PodSink};

        let mut acts: Vec<CanonicalAct> = [
            Operation::GrepSearch,
            Operation::WriteFiles,
            Operation::EditFiles,
            Operation::CreatePr,
        ]
        .into_iter()
        .map(|op| CanonicalAct::from(&Act::untargeted(op)))
        .collect();
        for sink in [PodSink::Observe, PodSink::Teardown] {
            acts.push(CanonicalAct::AgentSpawn {
                pod: PodId::new("child"),
                sink,
            });
        }

        for act in acts {
            let handler = make_test_handler(permit_everything(), RecordingEffects::new());
            let authority = Authority::new(bundle_for(act.operation(), act.sink_class()));
            let err = handler
                .perform(act.clone(), authority)
                .expect_err("an unperformable act must be refused");
            // Refused as unperformable, not by policy: the policy allows it.
            assert!(
                err.to_string().starts_with("not implemented: "),
                "{act:?} refused for the wrong reason: {err:?}"
            );
            assert!(
                handler.inner.calls().is_empty(),
                "{act:?} ran {:?} in its place",
                handler.inner.calls()
            );
        }
    }

    /// The payload survives: a write built with content writes that content.
    #[test]
    fn a_canonical_write_writes_its_content() {
        let handler = make_test_handler(permit_everything(), RecordingEffects::new());
        let act = CanonicalAct::write_file("out.txt", b"kept".to_vec());
        let authority = Authority::new(bundle_for(act.operation(), act.sink_class()));
        handler.perform(act, authority).expect("write");
        let calls = handler.inner.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].kind, "write");
    }

    /// An argument containing a space reaches the shell boundary as one
    /// argument, not two.
    #[test]
    fn an_argv_element_with_a_space_stays_one_argument() {
        use portcullis_core::discharge::test_helpers::bundle_for_subject;
        let argv = vec!["echo".to_string(), "a b".to_string()];
        let cmd = shell_words::join(&argv);
        let handler = make_test_handler(permit_everything(), RecordingEffects::new());
        let authority = Authority::new(bundle_for_subject(
            Operation::RunBash,
            SinkClass::BashExec,
            &cmd,
        ));
        handler
            .perform(CanonicalAct::run_argv(argv.clone()), authority)
            .expect("run");
        let calls = handler.inner.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(shell_words::split(&calls[0].detail).unwrap(), argv);
    }

    #[test]
    fn test_canonical_deny_all_handler() {
        let authority = Authority::new(bundle_for(Operation::ReadFiles, SinkClass::AuditLogAppend));
        let act = CanonicalAct::read_file("test.txt");
        let err = DenyAllEffects
            .perform(act, authority)
            .expect_err("deny all");
        assert!(matches!(err, EffectError::PolicyDenied(_)));
    }
}

//! The local driver's children, decided once at start-up (Program C, C2).
//!
//! `--driver local --allow-local-driver` runs each pod's tool-proxy as a host
//! process at the node's uid. What its children (`/v1/run` commands, the
//! workload) run as is decided here, by the realization contract
//! (`nucleus::LocalRealization::check`, the one decider):
//!
//! * **Met** ([`LocalChildren::Subordinate`]): every pod gets its own
//!   subordinate host uid/gid from the node user's delegated range, and its
//!   proxy runs its children there (`--subordinate-ids`). The node's evidence
//!   tier is `SeparatedLocal`. An id is never given twice: the next offset is
//!   kept in the state directory, so a later pod never inherits files an
//!   earlier pod's children left behind.
//! * **Unmet** ([`LocalChildren::SharedUid`]): the children share the node's
//!   uid. The bare tier stays the declared insecure mode of Program C, C0, and
//!   the reason is logged.
//!
//! # The workspace (what is granted, and what never is)
//!
//! A separated child is another host uid, so it reaches the pod's workspace
//! only if it is given it. The node grants it, by ACL, exactly when the pod's
//! `work_dir` resolves strictly inside `--workspace-root`, that root lies
//! outside the state directory, and no other local pod of this node was
//! granted an overlapping directory ([`SubordinatePool::grant`]). Any other
//! `work_dir` (the local driver accepts any path a creator names) is not
//! widened: the child gets whatever the directory's own bits give any user.
//! The workload door then sits inside the granted workspace, where the
//! workload can reach it; otherwise it stays in the pod directory, under the
//! 0700 state directory, which a separated workload cannot reach.
// The pod spawn that uses most of this exists only with the local driver.
#![cfg_attr(not(feature = "local-driver"), allow(dead_code))]

#[cfg(feature = "local-driver")]
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::ApiError;
use crate::insecure_mode::EvidenceTier;

/// The file under the state directory holding the next subordinate offset.
const NEXT_OFFSET_FILE: &str = "subordinate-ids.next";

/// The directory, inside a granted workspace, the workload door is bound in.
const DOOR_DIR: &str = ".nucleus-door";

/// What the local driver's children run as. No `Default` (ADR 0007 B-1).
#[derive(Clone)]
pub(crate) enum LocalChildren {
    /// Not the allowed local driver: no proxy is given `--unsandboxed`.
    NotOptedIn,
    /// The realization contract is unmet: the C0 insecure mode.
    SharedUid,
    /// The contract is met: each pod's children at its own subordinate ids.
    Subordinate(Arc<SubordinatePool>),
}

impl LocalChildren {
    /// Decide from the operator's opt-in and, for the bare tier, the
    /// realization contract on `state_dir`.
    pub(crate) fn decide(opt_in: nucleus::UnsandboxedOptIn, state_dir: &Path) -> Self {
        match opt_in {
            nucleus::UnsandboxedOptIn::Absent => Self::NotOptedIn,
            nucleus::UnsandboxedOptIn::Explicit | nucleus::UnsandboxedOptIn::Subordinate(_) => {
                match nucleus::LocalRealization::check(
                    state_dir,
                    std::process::Command::new("/bin/sh"),
                ) {
                    nucleus::LocalRealization::Separated(range) => {
                        tracing::info!(
                            ids = range.count(),
                            "the local driver separates its children at subordinate host ids \
                             (Program C, C2)"
                        );
                        Self::Subordinate(Arc::new(SubordinatePool {
                            range,
                            next: state_dir.join(NEXT_OFFSET_FILE),
                            claimed: Mutex::new(Vec::new()),
                        }))
                    }
                    nucleus::LocalRealization::SharedUid(why) => {
                        tracing::warn!(
                            %why,
                            "the local driver cannot separate its children from this node: the \
                             bare tier stays the declared insecure mode"
                        );
                        Self::SharedUid
                    }
                }
            }
        }
    }

    /// The evidence tier these children leave the node in.
    pub(crate) fn tier(&self) -> EvidenceTier {
        match self {
            Self::NotOptedIn => EvidenceTier::Separated,
            Self::SharedUid => EvidenceTier::InsecureSharedUid,
            Self::Subordinate(_) => EvidenceTier::SeparatedLocal,
        }
    }

    /// The opt-in a proxy is started with: the bare tier's, or none.
    pub(crate) fn opt_in(&self) -> nucleus::UnsandboxedOptIn {
        match self {
            Self::NotOptedIn => nucleus::UnsandboxedOptIn::Absent,
            Self::SharedUid | Self::Subordinate(_) => nucleus::UnsandboxedOptIn::Explicit,
        }
    }

    /// One new local pod's tool-proxy arguments: the node's own pid for its
    /// socket (`--node-peer-pid`), the bare-tier opt-in, the pod's ids, and
    /// its workload door, and that door. Allocates the ids and grants the
    /// workspace where [`SubordinatePool::grant`] allows. The door is
    /// [`crate::lifecycle::local_workload_door`] unless the workspace was
    /// granted, and the pod records the one passed, so the admission record
    /// (#3219) names the socket the proxy binds.
    ///
    /// # Errors
    /// The pool is used up or its offset file cannot be kept, or the door
    /// directory cannot be made.
    #[cfg(feature = "local-driver")]
    pub(crate) fn proxy_args(
        &self,
        state: &crate::NodeState,
        pod_dir: &Path,
        work_dir: &Path,
    ) -> Result<(Vec<OsString>, PathBuf), ApiError> {
        let mut args: Vec<OsString> = vec![
            "--node-peer-pid".into(),
            std::process::id().to_string().into(),
        ];
        let mut door = crate::lifecycle::local_workload_door(pod_dir)?;
        args.extend(
            crate::bare_tier_opt_in::unsandboxed_proxy_flag(self.opt_in()).map(OsString::from),
        );
        match self {
            Self::NotOptedIn | Self::SharedUid => {}
            Self::Subordinate(pool) => {
                let ids = pool.allocate()?;
                args.push("--subordinate-ids".into());
                args.push(format!("{}:{}", ids.uid(), ids.gid()).into());
                let (workspace_root, state_dir) =
                    (state.host_roots.workspace_root(), state.state_dir.as_path());
                match pool.grant(work_dir, workspace_root, state_dir, ids) {
                    Ok(granted) => door = door_dir(&granted)?.join("workload.sock"),
                    Err(why) => tracing::info!(
                        work_dir = %work_dir.display(),
                        uid = ids.uid(),
                        "workspace not granted to the pod's subordinate ids: {why}"
                    ),
                }
            }
        }
        args.push("--workload-door".into());
        args.push(door.clone().into());
        Ok((args, door))
    }
}

/// One new local pod's tool-proxy arguments, from the node's decision:
/// [`LocalChildren::proxy_args`].
///
/// # Errors
/// As [`LocalChildren::proxy_args`].
#[cfg(feature = "local-driver")]
pub(crate) fn proxy_args(
    state: &crate::NodeState,
    pod_dir: &Path,
    work_dir: &Path,
) -> Result<(Vec<OsString>, PathBuf), ApiError> {
    state.local_children.proxy_args(state, pod_dir, work_dir)
}

/// The node user's delegated range, and what this node has given out of it.
pub(crate) struct SubordinatePool {
    range: nucleus::SubordinateRange,
    next: PathBuf,
    /// Workspaces granted by this process: no two pods share one.
    claimed: Mutex<Vec<PathBuf>>,
}

impl SubordinatePool {
    /// The next pod's ids. The offset file is advanced before the ids are
    /// returned, so a crash between the two skips an id rather than reusing
    /// one.
    fn allocate(&self) -> Result<nucleus::SubordinateIds, ApiError> {
        let failed = |e: String| ApiError::Driver(format!("subordinate ids: {e}"));
        let _held = self
            .claimed
            .lock()
            .map_err(|_| failed("pool lock".into()))?;
        let offset = match std::fs::read_to_string(&self.next) {
            Ok(text) => text
                .trim()
                .parse::<u32>()
                .map_err(|e| failed(format!("{}: {e}", self.next.display())))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => nucleus::FIRST_POD_OFFSET,
            Err(e) => return Err(failed(format!("{}: {e}", self.next.display()))),
        };
        let ids = self
            .range
            .ids(offset.max(nucleus::FIRST_POD_OFFSET))
            .map_err(|e| failed(e.to_string()))?;
        let advanced = offset.max(nucleus::FIRST_POD_OFFSET).saturating_add(1);
        // Persist the advance through a host crash before handing the id to a pod.
        // The authority writer syncs the staging file and the directory after rename.
        crate::pod_authority::write_whole_sync(&self.next, advanced.to_string().as_bytes())
            .map_err(|e| failed(format!("{}: {e}", self.next.display())))?;
        Ok(ids)
    }

    /// Grant `ids` the pod's workspace, or say why not. See the module docs.
    fn grant(
        &self,
        work_dir: &Path,
        workspace_root: &Path,
        state_dir: &Path,
        ids: nucleus::SubordinateIds,
    ) -> Result<PathBuf, String> {
        let canonical = |p: &Path| {
            p.canonicalize()
                .map_err(|e| format!("{}: {e}", p.display()))
        };
        let (root, state, dir) = (
            canonical(workspace_root)?,
            canonical(state_dir)?,
            canonical(work_dir)?,
        );
        decide_grant(&dir, &root, &state)?;
        let mut claimed = self.claimed.lock().map_err(|_| "pool lock".to_string())?;
        if let Some(other) = claimed
            .iter()
            .find(|c| c.starts_with(&dir) || dir.starts_with(c))
        {
            return Err(format!(
                "it overlaps {}, another local pod's workspace",
                other.display()
            ));
        }
        nucleus::grant_workspace(&dir, ids).map_err(|e| e.to_string())?;
        claimed.push(dir.clone());
        Ok(dir)
    }
}

/// The static half of the grant rule: `dir` strictly inside `root`, and
/// `root` outside `state`.
pub(crate) fn decide_grant(dir: &Path, root: &Path, state: &Path) -> Result<(), String> {
    if root.starts_with(state) {
        return Err(format!(
            "--workspace-root {} is inside the state directory, which a separated child cannot \
             traverse",
            root.display()
        ));
    }
    if dir == root || !dir.starts_with(root) {
        return Err(format!(
            "it is not strictly inside --workspace-root {}",
            root.display()
        ));
    }
    Ok(())
}

/// The workload door's directory inside a granted workspace: made by the
/// node, before the proxy or any child of this pod exists. Anything already
/// there that is not the node's own directory is refused.
fn door_dir(granted: &Path) -> Result<PathBuf, ApiError> {
    use std::os::unix::fs::MetadataExt;
    let dir = granted.join(DOOR_DIR);
    match std::fs::symlink_metadata(&dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir(&dir)?,
        Ok(meta) if meta.is_dir() && meta.uid() == nucleus::runtime_uid() => {}
        Ok(_) => {
            return Err(ApiError::Driver(format!(
                "{} exists and is not this node's directory; refusing to bind the workload door \
                 there",
                dir.display()
            )));
        }
        Err(e) => return Err(e.into()),
    }
    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only a directory strictly inside a workspace root outside the state
    /// directory is ever granted; a creator naming the root itself, a
    /// directory outside it, or the state directory gets nothing.
    #[test]
    fn a_grant_is_confined_to_the_workspace_root() {
        let state = Path::new("/srv/node/state");
        let root = Path::new("/srv/node/workspaces");
        assert!(decide_grant(Path::new("/srv/node/workspaces/a"), root, state).is_ok());
        for refused in [
            "/srv/node/workspaces",
            "/srv/node",
            "/srv/node/state",
            "/srv/node/state/ca",
            "/home/operator/.ssh",
            "/srv/node/workspaces-evil/a",
        ] {
            assert!(
                decide_grant(Path::new(refused), root, state).is_err(),
                "{refused}"
            );
        }
        // The default root, under the state directory, grants nothing.
        let inside = Path::new("/srv/node/state/workspaces");
        assert!(decide_grant(Path::new("/srv/node/state/workspaces/a"), inside, state).is_err());
    }

    /// The bare tier's evidence tier follows the contract, and the opt-in a
    /// proxy is given follows the operator.
    #[test]
    fn the_tier_and_the_opt_in_follow_the_decision() {
        assert_eq!(LocalChildren::NotOptedIn.tier(), EvidenceTier::Separated);
        assert_eq!(
            LocalChildren::SharedUid.tier(),
            EvidenceTier::InsecureSharedUid
        );
        assert_eq!(
            LocalChildren::NotOptedIn.opt_in(),
            nucleus::UnsandboxedOptIn::Absent
        );
        assert_eq!(
            LocalChildren::SharedUid.opt_in(),
            nucleus::UnsandboxedOptIn::Explicit
        );
        // Without the opt-in the contract is not even asked.
        assert!(matches!(
            LocalChildren::decide(nucleus::UnsandboxedOptIn::Absent, Path::new("/nonexistent")),
            LocalChildren::NotOptedIn
        ));
    }

    /// A state directory another uid can enter is not separated, whatever
    /// the host's delegation: the node stays in the insecure mode.
    #[test]
    fn a_shared_state_directory_keeps_the_insecure_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).expect("0755");
        let children = LocalChildren::decide(nucleus::UnsandboxedOptIn::Explicit, dir.path());
        assert_eq!(children.tier(), EvidenceTier::InsecureSharedUid);
    }

    /// On a host whose contract holds (the C2 builders set
    /// `NUCLEUS_REQUIRE_SUBORDINATE_IDS`), the bare tier is `SeparatedLocal`,
    /// and no id is handed out twice, across a restart of the pool on the
    /// same state directory too. Elsewhere it says why it did not run.
    #[test]
    fn a_delegated_host_separates_and_never_reuses_an_id() {
        let dir = crate::state_lock::state_tempdir();
        let decide = || LocalChildren::decide(nucleus::UnsandboxedOptIn::Explicit, dir.path());
        let pool = match decide() {
            LocalChildren::Subordinate(pool) => pool,
            other => {
                assert!(
                    std::env::var_os("NUCLEUS_REQUIRE_SUBORDINATE_IDS").is_none(),
                    "NUCLEUS_REQUIRE_SUBORDINATE_IDS is set and the contract is unmet"
                );
                assert_eq!(other.tier(), EvidenceTier::InsecureSharedUid);
                eprintln!("not run: this host cannot separate the bare tier");
                return;
            }
        };
        assert_eq!(
            LocalChildren::Subordinate(Arc::clone(&pool)).tier(),
            EvidenceTier::SeparatedLocal
        );
        let (a, b) = (pool.allocate().expect("a"), pool.allocate().expect("b"));
        assert_ne!(a.uid(), b.uid());
        for ids in [a, b] {
            assert_ne!(ids.uid(), nucleus::runtime_uid());
            assert_ne!(ids.uid(), 0);
        }
        let LocalChildren::Subordinate(again) = decide() else {
            panic!("the same host stopped separating");
        };
        let c = again.allocate().expect("c");
        assert!(c.uid() > b.uid(), "an id was reused after a restart");
    }
}

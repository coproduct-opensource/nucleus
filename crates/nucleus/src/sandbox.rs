//! Capability-based file sandbox.
//!
//! Unlike `portcullis::PathLattice` which uses string-based path checking,
//! `Sandbox` uses `cap-std` to hold directory handles. This provides kernel-level
//! enforcement against:
//!
//! - **Symlink escapes**: The kernel resolves paths relative to the directory handle
//! - **TOCTOU races**: Operations happen atomically on the handle
//! - **Path traversal**: `..` cannot escape because the handle is the root
//!
//! ## Example
//!
//! ```ignore
//! use nucleus::Sandbox;
//! use portcullis::PermissionLattice;
//!
//! let policy = PermissionLattice::fix_issue();
//! let sandbox = Sandbox::new(&policy, "/home/user/project")?;
//!
//! // This opens relative to the sandbox root
//! let file = sandbox.open("src/main.rs")?;
//!
//! // This fails - path would escape
//! assert!(sandbox.open("../../etc/passwd").is_err());
//!
//! // This fails - blocked by policy
//! assert!(sandbox.open(".env").is_err());
//! ```

use cap_std::fs::{Dir, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::approval::{ApprovalRequest, ApprovalToken, Approver, CallbackApprover};
use crate::error::{NucleusError, Result};
use portcullis::kernel::DecisionToken;
use portcullis::{
    CapabilityLattice, CapabilityLevel, Obligations, Operation, PathLattice, PermissionLattice,
    SinkClass,
};
use portcullis_effects::authority::Authority;

/// Whether a [`GlobListing`] holds every match or stopped at its bound.
///
/// Two values, not a `bool` (ADR 0007 A-rule): the HTTP response used to carry
/// `truncated: Option<bool>`, where `None` and `Some(false)` meant the same
/// thing and a reader had to know which one the producer wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completeness {
    /// The walk finished; every entry the policy lets this sandbox see and the
    /// pattern matches is in `matches`.
    Complete,
    /// At least one more match exists beyond `max`. Whatever else is out
    /// there was not counted.
    Truncated,
}

/// The result of [`Sandbox::glob`].
///
/// Paths are relative to the sandbox root, whatever `dir` the caller searched
/// under, so a listing can be fed straight back into `read_to_string`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobListing {
    /// Matching entries, relative to the sandbox root, in directory-sorted
    /// walk order.
    pub matches: Vec<PathBuf>,
    /// Whether `matches` is the whole answer.
    pub completeness: Completeness,
    /// Entries the walk refused to report: symlinks (never followed, never
    /// listed), matches withheld by the path policy, and entries it could not
    /// read. A non-zero count says the listing is honest about its gaps
    /// without naming what is in them.
    pub skipped: usize,
}

/// A capability-based file sandbox.
///
/// All file operations go through this sandbox, which holds a directory handle
/// to the sandbox root. The kernel prevents escapes at the syscall level.
pub struct Sandbox {
    /// The root directory handle (capability)
    root: Dir,
    /// The absolute path of the root (for error messages)
    root_path: PathBuf,
    /// The path policy from portcullis
    policy: PathLattice,
    /// Capability policy for file operations
    capabilities: CapabilityLattice,
    /// Approval obligations for file operations
    obligations: Obligations,
    /// Approver for approval-gated operations
    approver: Option<Arc<dyn Approver>>,
    /// Checksum of the permissions this sandbox enforces.
    ///
    /// `DecisionToken::redeem` requires it, so every redeem site here names what
    /// it is executing under. Before `redeem` existed, all 24 of this file's
    /// redeem sites checked the operation and nothing else.
    permissions: String,
    /// The log every authority spent through this sandbox is recorded against.
    ///
    /// Sandbox writes spend their authority DIRECTLY, in `spend_as`, rather than
    /// through `PolicyEnforced` — which is where every other effect picks up its
    /// witness. So this was the one path in the workspace where an authority was
    /// spent with no log attached, and the writes it authorised left no record.
    /// `Authority::spend` now refuses that outright; this is the log that makes
    /// the refusal unnecessary.
    receipts: Arc<portcullis_effects::receipt::ReceiptLog>,
    /// The uid that files and directories this sandbox CREATES are handed to:
    /// the executor's dropped child uid, when it has one.
    ///
    /// Under MicroVM the runtime writes as root and the commands it runs drop
    /// to the workload uid. Without this, a file written through the sandbox
    /// would be root's, and the agent's next command — a formatter rewriting
    /// it in place, a build writing into a directory the sandbox made — would
    /// be refused. `None` keeps the runtime's ownership: the restrictive
    /// direction, not a grant.
    child_owner: Option<u32>,
}

impl Sandbox {
    /// Hand what this sandbox creates to the children `confinement` describes.
    /// A no-op for a confinement that does not drop uid.
    #[must_use]
    pub fn owned_for(mut self, confinement: crate::ChildConfinement) -> Self {
        self.child_owner = confinement.drop_uid();
        self
    }

    /// Give a just-created entry to the child uid. Called on the creating
    /// handle where there is one, so nothing can be swapped in between.
    fn hand_over_fd(&self, fd: impl std::os::fd::AsFd) -> std::io::Result<()> {
        match self.child_owner {
            Some(uid) => std::os::unix::fs::fchown(fd, Some(uid), Some(uid)),
            None => Ok(()),
        }
    }

    /// Give a just-created directory (relative to the root) to the child uid.
    fn hand_over_dir(&self, path: &Path) -> std::io::Result<()> {
        if self.child_owner.is_none() {
            return Ok(());
        }
        let dir = self.root.open_dir(path)?;
        self.hand_over_fd(&dir)
    }

    /// The receipts for authorities spent through this sandbox.
    pub fn receipts(&self) -> &portcullis_effects::receipt::ReceiptLog {
        &self.receipts
    }

    /// Create a new sandbox rooted at the given path.
    ///
    /// The `policy` determines which files within the sandbox can be accessed
    /// and which file operations are permitted.
    /// Even if a file is within the sandbox root, it can be blocked by pattern.
    pub fn new(policy: &PermissionLattice, root: impl AsRef<Path>) -> Result<Self> {
        let root_path = root.as_ref().to_path_buf();
        let normalized = policy.clone().normalize();
        let permissions = normalized.checksum();

        // Open the root directory - this is our capability handle
        let root_dir = Dir::open_ambient_dir(&root_path, cap_std::ambient_authority())?;

        Ok(Self {
            receipts: Arc::new(portcullis_effects::receipt::ReceiptLog::new()),
            root: root_dir,
            root_path,
            policy: normalized.paths,
            capabilities: normalized.capabilities,
            obligations: normalized.obligations,
            approver: None,
            permissions,
            child_owner: None,
        })
    }

    /// Set an approver for approval-gated operations.
    pub fn with_approver(mut self, approver: Arc<dyn Approver>) -> Self {
        self.approver = Some(approver);
        self
    }

    /// Set a callback-based approver for approval-gated operations.
    ///
    /// The callback receives an approval request and should return `true`
    /// if human approval was granted.
    pub fn with_approval_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(&ApprovalRequest) -> bool + Send + Sync + 'static,
    {
        self.approver = Some(Arc::new(CallbackApprover::new(callback)));
        self
    }

    /// Build an approval request for an operation string.
    pub fn approval_request(&self, operation: impl Into<String>) -> ApprovalRequest {
        ApprovalRequest::new(operation)
    }

    /// Request approval for an operation.
    pub fn request_approval(&self, operation: impl Into<String>) -> Result<ApprovalToken> {
        let request = self.approval_request(operation);
        if let Some(ref approver) = self.approver {
            approver.approve(&request)
        } else {
            Err(NucleusError::ApprovalRequired {
                operation: request.operation().to_string(),
            })
        }
    }

    /// Open a file for reading.
    ///
    /// The path is relative to the sandbox root. Policy is checked before opening.
    /// Requires a `DecisionToken` from `Kernel::decide()` proving the operation
    /// was authorized.
    pub fn open(
        &self,
        path: impl AsRef<Path>,
        decision: DecisionToken,
        authority: Authority,
    ) -> Result<File> {
        decision.redeem(&self.permissions, Operation::ReadFiles)?;
        self.spend_as(authority, Operation::ReadFiles, SinkClass::AuditLogAppend)?;
        self.open_internal(path.as_ref(), None)
    }

    /// Open a file for reading with an approval token.
    pub fn open_approved(
        &self,
        path: impl AsRef<Path>,
        decision: DecisionToken,
        approval: &ApprovalToken,
        authority: Authority,
    ) -> Result<File> {
        decision.redeem(&self.permissions, Operation::ReadFiles)?;
        self.spend_as(authority, Operation::ReadFiles, SinkClass::AuditLogAppend)?;
        self.open_internal(path.as_ref(), Some(approval))
    }

    fn open_internal(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<File> {
        let path = &self.root_relative(path)?;
        self.check_read_capability(path, approval)?;
        self.check_policy(path)?;

        self.root.open(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                NucleusError::Io(e)
            } else {
                NucleusError::SandboxEscape {
                    path: path.to_path_buf(),
                }
            }
        })
    }

    /// Open a file with custom options.
    pub fn open_with(
        &self,
        path: impl AsRef<Path>,
        options: &OpenOptions,
        decision: DecisionToken,
        authority: Authority,
    ) -> Result<File> {
        decision.redeem(&self.permissions, Operation::EditFiles)?;
        self.spend_as(authority, Operation::EditFiles, SinkClass::WorkspaceWrite)?;
        self.open_with_internal(path.as_ref(), options, None)
    }

    /// Open a file with custom options and an approval token.
    pub fn open_with_approved(
        &self,
        path: impl AsRef<Path>,
        options: &OpenOptions,
        decision: DecisionToken,
        approval: &ApprovalToken,
        authority: Authority,
    ) -> Result<File> {
        decision.redeem(&self.permissions, Operation::EditFiles)?;
        self.spend_as(authority, Operation::EditFiles, SinkClass::WorkspaceWrite)?;
        self.open_with_internal(path.as_ref(), options, Some(approval))
    }

    fn open_with_internal(
        &self,
        path: &Path,
        options: &OpenOptions,
        approval: Option<&ApprovalToken>,
    ) -> Result<File> {
        let path = &self.root_relative(path)?;
        // OpenOptions can include write or truncation; conservatively treat as edit.
        self.check_edit_capability(path, approval)?;
        self.check_policy(path)?;

        self.root
            .open_with(path, options)
            .map_err(|e| classify_path_io(path.to_path_buf(), &e))
    }

    /// Create a new file for writing.
    ///
    /// The path is relative to the sandbox root. Policy is checked before creating.
    pub fn create(
        &self,
        path: impl AsRef<Path>,
        decision: DecisionToken,
        authority: Authority,
    ) -> Result<File> {
        decision.redeem(&self.permissions, Operation::WriteFiles)?;
        self.spend_as(authority, Operation::WriteFiles, SinkClass::WorkspaceWrite)?;
        self.create_internal(path.as_ref(), None)
    }

    /// Create a new file for writing with an approval token.
    pub fn create_approved(
        &self,
        path: impl AsRef<Path>,
        decision: DecisionToken,
        approval: &ApprovalToken,
        authority: Authority,
    ) -> Result<File> {
        decision.redeem(&self.permissions, Operation::WriteFiles)?;
        self.spend_as(authority, Operation::WriteFiles, SinkClass::WorkspaceWrite)?;
        self.create_internal(path.as_ref(), Some(approval))
    }

    fn create_internal(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<File> {
        let path = &self.root_relative(path)?;
        self.check_write_capability(path, approval)?;
        self.check_policy(path)?;

        self.root
            .create(path)
            .map_err(|e| classify_path_io(path.to_path_buf(), &e))
    }

    /// Read a file's contents as bytes.
    pub fn read(
        &self,
        path: impl AsRef<Path>,
        decision: DecisionToken,
        authority: Authority,
    ) -> Result<Vec<u8>> {
        decision.redeem(&self.permissions, Operation::ReadFiles)?;
        self.spend_as(authority, Operation::ReadFiles, SinkClass::AuditLogAppend)?;
        self.read_internal(path.as_ref(), None)
    }

    /// Snapshot bounded bytes from a regular file under the same read decision,
    /// discharge, capability and path checks as `read`. Nonblocking open keeps
    /// an attacker-supplied FIFO from hanging artifact collection.
    pub fn read_bounded(
        &self,
        path: impl AsRef<Path>,
        limit: usize,
        decision: DecisionToken,
        authority: Authority,
    ) -> Result<Vec<u8>> {
        use std::io::Read;
        decision.redeem(&self.permissions, Operation::ReadFiles)?;
        self.spend_as(authority, Operation::ReadFiles, SinkClass::AuditLogAppend)?;
        let path = self.root_relative(path.as_ref())?;
        self.check_read_capability(&path, None)?;
        self.check_policy(&path)?;
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NONBLOCK);
        }
        let file = self
            .root
            .open_with(&path, &options)
            .map_err(|e| classify_path_io(path.clone(), &e))?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > limit as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "artifact must be a bounded regular file",
            )
            .into());
        }
        let bound = limit.checked_add(1).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "artifact limit overflow")
        })?;
        let mut bytes = Vec::new();
        file.take(bound as u64).read_to_end(&mut bytes)?;
        if bytes.len() > limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "artifact grew beyond its limit",
            )
            .into());
        }
        Ok(bytes)
    }

    /// Read a file's contents as bytes with an approval token.
    pub fn read_approved(
        &self,
        path: impl AsRef<Path>,
        decision: DecisionToken,
        approval: &ApprovalToken,
        authority: Authority,
    ) -> Result<Vec<u8>> {
        decision.redeem(&self.permissions, Operation::ReadFiles)?;
        self.spend_as(authority, Operation::ReadFiles, SinkClass::AuditLogAppend)?;
        self.read_internal(path.as_ref(), Some(approval))
    }

    fn read_internal(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<Vec<u8>> {
        let path = &self.root_relative(path)?;
        self.check_read_capability(path, approval)?;
        self.check_policy(path)?;

        self.root
            .read(path)
            .map_err(|e| classify_path_io(path.to_path_buf(), &e))
    }

    /// Read a file's contents as a string.
    pub fn read_to_string(
        &self,
        path: impl AsRef<Path>,
        decision: DecisionToken,
        authority: Authority,
    ) -> Result<String> {
        decision.redeem(&self.permissions, Operation::ReadFiles)?;
        self.spend_as(authority, Operation::ReadFiles, SinkClass::AuditLogAppend)?;
        self.read_to_string_internal(path.as_ref(), None)
    }

    /// Read a file's contents as a string with an approval token.
    pub fn read_to_string_approved(
        &self,
        path: impl AsRef<Path>,
        decision: DecisionToken,
        approval: &ApprovalToken,
        authority: Authority,
    ) -> Result<String> {
        decision.redeem(&self.permissions, Operation::ReadFiles)?;
        self.spend_as(authority, Operation::ReadFiles, SinkClass::AuditLogAppend)?;
        self.read_to_string_internal(path.as_ref(), Some(approval))
    }

    fn read_to_string_internal(
        &self,
        path: &Path,
        approval: Option<&ApprovalToken>,
    ) -> Result<String> {
        let path = &self.root_relative(path)?;
        self.check_read_capability(path, approval)?;
        self.check_policy(path)?;

        self.root
            .read_to_string(path)
            .map_err(|e| classify_path_io(path.to_path_buf(), &e))
    }

    /// Write bytes to a file (creates if needed, truncates if exists).
    ///
    /// Requires a `&DischargedBundle` proof (mint via
    /// [`preflight_action`](nucleus_ifc_kernel::discharge::preflight_action),
    /// e.g. the tool-proxy's `run_gate::preflight_fs`). This makes the
    /// FILESYSTEM-WRITE effect class a *compile*-checked precondition — parity
    /// with the spawn executor-proof gate ([`Executor::run_args`](crate::Executor)
    /// and the net [`NetEffect::fetch`]) — so an un-preflighted fs write cannot be
    /// typed. The existing `DecisionToken` and cap-std root confinement are
    /// retained (dual-stack, additive): the proof does not replace them. The
    /// bundle is a sealed 8-witness proof that only `preflight_action` can mint;
    /// there is no other constructor, so a caller that reaches this method has
    /// necessarily passed the fail-closed discharge preflight.
    ///
    /// The following omits the proof and does **not** compile (mirrors the
    /// sealed-bundle `compile_fail` doctest in `nucleus_ifc_kernel::discharge`
    /// and the spawn gate in `command.rs`):
    ///
    /// ```compile_fail
    /// use nucleus::Sandbox;
    /// use nucleus::portcullis::kernel::DecisionToken;
    ///
    /// fn un_preflighted_write(sandbox: &Sandbox, dt: &DecisionToken) {
    ///     // No trailing `Authority` — the sealed proof is missing, so this
    ///     // call cannot be typed. There is no way to write without one, and
    ///     // the one supplied must have been earned FOR a workspace write.
    ///     let _ = sandbox.write("out.txt", b"data", dt);
    /// }
    /// ```
    pub fn write(
        &self,
        path: impl AsRef<Path>,
        contents: impl AsRef<[u8]>,
        decision: DecisionToken,
        authority: Authority,
    ) -> Result<()> {
        // The SAME operation the capability check below will use, and the same
        // one the reference monitor upstream decided about: writing over an
        // existing file is an edit. Hardcoding `WriteFiles` here made the
        // authority spend disagree with the discharge bundle the caller had
        // minted — "bundle authorises EditFiles/WorkspaceWrite, this effect is
        // WriteFiles/WorkspaceWrite" — measured on a live pod.
        let op = self.write_operation_for(path.as_ref());
        decision.redeem(&self.permissions, op)?;
        self.spend_as(authority, op, SinkClass::WorkspaceWrite)?;
        self.write_internal(path.as_ref(), contents, None)
    }

    /// Write bytes to a file with an approval token.
    ///
    /// The approval-elevated sibling of [`Self::write`]; it is behind the same
    /// FILESYSTEM-WRITE effect gate and requires a `&DischargedBundle` proof in
    /// addition to the `ApprovalToken` (parity with
    /// [`Executor::run_args_with_approval`](crate::Executor)).
    pub fn write_approved(
        &self,
        path: impl AsRef<Path>,
        contents: impl AsRef<[u8]>,
        decision: DecisionToken,
        approval: &ApprovalToken,
        authority: Authority,
    ) -> Result<()> {
        // The SAME operation the capability check below will use, and the same
        // one the reference monitor upstream decided about: writing over an
        // existing file is an edit. Hardcoding `WriteFiles` here made the
        // authority spend disagree with the discharge bundle the caller had
        // minted — "bundle authorises EditFiles/WorkspaceWrite, this effect is
        // WriteFiles/WorkspaceWrite" — measured on a live pod.
        let op = self.write_operation_for(path.as_ref());
        decision.redeem(&self.permissions, op)?;
        self.spend_as(authority, op, SinkClass::WorkspaceWrite)?;
        self.write_internal(path.as_ref(), contents, Some(approval))
    }

    /// Spend a write authority, refusing one earned for anything else.
    ///
    /// Both write entry points previously took the bundle as `_proof` and never
    /// read it, so ANY bundle authorized a write — the confused deputy, and the
    /// same defect fixed in `NucleusRuntime` (#2087). The doc-test above claimed
    /// "there is no way to write without one", which was true of *presenting* a
    /// bundle and false of presenting the *right* one.
    ///
    /// Takes `&self` so it can attach the sandbox's receipt log. It was an
    /// associated function, which is precisely why it could not witness: there
    /// was no log in scope, and `spend` accepted that silently.
    fn spend_as(&self, authority: Authority, op: Operation, sink: SinkClass) -> Result<()> {
        authority
            .witnessed_by(Arc::clone(&self.receipts))
            .spend(op, sink)
            .map(drop)
            .map_err(|e| NucleusError::ScopeMismatch {
                reason: e.to_string(),
            })
    }

    fn write_internal(
        &self,
        path: &Path,
        contents: impl AsRef<[u8]>,
        approval: Option<&ApprovalToken>,
    ) -> Result<()> {
        let path = &self.root_relative(path)?;
        self.check_policy(path)?;
        self.check_write_or_edit_capability(path, approval)?;

        self.write_owned(path, contents.as_ref())
            .map_err(|e| classify_path_io(path.to_path_buf(), &e))
    }

    /// `Dir::write`, except that a file this call CREATES is handed to the
    /// child uid on the creating handle. An existing file is truncated in
    /// place and keeps its owner, as before.
    pub(crate) fn write_owned(&self, path: &Path, contents: &[u8]) -> std::io::Result<()> {
        if self.child_owner.is_none() {
            return self.root.write(path, contents);
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        match self.root.open_with(path, &options) {
            Ok(mut file) => {
                self.hand_over_fd(&file)?;
                std::io::Write::write_all(&mut file, contents)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                self.root.write(path, contents)
            }
            Err(e) => Err(e),
        }
    }

    /// Create a directory.
    pub fn create_dir(
        &self,
        path: impl AsRef<Path>,
        decision: DecisionToken,
        authority: Authority,
    ) -> Result<()> {
        decision.redeem(&self.permissions, Operation::WriteFiles)?;
        self.spend_as(authority, Operation::WriteFiles, SinkClass::WorkspaceWrite)?;
        self.create_dir_internal(path.as_ref(), None)
    }

    /// Create a directory with an approval token.
    pub fn create_dir_approved(
        &self,
        path: impl AsRef<Path>,
        decision: DecisionToken,
        approval: &ApprovalToken,
        authority: Authority,
    ) -> Result<()> {
        decision.redeem(&self.permissions, Operation::WriteFiles)?;
        self.spend_as(authority, Operation::WriteFiles, SinkClass::WorkspaceWrite)?;
        self.create_dir_internal(path.as_ref(), Some(approval))
    }

    fn create_dir_internal(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<()> {
        let path = &self.root_relative(path)?;
        self.check_write_capability(path, approval)?;
        self.check_policy(path)?;

        self.root
            .create_dir(path)
            .and_then(|()| self.hand_over_dir(path))
            .map_err(|e| classify_path_io(path.to_path_buf(), &e))
    }

    /// Create a directory and all parent directories.
    pub fn create_dir_all(
        &self,
        path: impl AsRef<Path>,
        decision: DecisionToken,
        authority: Authority,
    ) -> Result<()> {
        decision.redeem(&self.permissions, Operation::WriteFiles)?;
        self.spend_as(authority, Operation::WriteFiles, SinkClass::WorkspaceWrite)?;
        self.create_dir_all_internal(path.as_ref(), None)
    }

    /// Create a directory and all parent directories with an approval token.
    pub fn create_dir_all_approved(
        &self,
        path: impl AsRef<Path>,
        decision: DecisionToken,
        approval: &ApprovalToken,
        authority: Authority,
    ) -> Result<()> {
        decision.redeem(&self.permissions, Operation::WriteFiles)?;
        self.spend_as(authority, Operation::WriteFiles, SinkClass::WorkspaceWrite)?;
        self.create_dir_all_internal(path.as_ref(), Some(approval))
    }

    fn create_dir_all_internal(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<()> {
        let path = &self.root_relative(path)?;
        self.check_write_capability(path, approval)?;
        self.check_policy(path)?;

        // Only the components THIS call creates are handed over; a directory
        // that already existed keeps whatever owner it had.
        let created: Vec<PathBuf> = if self.child_owner.is_some() {
            path.ancestors()
                .filter(|p| !p.as_os_str().is_empty() && !self.root.exists(p))
                .map(Path::to_path_buf)
                .collect()
        } else {
            Vec::new()
        };
        self.root
            .create_dir_all(path)
            .and_then(|()| {
                // Outermost first, so each is handed over before what it holds.
                created.iter().rev().try_for_each(|p| self.hand_over_dir(p))
            })
            .map_err(|e| classify_path_io(path.to_path_buf(), &e))
    }

    /// Remove a file.
    pub fn remove_file(
        &self,
        path: impl AsRef<Path>,
        decision: DecisionToken,
        authority: Authority,
    ) -> Result<()> {
        decision.redeem(&self.permissions, Operation::EditFiles)?;
        self.spend_as(authority, Operation::EditFiles, SinkClass::WorkspaceWrite)?;
        self.remove_file_internal(path.as_ref(), None)
    }

    /// Remove a file with an approval token.
    pub fn remove_file_approved(
        &self,
        path: impl AsRef<Path>,
        decision: DecisionToken,
        approval: &ApprovalToken,
        authority: Authority,
    ) -> Result<()> {
        decision.redeem(&self.permissions, Operation::EditFiles)?;
        self.spend_as(authority, Operation::EditFiles, SinkClass::WorkspaceWrite)?;
        self.remove_file_internal(path.as_ref(), Some(approval))
    }

    fn remove_file_internal(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<()> {
        let path = &self.root_relative(path)?;
        self.check_edit_capability(path, approval)?;
        self.check_policy(path)?;

        self.root
            .remove_file(path)
            .map_err(|e| classify_path_io(path.to_path_buf(), &e))
    }

    /// Remove an empty directory.
    pub fn remove_dir(
        &self,
        path: impl AsRef<Path>,
        decision: DecisionToken,
        authority: Authority,
    ) -> Result<()> {
        decision.redeem(&self.permissions, Operation::EditFiles)?;
        self.spend_as(authority, Operation::EditFiles, SinkClass::WorkspaceWrite)?;
        self.remove_dir_internal(path.as_ref(), None)
    }

    /// Remove an empty directory with an approval token.
    pub fn remove_dir_approved(
        &self,
        path: impl AsRef<Path>,
        decision: DecisionToken,
        approval: &ApprovalToken,
        authority: Authority,
    ) -> Result<()> {
        decision.redeem(&self.permissions, Operation::EditFiles)?;
        self.spend_as(authority, Operation::EditFiles, SinkClass::WorkspaceWrite)?;
        self.remove_dir_internal(path.as_ref(), Some(approval))
    }

    fn remove_dir_internal(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<()> {
        let path = &self.root_relative(path)?;
        self.check_edit_capability(path, approval)?;
        self.check_policy(path)?;

        self.root
            .remove_dir(path)
            .map_err(|e| classify_path_io(path.to_path_buf(), &e))
    }

    /// Check if a path exists within the sandbox.
    ///
    /// `Result<bool>`, not `bool`: a decision minted for another operation means
    /// this cannot answer, and "I did not look" must not be returned as "it is
    /// not there" (ADR 0007 A-2). Before the scope check was enforced there was
    /// no third answer to return, so there was no reason for the `Result`.
    pub fn exists(&self, path: impl AsRef<Path>, decision: DecisionToken) -> Result<bool> {
        decision.redeem(&self.permissions, Operation::ReadFiles)?;
        Ok(self.exists_internal(path.as_ref(), None))
    }

    /// Check if a path exists within the sandbox with an approval token.
    pub fn exists_approved(
        &self,
        path: impl AsRef<Path>,
        decision: DecisionToken,
        approval: &ApprovalToken,
    ) -> Result<bool> {
        decision.redeem(&self.permissions, Operation::ReadFiles)?;
        Ok(self.exists_internal(path.as_ref(), Some(approval)))
    }

    fn exists_internal(&self, path: &Path, approval: Option<&ApprovalToken>) -> bool {
        let Ok(path) = self.root_relative(path) else {
            return false;
        };
        let path = &path;
        if self.check_read_capability(path, approval).is_err() {
            return false;
        }
        if self.check_policy(path).is_err() {
            return false;
        }
        self.root.exists(path)
    }

    /// Which capability a write to `path` will actually be checked against.
    ///
    /// [`Operation::EditFiles`] when the path already exists,
    /// [`Operation::WriteFiles`] when it does not — the same test
    /// `check_write_or_edit_capability` makes, exposed so the reference monitor
    /// upstream can decide about the SAME operation this sandbox will enforce.
    ///
    /// It has to be exposed rather than guessed. The HTTP write path mediated
    /// every write as `WriteFiles`, so writing over an existing file was
    /// decided by the kernel as one operation and enforced here as another: the
    /// caller was told to approve `WriteFiles notes.txt`, did, and was then
    /// refused for want of `EditFiles notes.txt`. Measured on a live pod
    /// (`nucleus-perf agency`, task `edit-an-existing-file`). The audit record
    /// was wrong in the same way — an edit recorded as a write.
    ///
    /// Deliberately NOT gated on a `DecisionToken`, unlike [`Self::exists`].
    /// It answers one bit about a path inside the pod's own workspace, which
    /// `glob` already answers in bulk, and its only use is choosing which of
    /// two gates applies. Gating it would force the caller to guess the
    /// operation before it may ask which operation it is, which is precisely
    /// the ordering that produced the mismatch.
    #[must_use]
    pub fn write_operation_for(&self, path: impl AsRef<Path>) -> Operation {
        if self.root.exists(path.as_ref()) {
            Operation::EditFiles
        } else {
            Operation::WriteFiles
        }
    }

    /// Get the absolute path of the sandbox root.
    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    /// The capability handle on the sandbox root, for the executor's
    /// execute-on-consume guard: it walks and restores through this, so it can
    /// no more follow a symlink out of the workspace than the sandbox can.
    pub(crate) fn root_dir(&self) -> &Dir {
        &self.root
    }

    /// Read a file for search/grep operations (#1273).
    ///
    /// Uses the cap-std sandbox directory for I/O, bypassing raw `std::fs`.
    ///
    /// Takes no `DecisionToken` — the caller obtains a GrepSearch decision via
    /// `kernel_decide` — but it DOES require an `Authority` scoped to
    /// `(GrepSearch, AuditLogAppend)`. That requirement used to be a comment
    /// saying the caller "must have already obtained a decision", which is a
    /// convention rather than an enforcement; the `mediated` lint flagged it as
    /// an agent-reachable read with no discharge.
    ///
    /// Returns `Err` for paths outside the sandbox or unreadable files.
    pub fn read_to_string_for_search(&self, path: &Path, authority: Authority) -> Result<String> {
        let path = &self.root_relative(path)?;
        self.spend_as(authority, Operation::GrepSearch, SinkClass::AuditLogAppend)?;
        self.check_policy(path)?;
        self.root
            .read_to_string(path)
            .map_err(|e| classify_path_io(path.to_path_buf(), &e))
    }

    /// List entries under `dir` whose path matches `pattern`.
    ///
    /// **Why this exists (2026-09-27).** Both glob transports in the tool proxy
    /// walked the host filesystem through `glob::glob` on an absolute pattern
    /// built by joining the request onto the root path: `std::fs`, following
    /// symlinks, and then canonicalizing each hit to see whether it had left the
    /// root. The decision token was dropped on the floor (`let _ =` over HTTP,
    /// `Ok(_decision_token) => {}` over MCP) and no discharge was minted, so
    /// the walk did not need the decision that preceded it — it was Checked,
    /// not Sealed, and one refactor from being neither. `RealEffects::glob` is
    /// not a substitute: it discards its authority and walks the process CWD.
    ///
    /// Here the order is fixed by the body, not by the caller:
    ///
    /// 1. the `DecisionToken` is redeemed for `GlobSearch` under this sandbox's
    ///    permissions;
    /// 2. the `Authority` is spent as `(GlobSearch, AuditLogAppend)`, so a
    ///    bundle earned for a read, a grep or a write cannot pay for a listing;
    /// 3. `glob_search` at `Never` refuses;
    /// 4. `pattern` is refused if absolute or if it contains `..`; `dir` is
    ///    passed through `root_relative` (an absolute spelling under the root
    ///    is the same directory, #2787) and then refused if anything but plain
    ///    names remain;
    /// 5. the walk runs over the cap-std `Dir` handle — never `std::fs` —
    ///    does not follow or list symlinks, opens each subdirectory with
    ///    `O_NOFOLLOW` so a directory swapped for a link mid-walk is refused
    ///    rather than entered, and runs `check_policy` on every entry it would
    ///    report.
    ///
    /// `pattern` is matched against the path relative to `dir`; the listing is
    /// relative to the root. Directories the policy withholds are still
    /// descended, because a policy of `src/**` does not match `src` itself;
    /// their contents face the same per-entry check. Approval obligations stay
    /// with the caller, as they do for the transports today; only the
    /// capability level is checked here.
    ///
    /// The pattern language is the `glob` crate's with a literal separator —
    /// `*` does not cross `/`, `**/` spans directories — which is what the
    /// transports' `glob::glob` gave agents before.
    pub fn glob(
        &self,
        dir: Option<&Path>,
        pattern: &str,
        max: std::num::NonZeroUsize,
        decision: DecisionToken,
        authority: Authority,
    ) -> Result<GlobListing> {
        decision.redeem(&self.permissions, Operation::GlobSearch)?;
        self.spend_as(authority, Operation::GlobSearch, SinkClass::AuditLogAppend)?;
        if self.capabilities.glob_search == CapabilityLevel::Never {
            return Err(NucleusError::InsufficientCapability {
                capability: "glob_search".into(),
                actual: CapabilityLevel::Never,
                required: CapabilityLevel::LowRisk,
            });
        }

        let pattern_path = Path::new(pattern);
        if pattern_path.is_absolute()
            || pattern.starts_with('/')
            || pattern.split(['/', '\\']).any(|c| c == "..")
        {
            return Err(NucleusError::SandboxEscape {
                path: pattern_path.to_path_buf(),
            });
        }
        let dir = match dir {
            Some(d) => self.root_relative(d)?,
            None => PathBuf::new(),
        };
        if dir.components().any(|c| {
            !matches!(
                c,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        }) {
            return Err(NucleusError::SandboxEscape { path: dir });
        }

        let matcher = glob::Pattern::new(pattern).map_err(|e| {
            NucleusError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid glob pattern: {e}"),
            ))
        })?;
        // Without `**` a pattern cannot match deeper than it has components,
        // so `*.rs` reads one directory rather than the whole tree.
        let depth_bound = if pattern.contains("**") {
            None
        } else {
            Some(pattern.split('/').filter(|c| !c.is_empty()).count())
        };

        let start = if dir.as_os_str().is_empty() {
            self.root.try_clone()?
        } else {
            self.root
                .open_dir(&dir)
                .map_err(|e| classify_path_io(dir.clone(), &e))?
        };

        let mut walk = GlobWalk {
            sandbox: self,
            matcher,
            depth_bound,
            max: max.get(),
            matches: Vec::new(),
            completeness: Completeness::Complete,
            skipped: 0,
        };
        walk.visit(&start, &dir, Path::new(""), 1);
        Ok(GlobListing {
            matches: walk.matches,
            completeness: walk.completeness,
            skipped: walk.skipped,
        })
    }

    /// Interpret a caller-supplied path against the sandbox root.
    ///
    /// A relative path is returned unchanged. An absolute path that is
    /// lexically under the root is returned with the root stripped, so the two
    /// spellings of the same file behave identically -- which is what every
    /// agent harness fronting this sandbox assumes, and what `/work/hello.txt`
    /// vs `hello.txt` used to disagree about (#2787). An absolute path that is
    /// *not* under the root keeps its refusal, and only now is the error's own
    /// claim ("resolves outside sandbox root") true: before this, the root was
    /// never consulted.
    ///
    /// Stripping cannot widen what is reachable. The result is fed through
    /// exactly the checks a relative path already faced -- the path policy
    /// here, and `cap-std`'s containment on the `Dir` handle at the point of
    /// I/O, which is what actually refuses `..` traversal and symlinks out.
    pub fn root_relative(&self, path: &Path) -> Result<PathBuf> {
        if !path.is_absolute() {
            return Ok(path.to_path_buf());
        }
        path.strip_prefix(&self.root_path)
            .map(Path::to_path_buf)
            .map_err(|_| NucleusError::SandboxEscape {
                path: path.to_path_buf(),
            })
    }

    /// Check if a path is allowed by the policy.
    fn check_policy(&self, path: &Path) -> Result<()> {
        // Absolute paths are interpreted against the root first; what survives
        // is relative, or a genuine escape.
        let path = self.root_relative(path)?;
        let path_str = path.to_string_lossy();

        // Check against portcullis policy
        // Note: We pass the relative path to the policy checker
        if !self.policy.can_access(&path) {
            return Err(NucleusError::PathDenied {
                path: path.clone(),
                reason: format!("blocked by path policy: {}", path_str),
            });
        }

        Ok(())
    }

    fn check_read_capability(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<()> {
        self.check_capability(
            Operation::ReadFiles,
            "read_files",
            self.capabilities.read_files,
            path,
            approval,
        )
    }

    fn check_write_capability(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<()> {
        self.check_capability(
            Operation::WriteFiles,
            "write_files",
            self.capabilities.write_files,
            path,
            approval,
        )
    }

    fn check_edit_capability(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<()> {
        self.check_capability(
            Operation::EditFiles,
            "edit_files",
            self.capabilities.edit_files,
            path,
            approval,
        )
    }

    fn check_write_or_edit_capability(
        &self,
        path: &Path,
        approval: Option<&ApprovalToken>,
    ) -> Result<()> {
        if self.root.exists(path) {
            self.check_edit_capability(path, approval)
        } else {
            self.check_write_capability(path, approval)
        }
    }

    /// [`crate::approval::approval_key`] for a path subject.
    ///
    /// A thin forward on purpose: the rule lives with `ApprovalRequest`, next
    /// to the type it names, so the file sandbox and the command executor
    /// cannot drift apart by each keeping their own copy of it.
    #[must_use]
    pub fn approval_key(op: Operation, subject: &Path) -> String {
        crate::approval_key(op, &subject.display().to_string())
    }

    fn check_capability(
        &self,
        op: Operation,
        capability_name: &str,
        level: CapabilityLevel,
        subject: &Path,
        approval: Option<&ApprovalToken>,
    ) -> Result<()> {
        let operation = &Self::approval_key(op, subject);
        if level == CapabilityLevel::Never {
            return Err(NucleusError::InsufficientCapability {
                capability: capability_name.into(),
                actual: level,
                required: CapabilityLevel::LowRisk,
            });
        }

        // A write to a file some host tool executes on reading it needs an
        // approval whatever the capability level says (`EXECUTE_ON_CONSUME`).
        // Keyed by the path, so approving one hook approves that hook only.
        let executes_on_consume = matches!(op, Operation::WriteFiles | Operation::EditFiles)
            && portcullis::executes_on_consume(&subject.to_string_lossy()).is_some();
        if self.obligations.requires(op) || executes_on_consume {
            if let Some(token) = approval {
                if token.matches(operation) {
                    Ok(())
                } else {
                    Err(NucleusError::InvalidApproval {
                        operation: operation.to_string(),
                    })
                }
            } else {
                Err(NucleusError::ApprovalRequired {
                    operation: operation.to_string(),
                })
            }
        } else {
            Ok(())
        }
    }

    /// Open a subdirectory as a new sandbox.
    ///
    /// The returned sandbox is constrained to the subdirectory and inherits
    /// the parent's policy (which will further restrict access).
    pub fn open_dir(
        &self,
        path: impl AsRef<Path>,
        decision: DecisionToken,
        authority: Authority,
    ) -> Result<Sandbox> {
        decision.redeem(&self.permissions, Operation::ReadFiles)?;
        self.spend_as(authority, Operation::ReadFiles, SinkClass::AuditLogAppend)?;
        self.open_dir_internal(path.as_ref(), None)
    }

    /// Open a subdirectory as a new sandbox with an approval token.
    pub fn open_dir_approved(
        &self,
        path: impl AsRef<Path>,
        decision: DecisionToken,
        approval: &ApprovalToken,
        authority: Authority,
    ) -> Result<Sandbox> {
        decision.redeem(&self.permissions, Operation::ReadFiles)?;
        self.spend_as(authority, Operation::ReadFiles, SinkClass::AuditLogAppend)?;
        self.open_dir_internal(path.as_ref(), Some(approval))
    }

    fn open_dir_internal(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<Sandbox> {
        let path = &self.root_relative(path)?;
        self.check_read_capability(path, approval)?;
        self.check_policy(path)?;

        let subdir = self
            .root
            .open_dir(path)
            .map_err(|e| classify_path_io(path.to_path_buf(), &e))?;

        Ok(Sandbox {
            receipts: Arc::new(portcullis_effects::receipt::ReceiptLog::new()),
            root: subdir,
            root_path: self.root_path.join(path),
            policy: self.policy.clone(),
            capabilities: self.capabilities.clone(),
            obligations: self.obligations.clone(),
            approver: self.approver.clone(),
            // A subdirectory enforces the SAME permissions as its parent — the
            // path narrows, the policy does not — so a token redeemable here is
            // redeemable there.
            permissions: self.permissions.clone(),
            // And the same children: what it creates goes to the same uid.
            child_owner: self.child_owner,
        })
    }
}

/// The recursive state of one [`Sandbox::glob`] call.
struct GlobWalk<'a> {
    sandbox: &'a Sandbox,
    matcher: glob::Pattern,
    depth_bound: Option<usize>,
    max: usize,
    matches: Vec<PathBuf>,
    completeness: Completeness,
    skipped: usize,
}

impl GlobWalk<'_> {
    /// `rel_root` is `here`'s path from the sandbox root (for the policy and
    /// the listing); `rel_pattern` is its path from the search directory (for
    /// the pattern). Stops once a match past `max` has been seen.
    fn visit(&mut self, here: &Dir, rel_root: &Path, rel_pattern: &Path, depth: usize) {
        let Ok(entries) = here.entries() else {
            self.skipped += 1;
            return;
        };
        let mut entries: Vec<_> = entries
            .filter_map(|e| match e {
                Ok(e) => Some(e),
                Err(_) => {
                    self.skipped += 1;
                    None
                }
            })
            .collect();
        entries.sort_by_key(cap_std::fs::DirEntry::file_name);

        for entry in entries {
            if self.completeness == Completeness::Truncated {
                return;
            }
            // `DirEntry::file_type` is the entry's own type (lstat), so a
            // symlink reads as a symlink and is neither listed nor entered.
            let Ok(file_type) = entry.file_type() else {
                self.skipped += 1;
                continue;
            };
            if file_type.is_symlink() {
                self.skipped += 1;
                continue;
            }
            let name = entry.file_name();
            let from_root = rel_root.join(&name);
            let from_pattern = rel_pattern.join(&name);

            if self.matcher.matches_path_with(&from_pattern, GLOB_OPTIONS) {
                if self.sandbox.check_policy(&from_root).is_err() {
                    self.skipped += 1;
                } else if self.matches.len() == self.max {
                    self.completeness = Completeness::Truncated;
                    return;
                } else {
                    self.matches.push(from_root.clone());
                }
            }

            let descend = file_type.is_dir() && self.depth_bound.is_none_or(|b| depth < b);
            if descend {
                match open_dir_nofollow(&entry) {
                    Ok(sub) => self.visit(&sub, &from_root, &from_pattern, depth + 1),
                    Err(_) => self.skipped += 1,
                }
            }
        }
    }
}

/// `*` does not cross `/`, as it did not under `glob::glob`'s per-component
/// walk; a leading dot is matched like any other character, as before.
const GLOB_OPTIONS: glob::MatchOptions = glob::MatchOptions {
    case_sensitive: true,
    require_literal_separator: true,
    require_literal_leading_dot: false,
};

/// Open a directory entry without following a symlink at its final component.
///
/// The walk has already refused entries whose type is a symlink; this closes
/// the window between that check and the open, in which the directory could be
/// replaced by a link. cap-std would still refuse a link that leaves the root,
/// but a link to elsewhere INSIDE the root would be entered and its contents
/// reported under the wrong name.
fn open_dir_nofollow(entry: &cap_std::fs::DirEntry) -> std::io::Result<Dir> {
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
        let file = entry.open_with(&options)?;
        Ok(Dir::from_std_file(file.into_std()))
    }
    #[cfg(not(unix))]
    {
        entry.open_dir()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Sanctioned test-only sealed bundle (WriteFiles/WorkspaceWrite term) — the
    // only supported way for a test to obtain a `DischargedBundle` for the
    // `_proof`-gated write path (the constructor is private to discharge).
    use nucleus_ifc_kernel::discharge::test_helpers::{allowed_bundle, bundle_for};
    use portcullis::kernel::Kernel;
    use tempfile::tempdir;

    #[allow(clippy::field_reassign_with_default)]
    fn permissive_policy() -> PermissionLattice {
        let mut policy = PermissionLattice::default();
        policy.paths = PathLattice::default();
        policy.obligations = Obligations::default();
        policy.capabilities.write_files = CapabilityLevel::LowRisk;
        policy.capabilities.edit_files = CapabilityLevel::LowRisk;
        policy
    }

    #[allow(clippy::field_reassign_with_default)]
    fn sensitive_policy() -> PermissionLattice {
        let mut policy = PermissionLattice::default();
        policy.paths = PathLattice::block_sensitive();
        policy.obligations = Obligations::default();
        policy.capabilities.write_files = CapabilityLevel::LowRisk;
        policy.capabilities.edit_files = CapabilityLevel::LowRisk;
        policy
    }

    /// Helper: get a DecisionToken from a permissive kernel for a given operation.
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
    fn token(kernel: &mut Kernel, op: Operation, subject: &str) -> DecisionToken {
        let (_decision, tok) = kernel.decide(op, subject);
        tok.expect("permissive kernel should allow this operation")
    }

    /// EVERY `DecisionToken`-taking method refuses an authority earned for a
    /// different action, and refuses it BEFORE the effect.
    ///
    /// Before this work only `write`/`write_approved` took a discharge at all,
    /// and they ignored it. The rest — including `remove_file`, which deletes —
    /// passed `DecisionToken` + capability-lattice checks but none of the eight
    /// obligations. That is the tier-B state the effect traits were in before
    /// the B1/B2 cutover, and it meant an agent routed through `Sandbox`
    /// bypassed obligations `FileEffect` enforces on the other filesystem path.
    ///
    /// A `git_push`-scoped authority is wrong for all of them, so one authority
    /// kind exercises the whole surface.
    #[test]
    fn no_sandbox_method_accepts_an_authority_earned_elsewhere() {
        let tmp = tempdir().unwrap();
        let policy = PermissionLattice::permissive();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();

        // Seed a file and a directory so failures cannot come from absence.
        std::fs::write(tmp.path().join("seed.txt"), b"seed").unwrap();
        std::fs::create_dir_all(tmp.path().join("seeddir")).unwrap();

        let wrong = || Authority::new(bundle_for(Operation::GitPush, SinkClass::GitPush));
        // A fresh decision per call. `DecisionToken` is taken BY VALUE now, so
        // one token cannot authorise four opens — and this test was relying on
        // the reference form to do exactly that. One closure, because three
        // would each need `&mut kernel` at once.
        let mut tok = |op, path| token(&mut kernel, op, path);

        macro_rules! refused {
            ($label:expr, $call:expr) => {{
                let e = $call.err().unwrap_or_else(|| {
                    panic!("{} accepted an authority earned for GitPush", $label)
                });
                assert!(
                    matches!(e, NucleusError::ScopeMismatch { .. }),
                    "{} refused for the wrong reason: {e:?}",
                    $label
                );
            }};
        }

        refused!(
            "open",
            sandbox.open("seed.txt", tok(Operation::ReadFiles, "seed.txt"), wrong())
        );
        refused!(
            "read",
            sandbox.read("seed.txt", tok(Operation::ReadFiles, "seed.txt"), wrong())
        );
        refused!(
            "read_to_string",
            sandbox.read_to_string("seed.txt", tok(Operation::ReadFiles, "seed.txt"), wrong())
        );
        refused!(
            "open_dir",
            sandbox.open_dir("seeddir", tok(Operation::ReadFiles, "seed.txt"), wrong())
        );
        refused!(
            "create",
            sandbox.create("new.txt", tok(Operation::WriteFiles, "new.txt"), wrong())
        );
        refused!(
            "create_dir",
            sandbox.create_dir("d1", tok(Operation::WriteFiles, "new.txt"), wrong())
        );
        refused!(
            "create_dir_all",
            sandbox.create_dir_all("d2/d3", tok(Operation::WriteFiles, "new.txt"), wrong())
        );
        refused!(
            "remove_file",
            sandbox.remove_file("seed.txt", tok(Operation::EditFiles, "seed.txt"), wrong())
        );
        refused!(
            "remove_dir",
            sandbox.remove_dir("seeddir", tok(Operation::EditFiles, "seed.txt"), wrong())
        );
        refused!(
            "write",
            sandbox.write(
                "new.txt",
                b"x",
                tok(Operation::WriteFiles, "new.txt"),
                wrong()
            )
        );

        // Nothing was created and nothing was deleted.
        assert!(tmp.path().join("seed.txt").exists(), "seed.txt was removed");
        assert!(tmp.path().join("seeddir").exists(), "seeddir was removed");
        assert!(!tmp.path().join("new.txt").exists(), "new.txt was created");
        assert!(!tmp.path().join("d1").exists(), "d1 was created");
    }

    /// The gap this closes: `write` took the bundle as `_proof` and never read
    /// it, so a bundle earned for a READ authorized a write — the confused
    /// deputy, the same defect fixed in `NucleusRuntime` (#2087). The doc-test
    /// on `write` claimed "there is no way to write without one", which was true
    /// of presenting *a* bundle and false of presenting the *right* one.
    #[test]
    fn a_read_authority_will_not_pay_for_a_sandbox_write() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = PermissionLattice::permissive();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();

        let wt = token(&mut kernel, Operation::WriteFiles, "escalated.txt");
        let read_authority =
            Authority::new(bundle_for(Operation::ReadFiles, SinkClass::AuditLogAppend));

        let err = sandbox
            .write("escalated.txt", b"written under a read", wt, read_authority)
            .expect_err("a read authority must not pay for a sandbox write");
        assert!(
            matches!(err, NucleusError::ScopeMismatch { .. }),
            "expected a scope mismatch, got: {err:?}"
        );
        assert!(
            !tmp.path().join("escalated.txt").exists(),
            "the refusal must precede the write, but the file was created"
        );
    }

    /// No false denial: the correctly-scoped authority still writes. A check
    /// that refused everything would satisfy the test above and break the API.
    #[test]
    fn a_write_authority_still_pays_for_a_sandbox_write() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = PermissionLattice::permissive();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();

        let wt = token(&mut kernel, Operation::WriteFiles, "ok.txt");
        sandbox
            .write("ok.txt", b"in scope", wt, Authority::new(allowed_bundle()))
            .expect("a correctly-scoped write must succeed");
        assert!(tmp.path().join("ok.txt").exists());
    }

    /// **The payoff.** Sandbox writes spend their authority directly rather than
    /// through `PolicyEnforced`, which is where every other effect picks up its
    /// witness — so this was the one path in the workspace that authorised an
    /// effect and recorded nothing. `Authority::spend` now refuses an
    /// unwitnessed spend outright, and these six write tests failing is what
    /// surfaced it.
    /// A decision minted for one operation must not authorise another, AND the
    /// refusal has to survive `--release`.
    ///
    /// This check used to be `debug_assert_eq!` at thirty call sites. That
    /// compiles to nothing when `debug_assertions` is off, so in every shipped
    /// build a `ReadFiles` decision handed to the write path was accepted
    /// exactly as readily as the right one — the allow path and the error path
    /// were the same path (ADR 0007 I-3). In a debug build it PANICKED rather
    /// than refusing, which is not a refusal either.
    ///
    /// Run this with `cargo test --release -p nucleus` as well as without. That
    /// is the falsifier: on the old code the release run let the write through.
    #[test]
    fn a_decision_for_another_operation_cannot_authorise_a_write() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = PermissionLattice::permissive();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();

        // A decision about READING, presented to the WRITE entry point.
        let read_token = token(&mut kernel, Operation::ReadFiles, "ok.txt");
        let err = sandbox
            .write(
                "ok.txt",
                b"nope",
                read_token,
                Authority::new(allowed_bundle()),
            )
            .expect_err("a ReadFiles decision must not authorise a write");
        assert!(
            matches!(err, NucleusError::ScopeMismatch { .. }),
            "expected a scope mismatch, got {err:?}"
        );
        assert!(
            !tmp.path().join("ok.txt").exists(),
            "the refusal must happen BEFORE the bytes land"
        );
    }

    #[test]
    fn a_sandbox_write_leaves_a_receipt() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = PermissionLattice::permissive();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        assert_eq!(sandbox.receipts().len(), 0);

        let wt = token(&mut kernel, Operation::WriteFiles, "ok.txt");
        sandbox
            .write("ok.txt", b"in scope", wt, Authority::new(allowed_bundle()))
            .expect("write succeeds");

        let entries = sandbox.receipts().entries();
        assert_eq!(entries.len(), 1, "the write must be recorded: {entries:?}");
        assert_eq!(entries[0].operation, Operation::WriteFiles);
    }

    /// A REFUSED write is recorded too. A log that only held successes would
    /// answer "what was allowed" but not "what was attempted", and the second
    /// question is the one an audit trail exists for.
    #[test]
    fn a_refused_sandbox_write_is_also_recorded() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = PermissionLattice::permissive();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();

        let wt = token(&mut kernel, Operation::WriteFiles, "no.txt");
        // An authority earned for reading cannot buy a write.
        let bundle = bundle_for(Operation::ReadFiles, SinkClass::AuditLogAppend);
        let err = sandbox.write("no.txt", b"nope", wt, Authority::new(bundle));
        assert!(err.is_err(), "a read authority must not buy a write");

        let entries = sandbox.receipts().entries();
        assert_eq!(
            entries.len(),
            1,
            "the refusal must be recorded, not just the successes: {entries:?}"
        );
        assert_eq!(
            entries[0].outcome,
            portcullis_effects::receipt::EffectOutcome::DeniedByScope
        );
    }

    #[test]
    fn test_basic_read_write() {
        let tmp = tempdir().unwrap();
        let policy = permissive_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();

        // Write a file
        let wt = token(&mut kernel, Operation::WriteFiles, "test.txt");
        sandbox
            .write(
                "test.txt",
                b"hello world",
                wt,
                Authority::new(allowed_bundle()),
            )
            .unwrap();

        // Read it back
        let rt = token(&mut kernel, Operation::ReadFiles, "test.txt");
        let contents = sandbox
            .read_to_string(
                "test.txt",
                rt,
                Authority::new(bundle_for(Operation::ReadFiles, SinkClass::AuditLogAppend)),
            )
            .unwrap();
        assert_eq!(contents, "hello world");
    }

    #[test]
    fn bounded_artifact_reads_preserve_bytes_and_refuse_overflow_and_wrong_authority() {
        let tmp = tempdir().unwrap();
        let data = b"binary\0\xff";
        std::fs::write(tmp.path().join("output"), data).unwrap();
        let policy = permissive_policy();
        let mut kernel = Kernel::capability_only(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        for (limit, pass) in [(data.len(), true), (data.len() - 1, false)] {
            let result = sandbox.read_bounded(
                "output",
                limit,
                token(&mut kernel, Operation::ReadFiles, "output"),
                Authority::new(bundle_for(Operation::ReadFiles, SinkClass::AuditLogAppend)),
            );
            if pass {
                assert_eq!(result.unwrap(), data);
            } else {
                assert!(result.is_err());
            }
        }
        assert!(
            sandbox
                .read_bounded(
                    "output",
                    100,
                    token(&mut kernel, Operation::ReadFiles, "output"),
                    Authority::new(allowed_bundle())
                )
                .is_err()
        );
        assert!(
            sandbox
                .read_bounded(
                    ".",
                    100,
                    token(&mut kernel, Operation::ReadFiles, "."),
                    Authority::new(bundle_for(Operation::ReadFiles, SinkClass::AuditLogAppend))
                )
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_artifact_read_refuses_symlink_escape() {
        let root = tempdir().unwrap();
        let other = tempdir().unwrap();
        std::fs::write(other.path().join("secret"), b"outside").unwrap();
        std::os::unix::fs::symlink(other.path().join("secret"), root.path().join("output"))
            .unwrap();
        let policy = permissive_policy();
        let mut kernel = Kernel::capability_only(policy.clone());
        let sandbox = Sandbox::new(&policy, root.path()).unwrap();
        assert!(
            sandbox
                .read_bounded(
                    "output",
                    100,
                    token(&mut kernel, Operation::ReadFiles, "output"),
                    Authority::new(bundle_for(Operation::ReadFiles, SinkClass::AuditLogAppend))
                )
                .is_err()
        );
    }

    #[test]
    fn test_policy_blocks_sensitive() {
        let tmp = tempdir().unwrap();
        let policy = sensitive_policy();
        let mut kernel = Kernel::capability_only(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();

        // Use issue_approved_token to bypass the kernel's PathLattice check.
        // The kernel's can_access() resolves relative paths via the CWD, which
        // on macOS case-insensitive FS may canonicalize to existing files whose
        // absolute path matches blocked patterns like `**/.ssh/**` when
        // running inside a git worktree. This test exercises the *sandbox*'s
        // path policy, not the kernel's.
        let wt = kernel.issue_approved_token(Operation::WriteFiles, "test: write normal file");
        sandbox
            .write(
                "normal_file.txt",
                b"# Hello",
                wt,
                Authority::new(allowed_bundle()),
            )
            .unwrap();

        // Should block .env files (sandbox policy blocks it; kernel also blocks via PathLattice)
        // Force a token to test the sandbox's own path policy enforcement
        let wt2 =
            kernel.issue_approved_token(Operation::WriteFiles, "test: .env blocked by sandbox");
        let result = sandbox.write(".env", b"SECRET=foo", wt2, Authority::new(allowed_bundle()));
        assert!(result.is_err());
    }

    #[test]
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
    fn test_write_requires_capability() {
        let tmp = tempdir().unwrap();
        let mut policy = permissive_policy();
        policy.capabilities.write_files = CapabilityLevel::Never;

        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();

        // Kernel will deny this — no token produced
        let (_decision, tok) = kernel.decide(Operation::WriteFiles, "blocked.txt");
        assert!(tok.is_none(), "kernel should deny Never capability");

        // Even if we bypass the kernel (issue_approved_token for test), sandbox blocks it
        let forced_token = kernel.issue_approved_token(Operation::WriteFiles, "test: force token");
        let result = sandbox.create(
            "blocked.txt",
            forced_token,
            Authority::new(bundle_for(Operation::WriteFiles, SinkClass::WorkspaceWrite)),
        );
        assert!(matches!(
            result,
            Err(NucleusError::InsufficientCapability { .. })
        ));
    }

    #[test]
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
    fn test_write_requires_approval() {
        let tmp = tempdir().unwrap();
        let mut policy = permissive_policy();
        policy.obligations.insert(Operation::WriteFiles);

        let mut kernel = Kernel::new(policy.clone());

        // Without pre-granted approval, kernel returns RequiresApproval — no token
        let (decision, tok) = kernel.decide(Operation::WriteFiles, "needs_approval.txt");
        assert!(
            matches!(
                decision.verdict,
                portcullis::kernel::Verdict::RequiresApproval
            ),
            "should require approval"
        );
        assert!(tok.is_none());

        // Grant approval, then get a token
        kernel.grant_approval(Operation::WriteFiles, 1);
        let (_, tok2) = kernel.decide(Operation::WriteFiles, "approved.txt");
        let decision_token = tok2.expect("should get token after grant_approval");

        let approved = Sandbox::new(&policy, tmp.path())
            .unwrap()
            .with_approval_callback(|_| true);
        // Derived, not spelled out: an approval is named `{Operation:?} {subject}`
        // everywhere (`Sandbox::approval_key`), and a test that hardcoded one
        // gate's wording is how the two vocabularies drifted apart in #2406.
        let approval_token = approved
            .request_approval(Sandbox::approval_key(
                Operation::WriteFiles,
                std::path::Path::new("approved.txt"),
            ))
            .unwrap();
        let result = approved.create_approved(
            "approved.txt",
            decision_token,
            &approval_token,
            Authority::new(bundle_for(Operation::WriteFiles, SinkClass::WorkspaceWrite)),
        );
        assert!(result.is_ok());
    }

    /// A file a host tool runs on reading it needs an approval even under a
    /// policy with no obligations, and the approval names that path. The
    /// control is an ordinary file under the same policy, written freely.
    #[test]
    #[allow(deprecated)] // Migration to decide_term tracked in #1194
    fn writing_a_file_a_host_tool_executes_needs_an_approval() {
        let tmp = tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".github/workflows")).unwrap();
        let policy = permissive_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();

        let hook = ".github/workflows/ci.yml";
        let dt = token(&mut kernel, Operation::WriteFiles, hook);
        let refused = sandbox.write(
            hook,
            "on: push",
            dt,
            Authority::new(bundle_for(Operation::WriteFiles, SinkClass::WorkspaceWrite)),
        );
        match refused {
            Err(NucleusError::ApprovalRequired { operation }) => assert_eq!(
                operation,
                Sandbox::approval_key(Operation::WriteFiles, std::path::Path::new(hook))
            ),
            other => panic!("expected ApprovalRequired naming the path, got {other:?}"),
        }
        assert!(!tmp.path().join(hook).exists(), "refused before the write");

        let dt = token(&mut kernel, Operation::WriteFiles, "src.rs");
        sandbox
            .write(
                "src.rs",
                "fn main() {}",
                dt,
                Authority::new(bundle_for(Operation::WriteFiles, SinkClass::WorkspaceWrite)),
            )
            .expect("the control: an ordinary file needs no approval");
    }

    #[test]
    fn test_escape_via_absolute_path() {
        let tmp = tempdir().unwrap();
        let policy = permissive_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();

        // Absolute paths should be rejected at policy level
        let rt = token(&mut kernel, Operation::ReadFiles, "/etc/passwd");
        let result = sandbox.open(
            "/etc/passwd",
            rt,
            Authority::new(bundle_for(Operation::ReadFiles, SinkClass::AuditLogAppend)),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_subdirectory_sandbox() {
        let tmp = tempdir().unwrap();
        let policy = permissive_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();

        // Create a subdirectory
        let wt1 = token(&mut kernel, Operation::WriteFiles, "subdir");
        sandbox
            .create_dir(
                "subdir",
                wt1,
                Authority::new(bundle_for(Operation::WriteFiles, SinkClass::WorkspaceWrite)),
            )
            .unwrap();

        let wt2 = token(&mut kernel, Operation::WriteFiles, "subdir/file.txt");
        sandbox
            .write(
                "subdir/file.txt",
                b"nested",
                wt2,
                Authority::new(allowed_bundle()),
            )
            .unwrap();

        // Open as sub-sandbox
        let rt1 = token(&mut kernel, Operation::ReadFiles, "subdir");
        let subsandbox = sandbox
            .open_dir(
                "subdir",
                rt1,
                Authority::new(bundle_for(Operation::ReadFiles, SinkClass::AuditLogAppend)),
            )
            .unwrap();

        let rt2 = token(&mut kernel, Operation::ReadFiles, "file.txt");
        let contents = subsandbox
            .read_to_string(
                "file.txt",
                rt2,
                Authority::new(bundle_for(Operation::ReadFiles, SinkClass::AuditLogAppend)),
            )
            .unwrap();
        assert_eq!(contents, "nested");
    }

    // ── Absolute paths under the root (#2787) ────────────────────────────

    /// The measured symptom: the same file, refused by its absolute spelling
    /// and accepted by its relative one.
    #[test]
    fn an_absolute_path_under_the_root_is_the_same_file_as_the_relative_one() {
        let tmp = tempdir().unwrap();
        let policy = permissive_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();

        let wt = token(&mut kernel, Operation::WriteFiles, "hello.txt");
        sandbox
            .write(
                "hello.txt",
                b"hello from the host",
                wt,
                Authority::new(allowed_bundle()),
            )
            .unwrap();

        // Read it back by the absolute spelling an agent harness would use.
        let absolute = sandbox.root_path().join("hello.txt");
        let rt = token(&mut kernel, Operation::ReadFiles, "hello.txt");
        let contents = sandbox
            .read_to_string(
                &absolute,
                rt,
                Authority::new(bundle_for(Operation::ReadFiles, SinkClass::AuditLogAppend)),
            )
            .expect("an absolute path under the root is not an escape");
        assert_eq!(contents, "hello from the host");
    }

    /// Writing by absolute path lands in the same place as writing by relative.
    #[test]
    fn an_absolute_write_lands_at_the_relative_path() {
        let tmp = tempdir().unwrap();
        let policy = permissive_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();

        let absolute = sandbox.root_path().join("written.txt");
        let wt = token(&mut kernel, Operation::WriteFiles, "written.txt");
        sandbox
            .write(&absolute, b"body", wt, Authority::new(allowed_bundle()))
            .expect("absolute write under the root should be accepted");

        let rt = token(&mut kernel, Operation::ReadFiles, "written.txt");
        let via_relative = sandbox
            .read_to_string(
                "written.txt",
                rt,
                Authority::new(bundle_for(Operation::ReadFiles, SinkClass::AuditLogAppend)),
            )
            .unwrap();
        assert_eq!(via_relative, "body");
    }

    /// Accepting absolute paths must not accept absolute paths that leave the
    /// root -- including one spelled as a traversal *through* the root, which
    /// strips to a relative `..` and must still be refused at the `Dir`.
    #[test]
    fn an_absolute_path_outside_the_root_is_still_refused() {
        let tmp = tempdir().unwrap();
        let policy = permissive_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();

        // Plainly outside.
        let rt = token(&mut kernel, Operation::ReadFiles, "/etc/passwd");
        assert!(
            sandbox
                .read_to_string(
                    "/etc/passwd",
                    rt,
                    Authority::new(bundle_for(Operation::ReadFiles, SinkClass::AuditLogAppend)),
                )
                .is_err(),
            "an absolute path outside the root must stay refused"
        );

        // Traversal that passes through the root on its way out.
        let escaping = sandbox.root_path().join("../etc/passwd");
        let rt2 = token(&mut kernel, Operation::ReadFiles, "../etc/passwd");
        assert!(
            sandbox
                .read_to_string(
                    &escaping,
                    rt2,
                    Authority::new(bundle_for(Operation::ReadFiles, SinkClass::AuditLogAppend)),
                )
                .is_err(),
            "stripping the root must not turn a traversal into an accepted read"
        );
    }

    /// `root_relative` is the whole rule, and is idempotent on relative input.
    #[test]
    fn root_relative_strips_the_root_and_leaves_relative_paths_alone() {
        let tmp = tempdir().unwrap();
        let policy = permissive_policy();
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();

        assert_eq!(
            sandbox.root_relative(Path::new("a/b.txt")).unwrap(),
            Path::new("a/b.txt")
        );
        assert_eq!(
            sandbox
                .root_relative(&sandbox.root_path().join("a/b.txt"))
                .unwrap(),
            Path::new("a/b.txt")
        );
        // The root itself is the empty relative path, not an escape.
        assert_eq!(
            sandbox.root_relative(sandbox.root_path()).unwrap(),
            Path::new("")
        );
        assert!(sandbox.root_relative(Path::new("/etc/passwd")).is_err());
    }

    // ── Sandbox::glob (2026-09-27) ───────────────────────────────────────

    fn glob_authority() -> Authority {
        Authority::new(bundle_for(Operation::GlobSearch, SinkClass::AuditLogAppend))
    }

    fn glob_max(n: usize) -> std::num::NonZeroUsize {
        std::num::NonZeroUsize::new(n).expect("test bounds are non-zero")
    }

    /// A tree with files at three depths, for the walk tests. The directory is
    /// `pkg`, not `src`: `PathLattice` canonicalizes a relative path against
    /// the process CWD, and the test CWD has its own `src`.
    fn glob_tree() -> tempfile::TempDir {
        let tmp = tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("pkg/nested")).unwrap();
        std::fs::write(tmp.path().join("top.rs"), b"").unwrap();
        std::fs::write(tmp.path().join("notes.txt"), b"").unwrap();
        std::fs::write(tmp.path().join("pkg/lib.rs"), b"").unwrap();
        std::fs::write(tmp.path().join("pkg/nested/deep.rs"), b"").unwrap();
        tmp
    }

    fn listed(listing: &GlobListing) -> Vec<String> {
        listing
            .matches
            .iter()
            .map(|p| p.display().to_string())
            .collect()
    }

    /// The authority is spent — and a wrong one refused — before the pattern
    /// is parsed or the directory opened. Both inputs here would fail on their
    /// own (a `..` pattern, a directory that does not exist), so a
    /// `ScopeMismatch` can only come from a spend that ran first; and the
    /// right authority leaves exactly one receipt.
    ///
    /// A-19: with the `spend_as` line removed from `Sandbox::glob`, the first
    /// call returns `SandboxEscape` and this test reds.
    #[test]
    fn glob_spends_before_walking() {
        let tmp = glob_tree();
        let policy = permissive_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();

        let read_bundle =
            Authority::new(bundle_for(Operation::ReadFiles, SinkClass::AuditLogAppend));
        let e = sandbox
            .glob(
                None,
                "../*",
                glob_max(10),
                token(&mut kernel, Operation::GlobSearch, "../*"),
                read_bundle,
            )
            .expect_err("a ReadFiles authority must not pay for a glob");
        assert!(
            matches!(e, NucleusError::ScopeMismatch { .. }),
            "the spend must refuse before the pattern is looked at: {e:?}"
        );
        let e = sandbox
            .glob(
                Some(Path::new("missing")),
                "*",
                glob_max(10),
                token(&mut kernel, Operation::GlobSearch, "*"),
                Authority::new(bundle_for(Operation::GrepSearch, SinkClass::AuditLogAppend)),
            )
            .expect_err("a GrepSearch authority must not pay for a glob");
        assert!(
            matches!(e, NucleusError::ScopeMismatch { .. }),
            "the spend must refuse before the directory is opened: {e:?}"
        );

        let before = sandbox.receipts().len();
        let listing = sandbox
            .glob(
                None,
                "*.rs",
                glob_max(10),
                token(&mut kernel, Operation::GlobSearch, "*.rs"),
                glob_authority(),
            )
            .expect("a GlobSearch authority pays for a glob");
        assert_eq!(listed(&listing), vec!["top.rs"]);
        assert_eq!(
            sandbox.receipts().len(),
            before + 1,
            "one listing spends one authority and leaves one receipt"
        );
    }

    /// A symlink is neither listed nor entered, whether it points out of the
    /// root or back into it.
    #[cfg(unix)]
    #[test]
    fn glob_does_not_follow_symlinks_out() {
        let tmp = glob_tree();
        let outside = tempdir().unwrap();
        std::fs::write(outside.path().join("secret.rs"), b"").unwrap();
        std::os::unix::fs::symlink(outside.path(), tmp.path().join("escape")).unwrap();
        std::os::unix::fs::symlink(outside.path().join("secret.rs"), tmp.path().join("link.rs"))
            .unwrap();
        std::os::unix::fs::symlink(tmp.path().join("pkg"), tmp.path().join("loop")).unwrap();

        let policy = permissive_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let listing = sandbox
            .glob(
                None,
                "**/*",
                glob_max(100),
                token(&mut kernel, Operation::GlobSearch, "**/*"),
                glob_authority(),
            )
            .unwrap();
        let names = listed(&listing);
        assert!(
            names.iter().all(|n| !n.contains("secret")
                && !n.starts_with("escape")
                && !n.starts_with("loop")
                && n != "link.rs"),
            "no symlink, and nothing behind one, may be listed: {names:?}"
        );
        // Non-vacuity: the real tree was walked.
        assert!(
            names.contains(&"pkg/nested/deep.rs".to_string()),
            "{names:?}"
        );
        assert_eq!(listing.skipped, 3, "the three links are counted as skipped");
    }

    /// `..` in the pattern or the directory, and an absolute pattern, are
    /// refused outright rather than walked and filtered.
    #[test]
    fn glob_rejects_parent_dir_pattern() {
        let tmp = glob_tree();
        let policy = permissive_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();

        for (dir, pattern) in [
            (None, "../*"),
            (None, "pkg/../../*"),
            (None, "/etc/*"),
            (Some(Path::new("pkg/../..")), "*"),
            (Some(Path::new("/etc")), "*"),
        ] {
            let e = sandbox
                .glob(
                    dir,
                    pattern,
                    glob_max(10),
                    token(&mut kernel, Operation::GlobSearch, pattern),
                    glob_authority(),
                )
                .expect_err("an escaping glob must be refused");
            assert!(
                matches!(e, NucleusError::SandboxEscape { .. }),
                "{dir:?} / {pattern} refused for the wrong reason: {e:?}"
            );
        }
    }

    /// The path policy decides per entry: a blocked file matching the pattern
    /// is withheld and counted, its unblocked siblings are listed.
    #[test]
    fn glob_respects_path_policy() {
        let tmp = glob_tree();
        std::fs::write(tmp.path().join(".env"), b"LLM_API_TOKEN=test-token-123").unwrap();
        std::fs::write(tmp.path().join("server.pem"), b"").unwrap();
        let policy = sensitive_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();

        let listing = sandbox
            .glob(
                None,
                "*",
                glob_max(100),
                token(&mut kernel, Operation::GlobSearch, "*"),
                glob_authority(),
            )
            .unwrap();
        let names = listed(&listing);
        assert!(
            !names.contains(&".env".to_string()) && !names.contains(&"server.pem".to_string()),
            "blocked entries must not be listed: {names:?}"
        );
        assert!(names.contains(&"top.rs".to_string()), "{names:?}");
        assert_eq!(
            listing.skipped, 2,
            "the two blocked matches are counted: {names:?}"
        );
    }

    /// `max` bounds the listing, and `Truncated` means a further match exists
    /// — a listing of exactly `max` with nothing more is `Complete`.
    #[test]
    fn glob_truncates_at_max() {
        let tmp = glob_tree();
        let policy = permissive_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let mut run = |max| {
            sandbox
                .glob(
                    None,
                    "**/*.rs",
                    glob_max(max),
                    token(&mut kernel, Operation::GlobSearch, "**/*.rs"),
                    glob_authority(),
                )
                .unwrap()
        };

        let full = run(10);
        assert_eq!(full.completeness, Completeness::Complete);
        assert_eq!(
            listed(&full),
            vec!["pkg/lib.rs", "pkg/nested/deep.rs", "top.rs"],
            "`**/` spans zero or more directories, in sorted walk order"
        );
        let exact = run(3);
        assert_eq!(exact.completeness, Completeness::Complete);
        assert_eq!(exact.matches.len(), 3);
        let cut = run(2);
        assert_eq!(cut.completeness, Completeness::Truncated);
        assert_eq!(listed(&cut), vec!["pkg/lib.rs", "pkg/nested/deep.rs"]);
    }

    /// An absolute directory under the root names the same directory as its
    /// relative spelling (#2787), and results are root-relative either way.
    #[test]
    fn glob_absolute_dir_under_root_equals_relative() {
        let tmp = glob_tree();
        let policy = permissive_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let absolute = sandbox.root_path().join("pkg");
        let mut run = |dir: &Path| {
            sandbox
                .glob(
                    Some(dir),
                    "*.rs",
                    glob_max(10),
                    token(&mut kernel, Operation::GlobSearch, "*.rs"),
                    glob_authority(),
                )
                .unwrap()
        };
        let relative = run(Path::new("pkg"));
        let by_absolute = run(&absolute);
        assert_eq!(listed(&relative), vec!["pkg/lib.rs"]);
        assert_eq!(relative, by_absolute);
    }
}

/// Classify a filesystem error against a path.
///
/// Only an OS **permission** denial is reported as a denial. Everything else —
/// the file is absent, the path is a directory, the name is not valid UTF-8 —
/// is a fact about the filesystem, and calling it "access denied" sends the
/// reader to a policy that had no part in it.
///
/// This mattered in practice: reading the one entry a pod's sandbox contained
/// returned `access denied: path 'audit': Is a directory (os error 21)` with
/// `kind: path_denied`. The sandbox was simply empty of files, and the message
/// said the policy had refused.
pub(crate) fn classify_path_io(path: impl Into<PathBuf>, e: &std::io::Error) -> NucleusError {
    let path = path.into();
    match e.kind() {
        // The OS itself refused. That IS a denial.
        std::io::ErrorKind::PermissionDenied => NucleusError::PathDenied {
            path,
            reason: e.to_string(),
        },
        std::io::ErrorKind::NotFound => NucleusError::PathNotFound { path },
        _ => NucleusError::PathUnusable {
            path,
            reason: e.to_string(),
        },
    }
}

#[cfg(test)]
mod path_io_classification {
    use super::*;
    use std::io::{Error, ErrorKind};

    /// An absent file is not a refusal. Reported as one, it sends the reader to
    /// a policy that had nothing to do with it.
    #[test]
    fn a_missing_file_is_not_access_denied() {
        let e = classify_path_io("x.txt", &Error::new(ErrorKind::NotFound, "no such file"));
        assert!(matches!(e, NucleusError::PathNotFound { .. }), "{e}");
        assert!(!e.to_string().contains("access denied"), "{e}");
    }

    /// The case measured on a live pod: the sandbox's only entry was a
    /// directory, and reading it reported a policy denial.
    #[test]
    fn a_directory_read_as_a_file_is_not_access_denied() {
        let e = classify_path_io("audit", &Error::other("Is a directory (os error 21)"));
        assert!(matches!(e, NucleusError::PathUnusable { .. }), "{e}");
        assert!(!e.to_string().contains("access denied"), "{e}");
    }

    /// Non-vacuity: a real OS permission denial MUST still read as a denial.
    /// Without this, "never say access denied" would satisfy both tests above
    /// and would hide genuine refusals.
    #[test]
    fn an_os_permission_denial_is_still_access_denied() {
        let e = classify_path_io(
            "secret",
            &Error::new(ErrorKind::PermissionDenied, "permission denied"),
        );
        assert!(matches!(e, NucleusError::PathDenied { .. }), "{e}");
        assert!(e.to_string().contains("access denied"), "{e}");
    }
}

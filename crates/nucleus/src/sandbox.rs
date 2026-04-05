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
};

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
}

impl Sandbox {
    /// Create a new sandbox rooted at the given path.
    ///
    /// The `policy` determines which files within the sandbox can be accessed
    /// and which file operations are permitted.
    /// Even if a file is within the sandbox root, it can be blocked by pattern.
    pub fn new(policy: &PermissionLattice, root: impl AsRef<Path>) -> Result<Self> {
        let root_path = root.as_ref().to_path_buf();
        let normalized = policy.clone().normalize();

        // Open the root directory - this is our capability handle
        let root_dir = Dir::open_ambient_dir(&root_path, cap_std::ambient_authority())?;

        Ok(Self {
            root: root_dir,
            root_path,
            policy: normalized.paths,
            capabilities: normalized.capabilities,
            obligations: normalized.obligations,
            approver: None,
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
    pub fn open(&self, path: impl AsRef<Path>, decision: &DecisionToken) -> Result<File> {
        debug_assert_eq!(
            decision.operation(),
            Operation::ReadFiles,
            "DecisionToken operation mismatch"
        );
        self.open_internal(path.as_ref(), None)
    }

    /// Open a file for reading with an approval token.
    pub fn open_approved(
        &self,
        path: impl AsRef<Path>,
        decision: &DecisionToken,
        approval: &ApprovalToken,
    ) -> Result<File> {
        debug_assert_eq!(
            decision.operation(),
            Operation::ReadFiles,
            "DecisionToken operation mismatch"
        );
        self.open_internal(path.as_ref(), Some(approval))
    }

    fn open_internal(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<File> {
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
        decision: &DecisionToken,
    ) -> Result<File> {
        debug_assert_eq!(
            decision.operation(),
            Operation::EditFiles,
            "DecisionToken operation mismatch"
        );
        self.open_with_internal(path.as_ref(), options, None)
    }

    /// Open a file with custom options and an approval token.
    pub fn open_with_approved(
        &self,
        path: impl AsRef<Path>,
        options: &OpenOptions,
        decision: &DecisionToken,
        approval: &ApprovalToken,
    ) -> Result<File> {
        debug_assert_eq!(
            decision.operation(),
            Operation::EditFiles,
            "DecisionToken operation mismatch"
        );
        self.open_with_internal(path.as_ref(), options, Some(approval))
    }

    fn open_with_internal(
        &self,
        path: &Path,
        options: &OpenOptions,
        approval: Option<&ApprovalToken>,
    ) -> Result<File> {
        // OpenOptions can include write or truncation; conservatively treat as edit.
        self.check_edit_capability(path, "open_with", approval)?;
        self.check_policy(path)?;

        self.root
            .open_with(path, options)
            .map_err(|e| NucleusError::PathDenied {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })
    }

    /// Create a new file for writing.
    ///
    /// The path is relative to the sandbox root. Policy is checked before creating.
    pub fn create(&self, path: impl AsRef<Path>, decision: &DecisionToken) -> Result<File> {
        debug_assert_eq!(
            decision.operation(),
            Operation::WriteFiles,
            "DecisionToken operation mismatch"
        );
        self.create_internal(path.as_ref(), None)
    }

    /// Create a new file for writing with an approval token.
    pub fn create_approved(
        &self,
        path: impl AsRef<Path>,
        decision: &DecisionToken,
        approval: &ApprovalToken,
    ) -> Result<File> {
        debug_assert_eq!(
            decision.operation(),
            Operation::WriteFiles,
            "DecisionToken operation mismatch"
        );
        self.create_internal(path.as_ref(), Some(approval))
    }

    fn create_internal(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<File> {
        self.check_write_capability(path, "create", approval)?;
        self.check_policy(path)?;

        self.root
            .create(path)
            .map_err(|e| NucleusError::PathDenied {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })
    }

    /// Read a file's contents as bytes.
    pub fn read(&self, path: impl AsRef<Path>, decision: &DecisionToken) -> Result<Vec<u8>> {
        debug_assert_eq!(
            decision.operation(),
            Operation::ReadFiles,
            "DecisionToken operation mismatch"
        );
        self.read_internal(path.as_ref(), None)
    }

    /// Read a file's contents as bytes with an approval token.
    pub fn read_approved(
        &self,
        path: impl AsRef<Path>,
        decision: &DecisionToken,
        approval: &ApprovalToken,
    ) -> Result<Vec<u8>> {
        debug_assert_eq!(
            decision.operation(),
            Operation::ReadFiles,
            "DecisionToken operation mismatch"
        );
        self.read_internal(path.as_ref(), Some(approval))
    }

    fn read_internal(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<Vec<u8>> {
        self.check_read_capability(path, approval)?;
        self.check_policy(path)?;

        self.root.read(path).map_err(|e| NucleusError::PathDenied {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })
    }

    /// Read a file's contents as a string.
    pub fn read_to_string(
        &self,
        path: impl AsRef<Path>,
        decision: &DecisionToken,
    ) -> Result<String> {
        debug_assert_eq!(
            decision.operation(),
            Operation::ReadFiles,
            "DecisionToken operation mismatch"
        );
        self.read_to_string_internal(path.as_ref(), None)
    }

    /// Read a file's contents as a string with an approval token.
    pub fn read_to_string_approved(
        &self,
        path: impl AsRef<Path>,
        decision: &DecisionToken,
        approval: &ApprovalToken,
    ) -> Result<String> {
        debug_assert_eq!(
            decision.operation(),
            Operation::ReadFiles,
            "DecisionToken operation mismatch"
        );
        self.read_to_string_internal(path.as_ref(), Some(approval))
    }

    fn read_to_string_internal(
        &self,
        path: &Path,
        approval: Option<&ApprovalToken>,
    ) -> Result<String> {
        self.check_read_capability(path, approval)?;
        self.check_policy(path)?;

        self.root
            .read_to_string(path)
            .map_err(|e| NucleusError::PathDenied {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })
    }

    /// Write bytes to a file (creates if needed, truncates if exists).
    pub fn write(
        &self,
        path: impl AsRef<Path>,
        contents: impl AsRef<[u8]>,
        decision: &DecisionToken,
    ) -> Result<()> {
        debug_assert_eq!(
            decision.operation(),
            Operation::WriteFiles,
            "DecisionToken operation mismatch"
        );
        self.write_internal(path.as_ref(), contents, None)
    }

    /// Write bytes to a file with an approval token.
    pub fn write_approved(
        &self,
        path: impl AsRef<Path>,
        contents: impl AsRef<[u8]>,
        decision: &DecisionToken,
        approval: &ApprovalToken,
    ) -> Result<()> {
        debug_assert_eq!(
            decision.operation(),
            Operation::WriteFiles,
            "DecisionToken operation mismatch"
        );
        self.write_internal(path.as_ref(), contents, Some(approval))
    }

    fn write_internal(
        &self,
        path: &Path,
        contents: impl AsRef<[u8]>,
        approval: Option<&ApprovalToken>,
    ) -> Result<()> {
        self.check_policy(path)?;
        self.check_write_or_edit_capability(path, "write", approval)?;

        self.root
            .write(path, contents)
            .map_err(|e| NucleusError::PathDenied {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })
    }

    /// Create a directory.
    pub fn create_dir(&self, path: impl AsRef<Path>, decision: &DecisionToken) -> Result<()> {
        debug_assert_eq!(
            decision.operation(),
            Operation::WriteFiles,
            "DecisionToken operation mismatch"
        );
        self.create_dir_internal(path.as_ref(), None)
    }

    /// Create a directory with an approval token.
    pub fn create_dir_approved(
        &self,
        path: impl AsRef<Path>,
        decision: &DecisionToken,
        approval: &ApprovalToken,
    ) -> Result<()> {
        debug_assert_eq!(
            decision.operation(),
            Operation::WriteFiles,
            "DecisionToken operation mismatch"
        );
        self.create_dir_internal(path.as_ref(), Some(approval))
    }

    fn create_dir_internal(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<()> {
        self.check_write_capability(path, "create_dir", approval)?;
        self.check_policy(path)?;

        self.root
            .create_dir(path)
            .map_err(|e| NucleusError::PathDenied {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })
    }

    /// Create a directory and all parent directories.
    pub fn create_dir_all(&self, path: impl AsRef<Path>, decision: &DecisionToken) -> Result<()> {
        debug_assert_eq!(
            decision.operation(),
            Operation::WriteFiles,
            "DecisionToken operation mismatch"
        );
        self.create_dir_all_internal(path.as_ref(), None)
    }

    /// Create a directory and all parent directories with an approval token.
    pub fn create_dir_all_approved(
        &self,
        path: impl AsRef<Path>,
        decision: &DecisionToken,
        approval: &ApprovalToken,
    ) -> Result<()> {
        debug_assert_eq!(
            decision.operation(),
            Operation::WriteFiles,
            "DecisionToken operation mismatch"
        );
        self.create_dir_all_internal(path.as_ref(), Some(approval))
    }

    fn create_dir_all_internal(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<()> {
        self.check_write_capability(path, "create_dir_all", approval)?;
        self.check_policy(path)?;

        self.root
            .create_dir_all(path)
            .map_err(|e| NucleusError::PathDenied {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })
    }

    /// Remove a file.
    pub fn remove_file(&self, path: impl AsRef<Path>, decision: &DecisionToken) -> Result<()> {
        debug_assert_eq!(
            decision.operation(),
            Operation::EditFiles,
            "DecisionToken operation mismatch"
        );
        self.remove_file_internal(path.as_ref(), None)
    }

    /// Remove a file with an approval token.
    pub fn remove_file_approved(
        &self,
        path: impl AsRef<Path>,
        decision: &DecisionToken,
        approval: &ApprovalToken,
    ) -> Result<()> {
        debug_assert_eq!(
            decision.operation(),
            Operation::EditFiles,
            "DecisionToken operation mismatch"
        );
        self.remove_file_internal(path.as_ref(), Some(approval))
    }

    fn remove_file_internal(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<()> {
        self.check_edit_capability(path, "remove_file", approval)?;
        self.check_policy(path)?;

        self.root
            .remove_file(path)
            .map_err(|e| NucleusError::PathDenied {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })
    }

    /// Remove an empty directory.
    pub fn remove_dir(&self, path: impl AsRef<Path>, decision: &DecisionToken) -> Result<()> {
        debug_assert_eq!(
            decision.operation(),
            Operation::EditFiles,
            "DecisionToken operation mismatch"
        );
        self.remove_dir_internal(path.as_ref(), None)
    }

    /// Remove an empty directory with an approval token.
    pub fn remove_dir_approved(
        &self,
        path: impl AsRef<Path>,
        decision: &DecisionToken,
        approval: &ApprovalToken,
    ) -> Result<()> {
        debug_assert_eq!(
            decision.operation(),
            Operation::EditFiles,
            "DecisionToken operation mismatch"
        );
        self.remove_dir_internal(path.as_ref(), Some(approval))
    }

    fn remove_dir_internal(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<()> {
        self.check_edit_capability(path, "remove_dir", approval)?;
        self.check_policy(path)?;

        self.root
            .remove_dir(path)
            .map_err(|e| NucleusError::PathDenied {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })
    }

    /// Check if a path exists within the sandbox.
    pub fn exists(&self, path: impl AsRef<Path>, decision: &DecisionToken) -> bool {
        debug_assert_eq!(
            decision.operation(),
            Operation::ReadFiles,
            "DecisionToken operation mismatch"
        );
        self.exists_internal(path.as_ref(), None)
    }

    /// Check if a path exists within the sandbox with an approval token.
    pub fn exists_approved(
        &self,
        path: impl AsRef<Path>,
        decision: &DecisionToken,
        approval: &ApprovalToken,
    ) -> bool {
        debug_assert_eq!(
            decision.operation(),
            Operation::ReadFiles,
            "DecisionToken operation mismatch"
        );
        self.exists_internal(path.as_ref(), Some(approval))
    }

    fn exists_internal(&self, path: &Path, approval: Option<&ApprovalToken>) -> bool {
        if self.check_read_capability(path, approval).is_err() {
            return false;
        }
        if self.check_policy(path).is_err() {
            return false;
        }
        self.root.exists(path)
    }

    /// Get the absolute path of the sandbox root.
    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    /// Check if a path is allowed by the policy.
    fn check_policy(&self, path: &Path) -> Result<()> {
        // First, check for obvious escapes
        let path_str = path.to_string_lossy();

        // Reject absolute paths
        if path.is_absolute() {
            return Err(NucleusError::SandboxEscape {
                path: path.to_path_buf(),
            });
        }

        // Check against portcullis policy
        // Note: We pass the relative path to the policy checker
        if !self.policy.can_access(path) {
            return Err(NucleusError::PathDenied {
                path: path.to_path_buf(),
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
            &format!("read {}", path.display()),
            approval,
        )
    }

    fn check_write_capability(
        &self,
        path: &Path,
        op: &str,
        approval: Option<&ApprovalToken>,
    ) -> Result<()> {
        self.check_capability(
            Operation::WriteFiles,
            "write_files",
            self.capabilities.write_files,
            &format!("{} {}", op, path.display()),
            approval,
        )
    }

    fn check_edit_capability(
        &self,
        path: &Path,
        op: &str,
        approval: Option<&ApprovalToken>,
    ) -> Result<()> {
        self.check_capability(
            Operation::EditFiles,
            "edit_files",
            self.capabilities.edit_files,
            &format!("{} {}", op, path.display()),
            approval,
        )
    }

    fn check_write_or_edit_capability(
        &self,
        path: &Path,
        op: &str,
        approval: Option<&ApprovalToken>,
    ) -> Result<()> {
        if self.root.exists(path) {
            self.check_edit_capability(path, op, approval)
        } else {
            self.check_write_capability(path, op, approval)
        }
    }

    fn check_capability(
        &self,
        op: Operation,
        capability_name: &str,
        level: CapabilityLevel,
        operation: &str,
        approval: Option<&ApprovalToken>,
    ) -> Result<()> {
        if level == CapabilityLevel::Never {
            return Err(NucleusError::InsufficientCapability {
                capability: capability_name.into(),
                actual: level,
                required: CapabilityLevel::LowRisk,
            });
        }

        if self.obligations.requires(op) {
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
    pub fn open_dir(&self, path: impl AsRef<Path>, decision: &DecisionToken) -> Result<Sandbox> {
        debug_assert_eq!(
            decision.operation(),
            Operation::ReadFiles,
            "DecisionToken operation mismatch"
        );
        self.open_dir_internal(path.as_ref(), None)
    }

    /// Open a subdirectory as a new sandbox with an approval token.
    pub fn open_dir_approved(
        &self,
        path: impl AsRef<Path>,
        decision: &DecisionToken,
        approval: &ApprovalToken,
    ) -> Result<Sandbox> {
        debug_assert_eq!(
            decision.operation(),
            Operation::ReadFiles,
            "DecisionToken operation mismatch"
        );
        self.open_dir_internal(path.as_ref(), Some(approval))
    }

    fn open_dir_internal(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<Sandbox> {
        self.check_read_capability(path, approval)?;
        self.check_policy(path)?;

        let subdir = self
            .root
            .open_dir(path)
            .map_err(|e| NucleusError::PathDenied {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })?;

        Ok(Sandbox {
            root: subdir,
            root_path: self.root_path.join(path),
            policy: self.policy.clone(),
            capabilities: self.capabilities.clone(),
            obligations: self.obligations.clone(),
            approver: self.approver.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn test_basic_read_write() {
        let tmp = tempdir().unwrap();
        let policy = permissive_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();

        // Write a file
        let wt = token(&mut kernel, Operation::WriteFiles, "test.txt");
        sandbox.write("test.txt", b"hello world", &wt).unwrap();

        // Read it back
        let rt = token(&mut kernel, Operation::ReadFiles, "test.txt");
        let contents = sandbox.read_to_string("test.txt", &rt).unwrap();
        assert_eq!(contents, "hello world");
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
        // absolute path matches blocked patterns like `**/.claude/**` when
        // running inside a git worktree. This test exercises the *sandbox*'s
        // path policy, not the kernel's.
        let wt = kernel.issue_approved_token(Operation::WriteFiles, "test: write normal file");
        sandbox.write("normal_file.txt", b"# Hello", &wt).unwrap();

        // Should block .env files (sandbox policy blocks it; kernel also blocks via PathLattice)
        // Force a token to test the sandbox's own path policy enforcement
        let wt2 =
            kernel.issue_approved_token(Operation::WriteFiles, "test: .env blocked by sandbox");
        let result = sandbox.write(".env", b"SECRET=foo", &wt2);
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
        let result = sandbox.create("blocked.txt", &forced_token);
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
        let approval_token = approved.request_approval("create approved.txt").unwrap();
        let result = approved.create_approved("approved.txt", &decision_token, &approval_token);
        assert!(result.is_ok());
    }

    #[test]
    fn test_escape_via_absolute_path() {
        let tmp = tempdir().unwrap();
        let policy = permissive_policy();
        let mut kernel = Kernel::new(policy.clone());
        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();

        // Absolute paths should be rejected at policy level
        let rt = token(&mut kernel, Operation::ReadFiles, "/etc/passwd");
        let result = sandbox.open("/etc/passwd", &rt);
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
        sandbox.create_dir("subdir", &wt1).unwrap();

        let wt2 = token(&mut kernel, Operation::WriteFiles, "subdir/file.txt");
        sandbox.write("subdir/file.txt", b"nested", &wt2).unwrap();

        // Open as sub-sandbox
        let rt1 = token(&mut kernel, Operation::ReadFiles, "subdir");
        let subsandbox = sandbox.open_dir("subdir", &rt1).unwrap();

        let rt2 = token(&mut kernel, Operation::ReadFiles, "file.txt");
        let contents = subsandbox.read_to_string("file.txt", &rt2).unwrap();
        assert_eq!(contents, "nested");
    }
}

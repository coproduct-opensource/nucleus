//! Capability-based file sandbox.
//!
//! Unlike `lattice_guard::PathLattice` which uses string-based path checking,
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
//! use lattice_guard::PermissionLattice;
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
use lattice_guard::{CapabilityLattice, CapabilityLevel, PathLattice, PermissionLattice};

/// A capability-based file sandbox.
///
/// All file operations go through this sandbox, which holds a directory handle
/// to the sandbox root. The kernel prevents escapes at the syscall level.
pub struct Sandbox {
    /// The root directory handle (capability)
    root: Dir,
    /// The absolute path of the root (for error messages)
    root_path: PathBuf,
    /// The path policy from lattice-guard
    policy: PathLattice,
    /// Capability policy for file operations
    capabilities: CapabilityLattice,
    /// Approver for AskFirst operations
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

        // Open the root directory - this is our capability handle
        let root_dir = Dir::open_ambient_dir(&root_path, cap_std::ambient_authority())?;

        Ok(Self {
            root: root_dir,
            root_path,
            policy: policy.paths.clone(),
            capabilities: policy.capabilities.clone(),
            approver: None,
        })
    }

    /// Set an approver for AskFirst operations.
    pub fn with_approver(mut self, approver: Arc<dyn Approver>) -> Self {
        self.approver = Some(approver);
        self
    }

    /// Set a callback-based approver for AskFirst operations.
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
    pub fn open(&self, path: impl AsRef<Path>) -> Result<File> {
        self.open_internal(path.as_ref(), None)
    }

    /// Open a file for reading with an approval token.
    pub fn open_approved(
        &self,
        path: impl AsRef<Path>,
        approval: &ApprovalToken,
    ) -> Result<File> {
        self.open_internal(path.as_ref(), Some(approval))
    }

    fn open_internal(
        &self,
        path: &Path,
        approval: Option<&ApprovalToken>,
    ) -> Result<File> {
        self.check_read_capability(path, approval)?;
        self.check_policy(path)?;

        self.root.open(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                NucleusError::Io(e.into())
            } else {
                NucleusError::SandboxEscape {
                    path: path.to_path_buf(),
                }
            }
        })
    }

    /// Open a file with custom options.
    pub fn open_with(&self, path: impl AsRef<Path>, options: &OpenOptions) -> Result<File> {
        self.open_with_internal(path.as_ref(), options, None)
    }

    /// Open a file with custom options and an approval token.
    pub fn open_with_approved(
        &self,
        path: impl AsRef<Path>,
        options: &OpenOptions,
        approval: &ApprovalToken,
    ) -> Result<File> {
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

        self.root.open_with(path, options).map_err(|e| {
            NucleusError::PathDenied {
                path: path.to_path_buf(),
                reason: e.to_string(),
            }
        })
    }

    /// Create a new file for writing.
    ///
    /// The path is relative to the sandbox root. Policy is checked before creating.
    pub fn create(&self, path: impl AsRef<Path>) -> Result<File> {
        self.create_internal(path.as_ref(), None)
    }

    /// Create a new file for writing with an approval token.
    pub fn create_approved(
        &self,
        path: impl AsRef<Path>,
        approval: &ApprovalToken,
    ) -> Result<File> {
        self.create_internal(path.as_ref(), Some(approval))
    }

    fn create_internal(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<File> {
        self.check_write_capability(path, "create", approval)?;
        self.check_policy(path)?;

        self.root.create(path).map_err(|e| {
            NucleusError::PathDenied {
                path: path.to_path_buf(),
                reason: e.to_string(),
            }
        })
    }

    /// Read a file's contents as bytes.
    pub fn read(&self, path: impl AsRef<Path>) -> Result<Vec<u8>> {
        self.read_internal(path.as_ref(), None)
    }

    /// Read a file's contents as bytes with an approval token.
    pub fn read_approved(
        &self,
        path: impl AsRef<Path>,
        approval: &ApprovalToken,
    ) -> Result<Vec<u8>> {
        self.read_internal(path.as_ref(), Some(approval))
    }

    fn read_internal(
        &self,
        path: &Path,
        approval: Option<&ApprovalToken>,
    ) -> Result<Vec<u8>> {
        self.check_read_capability(path, approval)?;
        self.check_policy(path)?;

        self.root.read(path).map_err(|e| {
            NucleusError::PathDenied {
                path: path.to_path_buf(),
                reason: e.to_string(),
            }
        })
    }

    /// Read a file's contents as a string.
    pub fn read_to_string(&self, path: impl AsRef<Path>) -> Result<String> {
        self.read_to_string_internal(path.as_ref(), None)
    }

    /// Read a file's contents as a string with an approval token.
    pub fn read_to_string_approved(
        &self,
        path: impl AsRef<Path>,
        approval: &ApprovalToken,
    ) -> Result<String> {
        self.read_to_string_internal(path.as_ref(), Some(approval))
    }

    fn read_to_string_internal(
        &self,
        path: &Path,
        approval: Option<&ApprovalToken>,
    ) -> Result<String> {
        self.check_read_capability(path, approval)?;
        self.check_policy(path)?;

        self.root.read_to_string(path).map_err(|e| {
            NucleusError::PathDenied {
                path: path.to_path_buf(),
                reason: e.to_string(),
            }
        })
    }

    /// Write bytes to a file (creates if needed, truncates if exists).
    pub fn write(&self, path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> Result<()> {
        self.write_internal(path.as_ref(), contents, None)
    }

    /// Write bytes to a file with an approval token.
    pub fn write_approved(
        &self,
        path: impl AsRef<Path>,
        contents: impl AsRef<[u8]>,
        approval: &ApprovalToken,
    ) -> Result<()> {
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

        self.root.write(path, contents).map_err(|e| {
            NucleusError::PathDenied {
                path: path.to_path_buf(),
                reason: e.to_string(),
            }
        })
    }

    /// Create a directory.
    pub fn create_dir(&self, path: impl AsRef<Path>) -> Result<()> {
        self.create_dir_internal(path.as_ref(), None)
    }

    /// Create a directory with an approval token.
    pub fn create_dir_approved(
        &self,
        path: impl AsRef<Path>,
        approval: &ApprovalToken,
    ) -> Result<()> {
        self.create_dir_internal(path.as_ref(), Some(approval))
    }

    fn create_dir_internal(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<()> {
        self.check_write_capability(path, "create_dir", approval)?;
        self.check_policy(path)?;

        self.root.create_dir(path).map_err(|e| {
            NucleusError::PathDenied {
                path: path.to_path_buf(),
                reason: e.to_string(),
            }
        })
    }

    /// Create a directory and all parent directories.
    pub fn create_dir_all(&self, path: impl AsRef<Path>) -> Result<()> {
        self.create_dir_all_internal(path.as_ref(), None)
    }

    /// Create a directory and all parent directories with an approval token.
    pub fn create_dir_all_approved(
        &self,
        path: impl AsRef<Path>,
        approval: &ApprovalToken,
    ) -> Result<()> {
        self.create_dir_all_internal(path.as_ref(), Some(approval))
    }

    fn create_dir_all_internal(
        &self,
        path: &Path,
        approval: Option<&ApprovalToken>,
    ) -> Result<()> {
        self.check_write_capability(path, "create_dir_all", approval)?;
        self.check_policy(path)?;

        self.root.create_dir_all(path).map_err(|e| {
            NucleusError::PathDenied {
                path: path.to_path_buf(),
                reason: e.to_string(),
            }
        })
    }

    /// Remove a file.
    pub fn remove_file(&self, path: impl AsRef<Path>) -> Result<()> {
        self.remove_file_internal(path.as_ref(), None)
    }

    /// Remove a file with an approval token.
    pub fn remove_file_approved(
        &self,
        path: impl AsRef<Path>,
        approval: &ApprovalToken,
    ) -> Result<()> {
        self.remove_file_internal(path.as_ref(), Some(approval))
    }

    fn remove_file_internal(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<()> {
        self.check_edit_capability(path, "remove_file", approval)?;
        self.check_policy(path)?;

        self.root.remove_file(path).map_err(|e| {
            NucleusError::PathDenied {
                path: path.to_path_buf(),
                reason: e.to_string(),
            }
        })
    }

    /// Remove an empty directory.
    pub fn remove_dir(&self, path: impl AsRef<Path>) -> Result<()> {
        self.remove_dir_internal(path.as_ref(), None)
    }

    /// Remove an empty directory with an approval token.
    pub fn remove_dir_approved(
        &self,
        path: impl AsRef<Path>,
        approval: &ApprovalToken,
    ) -> Result<()> {
        self.remove_dir_internal(path.as_ref(), Some(approval))
    }

    fn remove_dir_internal(&self, path: &Path, approval: Option<&ApprovalToken>) -> Result<()> {
        self.check_edit_capability(path, "remove_dir", approval)?;
        self.check_policy(path)?;

        self.root.remove_dir(path).map_err(|e| {
            NucleusError::PathDenied {
                path: path.to_path_buf(),
                reason: e.to_string(),
            }
        })
    }

    /// Check if a path exists within the sandbox.
    pub fn exists(&self, path: impl AsRef<Path>) -> bool {
        self.exists_internal(path.as_ref(), None)
    }

    /// Check if a path exists within the sandbox with an approval token.
    pub fn exists_approved(&self, path: impl AsRef<Path>, approval: &ApprovalToken) -> bool {
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

        // Check against lattice-guard policy
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
        capability_name: &str,
        level: CapabilityLevel,
        operation: &str,
        approval: Option<&ApprovalToken>,
    ) -> Result<()> {
        match level {
            CapabilityLevel::Never => Err(NucleusError::InsufficientCapability {
                capability: capability_name.into(),
                actual: level,
                required: CapabilityLevel::AskFirst,
            }),
            CapabilityLevel::AskFirst => {
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
            }
            CapabilityLevel::LowRisk | CapabilityLevel::Always => Ok(()),
        }
    }

    /// Open a subdirectory as a new sandbox.
    ///
    /// The returned sandbox is constrained to the subdirectory and inherits
    /// the parent's policy (which will further restrict access).
    pub fn open_dir(&self, path: impl AsRef<Path>) -> Result<Sandbox> {
        self.open_dir_internal(path.as_ref(), None)
    }

    /// Open a subdirectory as a new sandbox with an approval token.
    pub fn open_dir_approved(
        &self,
        path: impl AsRef<Path>,
        approval: &ApprovalToken,
    ) -> Result<Sandbox> {
        self.open_dir_internal(path.as_ref(), Some(approval))
    }

    fn open_dir_internal(
        &self,
        path: &Path,
        approval: Option<&ApprovalToken>,
    ) -> Result<Sandbox> {
        self.check_read_capability(path, approval)?;
        self.check_policy(path)?;

        let subdir = self.root.open_dir(path).map_err(|e| {
            NucleusError::PathDenied {
                path: path.to_path_buf(),
                reason: e.to_string(),
            }
        })?;

        Ok(Sandbox {
            root: subdir,
            root_path: self.root_path.join(path),
            policy: self.policy.clone(),
            capabilities: self.capabilities.clone(),
            approver: self.approver.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn permissive_policy() -> PermissionLattice {
        let mut policy = PermissionLattice::default();
        policy.paths = PathLattice::default();
        policy.capabilities.write_files = CapabilityLevel::LowRisk;
        policy.capabilities.edit_files = CapabilityLevel::LowRisk;
        policy
    }

    fn sensitive_policy() -> PermissionLattice {
        let mut policy = PermissionLattice::default();
        policy.paths = PathLattice::block_sensitive();
        policy.capabilities.write_files = CapabilityLevel::LowRisk;
        policy.capabilities.edit_files = CapabilityLevel::LowRisk;
        policy
    }

    #[test]
    fn test_basic_read_write() {
        let tmp = tempdir().unwrap();
        let sandbox = Sandbox::new(&permissive_policy(), tmp.path()).unwrap();

        // Write a file
        sandbox.write("test.txt", b"hello world").unwrap();

        // Read it back
        let contents = sandbox.read_to_string("test.txt").unwrap();
        assert_eq!(contents, "hello world");
    }

    #[test]
    fn test_policy_blocks_sensitive() {
        let tmp = tempdir().unwrap();
        let sandbox = Sandbox::new(&sensitive_policy(), tmp.path()).unwrap();

        // Should be able to write normal files
        sandbox.write("readme.md", b"# Hello").unwrap();

        // Should block .env files
        let result = sandbox.write(".env", b"SECRET=foo");
        assert!(result.is_err());
    }

    #[test]
    fn test_write_requires_capability() {
        let tmp = tempdir().unwrap();
        let mut policy = permissive_policy();
        policy.capabilities.write_files = CapabilityLevel::Never;

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();

        let result = sandbox.create("blocked.txt");
        assert!(matches!(result, Err(NucleusError::InsufficientCapability { .. })));
    }

    #[test]
    fn test_write_askfirst_requires_approval() {
        let tmp = tempdir().unwrap();
        let mut policy = permissive_policy();
        policy.capabilities.write_files = CapabilityLevel::AskFirst;

        let sandbox = Sandbox::new(&policy, tmp.path()).unwrap();
        let result = sandbox.create("needs_approval.txt");
        assert!(matches!(result, Err(NucleusError::ApprovalRequired { .. })));

        let approved = Sandbox::new(&policy, tmp.path())
            .unwrap()
            .with_approval_callback(|_| true);
        let token = approved
            .request_approval("create approved.txt")
            .unwrap();
        let result = approved.create_approved("approved.txt", &token);
        assert!(result.is_ok());
    }

    #[test]
    fn test_escape_via_absolute_path() {
        let tmp = tempdir().unwrap();
        let sandbox = Sandbox::new(&permissive_policy(), tmp.path()).unwrap();

        // Absolute paths should be rejected at policy level
        let result = sandbox.open("/etc/passwd");
        assert!(result.is_err());
    }

    #[test]
    fn test_subdirectory_sandbox() {
        let tmp = tempdir().unwrap();
        let sandbox = Sandbox::new(&permissive_policy(), tmp.path()).unwrap();

        // Create a subdirectory
        sandbox.create_dir("subdir").unwrap();
        sandbox.write("subdir/file.txt", b"nested").unwrap();

        // Open as sub-sandbox
        let subsandbox = sandbox.open_dir("subdir").unwrap();
        let contents = subsandbox.read_to_string("file.txt").unwrap();
        assert_eq!(contents, "nested");
    }
}

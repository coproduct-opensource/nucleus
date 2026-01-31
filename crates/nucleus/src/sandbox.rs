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

use crate::error::{NucleusError, Result};
use lattice_guard::PathLattice;

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
}

impl Sandbox {
    /// Create a new sandbox rooted at the given path.
    ///
    /// The `policy` determines which files within the sandbox can be accessed.
    /// Even if a file is within the sandbox root, it can be blocked by pattern.
    pub fn new(policy: &PathLattice, root: impl AsRef<Path>) -> Result<Self> {
        let root_path = root.as_ref().to_path_buf();

        // Open the root directory - this is our capability handle
        let root_dir = Dir::open_ambient_dir(&root_path, cap_std::ambient_authority())?;

        Ok(Self {
            root: root_dir,
            root_path,
            policy: policy.clone(),
        })
    }

    /// Open a file for reading.
    ///
    /// The path is relative to the sandbox root. Policy is checked before opening.
    pub fn open(&self, path: impl AsRef<Path>) -> Result<File> {
        let path = path.as_ref();
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
        let path = path.as_ref();
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
        let path = path.as_ref();
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
        let path = path.as_ref();
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
        let path = path.as_ref();
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
        let path = path.as_ref();
        self.check_policy(path)?;

        self.root.write(path, contents).map_err(|e| {
            NucleusError::PathDenied {
                path: path.to_path_buf(),
                reason: e.to_string(),
            }
        })
    }

    /// Create a directory.
    pub fn create_dir(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
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
        let path = path.as_ref();
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
        let path = path.as_ref();
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
        let path = path.as_ref();
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
        let path = path.as_ref();
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

    /// Open a subdirectory as a new sandbox.
    ///
    /// The returned sandbox is constrained to the subdirectory and inherits
    /// the parent's policy (which will further restrict access).
    pub fn open_dir(&self, path: impl AsRef<Path>) -> Result<Sandbox> {
        let path = path.as_ref();
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
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn permissive_policy() -> PathLattice {
        PathLattice::default()
    }

    fn sensitive_policy() -> PathLattice {
        PathLattice::block_sensitive()
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

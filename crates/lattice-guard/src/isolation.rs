//! Isolation level lattice for executor context.
//!
//! This module models execution isolation as a product lattice with three
//! orthogonal dimensions: process, filesystem, and network isolation.
//!
//! # Mathematical Structure
//!
//! ```text
//! IsolationLattice = ProcessIsolation × FileIsolation × NetworkIsolation
//! ```
//!
//! Each dimension is a linear order. The product forms a partial order where
//! `a ≤ b` iff `a` is weaker-or-equal on ALL dimensions.
//!
//! # Meet/Join Semantics
//!
//! - **Meet (∧)**: Minimum of each dimension (weaker isolation)
//! - **Join (∨)**: Maximum of each dimension (stronger isolation)
//!
//! # Example
//!
//! ```rust
//! use lattice_guard::isolation::{IsolationLattice, ProcessIsolation, FileIsolation, NetworkIsolation};
//! use lattice_guard::frame::{Lattice, BoundedLattice};
//!
//! let sandboxed = IsolationLattice {
//!     process: ProcessIsolation::Namespaced,
//!     file: FileIsolation::Sandboxed,
//!     network: NetworkIsolation::Filtered,
//! };
//!
//! let vm = IsolationLattice {
//!     process: ProcessIsolation::MicroVM,
//!     file: FileIsolation::ReadOnly,
//!     network: NetworkIsolation::Airgapped,
//! };
//!
//! // Join gives stronger isolation on each dimension
//! let strongest = sandboxed.join(&vm);
//! assert_eq!(strongest.process, ProcessIsolation::MicroVM);
//! assert_eq!(strongest.network, NetworkIsolation::Airgapped);
//! ```

use std::cmp::{max, min};
use std::fmt;
use std::str::FromStr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::frame::{BoundedLattice, Lattice};

/// Error returned when parsing an isolation level fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseIsolationError {
    /// The invalid value that was provided.
    pub value: String,
    /// The type being parsed.
    pub kind: &'static str,
}

/// Process isolation level.
///
/// Ordered from weakest (Shared) to strongest (MicroVM).
///
/// # Default
///
/// Defaults to `Namespaced` for secure-by-default behavior.
/// Use `ProcessIsolation::Shared` explicitly for localhost testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ProcessIsolation {
    /// Same process space (localhost execution).
    /// No isolation - agent runs in the host process.
    Shared = 0,

    /// Linux namespaces (pid, ipc, mount, user).
    /// Lightweight isolation via kernel namespaces.
    #[default]
    Namespaced = 1,

    /// Firecracker microVM with separate kernel.
    /// Strong isolation with dedicated kernel instance.
    MicroVM = 2,
}

impl ProcessIsolation {
    /// String representation for CEL context.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::Namespaced => "namespaced",
            Self::MicroVM => "microvm",
        }
    }
}

impl fmt::Display for ProcessIsolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for ProcessIsolation {
    type Err = ParseIsolationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "shared" => Ok(Self::Shared),
            "namespaced" => Ok(Self::Namespaced),
            "microvm" | "micro_vm" | "micro-vm" => Ok(Self::MicroVM),
            _ => Err(ParseIsolationError {
                value: s.to_string(),
                kind: "ProcessIsolation",
            }),
        }
    }
}

/// Filesystem isolation level.
///
/// Ordered from weakest (Unrestricted) to strongest (Ephemeral).
///
/// # Default
///
/// Defaults to `Sandboxed` for secure-by-default behavior.
/// Use `FileIsolation::Unrestricted` explicitly for localhost testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum FileIsolation {
    /// Full filesystem access.
    /// No isolation - agent can access any path.
    Unrestricted = 0,

    /// cap-std directory capabilities.
    /// Sandboxed to specific directories via capability handles.
    #[default]
    Sandboxed = 1,

    /// Immutable root filesystem.
    /// Read-only rootfs with optional scratch space.
    ReadOnly = 2,

    /// Ephemeral scratch-only storage.
    /// No persistent state - everything is temporary.
    Ephemeral = 3,
}

impl FileIsolation {
    /// String representation for CEL context.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unrestricted => "unrestricted",
            Self::Sandboxed => "sandboxed",
            Self::ReadOnly => "readonly",
            Self::Ephemeral => "ephemeral",
        }
    }
}

impl fmt::Display for FileIsolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for FileIsolation {
    type Err = ParseIsolationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "unrestricted" => Ok(Self::Unrestricted),
            "sandboxed" => Ok(Self::Sandboxed),
            "readonly" | "read_only" | "read-only" => Ok(Self::ReadOnly),
            "ephemeral" => Ok(Self::Ephemeral),
            _ => Err(ParseIsolationError {
                value: s.to_string(),
                kind: "FileIsolation",
            }),
        }
    }
}

/// Network isolation level.
///
/// Ordered from weakest (Host) to strongest (Airgapped).
///
/// # Default
///
/// Defaults to `Filtered` for secure-by-default behavior.
/// Use `NetworkIsolation::Host` explicitly for localhost testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum NetworkIsolation {
    /// Host network stack.
    /// No isolation - agent shares host networking.
    Host = 0,

    /// Network namespace with veth bridge.
    /// Isolated network namespace with controlled bridge.
    Namespaced = 1,

    /// Allowlist-only firewall.
    /// Network namespace with strict egress filtering.
    #[default]
    Filtered = 2,

    /// No network access (vsock only for host communication).
    /// Completely airgapped from external network.
    Airgapped = 3,
}

impl NetworkIsolation {
    /// String representation for CEL context.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Namespaced => "namespaced",
            Self::Filtered => "filtered",
            Self::Airgapped => "airgapped",
        }
    }
}

impl fmt::Display for NetworkIsolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for NetworkIsolation {
    type Err = ParseIsolationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "host" => Ok(Self::Host),
            "namespaced" => Ok(Self::Namespaced),
            "filtered" => Ok(Self::Filtered),
            "airgapped" | "air_gapped" | "air-gapped" => Ok(Self::Airgapped),
            _ => Err(ParseIsolationError {
                value: s.to_string(),
                kind: "NetworkIsolation",
            }),
        }
    }
}

impl fmt::Display for ParseIsolationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid {} value '{}': expected one of the valid isolation levels",
            self.kind, self.value
        )
    }
}

impl std::error::Error for ParseIsolationError {}

/// Product lattice of isolation dimensions.
///
/// Represents the complete isolation context for an execution environment.
/// Each dimension is independent and ordered from weakest to strongest.
///
/// # Partial Order
///
/// `a ≤ b` iff `a` is weaker-or-equal on ALL dimensions:
/// - `a.process ≤ b.process`
/// - `a.file ≤ b.file`
/// - `a.network ≤ b.network`
///
/// # Default
///
/// The `Default` implementation returns **sandboxed** isolation for security:
/// - Process: `Namespaced` (Linux namespaces)
/// - File: `Sandboxed` (cap-std capabilities)
/// - Network: `Filtered` (allowlist egress)
///
/// Use [`IsolationLattice::localhost()`] explicitly for development/testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IsolationLattice {
    /// Process isolation level.
    pub process: ProcessIsolation,

    /// Filesystem isolation level.
    pub file: FileIsolation,

    /// Network isolation level.
    pub network: NetworkIsolation,
}

impl IsolationLattice {
    /// Create a new isolation lattice with specified levels.
    pub fn new(process: ProcessIsolation, file: FileIsolation, network: NetworkIsolation) -> Self {
        Self {
            process,
            file,
            network,
        }
    }

    /// Localhost execution with no isolation.
    ///
    /// # Security Warning
    ///
    /// This provides NO isolation. Use only for development/testing
    /// or when the agent is already running in an isolated context.
    pub fn localhost() -> Self {
        Self {
            process: ProcessIsolation::Shared,
            file: FileIsolation::Unrestricted,
            network: NetworkIsolation::Host,
        }
    }

    /// Secure default for production use.
    ///
    /// Provides reasonable isolation without requiring a full microVM:
    /// - Process: Namespaced (Linux namespaces)
    /// - File: Sandboxed (cap-std directory capabilities)
    /// - Network: Filtered (allowlist-only egress)
    pub fn secure_default() -> Self {
        Self::sandboxed()
    }

    /// Sandboxed execution with cap-std and filtered network.
    pub fn sandboxed() -> Self {
        Self {
            process: ProcessIsolation::Namespaced,
            file: FileIsolation::Sandboxed,
            network: NetworkIsolation::Filtered,
        }
    }

    /// MicroVM execution with ephemeral storage and airgapped network.
    pub fn microvm() -> Self {
        Self {
            process: ProcessIsolation::MicroVM,
            file: FileIsolation::Ephemeral,
            network: NetworkIsolation::Airgapped,
        }
    }

    /// MicroVM with filtered (not airgapped) network for web access.
    pub fn microvm_with_network() -> Self {
        Self {
            process: ProcessIsolation::MicroVM,
            file: FileIsolation::ReadOnly,
            network: NetworkIsolation::Filtered,
        }
    }

    /// Check if network access is available.
    pub fn has_network(&self) -> bool {
        self.network != NetworkIsolation::Airgapped
    }

    /// Check if persistent storage is available.
    pub fn has_persistent_storage(&self) -> bool {
        self.file != FileIsolation::Ephemeral
    }

    /// Check if this isolation level is at least as strong as another.
    pub fn at_least(&self, other: &Self) -> bool {
        self.process >= other.process && self.file >= other.file && self.network >= other.network
    }
}

impl fmt::Display for IsolationLattice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "process={}, file={}, network={}",
            self.process, self.file, self.network
        )
    }
}

impl Lattice for IsolationLattice {
    /// Meet: minimum of each dimension (weaker isolation).
    ///
    /// The meet represents the isolation that BOTH configurations can provide.
    fn meet(&self, other: &Self) -> Self {
        Self {
            process: min(self.process, other.process),
            file: min(self.file, other.file),
            network: min(self.network, other.network),
        }
    }

    /// Join: maximum of each dimension (stronger isolation).
    ///
    /// The join represents the isolation required by EITHER configuration.
    fn join(&self, other: &Self) -> Self {
        Self {
            process: max(self.process, other.process),
            file: max(self.file, other.file),
            network: max(self.network, other.network),
        }
    }

    /// Partial order: self ≤ other iff weaker-or-equal on ALL dimensions.
    fn leq(&self, other: &Self) -> bool {
        self.process <= other.process && self.file <= other.file && self.network <= other.network
    }
}

impl BoundedLattice for IsolationLattice {
    /// Bottom: no isolation (localhost).
    fn bottom() -> Self {
        Self::localhost()
    }

    /// Top: maximum isolation (airgapped microVM with ephemeral storage).
    fn top() -> Self {
        Self {
            process: ProcessIsolation::MicroVM,
            file: FileIsolation::Ephemeral,
            network: NetworkIsolation::Airgapped,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_isolation_ordering() {
        assert!(ProcessIsolation::Shared < ProcessIsolation::Namespaced);
        assert!(ProcessIsolation::Namespaced < ProcessIsolation::MicroVM);
    }

    #[test]
    fn test_file_isolation_ordering() {
        assert!(FileIsolation::Unrestricted < FileIsolation::Sandboxed);
        assert!(FileIsolation::Sandboxed < FileIsolation::ReadOnly);
        assert!(FileIsolation::ReadOnly < FileIsolation::Ephemeral);
    }

    #[test]
    fn test_network_isolation_ordering() {
        assert!(NetworkIsolation::Host < NetworkIsolation::Namespaced);
        assert!(NetworkIsolation::Namespaced < NetworkIsolation::Filtered);
        assert!(NetworkIsolation::Filtered < NetworkIsolation::Airgapped);
    }

    #[test]
    fn test_lattice_meet() {
        let sandboxed = IsolationLattice::sandboxed();
        let microvm = IsolationLattice::microvm();

        let meet = sandboxed.meet(&microvm);

        // Meet takes minimum of each dimension
        assert_eq!(meet.process, ProcessIsolation::Namespaced);
        assert_eq!(meet.file, FileIsolation::Sandboxed);
        assert_eq!(meet.network, NetworkIsolation::Filtered);
    }

    #[test]
    fn test_lattice_join() {
        let sandboxed = IsolationLattice::sandboxed();
        let microvm = IsolationLattice::microvm();

        let join = sandboxed.join(&microvm);

        // Join takes maximum of each dimension
        assert_eq!(join.process, ProcessIsolation::MicroVM);
        assert_eq!(join.file, FileIsolation::Ephemeral);
        assert_eq!(join.network, NetworkIsolation::Airgapped);
    }

    #[test]
    fn test_lattice_leq() {
        let localhost = IsolationLattice::localhost();
        let sandboxed = IsolationLattice::sandboxed();
        let microvm = IsolationLattice::microvm();

        // localhost ≤ sandboxed ≤ microvm
        assert!(localhost.leq(&sandboxed));
        assert!(sandboxed.leq(&microvm));
        assert!(localhost.leq(&microvm));

        // Not the reverse
        assert!(!microvm.leq(&localhost));
        assert!(!sandboxed.leq(&localhost));
    }

    #[test]
    fn test_lattice_leq_incomparable() {
        // Two configurations that are incomparable
        let a = IsolationLattice {
            process: ProcessIsolation::MicroVM,
            file: FileIsolation::Unrestricted,
            network: NetworkIsolation::Host,
        };
        let b = IsolationLattice {
            process: ProcessIsolation::Shared,
            file: FileIsolation::Ephemeral,
            network: NetworkIsolation::Airgapped,
        };

        // Neither is ≤ the other
        assert!(!a.leq(&b));
        assert!(!b.leq(&a));
    }

    #[test]
    fn test_bounded_lattice() {
        let bottom = IsolationLattice::bottom();
        let top = IsolationLattice::top();
        let sandboxed = IsolationLattice::sandboxed();

        // bottom ≤ anything
        assert!(bottom.leq(&sandboxed));
        assert!(bottom.leq(&top));

        // anything ≤ top
        assert!(sandboxed.leq(&top));
        assert!(bottom.leq(&top));

        // Meet with top is identity
        assert_eq!(sandboxed.meet(&top), sandboxed);

        // Join with bottom is identity
        assert_eq!(sandboxed.join(&bottom), sandboxed);
    }

    #[test]
    fn test_lattice_idempotent() {
        let iso = IsolationLattice::sandboxed();

        assert_eq!(iso.meet(&iso), iso);
        assert_eq!(iso.join(&iso), iso);
    }

    #[test]
    fn test_lattice_commutative() {
        let a = IsolationLattice::sandboxed();
        let b = IsolationLattice::microvm();

        assert_eq!(a.meet(&b), b.meet(&a));
        assert_eq!(a.join(&b), b.join(&a));
    }

    #[test]
    fn test_lattice_associative() {
        let a = IsolationLattice::localhost();
        let b = IsolationLattice::sandboxed();
        let c = IsolationLattice::microvm();

        assert_eq!(a.meet(&b).meet(&c), a.meet(&b.meet(&c)));
        assert_eq!(a.join(&b).join(&c), a.join(&b.join(&c)));
    }

    #[test]
    fn test_lattice_absorption() {
        let a = IsolationLattice::sandboxed();
        let b = IsolationLattice::microvm();

        // a ∧ (a ∨ b) = a
        assert_eq!(a.meet(&a.join(&b)), a);

        // a ∨ (a ∧ b) = a
        assert_eq!(a.join(&a.meet(&b)), a);
    }

    #[test]
    fn test_has_network() {
        assert!(IsolationLattice::localhost().has_network());
        assert!(IsolationLattice::sandboxed().has_network());
        assert!(IsolationLattice::microvm_with_network().has_network());
        assert!(!IsolationLattice::microvm().has_network());
    }

    #[test]
    fn test_has_persistent_storage() {
        assert!(IsolationLattice::localhost().has_persistent_storage());
        assert!(IsolationLattice::sandboxed().has_persistent_storage());
        assert!(IsolationLattice::microvm_with_network().has_persistent_storage());
        assert!(!IsolationLattice::microvm().has_persistent_storage());
    }

    #[test]
    fn test_as_str() {
        assert_eq!(ProcessIsolation::Shared.as_str(), "shared");
        assert_eq!(ProcessIsolation::Namespaced.as_str(), "namespaced");
        assert_eq!(ProcessIsolation::MicroVM.as_str(), "microvm");

        assert_eq!(FileIsolation::Unrestricted.as_str(), "unrestricted");
        assert_eq!(FileIsolation::Sandboxed.as_str(), "sandboxed");
        assert_eq!(FileIsolation::ReadOnly.as_str(), "readonly");
        assert_eq!(FileIsolation::Ephemeral.as_str(), "ephemeral");

        assert_eq!(NetworkIsolation::Host.as_str(), "host");
        assert_eq!(NetworkIsolation::Namespaced.as_str(), "namespaced");
        assert_eq!(NetworkIsolation::Filtered.as_str(), "filtered");
        assert_eq!(NetworkIsolation::Airgapped.as_str(), "airgapped");
    }

    #[test]
    fn test_display() {
        let iso = IsolationLattice::sandboxed();
        let display = format!("{}", iso);
        assert!(display.contains("namespaced"));
        assert!(display.contains("sandboxed"));
        assert!(display.contains("filtered"));
    }
}

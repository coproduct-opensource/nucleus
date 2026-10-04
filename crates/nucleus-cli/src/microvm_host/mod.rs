//! The Apple `container` host for Firecracker microVMs, on macOS.
//!
//! `nucleus-node --driver firecracker` needs a Linux host with KVM. On a Mac
//! that host is a `container` started with nested virtualization and the L1
//! kernel from `docker/Containerfile.l1-kernel`; every name, version, path and
//! capability it uses is pinned in `nucleus_spec::microvm_host`.
//!
//! - [`container_cli`]: the only code that runs `container`, every call with a
//!   deadline and `SIGKILL` on expiry.
//! - [`preflight`]: can this Mac do it, as a pure `unmet(&Observed)`.
//! - [`lifecycle`]: the container's state, and [`lifecycle::ensure_ready`],
//!   which mints the [`lifecycle::MicroVmHost`] witness.
//! - [`supervisor`]: restart a dead host within a budget, and audit it.
//! - [`transport`]: reach a pod's proxy from the Mac through a relay.
//!
//! Not wired into `shell` or `run` yet; that is the next change.

pub mod container_cli;
pub mod lifecycle;
pub mod preflight;
pub mod supervisor;
pub mod transport;

#[cfg(test)]
mod live;

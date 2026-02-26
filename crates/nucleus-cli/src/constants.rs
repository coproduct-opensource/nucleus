//! Shared constants for nucleus-cli.
//!
//! This module centralizes constants used across multiple CLI commands
//! to maintain consistency and simplify version/configuration updates.

/// Version of Firecracker to download and validate.
///
/// This version is used by:
/// - `setup` command: Downloads and provisions Firecracker on Lima VM
/// - `doctor` command: Verifies installed Firecracker matches expected version
///
/// Update this constant when upgrading to a new Firecracker version.
pub const FIRECRACKER_VERSION: &str = "1.14.1";

//! The jailer's per-process resource limits on the VMM: `--resource-limit fsize=` and
//! `--resource-limit no-file=` (#2571).
//!
//! # What they bound
//!
//! The jailer calls `setrlimit` for both before it clones and `exec`s Firecracker, so the limits
//! hold from the VMM's first instruction, like the cgroup.
//!
//! - **`fsize`** (`RLIMIT_FSIZE`) is the furthest offset at which the VMM may write in any file.
//!   That covers the writable drive images, a snapshot's memory file, and the console log the
//!   node opened for it. Without it, a compromised VMM holding a writable drive's descriptor
//!   could keep extending that file until the host's disk is full. A write past the limit fails
//!   with `EFBIG` and raises `SIGXFSZ`, which ends the VMM.
//! - **`no-file`** (`RLIMIT_NOFILE`) caps how many descriptors the VMM can hold. The jailer has
//!   always applied 2048 when it is not told otherwise. The node now passes that value
//!   explicitly, so the limit comes from the node's config rather than from a jailer default
//!   that could change between versions.
//!
//! # The defaults
//!
//! - **64 GiB for `fsize`.** That is 16 times the node's provisioned scratch disk
//!   (`DEFAULT_SCRATCH_BYTES`) and 8 times the default per-pod memory ceiling
//!   (`--max-pod-memory-mib 8192`), which is the size of a snapshot's memory file. The limit is
//!   finite, so the host's disk is protected, and it is far above anything a default pod writes.
//! - **2048 for `no-file`**, the jailer's own default. Firecracker needs a few dozen descriptors.
//!
//! # Refused by name rather than killed later
//!
//! The limit is on write OFFSET, not growth: a write at offset N fails when N is at or past the
//! limit, even inside a file that is already that large. So a pod whose writable drive, or
//! whose memory (the snapshot file), is larger than the limit would boot and then die with
//! `SIGXFSZ` the first time the guest wrote near the end of its disk. [`JailerLimits::admit`]
//! refuses that launch before the jailer runs, and names the flag to raise.

use crate::ApiError;

/// `--jailer-max-file-bytes` when the operator does not say. See the module docs.
const DEFAULT_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
/// `--jailer-max-open-files` when the operator does not say: the jailer's own default.
const DEFAULT_MAX_OPEN_FILES: u64 = 2048;

/// The operator's limits on the jailed VMM, flattened into `Args`.
#[derive(clap::Args, Debug, Clone)]
pub(crate) struct JailerLimitArgs {
    /// The largest file offset the jailed VMM may write, in bytes (`RLIMIT_FSIZE`, passed as
    /// `--resource-limit fsize=`). It must be at least the pod's largest writable drive and its
    /// memory size. A launch that needs more is refused by name.
    #[arg(
        long = "jailer-max-file-bytes",
        env = "NUCLEUS_JAILER_MAX_FILE_BYTES",
        default_value_t = DEFAULT_MAX_FILE_BYTES,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub jailer_max_file_bytes: u64,
    /// The most descriptors the jailed VMM may hold open (`RLIMIT_NOFILE`, passed as
    /// `--resource-limit no-file=`). The minimum is 64, so the limit cannot be set low enough
    /// to stop Firecracker from starting.
    #[arg(
        long = "jailer-max-open-files",
        env = "NUCLEUS_JAILER_MAX_OPEN_FILES",
        default_value_t = DEFAULT_MAX_OPEN_FILES,
        value_parser = clap::value_parser!(u64).range(64..)
    )]
    pub jailer_max_open_files: u64,
}

/// The limits in force. No `Default` (ADR 0007 B-1): a limit is a grant, and none is neutral.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JailerLimits {
    max_file_bytes: u64,
    max_open_files: u64,
}

impl JailerLimitArgs {
    pub(crate) fn limits(&self) -> JailerLimits {
        let Self {
            jailer_max_file_bytes,
            jailer_max_open_files,
        } = *self;
        JailerLimits {
            max_file_bytes: jailer_max_file_bytes,
            max_open_files: jailer_max_open_files,
        }
    }
}

impl JailerLimits {
    /// The values of the jailer's `--resource-limit` arguments, one per limit.
    pub(crate) fn resource_limits(&self) -> [String; 2] {
        let Self {
            max_file_bytes,
            max_open_files,
        } = *self;
        [
            format!("fsize={max_file_bytes}"),
            format!("no-file={max_open_files}"),
        ]
    }

    /// Refuse a launch whose VMM must write at an offset the file-size limit forbids. `extent` is
    /// the furthest it must reach: its largest writable drive, or its memory (a snapshot's file).
    pub(crate) fn admit(&self, extent: u64) -> Result<(), ApiError> {
        if extent <= self.max_file_bytes {
            return Ok(());
        }
        Err(ApiError::Driver(format!(
            "this pod's VMM must write up to {extent} bytes into one file (its largest writable \
             drive or its memory snapshot), but the jailer's file-size limit is {} bytes. The \
             launch is refused rather than started to die of SIGXFSZ. Raise \
             --jailer-max-file-bytes (NUCLEUS_JAILER_MAX_FILE_BYTES) to admit it.",
            self.max_file_bytes
        )))
    }
}

#[cfg(test)]
impl JailerLimits {
    /// The flag defaults, without parsing an argv.
    pub(crate) fn defaults() -> Self {
        Self::new(DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_OPEN_FILES)
    }

    pub(crate) fn new(max_file_bytes: u64, max_open_files: u64) -> Self {
        Self {
            max_file_bytes,
            max_open_files,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Probe {
        #[command(flatten)]
        limits: JailerLimitArgs,
    }

    #[test]
    fn the_flags_default_to_a_finite_file_size_and_the_jailers_own_descriptor_limit() {
        let probe = Probe::try_parse_from(["node"]).unwrap();
        assert_eq!(probe.limits.limits(), JailerLimits::defaults());
        assert_eq!(
            JailerLimits::defaults().resource_limits(),
            ["fsize=68719476736".to_string(), "no-file=2048".to_string()]
        );
    }

    #[test]
    fn the_flags_set_both_limits_and_refuse_values_that_would_stop_the_vmm() {
        let probe = Probe::try_parse_from([
            "node",
            "--jailer-max-file-bytes",
            "1048576",
            "--jailer-max-open-files",
            "512",
        ])
        .unwrap();
        assert_eq!(
            probe.limits.limits().resource_limits(),
            ["fsize=1048576".to_string(), "no-file=512".to_string()]
        );
        assert!(Probe::try_parse_from(["node", "--jailer-max-file-bytes", "0"]).is_err());
        assert!(Probe::try_parse_from(["node", "--jailer-max-open-files", "63"]).is_err());
    }

    #[test]
    fn a_vmm_that_must_write_past_the_limit_is_refused_by_name() {
        let limits = JailerLimits::new(4096, 2048);
        assert!(limits.admit(4096).is_ok());
        let refused = limits.admit(4097).unwrap_err().to_string();
        assert!(
            refused.contains("--jailer-max-file-bytes") && refused.contains("4097"),
            "{refused}"
        );
    }
}

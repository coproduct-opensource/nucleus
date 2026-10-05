//! Measure a host image's installed inputs into the manifest that `nucleus
//! setup` and `verify --tier2 --apple-host-config` read (#3207).
//!
//! The release recipe runs this as its last build step, so the manifest
//! records the bytes the image actually carries, by the one schema type every
//! writer and reader shares ([`HostInputManifest`]). It refuses rather than
//! writing a partial manifest: a missing input or a guest kernel off the pin
//! fails the image build.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use nucleus_spec::microvm_host::{HostInput, HostInputManifest};
use nucleus_spec::tier2_artifacts::{GUEST_KERNEL_FILE, GUEST_ROOTFS_FILE, kernel_for};

/// Why no manifest was written.
#[derive(Debug)]
pub enum InputManifestError {
    /// An input could not be read (absent, unreadable, not a file).
    Unreadable {
        /// The input's path.
        path: PathBuf,
        /// The underlying error.
        error: std::io::Error,
    },
    /// An input exists but is empty.
    Empty(PathBuf),
    /// There is no pinned guest kernel for this architecture.
    NoKernelPin(String),
    /// The installed guest kernel is not the pinned one.
    KernelOffPin {
        /// The pinned digest.
        pinned: String,
        /// What is installed.
        installed: String,
    },
    /// The manifest could not be written.
    Write {
        /// Where it was to be written.
        path: PathBuf,
        /// The underlying error.
        error: std::io::Error,
    },
}

impl fmt::Display for InputManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { path, error } => {
                write!(f, "host input {} unreadable: {error}", path.display())
            }
            Self::Empty(path) => write!(f, "host input {} is empty", path.display()),
            Self::NoKernelPin(arch) => write!(f, "no guest kernel is pinned for {arch}"),
            Self::KernelOffPin { pinned, installed } => write!(
                f,
                "guest kernel sha256 {installed} is not the pinned {pinned}"
            ),
            Self::Write { path, error } => {
                write!(f, "writing {}: {error}", path.display())
            }
        }
    }
}

impl std::error::Error for InputManifestError {}

fn measure(path: &Path) -> Result<HostInput, InputManifestError> {
    let unreadable = |error| InputManifestError::Unreadable {
        path: path.to_path_buf(),
        error,
    };
    let meta = std::fs::metadata(path).map_err(unreadable)?;
    if !meta.is_file() {
        return Err(unreadable(std::io::Error::other("not a regular file")));
    }
    let input = HostInput::measure(path).map_err(unreadable)?;
    if input.bytes == 0 {
        return Err(InputManifestError::Empty(path.to_path_buf()));
    }
    Ok(input)
}

/// Measure `binaries` in `bin_dir` and the guest kernel and rootfs in
/// `artifacts_dir`, for a guest of `architecture`. Every input is required,
/// and the kernel must be the one pinned for `architecture`.
pub fn measure_installed(
    bin_dir: &Path,
    artifacts_dir: &Path,
    binaries: &[&str],
    architecture: &str,
) -> Result<HostInputManifest, InputManifestError> {
    let pinned = kernel_for(architecture)
        .ok_or_else(|| InputManifestError::NoKernelPin(architecture.to_string()))?
        .sha256;
    measure_with_kernel_pin(bin_dir, artifacts_dir, binaries, architecture, pinned)
}

fn measure_with_kernel_pin(
    bin_dir: &Path,
    artifacts_dir: &Path,
    binaries: &[&str],
    architecture: &str,
    pinned_kernel: &str,
) -> Result<HostInputManifest, InputManifestError> {
    let mut files = BTreeMap::new();
    for name in binaries {
        files.insert((*name).to_string(), measure(&bin_dir.join(name))?);
    }
    let kernel = measure(&artifacts_dir.join(GUEST_KERNEL_FILE))?;
    if kernel.sha256 != pinned_kernel {
        return Err(InputManifestError::KernelOffPin {
            pinned: pinned_kernel.to_string(),
            installed: kernel.sha256,
        });
    }
    files.insert(GUEST_KERNEL_FILE.to_string(), kernel);
    files.insert(
        GUEST_ROOTFS_FILE.to_string(),
        measure(&artifacts_dir.join(GUEST_ROOTFS_FILE))?,
    );
    Ok(HostInputManifest::new(architecture, files))
}

/// Write `manifest` to a new file at `out`, creating its directory. An
/// existing file is refused, never overwritten.
pub fn write_new(manifest: &HostInputManifest, out: &Path) -> Result<(), InputManifestError> {
    let failed = |error| InputManifestError::Write {
        path: out.to_path_buf(),
        error,
    };
    if let Some(dir) = out.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(failed)?;
    }
    let json = serde_json::to_vec_pretty(manifest).map_err(|e| failed(e.into()))?;
    let mut file = std::fs::File::create_new(out).map_err(failed)?;
    file.write_all(&json).map_err(failed)?;
    file.sync_all().map_err(failed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_spec::microvm_host::HOST_INPUT_SCHEMA;

    struct Host {
        _dir: tempfile::TempDir,
        bin: PathBuf,
        artifacts: PathBuf,
    }

    /// A host with every input present, the kernel replaced by `kernel`.
    fn host(kernel: &[u8]) -> Host {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("bin");
        let artifacts = dir.path().join("artifacts");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(&artifacts).unwrap();
        for name in ["a", "b"] {
            std::fs::write(bin.join(name), name.repeat(3)).unwrap();
        }
        std::fs::write(artifacts.join(GUEST_KERNEL_FILE), kernel).unwrap();
        std::fs::write(artifacts.join(GUEST_ROOTFS_FILE), b"rootfs").unwrap();
        Host {
            _dir: dir,
            bin,
            artifacts,
        }
    }

    #[test]
    fn every_input_is_measured_against_the_kernel_pin() {
        let h = host(b"kernel");
        let pin = HostInput::measure(&h.artifacts.join(GUEST_KERNEL_FILE))
            .unwrap()
            .sha256;
        let m =
            measure_with_kernel_pin(&h.bin, &h.artifacts, &["a", "b"], "aarch64", &pin).unwrap();
        assert_eq!(m.schema, HOST_INPUT_SCHEMA);
        assert_eq!(
            m.files.keys().map(String::as_str).collect::<Vec<_>>(),
            ["a", "b", GUEST_ROOTFS_FILE, GUEST_KERNEL_FILE]
        );
        assert_eq!(m.files[GUEST_KERNEL_FILE].sha256, pin);
        assert_eq!(m.files["a"].bytes, 3);
    }

    /// The real pin cannot be met by test bytes, so this is the refusal.
    #[test]
    fn a_kernel_off_the_pin_is_refused() {
        let h = host(b"not the pinned kernel");
        let err = measure_installed(&h.bin, &h.artifacts, &["a", "b"], "aarch64").unwrap_err();
        assert!(
            matches!(err, InputManifestError::KernelOffPin { ref pinned, .. }
                if *pinned == nucleus_spec::tier2_artifacts::KERNEL_AARCH64.sha256),
            "{err}"
        );
    }

    #[test]
    fn a_missing_binary_is_refused_before_anything_is_written() {
        let h = host(b"k");
        let err =
            measure_installed(&h.bin, &h.artifacts, &["a", "missing"], "aarch64").unwrap_err();
        assert!(
            matches!(&err, InputManifestError::Unreadable { path, .. } if path.ends_with("missing")),
            "{err}"
        );
    }

    #[test]
    fn an_empty_input_and_an_unpinned_arch_are_refused() {
        let h = host(b"k");
        std::fs::write(h.bin.join("a"), b"").unwrap();
        assert!(matches!(
            measure_installed(&h.bin, &h.artifacts, &["a"], "aarch64"),
            Err(InputManifestError::Empty(_))
        ));
        assert!(matches!(
            measure_installed(&h.bin, &h.artifacts, &["b"], "riscv64"),
            Err(InputManifestError::NoKernelPin(_))
        ));
    }

    #[test]
    fn the_manifest_round_trips_and_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        std::fs::write(&input, b"abc").unwrap();
        let measured = measure(&input).unwrap();
        assert_eq!(
            measured.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(measured.bytes, 3);
        let manifest =
            HostInputManifest::new("aarch64", BTreeMap::from([("input".into(), measured)]));
        let out = dir.path().join("share/nucleus/host-inputs.json");
        write_new(&manifest, &out).unwrap();
        let read: HostInputManifest =
            serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
        assert_eq!(read, manifest);
        assert_eq!(read.schema, HOST_INPUT_SCHEMA);
        assert!(read.is_aarch64());
        assert!(matches!(
            write_new(&manifest, &out),
            Err(InputManifestError::Write { .. })
        ));
    }
}

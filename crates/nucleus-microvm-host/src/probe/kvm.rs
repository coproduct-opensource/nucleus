//! Whether this host can actually run a KVM guest, not merely whether
//! `/dev/kvm` exists.
//!
//! A device node is necessary and not sufficient. A container can be handed a
//! `/dev/kvm` whose ioctls fail, and a nested-virtualisation host can expose one
//! whose API is not the stable one. So the probe does what Firecracker will do
//! first: open the device, ask `KVM_GET_API_VERSION`, and create a VM.
//!
//! The ioctls go through `kvm-ioctls`' safe wrappers — the crate the VMM itself
//! is built on — so this adds no `unsafe` to the workspace.

use serde::Serialize;

/// The only KVM API version there has ever been since 2.6.22. Anything else is
/// not a KVM this VMM can use.
pub const STABLE_API: i32 = 12;

/// The outcome of probing KVM. Three cases, never a bool: "there is no KVM" and
/// "there is one and it does not work" have different remedies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Kvm {
    /// Opened, reported the stable API, and created a VM.
    Present { api: i32 },
    /// No `/dev/kvm` on this host.
    Absent,
    /// Something is there and cannot be used; `reason` says which step failed.
    Unusable { reason: String },
}

impl Kvm {
    /// Whether a microVM can launch here. Only `Present` can.
    pub fn is_usable(&self) -> bool {
        matches!(self, Kvm::Present { .. })
    }
}

/// Decide from what was observed. Pure, so every arm is testable on any host.
///
/// `create_vm` is the result of `KVM_CREATE_VM`, attempted only after the API
/// version was read.
pub fn judge(api: i32, create_vm: Result<(), String>) -> Kvm {
    if api != STABLE_API {
        return Kvm::Unusable {
            reason: format!("KVM_GET_API_VERSION returned {api}, expected {STABLE_API}"),
        };
    }
    match create_vm {
        Ok(()) => Kvm::Present { api },
        Err(e) => Kvm::Unusable {
            reason: format!("KVM_CREATE_VM failed: {e}"),
        },
    }
}

/// Probe this host's KVM. I/O.
#[cfg(target_os = "linux")]
pub fn probe() -> Kvm {
    if !std::path::Path::new("/dev/kvm").exists() {
        return Kvm::Absent;
    }
    let kvm = match kvm_ioctls::Kvm::new() {
        Ok(k) => k,
        Err(e) => {
            return Kvm::Unusable {
                reason: format!("opening /dev/kvm: {e}"),
            };
        }
    };
    let api = kvm.get_api_version();
    let created = kvm.create_vm().map(drop).map_err(|e| e.to_string());
    judge(api, created)
}

/// Probe this host's KVM. There is none off Linux, and saying `Absent` would be
/// true but would hide why; the reason names the OS.
#[cfg(not(target_os = "linux"))]
pub fn probe() -> Kvm {
    Kvm::Unusable {
        reason: format!(
            "KVM exists only on Linux; this host is {}",
            std::env::consts::OS
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_stable_api_with_a_created_vm_is_present() {
        assert_eq!(judge(12, Ok(())), Kvm::Present { api: 12 });
        assert!(judge(12, Ok(())).is_usable());
    }

    #[test]
    fn a_wrong_api_version_is_unusable_even_if_a_vm_could_be_made() {
        let k = judge(11, Ok(()));
        assert!(!k.is_usable());
        assert!(
            matches!(&k, Kvm::Unusable { reason } if reason.contains("11")),
            "{k:?}"
        );
    }

    #[test]
    fn a_failed_create_vm_is_unusable_and_says_so() {
        let k = judge(12, Err("EPERM".into()));
        assert!(matches!(&k, Kvm::Unusable { reason } if reason.contains("KVM_CREATE_VM")));
        assert!(!Kvm::Absent.is_usable());
    }

    /// The JSON the `probe` command prints: a tagged status a script can match on.
    #[test]
    fn the_report_shape_is_tagged() {
        let v = serde_json::to_value(Kvm::Present { api: 12 }).expect("serialises");
        assert_eq!(v, serde_json::json!({"status": "present", "api": 12}));
        let v = serde_json::to_value(Kvm::Absent).expect("serialises");
        assert_eq!(v, serde_json::json!({"status": "absent"}));
    }

    /// Whatever this host is, the probe answers without panicking, and off Linux
    /// it never claims KVM.
    #[test]
    fn the_probe_runs_here() {
        let k = probe();
        if !cfg!(target_os = "linux") {
            assert!(!k.is_usable(), "{k:?}");
        }
    }
}

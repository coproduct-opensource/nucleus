//! The host contract: one definition of a nucleus host, whatever wraps it.
//!
//! A host is fit to run nucleus pods when it offers the same thing everywhere: an aarch64 Linux
//! kernel at the pinned release, a KVM that answers the stable API and creates a VM,
//! `/dev/vhost-vsock`, `/srv` on the same filesystem as the jailer chroot, and the pinned
//! Firecracker. What wraps that kernel is the **envelope**, and it is the only part allowed to
//! differ between an operator's Mac and a bare-metal server:
//!
//! * [`Envelope::AppleContainer`]: Apple `container run --virtualization --kernel <L1>` on an
//!   M3-or-newer Mac. KVM is nested. The kernel is [`L1_KERNEL`].
//! * [`Envelope::Metal`]: the kernel boots on the machine. KVM is native. The kernel release is
//!   whatever the deployment pinned for its image, so it must be given; there is no default.
//!
//! [`judge`] is the one decision, pure and total, used by both the host that probes itself and
//! the relying party that checks the result. [`verify`] re-runs it on the signed observation
//! rather than trusting a signer's own "conforms", so a host cannot sign itself fit.
//!
//! # What this does not claim
//!
//! * **Not the envelope.** Which envelope a host is in is declared by whoever launched it, and
//!   signed, not observed: nothing here distinguishes nested from native KVM. A host that lies
//!   about its envelope is caught only by a check that differs between them, which today is the
//!   kernel release.
//! * **Not the binaries.** The kernel release and Firecracker version are what they report about
//!   themselves (`vmm_version`'s own caveat). Binding to measured bytes is attestation work
//!   (ADR 0011), not this.
//! * **Not reflink.** `/srv` sharing a filesystem with the jailer chroot is checked; whether that
//!   filesystem clones cheaply is not, because it changes cost, not verdicts.
//! * **Not freshness.** `issued_at` is recorded; how old a probe may be is the relying party's.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use nucleus_spec::microvm_host::L1_KERNEL;
use nucleus_spec::vmm_version;
use serde::{Deserialize, Serialize};

use crate::probe::kvm::Kvm;

/// Domain of the bytes a host signs over its probe.
pub const PROBE_DOMAIN: &[u8] = b"nucleus/host-probe/v1\n";

/// The one architecture the contract admits.
pub const ARCHITECTURE: &str = "aarch64";

/// What wraps the host's kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Envelope {
    /// Apple `container` with nested virtualization, on an M3-or-newer Mac.
    AppleContainer,
    /// The kernel runs on the machine.
    Metal,
}

impl Envelope {
    /// How KVM reaches the hardware in this envelope. Declared with the envelope, not observed.
    pub const fn kvm_mode(self) -> KvmMode {
        match self {
            Self::AppleContainer => KvmMode::Nested,
            Self::Metal => KvmMode::Native,
        }
    }
}

/// How KVM reaches the hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KvmMode {
    /// KVM inside a guest of another hypervisor (nVHE under Apple's).
    Nested,
    /// KVM on the machine (VHE).
    Native,
}

/// What a relying party requires of a host. Built per envelope; never defaulted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostContract {
    envelope: Envelope,
    architecture: String,
    kernel_release: String,
    firecracker: String,
}

impl HostContract {
    /// The Mac envelope: the kernel is the pinned L1 kernel.
    pub fn apple_container() -> Self {
        Self::with(Envelope::AppleContainer, L1_KERNEL.linux_version)
    }

    /// The metal envelope: the kernel release the deployment's image pins.
    pub fn metal(kernel_release: &str) -> Result<Self, String> {
        if kernel_release.trim().is_empty() {
            return Err("a metal host contract needs the kernel release its image pins".into());
        }
        Ok(Self::with(Envelope::Metal, kernel_release.trim()))
    }

    fn with(envelope: Envelope, kernel_release: &str) -> Self {
        Self {
            envelope,
            architecture: ARCHITECTURE.to_owned(),
            kernel_release: kernel_release.to_owned(),
            firecracker: vmm_version::PINNED.to_string(),
        }
    }

    /// The envelope this contract is for.
    pub fn envelope(&self) -> Envelope {
        self.envelope
    }
}

/// What was seen on the host. `None` means the probe could not look, which is never a pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    /// `uname -m`.
    pub architecture: Option<String>,
    /// `/proc/sys/kernel/osrelease`.
    pub kernel_release: Option<String>,
    /// The version `firecracker --version` reported, as `X.Y.Z`.
    pub firecracker: Option<String>,
    /// The KVM probe's verdict.
    pub kvm: Kvm,
    /// `/dev/vhost-vsock` exists.
    pub vhost_vsock: bool,
    /// `/srv` and the jailer chroot base are on one filesystem.
    pub srv_beside_jailer: Option<bool>,
}

/// One way a host fails the contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "breach", rename_all = "snake_case")]
pub enum Breach {
    /// The machine is not the contract's architecture, or could not be read.
    Architecture {
        expected: String,
        found: Option<String>,
    },
    /// The running kernel is not the pinned release, or could not be read.
    Kernel {
        expected: String,
        found: Option<String>,
    },
    /// Firecracker is not the pinned version, or did not answer.
    Firecracker {
        expected: String,
        found: Option<String>,
    },
    /// KVM is absent or unusable.
    Kvm { found: Kvm },
    /// No `/dev/vhost-vsock`.
    VhostVsock,
    /// `/srv` and the jailer chroot are on different filesystems, so hard links fail (EXDEV).
    SrvApartFromJailer,
    /// Whether `/srv` and the jailer chroot share a filesystem could not be observed.
    SrvUnobserved,
}

impl fmt::Display for Breach {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seen = |v: &Option<String>| v.clone().unwrap_or_else(|| "nothing readable".into());
        match self {
            Self::Architecture { expected, found } => {
                write!(
                    f,
                    "architecture: expected {expected}, found {}",
                    seen(found)
                )
            }
            Self::Kernel { expected, found } => {
                write!(f, "kernel: expected {expected}, found {}", seen(found))
            }
            Self::Firecracker { expected, found } => {
                write!(f, "firecracker: expected {expected}, found {}", seen(found))
            }
            Self::Kvm { found } => write!(f, "kvm: {found:?}"),
            Self::VhostVsock => f.write_str("/dev/vhost-vsock is missing"),
            Self::SrvApartFromJailer => {
                f.write_str("/srv and the jailer chroot are on different filesystems")
            }
            Self::SrvUnobserved => f.write_str("/srv could not be observed"),
        }
    }
}

/// Every way `seen` fails `contract`, in a fixed order. Empty means the host conforms.
pub fn judge(contract: &HostContract, seen: &Observation) -> Vec<Breach> {
    let mut breaches = Vec::new();
    if seen.architecture.as_deref() != Some(contract.architecture.as_str()) {
        breaches.push(Breach::Architecture {
            expected: contract.architecture.clone(),
            found: seen.architecture.clone(),
        });
    }
    if !seen
        .kernel_release
        .as_deref()
        .is_some_and(|found| kernel_matches(&contract.kernel_release, found))
    {
        breaches.push(Breach::Kernel {
            expected: contract.kernel_release.clone(),
            found: seen.kernel_release.clone(),
        });
    }
    if seen.firecracker.as_deref() != Some(contract.firecracker.as_str()) {
        breaches.push(Breach::Firecracker {
            expected: contract.firecracker.clone(),
            found: seen.firecracker.clone(),
        });
    }
    if !seen.kvm.is_usable() {
        breaches.push(Breach::Kvm {
            found: seen.kvm.clone(),
        });
    }
    if !seen.vhost_vsock {
        breaches.push(Breach::VhostVsock);
    }
    match seen.srv_beside_jailer {
        Some(true) => {}
        Some(false) => breaches.push(Breach::SrvApartFromJailer),
        None => breaches.push(Breach::SrvUnobserved),
    }
    breaches
}

/// `found` is the release `expected`, or that release with a local suffix (`6.18.35-nucleus`,
/// `6.18.35+`). `6.18.350` is not `6.18.35`.
pub fn kernel_matches(expected: &str, found: &str) -> bool {
    found == expected
        || found
            .strip_prefix(expected)
            .is_some_and(|rest| rest.starts_with(['-', '+']))
}

/// The record a host signs about itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeBody {
    /// The contract the host was probed against.
    pub contract: HostContract,
    /// Implied by the envelope; recorded so a reader does not have to know the mapping.
    pub kvm_mode: KvmMode,
    /// What was seen.
    pub observation: Observation,
    /// [`judge`]'s answer when the host signed. [`verify`] recomputes it.
    pub breaches: Vec<Breach>,
    /// Unix seconds.
    pub issued_at: u64,
}

impl ProbeBody {
    /// Judge `observation` against `contract` and record the answer.
    pub fn new(contract: HostContract, observation: Observation, issued_at: u64) -> Self {
        let breaches = judge(&contract, &observation);
        Self {
            kvm_mode: contract.envelope.kvm_mode(),
            contract,
            observation,
            breaches,
            issued_at,
        }
    }
}

/// A probe as it travels: the body's exact bytes and the host's signature over
/// [`PROBE_DOMAIN`] followed by them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedProbe {
    /// Standard base64 of the body's JSON bytes.
    pub body_b64: String,
    /// Standard base64 of the 64-byte Ed25519 signature.
    pub signature_b64: String,
}

/// Sign `body` with the host's key.
pub fn sign(body: &ProbeBody, key: &SigningKey) -> Result<SignedProbe, serde_json::Error> {
    let bytes = serde_json::to_vec(body)?;
    let signature = key.sign(&signed_message(&bytes));
    Ok(SignedProbe {
        body_b64: STANDARD.encode(&bytes),
        signature_b64: STANDARD.encode(signature.to_bytes()),
    })
}

fn signed_message(body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(PROBE_DOMAIN.len().saturating_add(body.len()));
    message.extend_from_slice(PROBE_DOMAIN);
    message.extend_from_slice(body);
    message
}

/// Evidence that a pinned host key signed a probe in which the host met `contract`.
/// Minted only by [`verify`].
#[derive(Debug)]
pub struct ConformingHost {
    envelope: Envelope,
    kvm_mode: KvmMode,
    kernel_release: String,
    issued_at: u64,
}

impl ConformingHost {
    /// The envelope the host declared.
    pub fn envelope(&self) -> Envelope {
        self.envelope
    }
    /// How KVM reaches the hardware there.
    pub fn kvm_mode(&self) -> KvmMode {
        self.kvm_mode
    }
    /// The kernel release the host reported.
    pub fn kernel_release(&self) -> &str {
        &self.kernel_release
    }
    /// When the host signed.
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }
}

/// Why a probe does not show a conforming host.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProbeRefusal {
    /// Not base64, not a signature, or not signed by the pinned key.
    #[error("the probe is not signed by the pinned host key")]
    Signature,
    /// Signed, but not this format, or not its one encoding.
    #[error("the probe body is not a canonical probe record: {0}")]
    Body(String),
    /// Probed against some other contract than the one required.
    #[error("the host was probed against a different contract")]
    OtherContract,
    /// The recorded `kvm_mode` is not the envelope's.
    #[error("the recorded KVM mode does not follow from the envelope")]
    KvmMode,
    /// The recorded breaches are not what the observation implies.
    #[error("the recorded verdict does not follow from the observation")]
    Misjudged,
    /// The host does not meet the contract.
    #[error("the host breaches the contract: {}", .0.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "))]
    Breached(Vec<Breach>),
}

/// Check that `host_key` signed a probe showing a host that meets `required`.
pub fn verify(
    signed: &SignedProbe,
    host_key: &VerifyingKey,
    required: &HostContract,
) -> Result<ConformingHost, ProbeRefusal> {
    let bytes = STANDARD
        .decode(&signed.body_b64)
        .map_err(|_| ProbeRefusal::Signature)?;
    let signature = STANDARD
        .decode(&signed.signature_b64)
        .ok()
        .and_then(|raw| Signature::from_slice(&raw).ok())
        .ok_or(ProbeRefusal::Signature)?;
    host_key
        .verify_strict(&signed_message(&bytes), &signature)
        .map_err(|_| ProbeRefusal::Signature)?;
    let body: ProbeBody =
        serde_json::from_slice(&bytes).map_err(|e| ProbeRefusal::Body(e.to_string()))?;
    let again = serde_json::to_vec(&body).map_err(|e| ProbeRefusal::Body(e.to_string()))?;
    if again != bytes {
        return Err(ProbeRefusal::Body("not the canonical encoding".into()));
    }
    let ProbeBody {
        contract,
        kvm_mode,
        observation,
        breaches,
        issued_at,
    } = body;
    if &contract != required {
        return Err(ProbeRefusal::OtherContract);
    }
    if kvm_mode != contract.envelope.kvm_mode() {
        return Err(ProbeRefusal::KvmMode);
    }
    let rejudged = judge(&contract, &observation);
    if rejudged != breaches {
        return Err(ProbeRefusal::Misjudged);
    }
    if !rejudged.is_empty() {
        return Err(ProbeRefusal::Breached(rejudged));
    }
    Ok(ConformingHost {
        envelope: contract.envelope,
        kvm_mode,
        kernel_release: observation.kernel_release.unwrap_or_default(),
        issued_at,
    })
}

/// Look at this host. I/O; every failure to look is recorded as `None`, never as a pass.
#[cfg(target_os = "linux")]
pub fn observe() -> Observation {
    use nucleus_spec::microvm_host::{JAILER_CHROOT_BASE, SRV_MOUNT};

    let run = |program: &str, arg: &str| {
        std::process::Command::new(program)
            .arg(arg)
            .output()
            .ok()
            .filter(|out| out.status.success())
            .and_then(|out| String::from_utf8(out.stdout).ok())
    };
    Observation {
        architecture: run("uname", "-m").map(|s| s.trim().to_owned()),
        kernel_release: std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .map(|s| s.trim().to_owned()),
        firecracker: run("firecracker", "--version")
            .as_deref()
            .and_then(vmm_version::parse_version)
            .map(|v| v.to_string()),
        kvm: crate::probe::kvm::probe(),
        vhost_vsock: std::path::Path::new("/dev/vhost-vsock").exists(),
        srv_beside_jailer: same_filesystem(
            std::path::Path::new(SRV_MOUNT),
            std::path::Path::new(JAILER_CHROOT_BASE),
        ),
    }
}

/// Whether `a` and `b` are on one filesystem. `b` need not exist yet: it will be created in its
/// nearest existing ancestor, so that ancestor is what is compared. `None` when `a`, or every
/// ancestor of `b`, cannot be read.
#[cfg(unix)]
pub fn same_filesystem(a: &std::path::Path, b: &std::path::Path) -> Option<bool> {
    use std::os::unix::fs::MetadataExt as _;
    let a_dev = std::fs::metadata(a).ok()?.dev();
    let b_dev = b.ancestors().find_map(|p| std::fs::metadata(p).ok())?.dev();
    Some(a_dev == b_dev)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conforming(contract: &HostContract) -> Observation {
        Observation {
            architecture: Some(ARCHITECTURE.into()),
            kernel_release: Some(format!("{}-nucleus", contract.kernel_release)),
            firecracker: Some(vmm_version::PINNED.to_string()),
            kvm: Kvm::Present { api: 12 },
            vhost_vsock: true,
            srv_beside_jailer: Some(true),
        }
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn a_conforming_host_has_no_breach_in_either_envelope() {
        let mac = HostContract::apple_container();
        let metal = HostContract::metal("6.12.40").expect("metal");
        assert!(judge(&mac, &conforming(&mac)).is_empty());
        assert!(judge(&metal, &conforming(&metal)).is_empty());
    }

    /// Non-vacuity: a host that offers nothing breaches every clause, and "could not look"
    /// is a breach, never a pass (ADR 0007 A-1).
    #[test]
    fn a_host_that_could_not_be_observed_breaches_every_clause() {
        let contract = HostContract::apple_container();
        let blind = Observation {
            architecture: None,
            kernel_release: None,
            firecracker: None,
            kvm: Kvm::Absent,
            vhost_vsock: false,
            srv_beside_jailer: None,
        };
        let breaches = judge(&contract, &blind);
        assert_eq!(breaches.len(), 6, "{breaches:?}");
        assert!(breaches.contains(&Breach::SrvUnobserved));
    }

    #[test]
    fn each_clause_is_decided_on_its_own() {
        let contract = HostContract::apple_container();
        let cases: Vec<(Observation, fn(&Breach) -> bool)> = vec![
            (
                Observation {
                    architecture: Some("x86_64".into()),
                    ..conforming(&contract)
                },
                |b| matches!(b, Breach::Architecture { .. }),
            ),
            (
                Observation {
                    kernel_release: Some("6.1.141".into()),
                    ..conforming(&contract)
                },
                |b| matches!(b, Breach::Kernel { .. }),
            ),
            (
                Observation {
                    firecracker: Some("1.16.1".into()),
                    ..conforming(&contract)
                },
                |b| matches!(b, Breach::Firecracker { .. }),
            ),
            (
                Observation {
                    kvm: Kvm::Unusable {
                        reason: "KVM_CREATE_VM failed".into(),
                    },
                    ..conforming(&contract)
                },
                |b| matches!(b, Breach::Kvm { .. }),
            ),
            (
                Observation {
                    vhost_vsock: false,
                    ..conforming(&contract)
                },
                |b| matches!(b, Breach::VhostVsock),
            ),
            (
                Observation {
                    srv_beside_jailer: Some(false),
                    ..conforming(&contract)
                },
                |b| matches!(b, Breach::SrvApartFromJailer),
            ),
        ];
        for (seen, expected) in cases {
            let breaches = judge(&contract, &seen);
            assert_eq!(breaches.len(), 1, "{seen:?} -> {breaches:?}");
            assert!(breaches.iter().all(expected), "{breaches:?}");
        }
    }

    #[test]
    fn a_kernel_release_matches_only_itself_or_a_local_suffix() {
        assert!(kernel_matches("6.18.35", "6.18.35"));
        assert!(kernel_matches("6.18.35", "6.18.35-nucleus"));
        assert!(kernel_matches("6.18.35", "6.18.35+"));
        assert!(!kernel_matches("6.18.35", "6.18.350"));
        assert!(!kernel_matches("6.18.35", "6.18.3"));
        assert!(!kernel_matches("6.18.35", "6.18.34-nucleus"));
    }

    /// The Mac's kernel is the pinned L1 kernel, and metal has no default: a metal contract
    /// with no kernel release is refused rather than accepting any kernel (ADR 0007 B-2).
    #[test]
    fn the_envelope_fixes_the_kernel_and_metal_has_no_default() {
        assert_eq!(
            HostContract::apple_container().kernel_release,
            L1_KERNEL.linux_version
        );
        assert!(HostContract::metal("").is_err());
        assert!(HostContract::metal("   ").is_err());
        assert_eq!(Envelope::AppleContainer.kvm_mode(), KvmMode::Nested);
        assert_eq!(Envelope::Metal.kvm_mode(), KvmMode::Native);
    }

    #[test]
    fn a_signed_conforming_probe_verifies_under_the_pinned_key() {
        let contract = HostContract::metal("6.12.40").expect("metal");
        let body = ProbeBody::new(contract.clone(), conforming(&contract), 1_800_000_000);
        let signed = sign(&body, &key(7)).expect("sign");
        let host = verify(&signed, &key(7).verifying_key(), &contract).expect("conforms");
        assert_eq!(host.envelope(), Envelope::Metal);
        assert_eq!(host.kvm_mode(), KvmMode::Native);
        assert_eq!(host.kernel_release(), "6.12.40-nucleus");
        assert_eq!(host.issued_at(), 1_800_000_000);
    }

    #[test]
    fn a_probe_from_another_key_is_refused() {
        let contract = HostContract::apple_container();
        let body = ProbeBody::new(contract.clone(), conforming(&contract), 1);
        let signed = sign(&body, &key(7)).expect("sign");
        assert_eq!(
            verify(&signed, &key(8).verifying_key(), &contract).unwrap_err(),
            ProbeRefusal::Signature
        );
    }

    #[test]
    fn a_probe_against_another_contract_is_refused() {
        let mac = HostContract::apple_container();
        let body = ProbeBody::new(mac.clone(), conforming(&mac), 1);
        let signed = sign(&body, &key(7)).expect("sign");
        let metal = HostContract::metal(L1_KERNEL.linux_version).expect("metal");
        assert_eq!(
            verify(&signed, &key(7).verifying_key(), &metal).unwrap_err(),
            ProbeRefusal::OtherContract
        );
    }

    /// The signer cannot sign itself fit: the verdict is recomputed from the observation.
    #[test]
    fn a_host_that_signs_itself_fit_is_caught_by_the_rejudgement() {
        let contract = HostContract::apple_container();
        let mut body = ProbeBody::new(
            contract.clone(),
            Observation {
                vhost_vsock: false,
                ..conforming(&contract)
            },
            1,
        );
        assert_eq!(body.breaches, vec![Breach::VhostVsock]);
        body.breaches.clear();
        let signed = sign(&body, &key(7)).expect("sign");
        assert_eq!(
            verify(&signed, &key(7).verifying_key(), &contract).unwrap_err(),
            ProbeRefusal::Misjudged
        );
    }

    #[test]
    fn an_honest_probe_of_an_unfit_host_is_refused_naming_the_breach() {
        let contract = HostContract::apple_container();
        let body = ProbeBody::new(
            contract.clone(),
            Observation {
                srv_beside_jailer: Some(false),
                ..conforming(&contract)
            },
            1,
        );
        let signed = sign(&body, &key(7)).expect("sign");
        match verify(&signed, &key(7).verifying_key(), &contract) {
            Err(ProbeRefusal::Breached(b)) => assert_eq!(b, vec![Breach::SrvApartFromJailer]),
            other => panic!("expected Breached, got {other:?}"),
        }
    }

    #[test]
    fn a_kvm_mode_that_does_not_follow_from_the_envelope_is_refused() {
        let contract = HostContract::apple_container();
        let mut body = ProbeBody::new(contract.clone(), conforming(&contract), 1);
        body.kvm_mode = KvmMode::Native;
        let signed = sign(&body, &key(7)).expect("sign");
        assert_eq!(
            verify(&signed, &key(7).verifying_key(), &contract).unwrap_err(),
            ProbeRefusal::KvmMode
        );
    }

    #[test]
    fn a_body_in_another_encoding_is_refused_even_when_signed() {
        let contract = HostContract::apple_container();
        let body = ProbeBody::new(contract.clone(), conforming(&contract), 1);
        let pretty = serde_json::to_vec_pretty(&body).expect("json");
        let signature = key(7).sign(&signed_message(&pretty));
        let signed = SignedProbe {
            body_b64: STANDARD.encode(&pretty),
            signature_b64: STANDARD.encode(signature.to_bytes()),
        };
        assert!(matches!(
            verify(&signed, &key(7).verifying_key(), &contract),
            Err(ProbeRefusal::Body(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_path_not_yet_created_is_judged_by_its_nearest_ancestor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let later = dir.path().join("jailer/not/yet");
        assert_eq!(same_filesystem(dir.path(), &later), Some(true));
        assert_eq!(
            same_filesystem(&dir.path().join("missing"), dir.path()),
            None,
            "an unreadable first path is not observed"
        );
    }
}

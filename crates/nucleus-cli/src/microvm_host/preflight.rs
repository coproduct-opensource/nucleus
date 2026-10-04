//! Can this Mac host microVMs in a `container`?
//!
//! [`observe`] does the I/O. [`unmet`] is pure and total: given what was
//! observed, it says what is missing, and every decision lives there so it is
//! tested on any machine (the same split as `nucleus-microvm-host::probe`).
//!
//! The in-container probe is authoritative for nested virtualization. The chip
//! and macOS floors can only say it *should* work; `/dev/kvm` answering
//! `KVM_CREATE_VM` inside the running container says it *does*. So
//! [`KvmObservation::NotYetProbed`] is a legitimate state before the container
//! exists, and [`super::lifecycle::ensure_ready`] refuses to mint a host from
//! anything but [`KvmObservation::Usable`].

use std::fmt;
use std::path::Path;

use nucleus_spec::microvm_host::{
    self as pins, CliVersion, MIN_APPLE_CHIP_GENERATION, MIN_CLI_VERSION, MIN_MACOS_MAJOR,
};

use super::container_cli::{ContainerCli, Deadline, Outcome, run_with_deadline};

/// What `container --version` said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliObservation {
    /// Not installed.
    Missing,
    /// Ran, but no version could be read from it (or it did not finish).
    Unreadable { detail: String },
    /// This version.
    Version(CliVersion),
}

/// What `container system status` said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceObservation {
    /// The apiserver reports `running`.
    Running,
    /// It answered, and not with `running` (or the CLI could not ask).
    NotRunning { detail: String },
    /// It did not answer inside the deadline.
    Unresponsive,
}

/// The CPU, from `sysctl -n machdep.cpu.brand_string`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChipObservation {
    /// `Apple M<generation>…`.
    Apple { generation: u32 },
    /// Anything else, including an unreadable brand string.
    Other { brand: String },
}

/// The macOS version, from `sw_vers -productVersion`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacOsObservation {
    Major(u32),
    Unreadable { detail: String },
}

/// What the in-container probe said about `/dev/kvm`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KvmObservation {
    /// No container to probe yet. Not a pass: nothing mints a host from it.
    NotYetProbed,
    /// `nucleus-hostctl probe` exited 0.
    Usable,
    /// It did not, and this is why.
    Unusable { reason: String },
}

/// Everything preflight looks at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub cli: CliObservation,
    pub service: ServiceObservation,
    pub chip: ChipObservation,
    pub macos: MacOsObservation,
    pub kvm: KvmObservation,
}

/// One reason this Mac cannot host microVMs now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unmet {
    CliMissing,
    /// `found: None` means no version could be read, which is not new enough.
    CliTooOld {
        found: Option<CliVersion>,
    },
    ServiceNotRunning {
        detail: String,
    },
    ServiceUnresponsive,
    ChipUnsupported {
        brand: String,
    },
    MacOsTooOld {
        found: Option<u32>,
    },
    NestedVirtUnavailable {
        reason: String,
    },
}

impl fmt::Display for Unmet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CliMissing => write!(
                f,
                "the `container` CLI is not installed; install it (github.com/apple/container) \
                 and run `container system start`"
            ),
            Self::CliTooOld { found: Some(v) } => write!(
                f,
                "`container` {v} is older than {MIN_CLI_VERSION}, the oldest with per-container \
                 --kernel and --virtualization; upgrade it"
            ),
            Self::CliTooOld { found: None } => write!(
                f,
                "could not read a version from `container --version`; need {MIN_CLI_VERSION} or later"
            ),
            Self::ServiceNotRunning { detail } => write!(
                f,
                "the `container` service is not running ({detail}); run `container system start`"
            ),
            Self::ServiceUnresponsive => write!(
                f,
                "the `container` service did not answer within {:?}; another container may have \
                 wedged it. Check `container list --all` and stop what is stuck",
                Deadline::Query.duration()
            ),
            Self::ChipUnsupported { brand } => write!(
                f,
                "nested virtualization needs Apple M{MIN_APPLE_CHIP_GENERATION} or later; this is \
                 {brand:?}"
            ),
            Self::MacOsTooOld { found: Some(m) } => {
                write!(f, "macOS {m} is older than {MIN_MACOS_MAJOR}")
            }
            Self::MacOsTooOld { found: None } => write!(
                f,
                "could not read the macOS version; need {MIN_MACOS_MAJOR} or later"
            ),
            Self::NestedVirtUnavailable { reason } => {
                write!(f, "the host container has no usable /dev/kvm: {reason}")
            }
        }
    }
}

/// What is missing, given what was observed. Pure and total: every
/// observation maps to a verdict, and anything short of a positive
/// observation is unmet (ADR 0007 A-1, B-3).
pub fn unmet(o: &Observed) -> Vec<Unmet> {
    let mut out = Vec::new();
    match &o.cli {
        CliObservation::Missing => out.push(Unmet::CliMissing),
        CliObservation::Unreadable { .. } => out.push(Unmet::CliTooOld { found: None }),
        CliObservation::Version(v) if *v < MIN_CLI_VERSION => {
            out.push(Unmet::CliTooOld { found: Some(*v) })
        }
        CliObservation::Version(_) => {}
    }
    match &o.service {
        ServiceObservation::Running => {}
        ServiceObservation::NotRunning { detail } => out.push(Unmet::ServiceNotRunning {
            detail: detail.clone(),
        }),
        ServiceObservation::Unresponsive => out.push(Unmet::ServiceUnresponsive),
    }
    match &o.chip {
        ChipObservation::Apple { generation } if *generation >= MIN_APPLE_CHIP_GENERATION => {}
        ChipObservation::Apple { generation } => out.push(Unmet::ChipUnsupported {
            brand: format!("Apple M{generation}"),
        }),
        ChipObservation::Other { brand } => out.push(Unmet::ChipUnsupported {
            brand: brand.clone(),
        }),
    }
    match &o.macos {
        MacOsObservation::Major(m) if *m >= MIN_MACOS_MAJOR => {}
        MacOsObservation::Major(m) => out.push(Unmet::MacOsTooOld { found: Some(*m) }),
        MacOsObservation::Unreadable { .. } => out.push(Unmet::MacOsTooOld { found: None }),
    }
    match &o.kvm {
        KvmObservation::NotYetProbed | KvmObservation::Usable => {}
        KvmObservation::Unusable { reason } => out.push(Unmet::NestedVirtUnavailable {
            reason: reason.clone(),
        }),
    }
    out
}

// ── observation ─────────────────────────────────────────────────────

/// Read everything but the in-container probe.
pub fn observe(cli: &ContainerCli) -> Observed {
    Observed {
        cli: cli_from(&cli.version()),
        service: service_from(&cli.system_status()),
        chip: chip_from(&host_fact(
            "/usr/sbin/sysctl",
            &["-n", "machdep.cpu.brand_string"],
        )),
        macos: macos_from(&host_fact("/usr/bin/sw_vers", &["-productVersion"])),
        kvm: KvmObservation::NotYetProbed,
    }
}

fn host_fact(program: &str, args: &[&str]) -> Outcome {
    run_with_deadline(Path::new(program), args, Deadline::Query.duration())
}

pub(super) fn cli_from(out: &Outcome) -> CliObservation {
    match out {
        Outcome::Missing => CliObservation::Missing,
        Outcome::Succeeded { stdout, .. } => match pins::parse_cli_version(stdout) {
            Some(v) => CliObservation::Version(v),
            None => CliObservation::Unreadable {
                detail: stdout.trim().to_string(),
            },
        },
        other => CliObservation::Unreadable {
            detail: other.describe(),
        },
    }
}

/// The `status` field of `container system status --format json`.
#[derive(serde::Deserialize)]
struct SystemStatus {
    status: String,
}

pub(super) fn service_from(out: &Outcome) -> ServiceObservation {
    match out {
        Outcome::TimedOut { .. } => ServiceObservation::Unresponsive,
        Outcome::Succeeded { stdout, .. } => match serde_json::from_str::<SystemStatus>(stdout) {
            Ok(s) if s.status == "running" => ServiceObservation::Running,
            Ok(s) => ServiceObservation::NotRunning { detail: s.status },
            Err(e) => ServiceObservation::NotRunning {
                detail: format!("unreadable status: {e}"),
            },
        },
        other => ServiceObservation::NotRunning {
            detail: format!("`container system status` {}", other.describe()),
        },
    }
}

pub(super) fn chip_from(out: &Outcome) -> ChipObservation {
    let brand = out.stdout().unwrap_or_default().trim().to_string();
    match pins::parse_apple_chip_generation(&brand) {
        Some(generation) => ChipObservation::Apple { generation },
        None if brand.is_empty() => ChipObservation::Other {
            brand: format!("unknown (sysctl {})", out.describe()),
        },
        None => ChipObservation::Other { brand },
    }
}

pub(super) fn macos_from(out: &Outcome) -> MacOsObservation {
    match out.stdout().and_then(pins::parse_macos_major) {
        Some(m) => MacOsObservation::Major(m),
        None => MacOsObservation::Unreadable {
            detail: out.describe(),
        },
    }
}

/// What `nucleus-hostctl probe`'s outcome says about KVM.
pub(super) fn kvm_from(out: &Outcome) -> KvmObservation {
    match out {
        Outcome::Succeeded { .. } => KvmObservation::Usable,
        Outcome::Failed { stdout, stderr, .. } => KvmObservation::Unusable {
            reason: probe_reason(stdout).unwrap_or_else(|| stderr.trim().to_string()),
        },
        other => KvmObservation::Unusable {
            reason: format!("the probe {}", other.describe()),
        },
    }
}

/// The probe prints `{"kvm": {...}, "launch_unmet": [{"what": ...}]}`.
fn probe_reason(stdout: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(stdout).ok()?;
    let mut parts: Vec<String> = v
        .get("launch_unmet")?
        .as_array()?
        .iter()
        .filter_map(|u| u.get("what").and_then(|w| w.as_str()).map(str::to_string))
        .collect();
    // `Kvm` serialises as `{"status": "present" | "absent" | "unusable", "reason"?}`.
    let status = v.pointer("/kvm/status").and_then(|s| s.as_str());
    if status != Some("present") {
        let reason = v.pointer("/kvm/reason").and_then(|r| r.as_str());
        parts.insert(
            0,
            format!(
                "kvm {}{}",
                status.unwrap_or("unreported"),
                reason.map(|r| format!(": {r}")).unwrap_or_default()
            ),
        );
    }
    (!parts.is_empty()).then(|| parts.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_spec::vmm_version::VmmVersion;

    /// This Mac, as the spike measured it: everything met.
    fn good() -> Observed {
        Observed {
            cli: CliObservation::Version(VmmVersion::new(1, 4, 1)),
            service: ServiceObservation::Running,
            chip: ChipObservation::Apple { generation: 5 },
            macos: MacOsObservation::Major(26),
            kvm: KvmObservation::Usable,
        }
    }

    /// One row per rule: a single observation changed from `good()`, and the
    /// one verdict it must produce. Deleting any arm of `unmet` that pushes
    /// reds its row.
    #[test]
    fn each_rule_fires_alone() {
        type Row = (&'static str, fn(&mut Observed), Unmet);
        let rows: &[Row] = &[
            (
                "cli missing",
                |o| o.cli = CliObservation::Missing,
                Unmet::CliMissing,
            ),
            (
                "cli old",
                |o| o.cli = CliObservation::Version(VmmVersion::new(1, 4, 0)),
                Unmet::CliTooOld {
                    found: Some(VmmVersion::new(1, 4, 0)),
                },
            ),
            (
                "cli unreadable",
                |o| o.cli = CliObservation::Unreadable { detail: "?".into() },
                Unmet::CliTooOld { found: None },
            ),
            (
                "service stopped",
                |o| {
                    o.service = ServiceObservation::NotRunning {
                        detail: "stopped".into(),
                    }
                },
                Unmet::ServiceNotRunning {
                    detail: "stopped".into(),
                },
            ),
            (
                "service wedged",
                |o| o.service = ServiceObservation::Unresponsive,
                Unmet::ServiceUnresponsive,
            ),
            (
                "M2",
                |o| o.chip = ChipObservation::Apple { generation: 2 },
                Unmet::ChipUnsupported {
                    brand: "Apple M2".into(),
                },
            ),
            (
                "intel",
                |o| {
                    o.chip = ChipObservation::Other {
                        brand: "Intel".into(),
                    }
                },
                Unmet::ChipUnsupported {
                    brand: "Intel".into(),
                },
            ),
            (
                "macOS 15",
                |o| o.macos = MacOsObservation::Major(15),
                Unmet::MacOsTooOld { found: Some(15) },
            ),
            (
                "macOS unreadable",
                |o| o.macos = MacOsObservation::Unreadable { detail: "?".into() },
                Unmet::MacOsTooOld { found: None },
            ),
            (
                "no kvm",
                |o| {
                    o.kvm = KvmObservation::Unusable {
                        reason: "no /dev/kvm".into(),
                    }
                },
                Unmet::NestedVirtUnavailable {
                    reason: "no /dev/kvm".into(),
                },
            ),
        ];
        assert!(unmet(&good()).is_empty(), "{:?}", unmet(&good()));
        for (name, change, want) in rows {
            let mut o = good();
            change(&mut o);
            assert_eq!(unmet(&o), vec![want.clone()], "row {name}");
        }
        // Every variant has a row, so a new variant cannot ship untested.
        let covered: std::collections::BTreeSet<&str> =
            rows.iter().map(|(_, _, u)| variant(u)).collect();
        for v in [
            Unmet::CliMissing,
            Unmet::CliTooOld { found: None },
            Unmet::ServiceNotRunning {
                detail: String::new(),
            },
            Unmet::ServiceUnresponsive,
            Unmet::ChipUnsupported {
                brand: String::new(),
            },
            Unmet::MacOsTooOld { found: None },
            Unmet::NestedVirtUnavailable {
                reason: String::new(),
            },
        ] {
            assert!(covered.contains(variant(&v)), "no row for {v:?}");
        }
    }

    fn variant(u: &Unmet) -> &'static str {
        match u {
            Unmet::CliMissing => "CliMissing",
            Unmet::CliTooOld { .. } => "CliTooOld",
            Unmet::ServiceNotRunning { .. } => "ServiceNotRunning",
            Unmet::ServiceUnresponsive => "ServiceUnresponsive",
            Unmet::ChipUnsupported { .. } => "ChipUnsupported",
            Unmet::MacOsTooOld { .. } => "MacOsTooOld",
            Unmet::NestedVirtUnavailable { .. } => "NestedVirtUnavailable",
        }
    }

    #[test]
    fn not_yet_probed_is_not_unmet_but_is_not_usable_either() {
        let mut o = good();
        o.kvm = KvmObservation::NotYetProbed;
        assert!(unmet(&o).is_empty());
        assert_ne!(o.kvm, KvmObservation::Usable);
    }

    fn ok(stdout: &str) -> Outcome {
        Outcome::Succeeded {
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    #[test]
    fn observations_are_read_from_real_output() {
        assert_eq!(
            cli_from(&ok(
                "container CLI version 1.4.1 (build: release, commit: unspeci)\n"
            )),
            CliObservation::Version(VmmVersion::new(1, 4, 1))
        );
        assert_eq!(cli_from(&Outcome::Missing), CliObservation::Missing);
        // Captured from this Mac, 2026-09-29, trimmed to the fields read.
        let status = r#"{"client":{"version":"1.4.1"},"status":"running"}"#;
        assert_eq!(service_from(&ok(status)), ServiceObservation::Running);
        assert_eq!(
            service_from(&Outcome::TimedOut {
                after: Deadline::Query.duration()
            }),
            ServiceObservation::Unresponsive
        );
        assert!(matches!(
            service_from(&ok(r#"{"status":"stopped"}"#)),
            ServiceObservation::NotRunning { .. }
        ));
        assert_eq!(
            chip_from(&ok("Apple M5 Pro\n")),
            ChipObservation::Apple { generation: 5 }
        );
        assert!(matches!(
            chip_from(&Outcome::Missing),
            ChipObservation::Other { .. }
        ));
        assert_eq!(macos_from(&ok("26.6.2\n")), MacOsObservation::Major(26));
    }

    #[test]
    fn a_failed_probe_says_why() {
        let report = r#"{"kvm":{"status":"absent"},
                         "launch_unmet":[{"what":"/dev/vhost-vsock","because":"","remedy":""}]}"#;
        let got = kvm_from(&Outcome::Failed {
            code: Some(1),
            stdout: report.into(),
            stderr: String::new(),
        });
        assert!(
            matches!(&got, KvmObservation::Unusable { reason }
                if reason.contains("/dev/vhost-vsock") && reason.contains("kvm absent")),
            "{got:?}"
        );
        assert!(matches!(
            kvm_from(&Outcome::TimedOut {
                after: Deadline::Exec.duration()
            }),
            KvmObservation::Unusable { .. }
        ));
        assert_eq!(kvm_from(&ok("{}")), KvmObservation::Usable);
    }
}

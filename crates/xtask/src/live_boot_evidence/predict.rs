//! Check the reference manifest this build would publish against what booted.
//!
//! The manifest comes from `release_reference::manifest`, the function the
//! release workflow runs, fed this build's node binary packaged the way the
//! release packages it and the upstream Firecracker archive at the pinned
//! version. Its predictions are compared with the binaries the collector
//! measured while the pod ran. A disagreement means a release built from
//! this tree would publish reference values that contest an honest node of
//! its own, and is a hard failure.
//!
//! The prediction mirrors the appraisal's IMA scope (#3276): a release
//! manifest governs its install directory only, so a measured binary outside
//! that scope is neither predicted nor contested. It is listed as not checked
//! beside the verdicts, as the appraisal lists it as not in scope, so it is
//! named and counted, never silently passed.

use std::path::Path;

use anyhow::{Context, Result};
use nucleus_node_evidence::{Expect, ReferenceManifest};
use nucleus_spec::live_boot::{Measured, MeasuredHow};
use serde::Serialize;

use super::verdict::{Check, Verdict};
use crate::release_reference::{self, Arch, EmitArgs};

/// What the manifest declines to check, with its reason, carried into the
/// summary beside the verdicts so a green run does not read as more.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NotChecked {
    pub what: String,
    pub reason: String,
}

/// Generate the manifest from this build: the node binary in `bin_dir`,
/// packaged as `nucleus-node-<version>-<target>.tar.gz` in `work/dist`, and
/// the upstream Firecracker archive fetched to `work`.
pub fn generate(bin_dir: &Path, arch: Arch, work: &Path) -> Result<ReferenceManifest> {
    let version = env!("CARGO_PKG_VERSION");
    let dist = work.join("dist");
    std::fs::create_dir_all(&dist)?;
    let tarball = dist
        .join(nucleus_spec::tier2_artifacts::Tier2Artifact::Node.asset_name(version, arch.name()));
    // As release.yml packages it: the binary alone, at the archive root.
    let gz = flate2::write::GzEncoder::new(
        std::fs::File::create(&tarball)
            .with_context(|| format!("creating {}", tarball.display()))?,
        flate2::Compression::default(),
    );
    let mut tar = tar::Builder::new(gz);
    tar.append_path_with_name(bin_dir.join("nucleus-node"), "nucleus-node")
        .context("packaging nucleus-node")?;
    tar.into_inner()?.finish()?;

    let firecracker_tgz = work.join("firecracker.tgz");
    let config = work.join("firecracker.curl");
    release_reference::run(&release_reference::Args::FetchConfig {
        arch,
        output: firecracker_tgz.clone(),
        out: config.clone(),
    })?;
    let status = std::process::Command::new("curl")
        .args(["-fsSL", "--retry", "3", "--config"])
        .arg(&config)
        .status()
        .context("running curl")?;
    anyhow::ensure!(
        status.success(),
        "fetching the pinned Firecracker archive: {status}"
    );
    release_reference::manifest(&EmitArgs::new(dist, version.into(), arch, firecracker_tgz))
}

/// The manifest's predictions against the measurements, one check per path,
/// plus what the manifest does not check.
pub fn check(manifest: &ReferenceManifest, measured: &[Measured]) -> (Vec<Check>, Vec<NotChecked>) {
    let rv = &manifest.reference_values;
    let mut checks = Vec::new();
    let mut not_checked = Vec::new();
    let mut boot = |what: &'static str, reason: Option<&String>| {
        match reason {
        Some(reason) => not_checked.push(NotChecked {
            what: what.into(),
            reason: reason.clone(),
        }),
        // A release manifest never pins the host's boot; one that does was
        // not produced by this build's generator, and this run cannot appraise it.
        None => checks.push(Check::new(
            format!("prediction.{what}"),
            Verdict::CouldNotRun(format!(
                "the manifest pins {what}; a live boot measures no host boot (use verify-node-evidence on an attested node)"
            )),
        )),
    }
    };
    boot("secure_boot", reason(&rv.secure_boot));
    boot("efi_applications", reason(&rv.efi_applications));
    boot("boot_files", reason(&rv.boot_files));
    boot("kernel_cmdline", reason(&rv.kernel_cmdline));
    if !rv.pcrs.is_empty() {
        checks.push(Check::new(
            "prediction.pcrs",
            Verdict::CouldNotRun("the manifest pins PCRs; a live boot reads none".into()),
        ));
    }
    let ima = match &rv.ima {
        Expect::Required(ima) => ima,
        Expect::NotChecked(reason) => {
            checks.push(Check::new(
                "prediction.ima",
                Verdict::Fail(format!(
                    "a release manifest must pin the node's own binaries, and this one does not: {reason}"
                )),
            ));
            return (checks, not_checked);
        }
    };
    // The generator refuses to write an incoherent reference, and the
    // appraisal reports one as not evaluable; a manifest that reaches here
    // incoherent was not produced by this build's generator.
    if let Some(why) = ima.incoherence() {
        checks.push(Check::new(
            "prediction.ima",
            Verdict::Fail(format!(
                "the manifest's IMA reference could not be appraised: {why}"
            )),
        ));
        return (checks, not_checked);
    }
    for (path, allowed) in &ima.allowlist {
        let name = format!("prediction.{path}");
        let verdict = match measured.iter().find(|m| &m.path == path) {
            None => Verdict::Fail(format!(
                "the manifest names {path} and nothing was measured there{}",
                if ima.required.contains(path) {
                    " (it is required)"
                } else {
                    ""
                }
            )),
            Some(m) if allowed.contains(&m.sha256) => {
                Verdict::Pass(format!("{} {}", m.sha256, how(&m.how)))
            }
            Some(m) => Verdict::Fail(format!(
                "the manifest a release would ship disagrees with what booted: {path} ran {} {}; the manifest allows {}",
                m.sha256,
                how(&m.how),
                allowed.iter().cloned().collect::<Vec<_>>().join(", ")
            )),
        };
        checks.push(Check::new(name, verdict));
    }
    for m in measured {
        if !ima.scope.contains(&m.path) {
            not_checked.push(NotChecked {
                what: format!("prediction.{}", m.path),
                reason: format!(
                    "{} booted ({} {}) outside the manifest's IMA scope: the release vouches for its install directory only",
                    m.path,
                    m.sha256,
                    how(&m.how)
                ),
            });
        } else if !ima.allowlist.contains_key(&m.path) {
            checks.push(Check::new(
                format!("prediction.{}", m.path),
                Verdict::Fail(format!(
                    "{} booted ({} {}) and the manifest a release would ship does not name it",
                    m.path,
                    m.sha256,
                    how(&m.how)
                )),
            ));
        }
    }
    for path in &ima.required {
        if !ima.allowlist.contains_key(path) {
            checks.push(Check::new(
                format!("prediction.{path}"),
                Verdict::Fail(format!("{path} is required and has no allowed digest")),
            ));
        }
    }
    (checks, not_checked)
}

/// The reason a check is not made, or `None` when it is.
fn reason<T>(e: &Expect<T>) -> Option<&String> {
    match e {
        Expect::NotChecked(r) => Some(r),
        Expect::Required(_) => None,
    }
}

fn how(how: &MeasuredHow) -> String {
    match how {
        MeasuredHow::ProcessExe { pid, exe } => format!("(running pid {pid}, {exe})"),
        MeasuredHow::ConfiguredFile => "(the configured file)".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_node_evidence::{ImaReference, ImaScope, REFERENCE_PROFILE, ReferenceValues};
    use std::collections::{BTreeMap, BTreeSet};

    const NODE: &str = "/usr/local/bin/nucleus-node";
    const FC: &str = "/usr/local/bin/firecracker";

    fn manifest(node_digest: &str) -> ReferenceManifest {
        fn nc<T>() -> Expect<T> {
            Expect::NotChecked("no host image".into())
        }
        let one = |d: &str| [d.to_string()].into_iter().collect::<BTreeSet<_>>();
        ReferenceManifest {
            profile: REFERENCE_PROFILE.into(),
            tag_id: "t".into(),
            reference_values: ReferenceValues {
                pcrs: BTreeMap::new(),
                secure_boot: nc(),
                efi_applications: nc(),
                boot_files: nc(),
                kernel_cmdline: nc(),
                ima: Expect::Required(ImaReference {
                    // As `release_reference::manifest` scopes it.
                    scope: ImaScope::PathPrefixes(["/usr/local/bin".to_string()].into()),
                    allowlist: [(NODE.into(), one(node_digest)), (FC.into(), one("fc"))]
                        .into_iter()
                        .collect(),
                    required: one(NODE),
                }),
            },
        }
    }

    fn measured() -> Vec<Measured> {
        vec![
            Measured {
                path: NODE.into(),
                sha256: "node".into(),
                how: MeasuredHow::ProcessExe {
                    pid: 1,
                    exe: NODE.into(),
                },
            },
            Measured {
                path: FC.into(),
                sha256: "fc".into(),
                how: MeasuredHow::ConfiguredFile,
            },
        ]
    }

    fn fails(checks: &[Check]) -> Vec<&str> {
        checks
            .iter()
            .filter(|c| !matches!(c.verdict, Verdict::Pass(_)))
            .map(|c| c.name.as_str())
            .collect()
    }

    #[test]
    fn a_manifest_that_predicts_what_booted_passes_and_lists_what_it_skips() {
        let (checks, not_checked) = check(&manifest("node"), &measured());
        assert_eq!(checks.len(), 2);
        assert!(fails(&checks).is_empty(), "{checks:?}");
        assert_eq!(not_checked.len(), 4);
    }

    /// A-19: a manifest with the wrong node digest is red.
    #[test]
    fn a_wrong_node_digest_is_a_hard_failure() {
        let (checks, _) = check(&manifest("someone-else"), &measured());
        assert_eq!(
            fails(&checks),
            vec!["prediction./usr/local/bin/nucleus-node"]
        );
        let Verdict::Fail(why) = &checks[1].verdict else {
            panic!("{checks:?}")
        };
        assert!(why.contains("disagrees with what booted"), "{why}");
    }

    #[test]
    fn an_unmeasured_path_and_an_unnamed_binary_are_both_red() {
        let mut m = measured();
        m.retain(|m| m.path != FC);
        m.push(Measured {
            path: "/usr/local/bin/jailer".into(),
            sha256: "j".into(),
            how: MeasuredHow::ConfiguredFile,
        });
        let (checks, _) = check(&manifest("node"), &m);
        assert_eq!(
            fails(&checks),
            vec![
                "prediction./usr/local/bin/firecracker",
                "prediction./usr/local/bin/jailer"
            ]
        );
    }

    #[test]
    fn a_manifest_without_ima_or_with_boot_pins_is_not_a_pass() {
        let mut m = manifest("node");
        m.reference_values.ima = Expect::NotChecked("none".into());
        assert!(matches!(
            check(&m, &measured()).0[0].verdict,
            Verdict::Fail(_)
        ));
        let mut m = manifest("node");
        m.reference_values.secure_boot = Expect::Required(true);
        let (checks, _) = check(&m, &measured());
        assert!(
            checks.iter().any(|c| c.name == "prediction.secure_boot"
                && matches!(c.verdict, Verdict::CouldNotRun(_)))
        );
    }

    /// #3276: a binary measured outside the scope is listed, not predicted
    /// and not red; an unnamed binary inside it is still red.
    #[test]
    fn a_binary_outside_the_ima_scope_is_listed_not_contested() {
        let mut m = measured();
        m.push(Measured {
            path: "/opt/elsewhere/helper".into(),
            sha256: "h".into(),
            how: MeasuredHow::ConfiguredFile,
        });
        let (checks, not_checked) = check(&manifest("node"), &m);
        assert!(fails(&checks).is_empty(), "{checks:?}");
        assert!(
            not_checked
                .iter()
                .any(|n| n.what == "prediction./opt/elsewhere/helper"
                    && n.reason.contains("outside the manifest's IMA scope")),
            "{not_checked:?}"
        );
        // The same file under the install directory is unnamed and contests.
        m.last_mut().unwrap().path = "/usr/local/bin/helper".into();
        let (checks, _) = check(&manifest("node"), &m);
        assert_eq!(fails(&checks), vec!["prediction./usr/local/bin/helper"]);
    }

    /// An incoherent IMA reference (an allowlisted path outside its own
    /// scope) is red, never appraised as written.
    #[test]
    fn an_incoherent_ima_reference_is_red() {
        let mut m = manifest("node");
        let Expect::Required(ima) = &mut m.reference_values.ima else {
            unreachable!()
        };
        ima.scope = ImaScope::PathPrefixes(["/opt".to_string()].into());
        let (checks, _) = check(&m, &measured());
        assert_eq!(fails(&checks), vec!["prediction.ima"]);
    }
}

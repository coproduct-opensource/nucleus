//! `cargo xtask node-reference-manifest` — write a node reference manifest
//! (`nucleus-node-reference/v1`) from build outputs.
//!
//! Every digest is computed here from a file, or read from a `sha256sum`
//! listing produced on the machine that holds the files — never copied out of
//! an event log, because a reference taken from the thing it is meant to check
//! checks nothing. A check this command is given no input for is written out
//! as `not_checked` with the reason, so an omitted flag cannot read as a pass
//! (ADR 0007 A-5, B-2).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use nucleus_node_evidence::{
    CmdlineRule, DigestSet, Expect, ImaReference, REFERENCE_PROFILE, ReferenceManifest,
    ReferenceValues,
};
use sha2::{Digest, Sha256};

const NOT_SUPPLIED: &str = "not supplied to the reference generator";

/// Arguments.
#[derive(clap::Args, Debug)]
pub struct Args {
    /// The manifest's `tag-id` (e.g. the release version).
    #[arg(long)]
    tag_id: String,
    /// `required`, `disabled`, or omitted (not checked).
    #[arg(long)]
    secure_boot: Option<String>,
    /// A file the boot loader must load (kernel image): allowed and required.
    #[arg(long)]
    boot_file: Vec<PathBuf>,
    /// A file the boot loader may load (configuration, modules): allowed only.
    #[arg(long)]
    boot_file_allowed: Vec<PathBuf>,
    /// A `sha256sum` listing of boot files the loader may load (allowed only).
    #[arg(long)]
    boot_file_sums: Vec<PathBuf>,
    /// A path in a `--boot-file-sums` listing whose digest is also required.
    #[arg(long)]
    boot_required_path: Vec<String>,
    /// An Authenticode digest (hex) of an EFI application that may load.
    #[arg(long)]
    efi_app_sha256: Vec<String>,
    /// The exact kernel command line.
    #[arg(long, conflicts_with = "cmdline_param")]
    cmdline_exact: Option<String>,
    /// A parameter the kernel command line must contain (repeatable). Does
    /// not notice an ADDED parameter; prefer `--cmdline-exact-params`.
    #[arg(long, conflicts_with = "cmdline_exact_params")]
    cmdline_param: Vec<String>,
    /// The complete set of command-line words, in any order (repeatable).
    #[arg(long, conflicts_with = "cmdline_exact")]
    cmdline_exact_params: Vec<String>,
    /// `LOCAL=INSTALL`: hash LOCAL, allow it at INSTALL in the IMA log.
    #[arg(long)]
    ima_file: Vec<String>,
    /// A `sha256sum` listing (`DIGEST  PATH`) of files IMA may measure.
    #[arg(long)]
    ima_sums: Vec<PathBuf>,
    /// An install path that IMA must have measured (repeatable).
    #[arg(long)]
    ima_required: Vec<String>,
    /// `INDEX=HEX`: pin an exact SHA-256 PCR value.
    #[arg(long)]
    pcr: Vec<String>,
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

fn hex64(s: &str) -> Result<String> {
    let s = s.to_ascii_lowercase();
    if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(s)
    } else {
        Err(anyhow!("{s:?} is not a SHA-256 hex digest"))
    }
}

/// Parse a `sha256sum` listing into (digest, path) pairs.
fn sums(path: &Path) -> Result<Vec<(String, String)>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let (digest, file) = line
            .split_once(char::is_whitespace)
            .ok_or_else(|| anyhow!("{}:{}: not `DIGEST  PATH`", path.display(), n + 1))?;
        let file = file.trim_start().trim_start_matches('*');
        out.push((hex64(digest)?, file.to_string()));
    }
    if out.is_empty() {
        bail!("{} lists no files", path.display());
    }
    Ok(out)
}

/// Build the manifest from the arguments.
pub fn manifest(a: &Args) -> Result<ReferenceManifest> {
    let secure_boot = match a.secure_boot.as_deref() {
        None => Expect::NotChecked(NOT_SUPPLIED.into()),
        Some("required") => Expect::Required(true),
        Some("disabled") => Expect::Required(false),
        Some(other) => bail!("--secure-boot is `required` or `disabled`, not {other:?}"),
    };

    let boot_files = if a.boot_file.is_empty()
        && a.boot_file_allowed.is_empty()
        && a.boot_file_sums.is_empty()
    {
        Expect::NotChecked(NOT_SUPPLIED.into())
    } else {
        let mut set = DigestSet {
            allowed: BTreeSet::new(),
            required: BTreeSet::new(),
        };
        for f in &a.boot_file {
            let d = sha256_file(f)?;
            set.allowed.insert(d.clone());
            set.required.insert(d);
        }
        for f in &a.boot_file_allowed {
            set.allowed.insert(sha256_file(f)?);
        }
        let mut listed: BTreeMap<String, String> = BTreeMap::new();
        for listing in &a.boot_file_sums {
            for (digest, path) in sums(listing)? {
                set.allowed.insert(digest.clone());
                listed.insert(path, digest);
            }
        }
        for path in &a.boot_required_path {
            let digest = listed
                .get(path)
                .ok_or_else(|| anyhow!("--boot-required-path {path} is in no --boot-file-sums"))?;
            set.required.insert(digest.clone());
        }
        Expect::Required(set)
    };

    let efi_applications = if a.efi_app_sha256.is_empty() {
        Expect::NotChecked(NOT_SUPPLIED.into())
    } else {
        let digests = a
            .efi_app_sha256
            .iter()
            .map(|d| hex64(d))
            .collect::<Result<BTreeSet<_>>>()?;
        Expect::Required(DigestSet {
            allowed: digests.clone(),
            required: digests,
        })
    };

    let kernel_cmdline = match (
        &a.cmdline_exact,
        a.cmdline_exact_params.is_empty(),
        a.cmdline_param.is_empty(),
    ) {
        (Some(exact), _, _) => Expect::Required(CmdlineRule::Exact(exact.clone())),
        (None, false, _) => Expect::Required(CmdlineRule::ExactParams(
            a.cmdline_exact_params.iter().cloned().collect(),
        )),
        (None, true, false) => Expect::Required(CmdlineRule::RequiredParams(
            a.cmdline_param.iter().cloned().collect(),
        )),
        (None, true, true) => Expect::NotChecked(NOT_SUPPLIED.into()),
    };

    let ima = if a.ima_file.is_empty() && a.ima_sums.is_empty() {
        if !a.ima_required.is_empty() {
            bail!("--ima-required names files but no --ima-file / --ima-sums allows any");
        }
        Expect::NotChecked(NOT_SUPPLIED.into())
    } else {
        let mut allowlist: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for spec in &a.ima_file {
            let (local, install) = spec
                .split_once('=')
                .ok_or_else(|| anyhow!("--ima-file is LOCAL=INSTALL, got {spec:?}"))?;
            allowlist
                .entry(install.to_string())
                .or_default()
                .insert(sha256_file(Path::new(local))?);
        }
        for listing in &a.ima_sums {
            for (digest, path) in sums(listing)? {
                allowlist.entry(path).or_default().insert(digest);
            }
        }
        for r in &a.ima_required {
            if !allowlist.contains_key(r) {
                bail!("--ima-required {r} is not in the allowlist: it could never be satisfied");
            }
        }
        Expect::Required(ImaReference {
            allowlist,
            required: a.ima_required.iter().cloned().collect(),
        })
    };

    let mut pcrs = BTreeMap::new();
    for spec in &a.pcr {
        let (i, v) = spec
            .split_once('=')
            .ok_or_else(|| anyhow!("--pcr is INDEX=HEX, got {spec:?}"))?;
        let i: u8 = i.parse().with_context(|| format!("PCR index {i:?}"))?;
        if pcrs.insert(i, hex64(v)?).is_some() {
            bail!("PCR {i} pinned twice");
        }
    }

    Ok(ReferenceManifest {
        profile: REFERENCE_PROFILE.into(),
        tag_id: a.tag_id.clone(),
        reference_values: ReferenceValues {
            pcrs,
            secure_boot,
            efi_applications,
            boot_files,
            kernel_cmdline,
            ima,
        },
    })
}

/// Run: print the manifest as JSON.
pub fn run(a: &Args) -> Result<()> {
    let m = manifest(a)?;
    println!("{}", serde_json::to_string_pretty(&m)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Args {
        Args {
            tag_id: "t".into(),
            secure_boot: None,
            boot_file: vec![],
            boot_file_allowed: vec![],
            boot_file_sums: vec![],
            boot_required_path: vec![],
            efi_app_sha256: vec![],
            cmdline_exact: None,
            cmdline_param: vec![],
            cmdline_exact_params: vec![],
            ima_file: vec![],
            ima_sums: vec![],
            ima_required: vec![],
            pcr: vec![],
        }
    }

    #[test]
    fn nothing_supplied_is_all_not_checked_never_a_pass() {
        let m = manifest(&args()).unwrap();
        let rv = m.reference_values;
        assert!(matches!(rv.secure_boot, Expect::NotChecked(_)));
        assert!(matches!(rv.boot_files, Expect::NotChecked(_)));
        assert!(matches!(rv.efi_applications, Expect::NotChecked(_)));
        assert!(matches!(rv.kernel_cmdline, Expect::NotChecked(_)));
        assert!(matches!(rv.ima, Expect::NotChecked(_)));
    }

    #[test]
    fn files_are_hashed_and_required_paths_must_be_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("nucleus-node");
        std::fs::write(&bin, b"binary").unwrap();
        let mut a = args();
        a.ima_file = vec![format!("{}=/opt/nucleus/bin/nucleus-node", bin.display())];
        a.ima_required = vec!["/opt/nucleus/bin/nucleus-node".into()];
        let m = manifest(&a).unwrap();
        let Expect::Required(ima) = m.reference_values.ima else {
            panic!("ima should be required")
        };
        assert_eq!(
            ima.allowlist["/opt/nucleus/bin/nucleus-node"],
            [hex::encode(Sha256::digest(b"binary"))]
                .into_iter()
                .collect()
        );
        a.ima_required = vec!["/opt/nucleus/bin/missing".into()];
        assert!(manifest(&a).is_err());
    }

    #[test]
    fn a_sums_listing_parses_and_rejects_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let ok = dir.path().join("ok.sha256");
        std::fs::write(&ok, format!("{}  /usr/lib/x.ko\n", "ab".repeat(32))).unwrap();
        assert_eq!(sums(&ok).unwrap()[0].1, "/usr/lib/x.ko");
        let bad = dir.path().join("bad.sha256");
        std::fs::write(&bad, "nothex  /x\n").unwrap();
        assert!(sums(&bad).is_err());
        let empty = dir.path().join("empty.sha256");
        std::fs::write(&empty, "\n").unwrap();
        assert!(
            sums(&empty).is_err(),
            "an empty listing allows nothing and is refused"
        );
    }
}

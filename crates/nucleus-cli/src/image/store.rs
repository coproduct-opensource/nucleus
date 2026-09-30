//! Stage two from the CLI, and finding an imported image for `nucleus run --image`.
//!
//! Stage two (`nucleus_microvm_host::image_store::build`) builds an ext4 with the node
//! host's e2fsprogs and files it in the NODE's image store, so it runs where the node runs.
//! On Linux that is this machine and it runs here. Elsewhere the node is inside a VM or
//! container, and the exact `nucleus-hostctl image build` command to run there is printed
//! instead — a guess at how to reach that host would be a second decider for it.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use nucleus_microvm_host::image_store::{self, StoredImport};
use nucleus_spec::{ArtifactDigest, OciDigest, OciReference, OciRootfs};

use super::StagedRootfs;

/// The provisioned node's image store: `<HOST_STATE_DIR>/images`, the node's own
/// default (`--image-root` unset) under the state dir provisioning gives it.
pub fn default_image_root() -> PathBuf {
    Path::new(crate::provision::HOST_STATE_DIR).join(image_store::IMAGES_DIR)
}

/// What stage two did. Two cases, because "filed" and "you must run this" ask the
/// caller for different things (A-1).
#[derive(Debug)]
pub enum StageTwo {
    /// Built and filed in the store on this machine.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Filed(Box<image_store::Stored>),
    /// This machine is not the node host; run this there.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    RunOnNodeHost(String),
}

/// Single-quote `s` for a POSIX shell. The default cache on macOS is under
/// `Application Support`, so an unquoted path would split.
fn quote(s: &Path) -> String {
    format!("'{}'", s.display().to_string().replace('\'', r"'\''"))
}

/// The `nucleus-hostctl` command that runs stage two for `staged`.
pub fn hostctl_command(staged: &StagedRootfs, guest_layer: &Path, image_root: &Path) -> String {
    format!(
        "nucleus-hostctl image build {} --import-record {} --guest-layer {} --image-root {}",
        quote(&staged.tar()),
        quote(&staged.dir.join("import.json")),
        quote(guest_layer),
        quote(image_root)
    )
}

/// Run stage two here on Linux; elsewhere, say what to run on the node host.
pub fn stage_two(staged: &StagedRootfs, guest_layer: &Path, image_root: &Path) -> Result<StageTwo> {
    #[cfg(target_os = "linux")]
    {
        let tar = staged.tar();
        let record = staged.dir.join("import.json");
        let inputs = image_store::BuildInputs {
            rootfs_tar: &tar,
            import_record: &record,
            guest_layer,
            image_root,
        };
        // Called from inside `block_in_place` (see `image::execute`).
        let stored = tokio::runtime::Handle::current()
            .block_on(image_store::build(inputs))
            .map_err(|e| anyhow::anyhow!("stage two: {e}"))?;
        Ok(StageTwo::Filed(Box::new(stored)))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(StageTwo::RunOnNodeHost(hostctl_command(
            staged,
            guest_layer,
            image_root,
        )))
    }
}

/// An image in the store, as a spec names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRootfs {
    pub oci: OciRootfs,
    pub rootfs_digest: ArtifactDigest,
}

/// Every store entry imported from `reference`'s digest (one per guest layer).
fn entries_for(image_root: &Path, reference: &OciReference) -> Result<Vec<StoredRootfs>> {
    let dir = image_root.join("sha256");
    let listing = match std::fs::read_dir(&dir) {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("listing {}", dir.display())),
    };
    let mut found = Vec::new();
    for entry in listing {
        let entry = entry.with_context(|| format!("listing {}", dir.display()))?;
        let name = entry.file_name();
        let Some(hex) = name.to_str() else { continue };
        let Ok(rootfs_digest) = ArtifactDigest::parse(&format!("sha-256:{hex}")) else {
            continue;
        };
        let record_path = entry.path().join(image_store::RECORD_FILE);
        let record: StoredImport =
            image_store::read_record(&record_path).map_err(|e| anyhow::anyhow!("{e}"))?;
        if record.import.pinned.to_string() != reference.digest().as_str() {
            continue;
        }
        let manifest_digest = OciDigest::parse(&record.import.manifest_digest.to_string())
            .map_err(anyhow::Error::msg)?;
        found.push(StoredRootfs {
            oci: OciRootfs {
                reference: reference.clone(),
                manifest_digest,
                guest_layer_digest: record.guest_layer_digest,
            },
            rootfs_digest,
        });
    }
    found.sort_by(|a, b| a.rootfs_digest.as_str().cmp(b.rootfs_digest.as_str()));
    Ok(found)
}

/// The one store entry for `reference`, or `None` when it has not been imported.
///
/// More than one entry means the image was built with more than one guest layer;
/// `guest_layer` (a digest) picks one, and without it the choice is refused rather
/// than made.
pub fn find(
    image_root: &Path,
    reference: &OciReference,
    guest_layer: Option<&ArtifactDigest>,
) -> Result<Option<StoredRootfs>> {
    let mut found = entries_for(image_root, reference)?;
    if let Some(g) = guest_layer {
        found.retain(|f| &f.oci.guest_layer_digest == g);
    }
    match found.len() {
        0 => Ok(None),
        1 => Ok(found.pop()),
        _ => {
            let layers: Vec<&str> = found
                .iter()
                .map(|f| f.oci.guest_layer_digest.as_str())
                .collect();
            bail!(
                "{reference} is in {} under {} guest layers ({}); pass --guest-layer to choose",
                image_root.display(),
                found.len(),
                layers.join(", ")
            )
        }
    }
}

/// sha-256 of a guest layer tar, as a store record names it.
fn guest_layer_digest(path: &Path) -> Result<ArtifactDigest> {
    use sha2::Digest as _;
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    ArtifactDigest::parse(&format!(
        "sha-256:{}",
        hex::encode(sha2::Sha256::digest(bytes))
    ))
    .map_err(anyhow::Error::msg)
}

/// What `nucleus run --image` boots: the store entry for `reference`, imported
/// first (stage one and two) when it is missing and a guest layer is given.
pub fn resolve_for_run(
    reference: &str,
    guest_layer: Option<&Path>,
    image_root: Option<&Path>,
) -> Result<StoredRootfs> {
    let parsed = OciReference::parse(reference).map_err(anyhow::Error::msg)?;
    let root = image_root.map_or_else(default_image_root, Path::to_path_buf);
    let wanted = guest_layer.map(guest_layer_digest).transpose()?;
    if let Some(found) = find(&root, &parsed, wanted.as_ref())? {
        return Ok(found);
    }
    let Some(guest_layer) = guest_layer else {
        bail!(
            "{parsed} is not in the image store {}; import it with `nucleus image import \
             {parsed} --guest-layer <guest-layer.tar> --image-root {}`, or pass --guest-layer \
             to import it now",
            root.display(),
            quote(&root)
        );
    };
    let args = super::ImportArgs {
        reference: parsed.to_string(),
        oci_layout: None,
        oci_archive: None,
        arch: None,
        cache_dir: None,
        guest_layer: Some(guest_layer.to_path_buf()),
        image_root: Some(root.clone()),
        registry: super::RegistryOpts {
            insecure_registry: Vec::new(),
            registry_config: None,
        },
    };
    // The registry client is blocking; see `image::execute`.
    match tokio::task::block_in_place(|| super::import_to_store(&args))? {
        Some(StageTwo::Filed(_)) => find(&root, &parsed, wanted.as_ref())?
            .with_context(|| format!("{parsed} was imported but is not in {}", root.display())),
        Some(StageTwo::RunOnNodeHost(cmd)) => bail!(
            "{parsed} is not in the image store yet and stage two runs on the node host: \
             run `{cmd}` there, then retry"
        ),
        None => bail!("{parsed}: import stopped before stage two"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_with_a_space_or_quote_survives_the_printed_command() {
        assert_eq!(
            quote(Path::new("/Users/a/Library/Application Support/x")),
            "'/Users/a/Library/Application Support/x'"
        );
        assert_eq!(quote(Path::new("/tmp/it's")), r"'/tmp/it'\''s'");
    }

    fn record_json(pinned: &str, guest: &str) -> String {
        let d = |c: &str| format!("sha256:{}", c.repeat(64));
        format!(
            r#"{{"format":"nucleus-image-store/v1",
                "import":{{"crate_version":"t","pinned":"{pinned}","index_digest":null,
                  "manifest_digest":"{m}","config_digest":"{c}",
                  "platform":{{"os":"linux","architecture":"arm64"}},"layers":[],
                  "report":{{"dropped":[],"stripped_setid":[],"stripped_capabilities":[],
                            "dropped_xattrs":[]}},
                  "limits":{limits},
                  "rootfs":{{"digest":"{t}","bytes":1,"entries":1}},
                  "workload":{{"entrypoint":[],"cmd":[],"env":[],"working_dir":null,
                              "user":{{"status":"root","user":""}}}}}},
                "guest_layer_digest":"sha-256:{g}",
                "mke2fs":{{"major":1,"minor":47,"patch":2}},
                "builder_version":"t"}}"#,
            pinned = d(pinned),
            m = d("b"),
            c = d("e"),
            t = d("f"),
            g = guest.repeat(64),
            limits = serde_json::to_string(&nucleus_oci_rootfs::ImportLimits::standard())
                .expect("limits"),
        )
    }

    fn entry(root: &Path, hex: &str, pinned: &str, guest: &str) {
        let dir = root.join("sha256").join(hex.repeat(64));
        std::fs::create_dir_all(&dir).expect("entry");
        std::fs::write(dir.join("import.json"), record_json(pinned, guest)).expect("record");
    }

    #[test]
    fn find_names_the_one_entry_for_a_reference_and_refuses_to_guess_between_two() {
        let t = tempfile::tempdir().expect("tmp");
        let reference =
            OciReference::parse(&format!("registry.example/app@sha256:{}", "a".repeat(64)))
                .expect("reference");
        assert_eq!(find(t.path(), &reference, None).expect("empty"), None);

        entry(t.path(), "1", "a", "c");
        entry(t.path(), "2", "9", "c"); // another image
        let got = find(t.path(), &reference, None)
            .expect("found")
            .expect("one");
        assert_eq!(got.rootfs_digest.hex(), "1".repeat(64));
        assert_eq!(
            got.oci.manifest_digest.as_str(),
            format!("sha256:{}", "b".repeat(64))
        );

        entry(t.path(), "3", "a", "d"); // same image, another guest layer
        let err = find(t.path(), &reference, None).expect_err("two candidates");
        assert!(err.to_string().contains("--guest-layer"), "{err}");
        let d = ArtifactDigest::parse(&format!("sha-256:{}", "d".repeat(64))).expect("digest");
        let got = find(t.path(), &reference, Some(&d))
            .expect("chosen")
            .expect("one");
        assert_eq!(got.rootfs_digest.hex(), "3".repeat(64));
    }
}

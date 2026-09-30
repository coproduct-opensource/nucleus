//! Whole imports: layouts and archives, digests, platforms, config.

mod support;

use std::path::Path;

use nucleus_oci_rootfs::{
    Arch, BlobRole, BlobSource, Compression, ImportError, ImportLimits, Imported, LayoutDir,
    LayoutFile, OciArchive, PinnedReference, Sha256Digest, import,
};
use support::*;

fn pin(digest: &str) -> PinnedReference {
    PinnedReference::parse(&format!("registry.example/app@{digest}")).unwrap()
}

fn run(root: &Path, digest: &str, arch: Arch) -> (Result<Imported, ImportError>, Vec<u8>) {
    run_with(root, digest, arch, ImportLimits::standard())
}

fn run_with(
    root: &Path,
    digest: &str,
    arch: Arch,
    limits: ImportLimits,
) -> (Result<Imported, ImportError>, Vec<u8>) {
    let mut out = Vec::new();
    let r = import(
        &LayoutDir::new(root),
        &pin(digest),
        arch,
        &reserved(),
        limits,
        &mut out,
    );
    (r, out)
}

fn app_layer() -> Vec<u8> {
    layer(&[E::file(b"srv/app/data", b"hello").owner(1000, 1000)])
}

#[test]
fn layout_dir_imports_with_record_and_workload() {
    let dir = tempfile::tempdir().unwrap();
    let w = write_image(
        dir.path(),
        &[
            LayerBlob::gzip(base_layer()),
            LayerBlob::zstd(app_layer()),
            LayerBlob::plain(layer(&[E::file(b"etc/motd", b"hi")])),
        ],
        "app",
    );
    let (r, out) = run(dir.path(), &w.manifest, Arch::Amd64);
    let imported = r.unwrap();
    let rec = &imported.record;
    assert_eq!(rec.manifest_digest.to_string(), w.manifest);
    assert_eq!(rec.config_digest.to_string(), w.config);
    assert_eq!(rec.pinned.to_string(), w.manifest);
    assert_eq!(rec.index_digest, None);
    assert_eq!(
        rec.layers
            .iter()
            .map(|l| l.digest.to_string())
            .collect::<Vec<_>>(),
        w.layers
    );
    assert_eq!(
        rec.layers.iter().map(|l| l.compression).collect::<Vec<_>>(),
        [Compression::Gzip, Compression::Zstd, Compression::None]
    );
    assert_eq!(rec.rootfs.bytes, out.len() as u64);
    assert_eq!(rec.rootfs.digest.to_string(), sha(&out));
    assert_eq!(rec.crate_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(rec.limits, ImportLimits::standard());
    // The record is serde: it round-trips.
    let json = serde_json::to_string(rec).unwrap();
    assert_eq!(
        &serde_json::from_str::<nucleus_oci_rootfs::ImportRecord>(&json).unwrap(),
        rec
    );

    let wl = &imported.workload;
    assert_eq!((wl.uid, wl.gid), (1000, 1000));
    assert_eq!(wl.entrypoint, ["/usr/bin/agent"]);
    assert_eq!(wl.cmd, ["--serve"]);
    assert_eq!(wl.working_dir.as_deref(), Some("/work"));
    assert!(wl.env.iter().any(|e| e == "LLM_API_TOKEN=test-token-123"));

    let entries = read_back(&out);
    assert_eq!(find(&entries, "srv/app/data").unwrap().data, b"hello");
    assert_eq!(find(&entries, "etc/motd").unwrap().data, b"hi");
}

#[test]
fn oci_archive_imports_identically_to_its_directory() {
    let dir = tempfile::tempdir().unwrap();
    let layout = dir.path().join("layout");
    let w = write_image(&layout, &[LayerBlob::gzip(base_layer())], "app:wheel");
    let archive_path = dir.path().join("image.tar");
    archive_of(&layout, &archive_path);

    let (from_dir, dir_out) = run(&layout, &w.manifest, Arch::Amd64);
    let from_dir = from_dir.unwrap();
    let archive = OciArchive::open(&archive_path, &ImportLimits::standard()).unwrap();
    let mut arch_out = Vec::new();
    let from_archive = import(
        &archive,
        &pin(&w.manifest),
        Arch::Amd64,
        &reserved(),
        ImportLimits::standard(),
        &mut arch_out,
    )
    .unwrap();
    assert_eq!(dir_out, arch_out);
    assert_eq!(from_dir.record, from_archive.record);
    assert_eq!(
        (from_archive.workload.uid, from_archive.workload.gid),
        (1000, 10)
    );
}

#[test]
fn legacy_docker_save_is_refused_by_name() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("manifest.json"), b"[]").unwrap();
    std::fs::write(dir.path().join("repositories"), b"{}").unwrap();
    let (r, out) = run(dir.path(), &sha(b"x"), Arch::Amd64);
    assert!(matches!(r, Err(ImportError::LegacyDockerSave)), "{r:?}");
    assert!(out.is_empty());
}

#[test]
fn pinned_digest_absent_from_layout_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    write_image(dir.path(), &[LayerBlob::plain(base_layer())], "app");
    let (r, _) = run(dir.path(), &sha(b"another image"), Arch::Amd64);
    assert!(
        matches!(r, Err(ImportError::ReferenceNotInLayout { .. })),
        "{r:?}"
    );
}

// ── digests ──────────────────────────────────────────────────────────────

#[test]
fn layer_digest_mismatch_is_refused_before_any_layer_is_parsed() {
    let dir = tempfile::tempdir().unwrap();
    // Layer 0 would be refused by the flattener (`..`) if it were ever parsed;
    // layer 1's blob is tampered. The digest refusal must win: no layer is read
    // as a tar until every layer's blob has been verified.
    let w = write_image(
        dir.path(),
        &[
            LayerBlob::plain(layer(&[E::file(b"../escape", b"x")])),
            LayerBlob::plain(app_layer()),
        ],
        "app",
    );
    let path = blob_path(dir.path(), &w.layers[1]);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[600] ^= 0xff; // inside the first entry's data: same length, other content
    std::fs::write(&path, bytes).unwrap();
    let (r, out) = run(dir.path(), &w.manifest, Arch::Amd64);
    assert!(
        matches!(
            r,
            Err(ImportError::BlobDigestMismatch {
                role: BlobRole::Layer,
                ..
            })
        ),
        "{r:?}"
    );
    assert!(out.is_empty());
}

/// Serves the real layout, except that the second and later opens of one blob
/// return other bytes: a file rewritten between verification and parsing.
struct SwapAfterFirstOpen {
    inner: LayoutDir,
    target: LayoutFile,
    swapped: Vec<u8>,
    opens: std::cell::Cell<u32>,
}

impl BlobSource for SwapAfterFirstOpen {
    fn open(&self, file: LayoutFile) -> Result<Option<Box<dyn std::io::Read + '_>>, ImportError> {
        if file == self.target {
            let n = self.opens.get() + 1;
            self.opens.set(n);
            if n >= 2 {
                return Ok(Some(Box::new(std::io::Cursor::new(self.swapped.clone()))));
            }
        }
        self.inner.open(file)
    }
}

#[test]
fn layer_rewritten_between_verification_and_parsing_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let blob = LayerBlob::gzip(app_layer());
    // Change only the gzip header's OS byte: the decompressed bytes (and so the
    // diff_id) are unchanged, so only the second-pass blob digest can see it.
    let mut swapped = blob.blob.clone();
    swapped[9] ^= 0x01;
    let w = write_image(dir.path(), &[blob], "app");
    let source = SwapAfterFirstOpen {
        inner: LayoutDir::new(dir.path()),
        target: LayoutFile::Blob(Sha256Digest::parse(&w.layers[0]).unwrap()),
        swapped,
        opens: std::cell::Cell::new(0),
    };
    let mut out = Vec::new();
    let r = import(
        &source,
        &pin(&w.manifest),
        Arch::Amd64,
        &reserved(),
        ImportLimits::standard(),
        &mut out,
    );
    assert_eq!(source.opens.get(), 2, "verified once, then read once");
    assert!(
        matches!(
            r,
            Err(ImportError::BlobDigestMismatch {
                role: BlobRole::Layer,
                ..
            })
        ),
        "{r:?}"
    );
    assert!(out.is_empty());
}

#[test]
fn layer_size_mismatch_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let w = write_image(dir.path(), &[LayerBlob::plain(app_layer())], "app");
    let path = blob_path(dir.path(), &w.layers[0]);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.extend_from_slice(&[0u8; 512]);
    std::fs::write(&path, bytes).unwrap();
    let (r, _) = run(dir.path(), &w.manifest, Arch::Amd64);
    assert!(
        matches!(
            r,
            Err(ImportError::BlobSizeMismatch {
                role: BlobRole::Layer,
                ..
            })
        ),
        "{r:?}"
    );
}

#[test]
fn manifest_digest_mismatch_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let w = write_image(dir.path(), &[LayerBlob::plain(app_layer())], "app");
    let path = blob_path(dir.path(), &w.manifest);
    let text = std::fs::read_to_string(&path).unwrap();
    let tampered = text.replacen("\"schemaVersion\":2", "\"schemaVersion\":3", 1);
    assert_ne!(text, tampered);
    std::fs::write(&path, tampered).unwrap();
    let (r, _) = run(dir.path(), &w.manifest, Arch::Amd64);
    assert!(
        matches!(
            r,
            Err(ImportError::BlobDigestMismatch {
                role: BlobRole::Manifest,
                ..
            })
        ),
        "{r:?}"
    );
}

#[test]
fn config_digest_mismatch_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let w = write_image(dir.path(), &[LayerBlob::plain(app_layer())], "app");
    let path = blob_path(dir.path(), &w.config);
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, text.replacen("\"app\"", "\"svc\"", 1)).unwrap();
    let (r, _) = run(dir.path(), &w.manifest, Arch::Amd64);
    assert!(
        matches!(
            r,
            Err(ImportError::BlobDigestMismatch {
                role: BlobRole::Config,
                ..
            })
        ),
        "{r:?}"
    );
}

#[test]
fn diff_id_mismatch_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    // A config whose diff_id does not match the layer's uncompressed bytes.
    let blob = LayerBlob::gzip(app_layer());
    let layer_digest = put_blob(dir.path(), &blob.blob);
    let config = config_json("amd64", "1000:1000", &[sha(b"not the layer")]);
    let config_digest = put_blob(dir.path(), &config);
    let manifest = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST,
        "config": { "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": config_digest, "size": config.len() },
        "layers": [{ "mediaType": LAYER_GZIP, "digest": layer_digest, "size": blob.blob.len() }]
    }))
    .unwrap();
    let manifest_digest = put_blob(dir.path(), &manifest);
    write_layout_files(
        dir.path(),
        serde_json::json!([{ "mediaType": MANIFEST, "digest": manifest_digest, "size": manifest.len() }]),
    );
    let (r, _) = run(dir.path(), &manifest_digest, Arch::Amd64);
    assert!(
        matches!(r, Err(ImportError::DiffIdMismatch { layer: 0, .. })),
        "{r:?}"
    );
}

// ── platforms ────────────────────────────────────────────────────────────

#[test]
fn wrong_platform_config_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let w = write_image(dir.path(), &[LayerBlob::plain(app_layer())], "app");
    let (r, _) = run(dir.path(), &w.manifest, Arch::Arm64);
    assert!(
        matches!(&r, Err(ImportError::PlatformMismatch { expected: Arch::Arm64, found }) if found == "linux/amd64"),
        "{r:?}"
    );
}

#[test]
fn index_selects_the_requested_platform_and_refuses_a_missing_one() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let (amd, amd_size) = write_manifest(root, &[LayerBlob::plain(base_layer())], "amd64", "app");
    let (arm, arm_size) = write_manifest(
        root,
        &[
            LayerBlob::plain(base_layer()),
            LayerBlob::plain(app_layer()),
        ],
        "arm64",
        "app",
    );
    let index = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": INDEX,
        "manifests": [
            { "mediaType": MANIFEST, "digest": amd.manifest, "size": amd_size,
              "platform": { "os": "linux", "architecture": "amd64" } },
            { "mediaType": MANIFEST, "digest": arm.manifest, "size": arm_size,
              "platform": { "os": "linux", "architecture": "arm64", "variant": "v8" } },
            { "mediaType": MANIFEST, "digest": amd.manifest, "size": amd_size,
              "platform": { "os": "unknown", "architecture": "unknown" } }
        ]
    }))
    .unwrap();
    let index_digest = put_blob(root, &index);
    write_layout_files(
        root,
        serde_json::json!([{ "mediaType": INDEX, "digest": index_digest, "size": index.len() }]),
    );

    let (r, _) = run(root, &index_digest, Arch::Arm64);
    let rec = r.unwrap().record;
    assert_eq!(
        rec.index_digest.map(|d| d.to_string()),
        Some(index_digest.clone())
    );
    assert_eq!(rec.manifest_digest.to_string(), arm.manifest);
    assert_eq!(rec.layers.len(), 2);

    // A pinned platform manifest inside the index is found too.
    let (r, _) = run(root, &amd.manifest, Arch::Amd64);
    assert_eq!(r.unwrap().record.manifest_digest.to_string(), amd.manifest);

    // An index with only amd64 has nothing for arm64.
    let only_amd = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": INDEX,
        "manifests": [{ "mediaType": MANIFEST, "digest": amd.manifest, "size": amd_size,
                        "platform": { "os": "linux", "architecture": "amd64" } }]
    }))
    .unwrap();
    let only_amd_digest = put_blob(root, &only_amd);
    write_layout_files(
        root,
        serde_json::json!([{ "mediaType": INDEX, "digest": only_amd_digest, "size": only_amd.len() }]),
    );
    let (r, _) = run(root, &only_amd_digest, Arch::Arm64);
    assert!(
        matches!(
            r,
            Err(ImportError::NoManifestForPlatform { arch: Arch::Arm64 })
        ),
        "{r:?}"
    );
}

// ── limits ───────────────────────────────────────────────────────────────

#[test]
fn gzip_decompression_bomb_is_refused_at_the_limit() {
    let dir = tempfile::tempdir().unwrap();
    // 32 MiB of zeros compresses to ~32 KiB.
    let bomb = layer(&[E::file(b"bomb", &vec![0u8; 32 * 1024 * 1024])]);
    let blob = LayerBlob::gzip(bomb);
    assert!(blob.blob.len() < 256 * 1024);
    let w = write_image(dir.path(), &[blob], "app");
    let limits = ImportLimits {
        max_uncompressed_bytes: 1024 * 1024,
        ..ImportLimits::standard()
    };
    let (r, out) = run_with(dir.path(), &w.manifest, Arch::Amd64, limits);
    assert!(
        matches!(
            r,
            Err(ImportError::UncompressedLimitExceeded { limit: 1_048_576 })
        ),
        "{r:?}"
    );
    assert!(out.is_empty());
}

#[test]
fn oversized_metadata_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let w = write_image(dir.path(), &[LayerBlob::plain(app_layer())], "app");
    let limits = ImportLimits {
        max_metadata_bytes: 64,
        ..ImportLimits::standard()
    };
    let (r, _) = run_with(dir.path(), &w.manifest, Arch::Amd64, limits);
    assert!(
        matches!(r, Err(ImportError::MetadataTooLarge { .. })),
        "{r:?}"
    );
}

#[test]
fn reserved_path_in_an_image_is_refused_and_nothing_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let w = write_image(
        dir.path(),
        &[
            LayerBlob::plain(base_layer()),
            LayerBlob::gzip(layer(&[E::file(b"etc/nucleus/pod.yaml", b"evil")])),
        ],
        "app",
    );
    let (r, out) = run(dir.path(), &w.manifest, Arch::Amd64);
    assert!(
        matches!(r, Err(ImportError::ReservedPath { layer: 1, .. })),
        "{r:?}"
    );
    assert!(out.is_empty());
}

// ── config user resolution ──────────────────────────────────────────────

fn user_result(user: &str) -> Result<(u32, u32), ImportError> {
    let dir = tempfile::tempdir().unwrap();
    let w = write_image(dir.path(), &[LayerBlob::plain(base_layer())], user);
    let (r, out) = run(dir.path(), &w.manifest, Arch::Amd64);
    match r {
        Ok(i) => Ok((i.workload.uid, i.workload.gid)),
        Err(e) => {
            assert!(out.is_empty(), "a refused workload still wrote a rootfs");
            Err(e)
        }
    }
}

#[test]
fn config_user_resolution() {
    assert_eq!(user_result("app").unwrap(), (1000, 1000));
    assert_eq!(user_result("svc").unwrap(), (1001, 1002));
    assert_eq!(user_result("1000").unwrap(), (1000, 1000));
    assert_eq!(user_result("1000:10").unwrap(), (1000, 10));
    assert_eq!(user_result("app:wheel").unwrap(), (1000, 10));
    assert_eq!(user_result("4242:4242").unwrap(), (4242, 4242));
}

#[test]
fn root_workload_is_refused() {
    for user in ["", "root", "0", "0:0", "root:app"] {
        let r = user_result(user);
        assert!(
            matches!(r, Err(ImportError::RootWorkload { .. })),
            "{user:?}: {r:?}"
        );
    }
}

#[test]
fn absent_user_or_group_is_refused() {
    assert!(matches!(
        user_result("nobody"),
        Err(ImportError::UserNotFound { .. })
    ));
    assert!(matches!(
        user_result("app:nogroup"),
        Err(ImportError::GroupNotFound { .. })
    ));
    assert!(matches!(
        user_result("4242"),
        Err(ImportError::NumericUserWithoutGroup { uid: 4242 })
    ));
    assert!(matches!(
        user_result("app:"),
        Err(ImportError::MalformedUser { .. })
    ));
}

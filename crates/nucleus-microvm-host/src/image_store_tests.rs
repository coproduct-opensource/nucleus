use super::*;

/// Build a tar from `(path, kind)` entries, each with a small fixed body.
enum E<'a> {
    Dir(&'a str),
    File(&'a str, &'a [u8]),
    Symlink(&'a str, &'a str),
    HardLink(&'a str, &'a str),
}

fn tar_of(dir: &Path, name: &str, entries: &[E<'_>]) -> PathBuf {
    let path = dir.join(name);
    let mut b = tar::Builder::new(File::create(&path).expect("tar"));
    for e in entries {
        let mut h = tar::Header::new_gnu();
        h.set_mtime(0);
        h.set_uid(0);
        h.set_gid(0);
        match e {
            E::Dir(p) => {
                h.set_entry_type(tar::EntryType::Directory);
                h.set_mode(0o755);
                h.set_size(0);
                b.append_data(&mut h, p, io::empty()).expect("dir");
            }
            E::File(p, body) => {
                h.set_entry_type(tar::EntryType::Regular);
                h.set_mode(0o644);
                h.set_size(body.len() as u64);
                b.append_data(&mut h, p, *body).expect("file");
            }
            E::Symlink(p, t) => {
                h.set_entry_type(tar::EntryType::Symlink);
                h.set_mode(0o777);
                h.set_size(0);
                b.append_link(&mut h, p, t).expect("symlink");
            }
            E::HardLink(p, t) => {
                h.set_entry_type(tar::EntryType::Link);
                h.set_mode(0o644);
                h.set_size(0);
                b.append_link(&mut h, p, t).expect("link");
            }
        }
    }
    b.finish().expect("finish");
    path
}

fn names(tar: &[u8]) -> Vec<(String, tar::EntryType)> {
    let mut a = tar::Archive::new(tar);
    a.entries()
        .expect("entries")
        .map(|e| {
            let e = e.expect("entry");
            (
                String::from_utf8(e.path_bytes().into_owned()).expect("utf8"),
                e.header().entry_type(),
            )
        })
        .collect()
}

fn user(dir: &Path) -> PathBuf {
    let long = format!("usr/share/{}", "n".repeat(120));
    tar_of(
        dir,
        "user.tar",
        &[
            E::Dir("etc/"),
            E::File("etc/hostname", b"app\n"),
            E::Dir("usr/"),
            E::Dir("usr/local/"),
            E::Dir("usr/share/"),
            E::File(&long, b"long name\n"),
            E::Symlink("bin", "usr/bin"),
        ],
    )
}

#[test]
fn a_guest_layer_adds_its_paths_and_keeps_the_images_bytes() {
    let t = tempfile::tempdir().expect("tmp");
    let user = user(t.path());
    let guest = tar_of(
        t.path(),
        "guest.tar",
        &[
            E::Dir("./"),
            E::Dir("./etc/"),
            E::Dir("./etc/nucleus/"),
            E::File("./etc/nucleus/ca.pem", b"ca"),
            E::Dir("usr/local/"),
            E::Dir("usr/local/bin/"),
            E::File("usr/local/bin/nucleus-tool-proxy", b"proxy"),
            E::HardLink("usr/local/bin/alias", "usr/local/bin/nucleus-tool-proxy"),
            E::File("init", b"#!init"),
        ],
    );
    let mut merged = Vec::new();
    let o = overlay(&user, &guest, &mut merged).expect("the guest layer only adds");
    assert_eq!(o.added, 6, "{o:?}");
    assert_eq!(o.shared_dirs, 3, "root, etc, usr/local are the image's");

    let user_bytes = std::fs::read(&user).expect("user");
    let user_entries = names(&user_bytes).len();
    let got = names(&merged);
    assert_eq!(got.len(), user_entries + 6);
    // Every user entry first, in order, and the user tar's entry bytes verbatim.
    assert_eq!(got[..user_entries], names(&user_bytes)[..]);
    let end = user_bytes.len() - 1024;
    assert_eq!(&merged[..end], &user_bytes[..end]);
    assert!(
        got.iter()
            .any(|(p, _)| p == "usr/local/bin/nucleus-tool-proxy")
    );
    assert!(merged.ends_with(&[0u8; 1024]));

    // Deterministic: the same inputs give the same bytes.
    let mut again = Vec::new();
    overlay(&user, &guest, &mut again).expect("again");
    assert_eq!(merged, again);
}

#[test]
fn a_guest_file_on_an_image_path_is_refused() {
    let t = tempfile::tempdir().expect("tmp");
    let user = user(t.path());
    let guest = tar_of(
        t.path(),
        "guest.tar",
        &[E::Dir("etc/"), E::File("etc/hostname", b"runtime")],
    );
    let err = overlay(&user, &guest, io::sink()).expect_err("replacing an image file");
    assert!(
        matches!(&err, StoreError::Collision { path, user: "file" } if path == "etc/hostname"),
        "{err}"
    );
}

#[test]
fn a_guest_file_over_an_image_directory_is_refused() {
    let t = tempfile::tempdir().expect("tmp");
    let user = user(t.path());
    let guest = tar_of(t.path(), "guest.tar", &[E::File("usr/local", b"x")]);
    let err = overlay(&user, &guest, io::sink()).expect_err("a file over a dir");
    assert!(
        matches!(
            &err,
            StoreError::Collision {
                user: "directory",
                ..
            }
        ),
        "{err}"
    );
}

/// The image's `bin` is a symlink; a guest file under it would be written wherever it points.
#[test]
fn a_guest_entry_under_an_image_symlink_is_refused() {
    let t = tempfile::tempdir().expect("tmp");
    let user = user(t.path());
    let guest = tar_of(t.path(), "guest.tar", &[E::File("bin/nucleus-init", b"x")]);
    let err = overlay(&user, &guest, io::sink()).expect_err("through a symlink");
    assert!(
        matches!(&err, StoreError::ThroughNonDirectory { ancestor, .. } if ancestor == "bin"),
        "{err}"
    );
}

#[test]
fn a_guest_entry_without_a_parent_or_with_dot_dot_is_refused() {
    let t = tempfile::tempdir().expect("tmp");
    let user = user(t.path());
    let orphan = tar_of(t.path(), "orphan.tar", &[E::File("opt/x/y", b"x")]);
    assert!(matches!(
        overlay(&user, &orphan, io::sink()),
        Err(StoreError::MissingParent { .. })
    ));
    // A hard link to an image file would alias the image's bytes under a runtime name.
    let alias = tar_of(
        t.path(),
        "alias.tar",
        &[E::HardLink("etc/runtime-hostname", "etc/hostname")],
    );
    assert!(matches!(
        overlay(&user, &alias, io::sink()),
        Err(StoreError::Unsupported { .. })
    ));
}

fn record(manifest: &str) -> StoredImport {
    let json = format!(
        r#"{{"format":"nucleus-image-store/v1",
            "import":{import},
            "guest_layer_digest":"sha-256:{g}",
            "mke2fs":{{"major":1,"minor":47,"patch":2}},
            "builder_version":"test"}}"#,
        import = import_json(manifest),
        g = "c".repeat(64),
    );
    serde_json::from_str(&json).expect("a store record parses")
}

fn import_json(manifest: &str) -> String {
    let d = |c: &str| format!("sha256:{}", c.repeat(64));
    format!(
        r#"{{"crate_version":"0.0.0-test","pinned":"{pinned}","index_digest":null,
            "manifest_digest":"sha256:{manifest}","config_digest":"{cfg}",
            "platform":{{"os":"linux","architecture":"arm64"}},"layers":[],
            "report":{{"dropped":[],"stripped_setid":[],"stripped_capabilities":[],
                      "dropped_xattrs":[]}},
            "limits":{limits},
            "rootfs":{{"digest":"{tar}","bytes":10,"entries":1}},
            "workload":{workload}}}"#,
        pinned = d("a"),
        cfg = d("e"),
        tar = d("f"),
        limits =
            serde_json::to_string(&nucleus_oci_rootfs::ImportLimits::standard()).expect("limits"),
        workload = WORKLOAD,
    )
}

/// A minimal `WorkloadConfig`, as the flattener serializes one.
const WORKLOAD: &str =
    r#"{"entrypoint":[],"cmd":[],"env":[],"working_dir":null,"user":{"status":"root","user":""}}"#;

fn oci(reference: &str, manifest: &str, guest: &str) -> OciRootfs {
    serde_json::from_str(&format!(
        r#"{{"reference":"registry.example/app@sha256:{}",
            "manifest_digest":"sha256:{}","guest_layer_digest":"sha-256:{}"}}"#,
        reference.repeat(64),
        manifest.repeat(64),
        guest.repeat(64)
    ))
    .expect("oci")
}

#[test]
fn a_record_matches_only_the_image_it_describes() {
    let r = record(&"b".repeat(64));
    r.check(&oci("a", "b", "c")).expect("the same image");
    for (spec, field) in [
        (oci("d", "b", "c"), OciField::ReferenceDigest),
        (oci("a", "d", "c"), OciField::ManifestDigest),
        (oci("a", "b", "d"), OciField::GuestLayerDigest),
    ] {
        let err = r.check(&spec).expect_err("another image");
        assert_eq!(err.field, field, "{err}");
    }
    assert_eq!(r.importer_version(), "0.0.0-test");
}

#[test]
fn a_record_round_trips_and_refuses_unknown_fields() {
    let r = record(&"b".repeat(64));
    let json = serde_json::to_string(&r).expect("serializes");
    assert_eq!(
        serde_json::from_str::<StoredImport>(&json).expect("parses"),
        r
    );
    let extra = json.replacen('{', r#"{"rootfs_digest":"sha-256:00","#, 1);
    assert!(serde_json::from_str::<StoredImport>(&extra).is_err());
}

#[test]
fn the_rootfs_path_is_derived_from_the_digest_alone() {
    let d = ArtifactDigest::parse(&format!("sha-256:{}", "9".repeat(64))).expect("digest");
    assert_eq!(
        rootfs_path(Path::new("/images"), &d),
        Path::new("/images/sha256")
            .join("9".repeat(64))
            .join("rootfs.ext4")
    );
}

/// Stage two end to end, on a host whose mke2fs can read a tar.
#[tokio::test]
async fn stage_two_files_a_deterministic_image_under_its_digest() {
    if !crate::ext4::tests::tar_capable() {
        return;
    }
    let t = tempfile::tempdir().expect("tmp");
    let user = user(t.path());
    let hex = hex::encode(hash_file(&user).expect("hash"));
    let rec = t.path().join("import.json");
    std::fs::write(
        &rec,
        import_json(&"b".repeat(64)).replace(
            &format!("sha256:{}", "f".repeat(64)),
            &format!("sha256:{hex}"),
        ),
    )
    .expect("record");
    let guest = tar_of(
        t.path(),
        "guest.tar",
        &[
            E::Dir("etc/"),
            E::Dir("etc/nucleus/"),
            E::File("etc/nucleus/x", b"x"),
        ],
    );
    let build_into = |root: PathBuf| {
        let (user, rec, guest) = (user.clone(), rec.clone(), guest.clone());
        async move {
            build(BuildInputs {
                rootfs_tar: &user,
                import_record: &rec,
                guest_layer: &guest,
                image_root: &root,
            })
            .await
        }
    };
    let a = build_into(t.path().join("a")).await.expect("stage two");
    let b = build_into(t.path().join("b"))
        .await
        .expect("stage two again");
    assert_eq!(a.rootfs_digest, b.rootfs_digest, "deterministic");
    assert!(!a.reused);
    assert_eq!(a.dir, entry_dir(&t.path().join("a"), &a.rootfs_digest));
    let stored = read_record(&a.dir.join(RECORD_FILE)).expect("record");
    assert_eq!(stored, a.record);
    let again = build_into(t.path().join("a")).await.expect("idempotent");
    assert!(again.reused);

    // A tar that is not the one its record names is refused before anything is built.
    std::fs::write(&user, b"not the tar").expect("tamper");
    let err = build_into(t.path().join("c"))
        .await
        .expect_err("tampered tar");
    assert!(matches!(err, StoreError::TarMismatch { .. }), "{err}");
}

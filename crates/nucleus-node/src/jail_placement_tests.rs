use super::*;
use std::os::unix::fs::PermissionsExt;

const JAIL: JailUser = JailUser { uid: 123, gid: 100 };

/// POSIX picks exactly one class. An owner is judged by the owner bits alone, and can always
/// modify (it can `chmod`); a group member by the group bits; everyone else by the other bits.
#[test]
fn jail_access_selects_exactly_one_permission_class() {
    let cases = [
        // (owner, group, mode) -> (read, modify)
        ((123, 0, 0o444), (true, true)), // owner: read-only bits, still modifiable
        ((123, 0, 0o044), (false, true)), // owner bits win over group/other
        ((0, 100, 0o040), (true, false)),
        ((0, 100, 0o064), (true, true)),
        ((0, 100, 0o404), (false, false)), // group bits win over other
        ((0, 0, 0o444), (true, false)),
        ((0, 0, 0o600), (false, false)),
        ((0, 0, 0o666), (true, true)),
    ];
    for ((owner, group, mode), (read, modify)) in cases {
        assert_eq!(
            jail_access(owner, group, mode, JAIL),
            JailAccess { read, modify },
            "owner {owner} group {group} mode {mode:o}"
        );
    }
}

/// The one decision per role: only the caller's scratch disk is written through.
#[test]
fn only_the_callers_scratch_is_written_through() {
    for role in [
        ArtifactRole::Kernel,
        ArtifactRole::Rootfs,
        ArtifactRole::Data,
        ArtifactRole::SeccompFilter,
        ArtifactRole::CallerScratch,
    ] {
        let expected = if role == ArtifactRole::CallerScratch {
            Placement::GuestWritesThrough
        } else {
            Placement::SharedReadOnly
        };
        assert_eq!(role.placement(), expected, "{role:?}");
    }
    // An eval cell's disks are copies the node owns, never links (ADR 0013 rule 7).
    assert_eq!(
        ArtifactRole::EvalCellScratch.placement(),
        Placement::NodeCopyGuestWrites
    );
    assert_eq!(
        ArtifactRole::EvalCellData.placement(),
        Placement::NodeCopyReadOnly
    );
}

fn file_with_mode(dir: &Path, name: &str, mode: u32) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, b"x").expect("write");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).expect("chmod");
    p
}

/// A jail user that does not own what this test creates, whoever runs it.
fn foreign(dir: &Path) -> (JailUser, JailUser) {
    let probe = file_with_mode(dir, ".probe", 0o600);
    let m = std::fs::metadata(&probe).expect("meta");
    let me = JailUser {
        uid: m.uid(),
        gid: m.gid(),
    };
    let other = JailUser {
        uid: me.uid.wrapping_add(1),
        gid: me.gid.wrapping_add(1),
    };
    (me, other)
}

#[test]
fn a_shared_artifact_must_be_readable_and_not_modifiable_by_the_jail_user() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (me, other) = foreign(tmp.path());

    let ok = file_with_mode(tmp.path(), "ok", 0o444);
    assert_eq!(admit(&ok, "k", Placement::SharedReadOnly, other), Ok(()));

    let unreadable = file_with_mode(tmp.path(), "unreadable", 0o600);
    assert!(matches!(
        admit(&unreadable, "k", Placement::SharedReadOnly, other),
        Err(Refusal::JailCannotRead(_))
    ));

    let world_writable = file_with_mode(tmp.path(), "ww", 0o666);
    assert!(matches!(
        admit(&world_writable, "k", Placement::SharedReadOnly, other),
        Err(Refusal::JailCanModifyShared(_))
    ));

    // The state the bug left installed artifacts in: owned by the jail user.
    let owned = file_with_mode(tmp.path(), "owned", 0o444);
    let refusal = admit(
        &owned,
        "installed guest kernel",
        Placement::SharedReadOnly,
        me,
    )
    .expect_err("a shared artifact the jail user owns must be refused");
    assert!(matches!(refusal, Refusal::JailCanModifyShared(_)));
    let msg = refusal.to_string();
    assert!(
        msg.contains("installed guest kernel") && msg.contains("owned") && msg.contains("0444"),
        "the refusal names the artifact and the remedy: {msg}"
    );
}

#[test]
fn a_written_through_disk_must_already_be_writable_by_the_jail_user() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (me, other) = foreign(tmp.path());
    let disk = file_with_mode(tmp.path(), "scratch", 0o600);

    assert_eq!(admit(&disk, "s", Placement::GuestWritesThrough, me), Ok(()));
    let refusal = admit(
        &disk,
        "image.scratch_path",
        Placement::GuestWritesThrough,
        other,
    )
    .expect_err("a disk the jail user cannot write must be refused, not chowned");
    assert!(matches!(refusal, Refusal::JailCannotWrite(_)));
    assert!(refusal.to_string().contains("image.scratch_path"));
}

/// A-2: could not look is a refusal, and so is the wrong shape.
#[test]
fn what_cannot_be_inspected_or_is_not_a_file_is_refused() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (_, other) = foreign(tmp.path());
    assert!(matches!(
        admit(
            &tmp.path().join("absent"),
            "k",
            Placement::SharedReadOnly,
            other
        ),
        Err(Refusal::CannotInspect { .. })
    ));
    assert!(matches!(
        admit(tmp.path(), "k", Placement::SharedReadOnly, other),
        Err(Refusal::NotAFile { .. })
    ));
}

/// Node startup: an absent artifact is not checked (A-5: the count says so), a readable
/// root-owned one passes, and an unreadable one is refused by its installed name.
#[test]
fn startup_refuses_an_installed_artifact_the_jail_user_cannot_read() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (_, other) = foreign(tmp.path());
    let root = tmp.path().join("artifacts");
    std::fs::create_dir_all(&root).expect("root");

    assert_eq!(check_installed_artifacts(&root, other), Ok(0));

    let kernel = nucleus_spec::tier2_artifacts::GUEST_KERNEL_FILE;
    let rootfs = nucleus_spec::tier2_artifacts::GUEST_ROOTFS_FILE;
    file_with_mode(&root, kernel, 0o444);
    file_with_mode(&root, rootfs, 0o444);
    assert_eq!(check_installed_artifacts(&root, other), Ok(2));

    // What `ADD <url>` in a Containerfile lays down, and what the jailer could only open
    // because the node used to chown it.
    std::fs::set_permissions(root.join(kernel), std::fs::Permissions::from_mode(0o600))
        .expect("chmod");
    let refusal =
        check_installed_artifacts(&root, other).expect_err("an unreadable kernel must refuse");
    let msg = refusal.to_string();
    assert!(
        msg.contains("installed guest kernel") && msg.contains(kernel),
        "the refusal names the artifact: {msg}"
    );
}

/// A file born in the jail is created fresh: a symlink or hard link left at its path is
/// unlinked, never followed, and what it pointed at keeps its bytes and its owner.
#[test]
fn born_in_jail_replaces_a_planted_link_rather_than_following_it() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (me, _) = foreign(tmp.path());
    let victim = tmp.path().join("victim");
    std::fs::write(&victim, b"untouched").expect("victim");

    let via_symlink = tmp.path().join("config.json");
    std::os::unix::fs::symlink(&victim, &via_symlink).expect("plant");
    let mut born = BornInJail::create(&via_symlink).expect("create");
    born.write_all(b"new").expect("write");
    born.give_to_jail(me).expect("give");

    let via_link = tmp.path().join("firecracker.log");
    std::fs::hard_link(&victim, &via_link).expect("plant");
    BornInJail::create(&via_link)
        .expect("create")
        .give_to_jail(me)
        .expect("give");

    assert_eq!(std::fs::read(&victim).expect("read"), b"untouched");
    assert_eq!(std::fs::metadata(&victim).expect("meta").nlink(), 1);
    assert_eq!(std::fs::read(&via_symlink).expect("read"), b"new");
    assert!(
        !std::fs::symlink_metadata(&via_symlink)
            .expect("meta")
            .file_type()
            .is_symlink()
    );
}

/// The hand-over refuses an inode that has a second name: that is the only way a chown through
/// the fd could reach a file that exists elsewhere.
#[test]
fn born_in_jail_is_given_away_only_while_it_has_one_name() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (me, _) = foreign(tmp.path());
    let path = tmp.path().join("config.json");
    let born = BornInJail::create(&path).expect("create");
    std::fs::hard_link(&path, tmp.path().join("alias")).expect("alias");
    let err = born
        .give_to_jail(me)
        .expect_err("a second link must refuse the hand-over");
    assert!(err.contains("2 links"), "{err}");
}

/// A shared artifact placed by hard link is the same inode, unchanged in owner and mode.
#[test]
fn placing_a_shared_artifact_links_it_and_changes_nothing() {
    let tmp = tempfile::tempdir().expect("tmp");
    let (_, other) = foreign(tmp.path());
    let src = file_with_mode(tmp.path(), "vmlinux", 0o444);
    let before = std::fs::metadata(&src).expect("meta");
    let dest = tmp.path().join("kernel");
    let resource = JailResource {
        host_source: src.clone(),
        role: ArtifactRole::Kernel,
    };
    place(&resource, &dest, other).expect("place");
    let after = std::fs::metadata(&src).expect("meta");
    assert_eq!(
        std::fs::metadata(&dest).expect("dest").ino(),
        before.ino(),
        "same filesystem: a hard link"
    );
    assert_eq!(
        (after.uid(), after.gid(), after.mode()),
        (before.uid(), before.gid(), before.mode())
    );
}

/// A cross-device copy is the node's own read-only inode, never a writable one.
#[test]
fn a_shared_copy_is_read_only() {
    let tmp = tempfile::tempdir().expect("tmp");
    let src = file_with_mode(tmp.path(), "rootfs.ext4", 0o644);
    let dest = tmp.path().join("copy");
    copy_read_only(&src, &dest).expect("copy");
    assert_eq!(
        std::fs::metadata(&dest).expect("meta").mode() & 0o7777,
        0o444
    );
    assert_eq!(std::fs::read(&dest).expect("read"), b"x");
}

/// The disk `nucleus-hostctl seed` produces is exactly what a pod names as `image.scratch_path`,
/// and the node no longer chowns a placed file (#3152). So a seeded disk must leave seed ALREADY
/// admissible as [`Placement::GuestWritesThrough`], judged here by the node's own [`admit`]
/// rather than by a second statement of the rule.
///
/// Non-vacuous only as root: an unprivileged run can hand a file only to itself, and a file the
/// runner owns is the runner's to write whatever seed did. Root judges it as the default jail
/// user, which owns nothing root creates.
#[tokio::test]
async fn a_seeded_workspace_disk_is_admitted_as_written_through() {
    use nucleus_microvm_host::ext4::{Ext4Error, RootOwner};

    let tmp = tempfile::tempdir().expect("tmp");
    let (me, _) = foreign(tmp.path());
    let who = if me.uid == 0 { JAIL } else { me };
    let tree = tmp.path().join("tree");
    std::fs::create_dir_all(tree.join("src")).expect("tree");
    std::fs::write(tree.join("src/lib.rs"), b"pub fn f() {}\n").expect("file");
    let image = tmp.path().join("ws.ext4");
    let workload = RootOwner {
        uid: 65534,
        gid: 65534,
    };
    match nucleus_microvm_host::workspace::seed(&tree, &image, workload, who, 16).await {
        Ok(_) => {}
        Err(Ext4Error::Unsupported { .. })
            if std::env::var_os("NUCLEUS_E2FSPROGS_REQUIRED").is_none() =>
        {
            eprintln!("skipping: this host's mke2fs cannot seed from a tar");
            return;
        }
        Err(e) => panic!("seed: {e}"),
    }
    assert_eq!(
        admit(
            &image,
            "image.scratch_path",
            Placement::GuestWritesThrough,
            who
        ),
        Ok(()),
        "a freshly seeded disk must already be the jail user's to read and write"
    );
}

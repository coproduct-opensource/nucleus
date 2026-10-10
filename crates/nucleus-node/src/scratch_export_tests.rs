//! The export round trip: the node's disk reaches the caller's file at exit, the record carries
//! the digest of what was exported, and the export never writes through a link.

use super::*;

fn spec(eval_cell: bool, scratch: Option<&Path>) -> PodSpec {
    let mut spec: PodSpec = serde_json::from_str(
        r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"work_dir":"/work","image":{
            "kernel_path":"/k","rootfs_path":"/r"}}}"#,
    )
    .expect("spec");
    spec.spec.image.as_mut().expect("image").scratch_path = scratch.map(Path::to_path_buf);
    if eval_cell {
        IsolationProfile::EvalCell.label(&mut spec);
    }
    spec
}

#[test]
fn only_an_eval_cells_caller_scratch_is_owed_an_export() {
    let p = Path::new("/srv/caller/scratch.ext4");
    assert_eq!(target(&spec(true, Some(p))), Some(p.to_path_buf()));
    assert_eq!(target(&spec(false, Some(p))), None, "a standard pod links");
    assert_eq!(
        target(&spec(true, None)),
        None,
        "a node-made disk is not the caller's"
    );
}

#[tokio::test]
async fn the_guests_disk_reaches_the_callers_file_and_the_receipt_names_its_digest() {
    use std::os::unix::fs::MetadataExt as _;
    let tmp = tempfile::tempdir().expect("tmp");
    let disk = tmp.path().join("in-jail-scratch");
    std::fs::write(&disk, b"what the guest wrote, longer than before").expect("disk");
    let caller = tmp.path().join("caller.ext4");
    std::fs::write(
        &caller,
        b"what the caller seeded, and then some trailing bytes",
    )
    .expect("caller");
    let inode = std::fs::metadata(&caller).expect("meta").ino();
    let pod_dir = tmp.path().join("pod");
    std::fs::create_dir(&pod_dir).expect("pod dir");
    let s = spec(true, Some(&caller));

    assert!(
        recorded(&s, &pod_dir).starts_with("not exported"),
        "owed and not yet done is never empty"
    );
    export_and_record(&disk, &caller, &pod_dir).await;

    assert_eq!(
        std::fs::read(&caller).expect("exported"),
        std::fs::read(&disk).expect("disk"),
        "the caller's file holds exactly the guest's disk, with no trailing bytes left"
    );
    assert_eq!(
        std::fs::metadata(&caller).expect("meta").ino(),
        inode,
        "the caller's inode"
    );
    let digest = nucleus_identity::attestation::measure_artifact(&caller)
        .await
        .expect("measure");
    assert_eq!(
        recorded(&s, &pod_dir),
        format!("sha-256:{}", hex::encode(digest))
    );
    assert_eq!(
        recorded(&spec(false, Some(&caller)), &pod_dir),
        "",
        "nothing owed"
    );
}

#[tokio::test]
async fn the_export_never_writes_through_a_symlink_or_creates_a_file() {
    let tmp = tempfile::tempdir().expect("tmp");
    let disk = tmp.path().join("disk");
    std::fs::write(&disk, b"guest bytes").expect("disk");
    let elsewhere = tmp.path().join("elsewhere");
    std::fs::write(&elsewhere, b"not the caller's disk").expect("elsewhere");
    let link = tmp.path().join("caller.ext4");
    std::os::unix::fs::symlink(&elsewhere, &link).expect("symlink");

    export(&disk, &link)
        .await
        .expect_err("a symlink is refused");
    assert_eq!(
        std::fs::read(&elsewhere).expect("read"),
        b"not the caller's disk"
    );
    export(&disk, &tmp.path().join("absent"))
        .await
        .expect_err("a missing file is not created");
    assert!(!tmp.path().join("absent").exists());
}

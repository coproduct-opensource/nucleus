//! The reserved table an import actually applies, derived from
//! `nucleus_spec::guest_layout` (#3216), driven through the flattener with
//! layers built in-test.

use nucleus_oci_rootfs::{
    DroppedKind, Flattened, Flattener, ImportError, ImportLimits, RecordedPath,
};
use nucleus_spec::guest_layout::{self, GuestBinary, ReservedKind};

use super::reserved_guest_paths;

#[derive(Clone, Copy)]
enum Kind<'a> {
    Dir,
    File(&'a [u8]),
    Symlink(&'a str),
}

fn layer(entries: &[(&str, Kind<'_>)]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (path, kind) in entries {
        let mut h = tar::Header::new_ustar();
        h.set_path(path).unwrap();
        h.set_uid(0);
        h.set_gid(0);
        h.set_mtime(1_700_000_000);
        let body: &[u8] = match kind {
            Kind::Dir => {
                h.set_entry_type(tar::EntryType::Directory);
                h.set_mode(0o755);
                &[]
            }
            Kind::File(data) => {
                h.set_entry_type(tar::EntryType::Regular);
                h.set_mode(0o644);
                data
            }
            Kind::Symlink(target) => {
                h.set_entry_type(tar::EntryType::Symlink);
                h.set_mode(0o777);
                h.set_link_name(target).unwrap();
                &[]
            }
        };
        h.set_size(body.len() as u64);
        h.set_cksum();
        b.append(&h, body).unwrap();
    }
    b.into_inner().unwrap()
}

fn flatten(layers: &[Vec<u8>]) -> Result<Flattened, ImportError> {
    let reserved = reserved_guest_paths().unwrap();
    let mut f = Flattener::new(&reserved, ImportLimits::standard());
    for l in layers {
        f.apply_layer(l.as_slice())?;
    }
    f.finish()
}

fn dropped(f: &Flattened) -> Vec<(String, DroppedKind)> {
    f.report()
        .dropped
        .iter()
        .map(|d| match &d.path {
            RecordedPath::Utf8(s) => (s.clone(), d.kind),
            RecordedPath::Bytes { bytes_hex } => (bytes_hex.clone(), d.kind),
        })
        .collect()
}

/// A debian-style base: `/run/lock`, `/var/run -> /run`, a `/tmp` and a `/dev`.
fn debian_base() -> Vec<u8> {
    layer(&[
        ("bin", Kind::Dir),
        ("bin/sh", Kind::File(b"#!sh")),
        ("dev", Kind::Dir),
        ("etc", Kind::Dir),
        ("etc/passwd", Kind::File(b"root:x:0:0::/root:/bin/sh\n")),
        ("run", Kind::Dir),
        ("run/lock", Kind::Dir),
        ("run/lock/stale.pid", Kind::File(b"42")),
        ("tmp", Kind::Dir),
        ("var", Kind::Dir),
        ("var/run", Kind::Symlink("/run")),
    ])
}

#[test]
fn an_image_shipping_a_nucleus_prefixed_binary_is_refused() {
    for binary in [
        GuestBinary::Mcp,
        GuestBinary::EgressHttp,
        GuestBinary::NetProbe,
    ] {
        let path = binary.path().trim_start_matches('/');
        let err = flatten(&[layer(&[
            ("usr", Kind::Dir),
            ("usr/local", Kind::Dir),
            ("usr/local/bin", Kind::Dir),
            (path, Kind::File(b"impostor")),
        ])])
        .err();
        assert!(
            matches!(&err, Some(ImportError::ReservedPath { path: p, reserved, .. })
                if p == path && reserved == "usr/local/bin/nucleus-"),
            "{path}: {err:?}"
        );
    }
    // A name the prefix has never heard of is claimed too.
    let err = flatten(&[layer(&[(
        "usr/local/bin/nucleus-not-yet-written",
        Kind::File(b"x"),
    )])])
    .err();
    assert!(
        matches!(err, Some(ImportError::ReservedPath { .. })),
        "{err:?}"
    );
}

#[test]
fn run_lock_from_debian_layers_is_dropped_and_reported() {
    let f = flatten(&[debian_base()]).expect("a debian-style base must import");
    assert_eq!(f.regular_file("run/lock/stale.pid"), None);
    assert_eq!(f.regular_file("bin/sh"), Some(&b"#!sh"[..]));
    let dropped = dropped(&f);
    assert!(
        dropped.contains(&("run/lock".into(), DroppedKind::InsideMustBeEmptyDir)),
        "{dropped:?}"
    );
    assert!(
        dropped.contains(&(
            "run/lock/stale.pid".into(),
            DroppedKind::InsideMustBeEmptyDir
        )),
        "{dropped:?}"
    );
}

#[test]
fn a_whiteout_under_a_must_be_empty_dir_is_dropped_and_reported() {
    let upper = layer(&[
        ("run/lock/.wh.stale.pid", Kind::File(b"")),
        ("tmp/.wh..wh..opq", Kind::File(b"")),
        ("bin/.wh.sh", Kind::File(b"")),
    ]);
    let f = flatten(&[debian_base(), upper]).expect("whiteouts in /run must not refuse");
    let dropped = dropped(&f);
    assert!(
        dropped.contains(&(
            "run/lock/.wh.stale.pid".into(),
            DroppedKind::WhiteoutInsideMustBeEmptyDir
        )),
        "{dropped:?}"
    );
    // An opaque marker on the directory itself clears nothing reserved: applied, not reported.
    assert!(
        !dropped.iter().any(|(p, _)| p == "tmp/.wh..wh..opq"),
        "{dropped:?}"
    );
    // An ordinary whiteout still applies.
    assert_eq!(f.regular_file("bin/sh"), None);
}

#[test]
fn a_symlink_in_place_of_a_must_be_empty_dir_is_refused() {
    let err = flatten(&[layer(&[("run", Kind::Symlink("/var/lib/evil"))])]).err();
    assert!(
        matches!(&err, Some(ImportError::ReservedAncestorNotDirectory { path, .. }) if path == "run"),
        "{err:?}"
    );
}

#[test]
fn the_removed_guest_net_script_is_no_longer_reserved() {
    let f = flatten(&[layer(&[(
        "usr/local/bin/guest-net.sh",
        Kind::File(b"#!/bin/sh\n"),
    )])])
    .expect("guest-net.sh is no longer a guest path");
    assert_eq!(
        f.regular_file("usr/local/bin/guest-net.sh"),
        Some(&b"#!/bin/sh\n"[..])
    );
}

#[test]
fn every_guest_layout_entry_is_enforced_by_the_import() {
    // Each RESERVED entry, probed at a path it claims: a refusal or a drop, never kept.
    for r in guest_layout::RESERVED {
        let rel = r.path.trim_start_matches('/');
        let probe = match r.kind {
            ReservedKind::Exact => rel.to_string(),
            ReservedKind::Prefix | ReservedKind::MustBeEmptyDir => format!("{rel}probe"),
        };
        match flatten(&[layer(&[(probe.as_str(), Kind::File(b"x"))])]) {
            Err(ImportError::ReservedPath { .. }) => {}
            Ok(f) => assert!(
                f.regular_file(&probe).is_none()
                    && dropped(&f).contains(&(probe.clone(), DroppedKind::InsideMustBeEmptyDir)),
                "{} ({probe}) kept",
                r.path
            ),
            Err(other) => panic!("{} ({probe}): {other:?}", r.path),
        }
    }
}

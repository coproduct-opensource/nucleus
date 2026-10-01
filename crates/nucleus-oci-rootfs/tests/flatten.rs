//! Layer semantics and refusals, one tar stream at a time.

mod support;

use nucleus_oci_rootfs::{DroppedKind, ImportError, ImportLimits, RecordedPath, StrippedSetId};
use support::*;
use tar::EntryType;

fn refused(layers: &[Vec<u8>]) -> ImportError {
    flatten(layers).expect_err("the layers were accepted")
}

// ── path refusals ────────────────────────────────────────────────────────

#[test]
fn dotdot_prefix_is_refused() {
    let e = refused(&[layer(&[E::file(b"../etc/passwd", b"x")])]);
    assert!(
        matches!(e, ImportError::DotDotComponent { layer: 0, .. }),
        "{e:?}"
    );
}

#[test]
fn dotdot_that_climbs_out_midway_is_refused() {
    let e = refused(&[layer(&[E::file(b"a/../../x", b"x")])]);
    assert!(matches!(e, ImportError::DotDotComponent { .. }), "{e:?}");
}

#[test]
fn absolute_path_is_normalized_not_refused() {
    let f = flatten(&[layer(&[E::file(b"/etc//hosts", b"127.0.0.1 localhost\n")])]).unwrap();
    let out = read_back(&emit(f));
    assert_eq!(names(&out), ["etc/", "etc/hosts"]);
}

#[test]
fn nul_in_path_is_refused() {
    let e = refused(&[layer(&[
        E::file(b"placeholder", b"x").pax(b"path", b"etc/pass\0wd")
    ])]);
    assert!(matches!(e, ImportError::PathHasNul { .. }), "{e:?}");
}

#[test]
fn overlong_path_is_refused() {
    let limits = ImportLimits {
        max_path_bytes: 16,
        ..ImportLimits::standard()
    };
    let e = flatten_with(
        &[layer(&[E::file(b"a/very/long/path/indeed", b"")])],
        &reserved(),
        limits,
    )
    .unwrap_err();
    assert!(
        matches!(e, ImportError::PathTooLong { len: 23, .. }),
        "{e:?}"
    );
}

#[test]
fn too_many_entries_is_refused() {
    let limits = ImportLimits {
        max_entries: 2,
        ..ImportLimits::standard()
    };
    let e = flatten_with(
        &[layer(&[
            E::file(b"a", b""),
            E::file(b"b", b""),
            E::file(b"c", b""),
        ])],
        &reserved(),
        limits,
    )
    .unwrap_err();
    assert!(
        matches!(e, ImportError::TooManyEntries { limit: 2 }),
        "{e:?}"
    );
}

#[test]
fn byte_budget_is_refused_as_a_limit_not_a_corrupt_tar() {
    let limits = ImportLimits {
        max_uncompressed_bytes: 64 * 1024,
        ..ImportLimits::standard()
    };
    let big = vec![0u8; 256 * 1024];
    let e = flatten_with(&[layer(&[E::file(b"zeros", &big)])], &reserved(), limits).unwrap_err();
    assert!(
        matches!(e, ImportError::UncompressedLimitExceeded { limit: 65536 }),
        "{e:?}"
    );
}

// ── hardlinks ────────────────────────────────────────────────────────────

#[test]
fn hardlink_to_absent_target_is_refused() {
    let e = refused(&[layer(&[E::hardlink(b"x", b"/etc/shadow")])]);
    assert!(
        matches!(e, ImportError::HardlinkTargetMissing { .. }),
        "{e:?}"
    );
}

#[test]
fn hardlink_climbing_out_is_refused() {
    let e = refused(&[layer(&[E::hardlink(b"x", b"../x")])]);
    assert!(matches!(e, ImportError::DotDotComponent { .. }), "{e:?}");
}

#[test]
fn hardlink_to_directory_is_refused() {
    let e = refused(&[layer(&[E::dir(b"d"), E::hardlink(b"x", b"d")])]);
    assert!(
        matches!(e, ImportError::HardlinkTargetNotRegular { .. }),
        "{e:?}"
    );
}

#[test]
fn hardlinks_share_content_and_emit_primary_first() {
    let f = flatten(&[layer(&[
        E::file(b"z/orig", b"payload").owner(7, 8).mode(0o640),
        E::hardlink(b"a/link", b"z/orig"),
    ])])
    .unwrap();
    let out = read_back(&emit(f));
    // `a/link` sorts first, so it carries the content and `z/orig` links to it.
    let primary = find(&out, "a/link").unwrap();
    assert_eq!(primary.kind, EntryType::Regular);
    assert_eq!(primary.data, b"payload");
    assert_eq!((primary.uid, primary.gid, primary.mode), (7, 8, 0o640));
    let second = find(&out, "z/orig").unwrap();
    assert_eq!(second.kind, EntryType::Link);
    assert_eq!(second.link.as_deref(), Some(&b"a/link"[..]));
}

#[test]
fn hardlink_survives_whiteout_of_its_target_as_a_copy() {
    let f = flatten(&[
        layer(&[
            E::file(b"bin/busybox", b"BB"),
            E::hardlink(b"bin/sh", b"bin/busybox"),
        ]),
        layer(&[E::whiteout(b"bin/.wh.busybox")]),
    ])
    .unwrap();
    let out = read_back(&emit(f));
    assert_eq!(names(&out), ["bin/", "bin/sh"]);
    let sh = find(&out, "bin/sh").unwrap();
    assert_eq!(sh.kind, EntryType::Regular);
    assert_eq!(sh.data, b"BB");
}

#[test]
fn overwriting_a_link_target_does_not_change_the_link() {
    let f = flatten(&[
        layer(&[E::file(b"a", b"old"), E::hardlink(b"b", b"a")]),
        layer(&[E::file(b"a", b"new")]),
    ])
    .unwrap();
    let out = read_back(&emit(f));
    assert_eq!(find(&out, "a").unwrap().data, b"new");
    assert_eq!(find(&out, "b").unwrap().data, b"old");
    assert_eq!(find(&out, "b").unwrap().kind, EntryType::Regular);
}

// ── symlinks and reserved ancestors ──────────────────────────────────────

#[test]
fn symlink_over_reserved_ancestor_is_refused() {
    let e = refused(&[layer(&[
        E::dir(b"usr"),
        E::dir(b"usr/local"),
        E::symlink(b"usr/local/bin", b"/tmp"),
    ])]);
    assert!(
        matches!(&e, ImportError::ReservedAncestorNotDirectory { path, .. } if path == "usr/local/bin"),
        "{e:?}"
    );
}

#[test]
fn symlink_at_reserved_prefix_dir_is_refused() {
    let e = refused(&[layer(&[
        E::dir(b"etc"),
        E::symlink(b"etc/nucleus", b"/tmp"),
    ])]);
    assert!(
        matches!(&e, ImportError::ReservedAncestorNotDirectory { path, .. } if path == "etc/nucleus"),
        "{e:?}"
    );
}

#[test]
fn merged_usr_symlinks_and_absolute_targets_are_kept_verbatim() {
    let f = flatten(&[layer(&[
        E::symlink(b"bin", b"usr/bin"),
        E::dir(b"usr"),
        E::dir(b"usr/bin"),
        E::symlink(b"usr/bin/sh", b"/bin/busybox"),
        E::symlink(b"etc/localtime", b"/usr/share/zoneinfo/UTC"),
    ])])
    .unwrap();
    let out = read_back(&emit(f));
    assert_eq!(
        find(&out, "bin").unwrap().link.as_deref(),
        Some(&b"usr/bin"[..])
    );
    assert_eq!(
        find(&out, "usr/bin/sh").unwrap().link.as_deref(),
        Some(&b"/bin/busybox"[..])
    );
    assert_eq!(
        find(&out, "etc/localtime").unwrap().link.as_deref(),
        Some(&b"/usr/share/zoneinfo/UTC"[..])
    );
}

#[test]
fn entry_beneath_a_symlink_is_refused() {
    let e = refused(&[
        layer(&[E::symlink(b"lib", b"/")]),
        layer(&[E::file(b"lib/evil", b"x")]),
    ]);
    assert!(
        matches!(e, ImportError::AncestorNotDirectory { layer: 1, .. }),
        "{e:?}"
    );
}

// ── reserved paths ───────────────────────────────────────────────────────

#[test]
fn user_pod_yaml_is_refused() {
    let e = refused(&[layer(&[E::file(b"etc/nucleus/pod.yaml", b"evil: true")])]);
    assert!(
        matches!(&e, ImportError::ReservedPath { path, .. } if path == "etc/nucleus/pod.yaml"),
        "{e:?}"
    );
}

#[test]
fn user_tool_proxy_is_refused() {
    let e = refused(&[layer(&[E::file(b"usr/local/bin/nucleus-tool-proxy", b"x")])]);
    assert!(matches!(e, ImportError::ReservedPath { .. }), "{e:?}");
}

#[test]
fn reserved_prefix_directory_itself_is_allowed() {
    let f = flatten(&[layer(&[E::dir(b"etc"), E::dir(b"etc/nucleus")])]).unwrap();
    assert_eq!(names(&read_back(&emit(f))), ["etc/", "etc/nucleus/"]);
}

#[test]
fn whiteout_of_reserved_path_is_refused() {
    let e = refused(&[layer(&[E::whiteout(b".wh.init")])]);
    assert!(
        matches!(&e, ImportError::WhiteoutOverReserved { path, reserved, .. } if path == "init" && reserved == "init"),
        "{e:?}"
    );
}

#[test]
fn opaque_over_reserved_ancestor_is_refused() {
    let e = refused(&[layer(&[E::whiteout(b"etc/.wh..wh..opq")])]);
    assert!(
        matches!(&e, ImportError::WhiteoutOverReserved { path, .. } if path == "etc"),
        "{e:?}"
    );
}

#[test]
fn malformed_whiteouts_are_refused() {
    for name in [&b"a/.wh."[..], b"a/.wh..wh.x", b".wh.d/file"] {
        let e = refused(&[layer(&[E::whiteout(name)])]);
        assert!(
            matches!(e, ImportError::InvalidWhiteout { .. }),
            "{name:?}: {e:?}"
        );
    }
}

// ── whiteouts and opaque directories across three layers ────────────────

#[test]
fn whiteout_and_opaque_semantics_across_three_layers() {
    let l0 = layer(&[
        E::dir(b"app"),
        E::file(b"app/a", b"0a"),
        E::file(b"app/b", b"0b"),
        E::dir(b"app/sub"),
        E::file(b"app/sub/deep", b"0d"),
        E::dir(b"cache"),
        E::file(b"cache/1", b"c1"),
        E::file(b"cache/2", b"c2"),
        E::file(b"keep", b"k"),
    ]);
    let l1 = layer(&[
        // Removes app/sub and everything under it from layer 0.
        E::whiteout(b"app/.wh.sub"),
        // Opaque: clears cache's lower children, keeps this layer's own.
        E::dir(b"cache"),
        E::whiteout(b"cache/.wh..wh..opq"),
        E::file(b"cache/3", b"c3"),
        E::file(b"app/b", b"1b"),
    ]);
    let l2 = layer(&[
        // A whiteout never hides an entry of its own layer.
        E::file(b"app/c", b"2c"),
        E::whiteout(b"app/.wh.c"),
        E::whiteout(b"app/.wh.a"),
        // Re-create a whited-out directory: no lower children come back.
        E::dir(b"app/sub"),
    ]);
    let f = flatten(&[l0, l1, l2]).unwrap();
    let out = read_back(&emit(f));
    assert_eq!(
        names(&out),
        [
            "app/", "app/b", "app/c", "app/sub/", "cache/", "cache/3", "keep"
        ]
    );
    assert_eq!(find(&out, "app/b").unwrap().data, b"1b");
    assert!(names(&out).iter().all(|n| !n.contains(".wh.")));
}

#[test]
fn file_replaces_directory_and_its_subtree() {
    let f = flatten(&[
        layer(&[E::dir(b"x"), E::file(b"x/child", b"c")]),
        layer(&[E::file(b"x", b"now a file")]),
    ])
    .unwrap();
    assert_eq!(names(&read_back(&emit(f))), ["x"]);
}

// ── special files, modes, xattrs, ownership ─────────────────────────────

#[test]
fn devices_are_dropped_and_reported_fifos_kept() {
    let f = flatten(&[layer(&[
        E::dir(b"dev"),
        E::char_dev(b"dev/null"),
        E::block_dev(b"dev/sda"),
        E::fifo(b"run.pipe"),
    ])])
    .unwrap();
    let dropped: Vec<_> = f
        .report()
        .dropped
        .iter()
        .map(|d| (d.path.clone(), d.kind))
        .collect();
    assert_eq!(
        dropped,
        [
            (
                RecordedPath::Utf8("dev/null".into()),
                DroppedKind::CharDevice
            ),
            (
                RecordedPath::Utf8("dev/sda".into()),
                DroppedKind::BlockDevice
            ),
        ]
    );
    let out = read_back(&emit(f));
    assert_eq!(names(&out), ["dev/", "run.pipe"]);
    assert_eq!(find(&out, "run.pipe").unwrap().kind, EntryType::Fifo);
}

#[test]
fn device_replaces_what_was_below_it() {
    let f = flatten(&[
        layer(&[E::file(b"node", b"lower")]),
        layer(&[E::char_dev(b"node")]),
    ])
    .unwrap();
    assert!(names(&read_back(&emit(f))).is_empty());
}

#[test]
fn setuid_and_setgid_are_stripped_and_recorded() {
    let f = flatten(&[layer(&[
        E::file(b"usr/bin/su", b"su").mode(0o4755),
        E::file(b"usr/bin/wall", b"wall").mode(0o2755),
        E::dir(b"tmp").mode(0o1777),
    ])])
    .unwrap();
    assert_eq!(
        f.report().stripped_setid,
        [
            StrippedSetId {
                layer: 0,
                path: RecordedPath::Utf8("usr/bin/su".into()),
                bits: 0o4000
            },
            StrippedSetId {
                layer: 0,
                path: RecordedPath::Utf8("usr/bin/wall".into()),
                bits: 0o2000
            },
        ]
    );
    let out = read_back(&emit(f));
    assert_eq!(find(&out, "usr/bin/su").unwrap().mode, 0o755);
    assert_eq!(find(&out, "usr/bin/wall").unwrap().mode, 0o755);
    assert_eq!(
        find(&out, "tmp/").unwrap().mode,
        0o1777,
        "sticky bit is kept"
    );
}

#[test]
fn capability_xattr_is_stripped_and_recorded() {
    let f = flatten(&[layer(&[E::file(b"usr/bin/ping", b"ping")
        .pax(b"SCHILY.xattr.security.capability", b"\x01\x00\x00\x02")
        .pax(b"SCHILY.xattr.user.note", b"hi")])])
    .unwrap();
    let caps: Vec<_> = f
        .report()
        .stripped_capabilities
        .iter()
        .map(|x| (x.path.clone(), x.name.clone()))
        .collect();
    assert_eq!(
        caps,
        [(
            RecordedPath::Utf8("usr/bin/ping".into()),
            RecordedPath::Utf8("security.capability".into())
        )]
    );
    assert_eq!(f.report().dropped_xattrs.len(), 1);
    // `read_back` asserts every emitted entry is free of pax records.
    let out = read_back(&emit(f));
    assert_eq!(find(&out, "usr/bin/ping").unwrap().data, b"ping");
}

#[test]
fn uid_and_gid_are_preserved_and_names_dropped() {
    let f = flatten(&[layer(&[
        E::file(b"home/app/file", b"x").owner(1000, 1000),
        E::file(b"root-owned", b"y").owner(0, 0),
        E::file(b"big-id", b"z").owner(4_000_000_000, 70_000),
    ])])
    .unwrap();
    let out = read_back(&emit(f));
    let app = find(&out, "home/app/file").unwrap();
    assert_eq!((app.uid, app.gid), (1000, 1000));
    let root = find(&out, "root-owned").unwrap();
    assert_eq!((root.uid, root.gid), (0, 0));
    let big = find(&out, "big-id").unwrap();
    assert_eq!((big.uid, big.gid), (4_000_000_000, 70_000));
    assert!(out.iter().all(|o| o.uname.is_empty() && o.mtime == 0));
}

#[test]
fn non_utf8_names_round_trip_as_bytes() {
    let f = flatten(&[layer(&[E::file(b"data/\xff\xfe.bin", b"x")])]).unwrap();
    let out = read_back(&emit(f));
    assert!(out.iter().any(|o| o.name == b"data/\xff\xfe.bin"));
}

#[test]
fn long_names_and_link_targets_survive() {
    let deep = format!("{}/file", "d".repeat(150));
    let target = format!("/{}", "t".repeat(180));
    let f = flatten(&[layer(&[
        E::file(b"placeholder", b"x").pax(b"path", deep.as_bytes()),
        E::symlink(b"sl", b"placeholder").pax(b"linkpath", target.as_bytes()),
    ])])
    .unwrap();
    let out = read_back(&emit(f));
    assert_eq!(find(&out, &deep).unwrap().data, b"x");
    assert_eq!(
        find(&out, "sl").unwrap().link.as_deref(),
        Some(target.as_bytes())
    );
}

// ── determinism ──────────────────────────────────────────────────────────

#[test]
fn flattening_twice_is_byte_identical() {
    let layers = [base_layer(), layer(&[E::file(b"etc/motd", b"hello")])];
    let a = emit(flatten(&layers).unwrap());
    let b = emit(flatten(&layers).unwrap());
    assert_eq!(a, b);
}

#[test]
fn layer_order_and_header_noise_do_not_change_the_tar() {
    let x = layer(&[
        E::dir(b"opt").noise(1, b"alice"),
        E::file(b"opt/x", b"x").noise(111, b"alice"),
    ]);
    let y = layer(&[
        E::dir(b"srv").noise(2, b"bob"),
        E::file(b"srv/y", b"y")
            .noise(222, b"bob")
            .pax(b"atime", b"12345.6"),
    ]);
    // The same content spelled differently: leading `/` and `./`, a trailing
    // `/`, other mtimes and user names, pax time records, and the directory
    // declared after its child rather than before.
    let x_noisy = layer(&[
        E::file(b"./opt/x", b"x")
            .noise(999_999, b"mallory")
            .pax(b"mtime", b"1.5"),
        E::dir(b"/opt/").noise(3, b"eve"),
    ]);
    let y_noisy = layer(&[
        E::dir(b"./srv/").noise(0, b""),
        E::file(b"srv//y", b"y").noise(0, b"").pax(b"ctime", b"7"),
    ]);
    let a = emit(flatten(&[x.clone(), y.clone()]).unwrap());
    let b = emit(flatten(&[y, x]).unwrap());
    let c = emit(flatten(&[y_noisy, x_noisy]).unwrap());
    assert_eq!(a, b, "layer order changed the tar");
    assert_eq!(a, c, "header noise changed the tar");
    assert_eq!(names(&read_back(&a)), ["opt/", "opt/x", "srv/", "srv/y"]);
}

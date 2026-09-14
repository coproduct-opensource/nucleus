//! Unit tests for the token walk, from fixtures rather than from whatever this
//! workspace happens to contain today — the same split
//! [`crate::closure::from_metadata`] makes and for the same reason.

use super::*;

fn ws(dirs: &[(&str, &str)], closure: &[&str]) -> Workspace {
    let mut w = Workspace::default();
    for (name, dir) in dirs {
        w.dirs.insert((*name).to_string(), (*dir).to_string());
    }
    w.closures.insert(
        "a".to_string(),
        closure.iter().map(|s| (*s).to_string()).collect(),
    );
    w
}

/// Write `files` into a tempdir and scan crate `a`.
fn scan_fixture(files: &[(&str, &str)], dirs: &[(&str, &str)], closure: &[&str]) -> Scan {
    let root = tempfile::tempdir().expect("tempdir");
    let mut tracked: Vec<String> = Vec::new();
    for (path, body) in files {
        let full = root.path().join(path);
        std::fs::create_dir_all(full.parent().expect("parent")).expect("mkdir");
        std::fs::write(&full, body).expect("write");
        tracked.push((*path).to_string());
    }
    // Every fixture file is tracked here; the untracked case builds its tree
    // by hand in `an_untracked_target_is_distinguished_from_a_tracked_one`,
    // because "on disk but not in `git ls-files`" is the whole point of it.
    scan(&ws(dirs, closure), root.path(), &tracked, "a").expect("scan")
}

#[test]
fn a_read_beside_its_reader_is_covered() {
    let s = scan_fixture(
        &[
            (
                "crates/a/src/lib.rs",
                r#"const X: &str = include_str!("t.txt");"#,
            ),
            ("crates/a/src/t.txt", "hello"),
        ],
        &[("a", "crates/a")],
        &["a"],
    );
    assert_eq!(s.sites_examined, 1);
    assert!(s.is_clean(), "{s:?}");
}

#[test]
fn a_read_into_a_closure_member_is_covered() {
    let s = scan_fixture(
        &[
            (
                "crates/a/src/lib.rs",
                r#"const X: &str = include_str!("../../b/data/v.json");"#,
            ),
            ("crates/b/data/v.json", "{}"),
        ],
        &[("a", "crates/a"), ("b", "crates/b")],
        &["a", "b"],
    );
    assert!(s.is_clean(), "a dependency's tree is in the closure: {s:?}");
}

#[test]
fn a_read_outside_the_closure_escapes_and_says_it_is_tracked() {
    let s = scan_fixture(
        &[
            (
                "crates/a/src/lib.rs",
                r#"const X: &str = include_str!("../../../scripts/boot.sh");"#,
            ),
            ("scripts/boot.sh", "#!/bin/sh"),
        ],
        &[("a", "crates/a")],
        &["a"],
    );
    assert_eq!(s.escapes.len(), 1, "{s:?}");
    let e = s.escapes.first().expect("one escape");
    assert_eq!(e.target, "scripts/boot.sh");
    assert!(e.tracked, "the fixture tracks it");
}

#[test]
fn an_untracked_target_is_distinguished_from_a_tracked_one() {
    // Same shape as above, but the target is on disk and not in `tracked`.
    let root = tempfile::tempdir().expect("tempdir");
    let src = "crates/a/src/lib.rs";
    std::fs::create_dir_all(root.path().join("crates/a/src")).expect("mkdir");
    std::fs::create_dir_all(root.path().join("sdks/pkg")).expect("mkdir");
    std::fs::write(
        root.path().join(src),
        r#"const X: &[u8] = include_bytes!("../../../sdks/pkg/w.wasm");"#,
    )
    .expect("write");
    std::fs::write(root.path().join("sdks/pkg/w.wasm"), b"\0asm").expect("write");

    let tracked = vec![src.to_string()]; // deliberately omits the wasm
    let s = scan(
        &ws(&[("a", "crates/a")], &["a"]),
        root.path(),
        &tracked,
        "a",
    )
    .expect("scan");

    assert_eq!(s.escapes.len(), 1, "{s:?}");
    let e = s.escapes.first().expect("one escape");
    assert_eq!(e.target, "sdks/pkg/w.wasm");
    assert!(
        !e.tracked,
        "an untracked target must be reported as such: no closure can key it"
    );
}

#[test]
fn a_computed_path_is_unresolvable_not_covered() {
    let s = scan_fixture(
        &[(
            "crates/a/src/lib.rs",
            r#"const X: &str = include_str!(concat!(env!("OUT_DIR"), "/g.rs"));"#,
        )],
        &[("a", "crates/a")],
        &["a"],
    );
    assert!(s.escapes.is_empty());
    assert_eq!(s.unresolvable.len(), 1, "{s:?}");
    assert!(!s.is_clean(), "unresolvable must not read as clean");
}

/// The case a regex gets wrong, which is why this uses a lexer.
#[test]
fn a_macro_name_in_a_comment_or_string_is_not_a_site() {
    let s = scan_fixture(
        &[(
            "crates/a/src/lib.rs",
            r#"
            // include_str!("../../../scripts/commented.sh")
            /* include_bytes!("../../../scripts/blocked.sh") */
            const D: &str = "include_str!(\"../../../scripts/quoted.sh\")";
            "#,
        )],
        &[("a", "crates/a")],
        &["a"],
    );
    assert_eq!(s.sites_examined, 0, "none of those are calls: {s:?}");
    assert!(s.is_clean());
}

#[test]
fn a_raw_string_path_resolves() {
    let s = scan_fixture(
        &[(
            "crates/a/src/lib.rs",
            "const X: &str = include_str!(r#\"../../../scripts/raw.sh\"#);",
        )],
        &[("a", "crates/a")],
        &["a"],
    );
    assert_eq!(s.escapes.len(), 1, "raw strings are paths too: {s:?}");
    assert_eq!(s.escapes.first().expect("one").target, "scripts/raw.sh");
}

#[test]
fn a_call_nested_in_a_function_body_is_found() {
    let s = scan_fixture(
        &[(
            "crates/a/src/lib.rs",
            r#"fn f() { let _ = include_str!("../../../scripts/deep.sh"); }"#,
        )],
        &[("a", "crates/a")],
        &["a"],
    );
    assert_eq!(
        s.escapes.len(),
        1,
        "the walk must descend into groups: {s:?}"
    );
}

#[test]
fn a_path_climbing_above_the_root_is_unresolvable() {
    let s = scan_fixture(
        &[(
            "crates/a/src/lib.rs",
            r#"const X: &str = include_str!("../../../../../etc/passwd");"#,
        )],
        &[("a", "crates/a")],
        &["a"],
    );
    assert!(s.escapes.is_empty());
    assert_eq!(s.unresolvable.len(), 1, "{s:?}");
}

#[test]
fn a_workspace_wide_file_is_covered() {
    let s = scan_fixture(
        &[
            (
                "crates/a/src/lib.rs",
                r#"const X: &str = include_str!("../../../Cargo.lock");"#,
            ),
            ("Cargo.lock", ""),
        ],
        &[("a", "crates/a")],
        &["a"],
    );
    assert!(s.is_clean(), "Cargo.lock is in every closure: {s:?}");
}

#[test]
fn a_crate_outside_the_workspace_is_refused_not_reported_clean() {
    let root = tempfile::tempdir().expect("tempdir");
    let err = scan(&ws(&[("a", "crates/a")], &["a"]), root.path(), &[], "nope")
        .expect_err("a crate with no closure has no answer");
    assert!(format!("{err:#}").contains("not a workspace crate"));
}

#[test]
fn source_that_does_not_lex_is_an_error_not_an_empty_scan() {
    let root = tempfile::tempdir().expect("tempdir");
    let src = "crates/a/src/lib.rs";
    std::fs::create_dir_all(root.path().join("crates/a/src")).expect("mkdir");
    // An unterminated string: the lexer must reject it.
    std::fs::write(root.path().join(src), "const X: &str = \"oops;").expect("write");
    let err = scan(
        &ws(&[("a", "crates/a")], &["a"]),
        root.path(),
        &[src.to_string()],
        "a",
    )
    .expect_err("unlexable source must not read as 'no reads found'");
    assert!(format!("{err:#}").contains("lexing"));
}

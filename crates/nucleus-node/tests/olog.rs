//! The olog is checked, or it is decoration.
//!
//! `docs/olog/pod-snapshot-reuse.md` states the objects, arrows and laws of content-addressed pod
//! execution. A document like that is worth exactly as much as its ability to fail: this
//! repository has produced five things that were typed, tested, documented, and read by nothing,
//! each of which had prose asserting it was live.
//!
//! So every object's file and every arrow's `path:symbol` is resolved here. Rename a function or
//! move a module and this test goes red, naming the row that lied — which is the property that
//! makes the olog a load-bearing artifact rather than a snapshot of what was once true.
//!
//! Deliberately NOT checked: that an arrow does what its English reading says. No test can carry
//! that. The laws in the document name the tests that do, and those are checked by running them.

use std::path::{Path, PathBuf};

/// The repository root, from this crate's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/<name> is two levels below the root")
        .to_path_buf()
}

fn olog() -> String {
    let path = repo_root().join("docs/olog/pod-snapshot-reuse.md");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("the olog must exist at {}: {e}", path.display()))
}

/// The cells of a markdown table row, trimmed, ignoring the leading and trailing pipes.
fn cells(line: &str) -> Vec<&str> {
    line.trim()
        .trim_start_matches('|')
        .trim_end_matches('|')
        .split('|')
        .map(str::trim)
        .collect()
}

/// Rows whose last cell is a backticked path, i.e. the object and aspect tables.
fn rows_with_sites(doc: &str) -> Vec<(String, String)> {
    doc.lines()
        .filter(|l| l.trim_start().starts_with('|'))
        .filter_map(|l| {
            let c = cells(l);
            if c.len() < 2 {
                return None;
            }
            let name = c[0].trim_matches('`').to_string();
            let site = c[c.len() - 1];
            let site = site.strip_prefix('`')?.strip_suffix('`')?.to_string();
            // Skip the header separator and any row whose last cell is not a path.
            (site.contains('/') && site.ends_with(".rs") || site.contains(".rs:"))
                .then_some((name, site))
        })
        .collect()
}

/// Every file an object or arrow points at exists.
#[test]
fn every_olog_row_points_at_a_file_that_exists() {
    let doc = olog();
    let rows = rows_with_sites(&doc);
    assert!(
        rows.len() >= 30,
        "the olog should carry the objects and aspects tables; parsed only {} rows — the table \
         format probably changed and this test is no longer reading it",
        rows.len()
    );
    let root = repo_root();
    let mut missing = Vec::new();
    for (name, site) in &rows {
        let file = site.split(':').next().unwrap_or(site);
        if !root.join(file).is_file() {
            missing.push(format!("{name} -> {file}"));
        }
    }
    assert!(
        missing.is_empty(),
        "the olog names files that no longer exist:\n  {}",
        missing.join("\n  ")
    );
}

/// Every arrow's symbol is actually defined in the file the olog names.
///
/// This is the row that decays first — a rename leaves the file correct and the symbol gone, and
/// nothing else in the build would notice that the document now describes an arrow that is not
/// there.
#[test]
fn every_olog_arrow_resolves_to_a_symbol_in_its_file() {
    let doc = olog();
    let root = repo_root();
    let mut broken = Vec::new();
    let mut checked = 0usize;
    for (name, site) in rows_with_sites(&doc) {
        let Some((file, symbol)) = site.split_once(".rs:") else {
            continue; // an object row: a file, no symbol
        };
        let file = format!("{file}.rs");
        let Ok(src) = std::fs::read_to_string(root.join(&file)) else {
            continue; // reported by the test above
        };
        checked += 1;
        // A definition, not a mention: `fn <symbol>`, `const <symbol>`, or a struct field/variant
        // declaration. Searching for the bare name would pass on a comment, which is exactly the
        // kind of "documented and absent" this file exists to catch.
        let defined = [
            format!("fn {symbol}"),
            format!("const {symbol}"),
            format!("struct {symbol}"),
            format!("enum {symbol}"),
        ]
        .iter()
        .any(|pat| src.contains(pat.as_str()));
        if !defined {
            broken.push(format!("{name}: `{symbol}` is not defined in {file}"));
        }
    }
    assert!(
        checked >= 15,
        "expected the aspects table to carry at least 15 arrows, found {checked}"
    );
    assert!(
        broken.is_empty(),
        "the olog names arrows that are not defined where it says:\n  {}",
        broken.join("\n  ")
    );
}

/// Every test the laws cite exists somewhere in the tree.
///
/// A law is only as good as its enforcement, and citing a test that was deleted or renamed is the
/// same failure in a more convincing disguise — the document would still read as though the
/// property were guarded.
#[test]
fn every_law_cites_a_test_that_exists() {
    let doc = olog();
    let root = repo_root();

    // Law citations are list items whose first token is a backticked snake_case identifier.
    let cited: Vec<String> = doc
        .lines()
        .filter_map(|l| l.trim().strip_prefix("- `"))
        .filter_map(|rest| rest.split('`').next())
        .filter(|s| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
        .map(str::to_string)
        .collect();
    assert!(
        cited.len() >= 15,
        "the laws should cite their enforcing tests; found {}",
        cited.len()
    );

    let sources = collect_rs(&root.join("crates"));
    let haystack: String = sources
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .collect::<Vec<_>>()
        .join("\n");

    let missing: Vec<&String> = cited
        .iter()
        .filter(|name| !haystack.contains(format!("fn {name}").as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "the olog cites tests that do not exist:\n  {missing:#?}"
    );
}

fn collect_rs(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            // `target` can appear inside a crate dir and is enormous.
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            out.extend(collect_rs(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}

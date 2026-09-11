//! `cargo xtask clippy-config` — a crate-level `clippy.toml` shadows the root one entirely.
//!
//! Clippy resolves **one** configuration file. It reads `CLIPPY_CONF_DIR`, else
//! `CARGO_MANIFEST_DIR` — the *member* directory for a workspace member — and the first
//! `clippy.toml` it finds wins outright. There is no merge. A crate that has its own
//! `clippy.toml` therefore silently receives **none** of the root's entries.
//!
//! That is not a hypothetical. Measured on this tree, 2026-09-11:
//!
//! ```text
//! $ printf 'fn probe() { unsafe { std::env::set_var("P", "1") }; }\n' \
//!     >> crates/nucleus-tool-proxy/src/egress.rs
//! $ cargo clippy -p nucleus-tool-proxy --all-targets --all-features
//! warning: function `probe` is never used        <- the crate IS compiled
//!                                                <- and disallowed_methods does NOT fire
//! ```
//!
//! `crates/nucleus-tool-proxy/clippy.toml` exists to hold `disallowed-types` for #1216,
//! and by existing it dropped the root's `disallowed-methods` on the floor. The two
//! entries ADR 0007 wired — C-1 `std::mem::transmute` and C-5 `std::vec::Vec::leak` —
//! were vacuous in exactly the crate that holds the HTTP and MCP effect boundary.
//!
//! This is ADR 0007's own I-1 firing against ADR 0007: a gate whose green was
//! indistinguishable from vacuity. Both entries measured zero occurrences tree-wide, so
//! nothing could have revealed that one crate was never being asked.
//!
//! # What decides this
//!
//! Only files in the working tree. No toolchain, no network, no build. A `clippy.toml`
//! that cannot be read is reported as [`Outcome::CouldNotLook`] and never as a pass —
//! ADR 0007 A-2, "I could not look is never I looked and it was fine."

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// The two list-valued keys whose entries a shadowing config drops.
///
/// Named rather than positional (ADR 0007 E-3) and exhaustive: a third disallowed-\*
/// key added to the root must be added here too, and [`Key::ALL`] is what the gate
/// iterates so that adding a variant without listing it is a compile error (E-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Methods,
    Types,
    Macros,
}

impl Key {
    pub const ALL: [Key; 3] = [Key::Methods, Key::Types, Key::Macros];

    pub fn toml_name(self) -> &'static str {
        match self {
            Key::Methods => "disallowed-methods",
            Key::Types => "disallowed-types",
            Key::Macros => "disallowed-macros",
        }
    }
}

/// One root entry a crate-level config fails to carry.
///
/// Carries the crate that shadows, the key, and the path that was dropped — a sum type
/// keeps its payload (ADR 0007 A-6), so the report names what to add rather than only
/// that something is missing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dropped {
    /// Path of the shadowing `clippy.toml`, relative to the repository root.
    pub config: String,
    /// Which list the entry belongs to.
    pub key: Key,
    /// The `path = "..."` value the root declares and this config does not.
    pub entry: String,
}

/// What the check concluded.
///
/// Three states, not a `bool` (ADR 0007 A-1). `CouldNotLook` is neither a pass nor a
/// violation: a root `clippy.toml` that is absent or unreadable means the gate has no
/// subject, and reporting that as clean is the exact defect A-2 names.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Every crate-level config carries every root entry.
    Clean,
    /// At least one root entry is dropped by at least one crate-level config.
    Shadowed(Vec<Dropped>),
    /// The root config could not be read, so nothing was compared.
    CouldNotLook { reason: String },
}

/// Every `path = "..."` value under `key` in one parsed `clippy.toml`.
///
/// Returns `Result<Vec<_>, _>` rather than a bare `Vec`: "this config declares no
/// entries under this key" and "this text is not TOML" are different answers, and
/// collapsing them is ADR 0007 A-3 — the `grep`-exits-2 trap in Rust clothing.
pub fn entries(text: &str, key: Key) -> Result<Vec<String>> {
    let doc: toml::Value = toml::from_str(text).context("clippy.toml is not valid TOML")?;
    let Some(list) = doc.get(key.toml_name()) else {
        return Ok(Vec::new());
    };
    let Some(array) = list.as_array() else {
        anyhow::bail!("`{}` is not an array", key.toml_name());
    };
    let mut out = Vec::new();
    for item in array {
        // Clippy accepts both the bare-string form and the table form with a `reason`.
        // Both are the same declaration, so both are compared.
        match item {
            toml::Value::String(s) => out.push(s.clone()),
            toml::Value::Table(t) => {
                if let Some(toml::Value::String(p)) = t.get("path") {
                    out.push(p.clone());
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

/// Every `clippy.toml` below `root` other than the root's own, in a stable order.
fn crate_configs(root: &Path) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    let mut stack = vec![root.join("crates"), root.join("tools")];
    while let Some(dir) = stack.pop() {
        let Ok(read) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in read.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // `target/` holds vendored sources whose configs are not ours to gate.
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(path);
            } else if path.file_name().is_some_and(|n| n == "clippy.toml") {
                found.push(path);
            }
        }
    }
    found.sort();
    Ok(found)
}

/// Compare every crate-level `clippy.toml` against the root's.
pub fn check(root: &Path) -> Result<Outcome> {
    let root_config = root.join("clippy.toml");
    let root_text = match std::fs::read_to_string(&root_config) {
        Ok(t) => t,
        Err(e) => {
            return Ok(Outcome::CouldNotLook {
                reason: format!("{}: {e}", root_config.display()),
            });
        }
    };

    let mut dropped = Vec::new();
    for config in crate_configs(root)? {
        let text = std::fs::read_to_string(&config)
            .with_context(|| format!("reading {}", config.display()))?;
        let shown = config
            .strip_prefix(root)
            .unwrap_or(&config)
            .display()
            .to_string();
        for key in Key::ALL {
            let required = entries(&root_text, key)?;
            let present = entries(&text, key)?;
            for entry in required {
                if !present.contains(&entry) {
                    dropped.push(Dropped {
                        config: shown.clone(),
                        key,
                        entry,
                    });
                }
            }
        }
    }

    if dropped.is_empty() {
        Ok(Outcome::Clean)
    } else {
        Ok(Outcome::Shadowed(dropped))
    }
}

/// Run the gate and render its verdict. Exit codes follow the repository's convention:
/// 0 clean, 1 a violation, 2 could not look — the third is never a pass.
pub fn run(root: &Path) -> Result<i32> {
    match check(root)? {
        Outcome::Clean => {
            println!("ok: every crate-level clippy.toml carries the root's entries");
            Ok(0)
        }
        Outcome::CouldNotLook { reason } => {
            eprintln!("could not look: {reason}");
            eprintln!("this is NOT a pass -- the root clippy.toml is the gate's subject");
            Ok(2)
        }
        Outcome::Shadowed(dropped) => {
            eprintln!(
                "a crate-level clippy.toml shadows the root one. Clippy reads ONE config\n\
                 file -- the nearest -- and does not merge, so these root entries are not\n\
                 enforced in these crates:\n"
            );
            for d in &dropped {
                eprintln!(
                    "  {} drops {} entry `{}`",
                    d.config,
                    d.key.toml_name(),
                    d.entry
                );
            }
            eprintln!(
                "\nfix: copy the entry into the crate's clippy.toml. ADR 0007 G-2 -- where a\n\
                 second copy is unavoidable, the gate lives at the declaration, which is\n\
                 what this check is."
            );
            Ok(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = r#"
disallowed-methods = [
    { path = "std::mem::transmute", reason = "C-1" },
    { path = "std::env::set_var", reason = "H-1" },
]
"#;

    #[test]
    fn the_table_form_and_the_bare_string_form_are_the_same_declaration() {
        let bare = r#"disallowed-methods = ["std::mem::transmute"]"#;
        assert_eq!(
            entries(bare, Key::Methods).unwrap(),
            vec!["std::mem::transmute".to_string()],
        );
        assert_eq!(
            entries(ROOT, Key::Methods).unwrap(),
            vec![
                "std::mem::transmute".to_string(),
                "std::env::set_var".to_string()
            ],
        );
    }

    /// A-3: a config that declares nothing under a key and a config that cannot be
    /// parsed are different answers. The first is `Ok(vec![])`; the second is `Err`.
    /// Returning an empty vec for both would make a broken config read as compliant.
    #[test]
    fn an_unparseable_config_is_an_error_not_an_empty_list() {
        assert!(entries("", Key::Methods).unwrap().is_empty());
        assert!(entries("this is not toml {{{", Key::Methods).is_err());
    }

    /// A-2: no root config means the gate has no subject. It must not report clean.
    #[test]
    fn a_missing_root_config_is_could_not_look_never_clean() {
        let dir = tempfile::tempdir().unwrap();
        let outcome = check(dir.path()).unwrap();
        assert!(
            matches!(outcome, Outcome::CouldNotLook { .. }),
            "got {outcome:?}"
        );
    }

    /// THE regression. A crate-level config that omits a root entry is a violation,
    /// and the report names the entry to add rather than only that something is wrong.
    #[test]
    fn a_crate_config_that_drops_a_root_entry_is_reported_with_the_entry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("clippy.toml"), ROOT).unwrap();
        let krate = dir.path().join("crates").join("shadower");
        std::fs::create_dir_all(&krate).unwrap();
        std::fs::write(
            krate.join("clippy.toml"),
            r#"disallowed-types = [{ path = "std::fs::File", reason = "x" }]"#,
        )
        .unwrap();

        let Outcome::Shadowed(dropped) = check(dir.path()).unwrap() else {
            panic!("a config dropping both root entries must not read as clean");
        };
        let names: Vec<&str> = dropped.iter().map(|d| d.entry.as_str()).collect();
        assert!(names.contains(&"std::mem::transmute"), "{names:?}");
        assert!(names.contains(&"std::env::set_var"), "{names:?}");
    }

    /// Non-vacuity: the test above would pass against a gate that flagged everything.
    /// A crate config that carries every root entry must come back clean.
    #[test]
    fn a_crate_config_that_carries_every_root_entry_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("clippy.toml"), ROOT).unwrap();
        let krate = dir.path().join("crates").join("compliant");
        std::fs::create_dir_all(&krate).unwrap();
        std::fs::write(
            krate.join("clippy.toml"),
            r#"
disallowed-types = [{ path = "std::fs::File", reason = "x" }]
disallowed-methods = [
    { path = "std::mem::transmute", reason = "C-1" },
    { path = "std::env::set_var", reason = "H-1" },
]
"#,
        )
        .unwrap();
        assert_eq!(check(dir.path()).unwrap(), Outcome::Clean);
    }

    /// The gate on its own repository. This is the check that would have caught the
    /// defect that motivated the module, run against the real tree.
    #[test]
    fn this_repository_is_clean() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("workspace root");
        match check(root).unwrap() {
            Outcome::Clean => {}
            other => panic!("{other:?}"),
        }
    }
}

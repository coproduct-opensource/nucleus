//! Build-time provider for the built-in permission profiles.
//!
//! # Why this exists
//!
//! The ten YAML files in `profiles/` decide what an agent may do. They were
//! `include_str!`'d and parsed at process start, behind:
//!
//! ```ignore
//! Self::canonical().expect("canonical profiles must parse")
//! ```
//!
//! so a malformed built-in profile was a **runtime panic in a booting pod**,
//! discovered on a production node rather than in the build that shipped it.
//! That is the "a bad indent breaks at runtime" pattern, sitting in the security
//! kernel of a runtime whose whole purpose is to be the opposite of that.
//!
//! This is the F#-type-provider move, in the form Rust offers: read the external
//! artifact at BUILD time, validate it, and materialise types the compiler can
//! see. A malformed profile now fails `cargo build`, with the file named.
//!
//! # What is checked here, and what is not
//!
//! `build.rs` cannot use `portcullis`'s own types — it runs before the crate is
//! compiled — so validation here is STRUCTURAL: the file parses as YAML, is a
//! mapping, declares a `name` matching its filename, and carries no key
//! `ProfileSpec` would not accept. That catches the whole syntax-and-typo class,
//! which is the class that used to reach production.
//!
//! Full type-level validation (does `capabilities.read_files: low_risk` name a
//! real level?) needs the real serde types, so it lives in a test —
//! `every_builtin_profile_parses` — which runs in CI against
//! `ProfileName::ALL`. Between them: a bad indent fails the build, a bad value
//! fails the tests, and neither reaches a pod.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

/// Top-level keys `ProfileSpec` accepts. Anything else in a profile is a typo
/// that would be silently ignored by serde's default behaviour.
const KNOWN_KEYS: &[&str] = &[
    "name",
    "description",
    "capabilities",
    "obligations",
    "paths",
    "budget",
    "time",
];

fn main() {
    println!("cargo:rustc-check-cfg=cfg(kani)");
    generate_profile_names();
}

/// `safe-pr-fixer` -> `SafePrFixer`
fn variant_ident(name: &str) -> String {
    name.split(['-', '_'])
        .filter(|s| !s.is_empty())
        .map(|s| {
            let mut c = s.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + &c.as_str().to_lowercase(),
                None => String::new(),
            }
        })
        .collect()
}

fn generate_profile_names() {
    let dir = Path::new("profiles");
    println!("cargo:rerun-if-changed={}", dir.display());

    let mut entries: Vec<(String, String)> = Vec::new(); // (declared name, file stem)
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
        .collect();
    files.sort();

    for path in &files {
        println!("cargo:rerun-if-changed={}", path.display());
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_else(|| panic!("non-utf8 profile filename: {}", path.display()))
            .to_string();
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));

        // 1. It must be YAML at all. This is the bad-indent case, and the error
        //    carries serde_yaml's line/column.
        let value: serde_yaml::Value = serde_yaml::from_str(&text)
            .unwrap_or_else(|e| panic!("{}: not valid YAML: {e}", path.display()));

        let map = value
            .as_mapping()
            .unwrap_or_else(|| panic!("{}: a profile must be a mapping", path.display()));

        // 2. No key ProfileSpec would silently ignore.
        let known: BTreeSet<&str> = KNOWN_KEYS.iter().copied().collect();
        for k in map.keys() {
            let key = k
                .as_str()
                .unwrap_or_else(|| panic!("{}: non-string key", path.display()));
            if !known.contains(key) {
                panic!(
                    "{}: unknown key `{key}` — a profile accepts only {:?}. \
                     Left as-is this would be silently ignored.",
                    path.display(),
                    KNOWN_KEYS
                );
            }
        }

        // 3. The declared name must match the filename, or `ProfileName::Codegen`
        //    would resolve to a file called something else.
        let declared = map
            .get(serde_yaml::Value::from("name"))
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("{}: missing required `name`", path.display()));
        if declared != stem {
            panic!(
                "{}: declares name `{declared}` but the file is `{stem}.yaml`. \
                 They must agree — the generated variant is derived from both.",
                path.display()
            );
        }
        entries.push((declared.to_string(), stem));
    }

    assert!(
        entries.len() >= 5,
        "found only {} built-in profiles; the provider has stopped seeing the \
         directory and would generate an empty enum",
        entries.len()
    );

    let mut out = String::new();
    out.push_str(
        "// @generated by build.rs from profiles/*.yaml — do not edit.\n\
         /// A built-in profile, one variant per file in `profiles/`.\n\
         ///\n\
         /// Generated at build time, so a name that is not a built-in profile is\n\
         /// a compile error rather than a runtime `PolicyError`.\n\
         #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]\n\
         pub enum ProfileName {\n",
    );
    for (name, _) in &entries {
        let _ = writeln!(out, "    /// `{name}`\n    {},", variant_ident(name));
    }
    out.push_str("}\n\nimpl ProfileName {\n");

    let _ = writeln!(
        out,
        "    /// Every built-in profile.\n    pub const ALL: [ProfileName; {}] = [{}];\n",
        entries.len(),
        entries
            .iter()
            .map(|(n, _)| format!("ProfileName::{}", variant_ident(n)))
            .collect::<Vec<_>>()
            .join(", ")
    );

    out.push_str("    /// The canonical name, as written in the YAML.\n");
    out.push_str("    pub fn as_str(&self) -> &'static str {\n        match self {\n");
    for (name, _) in &entries {
        let _ = writeln!(
            out,
            "            ProfileName::{} => \"{name}\",",
            variant_ident(name)
        );
    }
    out.push_str("        }\n    }\n\n");

    out.push_str(
        "    /// The profile's YAML source, embedded at build time.\n\
         \x20   pub fn yaml(&self) -> &'static str {\n        match self {\n",
    );
    for (name, stem) in &entries {
        let _ = writeln!(
            out,
            "            ProfileName::{} => include_str!(\"{}/profiles/{stem}.yaml\"),",
            variant_ident(name),
            env!("CARGO_MANIFEST_DIR")
        );
    }
    out.push_str("        }\n    }\n\n");

    // Hyphen/underscore aliasing, generated rather than hand-maintained: the old
    // resolver spelled every pair out by hand (`"pr_review" | "pr-review"`) and
    // had to be kept in sync with this directory by memory.
    out.push_str(
        "    /// Resolve a name, accepting `-` and `_` interchangeably.\n\
         \x20   ///\n\
         \x20   /// Returns the candidate list on failure so the caller can say what\n\
         \x20   /// WAS valid — a bare \"unknown profile\" is how a typo becomes a\n\
         \x20   /// support ticket.\n\
         \x20   pub fn parse(s: &str) -> Result<ProfileName, Vec<&'static str>> {\n\
         \x20       let norm = s.trim().to_lowercase().replace('_', \"-\");\n\
         \x20       for p in ProfileName::ALL {\n\
         \x20           if p.as_str() == norm {\n\
         \x20               return Ok(p);\n\
         \x20           }\n\
         \x20       }\n\
         \x20       Err(ProfileName::ALL.iter().map(|p| p.as_str()).collect())\n\
         \x20   }\n",
    );
    out.push_str("}\n");

    let dest = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("profile_names.rs");
    std::fs::write(&dest, out).unwrap_or_else(|e| panic!("cannot write {}: {e}", dest.display()));
}

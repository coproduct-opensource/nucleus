//! `cargo xtask command-grammar` — every CLI leaf declares the band it demands.
//!
//! `docs/design/command-grammar.md` argues that a command's required authority should be an
//! index on its grammar term rather than something attached by convention. Measured while
//! writing it: `grep -rn "Act::\|preflight_action" crates/nucleus-cli/src/` returns **zero**
//! lines, so today no operator command's authority is decided by the kernel that decides the
//! agent's. This gate is the one row of that document's enforcement table that is
//! mechanised.
//!
//! It checks the leaf → band table in `docs/design/command-bands.toml` is **total in both
//! directions** against the clap derives: no command without an entry, no entry without a
//! command.
//!
//! # What it does NOT check
//!
//! **It does not check that any band is CORRECT.** A leaf declared `observe` that boots a
//! VM passes. Deriving the true band means walking each command to the `Act`s it performs
//! (`portcullis-core/src/act.rs:330`) and folding `Operation::is_mutation` /
//! `is_exfiltration_vector` over them, which needs a per-leaf `acts()` declaration that does
//! not exist yet.
//!
//! So the property is exactly: *the surface cannot grow a command whose authority nobody
//! wrote down.* That is strictly weaker than "the authority written down is right", and
//! saying so is the difference between a gate and a comment — `FINDINGS.md` F-52, where a
//! pin nothing read was described for a week as a control.
//!
//! # A check that was dropped for being vacuous
//!
//! The design doc originally proposed also forbidding a head word that collides with a
//! `SinkClass` wire name — a command claiming to be a destination. `SinkClass` carries
//! `#[serde(rename_all = "snake_case")]` and every one of its 19 variants is compound
//! (`workspace_write`, `bash_exec`, `secret_read`), while every head word is a single token.
//! The check cannot fire, today or plausibly ever. A gate that only ever passes proves
//! nothing, so it is review-tier in the doc rather than a green light here.
//!
//! # Why both directions
//!
//! A one-way check lets the table accumulate entries for commands that no longer exist, and
//! a stale entry reads exactly like a live one. The repo pins populations both ways for this
//! reason already — `assurance/ratchet.txt`, and `FINDINGS.md`'s exact-count pin.
//!
//! # Where the leaf set comes from
//!
//! `syn`, over the clap derives, not a grep. A grep would have to decide what a variant
//! looks like, and `FINDINGS.md` F-36 is five copies of one hand-rolled parser.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

/// The declared leaf → band table.
#[derive(Debug, Deserialize)]
struct BandTable {
    /// Leaf path (`"verify"`, `"identity verify"`) → band.
    ///
    /// One `Deserialize` struct and a loop rather than hand-walking a `toml::Value`
    /// (ADR 0007 **F-2**).
    leaf: BTreeMap<String, String>,
}

/// The three bands. A closed set: an unknown band is a violation, not a new band
/// (ADR 0007 **B-4** — a `_ =>` arm denies).
const BANDS: &[&str] = &["observe", "emit", "reach"];

/// What the gate established. Three outcomes, not two: "could not look" is never a pass,
/// which is `crates/ci-spec/src/lib.rs:26-32`'s contract, applied here rather than restated.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The table is total in both directions and every band is known.
    Clean,
    /// Something is missing, stale, or not a band.
    Violation {
        /// Commands in the CLI with no declared band.
        undeclared: Vec<String>,
        /// Declared entries naming no command.
        stale: Vec<String>,
        /// Entries whose band is not one of [`BANDS`].
        unknown_band: Vec<String>,
    },
    /// The gate could not read its own subject. Distinct from [`Outcome::Violation`]
    /// because "the file was missing" and "the table is wrong" are different facts
    /// (ADR 0007 **A-1**).
    CouldNotLook(String),
}

/// Variant names of the enum named `enum_name` in `path`.
fn variants_of(path: &Path, enum_name: &str) -> Result<Vec<String>> {
    let src = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let file: syn::File =
        syn::parse_file(&src).with_context(|| format!("parsing {}", path.display()))?;
    for item in &file.items {
        if let syn::Item::Enum(e) = item
            && e.ident == enum_name
        {
            return Ok(e.variants.iter().map(|v| v.ident.to_string()).collect());
        }
    }
    anyhow::bail!("no `enum {enum_name}` in {}", path.display())
}

/// `LineageVerifyChain` → `lineage-verify-chain`, matching clap's default rename.
fn kebab(ident: &str) -> String {
    let mut out = String::with_capacity(ident.len() + 4);
    for (i, ch) in ident.char_indices() {
        if ch.is_uppercase() {
            if i != 0 {
                out.push('-');
            }
            out.extend(ch.to_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// The groups: a top-level command whose leaves live in its own module's enum.
///
/// Listed rather than discovered, because the link from variant to module is an attribute
/// on a field whose type is the enum. A group added and not listed here surfaces as an
/// undeclared leaf — a red, not a silent pass, which is the direction that matters.
const GROUPS: &[(&str, &str, &str)] = &[
    ("trust", "trust.rs", "TrustCommand"),
    ("guard", "guard.rs", "GuardCommand"),
    ("manifest", "manifest.rs", "ManifestCommand"),
    ("token", "token.rs", "TokenCommand"),
    ("grant", "grant.rs", "GrantCommand"),
    ("identity", "identity.rs", "IdentityCommand"),
    ("node", "node.rs", "NodeCommand"),
    ("bundle", "bundle.rs", "BundleCommand"),
];

/// Every leaf of the `nucleus` CLI, as space-joined paths (`"identity verify"`).
pub fn leaves(root: &Path) -> Result<BTreeSet<String>> {
    let cli = root.join("crates/nucleus-cli/src");
    let group_names: BTreeSet<&str> = GROUPS.iter().map(|(n, _, _)| *n).collect();

    let mut out = BTreeSet::new();
    for variant in variants_of(&cli.join("main.rs"), "Commands")? {
        let name = kebab(&variant);
        // A group is not itself a leaf; its variants are.
        if !group_names.contains(name.as_str()) {
            out.insert(name);
        }
    }
    for (group, file, enum_name) in GROUPS {
        for variant in variants_of(&cli.join(file), enum_name)? {
            out.insert(format!("{group} {}", kebab(&variant)));
        }
    }
    Ok(out)
}

/// Check the declared table against the CLI.
pub fn check(root: &Path) -> Result<Outcome> {
    let table_path = root.join("docs/design/command-bands.toml");
    let Ok(raw) = fs::read_to_string(&table_path) else {
        return Ok(Outcome::CouldNotLook(format!(
            "{} is missing; the gate has no subject",
            table_path.display()
        )));
    };
    let table: BandTable = match toml::from_str(&raw) {
        Ok(t) => t,
        Err(e) => {
            return Ok(Outcome::CouldNotLook(format!(
                "{} does not parse: {e}",
                table_path.display()
            )));
        }
    };

    let actual = leaves(root)?;
    let declared: BTreeSet<String> = table.leaf.keys().cloned().collect();

    let unknown_band: Vec<String> = table
        .leaf
        .iter()
        .filter(|(_, band)| !BANDS.contains(&band.as_str()))
        .map(|(leaf, band)| format!("{leaf} = {band:?}"))
        .collect();

    let undeclared: Vec<String> = actual.difference(&declared).cloned().collect();
    let stale: Vec<String> = declared.difference(&actual).cloned().collect();

    if undeclared.is_empty() && stale.is_empty() && unknown_band.is_empty() {
        Ok(Outcome::Clean)
    } else {
        Ok(Outcome::Violation {
            undeclared,
            stale,
            unknown_band,
        })
    }
}

/// Run the gate and report. Returns the process exit code: 0 clean, 1 violation, 2 could
/// not look — `ci-spec`'s contract, which `docs/design/command-grammar.md` proposes the
/// CLI adopt and which this gate therefore follows first.
pub fn run(root: &Path) -> Result<i32> {
    match check(root)? {
        Outcome::Clean => {
            println!(
                "command-grammar: {} leaves, every one declares a band",
                leaves(root)?.len()
            );
            Ok(0)
        }
        Outcome::Violation {
            undeclared,
            stale,
            unknown_band,
        } => {
            for leaf in &undeclared {
                println!(
                    "command-grammar: `nucleus {leaf}` declares no band \
                     (add it to docs/design/command-bands.toml)"
                );
            }
            for leaf in &stale {
                println!(
                    "command-grammar: docs/design/command-bands.toml declares \
                     `nucleus {leaf}`, which is not a command"
                );
            }
            for entry in &unknown_band {
                println!(
                    "command-grammar: {entry} is not a band \
                     (observe | emit | reach)"
                );
            }
            Ok(1)
        }
        Outcome::CouldNotLook(why) => {
            println!("command-grammar: could not look: {why}");
            Ok(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .expect("crates/xtask sits two below the root")
    }

    #[test]
    fn kebab_matches_claps_default_rename() {
        assert_eq!(kebab("Verify"), "verify");
        assert_eq!(kebab("LineageVerifyChain"), "lineage-verify-chain");
        assert_eq!(kebab("TwoSafety"), "two-safety");
        assert_eq!(kebab("EnvelopeVerify"), "envelope-verify");
    }

    /// The gate's own subject: the real CLI parses, and yields both leaf shapes.
    ///
    /// Spot-checks rather than a restated count — a count beside the thing it counts is
    /// ADR 0007 **F-3**, and the gate itself already compares populations.
    #[test]
    fn the_real_cli_parses_and_has_both_leaf_shapes() {
        let leaves = leaves(repo_root()).expect("the CLI parses");
        assert!(leaves.contains("verify"), "a flat leaf");
        assert!(leaves.contains("identity verify"), "a nested leaf");
        assert!(
            leaves.contains("lineage-verify-chain"),
            "a kebab-cased leaf"
        );
        assert!(!leaves.contains("identity"), "a group is not itself a leaf");
    }

    /// The tree is clean. This is the gate's green half; the red half is A-19's
    /// perturbation, recorded in the design doc.
    #[test]
    fn the_committed_table_is_total() {
        assert_eq!(check(repo_root()).expect("gate runs"), Outcome::Clean);
    }

    #[test]
    fn a_missing_table_is_could_not_look_not_a_pass() {
        let tmp = tempfile::tempdir().expect("tempdir");
        match check(tmp.path()) {
            Ok(Outcome::CouldNotLook(why)) => assert!(why.contains("command-bands.toml")),
            other => panic!("expected CouldNotLook, got {other:?}"),
        }
    }
}

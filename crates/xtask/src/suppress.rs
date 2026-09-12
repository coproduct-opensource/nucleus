//! The `suppress` family — the exemption channel of every other family.
//!
//! # Why this is not one gate among six
//!
//! `bound`, `alg`, `tot`, `life` and `typed` each report how much of what the
//! tree declares is covered by *a mechanism that can fail*. Every one of those
//! mechanisms can be switched off, silently and permanently, by one line:
//!
//! ```text
//! #[allow(clippy::let_underscore_must_use)]
//! ```
//!
//! An `#[allow]` is forever. It outlives the reason it was written for, and
//! nothing tells you when that reason expires. An `#[expect]` is the same
//! waiver with an expiry attached: when the lint stops firing at that site,
//! `unfulfilled_lint_expectations` errors and the attribute has to go. **It is
//! the only suppression that can itself fail**, which is this card's own
//! definition of discharged, applied to the waivers.
//!
//! # The measurement that makes the case
//!
//! Over the production region: **292 `#[allow]`, of which 0 carry a
//! `reason =`. 48 `#[expect]`, of which 48 do.**
//!
//! The tree already knows the right form. `crates/portcullis-effects/src/lib.rs`
//! denies `clippy::let_underscore_must_use` crate-wide and discharges it at nine
//! sites with `#[expect(..., reason = ...)]` — a live mandate, correctly waived,
//! in exactly one crate.
//!
//! # A mandate only reaches where its table does
//!
//! `allow_attributes` and `allow_attributes_without_reason` are clippy lints, so
//! they arrive through `[workspace.lints.clippy]` — and that table reaches a
//! crate only if the crate opts in with `[lints] workspace = true`.
//!
//! **54 of 95 crates opt in. 41 do not, and they include `portcullis`,
//! `portcullis-core` and `nucleus-flow-replay`** — the crates holding the
//! lattice, the receipt hashing and the flow replay. A suppression in one of
//! those is not covered and cannot be, until that crate's manifest gains three
//! lines.
//!
//! So the population is the suppressions the table can reach, and the 81 outside
//! it are reported as `undeclared`: surface the denominator does not cover. This
//! is the same reading `tot` takes of the crates clippy cannot compile, and for
//! the same reason — ADR 0007 A-2, "I could not look" is never "I looked and it
//! was fine".
//!
//! Counting them as discharged would be the worst available answer: a crate
//! could leave the lint table and its allows would become *compliant*.

use anyhow::{Result, bail};
use std::collections::{BTreeMap, BTreeSet};

use crate::law_mechanisms::production_region;

/// Crates that opt into `[workspace.lints]`, and so can receive a clippy
/// mandate at all.
///
/// Parsed from the `[lints]` table rather than assumed: a crate with its own
/// `[lints.clippy]` section and no `workspace = true` does NOT inherit, and a
/// crate with no `[lints]` section at all inherits nothing.
pub fn adopting_crates(manifests: &BTreeMap<String, String>) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (path, src) in manifests {
        let Some(name) = crate_name(path) else {
            continue;
        };
        // At the start of a line, which includes the start of the file — a
        // manifest opening with `[lints]` is legal TOML and a parser keyed to a
        // preceding newline would silently miss it, scoring that crate as
        // outside the mandate when it is inside.
        let Some(start) = section(src, "[lints]") else {
            continue;
        };
        let body = &src[start..];
        let end = body[1..].find("\n[").map_or(body.len(), |i| i + 1);
        if body[..end].contains("workspace = true") {
            out.insert(name);
        }
    }
    out
}

/// The byte offset of a TOML section header at the start of a line.
fn section(src: &str, header: &str) -> Option<usize> {
    if src.starts_with(header) {
        return Some(0);
    }
    src.find(&format!("\n{header}")).map(|i| i + 1)
}

fn crate_name(path: &str) -> Option<String> {
    let rest = path
        .strip_prefix("crates/")
        .or_else(|| path.strip_prefix("tools/"))?;
    rest.split('/').next().map(str::to_string)
}

/// One suppression attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suppression {
    /// `#[allow(..)]` — forever, and silent about why.
    Allow,
    /// `#[expect(..)]` — expires when the lint stops firing.
    Expect,
}

/// Every suppression attribute in one source region, in order.
///
/// Inner (`#![allow]`) and outer (`#[allow]`) both count: a crate-level allow is
/// the broadest waiver there is.
pub fn suppressions(region: &str) -> Vec<Suppression> {
    let mut out = Vec::new();
    let mut rest = region;
    while let Some(i) = rest.find("[allow(").or_else(|| rest.find("[expect(")) {
        let is_allow = rest[i..].starts_with("[allow(");
        // Must be an attribute: `#[` or `#![` immediately before.
        let before = &rest[..i];
        let attr = before.ends_with('#') || before.ends_with("#!");
        if attr {
            out.push(if is_allow {
                Suppression::Allow
            } else {
                Suppression::Expect
            });
        }
        rest = &rest[i + 1..];
    }
    out
}

/// The measured state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Report {
    /// Suppressions in crates the lint table reaches.
    pub covered_allow: usize,
    /// Of those, the ones that expire.
    pub covered_expect: usize,
    /// Suppressions in crates outside the table.
    pub uncovered: usize,
}

pub fn report(
    corpus: &BTreeMap<String, String>,
    manifests: &BTreeMap<String, String>,
) -> Result<Report> {
    let adopting = adopting_crates(manifests);
    if adopting.is_empty() {
        bail!(
            "no crate opts into [workspace.lints]. The population would be empty and the ratio \
             meaningless — either the manifests moved or the parse is wrong."
        );
    }
    let mut r = Report::default();
    for (path, src) in corpus {
        let Some(name) = crate_name(path) else {
            continue;
        };
        let inside = adopting.contains(&name);
        for s in suppressions(&production_region(src)) {
            match (inside, s) {
                (true, Suppression::Expect) => r.covered_expect += 1,
                (true, Suppression::Allow) => r.covered_allow += 1,
                (false, _) => r.uncovered += 1,
            }
        }
    }
    Ok(r)
}

impl Report {
    /// The three numbers the card prints.
    ///
    /// Pure, so the mapping is testable without a checkout: `census` below reads
    /// real manifests through `git ls-files`, and `cargo test` runs with the
    /// crate root as its working directory rather than the repo root.
    pub const fn census(self) -> crate::scorecard::Census {
        crate::scorecard::Census {
            population: self.covered_allow + self.covered_expect,
            discharged: self.covered_expect,
            undeclared: self.uncovered,
        }
    }
}

pub struct Suppress;

impl crate::scorecard::Family for Suppress {
    fn name(&self) -> &'static str {
        "suppress"
    }

    fn unit(&self) -> &'static str {
        "lint suppression"
    }

    fn census(&self, corpus: &BTreeMap<String, String>) -> Result<crate::scorecard::Census> {
        let manifests = crate::law_mechanisms::tracked(is_manifest)?;
        Ok(report(corpus, &manifests)?.census())
    }
}

/// A crate manifest under `crates/` or `tools/`.
fn is_manifest(path: &str) -> bool {
    (path.starts_with("crates/") || path.starts_with("tools/")) && path.ends_with("/Cargo.toml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_attribute_forms_count() {
        let src = "#![allow(dead_code)]\nfn f() {\n    #[expect(unused, reason = \"why\")]\n    let x = 1;\n}\n";
        assert_eq!(
            suppressions(src),
            vec![Suppression::Allow, Suppression::Expect]
        );
    }

    #[test]
    fn a_mention_is_not_an_attribute() {
        // A doc line or a string naming the attribute must not count.
        assert!(suppressions("let s = \"[allow(x)]\";\n").is_empty());
        assert!(suppressions("// see [allow(dead_code)]\n").is_empty());
    }

    #[test]
    fn a_crate_with_no_lints_section_does_not_adopt() {
        let m = BTreeMap::from([(
            "crates/a/Cargo.toml".to_string(),
            "[package]\nname = \"a\"\n".to_string(),
        )]);
        assert!(adopting_crates(&m).is_empty());
    }

    #[test]
    fn a_crate_with_its_own_lints_table_does_not_inherit() {
        // `[lints.clippy]` without `workspace = true` receives nothing from the
        // workspace table, which is exactly how a mandate can miss a crate that
        // looks configured.
        let m = BTreeMap::from([(
            "crates/a/Cargo.toml".to_string(),
            "[package]\nname = \"a\"\n\n[lints.clippy]\nfoo = \"deny\"\n".to_string(),
        )]);
        assert!(adopting_crates(&m).is_empty());
    }

    #[test]
    fn a_manifest_opening_with_the_lints_table_still_adopts() {
        // Found by `the_test_region_is_not_the_subject` failing: the parser
        // keyed on "\n[lints]" and a manifest whose FIRST line is `[lints]`
        // would have been scored as outside the mandate while being inside it.
        let m = BTreeMap::from([(
            "crates/a/Cargo.toml".to_string(),
            "[lints]\nworkspace = true\n".to_string(),
        )]);
        assert_eq!(adopting_crates(&m), BTreeSet::from(["a".to_string()]));
    }

    #[test]
    fn opting_in_is_the_whole_requirement() {
        let m = BTreeMap::from([(
            "crates/a/Cargo.toml".to_string(),
            "[package]\nname = \"a\"\n\n[lints]\nworkspace = true\n\n[dependencies]\n".to_string(),
        )]);
        assert_eq!(adopting_crates(&m), BTreeSet::from(["a".to_string()]));
    }

    #[test]
    fn a_suppression_outside_the_table_is_undeclared_not_discharged() {
        // The worst available answer would be to count it as covered: a crate
        // could then leave the lint table and its allows would become compliant.
        let manifests = BTreeMap::from([
            (
                "crates/inside/Cargo.toml".to_string(),
                "[lints]\nworkspace = true\n".to_string(),
            ),
            (
                "crates/outside/Cargo.toml".to_string(),
                "[package]\nname = \"outside\"\n".to_string(),
            ),
        ]);
        let corpus = BTreeMap::from([
            (
                "crates/inside/src/lib.rs".to_string(),
                "#[allow(dead_code)]\n#[expect(unused, reason = \"r\")]\nfn f() {}\n".to_string(),
            ),
            (
                "crates/outside/src/lib.rs".to_string(),
                "#[allow(dead_code)]\nfn g() {}\n".to_string(),
            ),
        ]);
        let r = report(&corpus, &manifests).expect("succeeds");
        assert_eq!(r.covered_allow, 1);
        assert_eq!(r.covered_expect, 1);
        assert_eq!(r.uncovered, 1, "the outside allow is undeclared");
    }

    #[test]
    fn an_empty_lint_table_is_refused_rather_than_scored() {
        let manifests =
            BTreeMap::from([("crates/a/Cargo.toml".to_string(), "[package]\n".to_string())]);
        let err = report(&BTreeMap::new(), &manifests).expect_err("no population, no ratio");
        assert!(err.to_string().contains("meaningless"), "{err}");
    }

    #[test]
    fn the_test_region_is_not_the_subject() {
        // An allow inside `#[cfg(test)]` waives a lint for test code, which is
        // not the mandate this family measures.
        let manifests = BTreeMap::from([(
            "crates/a/Cargo.toml".to_string(),
            "[lints]\nworkspace = true\n".to_string(),
        )]);
        let corpus = BTreeMap::from([(
            "crates/a/src/lib.rs".to_string(),
            "#[allow(dead_code)]\nfn f() {}\n#[cfg(test)]\nmod tests {\n    #[allow(unused)]\n    fn t() {}\n}\n".to_string(),
        )]);
        let r = report(&corpus, &manifests).expect("succeeds");
        assert_eq!(r.covered_allow, 1, "only the production allow");
    }

    #[test]
    fn the_report_maps_to_the_three_numbers_the_card_prints() {
        // An untested adapter is how a correct census reaches the card wrong.
        let c = Report {
            covered_allow: 129,
            covered_expect: 5,
            uncovered: 53,
        }
        .census();
        assert_eq!(c.population, 134, "allow + expect, inside the table");
        assert_eq!(c.discharged, 5, "only the ones that expire");
        assert_eq!(c.undeclared, 53, "outside the table, never discharged");
        assert_eq!(c.basis_points(), 373);
    }

    #[test]
    fn an_empty_report_is_zero_not_a_hundred() {
        assert_eq!(Report::default().census().basis_points(), 0);
    }
}

//! The `tot` family — a function whose type says total, that panics.
//!
//! # The defect
//!
//! Of the 120 audit-and-bug issues the 2026-09-11 census classified, 7 are this:
//! #1203, `FlowTracker::label(0)` panicking on a `u64` underflow because a
//! sentinel id was not guarded; #1184, `truncate()` panicking on multi-byte
//! UTF-8; #481, Ed25519 key generation panicking in a hot path via `.expect()`;
//! #2395, a `guest_cid` other than 3 panicking the guest with nothing saying so.
//!
//! A function whose signature says `-> T` and panics is lying about its type.
//! Nothing has to notice the specific panic: the lint family decides it.
//!
//! # The measurement, and why the gate does not take it
//!
//! Measured 2026-09-11 over the production region, reproducible with:
//!
//! ```sh
//! cargo clippy --workspace --exclude nucleus-verifier-service --lib --bins \
//!   --all-features --message-format=json -- \
//!   -W clippy::unwrap_used -W clippy::expect_used -W clippy::indexing_slicing \
//!   -W clippy::arithmetic_side_effects -W clippy::panic -W clippy::unreachable \
//!   -W clippy::todo -A clippy::all
//! ```
//!
//! | lint | sites |
//! |---|---|
//! | `arithmetic_side_effects` | 912 |
//! | `indexing_slicing` | 616 |
//! | `expect_used` | 155 |
//! | `unwrap_used` | 87 |
//! | `panic` | 10 |
//! | `unreachable` | 7 |
//! | `todo` | 0 |
//! | **total** | **1787** |
//!
//! That census takes minutes and this gate runs in the fast `Manifest Guards`
//! job, so the gate does not recompute it. It asks the *binding* question
//! instead, which is a grep: **how many production crates have declared
//! themselves panic-free?** A count of sites that nothing enforces is a
//! measurement; a crate-level `deny` is a gate.
//!
//! # Why `cfg_attr(not(test), deny(…))` and not `deny(…)`
//!
//! `assert!` is a panic. Denying the family inside `#[cfg(test)]` forbids the
//! thing tests are made of, and the numbers say so: of 13 crates measuring zero
//! over lib and bins, only **2** are also clean under `--all-targets`. The other
//! 11 are clean where it matters and panic in their own test modules, correctly.
//!
//! So the declaration is scoped to the shipped build. That is the same line
//! `law_mechanisms::production_region` already draws when it strips the test
//! region, and it is not a dodge: the defect class is a *production* function
//! that panics.
//!
//! # Unmeasurable crates are not clean crates
//!
//! Eighteen crates showed zero in the first census. Five of them showed zero
//! because **clippy never looked**: four are `exclude`d from the workspace
//! (`exposure-web`, `nucleus-marketplace-dashboard-frontend`,
//! `portcullis-python`, `portcullis-zkvm-guest` — wasm, maturin and RISC-V
//! targets built separately) and `nucleus-verifier-service` needs a wasm
//! artifact CI builds. Counting them as discharged would be ADR 0007 A-2
//! exactly: *"I could not look" is never "I looked and it was fine."*
//!
//! They are reported as `undeclared` — surface the denominator does not reach —
//! and the population is the 80 crates clippy can actually see.

use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};

use crate::scorecard::{Census, Family};

/// The lints the family is made of. A crate discharges the obligation by
/// denying **all** of them: six of seven is a crate that can still panic.
pub const LINTS: [&str; 7] = [
    "clippy::unwrap_used",
    "clippy::expect_used",
    "clippy::indexing_slicing",
    "clippy::arithmetic_side_effects",
    "clippy::panic",
    "clippy::unreachable",
    "clippy::todo",
];

/// Crates clippy cannot reach, and why. Each must be a real workspace `exclude`
/// or a documented build blocker; a crate on this list is neither discharged nor
/// counted against the ratio.
///
/// This is a hand-list, which is normally the shape of a gate that cannot fail.
/// It is bounded here by being checked against the tree: `unmeasurable_rows`
/// refuses an entry naming a crate that does not exist, so it can go stale in
/// only one direction and that direction is caught.
pub const UNMEASURABLE: [(&str, &str); 5] = [
    (
        "exposure-web",
        "workspace exclude: wasm32-unknown-unknown only",
    ),
    (
        "nucleus-marketplace-dashboard-frontend",
        "workspace exclude: Leptos CSR, built with trunk",
    ),
    ("portcullis-python", "workspace exclude: requires maturin"),
    (
        "portcullis-zkvm-guest",
        "workspace exclude: RISC-V guest, built by risc0-build",
    ),
    (
        "nucleus-verifier-service",
        "needs a wasm artifact CI builds; excluded from the clippy invocation",
    ),
];

/// Does `src` carry a crate-level denial of the whole family?
///
/// Accepts `deny` and `forbid`, bare or under any `cfg_attr`, because the
/// question is whether the shipped build refuses the lint and not how the author
/// spelled it. Requires **every** lint in [`LINTS`]: a partial denial leaves a
/// way to panic, and crediting it would make the ratio mean "mostly".
pub fn declares_totality(src: &str) -> bool {
    // Inner attributes only, and only the ones that deny. A `#[allow]` naming
    // the same lints must not read as a declaration.
    let denies: String = src
        .split("#![")
        .skip(1)
        .filter(|chunk| {
            let head = chunk.split(']').next().unwrap_or("");
            head.contains("deny") || head.contains("forbid")
        })
        .collect();
    LINTS.iter().all(|l| denies.contains(l))
}

/// Every crate with at least one production source file.
pub fn production_crates(corpus: &BTreeMap<String, String>) -> BTreeSet<String> {
    corpus
        .keys()
        .filter_map(|p| p.strip_prefix("crates/"))
        .filter_map(|r| r.split('/').next())
        .map(str::to_string)
        .collect()
}

/// Crates whose crate root declares the family.
pub fn declaring_crates(corpus: &BTreeMap<String, String>) -> BTreeSet<String> {
    corpus
        .iter()
        .filter(|(p, src)| {
            (p.ends_with("/src/lib.rs") || p.ends_with("/src/main.rs")) && declares_totality(src)
        })
        .filter_map(|(p, _)| p.strip_prefix("crates/"))
        .filter_map(|r| r.split('/').next())
        .map(str::to_string)
        .collect()
}

/// The unmeasurable crates that actually exist in the tree.
///
/// An entry naming a crate with no production source is a stale row and an
/// error: it would shrink the denominator for a crate that is not there.
pub fn unmeasurable_rows(present: &BTreeSet<String>) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for (name, why) in UNMEASURABLE {
        if !present.contains(name) {
            anyhow::bail!(
                "UNMEASURABLE names `{name}` ({why}) and no crate by that name has a production \
                 source file. A stale row shrinks the denominator for a crate that is not there; \
                 delete it."
            );
        }
        out.insert(name.to_string());
    }
    Ok(out)
}

pub struct Tot;

impl Family for Tot {
    fn name(&self) -> &'static str {
        "tot"
    }

    fn unit(&self) -> &'static str {
        "production crate"
    }

    fn census(&self, corpus: &BTreeMap<String, String>) -> Result<Census> {
        let present = production_crates(corpus);
        let unreachable = unmeasurable_rows(&present)?;
        let population = present.difference(&unreachable).count();
        let discharged = declaring_crates(corpus).difference(&unreachable).count();
        Ok(Census {
            population,
            discharged,
            undeclared: unreachable.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_seven(kind: &str) -> String {
        format!("#![{kind}({})]\n", LINTS.join(", "))
    }

    #[test]
    fn a_bare_deny_of_every_lint_is_a_declaration() {
        assert!(declares_totality(&all_seven("deny")));
    }

    #[test]
    fn forbid_counts_too() {
        assert!(declares_totality(&all_seven("forbid")));
    }

    #[test]
    fn the_cfg_attr_form_the_tree_uses_counts() {
        let src = format!(
            "//! docs\n#![cfg_attr(not(test), deny(\n{}\n))]\n",
            LINTS.join(",\n")
        );
        assert!(declares_totality(&src));
    }

    #[test]
    fn six_of_seven_is_not_a_declaration() {
        // A partial denial leaves a way to panic; crediting it would make the
        // ratio mean "mostly".
        let src = format!("#![deny({})]\n", LINTS[..6].join(", "));
        assert!(!declares_totality(&src));
    }

    #[test]
    fn an_allow_naming_the_same_lints_is_not_a_declaration() {
        assert!(!declares_totality(&all_seven("allow")));
        assert!(!declares_totality(&all_seven("warn")));
    }

    #[test]
    fn a_crate_with_no_attribute_is_not_a_declaration() {
        assert!(!declares_totality("pub fn f() {}\n"));
    }

    #[test]
    fn only_a_crate_root_declares() {
        // A module deep in the crate cannot deny for the crate.
        let corpus = BTreeMap::from([("crates/demo/src/inner.rs".to_string(), all_seven("deny"))]);
        assert!(declaring_crates(&corpus).is_empty());
    }

    #[test]
    fn a_main_rs_declares_for_a_binary_crate() {
        let corpus = BTreeMap::from([("crates/demo/src/main.rs".to_string(), all_seven("deny"))]);
        assert_eq!(declaring_crates(&corpus).len(), 1);
    }

    #[test]
    fn an_unmeasurable_crate_is_neither_discharged_nor_counted() {
        // "I could not look" is never "I looked and it was fine" (A-2). The
        // four workspace excludes and nucleus-verifier-service showed zero in
        // the first census because clippy never ran on them.
        let mut corpus =
            BTreeMap::from([("crates/seen/src/lib.rs".to_string(), all_seven("deny"))]);
        for (name, _) in UNMEASURABLE {
            corpus.insert(format!("crates/{name}/src/lib.rs"), String::new());
        }
        let c = Tot.census(&corpus).expect("every unmeasurable row exists");
        assert_eq!(c.population, 1, "only the crate clippy can see");
        assert_eq!(c.discharged, 1);
        assert_eq!(c.undeclared, UNMEASURABLE.len());
        assert_eq!(c.basis_points(), 10_000);
    }

    #[test]
    fn an_unmeasurable_crate_that_declares_is_still_not_credited() {
        // Otherwise adding the attribute to a crate nothing compiles would raise
        // the ratio for free.
        let mut corpus = BTreeMap::new();
        for (name, _) in UNMEASURABLE {
            corpus.insert(format!("crates/{name}/src/lib.rs"), all_seven("deny"));
        }
        corpus.insert("crates/seen/src/lib.rs".to_string(), String::new());
        let c = Tot.census(&corpus).expect("rows exist");
        assert_eq!(
            c.discharged, 0,
            "a crate clippy cannot check discharges nothing"
        );
        assert_eq!(c.population, 1);
    }

    #[test]
    fn a_stale_unmeasurable_row_is_an_error_not_a_smaller_denominator() {
        let corpus = BTreeMap::from([("crates/only/src/lib.rs".to_string(), String::new())]);
        let err = Tot
            .census(&corpus)
            .expect_err("the rows name absent crates");
        assert!(err.to_string().contains("delete it"), "{err}");
    }
}

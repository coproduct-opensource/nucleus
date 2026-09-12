//! The `typed` family — how much of the runtime IFC is a compile error.
//!
//! # The mechanism already exists and is already proven
//!
//! `portcullis_core::labeled` encodes a Denning-style security lattice in the
//! trait system: `Labeled<T, I: IntegTag, C: ConfTag>`, with
//! `Trusted/Untrusted/Adversarial` crossed with `Public/Internal/Secret`. Its
//! own `compile_fail` doctest proves the thing that matters —
//!
//! ```text
//! fn publish<C: ConfAtMost<Public>>(_v: Labeled<String, Trusted, C>) {}
//! let key: Labeled<String, Trusted, Secret> = Labeled::new(..);
//! publish(key); // ERROR: Secret does not implement ConfAtMost<Public>
//! ```
//!
//! — and that is a compile error, not a check anyone has to reach. It is the
//! same construction the 2026 literature calls Denning-style IFC in Rust's type
//! system, built here already.
//!
//! It is applied to **two** of the twenty-four kinds `NodeKind` distinguishes.
//! The other twenty-two are tracked by `FlowTracker` at runtime. Runtime
//! tracking is sound and it is also a check, which means it has to be reached:
//! `nucleus-observed-lint` exists precisely because an ingest path can forget to
//! call `observe`, and its own doc names the defect it was built from — `/v1/run`
//! returned arbitrary subprocess stdout and observed nothing.
//!
//! A kind that is lifted cannot forget. That is the whole difference, and this
//! family is the fraction.
//!
//! # Why a lint and a type system are not the same tool
//!
//! A dylint pass can decide **adoption**: does every function in the ingest
//! closure return a labelled type? That is a `typeck` question over a bounded
//! set of paths, and `nucleus-observed-lint` already answers the runtime
//! equivalent with a reachability closure over `AGENT_ROOTS`.
//!
//! It cannot decide **the invariant**. "No `Secret` value reaches a `Public`
//! sink, through any composition of functions anyone writes later" is not a
//! bounded search; it is exactly what parametric polymorphism gives for free
//! once the data is inside the typed region.
//!
//! So they compose rather than compete: **the lint guards the frontier of the
//! typed region, and the types guard its interior.** The useful consequence is
//! that this family and `observed` move in opposite directions — every kind
//! lifted here is a path `observed` no longer has to police, and its ceiling
//! should fall as this ratio rises.
//!
//! # Population and discharge
//!
//! * **population** — the variants of `NodeKind`, the runtime taxonomy, minus
//!   `Custom`, which is an escape hatch rather than a kind of data.
//! * **discharged** — the rows of `LIFTED_TO_TYPES`, each checked to name a type
//!   that exists and carries a `Labeled<` field, so a row cannot buy a point
//!   without the type behind it.
//! * **undeclared** — zero. Unlike `bound` and `alg`, there is no shape-without-
//!   declaration here: a kind is in the enum or it is not, and reporting a guess
//!   would be worse than reporting none.

use anyhow::{Result, bail};
use std::collections::BTreeMap;

use crate::scorecard::{Census, Family};

/// The runtime taxonomy lives here.
const FLOW: &str = "crates/nucleus-ifc-kernel/src/flow.rs";

/// The registry of lifts lives here, beside the types it names.
const RUNTIME: &str = "crates/portcullis-effects/src/runtime.rs";

/// `Custom` is an escape hatch, not a kind of data: it carries a caller-supplied
/// string and cannot be given a fixed pair of tags. Excluded by name rather than
/// silently, the way `convergence` excludes its two unmeasurable arrows.
const NOT_A_KIND: [&str; 1] = ["Custom"];

/// The variants of `NodeKind`.
pub fn kinds(src: &str) -> Vec<String> {
    let Some(start) = src.find("pub enum NodeKind") else {
        return Vec::new();
    };
    let body = &src[start..];
    let end = body.find("\n}").map_or(body.len(), |i| i + 1);
    body[..end]
        .lines()
        .skip(1)
        .filter_map(|l| {
            let t = l.trim();
            if t.starts_with("//") || t.starts_with('#') {
                return None;
            }
            let name: String = t
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect();
            let first = name.chars().next()?;
            (first.is_ascii_uppercase() && !NOT_A_KIND.contains(&name.as_str())).then_some(name)
        })
        .collect()
}

/// The `(NodeKind, output type)` rows of `LIFTED_TO_TYPES`.
pub fn lifts(src: &str) -> Vec<(String, String)> {
    let Some(start) = src.find("pub const LIFTED_TO_TYPES") else {
        return Vec::new();
    };
    let body = &src[start..];
    let end = body.find("];").map_or(body.len(), |i| i);
    let mut out = Vec::new();
    let mut rest = &body[..end];
    while let Some(i) = rest.find("(\"") {
        rest = &rest[i + 2..];
        let Some(j) = rest.find('"') else { break };
        let kind = rest[..j].to_string();
        let after = &rest[j..];
        let Some(k) = after.find("\"") else { break };
        let tail = &after[k + 1..];
        let Some(m) = tail.find('"') else { break };
        let Some(n) = tail[m + 1..].find('"') else {
            break;
        };
        out.push((kind, tail[m + 1..m + 1 + n].to_string()));
        rest = &tail[m + 1 + n..];
    }
    out
}

/// Does `ty` exist in `src` and carry a `Labeled<` field?
///
/// The anti-over-claim check: a registry row naming a type that does not label
/// its data would otherwise buy a point for nothing.
pub fn labels_its_data(src: &str, ty: &str) -> bool {
    let Some(i) = src.find(&format!("pub struct {ty} {{")) else {
        return false;
    };
    let body = &src[i..];
    let end = body.find("\n}").map_or(body.len(), |j| j);
    body[..end].contains("Labeled<")
}

pub struct Typed;

impl Family for Typed {
    fn name(&self) -> &'static str {
        "typed"
    }

    fn unit(&self) -> &'static str {
        "runtime flow kind"
    }

    fn census(&self, corpus: &BTreeMap<String, String>) -> Result<Census> {
        let flow = corpus
            .get(FLOW)
            .ok_or_else(|| anyhow::anyhow!("{FLOW} is not in the production corpus"))?;
        let runtime = corpus
            .get(RUNTIME)
            .ok_or_else(|| anyhow::anyhow!("{RUNTIME} is not in the production corpus"))?;

        let kinds = kinds(flow);
        if kinds.is_empty() {
            bail!(
                "no NodeKind variants found in {FLOW}. The population would be zero and the \
                 ratio meaningless — the enum moved or was renamed."
            );
        }

        let mut discharged = 0usize;
        for (kind, ty) in lifts(runtime) {
            if !kinds.contains(&kind) {
                bail!(
                    "LIFTED_TO_TYPES names NodeKind::{kind}, which is not a variant. A stale row \
                     discharges an obligation that does not exist."
                );
            }
            if !labels_its_data(runtime, &ty) {
                bail!(
                    "LIFTED_TO_TYPES says {ty} lifts NodeKind::{kind}, but {ty} carries no \
                     `Labeled<` field. A row cannot buy a point without the type behind it."
                );
            }
            discharged += 1;
        }

        Ok(Census {
            population: kinds.len(),
            discharged,
            // A kind is in the enum or it is not. There is no shape-without-
            // declaration here, and a guess would be worse than nothing.
            undeclared: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENUM: &str = "pub enum NodeKind {\n    UserPrompt,\n    WebContent,\n    /// doc\n    FileRead,\n    Custom(String),\n}\n";

    #[test]
    fn the_variants_are_the_population() {
        assert_eq!(kinds(ENUM), vec!["UserPrompt", "WebContent", "FileRead"]);
    }

    #[test]
    fn custom_is_an_escape_hatch_not_a_kind() {
        // It carries a caller-supplied string and cannot take a fixed pair of
        // tags, so counting it would put an undischargeable obligation in the
        // denominator forever.
        assert!(!kinds(ENUM).contains(&"Custom".to_string()));
    }

    #[test]
    fn a_doc_comment_is_not_a_variant() {
        assert!(!kinds(ENUM).iter().any(|k| k == "doc"));
    }

    #[test]
    fn the_registry_parses() {
        let src = "pub const LIFTED_TO_TYPES: [(&str, &str); 2] = [\n    // c\n    (\"FileRead\", \"ReadOutput\"),\n    (\"WebContent\", \"FetchOutput\"),\n];\n";
        assert_eq!(
            lifts(src),
            vec![
                ("FileRead".into(), "ReadOutput".into()),
                ("WebContent".into(), "FetchOutput".into())
            ]
        );
    }

    #[test]
    fn a_type_without_a_labeled_field_does_not_discharge() {
        let src = "pub struct Bare {\n    data: Vec<u8>,\n}\n";
        assert!(!labels_its_data(src, "Bare"));
        let ok = "pub struct Tagged {\n    data: Labeled<Vec<u8>, Trusted, Internal>,\n}\n";
        assert!(labels_its_data(ok, "Tagged"));
    }

    fn corpus(flow: &str, runtime: &str) -> BTreeMap<String, String> {
        BTreeMap::from([
            (FLOW.to_string(), flow.to_string()),
            (RUNTIME.to_string(), runtime.to_string()),
        ])
    }

    #[test]
    fn the_census_is_lifts_over_kinds() {
        let runtime = "pub const LIFTED_TO_TYPES: [(&str, &str); 1] = [\n    (\"WebContent\", \"FetchOutput\"),\n];\npub struct FetchOutput {\n    data: Labeled<Vec<u8>, Adversarial, Public>,\n}\n";
        let c = Typed.census(&corpus(ENUM, runtime)).expect("succeeds");
        assert_eq!(c.population, 3);
        assert_eq!(c.discharged, 1);
        assert_eq!(c.undeclared, 0);
    }

    #[test]
    fn a_row_naming_a_type_that_does_not_label_is_refused() {
        let runtime = "pub const LIFTED_TO_TYPES: [(&str, &str); 1] = [\n    (\"WebContent\", \"Bare\"),\n];\npub struct Bare {\n    data: Vec<u8>,\n}\n";
        let err = Typed
            .census(&corpus(ENUM, runtime))
            .expect_err("a row cannot buy a point without the type behind it");
        assert!(err.to_string().contains("carries no"), "{err}");
    }

    #[test]
    fn a_row_naming_a_variant_that_does_not_exist_is_refused() {
        let runtime = "pub const LIFTED_TO_TYPES: [(&str, &str); 1] = [\n    (\"Ghost\", \"FetchOutput\"),\n];\npub struct FetchOutput {\n    data: Labeled<Vec<u8>, Adversarial, Public>,\n}\n";
        let err = Typed
            .census(&corpus(ENUM, runtime))
            .expect_err("a stale row discharges nothing");
        assert!(err.to_string().contains("not a variant"), "{err}");
    }

    #[test]
    fn an_empty_taxonomy_is_refused_rather_than_scored() {
        let err = Typed
            .census(&corpus("pub enum Other {}", ""))
            .expect_err("no population means no ratio");
        assert!(
            err.to_string().contains("population would be zero"),
            "{err}"
        );
    }
}

//! `nucleus-action-key` — derive a CI gate's receipt key, or say why it has none.

// TOTALITY: a function whose signature says `-> T` and panics is lying about
// its type. All seven lints, denied for the shipped build only — `assert!` IS
// a panic, so denying inside `#[cfg(test)]` would forbid the thing tests are
// made of. Measured zero of all seven before adding this, per `clippy.toml`'s
// rule that an entry is added only when the tree is already clean of it.
//
// It matters more here than in most crates: this one decides whether a receipt
// may be REUSED. A panic in the key derivation is a gate that could not look,
// and the whole design turns on never confusing that with a gate that looked.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic,
        clippy::unreachable,
        clippy::todo
    )
)]

use anyhow::Result;
use nucleus_action_key::census::{self, Outcome};
use nucleus_action_key::{closure, derive};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn main() -> Result<()> {
    let root = std::env::var("NUCLEUS_REPO_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));

    // `--crates` reports the DERIVED read-sets: one per workspace crate, from
    // `cargo metadata`'s dependency graph rather than a hand-written `paths:`
    // filter. Every crate has one, which is the point — the 37 contexts the
    // context census refuses for want of a declaration need no declaration
    // here.
    if std::env::args().nth(1).as_deref() == Some("--crates") {
        return crates_report(&root);
    }

    let census = census::run(&root)?;

    let mut keyed: Vec<&Outcome> = Vec::new();
    let mut refused: Vec<&Outcome> = Vec::new();
    let mut unmeasured: Vec<&Outcome> = Vec::new();
    for o in &census.outcomes {
        match o {
            Outcome::Keyed { .. } => keyed.push(o),
            Outcome::Refused(_) => refused.push(o),
            Outcome::Unmeasured { .. } => unmeasured.push(o),
        }
    }

    println!("KEYED ({})", keyed.len());
    for o in &keyed {
        if let Outcome::Keyed {
            context,
            key,
            reads,
            gate_files,
        } = o
        {
            println!(
                "  {:.16}  {reads:>5} read  {gate_files:>2} gate  {context}",
                key.to_hex()
            );
        }
    }

    println!("\nNO KEY ({})", refused.len());
    for o in &refused {
        if let Outcome::Refused(r) = o {
            println!("  {r}");
        }
    }

    if !unmeasured.is_empty() {
        println!("\nCOULD NOT LOOK ({})", unmeasured.len());
        for o in &unmeasured {
            if let Outcome::Unmeasured { context, why } = o {
                println!("  {context}: {why}");
            }
        }
    }

    println!(
        "\n{} required context(s): {} keyed, {} refused, {} unmeasured",
        census.outcomes.len(),
        census.keyed(),
        census.refused(),
        census.unmeasured()
    );
    // Exit 2 for "could not look" — the third state ci-spec keeps and for the
    // same reason: an unreadable filter reported as a clean refusal is the
    // vacuity these gates exist to find.
    if census.unmeasured() > 0 {
        std::process::exit(2);
    }
    Ok(())
}

/// One line per crate: how many crates its closure spans and how many files
/// that is, widest first.
fn crates_report(root: &Path) -> Result<()> {
    let ws = closure::load(root)?;
    let tracked = derive::tracked_files(root)?;
    let mut rows: Vec<(usize, usize, &String)> = Vec::new();
    for name in ws.closures.keys() {
        let files = ws.read_set(root, &tracked, name)?.len();
        let span = ws.closures.get(name).map_or(0, BTreeSet::len);
        rows.push((span, files, name));
    }
    rows.sort_unstable();
    rows.reverse();
    println!(
        "{} crate(s), {} tracked file(s) in the tree",
        rows.len(),
        tracked.len()
    );
    println!("{:>6}  {:>6}  crate", "closure", "files");
    for (span, files, name) in &rows {
        println!("{span:>6}  {files:>6}  {name}");
    }
    Ok(())
}

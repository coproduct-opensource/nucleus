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
use std::path::PathBuf;

fn main() -> Result<()> {
    let root = std::env::var("NUCLEUS_REPO_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));

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

//! A blast radius, printed the way an underwriter reads it.
//!
//! Mints a permissive root certificate, delegates a narrower one to an agent,
//! and prints both radii — then shows that the leaf's claim recomputes and
//! that a widened claim does not.
//!
//! ```sh
//! cargo run -q -p nucleus-blast-radius --example radius
//! ```

use chrono::{Duration, Utc};
use nucleus_blast_radius::{BlastRadius, issue, verify};
use portcullis::certificate::LatticeCertificate;
use portcullis::{CapabilityLattice, CapabilityLevel, Operation, PermissionLattice};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

fn show(title: &str, r: &BlastRadius) {
    println!("{title}");
    println!("  holder            {}", r.leaf_identity);
    println!("  spend ceiling     {} µUSD", r.max_spend_micro);
    println!("  autonomous        {:?}", r.autonomous);
    println!("  low-risk          {:?}", r.low_risk);
    println!("  human-gated       {:?}", r.human_gated);
    println!("  denied            {:?}", r.denied);
    println!(
        "  lethal trifecta   reachable={} gated={}{}",
        r.trifecta_reachable,
        r.trifecta_gated,
        if r.trifecta_ungated() {
            "  <-- DECLINE"
        } else {
            ""
        }
    );
    println!(
        "  sinks             hosts={:?} paths={:?} refs={:?}  (empty = unrestricted)",
        r.allowed_hosts, r.allowed_paths, r.allowed_git_refs
    );
    println!("  valid until       {}", r.valid_until);
    println!("  chain depth       {}", r.chain_depth);
    println!();
}

fn main() {
    let rng = SystemRandom::new();
    let Ok(pkcs8) = Ed25519KeyPair::generate_pkcs8(&rng) else {
        eprintln!("could not generate a root key");
        std::process::exit(2);
    };
    let Ok(root_key) = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()) else {
        eprintln!("could not parse the root key");
        std::process::exit(2);
    };
    let until = Utc::now() + Duration::hours(8);

    let mut root_lattice = PermissionLattice::new("platform root");
    root_lattice.capabilities = CapabilityLattice::permissive();
    root_lattice.budget.max_cost_usd = "250.00".parse().unwrap_or_default();
    let (root, holder) = LatticeCertificate::mint(
        root_lattice,
        "spiffe://example.org/platform".into(),
        until,
        &root_key,
        &rng,
    );

    let mut agent_lattice = PermissionLattice::new("pr-fixer");
    agent_lattice.capabilities = CapabilityLattice::permissive();
    agent_lattice.capabilities.git_push = CapabilityLevel::Never;
    agent_lattice.capabilities.spawn_agent = CapabilityLevel::Never;
    agent_lattice.capabilities.web_fetch = CapabilityLevel::LowRisk;
    agent_lattice.budget.max_cost_usd = "12.50".parse().unwrap_or_default();
    agent_lattice.obligations.insert(Operation::CreatePr);
    let Ok((leaf, _)) = root.delegate(
        &agent_lattice,
        "spiffe://example.org/agents/pr-fixer".into(),
        until - Duration::hours(1),
        &holder,
        &rng,
    ) else {
        eprintln!("delegation refused");
        std::process::exit(2);
    };

    let now = Utc::now();
    let pk = root_key.public_key();
    let (Ok(root_claim), Ok(leaf_claim)) = (
        issue(root, pk.as_ref(), now, 8),
        issue(leaf, pk.as_ref(), now, 8),
    ) else {
        eprintln!("a chain did not verify");
        std::process::exit(2);
    };

    show("ROOT AUTHORITY", &root_claim.claimed);
    show("DELEGATED AGENT", &leaf_claim.claimed);

    println!("leaf claim recomputes?   {:?}", verify(&leaf_claim));
    let mut widened = leaf_claim;
    widened.claimed.autonomous.push(Operation::GitPush);
    println!("widened claim recomputes? {:?}", verify(&widened));
}

//! `xtask` — the workspace task runner.
//!
//! Rust-native replacement for ad-hoc shell scripts, invoked as `cargo xtask
//! <command>` (via the `.cargo/config.toml` alias) and fronted by `just`
//! recipes. Per the repo's "Rust-based tooling first" convention, build/CI/dev
//! orchestration that lives in `scripts/*.sh` is migrated here one command at a
//! time, so it is cross-platform, type-checked, and testable.
//!
//! Scripts that must stay shell — anything that runs *inside* the Firecracker
//! guest or at boot, in-container smoke tests, the GitHub-action entrypoint, and
//! the curl-bootstrap installer — are intentionally NOT ported.
//!
//! This first commit is the harness plus one read-only command (`scripts`),
//! which inventories the shell scripts and flags which are port candidates —
//! i.e. it tracks its own migration backlog. Subsequent commits port one
//! orchestration script per change.

use std::process::Command as ProcessCommand;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "xtask",
    about = "Nucleus workspace task runner (cargo xtask <command>)",
    long_about = "Rust-native dev/CI task runner. Run via `cargo xtask <command>` \
                  or `just xtask <command>`. Shell scripts are migrated here over \
                  time; see `cargo xtask scripts` for the remaining backlog."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Inventory repo shell scripts and flag which are xtask port candidates.
    Scripts,
    /// Build every workspace crate in isolation (`cargo build -p <crate>`) to
    /// catch feature-unification-masked breakages — crates that compile in a
    /// full `--workspace` build but fail standalone (and on `cargo publish`)
    /// because a dependency feature is only enabled by a sibling crate.
    ///
    /// This is the bug class that hid the `nucleus-fly-oidc` missing-`json`
    /// reqwest feature and the `portcullis` `default-features = false` break.
    CheckIsolation,
    /// Constitutional gate (most-paranoid #5): run ck-kernel admission on a
    /// PolicyManifest amendment. Exits non-zero if the candidate is non-monotone
    /// (capability/IO/budget/proof-req escalation, anti-coup) or touches a
    /// `may_not_modify` path. This is the in-repo replacement for the external
    /// closed "Constitutional Gate" — the kernel is now actually invoked.
    PolicyGate {
        /// Path to the base (parent) PolicyManifest.toml.
        #[arg(long)]
        base: String,
        /// Path to the candidate (head) PolicyManifest.toml.
        #[arg(long)]
        candidate: String,
        /// Optional path to a newline-delimited list of changed repo files
        /// (checked against the parent's `may_not_modify` rules).
        #[arg(long)]
        changed_files: Option<String>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Scripts => scripts(),
        Command::CheckIsolation => check_isolation(),
        Command::PolicyGate {
            base,
            candidate,
            changed_files,
        } => policy_gate(&base, &candidate, changed_files.as_deref()),
    }
}

/// Gate a PolicyManifest amendment through the constitutional kernel (Preflight
/// mode: monotonicity + `may_not_modify`, signatures skipped). Exits the process
/// with code 1 on rejection so CI fails the PR.
fn policy_gate(base: &str, candidate: &str, changed_files: Option<&str>) -> Result<()> {
    use ck_kernel::{gate_manifest_amendment, GateMode};
    use ck_types::{AdmissionDecision, PolicyManifest};

    let base_src =
        std::fs::read_to_string(base).with_context(|| format!("reading base manifest {base}"))?;
    let cand_src = std::fs::read_to_string(candidate)
        .with_context(|| format!("reading candidate manifest {candidate}"))?;
    let parent = PolicyManifest::from_toml(&base_src)
        .map_err(|e| anyhow!("parsing base manifest {base}: {e}"))?;
    let cand = PolicyManifest::from_toml(&cand_src)
        .map_err(|e| anyhow!("parsing candidate manifest {candidate}: {e}"))?;

    let files: Vec<String> = match changed_files {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("reading changed-files list {path}"))?
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect(),
        None => Vec::new(),
    };

    let outcome = gate_manifest_amendment(&parent, &cand, &files, GateMode::Preflight);
    match outcome.decision {
        AdmissionDecision::Accepted { .. } => {
            println!(
                "constitutional gate: PolicyManifest amendment ACCEPTED \
                 (monotone; may_not_modify respected)"
            );
            Ok(())
        }
        AdmissionDecision::Rejected { reasons } => {
            eprintln!("constitutional gate: PolicyManifest amendment REJECTED");
            for r in &reasons {
                eprintln!("  - {:?}: {}", r.invariant, r.message);
            }
            std::process::exit(1);
        }
        other => {
            // Quarantined / Expired — not an acceptance; fail the gate.
            eprintln!("constitutional gate: amendment NOT accepted: {other:?}");
            std::process::exit(1);
        }
    }
}

/// Shell scripts that must remain shell (run in the guest/at boot, in a
/// container, as the GH-action entrypoint, or as a curl-bootstrap installer).
/// Matched by path suffix.
const KEEP_AS_SHELL: &[&str] = &[
    "scripts/firecracker/guest-init.sh",
    "scripts/firecracker/guest-net.sh",
    "scripts/firecracker/build-rootfs.sh",
    "scripts/firecracker/build-scratch.sh",
    "scripts/container/smoke-test.sh",
    "scripts/action-entrypoint.sh",
    "scripts/install.sh",
];

/// Walk the repo (skipping `target/`, `.git/`, `node_modules/`) and list every
/// `*.sh`, marking each as a port candidate or "keep as shell".
fn scripts() -> Result<()> {
    let root = repo_root()?;
    let mut found = Vec::new();
    collect_sh(&root, &root, &mut found)?;
    found.sort();

    let (keep, port): (Vec<_>, Vec<_>) = found
        .iter()
        .partition(|rel| KEEP_AS_SHELL.iter().any(|k| rel.ends_with(k)));

    println!("Shell scripts ({} total)\n", found.len());
    println!("  PORT CANDIDATES → xtask + just ({}):", port.len());
    for p in &port {
        println!("    [ ] {p}");
    }
    println!("\n  KEEP AS SHELL ({}):", keep.len());
    for k in &keep {
        println!("    [x] {k}");
    }
    Ok(())
}

/// The workspace root = parent of this crate's manifest dir's parent
/// (`crates/xtask` → `crates` → root).
fn repo_root() -> Result<std::path::PathBuf> {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .ancestors()
        .nth(2)
        .map(|p| p.to_path_buf())
        .ok_or_else(|| anyhow::anyhow!("could not locate workspace root from {manifest:?}"))
}

fn collect_sh(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if path.is_dir() {
            // Skip build output, vendored trees, and any dot-dir (.git, .venv,
            // .lake, .verus, …) so the inventory shows only first-party scripts.
            if name.starts_with('.')
                || matches!(name, "target" | "node_modules" | "dist" | "vendor")
            {
                continue;
            }
            collect_sh(root, &path, out)?;
        } else if name.ends_with(".sh") {
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(rel.to_string_lossy().into_owned());
            }
        }
    }
    Ok(())
}

// ── check-isolation ──────────────────────────────────────────────────────────

/// Parse the package names of the workspace members out of
/// `cargo metadata --no-deps --format-version 1` output.
///
/// With `--no-deps`, the `packages` array contains exactly the workspace
/// members, so their `name` fields are the set we want to build in isolation.
/// Pure (no I/O) so it is unit-testable against a fixture.
fn parse_member_names(metadata_json: &str) -> Result<Vec<String>> {
    let value: serde_json::Value =
        serde_json::from_str(metadata_json).context("parsing cargo metadata JSON")?;
    let packages = value
        .get("packages")
        .and_then(|p| p.as_array())
        .ok_or_else(|| anyhow!("cargo metadata: missing `packages` array"))?;
    let mut names: Vec<String> = packages
        .iter()
        .filter_map(|pkg| pkg.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect();
    names.sort();
    names.dedup();
    Ok(names)
}

/// Build every workspace crate on its own with `cargo build -p <crate>` and
/// report which fail standalone. Exits non-zero if any crate fails, so it can
/// gate locally or in a (non-fast) CI lane.
fn check_isolation() -> Result<()> {
    let root = repo_root()?;

    let metadata = ProcessCommand::new("cargo")
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(&root)
        .output()
        .context("running `cargo metadata`")?;
    if !metadata.status.success() {
        return Err(anyhow!(
            "`cargo metadata` failed:\n{}",
            String::from_utf8_lossy(&metadata.stderr)
        ));
    }
    let names = parse_member_names(&String::from_utf8_lossy(&metadata.stdout))?;

    println!(
        "Building {} workspace crates in isolation (cargo build -p <crate>)...\n",
        names.len()
    );
    println!(
        "Note: crates with their OWN [workspace] (e.g. portcullis-zkvm-guest) are\n\
         not workspace members and are not swept here.\n"
    );

    let mut failed: Vec<String> = Vec::new();
    for name in &names {
        let status = ProcessCommand::new("cargo")
            .args(["build", "-p", name, "--quiet"])
            .current_dir(&root)
            .status()
            .with_context(|| format!("running `cargo build -p {name}`"))?;
        if status.success() {
            println!("  ok    {name}");
        } else {
            println!("  FAIL  {name}");
            failed.push(name.clone());
        }
    }

    if failed.is_empty() {
        println!("\nAll {} crates build standalone.", names.len());
        Ok(())
    } else {
        Err(anyhow!(
            "{} crate(s) fail to build in isolation (compile in --workspace but not \
             standalone — usually a missing dependency feature only enabled by a \
             sibling crate): {}",
            failed.len(),
            failed.join(", ")
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::parse_member_names;

    #[test]
    fn parses_and_sorts_member_names() {
        let json = r#"{
            "packages": [
                {"name": "portcullis", "version": "1.0.0"},
                {"name": "nucleus-sdk", "version": "1.0.0"},
                {"name": "nucleus-envelope", "version": "1.0.0"}
            ],
            "workspace_members": []
        }"#;
        let names = parse_member_names(json).unwrap();
        assert_eq!(names, ["nucleus-envelope", "nucleus-sdk", "portcullis"]);
    }

    #[test]
    fn errors_when_packages_array_missing() {
        assert!(parse_member_names(r#"{"workspace_members": []}"#).is_err());
    }

    #[test]
    fn errors_on_invalid_json() {
        assert!(parse_member_names("not json").is_err());
    }
}

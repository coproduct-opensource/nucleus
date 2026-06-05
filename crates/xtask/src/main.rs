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

use anyhow::Result;
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
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Scripts => scripts(),
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

//! The configuration that constrains an agent must not be writable by it.
//!
//! # The asymmetry this closes (#2782)
//!
//! `nucleus audit` treats agent-harness configuration as security-critical and
//! scans it for plaintext credentials, dangerous commands and trifecta
//! exposure — `nucleus-cli`'s `MCP_CONFIG_CANDIDATES` names six such files.
//! Before this, `grep -rln '\.claude|\.mcp\.json|\.cursor'` over
//! `portcullis/profiles/*.yaml` returned **nothing**: none of the eleven
//! canonical profiles mentioned any of them.
//!
//! So the same files were security-relevant enough to audit and unprotected
//! against being written by the agent whose permissions they configure.
//! `codegen` — the profile a coding agent would pick — has
//! `write_files: low_risk` and blocked credential material (`**/.ssh/**`,
//! `**/.env`, `/etc/shadow`) but nothing about harness config.
//!
//! The concrete shape: an integration that mediates an agent by installing a
//! hook in `.claude/settings.json` puts the mechanism that constrains the agent
//! inside the tree the agent may write. Removing a hook disables mediation;
//! rewriting `.mcp.json` is worse, because it can add an **unmediated** server.
//!
//! # Why a floor, and why this test
//!
//! The fix is a floor in `profile.rs` — `AGENT_HARNESS_CONFIG` unioned into
//! every profile's blocked set as it becomes a `PathLattice` — rather than a
//! line added to eleven YAML files. Those per-profile lists had **already
//! drifted**: five of the six write-permitting profiles blocked `/etc/passwd`
//! and `doc-editor` did not, which is the same two-copies failure
//! `profile_namespace_parity.rs` was written for.
//!
//! A floor cannot be forgotten by a new profile or removed by editing one YAML
//! file, so this test is not what makes the property true. It pins that the
//! floor is reached through the resolver a pod spec actually hits, and that the
//! block list and the audit list cannot drift apart.

// `profile` is behind the `spec` feature. CI lints portcullis TWICE -- once
// `--all-features`, once at its own defaults (#2746) -- precisely because
// feature unification hides this: the registry tests below cannot compile
// without `spec`, while the two that check the floor itself need nothing and
// stay available at default features.
#[cfg(feature = "spec")]
use portcullis::profile::ProfileRegistry;
use portcullis::{glob_match, AGENT_HARNESS_CONFIG};

/// Representative real paths, one per file `nucleus audit` looks for.
///
/// These are the literal `MCP_CONFIG_CANDIDATES` entries, placed under a
/// plausible checkout root — the exact strings the audit scans for, so a floor
/// that misses one would be auditing a file it does not protect.
const AUDITED_FILES: &[&str] = &[
    "/work/repo/.claude/settings.json",
    "/work/repo/.mcp.json",
    "/work/repo/mcp.json",
    "/work/repo/.vscode/mcp.json",
    "/work/repo/.cursor/mcp.json",
    "/work/repo/claude_desktop_config.json",
];

fn blocks(patterns: &[String], path: &str) -> bool {
    patterns.iter().any(|p| glob_match(p, path))
}

/// The property: every profile, not just the ones that permit writes.
///
/// A `write_files: never` profile blocking these too is free — the floor costs
/// nothing where writes are already refused, and a profile's write posture can
/// be raised later by an edit that would otherwise silently uncover them.
#[cfg(feature = "spec")]
#[test]
fn every_profile_blocks_the_configuration_that_configures_the_agent() {
    let registry = ProfileRegistry::default();
    let mut gaps = Vec::new();

    for name in registry.names() {
        let lattice = registry
            .resolve(name)
            .unwrap_or_else(|e| panic!("`{name}` must resolve: {e}"));
        let blocked: Vec<String> = lattice.paths.blocked.iter().cloned().collect();
        for file in AUDITED_FILES {
            if !blocks(&blocked, file) {
                gaps.push(format!("{name} does not block {file}"));
            }
        }
    }

    assert!(
        gaps.is_empty(),
        "a profile permits access to the configuration that decides what the \
         agent may do, which is the asymmetry #2782 named:\n  {}",
        gaps.join("\n  ")
    );
}

/// The audit list and the block list are the same set of facts — "these files
/// configure an agent's permissions" — and were held in two places. This is the
/// half that cannot be made structural: `MCP_CONFIG_CANDIDATES` is relative
/// file paths for a scanner, `AGENT_HARNESS_CONFIG` is globs for a lattice. So
/// pin that every audited file is covered, which is the direction that matters.
#[test]
fn the_floor_covers_every_file_the_audit_scans() {
    let floor: Vec<String> = AGENT_HARNESS_CONFIG.iter().map(|s| s.to_string()).collect();
    for file in AUDITED_FILES {
        assert!(
            blocks(&floor, file),
            "`nucleus audit` scans {file} for plaintext credentials, but no \
             AGENT_HARNESS_CONFIG glob blocks it — audited and unprotected is \
             exactly the asymmetry this floor exists to remove"
        );
    }
}

/// Non-vacuity. If `glob_match` stopped matching, or the floor were emptied,
/// both tests above would pass while checking nothing. An ordinary source file
/// under the same root must stay reachable.
#[test]
fn the_floor_does_not_block_ordinary_source() {
    let floor: Vec<String> = AGENT_HARNESS_CONFIG.iter().map(|s| s.to_string()).collect();
    assert!(
        !floor.is_empty(),
        "an empty floor would pass every assertion"
    );

    for ordinary in [
        "/work/repo/src/main.rs",
        "/work/repo/README.md",
        "/work/repo/CLAUDE.md",
        "/work/repo/claude/notes.md",
    ] {
        assert!(
            !blocks(&floor, ordinary),
            "{ordinary} is not permission-granting configuration; a coding \
             agent that cannot touch it is broken rather than contained"
        );
    }
}

/// The drift that was already there. Five of the six write-permitting profiles
/// blocked `/etc/passwd`; `doc-editor` did not. That is not covered by the
/// floor — it is credential material, left in the YAML — so it needs its own
/// pin, or the next profile added by copy-paste reintroduces it.
#[cfg(feature = "spec")]
#[test]
fn write_permitting_profiles_share_one_credential_baseline() {
    // The set every write-permitting profile carried, minus the one it had
    // drifted on. A profile may block MORE (untrusted-model blocks
    // `**/.git/config` and `/proc/*/environ`); it may not block less.
    const BASELINE: &[&str] = &[
        "/work/repo/.ssh/id_rsa",
        "/work/repo/.aws/credentials",
        "/work/repo/.env",
        "/work/repo/.env.local",
        "/etc/shadow",
        "/etc/passwd",
    ];

    let registry = ProfileRegistry::default();
    let mut gaps = Vec::new();

    for name in registry.names() {
        let lattice = registry
            .resolve(name)
            .unwrap_or_else(|e| panic!("`{name}` must resolve: {e}"));
        if lattice.capabilities.write_files == portcullis::CapabilityLevel::Never {
            continue;
        }
        let blocked: Vec<String> = lattice.paths.blocked.iter().cloned().collect();
        for file in BASELINE {
            if !blocks(&blocked, file) {
                gaps.push(format!("{name} permits writes but does not block {file}"));
            }
        }
    }

    assert!(
        gaps.is_empty(),
        "the per-profile credential lists have drifted apart again:\n  {}",
        gaps.join("\n  ")
    );
}

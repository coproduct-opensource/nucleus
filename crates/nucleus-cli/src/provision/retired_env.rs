//! Variables an earlier `nucleus setup` wrote into `node.env` that nothing
//! reads any more, and taking them back out on upgrade (#3294).

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};

use super::{NODE_ENV_PATH, StagedFile, Tier2Host, land_staged, stage_files};

/// Variables an earlier `nucleus setup` wrote into [`NODE_ENV_PATH`] that
/// nothing reads any more. One list, read by the writer's test, the Tier 2
/// upgrade ([`scrub_retired_node_env`]) and the Apple host's own env file.
pub(crate) const RETIRED_NODE_ENV_KEYS: &[&str] = &["NUCLEUS_NODE_AUTH_SECRET"];

/// `body` with every assignment of a [`RETIRED_NODE_ENV_KEYS`] key removed and
/// every other byte kept — order, comments, blank lines, line endings, a last
/// line without a newline. `None` when there is nothing to remove, so a caller
/// rewrites the file only when it changes.
pub(crate) fn without_retired_node_env(body: &[u8]) -> Option<Vec<u8>> {
    let mut kept = Vec::with_capacity(body.len());
    let mut removed = false;
    for line in body.split_inclusive(|&b| b == b'\n') {
        if assigns_a_retired_key(line) {
            removed = true;
        } else {
            kept.extend_from_slice(line);
        }
    }
    removed.then_some(kept)
}

/// Whether `line` is `KEY=…` (spaces allowed around the key) for a retired
/// `KEY`. A longer name that merely starts with one is not a match.
fn assigns_a_retired_key(line: &[u8]) -> bool {
    let line = line.trim_ascii_start();
    RETIRED_NODE_ENV_KEYS.iter().any(|key| {
        line.strip_prefix(key.as_bytes())
            .is_some_and(|rest| rest.trim_ascii_start().first() == Some(&b'='))
    })
}

/// Take the retired variables out of an existing [`NODE_ENV_PATH`] on `host`,
/// and say so. Nothing happens when the file is absent or already clean.
///
/// `setup` rewrites the whole file when it installs the node, but not under
/// `--skip-artifacts`, and an upgrade should not depend on which flags it was
/// run with. The rewrite goes through [`stage_files`] and [`land_staged`]: a
/// `0600` sibling renamed over the file, then its digest checked on the host.
pub fn scrub_retired_node_env(host: &Tier2Host) -> Result<()> {
    // Absent and "could not look" are different answers (ADR 0007 A-1).
    let state = host.sh(&format!(
        "if [ -e {NODE_ENV_PATH} ]; then echo present; else echo absent; fi"
    ))?;
    match state.as_str() {
        "absent" => return Ok(()),
        "present" => {}
        other => bail!(
            "could not tell whether {NODE_ENV_PATH} exists on {}: {other:?}",
            host.describe()
        ),
    }
    let body = host.sh_bytes(&format!("cat {NODE_ENV_PATH}"))?;
    let Some(scrubbed) = without_retired_node_env(&body) else {
        return Ok(());
    };
    let staging = tempfile::tempdir().context("failed to create a staging directory")?;
    let staged = stage_node_env(staging.path(), NODE_ENV_PATH, &scrubbed)?;
    land_staged(host, &staged)?;
    println!(
        "  Removed retired {} from {NODE_ENV_PATH} on {} — nucleus-node no longer reads it",
        RETIRED_NODE_ENV_KEYS.join(", "),
        host.describe()
    );
    Ok(())
}

/// Stage `body` for landing at `remote`, owner-only, mode `0600`.
pub(super) fn stage_node_env(staging: &Path, remote: &str, body: &[u8]) -> Result<Vec<StagedFile>> {
    let (dir, name) = remote
        .rsplit_once('/')
        .ok_or_else(|| anyhow!("{remote} is not an absolute path"))?;
    stage_files(staging, dir, &[(name, body, "0600")])
}

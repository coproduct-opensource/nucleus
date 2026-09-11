//! `cargo xtask gatehouse-pin` — the two pins that must move together.
//!
//! nucleus names gatehouse twice, and the two names have to agree:
//!
//! * `.gatehouse/pipeline.writ` imports the `ci` prelude **by digest**
//!   (`import "sha256:…" as ci`), which is what makes the plan hermetic;
//! * `.github/workflows/gatehouse-plan.yml` pins `GATEHOUSE_REF` to the gatehouse
//!   commit whose `gate` binary checks that plan;
//! * `.github/workflows/gatehouse-shadow.yml` pins its OWN `GATEHOUSE_REF`, and must
//!   name the same commit — a shadow built from a different gatehouse than the plan
//!   check is comparing two things that were never the same.
//!
//! The import digest must be the SHA-256 of `prelude/ci.writ` **at that ref**. The
//! workflow already says so in a comment — "its embedded prelude must match the import
//! hash in .gatehouse/pipeline.writ" — and nothing checked it, which is the difference
//! between a convention and a gate.
//!
//! # Why this exists
//!
//! Bumping one pin alone breaks the plan check, and the failure is remote and slow: the
//! job spends ~3 minutes building gatehouse before `gate` reports `no library for import`.
//! Worse, reading that message from the *wrong* side is how a working pin gets mistaken
//! for a stale one — a pin refusing a library the pinned build does not have is the pin
//! doing its job. That mistake was made against this exact pair (gatehouse `FINDINGS.md`
//! F-21) and produced a PR that moved one pin alone.
//!
//! # What decides this
//!
//! All three operands are declarations: a workflow `env` value, an import line, and a file
//! in a repository pinned by SHA. Nothing here reads nucleus's source tree, nothing needs a
//! toolchain, and the verdict is the same against an empty checkout of nucleus. See
//! gatehouse `docs/tiering.md` — this is the shape that gate is cheapest.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

const PIPELINE: &str = ".gatehouse/pipeline.writ";
/// Both workflows that build gatehouse pin the ref they build it at. The plan lane's
/// pin is the one the import digest must agree with; the shadow lane's is checked for
/// agreement with it, because a shadow running a DIFFERENT gatehouse than the plan
/// check is comparing two things that were never the same.
const WORKFLOWS: [&str; 2] = [
    ".github/workflows/gatehouse-plan.yml",
    ".github/workflows/gatehouse-shadow.yml",
];
const WORKFLOW: &str = WORKFLOWS[0];
const PRELUDE: &str = "prelude/ci.writ";

/// The `sha256:…` an `import` line names, as lowercase hex without the prefix.
pub fn imported_digest(pipeline_src: &str) -> Result<String> {
    for line in pipeline_src.lines() {
        let line = line.trim_start();
        if !line.starts_with("import ") {
            continue;
        }
        // `import "sha256:<64 hex>" as ci`
        let Some(open) = line.find('"') else { continue };
        let Some(close) = line[open + 1..].find('"') else {
            continue;
        };
        let quoted = &line[open + 1..open + 1 + close];
        let Some(hex) = quoted.strip_prefix("sha256:") else {
            bail!("{PIPELINE}: import {quoted:?} is not a sha256: digest");
        };
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("{PIPELINE}: import digest {hex:?} is not 64 hex characters");
        }
        // The plan imports one library today. If it ever imports several this must name
        // WHICH, rather than silently checking the first — the `head -1` failure that
        // .line-ratchet.toml already paid for once.
        return Ok(hex.to_ascii_lowercase());
    }
    bail!("{PIPELINE}: no `import \"sha256:…\"` line")
}

/// `GATEHOUSE_REF` as the workflow declares it.
pub fn pinned_ref(workflow_src: &str) -> Result<String> {
    for line in workflow_src.lines() {
        let t = line.trim();
        if let Some(v) = t.strip_prefix("GATEHOUSE_REF:") {
            let v = v.trim().trim_matches(|c| c == '"' || c == '\'');
            if v.len() != 40 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("{WORKFLOW}: GATEHOUSE_REF {v:?} is not a 40-character commit sha");
            }
            return Ok(v.to_ascii_lowercase());
        }
    }
    bail!("{WORKFLOW}: no GATEHOUSE_REF")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Check the pins. `gatehouse` is a checkout of `coproduct-private/gatehouse`; without one
/// only the two nucleus-side declarations can be read, which is reported rather than
/// treated as a pass.
pub fn check(root: &Path, gatehouse: Option<PathBuf>) -> Result<()> {
    let pipeline =
        fs::read_to_string(root.join(PIPELINE)).with_context(|| format!("reading {PIPELINE}"))?;
    let workflow =
        fs::read_to_string(root.join(WORKFLOW)).with_context(|| format!("reading {WORKFLOW}"))?;

    let want = imported_digest(&pipeline)?;
    let gh_ref = pinned_ref(&workflow)?;
    println!("{PIPELINE} imports sha256:{want}");
    println!("{WORKFLOW} pins    GATEHOUSE_REF {gh_ref}");

    // The THIRD pin. gatehouse-shadow.yml builds gatehouse too, at its own
    // GATEHOUSE_REF, and nothing said the two had to be the same commit. They were
    // not: the plan lane ran 4d42510 while the shadow lane ran 7326bfa9, a descendant
    // — so the shadow was comparing a gate built from one gatehouse against a plan
    // checked by another, and calling agreement between them meaningful.
    let shadow_path = root.join(WORKFLOWS[1]);
    let shadow_ref = pinned_ref(
        &fs::read_to_string(&shadow_path).with_context(|| format!("reading {}", WORKFLOWS[1]))?,
    )?;
    println!("{} pins  GATEHOUSE_REF {shadow_ref}", WORKFLOWS[1]);
    if shadow_ref != gh_ref {
        bail!(
            "the two workflows build gatehouse at different commits.\n\
             \x20 {WORKFLOW} pins   {gh_ref}\n\
             \x20 {} pins {shadow_ref}\n\
             The shadow gate exists to say whether gatehouse's verdict agrees with \
             GitHub's. Run against a different gatehouse than the plan check, it answers \
             a question nobody asked. If the skew is deliberate, say so here and in both \
             workflows; otherwise move them together.",
            WORKFLOWS[1]
        );
    }

    let Some(dir) = gatehouse else {
        println!(
            "no --gatehouse checkout given: the third operand is {PRELUDE} at {gh_ref}, so \
             this run checked only that both declarations exist and are well formed"
        );
        return Ok(());
    };

    // The checkout must BE the pinned ref, or this compares against the wrong side — the
    // exact mistake F-21 records.
    let head = std::process::Command::new("git")
        .args(["-C", &dir.to_string_lossy(), "rev-parse", "HEAD"])
        .output()
        .with_context(|| format!("git rev-parse in {}", dir.display()))?;
    let head = String::from_utf8_lossy(&head.stdout)
        .trim()
        .to_ascii_lowercase();
    if head != gh_ref {
        bail!(
            "the gatehouse checkout at {} is {head}, but {WORKFLOW} pins {gh_ref}.\n\
             Comparing the prelude against the wrong commit answers a different question \
             than the one this gate asks.",
            dir.display()
        );
    }

    let prelude = fs::read(dir.join(PRELUDE))
        .with_context(|| format!("reading {PRELUDE} from {}", dir.display()))?;
    let got = sha256_hex(&prelude);
    if got != want {
        bail!(
            "the two pins disagree.\n\
             \x20 {PIPELINE} imports          sha256:{want}\n\
             \x20 {PRELUDE} at {gh_ref} is sha256:{got}\n\
             They must move together: bumping GATEHOUSE_REF without the import digest (or the \
             reverse) makes `gate plan check` fail with `no library for import`, ~3 minutes into \
             a build. If gatehouse's prelude changed deliberately, bump BOTH in one change, and \
             re-check the plan is still admissible rather than merely parseable."
        );
    }
    println!("ok: {PRELUDE} at {gh_ref} hashes to the digest the plan imports");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_real_declarations() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let pipeline = fs::read_to_string(root.join(PIPELINE)).unwrap();
        let workflow = fs::read_to_string(root.join(WORKFLOW)).unwrap();
        let d = imported_digest(&pipeline).expect("the shipped plan names a digest");
        let r = pinned_ref(&workflow).expect("the shipped workflow pins a ref");
        assert_eq!(d.len(), 64);
        assert_eq!(r.len(), 40);
    }

    #[test]
    fn a_tag_shaped_import_is_refused() {
        assert!(imported_digest("import \"rust:1.96\" as ci\n").is_err());
    }

    #[test]
    fn a_truncated_digest_is_refused() {
        assert!(imported_digest("import \"sha256:abc123\" as ci\n").is_err());
    }

    #[test]
    fn a_branch_name_is_not_a_pin() {
        assert!(pinned_ref("    GATEHOUSE_REF: main\n").is_err());
    }

    #[test]
    fn the_digest_is_plain_sha256_of_the_file_bytes() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}

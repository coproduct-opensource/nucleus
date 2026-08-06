//! The confidentiality claim may not be stated without its limit.
//!
//! # Why this is a test and not a style rule
//!
//! The cross-pod confidentiality claim excludes timing, cache, and other
//! microarchitectural channels. That exclusion is not a caveat we would like to
//! remember — it is the difference between a true statement and one that reads
//! as "immune to co-tenancy attacks", which this project has no basis for:
//! Firecracker, the host kernel, and the hardware are all in the TCB and none of
//! them is modelled.
//!
//! A claim like that gets quoted. It gets pasted into a README, a pitch deck, a
//! landing page. The failure mode is not someone deleting the exclusion on
//! purpose; it is someone copying the strong sentence and leaving the qualifying
//! one behind. So the check is on the PARAGRAPH: the limit must travel with the
//! claim, in the same block of prose, or this fails.
//!
//! It scans every markdown file under `docs/` rather than the one file the claim
//! lives in today. A gate that names its file only covers the copy it knows
//! about, and the whole risk here is copies.

use std::path::{Path, PathBuf};

/// A phrase distinctive enough that its presence means the confidentiality claim
/// is being made, and generic enough to survive rewording around it.
const CLAIM_MARKER: &str = "nor those of any other pod";

/// The exclusion that must travel with it. Matched on the substantive words
/// rather than the full sentence so the claim can be reworded without this test
/// becoming a spelling check.
const LIMIT_MARKERS: [&str; 2] = ["timing", "microarchitectural"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root should resolve from the crate manifest dir")
}

/// Every markdown file under `docs/`, recursively.
fn markdown_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            markdown_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "md") {
            out.push(path);
        }
    }
}

/// The claim must never appear in a paragraph that does not also carry its limit.
#[test]
fn the_confidentiality_claim_never_appears_without_its_limit() {
    let root = repo_root();
    let mut docs = Vec::new();
    markdown_files(&root.join("docs"), &mut docs);

    // A gate that finds nothing to check passes for the wrong reason. If the
    // docs tree ever moves, this fails loudly instead of going quietly green.
    assert!(
        !docs.is_empty(),
        "no markdown found under {}/docs -- this check would pass vacuously",
        root.display()
    );

    let mut offences = Vec::new();
    let mut sightings = 0usize;

    for path in &docs {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for (index, paragraph) in text.split("\n\n").enumerate() {
            if !paragraph.contains(CLAIM_MARKER) {
                continue;
            }
            sightings += 1;
            let missing: Vec<_> = LIMIT_MARKERS
                .iter()
                .filter(|m| !paragraph.contains(**m))
                .collect();
            if !missing.is_empty() {
                offences.push(format!(
                    "{} (paragraph {index}): states the cross-pod confidentiality \
                     claim but the paragraph does not mention {missing:?}",
                    path.strip_prefix(&root).unwrap_or(path).display()
                ));
            }
        }
    }

    // The claim has to exist somewhere, or "every statement carries its limit"
    // is true because there are no statements.
    assert!(
        sightings > 0,
        "the confidentiality claim was not found in any doc -- either it was \
         removed, or CLAIM_MARKER no longer matches how it is worded. Either way \
         this check is no longer checking anything."
    );

    assert!(
        offences.is_empty(),
        "the confidentiality claim is stated without its microarchitectural \
         exclusion:\n  {}\n\nThe exclusion belongs in the same paragraph as the \
         claim, not in a footnote -- the claim gets quoted, and a limit that does \
         not travel with it is a limit nobody reads.",
        offences.join("\n  ")
    );
}

//! The two report builders behind the CLI subcommands.
//!
//! Both return the full report as a `String` (so tests can assert on them)
//! and both print provenance for every fact they rest on — a derived
//! "verified" with no checkable citation is vibes, and `Atlas::citation`
//! errors instead of printing one.

use anyhow::{Context, Result};
use std::fmt::Write as _;
use std::path::Path;

use crate::atlas::Atlas;
use crate::extractors::{
    self, extract_kani_harnesses, live_required_checks, live_workflows, Source,
};
use crate::model::{Fixtures, Maturity, TrustEdge};

// ---------------------------------------------------------------------------
// weakest-link
// ---------------------------------------------------------------------------

/// The receipt-claim chain assessed by `trust-atlas weakest-link`, as node-id
/// prefixes into fixtures/recon/trust_path.json.
const CHAIN: [&str; 4] = [
    "nucleus-auction-hub-server",
    "nucleus-substrate-core",
    "nucleus-receipt",
    "nucleus-verifier-wasm (sdks/verifier-js)",
];

fn node_id<'a>(fix: &'a Fixtures, prefix: &str) -> Result<&'a str> {
    fix.trust_path
        .nodes
        .iter()
        .find(|n| n.id.starts_with(prefix))
        .map(|n| n.id.as_str())
        .with_context(|| format!("no trust_path node with prefix '{prefix}'"))
}

fn find_edge<'a>(fix: &'a Fixtures, from: &str, to: &str) -> Option<&'a TrustEdge> {
    fix.trust_path
        .edges
        .iter()
        .find(|e| e.from.starts_with(from) && e.to.starts_with(to))
}

pub fn weakest_link(fix: &Fixtures) -> Result<String> {
    let mut atlas = Atlas::new()?;
    let mut out = String::new();

    // Load every recon equivalence: union lhs/rhs (transport), record
    // fragment conditions on the side table, rank by evidence kind.
    for eq in &fix.equivalences.equivalences {
        atlas.add_equivalence(
            &eq.name,
            &eq.lhs,
            &eq.rhs,
            Maturity::for_equivalence_kind(&eq.kind),
            &eq.fragment_condition,
            &eq.evidence,
        )?;
    }

    // Chain hops. Hop 3 has no forward edge in the recon graph at all — the
    // SDK-verifies-hub-receipt edge was probed and found ABSENT — so we cite
    // that ABSENT finding as the hop's evidence.
    let hub = node_id(fix, CHAIN[0])?.to_string();
    let substrate = node_id(fix, CHAIN[1])?.to_string();
    let receipt = node_id(fix, CHAIN[2])?.to_string();
    let verifier = node_id(fix, CHAIN[3])?.to_string();

    let hop1 = find_edge(fix, CHAIN[0], CHAIN[1]).context("hop1 edge missing from fixture")?;
    let hop2 = find_edge(fix, CHAIN[1], CHAIN[2]).context("hop2 edge missing from fixture")?;
    let hop3 = find_edge(fix, CHAIN[3], "AuctionReceipt")
        .context("hop3 (SDK verifies hub receipt) probe missing from fixture")?;

    let hops: [(&str, &str, &TrustEdge); 3] = [
        (&hub, &substrate, hop1),
        (&substrate, &receipt, hop2),
        (&receipt, &verifier, hop3),
    ];
    for (from, to, edge) in &hops {
        atlas.set_edge(from, to, edge.maturity(), &edge.evidence)?;
    }

    // Supporting node facts.
    let signs = find_edge(fix, CHAIN[0], "AuctionReceipt").context("hub signs edge missing")?;
    atlas.set_maturity(
        "AuctionReceipt (hub wire type)",
        signs.maturity(),
        &signs.evidence,
    )?;
    let jcs = fix
        .equivalences
        .equivalences
        .iter()
        .find(|e| e.name.contains("RFC 8785"))
        .context("JCS golden equivalence missing from fixture")?;
    atlas.set_maturity(
        &receipt,
        Maturity::for_equivalence_kind(&jcs.kind),
        &jcs.evidence,
    )?;

    // Node-level transport for the claimed re-export identity (union is
    // performed; fragment condition recorded, reported below).
    let reexport = fix
        .equivalences
        .equivalences
        .iter()
        .find(|e| e.kind == "reexport-identity")
        .context("reexport-identity equivalence missing from fixture")?;
    atlas.add_equivalence(
        &format!("{} [node-level transport]", reexport.name),
        &substrate,
        &receipt,
        Maturity::for_equivalence_kind(&reexport.kind),
        &reexport.fragment_condition,
        &reexport.evidence,
    )?;

    atlas.saturate()?;

    writeln!(out, "trust-atlas weakest-link — the receipt claim")?;
    writeln!(
        out,
        "claim: \"a receipt signed by the platform auction hub verifies offline in the open-source WASM verifier SDK\""
    )?;
    writeln!(
        out,
        "fixtures: {} ({})",
        fix.dir.display(),
        fix.trust_path.provenance
    )?;
    writeln!(out)?;
    writeln!(
        out,
        "chain (per-edge maturity = meet semantics, min-merge):"
    )?;
    for (i, (from, to, edge)) in hops.iter().enumerate() {
        let m = edge.maturity();
        writeln!(out, "  hop {}: {} -> {}", i + 1, from, to)?;
        writeln!(
            out,
            "    maturity:   [{m}]{}",
            if edge.is_absent() {
                "  <- DISCONTINUITY"
            } else {
                ""
            }
        )?;
        writeln!(
            out,
            "    provenance: {}",
            atlas.citation(&format!("edge:{from} -> {to}"))?
        )?;
    }
    writeln!(out)?;

    let end_to_end = atlas
        .path_maturity(&hub, &verifier)
        .context("path-maturity did not derive an end-to-end rank")?;
    let min_by_hand = hops.iter().map(|(_, _, e)| e.maturity()).min().unwrap();
    anyhow::ensure!(
        end_to_end == min_by_hand,
        "egglog path-maturity {end_to_end} != hand-computed min {min_by_hand}"
    );
    writeln!(
        out,
        "END-TO-END MATURITY (egglog path-maturity, MIN over edges): [{end_to_end}]"
    )?;
    writeln!(out)?;

    // Supporting facts (each with provenance).
    writeln!(out, "supporting facts:")?;
    let auction_m = atlas
        .maturity("AuctionReceipt (hub wire type)")
        .context("AuctionReceipt maturity missing")?;
    writeln!(out, "  - hub signs AuctionReceipt: [{auction_m}]")?;
    writeln!(
        out,
        "    provenance: {}",
        atlas.citation("maturity:AuctionReceipt (hub wire type)")?
    )?;
    // Equivalence transport demo: the substrate-core node was never given a
    // maturity directly; querying it answers via the union with the receipt
    // node, and min-merge resolves the class to the WEAKER rank (the unmerged
    // re-export claim), not the pinned JCS rank.
    let transported = atlas
        .maturity(&substrate)
        .context("transport failed: substrate-core has no maturity via the union")?;
    let receipt_m = atlas
        .maturity(&receipt)
        .context("receipt maturity missing")?;
    writeln!(
        out,
        "  - equivalence transport (reexport-identity union): maturity({substrate}) = [{transported}] == maturity(nucleus-receipt) = [{receipt_m}]"
    )?;
    writeln!(
        out,
        "    the JCS golden pin [{}] is dragged down to the unmerged re-export claim's rank by min-merge",
        Maturity::for_equivalence_kind(&jcs.kind)
    )?;
    writeln!(
        out,
        "    fragment condition (side table, union NOT skipped): {}",
        atlas
            .fragments
            .get(&format!("{} [node-level transport]", reexport.name))
            .map(String::as_str)
            .unwrap_or("(none)")
    )?;
    writeln!(
        out,
        "    provenance: {}",
        atlas.citation(&format!("equiv:{} [node-level transport]", reexport.name))?
    )?;
    writeln!(out)?;

    writeln!(
        out,
        "discontinuities (recon notes, fixtures/recon/trust_path.json:notes):"
    )?;
    let verdict_end = fix
        .trust_path
        .notes
        .find("discontinuities.")
        .map(|i| i + "discontinuities.".len())
        .unwrap_or(fix.trust_path.notes.len().min(200));
    writeln!(out, "  {}", &fix.trust_path.notes[..verdict_end])?;
    for (i, (from, to, edge)) in hops.iter().enumerate() {
        if edge.is_absent() {
            writeln!(out, "  ({}) {} -> {}: {}", i + 1, from, to, edge.evidence)?;
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// findings
// ---------------------------------------------------------------------------

/// Workflows that are not PR gates (publishers, releases, dashboards) — kept
/// out of the unenforced-gate finding so it matches the recon notes exactly.
const NON_GATE_FILES: [&str; 14] = [
    // coproduct-opensource/nucleus
    ".github/workflows/action-smoke-test.yml",
    ".github/workflows/crates-publish.yml",
    ".github/workflows/dependabot-automerge.yml",
    ".github/workflows/docker.yml",
    ".github/workflows/docs.yml",
    ".github/workflows/release.yml",
    ".github/workflows/scorecard.yml",
    ".github/workflows/scan-attest.yml",
    ".github/workflows/oidc-keyless-prototype.yml",
    // coproduct-private/spiffy
    ".github/workflows/publish-mcp.yml",
    ".github/workflows/release-issue-license.yml",
    ".github/workflows/release-nucleus-verify.yml",
    ".github/workflows/release-plz.yml",
    ".github/workflows/witness-peers.yml",
];

/// A workflow counts as enforced iff one of its job strings contains a
/// required status-check context (job display names are job-level contexts).
fn matched_jobs<'a>(jobs: &'a [String], required: &[String]) -> Vec<&'a String> {
    jobs.iter()
        .filter(|j| required.iter().any(|r| j.contains(r.as_str())))
        .collect()
}

pub struct GateReport {
    pub atlas: Atlas,
    pub text: String,
    /// (repo, gate name) pairs derived unenforced by the egglog rule.
    pub unenforced: Vec<(String, String)>,
}

/// Feed gate facts (live where possible) into the atlas and derive
/// unenforced gates via the egglog rule — not via Rust-side filtering.
pub fn gate_findings(fix: &Fixtures, try_live: bool) -> Result<GateReport> {
    let mut atlas = Atlas::new()?;
    let mut text = String::new();
    let mut unenforced = Vec::new();

    for (idx, repo) in fix.gates.repos.iter().enumerate() {
        let is_nucleus = repo.repo.starts_with(extractors::NUCLEUS_REPO_SLUG);
        // LIVE extractor 1 (gates) — only the public nucleus repo; spiffy's
        // protection API 403s (free plan), the fixture notes carry that probe.
        let (required, req_source) = if is_nucleus && try_live {
            match live_required_checks(extractors::NUCLEUS_REPO_SLUG) {
                Ok(live) => (live, Source::Live),
                Err(e) => {
                    writeln!(text, "  (gh api failed: {e}; falling back to fixture)")?;
                    (repo.required_checks.clone(), Source::Fixture)
                }
            }
        } else {
            (repo.required_checks.clone(), Source::Fixture)
        };
        let live_paths: Option<Vec<String>> = if is_nucleus && try_live {
            live_workflows(extractors::NUCLEUS_REPO_SLUG)
                .ok()
                .map(|ws| ws.into_iter().map(|w| w.path).collect())
        } else {
            None
        };

        writeln!(text, "== unenforced gates: {} ==", repo.repo)?;
        writeln!(
            text,
            "  required contexts {} ({}): {}",
            req_source.marker(),
            if req_source == Source::Live {
                "gh api repos/coproduct-opensource/nucleus/branches/main/protection/required_status_checks".to_string()
            } else {
                format!(
                    "fixtures/recon/gates.json repos[{idx}].required_checks; {}",
                    &fix.gates.provenance
                )
            },
            if required.is_empty() {
                "NONE — zero checks enforced on main".to_string()
            } else {
                required.join(", ")
            }
        )?;
        if let Some(paths) = &live_paths {
            writeln!(
                text,
                "  workflow list [live]: gh api …/actions/workflows returned {} workflows (job mapping below remains [fixture] — the API does not expose job contexts)",
                paths.len()
            )?;
        }

        for wf in &repo.workflows {
            if NON_GATE_FILES.contains(&wf.file.as_str()) {
                continue;
            }
            let matched = matched_jobs(&wf.jobs, &required);
            let gate_key = format!("{} :: {}", repo.repo, wf.name);
            let citation = format!(
                "{} {} + required set {} ({})",
                wf.file,
                Source::Fixture.marker(),
                req_source.marker(),
                "fixtures/recon/gates.json"
            );
            atlas.add_gate(&gate_key, !matched.is_empty(), &citation)?;
            if !matched.is_empty() && matched.len() < wf.jobs.len() {
                let missing: Vec<&str> = wf
                    .jobs
                    .iter()
                    .filter(|j| !matched.contains(j))
                    .map(String::as_str)
                    .collect();
                writeln!(
                    text,
                    "  PARTIAL: {} ({}) — jobs not in required set: {}",
                    wf.name,
                    wf.file,
                    missing.join("; ")
                )?;
                writeln!(text, "    provenance: {citation}")?;
            }
        }
        atlas.saturate()?;
        for wf in &repo.workflows {
            if NON_GATE_FILES.contains(&wf.file.as_str()) {
                continue;
            }
            let gate_key = format!("{} :: {}", repo.repo, wf.name);
            if atlas.is_unenforced(&gate_key) {
                writeln!(
                    text,
                    "  - {} ({}) — runs on PR, NOT required",
                    wf.name, wf.file
                )?;
                writeln!(
                    text,
                    "    provenance: {}",
                    atlas.citation(&format!("gate:{gate_key}"))?
                )?;
                unenforced.push((repo.repo.clone(), wf.name.clone()));
            }
        }
        writeln!(text)?;
    }

    Ok(GateReport {
        atlas,
        text,
        unenforced,
    })
}

pub fn findings(fix: &Fixtures, repo_path: &Path, try_live: bool) -> Result<String> {
    let mut out = String::new();
    writeln!(out, "trust-atlas findings")?;
    writeln!(
        out,
        "fixtures: {} ({})",
        fix.dir.display(),
        fix.gates.provenance
    )?;
    writeln!(out)?;

    let gates = gate_findings(fix, try_live)?;
    out.push_str(&gates.text);

    // Sorry findings: a load-bearing artifact is a Lean lib that CI builds.
    writeln!(
        out,
        "== sorry findings (fixtures/recon/verification.json) =="
    )?;
    let mut load_bearing_sorry = false;
    for lib in &fix.verification.lean_libs {
        if !lib.sorry_free && lib.built_by_ci != "none" {
            load_bearing_sorry = true;
            writeln!(
                out,
                "  CRITICAL: CI-built lib {} is NOT sorry-free (built by {})",
                lib.lib, lib.built_by_ci
            )?;
        }
    }
    if !load_bearing_sorry {
        let ci_built = fix
            .verification
            .lean_libs
            .iter()
            .filter(|l| l.built_by_ci != "none")
            .count();
        writeln!(
            out,
            "  no load-bearing artifact rests on a sorry: all {ci_built} CI-built Lean libs are sorry-free"
        )?;
        writeln!(
            out,
            "    provenance: per-lib built_by_ci workflow:line citations in fixtures/recon/verification.json lean_libs[]"
        )?;
    }
    writeln!(
        out,
        "  sorry'd files exist OUTSIDE CI ({} files, research libs built by NO workflow):",
        fix.verification.sorry_files.len()
    )?;
    for sf in &fix.verification.sorry_files {
        writeln!(out, "  - {} ({} sorries) [fixture]", sf.file, sf.count)?;
    }
    writeln!(out)?;

    // LIVE extractor 2: kani harness facts with file:line provenance.
    writeln!(
        out,
        "== kani harnesses [live] (grep '#[kani::proof]' under --repo {}) ==",
        repo_path.display()
    )?;
    match extract_kani_harnesses(repo_path) {
        Ok(facts) => {
            writeln!(
                out,
                "  {} harnesses found live (fixture count: {}; fixture excludes the string-literal match at crates/nucleus-audit/src/main.rs:1172, and so does this grep)",
                facts.len(),
                fix.verification.kani_harnesses.len()
            )?;
            for f in facts.iter().take(3) {
                writeln!(out, "  - {}  provenance: {}", f.name, f.citation())?;
            }
            if facts.len() > 3 {
                writeln!(
                    out,
                    "  … {} more (each with file:line provenance)",
                    facts.len() - 3
                )?;
            }
            if gates.unenforced.iter().any(|(_, name)| name == "Kani BMC") {
                writeln!(
                    out,
                    "  NOTE: every harness above sits behind kani-nightly.yml ('Kani BMC'), which the gate analysis derived as UNENFORCED — KernelChecked facts are advisory at merge time."
                )?;
            }
        }
        Err(e) => {
            writeln!(
                out,
                "  live grep failed ({e}); fixture lists {} harnesses [fixture]",
                fix.verification.kani_harnesses.len()
            )?;
        }
    }
    Ok(out)
}

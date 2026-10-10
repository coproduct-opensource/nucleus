//! Perturbations: each introduces a REAL violation of its gate's own stated property, not a
//! syntax error that would fail any check. Ported one for one from the shell functions of the
//! same names in the script this replaces; the comments there that explain each choice are kept
//! with the probe in `table.rs`.
//!
//! Every payload that is itself the shape some gate scans for is ASSEMBLED with `concat!`, never
//! written contiguously. This file lives under `crates/`, which most of those gates walk, and a
//! payload held as a literal would be a live hit on the clean tree -- the gate red on its own
//! perturbation (gatehouse F-115; the shell carried the same split for `mktemp -t`).
//!
//! A perturbation returns the new text of its target, and optionally a complaint: the shape it
//! expected has moved. The text is written either way, as the shell wrote whatever `sed` left,
//! and the harness's no-op check then decides whether the probe still bites.

use std::fs;
use std::path::Path;

use regex::Regex;

/// This file's source, for `inputs::Index::function_inputs`: the files a perturbation or
/// generator names are inputs of its probe.
pub const SOURCE: &str = include_str!("perturb.rs");

pub struct Perturbed {
    pub text: String,
    pub complaint: Option<String>,
}

pub type PerturbFn = fn(&Path, &str) -> Perturbed;
pub type GenFn = fn(&Path, &Path) -> bool;

fn ok(text: String) -> Perturbed {
    Perturbed {
        text,
        complaint: None,
    }
}

fn moved(text: String, why: &str) -> Perturbed {
    Perturbed {
        text,
        complaint: Some(why.to_string()),
    }
}

fn rx(pat: &str) -> Regex {
    Regex::new(pat).unwrap_or_else(|e| panic!("perturbation regex {pat}: {e}"))
}

/// `printf '%s\n' LINE >> file`.
fn append(text: &str, lines: &[&str]) -> String {
    let mut out = text.to_string();
    for l in lines {
        out.push_str(l);
        out.push('\n');
    }
    out
}

/// `sed 's/RE/REP/'`: the first match on EVERY line.
fn sed_s(text: &str, pat: &str, rep: &str) -> String {
    let re = rx(pat);
    text.split_inclusive('\n')
        .map(|chunk| {
            let (line, nl) = chunk.strip_suffix('\n').map_or((chunk, ""), |l| (l, "\n"));
            format!("{}{nl}", re.replace(line, rep))
        })
        .collect()
}

/// `sed '/RE/d'`.
fn sed_d(text: &str, pat: &str) -> String {
    let re = rx(pat);
    text.split_inclusive('\n')
        .filter(|chunk| !re.is_match(chunk.strip_suffix('\n').unwrap_or(chunk)))
        .collect()
}

/// `perl -0pi -e 's/RE/REP/'`: the first match in the whole file.
fn perl_first(text: &str, pat: &str, rep: &str) -> String {
    rx(pat).replace(text, rep).into_owned()
}

/// `awk '{ if (RE) print NEW; else print }'`: every matching line replaced. awk terminates every
/// line it prints, so a missing final newline is added.
fn awk_replace(text: &str, pat: &str, new: &str) -> (String, usize) {
    let re = rx(pat);
    let mut hits = 0;
    let mut out = String::new();
    for line in text.lines() {
        if re.is_match(line) {
            hits += 1;
            out.push_str(new);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    (out, hits)
}

const WITNESS: &str = concat!("Autho", "rity");

pub fn perturb_law_mechanism_wired(_: &Path, t: &str) -> Perturbed {
    ok(append(
        t,
        &[concat!(
            "fn _gate_of_gates() { let _: Option<Provenance",
            "DAG> = None; }"
        )],
    ))
}

pub fn perturb_inert_authority_added(_: &Path, t: &str) -> Perturbed {
    ok(append(
        t,
        &[&format!(
            "fn _gate_of_gates_inert(_authority: {WITNESS}) {{}}"
        )],
    ))
}

pub fn perturb_inert_authority_paid(_: &Path, t: &str) -> Perturbed {
    ok(sed_s(
        t,
        &regex::escape(concat!("_verified: &Verified", "Grant")),
        concat!("verified: &Verified", "Grant"),
    ))
}

pub fn perturb_dead_code_ratchet(_: &Path, t: &str) -> Perturbed {
    ok(append(
        t,
        &[
            concat!("#[al", "low(dead_code)]"),
            "fn _gate_of_gates_unused() {}",
        ],
    ))
}

pub fn perturb_line_ratchet(_: &Path, t: &str) -> Perturbed {
    ok(append(t, &["// gate-of-gates padding"; 400]))
}

pub fn perturb_mediation(_: &Path, t: &str) -> Perturbed {
    ok(append(
        t,
        &[concat!(
            "fn _gate_of_gates() { let _ = std::process::Command::",
            "new(\"sh\"); }"
        )],
    ))
}

pub fn perturb_sealed_home(_: &Path, t: &str) -> Perturbed {
    ok(append(
        t,
        &[concat!(
            "fn _gate_of_gates_unlisted() { let _ = Command::",
            "new(\"definitely-not-allowlisted\"); }"
        )],
    ))
}

pub fn perturb_verify_strict(_: &Path, t: &str) -> Perturbed {
    ok(append(
        t,
        &[
            concat!("use ed25519_dalek::Veri", "fier;"),
            concat!(
                "fn _gate_of_gates_weak(k: &ed25519_dalek::VerifyingKey, m: &[u8], ",
                "s: ed25519_dalek::Signature) -> bool { k.ver",
                "ify(m, &s).is_ok() }"
            ),
        ],
    ))
}

pub fn perturb_ring_ed25519(_: &Path, t: &str) -> Perturbed {
    ok(append(
        t,
        &[concat!(
            "fn _gate_of_gates_ring(k: &[u8], m: &[u8], s: &[u8]) -> bool { ",
            "ring::signature::UnparsedPublicKey::new(&ring::signature::ED2",
            "5519, k).verify(m, s).is_ok() }"
        )],
    ))
}

pub fn perturb_failclosed(_: &Path, t: &str) -> Perturbed {
    ok(append(
        t,
        &[
            "",
            concat!("#[cfg(not(target", "_os = \"linux\"))]"),
            "fn verify_gate_of_gates_stub() -> Result<(), String> {",
            "    Ok(())",
            "}",
        ],
    ))
}

pub fn perturb_ingest_hashed(_: &Path, t: &str) -> Perturbed {
    ok(append(
        t,
        &[concat!(
            "fn _gate_of_gates_ingest(f: &mut FlowTracker) { f.obs",
            "erve(NodeKind::WebFetch); }"
        )],
    ))
}

pub fn perturb_lean_lib_unbuilt(_: &Path, t: &str) -> Perturbed {
    ok(append(
        t,
        &[
            "",
            "lean_lib «GateOfGatesUnbuiltProbe» where",
            "  roots := #[`GateOfGatesUnbuiltProbe]",
        ],
    ))
}

pub fn perturb_default_target_unbuilt(_: &Path, t: &str) -> Perturbed {
    let t = sed_d(t, r"run: LEAN_NUM_THREADS=4 lake build$");
    ok(sed_s(
        &t,
        r#"^([[:space:]]*)build: "true"$"#,
        r#"${1}build: "false""#,
    ))
}

pub fn perturb_kani_harness_deleted(_: &Path, t: &str) -> Perturbed {
    let attr = concat!("#[kani", "::proof]");
    let mut done = false;
    let mut out = String::new();
    for line in t.lines() {
        if !done && line.contains(attr) {
            done = true;
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    ok(out)
}

pub fn perturb_compiler_online(_: &Path, t: &str) -> Perturbed {
    ok(format!("{t}\nreqwest = \"0.12\"\n"))
}

pub fn perturb_test_helpers_in_prod(_: &Path, t: &str) -> Perturbed {
    let from = r#"nucleus-ifc-kernel = { path = "../nucleus-ifc-kernel", version = "1.0.0" }"#;
    let to = concat!(
        r#"nucleus-ifc-kernel = { path = "../nucleus-ifc-kernel", version = "1.0.0", "#,
        r#"features = ["test-helpers"] }"#
    );
    let out = sed_s(
        t,
        &format!("^{}$", regex::escape(from)),
        &to.replace('$', "$$"),
    );
    if !rx(r#"nucleus-ifc-kernel.*features = \["test-helpers"\]"#).is_match(&out) {
        return moved(
            out,
            "the nucleus-ifc-kernel dependency line changed shape;\n         this perturbation no longer applies and must be updated.",
        );
    }
    ok(out)
}

pub fn perturb_trusted_base(_: &Path, t: &str) -> Perturbed {
    ok(append(
        t,
        &["gate_of_gates_fake_component pinned_by:definitely_not_a_real_test_anywhere"],
    ))
}

pub fn perturb_ledger_restore_false_row(_: &Path, t: &str) -> Perturbed {
    let legacy = "| Declassification is single-use and not adversary-steerable | **Proved** in the model; **tested** on the live path (spent-token set keyed on the Ed25519 signature) |";
    let (out, hits) = awk_replace(t, r"^\| C4 \|", legacy);
    if hits == 0 {
        return moved(
            t.to_string(),
            "no '| C4 |' row found in the ledger;\n         the ledger's C4 row moved and this perturbation must be updated.",
        );
    }
    ok(out)
}

pub fn perturb_twin_paths_ignore(_: &Path, t: &str) -> Perturbed {
    let out = sed_d(t, r#"^      - "\.kani-minimum-proofs"$"#);
    if out.contains(r#"".kani-minimum-proofs""#) {
        return moved(
            out,
            "the kani-nightly-noop paths-ignore entry changed shape;\n         this perturbation no longer applies and must be updated.",
        );
    }
    ok(out)
}

pub fn perturb_ci_assurance_overclaim(_: &Path, t: &str) -> Perturbed {
    let out = sed_s(
        t,
        r"^\| CI-10 \| (.*) \| NOT-YET \| `ci/merge-queue.toml#strict` \| — \|$",
        "| CI-10 | ${1} | PROVED | `ci/lean/CiSpec/Queue.lean#T8_strict_livelock` | `scripts/check-ci-spec.sh` |",
    );
    if !rx(r"(?m)^\| CI-10 \| .* \| PROVED \| `ci/lean/CiSpec/Queue.lean#T8_strict_livelock`")
        .is_match(&out)
    {
        return moved(
            out,
            "the CI-10 row changed shape; this perturbation must be updated.",
        );
    }
    ok(out)
}

pub fn perturb_golden_lean(_: &Path, t: &str) -> Perturbed {
    ok(append(
        t,
        &["-- gate-of-gates: a hand edit the generator would not produce"],
    ))
}

pub fn perturb_bite_semantics(_: &Path, t: &str) -> Perturbed {
    ok(append(
        t,
        &["structure GateOfGatesProbe where", "  x : Nat"],
    ))
}

pub fn perturb_cancel_in_progress(_: &Path, t: &str) -> Perturbed {
    let out = sed_s(
        t,
        r"^  cancel-in-progress: .*$",
        "  cancel-in-progress: true",
    );
    if !rx(r"(?m)^  cancel-in-progress: true$").is_match(&out) {
        return moved(
            out,
            "the zizmor.yml concurrency block changed shape;\n         this perturbation no longer applies and must be updated.",
        );
    }
    ok(out)
}

pub fn perturb_declassify_unscope(_: &Path, t: &str) -> Perturbed {
    let out = sed_s(
        t,
        &regex::escape("sink_mask: token.sink_mask(),"),
        "sink_mask: 0xFFFFu16,",
    );
    if !out.contains("sink_mask: 0xFFFFu16,") {
        return moved(
            out,
            "apply_token's 'sink_mask: token.sink_mask()' line changed shape;\n         this perturbation no longer applies and must be updated.",
        );
    }
    ok(out)
}

pub fn perturb_governor_keys_unsealed(_: &Path, t: &str) -> Perturbed {
    ok(append(
        t,
        &[
            "",
            concat!("#[al", "low(dead_code)]"),
            "fn _gate_of_gates_unseal(k: &mut nucleus::portcullis::kernel::Kernel) {",
            concat!("    k.set_trusted", "_keys(vec![[0u8; 32]]);"),
            "}",
        ],
    ))
}

pub fn perturb_c1_inbound_fence(_: &Path, t: &str) -> Perturbed {
    let guard = concat!("&& entry.material == MaterialKind::Ordinary", "Data");
    let out = sed_s(t, &regex::escape(guard), "&& false");
    if out.contains(guard) {
        return moved(
            out,
            "admit()'s reserved-namespace guard changed shape;\n         this perturbation no longer applies and must be updated.",
        );
    }
    ok(out)
}

pub fn perturb_declassify_value_unbind(_: &Path, t: &str) -> Perturbed {
    let out = sed_s(
        t,
        &regex::escape(concat!(
            "committed != [0u8; 32] && recorded == ",
            "Some(committed)"
        )),
        "{ let _ = (committed, recorded); true }",
    );
    if !out.contains("let _ = (committed, recorded); true") {
        return moved(
            out,
            "FlowGraph::value_binding_ok's body changed shape;\n         this perturbation no longer applies and must be updated.",
        );
    }
    ok(out)
}

pub fn perturb_no_hmac_auth(_: &Path, t: &str) -> Perturbed {
    ok(append(
        t,
        &[concat!(
            "const _GATE_PROBE: &str = \"NUCLEUS_NODE_AUTH",
            "_SECRET\";"
        )],
    ))
}

pub fn perturb_extracted_callsite(_: &Path, t: &str) -> Perturbed {
    let out = sed_s(
        t,
        &regex::escape(concat!("if !ident_may_", "deliver(entry.material")),
        concat!("if !ident_may_", "deliver_REMOVED(entry.material"),
    );
    if !out.contains("ident_may_deliver_REMOVED") {
        return moved(
            out,
            "the ident_may_deliver call site in workload.rs changed shape;\n         this perturbation no longer applies and must be updated.",
        );
    }
    ok(out)
}

pub fn perturb_kani_divergence_unlisted(_: &Path, t: &str) -> Perturbed {
    ok(append(
        t,
        &[
            "",
            concat!("#[cfg(not(ka", "ni))]"),
            "pub fn gate_of_gates_unlisted_divergence_probe() -> bool {",
            "    true",
            "}",
        ],
    ))
}

/// The issue's own trivial harness (#2585): a registered Kani harness that still calls its
/// function but no longer ends in `kani::cover!`, so nothing shows its end is reachable. Every
/// cover line goes, not just the last, or the next one up would be terminal and the probe a
/// no-op.
pub fn perturb_proof_obligation_vacuous_harness(_: &Path, t: &str) -> Perturbed {
    let text = sed_d(t, r"^\s*kani::cover!\(verdict");
    if text == t {
        return moved(text, "no `kani::cover!(verdict` line in the argv harness");
    }
    ok(text)
}

/// The ceiling READ out of the file and lowered by one: a hard-coded value would stop biting the
/// day a proof PR lowers the real one.
pub fn perturb_proof_obligation_missing_ceiling(_: &Path, t: &str) -> Perturbed {
    let Some(n) = t.lines().find_map(|l| {
        l.trim()
            .strip_prefix("MISSING_CEILING=")
            .and_then(|v| v.trim().parse::<usize>().ok())
    }) else {
        return moved(t.to_string(), "no MISSING_CEILING=<n> line");
    };
    let Some(lower) = n.checked_sub(1) else {
        return moved(
            t.to_string(),
            "MISSING_CEILING is 0: there is no gap left to over-count",
        );
    };
    let (text, hits) = awk_replace(t, r"^MISSING_CEILING=", &format!("MISSING_CEILING={lower}"));
    if hits != 1 {
        return moved(text, "MISSING_CEILING= is not on exactly one line");
    }
    ok(text)
}

pub fn perturb_assurance_required_pin(_: &Path, t: &str) -> Perturbed {
    ok(awk_replace(t, r"^UNREQUIRED_FALSIFIERS=", "UNREQUIRED_FALSIFIERS=255").0)
}

/// The version is READ OUT of the file rather than written here: a hard-coded one goes vacuous
/// the moment the toolchain moves.
pub fn perturb_lean_toolchain_split(_: &Path, t: &str) -> Perturbed {
    let cur = t
        .lines()
        .find_map(|l| {
            rx(r"^.*leanprover/lean4:([^[:space:]]*)")
                .captures(l)
                .map(|c| c[1].to_string())
        })
        .unwrap_or_default();
    if cur.is_empty() {
        return moved(t.to_string(), "no leanprover/lean4 version found");
    }
    let other = if cur == "v4.29.0" {
        "v4.28.0"
    } else {
        "v4.29.0"
    };
    ok(sed_s(
        t,
        &regex::escape(&format!("leanprover/lean4:{cur}")),
        &format!("leanprover/lean4:{other}"),
    ))
}

pub fn perturb_self_pin_sha(_: &Path, t: &str) -> Perturbed {
    ok(sed_s(
        t,
        r"(uses: coproduct-opensource/nucleus/[^@]*@)[0-9a-f]{40}",
        "${1}0000000000000000000000000000000000000000",
    ))
}

pub fn perturb_allowlist_pin(_: &Path, t: &str) -> Perturbed {
    ok(awk_replace(t, r"^mediation/net=", "mediation/net=255").0)
}

pub fn perturb_push_auth_strip(_: &Path, t: &str) -> Perturbed {
    ok(sed_d(t, r"git remote set-url origin"))
}

pub fn perturb_coverage_floor(_: &Path, t: &str) -> Perturbed {
    ok(sed_s(t, r"(--fail-under-lines )[0-9.]+", "${1}82.4"))
}

pub fn perturb_gate_budget_timeout(_: &Path, t: &str) -> Perturbed {
    ok(sed_s(
        t,
        r#"^( *)timeout: "[0-9]+""#,
        r#"${1}timeout: "9999""#,
    ))
}

pub fn perturb_pipefail_new_unguarded_pipe(_: &Path, t: &str) -> Perturbed {
    ok(perl_first(
        t,
        r"(\n( +)run: \|\n)",
        "${1}${2}  cat /etc/hostname | tr -d \"\\n\"\n",
    ))
}

pub fn perturb_wasm_closure_forbid_present(_: &Path, t: &str) -> Perturbed {
    ok(sed_s(t, r"^FORBIDDEN=\((.*)\)$", "FORBIDDEN=(${1} serde)"))
}

/// The 2026-09-19 outage state: a gate definition that declares no `tools`. The key is removed
/// as text, so every other byte of the file is what was committed.
pub fn perturb_gate_def_tools_dropped(_: &Path, t: &str) -> Perturbed {
    let out = perl_first(t, r#"(?m)^  "tools": \[[^\]]*\],\n"#, "");
    let parsed: Option<serde_json::Value> = serde_json::from_str(&out).ok();
    match parsed {
        Some(v) if v.get("tools").is_none() => ok(out),
        _ => moved(
            t.to_string(),
            "the gate definition's top-level \"tools\" list changed shape;\n         this perturbation no longer applies and must be updated.",
        ),
    }
}

pub fn perturb_dep_ceiling_raise(_: &Path, t: &str) -> Perturbed {
    ok(sed_s(
        t,
        r#"^([[:space:]]*"[a-z0-9_-]+) [0-9]+""#,
        r#"${1} 9""#,
    ))
}

/// The forbidden spelling is assembled, never written: the gate scans shell, and a payload
/// holding the literal would make the next shell copy of this a hit on itself.
pub fn perturb_portability_bsd_only(_: &Path, t: &str) -> Perturbed {
    ok(perl_first(
        t,
        &regex::escape(r#"tmp="$(mktemp)""#),
        concat!("tmp=\"$$(mk", "temp -", "t golden)\""),
    ))
}

pub fn perturb_action_inputs_undeclared_key(_: &Path, t: &str) -> Perturbed {
    ok(perl_first(
        t,
        r"(?m)^(\s*)(scope: \$\{\{ matrix\.scope \}\})$",
        "${1}${2}\n${1}tarjets: wasm32-unknown-unknown",
    ))
}

pub fn gen_policy_base(cwd: &Path, out: &Path) -> bool {
    fs::copy(cwd.join("PolicyManifest.toml"), out).is_ok()
}

pub fn gen_policy_changed(_: &Path, out: &Path) -> bool {
    fs::write(out, "PolicyManifest.toml\n").is_ok()
}

pub fn perturb_policy_escalation(_: &Path, t: &str) -> Perturbed {
    ok(perl_first(
        t,
        r"(?m)^(network_allow = \[)",
        "${1}\"evil.example.com\", ",
    ))
}

pub fn perturb_exemplar_baseline(_: &Path, t: &str) -> Perturbed {
    ok(sed_s(
        t,
        r#"("sorry_admit"[[:space:]]*:[[:space:]]*)[0-9]+"#,
        "${1}0",
    ))
}

/// Since #3057 the build pool legitimately requires a volume with all its volumes listed, so the
/// refused state is reached by dropping the volume list.
pub fn perturb_fly_pool_volumes(_: &Path, t: &str) -> Perturbed {
    ok(perl_first(t, r#","volumes":\[[^\]]*\]"#, ""))
}

pub fn perturb_gatehouse_ref_skew(_: &Path, t: &str) -> Perturbed {
    ok(perl_first(
        t,
        r"(GATEHOUSE_REF:\s*)[0-9a-f]{40}",
        "${1}4d425108b1a4de0e0c0f3f0e0d0c0b0a09080706",
    ))
}

pub fn perturb_gatehouse_bin_dir_dropped(_: &Path, t: &str) -> Perturbed {
    ok(perl_first(t, r"(?m)^\s*bin-dir:.*\n", ""))
}

pub fn perturb_runs_on_undeclared_var(_: &Path, t: &str) -> Perturbed {
    ok(perl_first(
        t,
        r"(runs-on: \$\{\{ vars\.)CI_RUNNER",
        "${1}CI_HEAVY_RUNNER",
    ))
}

pub fn perturb_command_band_dropped(_: &Path, t: &str) -> Perturbed {
    ok(perl_first(t, r#"(?m)^"config" = "observe"[^\n]*\n"#, ""))
}

pub fn perturb_workspace_member_dropped(_: &Path, t: &str) -> Perturbed {
    ok(perl_first(
        t,
        r#"(?m)^\s*"crates/nucleus-audit",[^\n]*\n"#,
        "",
    ))
}

/// The defect `cargo xtask test-shards` caught on its first run: a crate that depends on a
/// `test-node` crate left in `test-libs`, where that crate is an empty stub.
pub fn perturb_test_shards_layout_drops_a_node_crate(_: &Path, t: &str) -> Perturbed {
    let out = t.replacen("\"nucleus-microvm-host\", ", "", 1);
    if out == t {
        return moved(
            t.to_string(),
            "nucleus-microvm-host is no longer in test-node's packages;\n         this perturbation no longer applies and must be updated.",
        );
    }
    ok(out)
}

/// A committed shard generation that is not what the layout generates: one exclude gone.
pub fn perturb_test_shards_generation_stale(_: &Path, t: &str) -> Perturbed {
    let out = perl_first(t, r#"(?m)^\s*"crates/xtask/\*/\*/\*\*",\n"#, "");
    if out == t {
        return moved(
            t.to_string(),
            "test-libs.json no longer excludes crates/xtask/*/*/**;\n         this perturbation no longer applies and must be updated.",
        );
    }
    ok(out)
}

/// The plan's generated test-libs term edited by hand: its first `crates/xtask/*/*/**` gone.
pub fn perturb_test_shards_plan_term_stale(_: &Path, t: &str) -> Perturbed {
    let out = t.replacen(r#"#b"crates/xtask/*/*/**", "#, "", 1);
    if out == t {
        return moved(
            t.to_string(),
            "pipeline.writ's generated test-libs term no longer names crates/xtask/*/*/**;\n         this perturbation no longer applies and must be updated.",
        );
    }
    ok(out)
}

pub fn perturb_unported_shell_gate(_: &Path, t: &str) -> Perturbed {
    ok(append(
        t,
        &["echo \"unported gate PASSED: a question the Rust harness does not ask.\""],
    ))
}

pub fn perturb_convergence_linearity(_: &Path, t: &str) -> Perturbed {
    ok(append(
        t,
        &[&format!(
            "fn _gate_of_gates_affine(_a: &portcullis_effects::{WITNESS}) {{}}"
        )],
    ))
}

/// UNQUALIFIED, unlike the convergence payload: `bound` compares the HEAD of the type against a
/// closed vocabulary, and the head of the qualified form is the crate name.
pub fn perturb_bound_dropped_witness(_: &Path, t: &str) -> Perturbed {
    ok(append(
        t,
        &[&format!(
            "fn _gate_of_gates_dropped(_authority: {WITNESS}) {{}}"
        )],
    ))
}

/// The perturbation SCALES WITH THE FAMILY: k witnesses take d/p to (d+k)/(p+k), and crossing
/// one basis point needs k >= ((F+1)p - 10000d) / (9999-F). F and p are read from the pin in
/// `.scorecard-ratchet.toml`, and d is what a tight pin implies, ceil(F*p/10000).
pub fn perturb_scorecard_slack(_: &Path, t: &str) -> Perturbed {
    // A-19: create genuine Slack even when the bound family already measures 100%.
    // Lower the temporary pin, never the committed floor or the measured population.
    let Some(section) = t.find("[family.bound]\n") else {
        return moved(t.to_string(), "bound family is absent");
    };
    let end = t[section..].find("\n[").map_or(t.len(), |n| section + n);
    let pattern = rx(r"(?m)^floor_bp = (\d+)");
    let Some(captures) = pattern.captures(&t[section..end]) else {
        return moved(t.to_string(), "bound floor is absent");
    };
    let Some(floor) = captures[1]
        .parse::<u32>()
        .ok()
        .and_then(|n| n.checked_sub(1))
    else {
        return moved(t.to_string(), "bound floor cannot be lowered");
    };
    if floor == 0 {
        return moved(
            t.to_string(),
            "a zero pin would fail parsing, not the Slack decision",
        );
    }
    let value = captures.get(1).expect("matched floor");
    let mut out = t.to_string();
    out.replace_range(
        section + value.start()..section + value.end(),
        &floor.to_string(),
    );
    ok(out)
}

pub fn perturb_scorecard_undischarged_law(_: &Path, t: &str) -> Perturbed {
    ok(append(
        t,
        &[concat!(
            "impl Distributive",
            "Lattice for _GateOfGatesAlg {}"
        )],
    ))
}

pub fn perturb_scorecard_partial_totality(_: &Path, t: &str) -> Perturbed {
    ok(sed_s(t, r"^        clippy::indexing_slicing,$", ""))
}

pub fn perturb_scorecard_forever_waiver(_: &Path, t: &str) -> Perturbed {
    ok(sed_s(t, r"^    #\[expect\($", concat!("    #[al", "low(")))
}

pub fn perturb_scorecard_first_expiry(_: &Path, t: &str) -> Perturbed {
    ok(sed_s(
        t,
        r"^pub struct ServeToken \{$",
        concat!("pub struct Serve", "Token {\n    expires_at: u64,"),
    ))
}

pub fn perturb_econ_boundary_reach(_: &Path, t: &str) -> Perturbed {
    let line = "    let requested = state.runtime.policy().capabilities.level_for(op);";
    ok(sed_s(
        t,
        &format!("^{}$", regex::escape(line)),
        &format!(
            "{}\n{line}",
            concat!(
                "    let _ = nucleus_permission",
                "_market::PermissionMarket::new();"
            )
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sed_s_replaces_the_first_match_on_every_line_and_keeps_a_missing_newline() {
        assert_eq!(sed_s("a a\nb a\na", "a", "x"), "x a\nb x\nx");
    }

    #[test]
    fn sed_d_and_awk_replace_are_line_wise() {
        assert_eq!(sed_d("keep\ndrop me\nkeep\n", "drop"), "keep\nkeep\n");
        assert_eq!(
            awk_replace("A=1\nB=2", "^A=", "A=9"),
            ("A=9\nB=2\n".to_string(), 1)
        );
    }

    #[test]
    fn a_slack_pin_is_rejected_including_at_a_complete_family() {
        use crate::scorecard::{Census, Finding, decide, parse_ratchet};
        for (discharged, population) in [(173, 174), (198, 198)] {
            let census = Census {
                discharged,
                population,
                undeclared: 0,
            };
            let original = format!(
                "[family.bound]\nfloor_bp = {}\npopulation_floor = {population}\nfloor_set = \"measurement\"\n",
                census.basis_points()
            );
            let card = vec![("bound".to_string(), census)];
            assert!(decide(&parse_ratchet(&original).unwrap(), &card).is_empty());
            let changed = perturb_scorecard_slack(Path::new("."), &original);
            assert!(changed.complaint.is_none());
            assert!(
                matches!(decide(&parse_ratchet(&changed.text).unwrap(), &card).as_slice(),
                [Finding::Slack { family, .. }] if family == "bound")
            );
            assert!(decide(&parse_ratchet(&original).unwrap(), &card).is_empty());
        }
    }

    #[test]
    fn a_slack_probe_refuses_a_missing_or_unlowerable_pin() {
        for text in [
            "",
            "[family.bound]\nfloor_bp = 0\n",
            "[family.bound]\nfloor_bp = 1\n",
        ] {
            let changed = perturb_scorecard_slack(Path::new("."), text);
            assert!(changed.complaint.is_some());
            assert_eq!(changed.text, text);
        }
    }

    #[test]
    fn the_pipefail_payload_carries_a_literal_backslash_n() {
        let got = perturb_pipefail_new_unguarded_pipe(Path::new("."), "x:\n    run: |\n      a\n");
        assert_eq!(
            got.text,
            "x:\n    run: |\n      cat /etc/hostname | tr -d \"\\n\"\n      a\n"
        );
    }

    #[test]
    fn a_moved_shape_is_a_complaint_not_a_silent_no_op() {
        let got = perturb_test_helpers_in_prod(Path::new("."), "[dependencies]\n");
        assert!(got.complaint.is_some());
        assert_eq!(got.text, "[dependencies]\n");
    }

    #[test]
    fn the_portability_payload_is_the_bsd_spelling() {
        let got = perturb_portability_bsd_only(Path::new("."), "tmp=\"$(mktemp)\"\n");
        assert_eq!(got.text, concat!("tmp=\"$(mk", "temp -t golden)\"\n"));
    }

    #[test]
    fn dropping_tools_leaves_valid_json() {
        let src = "{\n  \"a\": 1,\n  \"tools\": [\n    \"x\"\n  ],\n  \"b\": 2\n}\n";
        let got = perturb_gate_def_tools_dropped(Path::new("."), src);
        assert!(got.complaint.is_none());
        assert_eq!(got.text, "{\n  \"a\": 1,\n  \"b\": 2\n}\n");
    }
}

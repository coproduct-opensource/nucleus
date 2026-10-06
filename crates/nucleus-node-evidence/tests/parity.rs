//! The documents-in, report-out entry point ([`nucleus_node_evidence::report`])
//! over the real-TPM fixtures, and the golden reports the browser and Python
//! verifiers must reproduce.
//!
//! `tests/fixtures/parity/cases.json` is the one list of cases. For each, this
//! test checks the EAR status the other fixture tests assert
//! (`live_node_fixtures.rs`, `real_tpm_fixtures.rs`) and that the full report
//! equals the checked-in golden one. `sdks/verifier-js` runs the same cases
//! through its wasm build and requires a deep-equal report; `sdks/verifier-py`
//! does the same natively. So the three languages agree because they are
//! compared with one file this crate wrote, not with each other's restatement.
//!
//! To regenerate the goldens after an intended change to the report:
//! `NUCLEUS_NODE_EVIDENCE_PARITY_WRITE=1 cargo test -p nucleus-node-evidence --test parity`.

use std::path::PathBuf;

use nucleus_node_evidence::{Report, report};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(fixtures().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn status(r: &Report) -> &str {
    match r {
        Report::Appraised { ear, .. } => ear
            .pointer("/submods/node/ear.status")
            .and_then(serde_json::Value::as_str)
            .expect("an EAR always carries a status"),
        Report::Refused { .. } => "refused",
    }
}

#[test]
fn every_parity_case_gives_its_status_and_its_golden_report() {
    let cases: serde_json::Value = serde_json::from_slice(&read("parity/cases.json")).unwrap();
    let cases = cases["cases"].as_array().unwrap();
    // A list that silently emptied would pass every case it no longer holds.
    assert_eq!(cases.len(), 7);
    let write = std::env::var_os("NUCLEUS_NODE_EVIDENCE_PARITY_WRITE").is_some();
    let mut statuses = std::collections::BTreeSet::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let rp = serde_json::to_vec(&case["relying_party"]).unwrap();
        let r = report(
            &read(case["evidence"].as_str().unwrap()),
            &read(case["reference"].as_str().unwrap()),
            &rp,
        )
        .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(status(&r), case["expect_status"], "{name}");
        statuses.insert(status(&r).to_string());
        let mut got = serde_json::to_string_pretty(&r).unwrap();
        got.push('\n');
        let golden = fixtures().join(case["report"].as_str().unwrap());
        if write {
            std::fs::write(&golden, &got).unwrap();
        } else {
            let want = std::fs::read_to_string(&golden).unwrap_or_else(|e| {
                panic!(
                    "{}: {e} (NUCLEUS_NODE_EVIDENCE_PARITY_WRITE=1 writes it)",
                    golden.display()
                )
            });
            // Compared as JSON values, not text: key order depends on whether
            // the build unifies serde_json's `preserve_order` (a workspace-wide
            // build does; `-p nucleus-node-evidence` does not), and key order
            // is not part of the report. The JS and Python tests compare the
            // same way.
            let got: serde_json::Value = serde_json::from_str(&got).unwrap();
            let want: serde_json::Value = serde_json::from_str(&want).unwrap();
            assert_eq!(got, want, "{name}: the report moved from its golden");
        }
    }
    // Every verdict a stranger can get is represented, so a binding that
    // collapsed two of them cannot match every golden.
    assert_eq!(
        statuses.into_iter().collect::<Vec<_>>(),
        ["affirming", "contraindicated", "none", "refused", "warning"]
    );
}

#[test]
fn a_relying_party_document_missing_a_field_is_an_input_error_not_a_verdict() {
    // No `operator_pins`: "trust nothing" must be written `[]`, never reached
    // by omission (ADR 0007 B-1).
    let rp = br#"{"binding":{"executor_key":{"ed25519":"929fbe08d9cbaec3659c5ac626e31bec8065107461fe77aa3b4af1c4f230be85"},"federation":"not_federated"},"freshness":{"epoch":{"receipt_time":1,"max_age_secs":900,"max_future_secs":60}},"trust_roots":[],"now":1}"#;
    let e = report(
        &read("live-node-epoch4-evidence.json"),
        &read("live-node-reference-exact.json"),
        rp,
    )
    .unwrap_err();
    assert!(
        matches!(e, nucleus_node_evidence::InputError::RelyingParty(ref m) if m.contains("operator_pins")),
        "{e}"
    );
}

#[test]
fn the_report_names_the_digest_a_receipt_would() {
    let rp = serde_json::to_vec(&serde_json::json!({
        "binding": {"executor_key": {"ed25519": "929fbe08d9cbaec3659c5ac626e31bec8065107461fe77aa3b4af1c4f230be85"}, "federation": "not_federated"},
        "freshness": {"epoch": {"receipt_time": 1_791_247_262_i64, "max_age_secs": 900, "max_future_secs": 60}},
        "trust_roots": [], "operator_pins": [], "now": 1_791_247_232_i64,
    }))
    .unwrap();
    let r = report(
        &read("live-node-epoch4-evidence.json"),
        &read("live-node-reference-exact.json"),
        &rp,
    )
    .unwrap();
    let (Report::Appraised {
        evidence_sha256, ..
    }
    | Report::Refused {
        evidence_sha256, ..
    }) = r;
    // The digest the live run's signed receipt named (live_node_fixtures.rs).
    assert_eq!(
        evidence_sha256,
        "d0689ce45219cf0e9e7827e0988c00a0a8545df93f773339734d92f44837bcab"
    );
}

#![allow(deprecated)]
//! Consent is declared, never inferred (Program A, PR 2).
//!
//! Every operation above `Never` must be declared `Autonomous` (the
//! `autonomous` set) or `RequiresApproval` (the `obligations` set). An
//! operation in neither, or in both, is refused at construction — by
//! deserialization and by the profile loader — with an error that names it.
//! And nothing decides autonomy from omission: a lattice whose declaration was
//! broken after construction, through the public fields, is decided
//! `RequiresApproval` for the undeclared operation.
//!
//! RED FIRST (A-19). This file uses only API that existed before the change,
//! so it compiles on the previous main and every test below fails there: the
//! deserializer ignored the `autonomous` key, accepted a lattice without one,
//! and the kernel ran an undeclared operation autonomously.

use portcullis::kernel::{Kernel, Verdict};
use portcullis::profile::ProfileSpec;
use portcullis::{CapabilityLevel, Operation, PermissionLattice};

/// A lattice body with `{consent}` spliced in after `obligations`: read and
/// write permitted, nothing else.
fn lattice_json(consent: &str) -> String {
    format!(
        r#"{{
        "id": "00000000-0000-0000-0000-000000000001",
        "description": "consent probe",
        "derived_from": null,
        "capabilities": {{
            "read_files": "always",
            "write_files": "low_risk",
            "edit_files": "never",
            "run_bash": "never",
            "glob_search": "never",
            "grep_search": "never",
            "web_search": "never",
            "web_fetch": "never",
            "git_commit": "never",
            "git_push": "never",
            "create_pr": "never"
        }},
        {consent}
        "paths": {{"allowed": [], "blocked": [], "work_dir": null}},
        "budget": {{"max_cost_usd": "5", "consumed_usd": "0", "max_input_tokens": 100000, "max_output_tokens": 10000}},
        "commands": {{"allowed": [], "blocked": []}},
        "time": {{"valid_from": "2024-01-01T00:00:00Z", "valid_until": "2030-01-01T00:00:00Z"}},
        "created_at": "2024-01-01T00:00:00Z",
        "created_by": "test"
    }}"#
    )
}

fn refusal(consent: &str) -> String {
    match serde_json::from_str::<PermissionLattice>(&lattice_json(consent)) {
        Ok(l) => panic!(
            "a lattice with consent `{consent}` was accepted; read_files consent: {:?}",
            l.requires_approval(Operation::ReadFiles)
        ),
        Err(e) => e.to_string(),
    }
}

#[test]
fn a_lattice_without_an_autonomous_field_is_refused() {
    // Everything permitted IS obligated here, so only the missing field is at
    // fault: the field is required, never read as an empty set.
    let why = refusal(r#""obligations": {"approvals": ["read_files", "write_files"]},"#);
    assert!(why.contains("`autonomous`"), "{why}");
}

#[test]
fn an_undeclared_operation_is_refused_by_name() {
    let why = refusal(r#""obligations": {"approvals": []}, "autonomous": ["read_files"],"#);
    assert!(
        why.contains("write_files"),
        "names the undeclared op: {why}"
    );
    assert!(
        !why.contains("read_files"),
        "and only the undeclared op: {why}"
    );
}

#[test]
fn an_operation_declared_both_ways_is_refused_by_name() {
    let why = refusal(
        r#""obligations": {"approvals": ["write_files"]}, "autonomous": ["read_files", "write_files"],"#,
    );
    assert!(
        why.contains("write_files"),
        "names the contradiction: {why}"
    );
    assert!(why.contains("both"), "{why}");
}

#[test]
fn a_complete_declaration_is_accepted_and_decides_what_it_says() {
    let l: PermissionLattice = serde_json::from_str(&lattice_json(
        r#""obligations": {"approvals": ["write_files"]}, "autonomous": ["read_files"],"#,
    ))
    .expect("every permitted op is declared exactly once");
    assert!(!l.requires_approval(Operation::ReadFiles));
    assert!(l.requires_approval(Operation::WriteFiles));
    // And it survives a round trip unchanged.
    let back: PermissionLattice =
        serde_json::from_str(&serde_json::to_string(&l).unwrap()).expect("round trip");
    assert_eq!(back, l);
}

/// A declaration broken after construction — an operation raised from `Never`
/// through the public field, with no consent stated — is decided
/// `RequiresApproval` by the kernel, never `Allow`.
#[test]
fn the_kernel_never_infers_autonomy_from_omission() {
    let mut perms = PermissionLattice::restrictive();
    assert_eq!(perms.capabilities.write_files, CapabilityLevel::Never);
    perms.capabilities.write_files = CapabilityLevel::LowRisk;

    let mut kernel = Kernel::new(perms);
    let (d, _) = kernel.decide(Operation::WriteFiles, "notes.txt");
    assert!(
        matches!(d.verdict, Verdict::RequiresApproval),
        "an undeclared op ran without approval: {:?}",
        d.verdict
    );
}

#[test]
fn a_profile_that_leaves_an_operation_undeclared_is_refused_by_name() {
    // `web_fetch` is left at its default level (`low_risk`) and declared nowhere.
    let spec = ProfileSpec::from_yaml(
        r#"
name: undeclared
capabilities:
  read_files: always
  write_files: never
  edit_files: never
  glob_search: never
  grep_search: never
  web_search: never
  git_commit: never
  create_pr: never
autonomous: [read_files]
"#,
    )
    .expect("parses");
    let why = spec
        .build()
        .expect_err("web_fetch is undeclared")
        .to_string();
    assert!(why.contains("web_fetch"), "{why}");
    assert!(!why.contains("read_files"), "{why}");
}

#[test]
fn a_profile_that_declares_an_operation_both_ways_is_refused_by_name() {
    let spec = ProfileSpec::from_yaml(
        r#"
name: contradictory
capabilities:
  read_files: always
  write_files: never
  edit_files: never
  glob_search: never
  grep_search: never
  web_search: never
  web_fetch: never
  git_commit: never
  create_pr: never
obligations: [read_files]
autonomous: [read_files]
"#,
    )
    .expect("parses");
    let why = spec.build().expect_err("read_files both ways").to_string();
    assert!(why.contains("read_files"), "{why}");
    assert!(why.contains("both"), "{why}");
}

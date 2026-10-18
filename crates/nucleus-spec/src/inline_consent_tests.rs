//! Inline pod policies declare consent explicitly (Program A, PR 2).
//!
//! RED FIRST (A-19): these compile on the previous main, where an inline
//! lattice with no `autonomous` field parsed and an undeclared operation
//! resolved — and so ran — autonomously.

use super::*;

fn pod_with_inline(lattice_json: &str) -> Result<PodSpec, String> {
    let json = format!(
        r#"{{"apiVersion":"nucleus/v1","kind":"Pod",
            "spec":{{"policy":{{"type":"inline","lattice":{lattice_json}}}}}}}"#
    );
    serde_json::from_str(&json).map_err(|e| e.to_string())
}

/// The codegen lattice as JSON, with its `autonomous` key removed.
fn codegen_without_autonomous() -> String {
    let mut v = serde_json::to_value(PermissionLattice::codegen()).expect("serializes");
    v.as_object_mut().expect("an object").remove("autonomous");
    v.to_string()
}

#[test]
fn an_inline_policy_that_declares_no_consent_is_refused_by_name() {
    let why = pod_with_inline(&codegen_without_autonomous())
        .expect_err("an inline policy without `autonomous` is refused");
    for op in ["read_files", "write_files", "run_bash", "git_commit"] {
        assert!(why.contains(op), "names {op}: {why}");
    }
}

#[test]
fn an_inline_policy_built_in_code_with_an_undeclared_op_is_refused_at_resolve() {
    let mut lattice = PermissionLattice::restrictive();
    lattice.capabilities.write_files = portcullis::CapabilityLevel::LowRisk;
    let policy = PolicySpec::Inline {
        lattice: Box::new(lattice),
    };
    let why = policy
        .resolve()
        .expect_err("undeclared write_files is refused")
        .to_string();
    assert!(why.contains("write_files"), "{why}");
}

#[test]
fn a_declared_inline_policy_resolves_and_decides_what_it_declares() {
    let json = serde_json::to_string(&PermissionLattice::codegen()).expect("serializes");
    let spec = pod_with_inline(&json).expect("a declared inline policy parses");
    let lattice = spec.spec.resolve_policy().expect("and resolves");
    assert!(!lattice.requires_approval(portcullis::Operation::RunBash));
    assert_eq!(lattice.check_consent(), Ok(()));
}

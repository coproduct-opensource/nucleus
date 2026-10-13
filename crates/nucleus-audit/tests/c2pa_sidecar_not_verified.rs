//! C2PA support is gone from nucleus. A `.c2pa` sidecar next to a provenance
//! output is therefore something nothing here can check — and the command
//! must SAY so, not print a hint about a build feature that no longer exists
//! or pass over the file in silence. "Could not look" is reported as exactly
//! that (A-1).

use std::process::Command;

fn audit() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_nucleus-audit"));
    c.env_remove("RUST_LOG");
    c
}

fn provenance_output(dir: &std::path::Path) -> std::path::PathBuf {
    let out = dir.join("provenance-output.json");
    let doc = serde_json::json!({
        "_provenance": {
            "receipt_chain_head": "sha256:00",
            "schema_hash": "00",
            "contains_ai_derived": true
        }
    });
    std::fs::write(&out, serde_json::to_vec(&doc).unwrap()).unwrap();
    out
}

#[test]
fn a_c2pa_sidecar_is_reported_as_not_verified() {
    let dir = tempfile::tempdir().unwrap();
    let out = provenance_output(dir.path());
    std::fs::write(out.with_extension("c2pa"), b"\x00manifest-bytes").unwrap();

    // The old name keeps working, so a script that called it learns the
    // sidecar went unchecked instead of failing on an unknown subcommand.
    for subcommand in ["inspect-provenance", "verify-c2pa"] {
        let run = audit()
            .args([subcommand, "--output"])
            .arg(&out)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&run.stdout);
        assert!(
            stdout.contains("NOT VERIFIED: C2PA support was removed"),
            "{subcommand}: {stdout}\n{}",
            String::from_utf8_lossy(&run.stderr)
        );
    }
}

#[test]
fn with_no_sidecar_nothing_about_c2pa_is_claimed() {
    let dir = tempfile::tempdir().unwrap();
    let out = provenance_output(dir.path());
    let run = audit()
        .args(["inspect-provenance", "--output"])
        .arg(&out)
        .output()
        .unwrap();
    assert!(run.status.success(), "{run:?}");
    let stdout = String::from_utf8_lossy(&run.stdout);
    assert!(!stdout.contains("C2PA"), "{stdout}");
}

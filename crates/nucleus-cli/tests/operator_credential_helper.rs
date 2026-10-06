//! `nucleus federation operator-assertion --format executable-credential`
//! is run by a token-exchange client that reads stdout as the response and
//! merges stderr into it. One log line on stderr turns a valid assertion into
//! an unparseable response, so the real binary must write the JSON and
//! nothing else, on either stream.

use std::process::{Command, Stdio};

fn nucleus() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nucleus"))
}

#[test]
fn the_credential_helper_writes_only_its_response() {
    let dir = tempfile::tempdir().unwrap();
    let keys = dir.path().join("operator-key");
    let keys = keys.to_str().unwrap();
    let init = nucleus()
        .args([
            "federation",
            "operator-key",
            "--key-store",
            "file",
            "--key-dir",
            keys,
            "init",
        ])
        .env_remove("RUST_LOG")
        .output()
        .unwrap();
    assert!(init.status.success(), "{init:?}");

    let out = nucleus()
        .args([
            "federation",
            "operator-assertion",
            "--key-store",
            "file",
            "--key-dir",
            keys,
            "--issuer",
            "https://operator.example.invalid",
            "--trust-domain",
            "operator.example.invalid",
            "--audience",
            "//relying-party.example.invalid/providers/operator",
            "--format",
            "executable-credential",
        ])
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert!(
        out.stderr.is_empty(),
        "stderr would corrupt the merged response: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let resp: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is one JSON value");
    assert_eq!(resp["success"], true);
    assert!(
        resp["id_token"]
            .as_str()
            .is_some_and(|t| t.split('.').count() == 3)
    );
}

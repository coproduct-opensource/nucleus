//! Exercise the actual process protocol used by a pinned service child.
use nucleus_studio_proof::{
    Packet,
    definition::{self, Certificate, Expected},
    envelope::digest_json,
};
use serde_json::{Value, json};
use std::{
    io::Write as _,
    process::{Command, Stdio},
};

fn invoke(args: &[&str], input: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_studio-proof-certify"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn definition_child_produces_recheckable_evidence_and_refuses_other_commitments() {
    let mut packet: Packet =
        serde_json::from_slice(include_bytes!("../fixtures/equipment.packet.json")).unwrap();
    packet.new_recipe = packet.old_recipe.clone();
    packet.after = packet.before.clone();
    packet.authority_after = packet.authority_before.clone();
    let c = Certificate {
        purpose: definition::PURPOSE.into(),
        blueprint: json!({"version":1,"spec":packet.new_recipe}),
        packet,
        delta_gzip: vec![],
    };
    let blueprint = digest_json(&c.blueprint).unwrap();
    let contract = digest_json(&c.packet.after).unwrap();
    let input = serde_json::to_vec(&c).unwrap();
    let output = invoke(&["--definition", &blueprint, &contract], &input);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.as_object().unwrap().len(), 2);
    let generated: Certificate = serde_json::from_value(output["certificate"].clone()).unwrap();
    assert!(!generated.delta_gzip.is_empty());
    let mut original = generated.clone();
    original.delta_gzip.clear();
    assert_eq!(
        serde_json::to_value(original).unwrap(),
        serde_json::to_value(&c).unwrap()
    );
    let checked = definition::verify_bytes(
        include_bytes!("../fixtures/base.ndjson.gz"),
        &serde_json::to_vec(&generated).unwrap(),
        Expected {
            blueprint_sha256: &blueprint,
            contract_sha256: &contract,
        },
    )
    .unwrap();
    assert_eq!(output["checked"], serde_json::to_value(checked).unwrap());
    for (args, body) in [
        (vec!["--definition", &contract, &contract], input.clone()),
        (vec!["--definition", &blueprint, &blueprint], input.clone()),
        (
            vec!["--definition", &blueprint, &contract],
            serde_json::to_vec(&generated).unwrap(),
        ),
        (vec!["https://studio.example", "studio.example"], input),
    ] {
        let refusal = invoke(&args, &body);
        assert!(!refusal.status.success());
        assert!(refusal.stdout.is_empty());
    }
}

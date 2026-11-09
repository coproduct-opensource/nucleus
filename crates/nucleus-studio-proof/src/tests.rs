use crate::export::{self, verify};
use std::io::Read as _;

fn inflate(bytes: &[u8], limit: usize) -> Vec<u8> {
    let mut out = vec![];
    flate2::read::GzDecoder::new(bytes)
        .take((limit + 1) as u64)
        .read_to_end(&mut out)
        .unwrap();
    assert!(out.len() <= limit);
    out
}

#[test]
fn actual_closed_decision_rechecks_and_substitution_and_false_proof_refuse() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let base = inflate(
                include_bytes!("../fixtures/base.ndjson.gz"),
                export::MAX_BASE_BYTES,
            );
            let delta = inflate(
                include_bytes!("../fixtures/equipment.delta.ndjson.gz"),
                crate::MAX_PACKET_BYTES,
            );
            let packet = include_bytes!("../fixtures/equipment.packet.json");
            let mut proof = base.clone();
            proof.extend_from_slice(&delta);
            let checked = verify(&base, &proof, packet)
                .expect("actual app decision must independently recheck");
            assert!(
                serde_json::to_value(checked).unwrap()["declaration_count"]
                    .as_u64()
                    .unwrap()
                    > 0
            );

            // A valid proof of the generic laws alone is not a per-app decision.
            assert!(
                verify(&base, &base, packet)
                    .unwrap_err()
                    .contains("decision theorem missing")
            );
            let mut swapped: serde_json::Value = serde_json::from_slice(packet).unwrap();
            swapped["after"]["views"][0]["columns"][0]["label"] =
                serde_json::json!("Different visible field");
            assert!(
                verify(&base, &proof, &serde_json::to_vec(&swapped).unwrap())
                    .unwrap_err()
                    .contains("statement differs")
            );

            let mut wrong_base = base.clone();
            wrong_base[0] ^= 1;
            assert!(
                verify(&wrong_base, &proof, packet)
                    .unwrap_err()
                    .contains("base digest differs")
            );

            // Keep the exact statement and typed literals; replace its actual proof
            // with a Sort. Binding checks still pass, so only kernel checking can
            // refuse this certificate (ADR I-1).
            let mut lines: Vec<serde_json::Value> = delta
                .split(|b| *b == b'\n')
                .filter(|l| !l.is_empty())
                .map(|l| serde_json::from_slice(l).unwrap())
                .collect();
            let last = lines
                .iter_mut()
                .rev()
                .find(|line| line.get("thm").is_some())
                .unwrap();
            last["thm"]["value"] = serde_json::json!(0);
            let mut false_proof = base.clone();
            for line in lines {
                false_proof.extend_from_slice(&serde_json::to_vec(&line).unwrap());
                false_proof.push(b'\n');
            }
            let rejected = std::panic::catch_unwind(|| verify(&base, &false_proof, packet));
            assert!(
                !matches!(rejected, Ok(Ok(_))),
                "a false proof was certified"
            );
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn wire_shape_refuses_unknown_fields_and_lean_source_injection_is_quoted() {
    let input = include_bytes!("../fixtures/equipment.packet.json");
    let mut packet: serde_json::Value = serde_json::from_slice(input).unwrap();
    packet["after"]["unreadPolicy"] = serde_json::json!("allow");
    assert!(crate::witness_source(&serde_json::to_vec(&packet).unwrap()).is_err());
    packet["after"]
        .as_object_mut()
        .unwrap()
        .remove("unreadPolicy");
    packet["authorityBefore"] = serde_json::json!("\"\naxiom forged : False\n");
    let source = crate::witness_source(&serde_json::to_vec(&packet).unwrap()).unwrap();
    assert_eq!(
        source
            .lines()
            .filter(|line| line.starts_with("axiom "))
            .count(),
        0
    );
}

#[test]
fn rust_constructed_reflexivity_proof_rechecks_and_all_four_bad_edits_refuse() {
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let base = inflate(
                include_bytes!("../fixtures/base.ndjson.gz"),
                export::MAX_BASE_BYTES,
            );
            let packet = include_bytes!("../fixtures/equipment.packet.json");
            let prove = |bytes: &[u8]| {
                let delta = crate::producer::propose_delta(&base, bytes).unwrap();
                let mut proof = base.clone();
                proof.extend_from_slice(&delta);
                verify(&base, &proof, bytes)
            };
            prove(packet)
                .expect("a literal reflexivity proof must recheck for the valid closed decision");
            let original: serde_json::Value = serde_json::from_slice(packet).unwrap();
            for mutation in 0..4 {
                let mut bad = original.clone();
                match mutation {
                    // Return no longer checks that this borrower is the actor.
                    0 => {
                        let commands = bad["after"]["commands"].as_array_mut().unwrap();
                        let return_program =
                            commands.iter_mut().find(|p| p["name"] == "return").unwrap();
                        let instructions = return_program["instructions"].as_array_mut().unwrap();
                        let guard = instructions
                            .iter_mut()
                            .find(|i| {
                                i.pointer("/require/guard/equal/left/link/name")
                                    == Some(&serde_json::json!("borrower"))
                            })
                            .unwrap();
                        *guard = serde_json::json!({"require":{"guard":"human"}});
                    }
                    1 => {
                        let objects = bad["after"]["data"]["schema"]["objects"]
                            .as_array_mut()
                            .unwrap();
                        let asset = objects.iter_mut().find(|o| o["name"] == "Asset").unwrap();
                        asset["fields"]
                            .as_array_mut()
                            .unwrap()
                            .retain(|f| f["name"] != "value_description");
                    }
                    2 => bad["after"]["commands"][1]["instructions"]
                        .as_array_mut()
                        .unwrap()
                        .push(serde_json::json!({"erase":{"binding":"item"}})),
                    _ => {
                        bad["after"]["views"][0]["columns"][0]["label"] =
                            serde_json::json!("Tampered contract label")
                    }
                }
                let bytes = serde_json::to_vec(&bad).unwrap();
                let refusal = std::panic::catch_unwind(|| prove(&bytes));
                assert!(
                    !matches!(refusal, Ok(Ok(_))),
                    "certified unsafe edit {mutation}"
                );
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

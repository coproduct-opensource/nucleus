use super::invalid;
use crate::AuditError;
use ed25519_dalek::{Signature, VerifyingKey};
use nucleus_spec::host_effect::outcome::{SignedOutcome, VERSION, record_hash, signing_bytes};
use std::{collections::BTreeSet, path::Path};

pub(super) fn verify(
    path: &Path,
    pod: &str,
    key: &VerifyingKey,
    authorizations: &BTreeSet<String>,
) -> Result<usize, AuditError> {
    let mut lines = crate::record_lines::open(path)?;
    let mut previous = String::new();
    let mut seen = BTreeSet::new();
    for line in &mut lines {
        let (number, text) = line?;
        let record: SignedOutcome = crate::record_lines::parse(number, &text)?;
        let claim = &record.outcome;
        if claim.version != VERSION
            || claim.pod_id != pod
            || claim.sequence != seen.len() as u64 + 1
            || claim.previous_record_sha256 != previous
            || !authorizations.contains(&claim.authorization_record_sha256)
            || seen.contains(&claim.authorization_record_sha256)
        {
            return Err(invalid(
                number,
                "wrong outcome schema, pod, sequence, chain, or authorization",
            ));
        }
        let signature = hex::decode(&record.signature)
            .map_err(|_| invalid(number, "invalid outcome signature encoding"))?;
        let signature = Signature::from_slice(&signature)
            .map_err(|_| invalid(number, "invalid outcome signature length"))?;
        let bytes = signing_bytes(claim).map_err(|e| invalid(number, e.to_string()))?;
        key.verify_strict(&bytes, &signature)
            .map_err(|_| invalid(number, "host outcome signature does not verify"))?;
        previous = record_hash(&record).map_err(|e| invalid(number, e.to_string()))?;
        seen.insert(claim.authorization_record_sha256.clone());
    }
    lines.finish(seen.len())?;
    Ok(seen.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use nucleus_spec::host_effect::outcome::{Outcome, Termination};

    fn signed(
        key: &SigningKey,
        sequence: u64,
        authorization: &str,
        previous: String,
    ) -> SignedOutcome {
        let outcome = Outcome {
            version: VERSION,
            pod_id: "pod-a".into(),
            sequence,
            authorization_record_sha256: authorization.into(),
            observed_unix: 100,
            termination: Termination::Interrupted,
            response: None,
            previous_record_sha256: previous,
        };
        let signature = hex::encode(key.sign(&signing_bytes(&outcome).unwrap()).to_bytes());
        SignedOutcome { outcome, signature }
    }

    #[test]
    fn rejects_unknown_duplicate_tampered_and_guest_signed_outcomes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("outcomes.jsonl");
        let key = SigningKey::from_bytes(&[38; 32]);
        let auth = BTreeSet::from(["auth-a".into(), "auth-b".into()]);
        let first = signed(&key, 1, "auth-a", String::new());
        let check = |records: &[SignedOutcome]| {
            let lines: String = records
                .iter()
                .map(|r| format!("{}\n", serde_json::to_string(r).unwrap()))
                .collect();
            std::fs::write(&path, lines).unwrap();
            verify(&path, "pod-a", &key.verifying_key(), &auth)
        };
        assert_eq!(check(&[]).unwrap(), 0, "missing outcomes are unknown");
        assert_eq!(check(std::slice::from_ref(&first)).unwrap(), 1);
        let second = signed(&key, 2, "auth-b", record_hash(&first).unwrap());
        assert_eq!(check(&[first.clone(), second.clone()]).unwrap(), 2);
        assert!(check(&[second]).is_err(), "missing prefix");
        let duplicate = signed(&key, 2, "auth-a", record_hash(&first).unwrap());
        assert!(check(&[first.clone(), duplicate]).is_err());
        assert!(check(&[signed(&key, 1, "foreign", String::new())]).is_err());
        assert!(
            check(&[signed(
                &SigningKey::from_bytes(&[39; 32]),
                1,
                "auth-a",
                String::new()
            )])
            .is_err()
        );
        let mut tampered = first;
        tampered.outcome.termination = Termination::ResponseRead;
        assert!(check(&[tampered]).is_err());
        let torn = serde_json::to_string(&signed(&key, 1, "auth-a", String::new())).unwrap();
        std::fs::write(&path, torn).unwrap();
        assert!(matches!(
            verify(&path, "pod-a", &key.verifying_key(), &auth),
            Err(AuditError::TornTail { .. })
        ));
    }
}

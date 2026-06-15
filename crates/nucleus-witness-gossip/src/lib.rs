//! `nucleus-witness-gossip` — slice 1: the **verifiable-head message
//! layer** for best-effort cosignature dissemination.
//!
//! # What this is (and is NOT)
//!
//! This crate defines the wire shape of a witness cosignature ready to
//! be *gossiped* between verifiers ([`SignedWitnessHead`]) and the pure
//! verification logic that turns a pile of received heads into the SET
//! OF WITNESS NAMES whose signatures actually checked out
//! ([`collect_verified_names`]). That set is fed, UNCHANGED, into the
//! existing k-of-n quorum evaluator
//! ([`nucleus_lineage::policy::Policy::is_satisfied`]).
//!
//! It is **NOT** consensus and adds **NO** availability or ordering
//! guarantee. Gossip is best-effort byte-movement; the sole
//! cryptographic trust boundary remains the k-of-n cosignature check.
//! Even a perfect split-view attacker who controls dissemination cannot
//! manufacture a quorum, because every head must carry a valid Ed25519
//! cosignature under a pubkey the *verifier already trusts*.
//!
//! # Load-bearing invariants
//!
//! 1. **Signed messages only, fail-closed.** A forged, unsigned,
//!    wrong-key, or tampered head contributes *nothing* to the
//!    verified-names set. There is no fail-open path.
//! 2. **No key smuggling.** The verifier verifies a head against the
//!    pubkey from its OWN trusted policy, keyed by `witness_name` —
//!    NEVER a pubkey carried in the gossip message. A [`SignedWitnessHead`]
//!    deliberately carries no pubkey field, so a malicious gossiper
//!    cannot supply a key that "verifies" its own forgery.
//! 3. **Pure.** No iroh / iroh-gossip / QUIC dependency. Transport is
//!    slice 2. This slice is crypto + name-collection only.
//!
//! # Crypto reuse
//!
//! We do not re-invent the cosignature/v1 framing. [`verify_head`]
//! reconstructs the exact bytes the witness signed via
//! [`nucleus_witness::WitnessKey::cosignature_message`] —
//! `b"cosignature/v1\n" + b"time <ts>\n" + note_body` — and checks the
//! Ed25519 signature against it.

use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use nucleus_witness::WitnessKey;
use serde::{Deserialize, Serialize};

/// A witness cosignature over a checkpoint, ready for gossip
/// dissemination.
///
/// There is **no embedded pubkey by design**: the verifier supplies the
/// trusted key from its own policy (keyed by [`Self::witness_name`]), so
/// a gossiped message can never smuggle in the key used to check it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedWitnessHead {
    /// Log identifier (origin) — e.g. `"nucleus.example.com/log42"`.
    pub origin: String,
    /// The witness's C2SP name — must match a declared witness in the
    /// verifier's policy for the head to count toward quorum.
    pub witness_name: String,
    /// Unix seconds at which the witness cosigned. Part of the signed
    /// message, so it is covered by the signature.
    pub timestamp: u64,
    /// Full checkpoint note body (including its final newline), exactly
    /// as the witness signed it.
    pub note_body: Vec<u8>,
    /// Ed25519 signature over the cosignature/v1 message.
    #[serde(with = "sig_serde")]
    pub sig: [u8; 64],
}

/// Serde shim for the 64-byte signature: serde derives arrays only up to
/// length 32, so we round-trip the signature through a byte slice / `Vec`
/// (fixed-length, fail-closed on a wrong length).
mod sig_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(sig: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(sig)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let bytes = <Vec<u8>>::deserialize(d)?;
        let arr: [u8; 64] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::invalid_length(bytes.len(), &"64 bytes"))?;
        Ok(arr)
    }
}

/// Verify a head's signature using a trusted pubkey (supplied by the
/// verifier from its OWN policy — never from the message).
///
/// Returns `true` iff the Ed25519 signature is valid over the exact
/// cosignature/v1 message
/// (`b"cosignature/v1\n" + b"time <timestamp>\n" + note_body`); returns
/// `false` for any tampering (note body, timestamp, signature) or a
/// wrong key. Fail-closed: a malformed key also returns `false`.
pub fn verify_head(head: &SignedWitnessHead, trusted_pubkey: &[u8; 32]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(trusted_pubkey) else {
        return false;
    };
    let msg = WitnessKey::cosignature_message(head.timestamp, &head.note_body);
    let sig = Signature::from_bytes(&head.sig);
    vk.verify(&msg, &sig).is_ok()
}

/// Verify all heads and collect the witness names whose signatures
/// validate against the verifier's trusted policy keys.
///
/// For each head: look up its `witness_name` in `policy_keys`, verify
/// the head against that trusted pubkey, and insert the name iff the
/// signature checks out. Heads whose name is not in `policy_keys`, or
/// whose signature is invalid, are silently dropped (fail-closed).
///
/// The returned set is ready to pass directly to
/// [`nucleus_lineage::policy::Policy::is_satisfied`].
pub fn collect_verified_names(
    heads: &[SignedWitnessHead],
    policy_keys: &HashMap<String, [u8; 32]>,
) -> HashSet<String> {
    let mut verified_names = HashSet::new();
    for head in heads {
        if let Some(pubkey) = policy_keys.get(&head.witness_name) {
            if verify_head(head, pubkey) {
                verified_names.insert(head.witness_name.clone());
            }
        }
    }
    verified_names
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use nucleus_lineage::policy::Policy;

    /// Mint a real head by cosigning `note_body` with `wk`, then parsing
    /// the cosignature line's `keyID(4) || ts(8) || sig(64)` payload back
    /// out — exercising the SAME bytes a witness emits on the wire.
    fn mint_head(wk: &WitnessKey, origin: &str, note_body: &[u8], ts: u64) -> SignedWitnessHead {
        let line = wk.cosign_line(note_body, ts);
        // Line is `— <name> <base64(keyID||ts||sig)>`.
        let b64 = line.rsplit(' ').next().expect("base64 token");
        let payload = B64.decode(b64).expect("valid base64 payload");
        assert_eq!(payload.len(), 4 + 8 + 64, "keyID(4)||ts(8)||sig(64)");
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&payload[12..]);
        SignedWitnessHead {
            origin: origin.to_string(),
            witness_name: wk.name().to_string(),
            timestamp: ts,
            note_body: note_body.to_vec(),
            sig,
        }
    }

    /// 1-of-1 policy naming a single witness `name` with `pubkey`.
    fn policy_1_of_1(name: &str, pubkey: &[u8; 32]) -> Policy {
        let src = format!(
            "witness {name} {hex}\nquorum {name}\n",
            hex = hex_encode(pubkey)
        );
        Policy::parse(&src).expect("policy parses")
    }

    fn hex_encode(b: &[u8; 32]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn keys_from(policy: &Policy) -> HashMap<String, [u8; 32]> {
        policy
            .witnesses
            .iter()
            .map(|(n, w)| (n.clone(), w.pubkey))
            .collect()
    }

    const NOTE: &[u8] = b"nucleus.example/log\n5\ncm9vdA==\n";

    // Test 1: a real cosignature verifies, its name enters the set, and
    // the 1-of-1 policy is satisfied.
    #[test]
    fn real_head_verifies_name_in_set_and_quorum_satisfied() {
        let wk = WitnessKey::from_seed([7u8; 32], "w1");
        let head = mint_head(&wk, "nucleus.example/log", NOTE, 1_700_000_000);
        let policy = policy_1_of_1("w1", &wk.verifying_key_bytes());
        let keys = keys_from(&policy);

        assert!(verify_head(&head, &wk.verifying_key_bytes()));
        let names = collect_verified_names(&[head], &keys);
        assert!(names.contains("w1"));
        assert!(policy.is_satisfied(&names));
    }

    // Test 2: tampered note_body → verify fails, name absent, NOT satisfied.
    #[test]
    fn tampered_note_body_fails_closed() {
        let wk = WitnessKey::from_seed([7u8; 32], "w1");
        let mut head = mint_head(&wk, "nucleus.example/log", NOTE, 1_700_000_000);
        head.note_body = b"tampered\n".to_vec();
        let policy = policy_1_of_1("w1", &wk.verifying_key_bytes());
        let keys = keys_from(&policy);

        assert!(!verify_head(&head, &wk.verifying_key_bytes()));
        let names = collect_verified_names(&[head], &keys);
        assert!(!names.contains("w1"));
        assert!(!policy.is_satisfied(&names));
    }

    // Test 3: tampered timestamp → signed message differs → verify fails.
    #[test]
    fn tampered_timestamp_fails_closed() {
        let wk = WitnessKey::from_seed([7u8; 32], "w1");
        let mut head = mint_head(&wk, "nucleus.example/log", NOTE, 1_700_000_000);
        head.timestamp = 1_700_000_001;
        let policy = policy_1_of_1("w1", &wk.verifying_key_bytes());
        let keys = keys_from(&policy);

        assert!(!verify_head(&head, &wk.verifying_key_bytes()));
        let names = collect_verified_names(&[head], &keys);
        assert!(!names.contains("w1"));
        assert!(!policy.is_satisfied(&names));
    }

    // Test 4: tampered signature → verify fails.
    #[test]
    fn tampered_signature_fails_closed() {
        let wk = WitnessKey::from_seed([7u8; 32], "w1");
        let mut head = mint_head(&wk, "nucleus.example/log", NOTE, 1_700_000_000);
        head.sig[0] ^= 0x01;
        let policy = policy_1_of_1("w1", &wk.verifying_key_bytes());
        let keys = keys_from(&policy);

        assert!(!verify_head(&head, &wk.verifying_key_bytes()));
        let names = collect_verified_names(&[head], &keys);
        assert!(!names.contains("w1"));
        assert!(!policy.is_satisfied(&names));
    }

    // Test 5: wrong/other pubkey → a valid signature does NOT verify
    // against an unrelated key.
    #[test]
    fn wrong_pubkey_fails() {
        let signer = WitnessKey::from_seed([7u8; 32], "w1");
        let other = WitnessKey::from_seed([8u8; 32], "other");
        let head = mint_head(&signer, "nucleus.example/log", NOTE, 1_700_000_000);

        assert!(verify_head(&head, &signer.verifying_key_bytes()));
        assert!(!verify_head(&head, &other.verifying_key_bytes()));
    }

    // Test 6: key-smuggling defense — a head claims witness "A" but was
    // signed by B's key. Verified against A's policy pubkey it FAILS, so
    // "A" never enters the set and the policy is not satisfied.
    #[test]
    fn key_smuggling_attempt_fails_closed() {
        let a = WitnessKey::from_seed([7u8; 32], "A");
        let b = WitnessKey::from_seed([8u8; 32], "B");
        // B signs, but the head advertises witness_name "A".
        let mut head = mint_head(&b, "nucleus.example/log", NOTE, 1_700_000_000);
        head.witness_name = "A".to_string();

        // Verifier's policy binds name "A" to A's real pubkey.
        let policy = policy_1_of_1("A", &a.verifying_key_bytes());
        let keys = keys_from(&policy);

        // B's signature does not verify under A's trusted key.
        assert!(!verify_head(&head, &a.verifying_key_bytes()));
        let names = collect_verified_names(&[head], &keys);
        assert!(!names.contains("A"));
        assert!(!policy.is_satisfied(&names));
    }
}

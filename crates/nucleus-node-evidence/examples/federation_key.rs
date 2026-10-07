//! Create a TPM-resident federation key, certify it with the AK, quote the
//! boot, and write what a stranger checks (ADR 0012). Then show that a moved
//! boot state stops the key.
//!
//! ```text
//! federation_key <tpm> capture <out_dir> [nv:<index>|default-ecc]
//! federation_key <tpm> sign <out_dir>
//! ```
//!
//! `<tpm>` is a device (`/dev/tpmrm0`) or `socket:<host:port>` (swtpm).
//! `capture` writes `key.json` (the TPM-wrapped key), `jwks.json`,
//! `federation-keys.json` (the custody statement), `evidence.json` (a quote
//! over nonce `77…77`, bound to executor key `5e…5e` and the JWKS's digest),
//! `ak-pin.txt`, then extends PCR 8 and writes `evidence-moved.json` (nonce
//! `78…78`) and `sign-after-extend.txt`. `sign` signs one digest with
//! `key.json` and reports whether the TPM refused it for its policy.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use nucleus_node_evidence::attester::{
    AkTemplate, Attester, LogSources, Tpm, Transport, default_pcrs,
};
use nucleus_node_evidence::key_attestation::boot_policy_pcrs;
use nucleus_node_evidence::tpm::AkPublic;
use nucleus_node_evidence::tpm_key::{
    TpmEndpoint, WrappedKey, create_federation_key, sign_with_federation_key,
};
use nucleus_node_evidence::{
    AkAnchorClaim, AttestedKey, ExecutorKey, Federation, FederationKeyAttestation, Freshness,
    KEY_ATTESTATION_PROFILE, KeyBinding, Nonce,
};
use sha2::Digest as _;

type Error = Box<dyn std::error::Error>;

fn endpoint(s: &str) -> TpmEndpoint {
    match s.strip_prefix("socket:") {
        Some(addr) => TpmEndpoint::Socket(addr.to_string()),
        None => TpmEndpoint::Device(PathBuf::from(s)),
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct KeyFile {
    public: String,
    private: String,
    policy_pcrs: BTreeSet<u8>,
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn save_key(path: &Path, key: &WrappedKey) -> Result<(), Error> {
    let f = KeyFile {
        public: b64().encode(key.public()),
        private: b64().encode(key.private()),
        policy_pcrs: key.policy_pcrs().clone(),
    };
    std::fs::write(path, serde_json::to_vec_pretty(&f)?)?;
    Ok(())
}

fn load_key(path: &Path) -> Result<WrappedKey, Error> {
    let f: KeyFile = serde_json::from_slice(&std::fs::read(path)?)?;
    Ok(WrappedKey::from_parts(
        b64().decode(f.public)?,
        b64().decode(f.private)?,
        f.policy_pcrs,
    )?)
}

fn sign<T: Transport>(t: &mut Tpm<T>, key: &WrappedKey) -> String {
    let digest: [u8; 32] = sha2::Sha256::digest(b"header.payload").into();
    match sign_with_federation_key(t, key, &digest) {
        Ok(sig) => format!("signed: {}", hex::encode(sig)),
        Err(e) if e.is_policy_failure() => format!("REFUSED by the TPM for its policy: {e}"),
        Err(e) => format!("failed: {e}"),
    }
}

fn main() -> Result<(), Error> {
    let args: Vec<String> = std::env::args().collect();
    let (Some(tpm), Some(cmd), Some(out)) = (args.get(1), args.get(2), args.get(3)) else {
        return Err("usage: federation_key <tpm> capture|sign <out_dir> [ak-template]".into());
    };
    let tpm = endpoint(tpm);
    let out = PathBuf::from(out);
    if cmd == "sign" {
        println!(
            "{}",
            sign(&mut tpm.connect()?, &load_key(&out.join("key.json"))?)
        );
        return Ok(());
    }
    if cmd != "capture" {
        return Err(format!("unknown command {cmd}").into());
    }
    std::fs::create_dir_all(&out)?;
    let template = match args.get(4).map(String::as_str) {
        None | Some("default-ecc") => AkTemplate::DefaultEccP256,
        Some(nv) => AkTemplate::NvIndex(u32::from_str_radix(
            nv.trim_start_matches("nv:").trim_start_matches("0x"),
            16,
        )?),
    };
    let logs = match &tpm {
        TpmEndpoint::Device(_) => LogSources::linux(),
        TpmEndpoint::Socket(_) => LogSources {
            boot_event_log: "/nonexistent/boot".into(),
            ima_sha256: "/nonexistent/ima256".into(),
            ima_sha1: "/nonexistent/ima1".into(),
        },
    };
    let mut attester = Attester::new(
        tpm.connect()?,
        template,
        default_pcrs(),
        logs,
        AkAnchorClaim::OperatorFetched {
            source: "operator".into(),
        },
    );
    let ak = AkPublic::from_tpm2b_public(&attester.ak_public()?)?;
    std::fs::write(out.join("ak-pin.txt"), hex::encode(ak.spki_sha256()))?;

    let key = create_federation_key(attester.tpm(), &boot_policy_pcrs())?;
    save_key(&out.join("key.json"), &key)?;
    let (x, y) = key.point();
    let url = |v: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v);
    let kid = {
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            url(&x),
            url(&y)
        );
        url(&sha2::Sha256::digest(canonical.as_bytes()))
    };
    let jwks = serde_json::json!({ "keys": [{
        "kty": "EC", "crv": "P-256", "x": url(&x), "y": url(&y),
        "kid": kid, "alg": "ES256", "use": "sig"
    }]});
    let jwks_bytes = serde_json::to_vec(&jwks)?;
    std::fs::write(out.join("jwks.json"), &jwks_bytes)?;

    let doc = FederationKeyAttestation {
        profile: KEY_ATTESTATION_PROFILE.into(),
        keys: vec![AttestedKey {
            kid,
            custody: attester.certify_federation_key(&key)?,
        }],
    };
    std::fs::write(
        out.join("federation-keys.json"),
        serde_json::to_vec_pretty(&doc)?,
    )?;

    let binding = KeyBinding {
        executor_key: ExecutorKey::Ed25519([0x5e; 32]),
        federation: Federation::JwksSha256(sha2::Sha256::digest(&jwks_bytes).into()),
    };
    let quote = |attester: &mut Attester<_>, byte: u8| -> Result<Vec<u8>, Error> {
        let e = attester.attest(
            &binding,
            Freshness::Challenge {
                eat_nonce: Nonce::new(vec![byte; 32])?,
            },
        )?;
        Ok(serde_json::to_vec_pretty(&e)?)
    };
    std::fs::write(out.join("evidence.json"), quote(&mut attester, 0x77)?)?;
    println!("before: {}", sign(attester.tpm(), &key));

    // Move the boot state: PCR 8 is the kernel command line.
    attester.tpm().pcr_extend(8, &[0x08; 32])?;
    std::fs::write(out.join("evidence-moved.json"), quote(&mut attester, 0x78)?)?;
    let after = sign(attester.tpm(), &key);
    std::fs::write(out.join("sign-after-extend.txt"), &after)?;
    println!("after extending PCR 8: {after}");
    Ok(())
}

//! Run the attester against a software TPM's socket and print the evidence.
//! Development and fixture capture only; a node uses the device transport.
//!
//! ```text
//! swtpm_attest ADDR EXECUTOR_ED25519_HEX (epoch:COUNTER:IAT | nonce:HEX) [anchor-source]
//! ```
//! The AK's SubjectPublicKeyInfo SHA-256 (what an operator would pin) goes to stderr.

use std::process::ExitCode;

use nucleus_node_evidence::attester::{AkTemplate, Attester, LogSources, SocketTransport, Tpm};
use nucleus_node_evidence::tpm::AkPublic;
use nucleus_node_evidence::{AkAnchorClaim, ExecutorKey, Federation, Freshness, KeyBinding, Nonce};

fn run(args: &[String]) -> Result<String, String> {
    let [addr, key, fresh, rest @ ..] = args else {
        return Err("usage: swtpm_attest ADDR KEY (epoch:N:IAT | nonce:HEX) [source]".into());
    };
    let key: [u8; 32] = hex::decode(key)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "key must be 32 bytes")?;
    let freshness = match fresh.split(':').collect::<Vec<_>>().as_slice() {
        ["epoch", n, t] => Freshness::Epoch {
            counter: n.parse().map_err(|_| "counter")?,
            iat: t.parse().map_err(|_| "iat")?,
        },
        ["nonce", h] => Freshness::Challenge {
            eat_nonce: Nonce::new(hex::decode(h).map_err(|e| e.to_string())?)?,
        },
        _ => return Err("freshness is epoch:N:IAT or nonce:HEX".into()),
    };
    let anchor = match rest.first() {
        Some(source) => AkAnchorClaim::OperatorFetched {
            source: source.clone(),
        },
        None => AkAnchorClaim::None,
    };
    let tpm = Tpm::new(SocketTransport::connect(addr).map_err(|e| e.to_string())?);
    let logs = LogSources {
        boot_event_log: "/nonexistent/swtpm-has-no-firmware-log".into(),
        ima_sha256: "/nonexistent/swtpm-has-no-ima".into(),
        ima_sha1: "/nonexistent/swtpm-has-no-ima".into(),
    };
    let mut a = Attester::new(
        tpm,
        AkTemplate::DefaultEccP256,
        [0u8, 16].into_iter().collect(),
        logs,
        anchor,
    );
    let ak = AkPublic::from_tpm2b_public(&a.ak_public().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    eprintln!("ak_spki_sha256={}", hex::encode(ak.spki_sha256()));
    let binding = KeyBinding {
        executor_key: ExecutorKey::Ed25519(key),
        federation: Federation::NotFederated,
    };
    let e = a.attest(&binding, freshness).map_err(|e| e.to_string())?;
    serde_json::to_string_pretty(&e).map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(s) => {
            println!("{s}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("swtpm_attest: {e}");
            ExitCode::FAILURE
        }
    }
}

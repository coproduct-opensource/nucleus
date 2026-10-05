//! Assemble a `NodeEvidence` document from the files TPM 2.0 command-line
//! tools write, and compute the qualifying data to quote over.
//!
//! This is how the checked-in fixtures under `tests/fixtures/` were made from
//! real TPMs (a software TPM and a cloud vTPM): an independent TPM stack
//! produced the quote, and only the JSON framing is this crate's. See
//! `tests/real_tpm_fixtures.rs` for the capture commands.
//!
//! ```text
//! assemble_evidence qualifying-data --executor-ed25519 HEX (--nonce HEX | --epoch N:IAT)
//! assemble_evidence evidence --executor-ed25519 HEX (--nonce HEX | --epoch N:IAT)
//!     --ak-pub FILE --attest FILE --sig FILE --pcrs FILE --pcr-list 0,1,..
//!     [--event-log FILE] [--ima-log FILE --ima-format sha1|sha256]
//!     (--anchor-operator SOURCE | --anchor-none)
//! ```

use std::collections::BTreeMap;
use std::process::ExitCode;

use nucleus_node_evidence::{
    AkAnchorClaim, BootLog, EVIDENCE_PROFILE, ExecutorKey, Federation, Freshness, ImaLog,
    ImaLogFormat, KeyBinding, NodeEvidence, Nonce, TpmQuote, qualifying_data,
};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn need(args: &[String], name: &str) -> Result<String, String> {
    arg(args, name).ok_or_else(|| format!("missing {name}"))
}

fn read(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{path}: {e}"))
}

fn binding_and_freshness(args: &[String]) -> Result<(KeyBinding, Freshness), String> {
    let key = hex::decode(need(args, "--executor-ed25519")?).map_err(|e| e.to_string())?;
    let key: [u8; 32] = key
        .try_into()
        .map_err(|_| "executor key must be 32 bytes")?;
    let freshness = match (arg(args, "--nonce"), arg(args, "--epoch")) {
        (Some(n), None) => Freshness::Challenge {
            eat_nonce: Nonce::new(hex::decode(n).map_err(|e| e.to_string())?)?,
        },
        (None, Some(e)) => {
            let (c, t) = e.split_once(':').ok_or("--epoch is COUNTER:IAT")?;
            Freshness::Epoch {
                counter: c.parse().map_err(|_| "bad epoch counter")?,
                iat: t.parse().map_err(|_| "bad epoch iat")?,
            }
        }
        _ => return Err("exactly one of --nonce / --epoch".into()),
    };
    Ok((
        KeyBinding {
            executor_key: ExecutorKey::Ed25519(key),
            federation: Federation::NotFederated,
        },
        freshness,
    ))
}

fn evidence(args: &[String]) -> Result<NodeEvidence, String> {
    let (binding, freshness) = binding_and_freshness(args)?;
    let list: Vec<u8> = need(args, "--pcr-list")?
        .split(',')
        .map(|p| p.parse().map_err(|_| format!("bad PCR {p}")))
        .collect::<Result<_, _>>()?;
    let values = read(&need(args, "--pcrs")?)?;
    if values.len() != 32 * list.len() {
        return Err(format!(
            "--pcrs holds {} bytes; {} SHA-256 PCRs need {}",
            values.len(),
            list.len(),
            32 * list.len()
        ));
    }
    let mut pcrs = BTreeMap::new();
    for (i, p) in list.iter().enumerate() {
        let mut v = [0u8; 32];
        v.copy_from_slice(&values[32 * i..32 * (i + 1)]);
        pcrs.insert(*p, v);
    }
    let tpm = TpmQuote::from_parts(
        &read(&need(args, "--ak-pub")?)?,
        &read(&need(args, "--attest")?)?,
        &read(&need(args, "--sig")?)?,
        &pcrs,
    );
    let boot_event_log = match arg(args, "--event-log") {
        Some(p) => BootLog::attach(&read(&p)?),
        None => BootLog::Absent("no firmware event log on this TPM".into()),
    };
    let ima_log = match arg(args, "--ima-log") {
        Some(p) => {
            let format = match need(args, "--ima-format")?.as_str() {
                "sha1" => ImaLogFormat::Sha1TemplateDigests,
                "sha256" => ImaLogFormat::Sha256TemplateDigests,
                other => return Err(format!("unknown IMA format {other}")),
            };
            ImaLog::attach(format, &read(&p)?)
        }
        None => ImaLog::Absent("IMA not enabled".into()),
    };
    let ak_anchor = match (
        arg(args, "--anchor-operator"),
        args.iter().any(|a| a == "--anchor-none"),
    ) {
        (Some(source), false) => AkAnchorClaim::OperatorFetched { source },
        (None, true) => AkAnchorClaim::None,
        _ => return Err("exactly one of --anchor-operator / --anchor-none".into()),
    };
    Ok(NodeEvidence {
        eat_profile: EVIDENCE_PROFILE.into(),
        binding,
        freshness,
        tpm,
        boot_event_log,
        ima_log,
        ak_anchor,
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = match args.first().map(String::as_str) {
        Some("qualifying-data") => {
            binding_and_freshness(&args).map(|(b, f)| hex::encode(qualifying_data(&b, &f)))
        }
        Some("evidence") => evidence(&args)
            .and_then(|e| serde_json::to_string_pretty(&e).map_err(|e| e.to_string())),
        _ => Err("usage: assemble_evidence (qualifying-data | evidence) ...".into()),
    };
    match out {
        Ok(s) => {
            println!("{s}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("assemble_evidence: {e}");
            ExitCode::FAILURE
        }
    }
}

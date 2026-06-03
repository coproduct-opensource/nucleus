//! `verify-guarantee-receipt` — holder-side verifier for a guarantee receipt.
//!
//! Checks that a receipt JSON + detached signature verify against a witness PUBLIC key.
//! This proves only that the named witness signed *this exact receipt* — and a receipt
//! attests only the SCREEN RESULT at one `(source, toolchain, profile)` hash, NOT
//! extractability and NOT correctness (see the `receipt` module docs / README).
//!
//! Usage:
//!   verify-guarantee-receipt --json <receipt.json> --sig <receipt.sig> \
//!       --pubkey-hex <64-hex> | --pubkey-file <path>
//!   [--source <file>]   # optional: also bind-check the anchor_hash to this source file
//!                       #            using the receipt's own toolchain + profile_id
//!
//! Exit code 0 = verified; 1 = NOT verified / error.
//!
//! The signature file is hex (as written by the lint). The pubkey is a 32-byte ed25519
//! verifying key, given as 64 hex chars (`--pubkey-hex`) or a raw/hex file
//! (`--pubkey-file`).

use nucleus_guarantee_receipt::{
    Receipt, load_verifying_key, verify_receipt, verify_receipt_bound_to,
};
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(true) => {
            eprintln!("VERIFIED: signature is valid for this receipt.");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            eprintln!("NOT VERIFIED: signature does not validate (or anchor bind-check failed).");
            ExitCode::FAILURE
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<bool, String> {
    let mut json_path: Option<String> = None;
    let mut sig_path: Option<String> = None;
    let mut pubkey_hex: Option<String> = None;
    let mut pubkey_file: Option<String> = None;
    let mut source_file: Option<String> = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut take = |name: &str| {
            args.next()
                .ok_or_else(|| format!("missing value for {name}"))
        };
        match arg.as_str() {
            "--json" => json_path = Some(take("--json")?),
            "--sig" => sig_path = Some(take("--sig")?),
            "--pubkey-hex" => pubkey_hex = Some(take("--pubkey-hex")?),
            "--pubkey-file" => pubkey_file = Some(take("--pubkey-file")?),
            "--source" => source_file = Some(take("--source")?),
            "-h" | "--help" => {
                print_help();
                return Ok(true);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    let json_path = json_path.ok_or("--json is required")?;
    let sig_path = sig_path.ok_or("--sig is required")?;

    let json = std::fs::read(&json_path).map_err(|e| format!("read {json_path}: {e}"))?;
    let sig_text = std::fs::read_to_string(&sig_path).map_err(|e| format!("read {sig_path}: {e}"))?;
    let sig_bytes = hex::decode(sig_text.trim()).map_err(|e| format!("sig is not hex: {e}"))?;

    let pubkey = match (pubkey_hex, pubkey_file) {
        (Some(h), None) => load_verifying_key(h.trim().as_bytes()).map_err(|e| e.to_string())?,
        (None, Some(f)) => {
            let bytes = std::fs::read(&f).map_err(|e| format!("read {f}: {e}"))?;
            load_verifying_key(&bytes).map_err(|e| e.to_string())?
        }
        (Some(_), Some(_)) => return Err("pass only one of --pubkey-hex / --pubkey-file".into()),
        (None, None) => return Err("one of --pubkey-hex / --pubkey-file is required".into()),
    };

    // Optional fail-closed anchor bind-check against a source file, using the receipt's
    // own declared toolchain + profile_id (so the holder confirms the source matches).
    if let Some(src_file) = source_file {
        let src = std::fs::read_to_string(&src_file).map_err(|e| format!("read {src_file}: {e}"))?;
        let receipt: Receipt =
            serde_json::from_slice(&json).map_err(|e| format!("parse receipt json: {e}"))?;
        return verify_receipt_bound_to(
            &json,
            &sig_bytes,
            &pubkey,
            &src,
            &receipt.toolchain,
            &receipt.profile_id,
        )
        .map_err(|e| e.to_string());
    }

    verify_receipt(&json, &sig_bytes, &pubkey).map_err(|e| e.to_string())
}

fn print_help() {
    eprintln!(
        "verify-guarantee-receipt --json <receipt.json> --sig <receipt.sig> \
         (--pubkey-hex <64hex> | --pubkey-file <path>) [--source <file>]"
    );
}

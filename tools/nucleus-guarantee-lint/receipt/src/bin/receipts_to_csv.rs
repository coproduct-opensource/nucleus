//! `receipts-to-csv` — project a directory of signed guarantee-receipt JSON files into a
//! single CSV that the olog (`ologs/nucleus_security.toml`) can ingest via a
//! `source = { type = "csv", ... }` block.
//!
//! WHY a generator: the olog runtime supports only `csv` and `rustsec` source kinds
//! (see olog `src/olog_runtime.rs::generate_import_pipeline`) — there is no JSON/glob
//! source. So receipts are flattened to CSV here, deterministically, and the olog points
//! a CSV source at the output.
//!
//! HONESTY: this is a PURE data projection — it reads receipts, verifies NOTHING, and
//! writes a row per receipt. A row's presence means "a receipt file existed", which is
//! the `lint_attested` (screen) tier — STRICTLY WEAKER than `parity_tested`/`extracted`.
//! It is NOT a proof and the CSV carries no signature; signature verification is the
//! holder's job via `verify-guarantee-receipt`.
//!
//! Usage: receipts-to-csv <receipt_dir> [out.csv]
//!   default out = <receipt_dir>/../guarantee-receipts.csv
//!
//! CSV columns (header row written), id_col = 0:
//!   anchor_hash,item_path,item_kind,result,toolchain,profile_id,schema_version,ineligible_reasons
//! `ineligible_reasons` is `;`-joined (empty when clean).

use nucleus_guarantee_receipt::Receipt;
use std::path::{Path, PathBuf};

fn main() -> std::process::ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(dir) = args.next() else {
        eprintln!("usage: receipts-to-csv <receipt_dir> [out.csv]");
        return std::process::ExitCode::FAILURE;
    };
    let dir = PathBuf::from(dir);
    let out = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| dir.join("..").join("guarantee-receipts.csv"));

    match run(&dir, &out) {
        Ok(n) => {
            eprintln!("wrote {n} receipt row(s) to {}", out.display());
            std::process::ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(dir: &Path, out: &Path) -> Result<usize, String> {
    let mut rows: Vec<Receipt> = Vec::new();
    let entries = std::fs::read_dir(dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
    for entry in entries {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let bytes = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let receipt: Receipt =
            serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", path.display()))?;
        rows.push(receipt);
    }
    // Deterministic order by anchor_hash so the CSV is reproducible.
    rows.sort_by(|a, b| a.anchor_hash.cmp(&b.anchor_hash));

    let mut csv = String::new();
    csv.push_str(
        "anchor_hash,item_path,item_kind,result,toolchain,profile_id,schema_version,ineligible_reasons\n",
    );
    for r in &rows {
        let result = match r.result {
            nucleus_guarantee_receipt::ScreenResult::Clean => "clean",
            nucleus_guarantee_receipt::ScreenResult::Ineligible => "ineligible",
        };
        let reasons = r.ineligible_reasons.join(";");
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            csv_field(&r.anchor_hash),
            csv_field(&r.item_path),
            csv_field(&r.item_kind),
            result,
            csv_field(&r.toolchain),
            csv_field(&r.profile_id),
            r.schema_version,
            csv_field(&reasons),
        ));
    }
    std::fs::write(out, csv).map_err(|e| format!("write {}: {e}", out.display()))?;
    Ok(rows.len())
}

/// Minimal CSV escaping: quote + double inner quotes when the field contains a comma,
/// quote, or newline.
fn csv_field(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

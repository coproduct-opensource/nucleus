//! The Linux IMA measurement list (binary form), its PCR 10 replay, and the
//! file measurements read out of it.
//!
//! Two binary layouts exist and both are accepted, declared by the evidence:
//!
//! * [`ImaLogFormat::Sha1TemplateDigests`] — `binary_runtime_measurements`.
//!   Each entry's template digest is SHA-1; the SHA-256 bank of PCR 10 was
//!   extended with `SHA-256(template data)`, so replay recomputes it.
//! * [`ImaLogFormat::Sha256TemplateDigests`] — the per-bank
//!   `binary_runtime_measurements_sha256` newer kernels publish. The template
//!   digest *is* the SHA-256 bank extend value; replay checks it recomputes
//!   from the template data before using it.
//!
//! A violation entry (an all-zero template digest) extends `0xFF..FF`, as the
//! kernel does.
//!
//! The log keeps growing after a quote, so the verifier accepts the shortest
//! prefix that reproduces the quoted PCR 10 and reports the rest as an
//! unquoted tail — measured by the kernel, but not covered by this quote, so
//! never read as evidence.

use serde::{Deserialize, Serialize};

use crate::Malformed;
use crate::crypto::sha256;
use crate::wire::Reader;

/// Which binary layout the IMA log is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImaLogFormat {
    /// `binary_runtime_measurements`: SHA-1 template digests.
    Sha1TemplateDigests,
    /// `binary_runtime_measurements_sha256`: SHA-256 template digests.
    Sha256TemplateDigests,
}

impl ImaLogFormat {
    fn digest_len(self) -> usize {
        match self {
            Self::Sha1TemplateDigests => 20,
            Self::Sha256TemplateDigests => 32,
        }
    }
}

/// The file digest a measurement recorded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImaEntry {
    /// The measured path (the `n-ng` field).
    pub path: String,
    /// The digest algorithm named in the `d-ng` field (`sha256` expected).
    pub algorithm: String,
    /// The file digest, hex.
    pub digest: String,
    /// The template name (`ima-ng`, `ima-sig`, `ima-buf`).
    pub template: String,
}

/// The replay-verified part of an IMA log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImaFacts {
    /// Entries covered by the quote, in measurement order. Violation entries
    /// appear with path `"<violation>"`.
    pub entries: Vec<ImaEntry>,
    /// Entries after the quoted prefix: measured after the quote was taken,
    /// not evidence.
    pub unquoted_tail: usize,
}

struct RawEntry {
    pcr: u32,
    extend: [u8; 32],
    entry: ImaEntry,
}

fn field(reason: impl Into<String>) -> Malformed {
    Malformed::Field {
        structure: "IMA log",
        reason: reason.into(),
    }
}

fn parse_template(name: &str, data: &[u8]) -> Result<ImaEntry, Malformed> {
    match name {
        "ima-ng" | "ima-sig" | "ima-buf" => {}
        other => return Err(field(format!("unsupported IMA template {other:?}"))),
    }
    let mut r = Reader::new(data, "IMA template data");
    let d_ng = r.le_sized()?;
    let n_ng = r.le_sized()?;
    let sep = d_ng
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| field("d-ng field has no algorithm separator"))?;
    let (alg, rest) = d_ng
        .split_at_checked(sep)
        .ok_or_else(|| field("d-ng separator"))?;
    let algorithm = String::from_utf8_lossy(alg)
        .trim_end_matches(':')
        .to_string();
    // `rest` starts with the NUL separator `position` found.
    let digest = hex::encode(rest.get(1..).unwrap_or_default());
    let path = String::from_utf8_lossy(n_ng)
        .trim_end_matches('\0')
        .to_string();
    Ok(ImaEntry {
        path,
        algorithm,
        digest,
        template: name.to_string(),
    })
}

fn parse(bytes: &[u8], format: ImaLogFormat) -> Result<Vec<RawEntry>, Malformed> {
    let mut r = Reader::new(bytes, "IMA log");
    let mut out = Vec::new();
    while !r.is_empty() {
        let pcr = r.le_u32()?;
        let template_digest = r.bytes(format.digest_len())?;
        let name = String::from_utf8_lossy(r.le_sized()?).into_owned();
        let data = r.le_sized()?;
        let violation = template_digest.iter().all(|&b| b == 0);
        let extend = if violation {
            [0xFF; 32]
        } else {
            let recomputed = sha256(data);
            if format == ImaLogFormat::Sha256TemplateDigests && template_digest != recomputed {
                return Err(field(format!(
                    "entry {} template digest does not recompute from its data",
                    out.len()
                )));
            }
            recomputed
        };
        let entry = if violation {
            ImaEntry {
                path: "<violation>".into(),
                algorithm: String::new(),
                digest: String::new(),
                template: name,
            }
        } else {
            parse_template(&name, data)?
        };
        out.push(RawEntry { pcr, extend, entry });
    }
    Ok(out)
}

/// Replay `bytes` into a SHA-256 PCR 10 and return the entries of the
/// shortest prefix that reproduces `quoted_pcr10`. `Ok(None)` when no prefix
/// does — the log is not the log behind this quote.
pub fn verify_ima_log(
    bytes: &[u8],
    format: ImaLogFormat,
    quoted_pcr10: &[u8; 32],
) -> Result<Option<ImaFacts>, Malformed> {
    let entries = parse(bytes, format)?;
    let mut pcr = [0u8; 32];
    let mut prefix = (pcr == *quoted_pcr10).then_some(0);
    if prefix.is_none() {
        for (i, e) in entries.iter().enumerate() {
            if e.pcr != 10 {
                return Err(field(format!("entry {i} is for PCR {}, not 10", e.pcr)));
            }
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&pcr);
            buf[32..].copy_from_slice(&e.extend);
            pcr = sha256(&buf);
            if pcr == *quoted_pcr10 {
                prefix = Some(i.saturating_add(1));
                break;
            }
        }
    }
    Ok(prefix.map(|k| {
        let total = entries.len();
        ImaFacts {
            entries: entries.into_iter().take(k).map(|e| e.entry).collect(),
            unquoted_tail: total.saturating_sub(k),
        }
    }))
}

/// Builders for tests.
#[cfg(test)]
pub(crate) mod build {
    use super::*;

    /// An `ima-ng` entry in the SHA-256 per-bank layout; returns the bytes
    /// and advances `pcr10`.
    pub(crate) fn entry(pcr10: &mut [u8; 32], path: &str, file_digest: [u8; 32]) -> Vec<u8> {
        let mut d_ng = b"sha256:\0".to_vec();
        d_ng.extend_from_slice(&file_digest);
        let mut n_ng = path.as_bytes().to_vec();
        n_ng.push(0);
        let mut data = Vec::new();
        for f in [&d_ng, &n_ng] {
            data.extend_from_slice(&u32::try_from(f.len()).unwrap().to_le_bytes());
            data.extend_from_slice(f);
        }
        let td = sha256(&data);
        let mut out = Vec::new();
        out.extend_from_slice(&10u32.to_le_bytes());
        out.extend_from_slice(&td);
        out.extend_from_slice(&6u32.to_le_bytes());
        out.extend_from_slice(b"ima-ng");
        out.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
        out.extend_from_slice(&data);
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(pcr10);
        buf[32..].copy_from_slice(&td);
        *pcr10 = sha256(&buf);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_replay_accepts_a_grown_log() {
        let mut pcr = [0u8; 32];
        let mut log = build::entry(&mut pcr, "boot_aggregate", [1; 32]);
        log.extend(build::entry(
            &mut pcr,
            "/opt/nucleus/bin/nucleus-node",
            [2; 32],
        ));
        let quoted = pcr;
        log.extend(build::entry(&mut pcr, "/opt/nucleus/bin/late", [3; 32]));
        let facts = verify_ima_log(&log, ImaLogFormat::Sha256TemplateDigests, &quoted)
            .unwrap()
            .unwrap();
        assert_eq!(facts.entries.len(), 2);
        assert_eq!(facts.unquoted_tail, 1);
        assert_eq!(facts.entries[1].path, "/opt/nucleus/bin/nucleus-node");
        assert_eq!(facts.entries[1].digest, hex::encode([2u8; 32]));
    }

    #[test]
    fn a_log_that_never_reaches_the_quote_is_none() {
        let mut pcr = [0u8; 32];
        let log = build::entry(&mut pcr, "boot_aggregate", [1; 32]);
        let other = [9u8; 32];
        assert_eq!(
            verify_ima_log(&log, ImaLogFormat::Sha256TemplateDigests, &other).unwrap(),
            None
        );
    }

    #[test]
    fn a_rewritten_entry_is_refused() {
        let mut pcr = [0u8; 32];
        let mut log = build::entry(&mut pcr, "/opt/nucleus/bin/nucleus-node", [2; 32]);
        // Rewrite the file digest inside the template data, leaving the
        // template digest: the per-bank digest no longer recomputes.
        let n = log.len();
        log[n - 40] ^= 1;
        assert!(verify_ima_log(&log, ImaLogFormat::Sha256TemplateDigests, &pcr).is_err());
    }
}

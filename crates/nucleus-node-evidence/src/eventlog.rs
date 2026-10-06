//! The TCG PC Client "crypto agile" boot event log (TCG PC Client Platform
//! Firmware Profile, §10), its replay, and the boot facts read out of it.
//!
//! The log is untrusted text the node hands over. It becomes evidence only
//! through replay: extending a zero register with each event's SHA-256
//! digest must reproduce the PCR value the TPM quoted. A PCR the quote did
//! not cover is never replayed against anything, so no fact is read from
//! its events.
//!
//! Event *data* is a further step removed: the digest is what was measured,
//! and the data is a description of it. A fact taken from event data — the
//! kernel command line, the Secure Boot variable — is used only when the
//! event's digest is recomputable from its data, so the description is the
//! measured thing and not a caption beside it.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::Malformed;
use crate::crypto::{HashAlg, sha256};
use crate::wire::Reader;

const EV_NO_ACTION: u32 = 0x0000_0003;
const EV_IPL: u32 = 0x0000_000D;
const EV_EFI_VARIABLE_DRIVER_CONFIG: u32 = 0x8000_0001;
const EV_EFI_BOOT_SERVICES_APPLICATION: u32 = 0x8000_0003;

const SPEC_ID_SIGNATURE: &[u8; 16] = b"Spec ID Event03\0";
const STARTUP_LOCALITY: &[u8; 16] = b"StartupLocality\0";
const KERNEL_CMDLINE_PREFIX: &[u8] = b"kernel_cmdline: ";

/// The PCR GRUB measures strings (commands, the kernel command line) into.
const PCR_GRUB_STRINGS: u8 = 8;
/// The PCR GRUB measures files it loads (kernel, initrd) into.
const PCR_GRUB_FILES: u8 = 9;
/// The PCR UEFI measures loaded EFI applications into.
const PCR_EFI_APPS: u8 = 4;
/// The PCR UEFI measures the Secure Boot policy into.
const PCR_SECURE_BOOT: u8 = 7;

/// One event, with its SHA-256 bank digest if the log carried one.
#[derive(Clone, Debug)]
pub(crate) struct Event {
    pcr: u8,
    event_type: u32,
    sha256: Option<[u8; 32]>,
    data: Vec<u8>,
}

/// A parsed event log.
#[derive(Clone, Debug)]
pub struct EventLog {
    events: Vec<Event>,
    startup_locality: u8,
}

fn field(reason: impl Into<String>) -> Malformed {
    Malformed::Field {
        structure: "TCG event log",
        reason: reason.into(),
    }
}

/// Parse a crypto-agile event log (`binary_bios_measurements`).
pub fn parse_event_log(bytes: &[u8]) -> Result<EventLog, Malformed> {
    let mut r = Reader::new(bytes, "TCG event log");
    // The first event is in the legacy SHA-1 format and must be the Spec ID
    // event that declares the digest sizes of every later event.
    let _pcr = r.le_u32()?;
    let ty = r.le_u32()?;
    let _sha1 = r.bytes(20)?;
    let spec = r.le_sized()?;
    if ty != EV_NO_ACTION || !spec.starts_with(SPEC_ID_SIGNATURE) {
        return Err(field(
            "first event is not a Spec ID Event03 (not a crypto-agile log)",
        ));
    }
    let body = spec.get(SPEC_ID_SIGNATURE.len()..).unwrap_or_default();
    let mut s = Reader::new(body, "TCG_EfiSpecIDEvent");
    let _platform_class = s.le_u32()?;
    let _minor = s.u8()?;
    let _major = s.u8()?;
    let _errata = s.u8()?;
    let _uintn = s.u8()?;
    let n_algs = s.le_u32()?;
    let mut sizes: BTreeMap<u16, usize> = BTreeMap::new();
    for _ in 0..n_algs {
        let alg = s.le_u16()?;
        let size = s.le_u16()?;
        sizes.insert(alg, usize::from(size));
    }
    let mut events = Vec::new();
    let mut startup_locality = 0u8;
    while !r.is_empty() {
        let pcr = r.le_u32()?;
        let pcr = u8::try_from(pcr).map_err(|_| field(format!("PCR index {pcr}")))?;
        let event_type = r.le_u32()?;
        let count = r.le_u32()?;
        let mut sha = None;
        for _ in 0..count {
            let alg = r.le_u16()?;
            let size = *sizes
                .get(&alg)
                .ok_or_else(|| field(format!("digest algorithm 0x{alg:04x} not in Spec ID")))?;
            let d = r.bytes(size)?;
            if alg == HashAlg::TPM_SHA256 {
                sha = Some(
                    <[u8; 32]>::try_from(d).map_err(|_| field("SHA-256 digest is not 32 bytes"))?,
                );
            }
        }
        let data = r.le_sized()?.to_vec();
        if event_type == EV_NO_ACTION && pcr == 0 && data.starts_with(STARTUP_LOCALITY) {
            startup_locality = data.get(16).copied().unwrap_or(0);
        }
        events.push(Event {
            pcr,
            event_type,
            sha256: sha,
            data,
        });
    }
    Ok(EventLog {
        events,
        startup_locality,
    })
}

/// A quoted PCR the log does not reproduce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayMismatch {
    /// The PCR.
    pub pcr: u8,
    /// What the TPM quoted.
    pub quoted: [u8; 32],
    /// What replaying the log produced (`None`: an event lacked a SHA-256 digest).
    pub replayed: Option<[u8; 32]>,
}

/// The Secure Boot state read from PCR 7.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecureBoot {
    /// The `SecureBoot` variable was measured as 1.
    Enabled,
    /// The `SecureBoot` variable was measured as 0.
    Disabled,
    /// Could not be read from verified events; the reason says why.
    Unknown(String),
}

/// A file the boot loader measured (PCR 9). The digest is replay-verified;
/// the path is the loader's description and is NOT authenticated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BootFile {
    /// SHA-256 of the file contents, hex.
    pub sha256: String,
    /// The path the loader reported (unauthenticated label).
    pub path_label: String,
}

/// What the replay-verified part of the boot log says booted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BootFacts {
    /// PCRs whose events replayed to the quoted value.
    pub verified_pcrs: BTreeSet<u8>,
    /// EFI applications loaded (PCR 4), Authenticode digests in load order, hex.
    pub efi_applications: Vec<String>,
    /// Secure Boot state (PCR 7).
    pub secure_boot: SecureBoot,
    /// Kernel command lines GRUB measured (PCR 8), digest-authenticated.
    pub kernel_cmdlines: Vec<String>,
    /// Files GRUB loaded (PCR 9).
    pub boot_files: Vec<BootFile>,
}

impl EventLog {
    /// The number of events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the log has no events after the Spec ID header.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Replay the SHA-256 bank. `None` for a PCR some event of which lacked
    /// a SHA-256 digest.
    fn replay(&self) -> BTreeMap<u8, Option<[u8; 32]>> {
        let mut pcrs: BTreeMap<u8, Option<[u8; 32]>> = BTreeMap::new();
        for e in &self.events {
            if e.event_type == EV_NO_ACTION {
                continue;
            }
            let slot = pcrs.entry(e.pcr).or_insert_with(|| {
                let mut init = [0u8; 32];
                if e.pcr == 0 {
                    init[31] = self.startup_locality;
                }
                Some(init)
            });
            *slot = match (*slot, e.sha256) {
                (Some(cur), Some(d)) => {
                    let mut buf = [0u8; 64];
                    buf[..32].copy_from_slice(&cur);
                    buf[32..].copy_from_slice(&d);
                    Some(sha256(&buf))
                }
                _ => None,
            };
        }
        pcrs
    }

    /// Replay against the quoted SHA-256 PCR values. Every quoted PCR the log
    /// has events for must match exactly; facts are read only from those.
    pub fn verify_against(
        &self,
        quoted: &BTreeMap<u8, [u8; 32]>,
    ) -> Result<BootFacts, ReplayMismatch> {
        let replayed = self.replay();
        let mut verified = BTreeSet::new();
        for (pcr, value) in &replayed {
            if let Some(q) = quoted.get(pcr) {
                if *value != Some(*q) {
                    return Err(ReplayMismatch {
                        pcr: *pcr,
                        quoted: *q,
                        replayed: *value,
                    });
                }
                verified.insert(*pcr);
            }
        }
        Ok(self.facts(verified))
    }

    fn facts(&self, verified: BTreeSet<u8>) -> BootFacts {
        let ok = |e: &&Event| verified.contains(&e.pcr) && e.event_type != EV_NO_ACTION;
        let events: Vec<&Event> = self.events.iter().filter(ok).collect();
        let efi_applications = events
            .iter()
            .filter(|e| e.pcr == PCR_EFI_APPS && e.event_type == EV_EFI_BOOT_SERVICES_APPLICATION)
            .filter_map(|e| e.sha256.map(hex::encode))
            .collect();
        let kernel_cmdlines = events
            .iter()
            .filter(|e| e.pcr == PCR_GRUB_STRINGS && e.event_type == EV_IPL)
            .filter_map(|e| authenticated_cmdline(e))
            .collect();
        let boot_files = events
            .iter()
            .filter(|e| e.pcr == PCR_GRUB_FILES && e.event_type == EV_IPL)
            .filter_map(|e| {
                e.sha256.map(|d| BootFile {
                    sha256: hex::encode(d),
                    path_label: String::from_utf8_lossy(&e.data)
                        .trim_end_matches('\0')
                        .to_string(),
                })
            })
            .collect();
        let secure_boot = if verified.contains(&PCR_SECURE_BOOT) {
            secure_boot_state(&events)
        } else {
            SecureBoot::Unknown("PCR 7 was not quoted or has no events".into())
        };
        BootFacts {
            verified_pcrs: verified,
            efi_applications,
            secure_boot,
            kernel_cmdlines,
            boot_files,
        }
    }
}

/// GRUB measures `H(cmdline)` and describes it as `"kernel_cmdline: " +
/// cmdline`. Returned only when the digest recomputes from the description.
fn authenticated_cmdline(e: &Event) -> Option<String> {
    let rest = e.data.strip_prefix(KERNEL_CMDLINE_PREFIX)?;
    let end = rest
        .iter()
        .rposition(|&b| b != 0)
        .map_or(0, |i| i.saturating_add(1));
    let text = rest.get(..end)?;
    (e.sha256? == sha256(text)).then(|| String::from_utf8_lossy(text).into_owned())
}

/// Read the `SecureBoot` variable from PCR 7's `EV_EFI_VARIABLE_DRIVER_CONFIG`
/// events. The event digest must be `H(UEFI_VARIABLE_DATA)`.
fn secure_boot_state(events: &[&Event]) -> SecureBoot {
    let name: Vec<u8> = "SecureBoot"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    for e in events {
        if e.pcr != PCR_SECURE_BOOT || e.event_type != EV_EFI_VARIABLE_DRIVER_CONFIG {
            continue;
        }
        let mut r = Reader::new(&e.data, "UEFI_VARIABLE_DATA");
        let parsed = (|| {
            let _guid = r.bytes(16)?;
            let name_len = r.le_u64()?;
            let data_len = r.le_u64()?;
            let n = r.bytes(usize::try_from(name_len.saturating_mul(2)).unwrap_or(usize::MAX))?;
            let d = r.bytes(usize::try_from(data_len).unwrap_or(usize::MAX))?;
            Ok::<_, Malformed>((n.to_vec(), d.to_vec()))
        })();
        let Ok((n, d)) = parsed else { continue };
        if n != name {
            continue;
        }
        if e.sha256 != Some(sha256(&e.data)) {
            return SecureBoot::Unknown(
                "SecureBoot event digest does not recompute from its data".into(),
            );
        }
        return match d.as_slice() {
            [1] => SecureBoot::Enabled,
            [0] => SecureBoot::Disabled,
            other => SecureBoot::Unknown(format!("SecureBoot value {other:?}")),
        };
    }
    SecureBoot::Unknown("no SecureBoot variable event in PCR 7".into())
}

/// Builders for tests: a minimal crypto-agile log.
#[cfg(test)]
pub(crate) mod build {
    use super::*;

    pub(crate) struct LogBuilder {
        bytes: Vec<u8>,
        pcrs: BTreeMap<u8, [u8; 32]>,
    }

    impl LogBuilder {
        pub(crate) fn new() -> Self {
            let mut spec = Vec::new();
            spec.extend_from_slice(SPEC_ID_SIGNATURE);
            spec.extend_from_slice(&0u32.to_le_bytes());
            spec.extend_from_slice(&[0, 2, 0, 2]);
            spec.extend_from_slice(&1u32.to_le_bytes());
            spec.extend_from_slice(&HashAlg::TPM_SHA256.to_le_bytes());
            spec.extend_from_slice(&32u16.to_le_bytes());
            spec.push(0);
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&0u32.to_le_bytes());
            bytes.extend_from_slice(&EV_NO_ACTION.to_le_bytes());
            bytes.extend_from_slice(&[0u8; 20]);
            bytes.extend_from_slice(&u32::try_from(spec.len()).unwrap().to_le_bytes());
            bytes.extend_from_slice(&spec);
            Self {
                bytes,
                pcrs: BTreeMap::new(),
            }
        }

        pub(crate) fn event(mut self, pcr: u8, ty: u32, digest: [u8; 32], data: &[u8]) -> Self {
            self.bytes.extend_from_slice(&u32::from(pcr).to_le_bytes());
            self.bytes.extend_from_slice(&ty.to_le_bytes());
            self.bytes.extend_from_slice(&1u32.to_le_bytes());
            self.bytes
                .extend_from_slice(&HashAlg::TPM_SHA256.to_le_bytes());
            self.bytes.extend_from_slice(&digest);
            self.bytes
                .extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
            self.bytes.extend_from_slice(data);
            let cur = self.pcrs.entry(pcr).or_insert([0u8; 32]);
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(cur);
            buf[32..].copy_from_slice(&digest);
            *cur = sha256(&buf);
            self
        }

        pub(crate) fn efi_app(self, digest: [u8; 32]) -> Self {
            self.event(
                PCR_EFI_APPS,
                EV_EFI_BOOT_SERVICES_APPLICATION,
                digest,
                b"devpath",
            )
        }

        pub(crate) fn cmdline(self, text: &str) -> Self {
            let mut data = KERNEL_CMDLINE_PREFIX.to_vec();
            data.extend_from_slice(text.as_bytes());
            data.push(0);
            self.event(PCR_GRUB_STRINGS, EV_IPL, sha256(text.as_bytes()), &data)
        }

        pub(crate) fn boot_file(self, path: &str, contents: &[u8]) -> Self {
            let mut data = path.as_bytes().to_vec();
            data.push(0);
            self.event(PCR_GRUB_FILES, EV_IPL, sha256(contents), &data)
        }

        pub(crate) fn secure_boot(self, on: bool) -> Self {
            let mut data = vec![0u8; 16];
            data.extend_from_slice(&10u64.to_le_bytes());
            data.extend_from_slice(&1u64.to_le_bytes());
            data.extend("SecureBoot".encode_utf16().flat_map(|u| u.to_le_bytes()));
            data.push(u8::from(on));
            let d = sha256(&data);
            self.event(PCR_SECURE_BOOT, EV_EFI_VARIABLE_DRIVER_CONFIG, d, &data)
        }

        pub(crate) fn finish(self) -> (Vec<u8>, BTreeMap<u8, [u8; 32]>) {
            (self.bytes, self.pcrs)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::build::LogBuilder;
    use super::*;

    #[test]
    fn replay_reads_facts_from_verified_pcrs() {
        let (log, pcrs) = LogBuilder::new()
            .efi_app([4; 32])
            .secure_boot(true)
            .cmdline("root=/dev/vda ro ima_hash=sha256")
            .boot_file("/vmlinuz", b"kernel bytes")
            .finish();
        let parsed = parse_event_log(&log).unwrap();
        let facts = parsed.verify_against(&pcrs).unwrap();
        assert_eq!(facts.efi_applications, vec![hex::encode([4u8; 32])]);
        assert_eq!(facts.secure_boot, SecureBoot::Enabled);
        assert_eq!(
            facts.kernel_cmdlines,
            vec!["root=/dev/vda ro ima_hash=sha256"]
        );
        assert_eq!(
            facts.boot_files[0].sha256,
            hex::encode(sha256(b"kernel bytes"))
        );
        assert_eq!(facts.boot_files[0].path_label, "/vmlinuz");
    }

    #[test]
    fn a_flipped_pcr_does_not_replay() {
        let (log, mut pcrs) = LogBuilder::new().efi_app([4; 32]).finish();
        pcrs.get_mut(&4).unwrap()[0] ^= 1;
        let err = parse_event_log(&log)
            .unwrap()
            .verify_against(&pcrs)
            .unwrap_err();
        assert_eq!(err.pcr, 4);
    }

    #[test]
    fn unquoted_pcrs_yield_no_facts() {
        let (log, mut pcrs) = LogBuilder::new()
            .efi_app([4; 32])
            .cmdline("init=/bin/sh")
            .finish();
        pcrs.remove(&8);
        let facts = parse_event_log(&log)
            .unwrap()
            .verify_against(&pcrs)
            .unwrap();
        assert!(facts.kernel_cmdlines.is_empty(), "PCR 8 was not quoted");
        assert!(!facts.verified_pcrs.contains(&8));
    }

    #[test]
    fn a_cmdline_caption_that_is_not_what_was_measured_is_dropped() {
        let mut data = KERNEL_CMDLINE_PREFIX.to_vec();
        data.extend_from_slice(b"quiet");
        let (log, pcrs) = LogBuilder::new()
            .event(PCR_GRUB_STRINGS, EV_IPL, sha256(b"init=/bin/sh"), &data)
            .finish();
        let facts = parse_event_log(&log)
            .unwrap()
            .verify_against(&pcrs)
            .unwrap();
        assert!(facts.kernel_cmdlines.is_empty());
    }

    #[test]
    fn startup_locality_seeds_pcr0() {
        let mut loc = STARTUP_LOCALITY.to_vec();
        loc.push(3);
        let (log, _) = LogBuilder::new()
            .event(0, EV_NO_ACTION, [0; 32], &loc)
            .event(0, 1, [1; 32], b"")
            .finish();
        let parsed = parse_event_log(&log).unwrap();
        let mut init = [0u8; 64];
        init[31] = 3;
        init[32..].copy_from_slice(&[1; 32]);
        let expected: BTreeMap<u8, [u8; 32]> = [(0, sha256(&init))].into_iter().collect();
        parsed.verify_against(&expected).unwrap();
    }

    #[test]
    fn not_a_crypto_agile_log() {
        assert!(parse_event_log(&[0u8; 40]).is_err());
    }
}

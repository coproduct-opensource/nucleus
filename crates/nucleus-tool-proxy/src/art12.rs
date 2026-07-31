//! EU AI Act Article 12 decision records — a synchronous, hash-chained,
//! per-decision evidence log.
//!
//! Article 12 obliges automatic event logging over a system's lifetime, with
//! traceability that regulators read as **tamper-evident**, sufficient to
//! **reconstruct an individual AI-assisted decision** after the fact. This
//! module is the writer for that record.
//!
//! # Why a second log, and not the existing one
//!
//! The tool-proxy already has an HMAC-chained [`AuditLog`](crate::AuditLog), and
//! reusing it was the obvious first idea. It is the wrong home here:
//!
//! - Its `log()` is **async**, because it optionally fetches a drand round per
//!   entry. [`VerdictSink::record`] is **sync**, and a per-tool-call network
//!   round-trip on the decision path is unacceptable regardless.
//! - Node-side lifecycle events historically shared its file, which is why
//!   every local/container audit log failed verification until that was split
//!   out. A record an auditor must be able to verify should not share a file
//!   with unsigned lines by construction.
//!
//! So Article 12 records go to their own file, with their own chain — and that
//! chain's **genesis is bound to the existing one**: the first record's
//! `prev_hash` is the boot report's hash. There is still exactly one chain to
//! follow, and the boot report (which carries the sandbox-proof tier) is its
//! commitment.
//!
//! # Durability posture, stated plainly
//!
//! Each append is `write_all` + `flush` into the page cache, under a mutex,
//! holding one file handle for the process lifetime. There is **no `fsync`**:
//! it would add a journal commit per tool call, and the failure it guards
//! (host power loss) is both bounded and *detectable* — a lost tail shows up as
//! a `seq` gap and a `head_hash` that does not match. This is recorded in the
//! exported bundle's `limitations`, not papered over.
//!
//! # What tamper-evidence here does and does not mean
//!
//! The chain is HMAC'd with the audit secret. That detects modification by any
//! party who does not hold the secret. It does **not** protect against a holder
//! of the secret rewriting history — only a signature over the chain head by a
//! key the pod does not possess can do that, which is why the export attaches
//! one. Both properties are asserted by tests, including the one that
//! deliberately demonstrates the HMAC limit.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// Schema version for [`Art12Record`]. v1 is FROZEN: fields may be added with
/// `#[serde(default)]`, never removed or repurposed, and the canonical preimage
/// below must not change without a version bump.
pub const ART12_SCHEMA_VERSION: u32 = 1;

/// Domain separation tag for the record preimage, so an Article 12 record can
/// never be confused with another HMAC'd artifact signed by the same secret.
const PREIMAGE_DOMAIN: &str = "nucleus-art12-record-v1";

/// What went wrong writing a record.
#[derive(Debug)]
pub enum Art12Error {
    /// The record could not be serialized.
    Serialize(serde_json::Error),
    /// The record could not be written or flushed.
    Io(std::io::Error),
    /// The log's mutex was poisoned by a panic in another thread.
    Poisoned,
}

impl std::fmt::Display for Art12Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Art12Error::Serialize(e) => write!(f, "serialize art12 record: {e}"),
            Art12Error::Io(e) => write!(f, "write art12 record: {e}"),
            Art12Error::Poisoned => write!(f, "art12 log mutex poisoned"),
        }
    }
}

impl std::error::Error for Art12Error {}

/// The identity of whoever caused a decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    /// `authenticated` | `stdio_guest` | `unknown`.
    pub kind: String,
    /// SPIFFE ID when authenticated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<String>,
}

/// A refusal, in machine-queryable form.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DenyInfo {
    /// The `DenyReason` serde tag (e.g. `dlc_admission_denied`) — stable across
    /// releases, unlike a `Debug` rendering.
    pub code: String,
    /// Human-readable detail, for a reader rather than a query.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// One reconstructable decision.
///
/// Field set is deliberately sufficient to answer, without any other artifact:
/// *who* asked, *what* they asked for, *what was decided*, *which kind of
/// control decided it*, and *against which policy* — plus the chain fields that
/// make the answer tamper-evident.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Art12Record {
    /// Schema version; see [`ART12_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Monotonic sequence within this log, starting at 1.
    pub seq: u64,
    /// Seconds since the Unix epoch.
    pub timestamp_unix: u64,
    /// Session this decision belongs to.
    pub session_id: String,
    /// Which transport carried the request (`http` | `mcp`).
    pub transport: String,
    /// Who asked.
    pub actor: Actor,
    /// The operation's canonical name.
    pub operation: String,
    /// What it was requested against (path, command, URL, …).
    pub subject: String,
    /// `allow` | `requires_approval` | `deny` | `error`.
    pub verdict: String,
    /// Which KIND of control decided — the Article 12 hard/soft gate field.
    pub gate_class: String,
    /// Present iff `verdict == "deny"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny_reason: Option<DenyInfo>,
    /// Checksum of the permission lattice in force.
    pub policy_checksum: String,
    /// The named policy rule that decided, when one did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_rule: Option<String>,
    /// `admitted` | `not_admitted` | `unprovisioned` — whether verified
    /// admission was armed, and whether it passed. Distinguishes "the gate
    /// refused" from "the gate was never armed".
    pub dlc_admission: String,
    /// Whether emergency lockdown was active at decision time (Article 14).
    pub lockdown_active: bool,
    /// Kernel decision sequence, when this record reflects a kernel decision —
    /// joins the pre-effect and post-effect records for one operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_sequence: Option<u64>,
    /// Domain-specific metadata (e.g. a discharged-bundle witness).
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub extensions: std::collections::BTreeMap<String, String>,
    /// Hash of the previous record; for the first record, the boot report's hash.
    pub prev_hash: String,
    /// SHA-256 over the canonical preimage.
    pub hash: String,
    /// HMAC-SHA256 over the canonical preimage, under the audit secret.
    pub signature: String,
}

impl Art12Record {
    /// The canonical preimage: a `|`-joined, field-ordered rendering that both
    /// the writer and any verifier reconstruct **from the record's own fields**.
    ///
    /// Deliberately not `serde_json::to_string` — JSON key order and escaping
    /// are not guaranteed stable across serde versions, and a verifier that
    /// re-serializes to check a hash is checking its own serializer.
    #[must_use]
    pub fn canonical_preimage(&self) -> String {
        let deny = self
            .deny_reason
            .as_ref()
            .map(|d| format!("{}:{}", d.code, d.detail.as_deref().unwrap_or("")))
            .unwrap_or_default();
        let ext = self
            .extensions
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            PREIMAGE_DOMAIN,
            self.schema_version,
            self.seq,
            self.timestamp_unix,
            self.session_id,
            self.transport,
            self.actor.kind,
            self.actor.spiffe_id.as_deref().unwrap_or(""),
            self.operation,
            self.subject,
            self.verdict,
            self.gate_class,
            deny,
            self.policy_checksum,
            self.policy_rule.as_deref().unwrap_or(""),
            self.dlc_admission,
            self.lockdown_active,
            self.prev_hash,
        ) + &format!(
            "|{}|{}",
            self.decision_sequence
                .map(|s| s.to_string())
                .unwrap_or_default(),
            ext
        )
    }
}

/// The synchronous, chained writer.
pub struct Art12Log {
    inner: Mutex<Inner>,
    secret: Vec<u8>,
    /// Latched once a write fails. Consulted by `preflight` so the NEXT
    /// operation is denied before it executes — bounding evidence loss without
    /// failing calls whose effect already happened.
    degraded: AtomicBool,
    /// Records that could not be written. Published in the export so a gap is
    /// explicit rather than silent.
    dropped: AtomicU64,
    /// Mirror each append to stdout, for guests whose file the host cannot read.
    console_mirror: bool,
}

struct Inner {
    file: File,
    last_hash: String,
    seq: u64,
}

impl Art12Log {
    /// Open (or create) the log, chaining from `genesis_prev_hash` — the boot
    /// report's hash, so this chain is anchored to the existing audit chain.
    ///
    /// # Errors
    /// If the file cannot be opened for appending.
    pub fn open(
        path: &Path,
        secret: Vec<u8>,
        genesis_prev_hash: String,
        console_mirror: bool,
    ) -> Result<Self, Art12Error> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(Art12Error::Io)?;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(Art12Error::Io)?;
        Ok(Self {
            inner: Mutex::new(Inner {
                file,
                last_hash: genesis_prev_hash,
                seq: 0,
            }),
            secret,
            degraded: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
            console_mirror,
        })
    }

    /// Whether a write has failed since startup.
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Acquire)
    }

    /// How many records could not be written.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Acquire)
    }

    /// The current chain head, and how many records this process wrote.
    ///
    /// # Errors
    /// If the mutex is poisoned.
    pub fn head(&self) -> Result<(String, u64), Art12Error> {
        let inner = self.inner.lock().map_err(|_| Art12Error::Poisoned)?;
        Ok((inner.last_hash.clone(), inner.seq))
    }

    /// Append a decision. `draft` supplies everything except the chain fields,
    /// which are assigned here.
    ///
    /// # Errors
    /// [`Art12Error`] on serialize/IO failure; the log latches `degraded` and
    /// increments `dropped` before returning, so the caller may continue while
    /// the next `preflight` fails closed.
    pub fn append(&self, mut draft: Art12Record) -> Result<(), Art12Error> {
        let result = self.append_inner(&mut draft);
        if result.is_err() {
            self.degraded.store(true, Ordering::Release);
            self.dropped.fetch_add(1, Ordering::AcqRel);
        }
        result
    }

    fn append_inner(&self, draft: &mut Art12Record) -> Result<(), Art12Error> {
        let mut inner = self.inner.lock().map_err(|_| Art12Error::Poisoned)?;

        draft.schema_version = ART12_SCHEMA_VERSION;
        draft.seq = inner.seq + 1;
        draft.prev_hash = inner.last_hash.clone();

        let preimage = draft.canonical_preimage();
        draft.signature = crate::auth::sign_message(&self.secret, preimage.as_bytes());
        draft.hash = sha256_hex(&preimage);

        let line = serde_json::to_string(&draft).map_err(Art12Error::Serialize)?;
        inner
            .file
            .write_all(line.as_bytes())
            .and_then(|()| inner.file.write_all(b"\n"))
            .and_then(|()| inner.file.flush())
            .map_err(Art12Error::Io)?;

        // Console mirror: a compact checkpoint the HOST can read even when the
        // record file lives on a guest filesystem it cannot mount. Direct
        // `println!`, never `tracing` — tracing is `RUST_LOG`-gated and is
        // precisely why per-call evidence was invisible before this.
        if self.console_mirror {
            let mut out = std::io::stdout().lock();
            let _ = writeln!(
                out,
                "NUCLEUS-ART12 {}|{}|{}|{}|{}",
                draft.seq, draft.hash, draft.verdict, draft.gate_class, draft.operation
            );
            let _ = out.flush();
        }

        inner.last_hash = draft.hash.clone();
        inner.seq = draft.seq;
        Ok(())
    }
}

/// SHA-256 of a string, hex-encoded.
///
/// Lives here rather than in `main.rs` because this is where the hashing it
/// serves lives; the boot-report chain in `AuditLog` uses the same helper.
pub fn sha256_hex(message: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn draft(operation: &str, verdict: &str, gate_class: &str) -> Art12Record {
        Art12Record {
            schema_version: 0, // overwritten by append
            seq: 0,            // overwritten
            timestamp_unix: 1_700_000_000,
            session_id: "sess-1".to_string(),
            transport: "http".to_string(),
            actor: Actor {
                kind: "stdio_guest".to_string(),
                spiffe_id: None,
            },
            operation: operation.to_string(),
            subject: "/work/x".to_string(),
            verdict: verdict.to_string(),
            gate_class: gate_class.to_string(),
            deny_reason: None,
            policy_checksum: "abc123".to_string(),
            policy_rule: None,
            dlc_admission: "unprovisioned".to_string(),
            lockdown_active: false,
            decision_sequence: None,
            extensions: BTreeMap::new(),
            prev_hash: String::new(), // overwritten
            hash: String::new(),      // overwritten
            signature: String::new(), // overwritten
        }
    }

    fn read_records(path: &Path) -> Vec<Art12Record> {
        std::fs::read_to_string(path)
            .expect("read log")
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("record parses"))
            .collect()
    }

    #[test]
    fn append_writes_exactly_one_parseable_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("art12.jsonl");
        let log = Art12Log::open(&path, b"s".to_vec(), "genesis".to_string(), false).unwrap();
        log.append(draft("read_files", "allow", "none")).unwrap();

        let recs = read_records(&path);
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].seq, 1);
        assert_eq!(recs[0].schema_version, ART12_SCHEMA_VERSION);
        assert_eq!(recs[0].prev_hash, "genesis");
        assert!(!recs[0].hash.is_empty() && !recs[0].signature.is_empty());
    }

    #[test]
    fn two_appends_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("art12.jsonl");
        let log = Art12Log::open(&path, b"s".to_vec(), "genesis".to_string(), false).unwrap();
        log.append(draft("read_files", "allow", "none")).unwrap();
        log.append(draft("run_bash", "deny", "admission")).unwrap();

        let recs = read_records(&path);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[1].prev_hash, recs[0].hash, "record 2 must chain to 1");
        assert_eq!(recs[1].seq, 2);
    }

    /// The chain's first link is the EXISTING audit chain's head, so there is
    /// one chain to verify rather than two unrelated ones.
    #[test]
    fn genesis_prev_hash_is_the_supplied_boot_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("art12.jsonl");
        let log =
            Art12Log::open(&path, b"s".to_vec(), "boot-report-hash".to_string(), false).unwrap();
        log.append(draft("read_files", "allow", "none")).unwrap();
        assert_eq!(read_records(&path)[0].prev_hash, "boot-report-hash");
    }

    /// The hash must be recomputable from the record's own fields — this is
    /// exactly what a third-party verifier will do.
    #[test]
    fn hash_recomputes_from_the_record_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("art12.jsonl");
        let log = Art12Log::open(&path, b"secret".to_vec(), "g".to_string(), false).unwrap();
        log.append(draft("read_files", "allow", "none")).unwrap();

        let rec = &read_records(&path)[0];
        assert_eq!(sha256_hex(&rec.canonical_preimage()), rec.hash);
        assert_eq!(
            crate::auth::sign_message(b"secret", rec.canonical_preimage().as_bytes()),
            rec.signature
        );
    }

    /// ★ Tampering must be detectable: change one field and the stored hash no
    /// longer matches the recomputed preimage.
    #[test]
    fn tampering_breaks_the_recomputed_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("art12.jsonl");
        let log = Art12Log::open(&path, b"secret".to_vec(), "g".to_string(), false).unwrap();
        log.append(draft("run_bash", "deny", "admission")).unwrap();

        let mut rec = read_records(&path).remove(0);
        assert_eq!(sha256_hex(&rec.canonical_preimage()), rec.hash);
        rec.verdict = "allow".to_string(); // the edit an attacker wants
        assert_ne!(
            sha256_hex(&rec.canonical_preimage()),
            rec.hash,
            "flipping deny→allow must invalidate the hash"
        );
    }

    /// A write failure latches `degraded` and counts the loss, so the gap is
    /// explicit and the next `preflight` can fail closed.
    #[test]
    fn write_failure_latches_degraded_and_counts() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("art12.jsonl");
        let log = Art12Log::open(&path, b"s".to_vec(), "g".to_string(), false).unwrap();
        assert!(!log.is_degraded() && log.dropped() == 0);

        // Poison the mutex to force the failure path deterministically, without
        // depending on filesystem permissions (which differ under CI and root).
        let poisoner = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = log.inner.lock().unwrap();
            panic!("poison");
        }));
        assert!(poisoner.is_err());

        let err = log.append(draft("read_files", "allow", "none"));
        assert!(err.is_err(), "append must fail on a poisoned log");
        assert!(log.is_degraded(), "degraded must latch");
        assert_eq!(log.dropped(), 1, "the loss must be counted");
    }

    #[test]
    fn head_tracks_the_last_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("art12.jsonl");
        let log = Art12Log::open(&path, b"s".to_vec(), "g".to_string(), false).unwrap();
        assert_eq!(log.head().unwrap(), ("g".to_string(), 0));

        log.append(draft("read_files", "allow", "none")).unwrap();
        log.append(draft("run_bash", "deny", "admission")).unwrap();

        let (head, count) = log.head().unwrap();
        assert_eq!(count, 2);
        assert_eq!(head, read_records(&path)[1].hash);
    }

    /// Domain separation: an Article 12 preimage cannot collide with another
    /// artifact HMAC'd under the same secret.
    #[test]
    fn preimage_is_domain_separated() {
        let rec = draft("read_files", "allow", "none");
        assert!(rec.canonical_preimage().starts_with(PREIMAGE_DOMAIN));
    }
}

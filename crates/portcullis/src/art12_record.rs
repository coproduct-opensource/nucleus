//! The EU AI Act Article 12 decision-record TYPE and its canonical preimage.
//!
//! Lives in `portcullis` — not in the tool-proxy that writes records, nor in the
//! audit tool that verifies them — so that the writer and the verifier share
//! **one** definition. A duplicated canonical preimage is the failure mode this
//! placement exists to prevent: two copies that drift produce a verifier which
//! rejects authentic evidence (exactly the drand-suffix bug fixed alongside
//! this work) or, worse, accepts forged evidence.
//!
//! The writer (`nucleus_tool_proxy::art12::Art12Log`) owns file I/O and chain
//! state; everything about what a record *is* lives here.
//!
//! # Signed, not MAC'd (#3309)
//!
//! A record used to carry `HMAC(audit secret, preimage)`. A MAC shows who
//! wrote a record only if its key is kept from everyone else, and the
//! tool-proxy's secret-free transports (vsock, the peer-verified socket) have no
//! such key. A record is now signed with Ed25519 by the tool-proxy's audit
//! signer, the same in-memory key that signs its audit log (#3293), and names
//! that key (`signer`) inside the signed bytes and so inside the chain hash.
//! The two forms, and the rule that tells them apart, are the audit log's
//! ([`crate::signed_record`]); [`Art12Record::form`] applies it.
//!
//! A **legacy** record (no `sig_alg`, no `signer`) keeps its `|`-joined
//! [`Art12Record::canonical_preimage`] byte for byte, so a log written before
//! #3309 can still be checked against the secret it was keyed with.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::signed_record::{absorb, absorb_opt, signed_chain_hash, FormError, RecordForm, SigAlg};

/// Schema version for [`Art12Record`]. v1 is FROZEN: fields may be added with
/// `#[serde(default)]`, never removed or repurposed, and the canonical preimage
/// below must not change without a version bump.
pub const ART12_SCHEMA_VERSION: u32 = 1;

/// Domain separation tag for the LEGACY record preimage, so an Article 12
/// record can never be confused with another HMAC'd artifact signed by the same
/// secret.
pub const PREIMAGE_DOMAIN: &str = "nucleus-art12-record-v1";

/// The domain tag at the head of every SIGNED record's preimage. The audit
/// signer also signs the tool-proxy's audit log (`nucleus-tool-proxy-audit/2`),
/// so the tag is what keeps a signature over one kind of record from being a
/// valid signature over the other.
pub const SIGNED_DOMAIN: &str = "nucleus-art12-record/2";

/// Extension keys binding a record to the AUTHORITY it was decided under
/// (#2437): the pod certificate the tool-proxy verified at boot against the
/// node's pinned root key. The kernel that produced the verdict was built from
/// that certificate (`Kernel::from_certificate`), so these three keys let a
/// verifier holding the node's `authority.json` for the pod tie every decision
/// back to the chain — and the root public key — that authorized it, with no
/// side channel. They travel as extensions so the v1 preimage is unchanged:
/// extensions are already folded into the hash and signature.
///
/// A record written by a pod that holds a certificate carries all three; the
/// node refuses a shipped record whose fingerprint is not the one it issued.
pub const EXT_AUTHORITY_FINGERPRINT: &str = "authority.fingerprint";
/// Hops from the node's root to the pod (`LatticeCertificate` chain depth).
pub const EXT_AUTHORITY_CHAIN_DEPTH: &str = "authority.chain_depth";
/// The identity at the root of the pod's chain (its creator).
pub const EXT_AUTHORITY_ROOT: &str = "authority.root_identity";

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
    /// The chain hash: for a signed record, SHA-256 over the signed preimage
    /// and the signature ([`Art12Record::chain_hash`]); for a legacy one,
    /// SHA-256 over the canonical preimage.
    pub hash: String,
    /// Ed25519 by `signer` over [`Art12Record::signed_bytes`], hex-encoded. On
    /// a legacy record, HMAC-SHA256 over the canonical preimage.
    pub signature: String,
    /// Absent on a legacy record. See [`RecordForm`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_alg: Option<SigAlg>,
    /// The signer's Ed25519 public key, 64 hex characters. Absent on a legacy
    /// record. Inside the signed bytes, and so inside the chain hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

impl Art12Record {
    /// The certificate fingerprint this decision was made under, when the
    /// writing pod held one ([`EXT_AUTHORITY_FINGERPRINT`]).
    #[must_use]
    pub fn authority_fingerprint(&self) -> Option<&str> {
        self.extensions
            .get(EXT_AUTHORITY_FINGERPRINT)
            .map(String::as_str)
    }

    /// The LEGACY canonical preimage: a `|`-joined, field-ordered rendering
    /// that a verifier reconstructs **from the record's own fields**. Only a
    /// record in [`RecordForm::LegacyMac`] form is MAC'd and hashed over it;
    /// a signed record uses [`Art12Record::signed_bytes`]. Kept byte for byte,
    /// and it still lets a `|` in one field move a boundary, which is one reason
    /// the signed preimage is length-prefixed instead.
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

    /// Which form this record is in, by the rule the audit log uses.
    ///
    /// # Errors
    /// [`FormError`] when exactly one of `sig_alg` and `signer` is present.
    pub fn form(&self) -> Result<RecordForm<'_>, FormError> {
        crate::signed_record::form(self.sig_alg, self.signer.as_deref())
    }

    /// This draft, to be signed by `signer` (hex public key): it names the
    /// signer and the algorithm, and its `hash` and `signature` are cleared.
    /// [`Art12Record::with_signature`] seals it.
    #[must_use]
    pub fn to_be_signed_by(mut self, signer: String) -> Self {
        self.sig_alg = Some(SigAlg::Ed25519);
        self.signer = Some(signer);
        self.hash = String::new();
        self.signature = String::new();
        self
    }

    /// The bytes `signature` covers, for this record's form.
    ///
    /// # Errors
    /// [`FormError`] when the record is neither form.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, FormError> {
        match self.form()? {
            RecordForm::LegacyMac => Ok(self.canonical_preimage().into_bytes()),
            RecordForm::Signed { .. } => Ok(self.signed_preimage()),
        }
    }

    /// The chain hash this record must carry, given its `signature`. The next
    /// record names it as its `prev_hash`.
    ///
    /// # Errors
    /// [`FormError`] when the record is neither form.
    pub fn chain_hash(&self) -> Result<String, FormError> {
        match self.form()? {
            RecordForm::LegacyMac => Ok(hex::encode(Sha256::digest(
                self.canonical_preimage().as_bytes(),
            ))),
            RecordForm::Signed { .. } => {
                Ok(signed_chain_hash(self.signed_preimage(), &self.signature))
            }
        }
    }

    /// Set the signature and the chain hash it implies.
    ///
    /// # Errors
    /// [`FormError`] when the record is neither form.
    pub fn with_signature(mut self, signature: String) -> Result<Self, FormError> {
        self.signature = signature;
        self.hash = self.chain_hash()?;
        Ok(self)
    }

    /// The signed preimage. Every field is tag-separated and length-prefixed,
    /// so no two distinct records share a preimage by concatenation.
    ///
    /// EXHAUSTIVELY DESTRUCTURED (ADR 0007 E-1): a field added to the record,
    /// to its actor or to its refusal is a compile error here until someone
    /// decides whether it is signed.
    fn signed_preimage(&self) -> Vec<u8> {
        let Art12Record {
            schema_version,
            seq,
            timestamp_unix,
            session_id,
            transport,
            actor: Actor { kind, spiffe_id },
            operation,
            subject,
            verdict,
            gate_class,
            deny_reason,
            policy_checksum,
            policy_rule,
            dlc_admission,
            lockdown_active,
            decision_sequence,
            extensions,
            prev_hash,
            hash: _,
            signature: _,
            sig_alg: _,
            signer,
        } = self;
        let mut out = Vec::new();
        absorb(&mut out, "domain", SIGNED_DOMAIN.as_bytes());
        absorb_opt(&mut out, "signer", signer.as_deref().map(str::as_bytes));
        absorb(&mut out, "schema_version", &schema_version.to_be_bytes());
        absorb(&mut out, "seq", &seq.to_be_bytes());
        absorb(&mut out, "timestamp_unix", &timestamp_unix.to_be_bytes());
        absorb(&mut out, "session_id", session_id.as_bytes());
        absorb(&mut out, "transport", transport.as_bytes());
        absorb(&mut out, "actor.kind", kind.as_bytes());
        absorb_opt(
            &mut out,
            "actor.spiffe_id",
            spiffe_id.as_deref().map(str::as_bytes),
        );
        absorb(&mut out, "operation", operation.as_bytes());
        absorb(&mut out, "subject", subject.as_bytes());
        absorb(&mut out, "verdict", verdict.as_bytes());
        absorb(&mut out, "gate_class", gate_class.as_bytes());
        // The code is present exactly when the refusal is, so the pair
        // (code, detail) is unambiguous for all three shapes.
        let (code, detail) = match deny_reason {
            Some(DenyInfo { code, detail }) => (Some(code.as_bytes()), detail.as_deref()),
            None => (None, None),
        };
        absorb_opt(&mut out, "deny_reason.code", code);
        absorb_opt(&mut out, "deny_reason.detail", detail.map(str::as_bytes));
        absorb(&mut out, "policy_checksum", policy_checksum.as_bytes());
        absorb_opt(
            &mut out,
            "policy_rule",
            policy_rule.as_deref().map(str::as_bytes),
        );
        absorb(&mut out, "dlc_admission", dlc_admission.as_bytes());
        absorb(&mut out, "lockdown_active", &[u8::from(*lockdown_active)]);
        let decision = decision_sequence.map(u64::to_be_bytes);
        absorb_opt(
            &mut out,
            "decision_sequence",
            decision.as_ref().map(<[u8; 8]>::as_slice),
        );
        absorb(
            &mut out,
            "extensions.len",
            &u64::try_from(extensions.len())
                .unwrap_or(u64::MAX)
                .to_be_bytes(),
        );
        for (k, v) in extensions {
            absorb(&mut out, "extension.key", k.as_bytes());
            absorb(&mut out, "extension.value", v.as_bytes());
        }
        absorb(&mut out, "prev_hash", prev_hash.as_bytes());
        out
    }
}

/// A host-signed attestation binding an Article 12 log to the executor that ran it.
///
/// # Why it lives here, beside `Art12Record`
///
/// For the same reason the record does: the SIGNER (`nucleus-node`) and the
/// VERIFIER (`nucleus-audit`) must share one definition of the preimage. Two
/// independent renderings that happen to agree today are the shape that breaks
/// the first time either side gains a field, and it breaks by rejecting
/// authentic evidence.
///
/// # What it establishes
///
/// `verify-art12` can show no party LACKING the log's signing key altered it. It
/// cannot show that the HOLDER of the key did not rewrite history — and the key
/// is the tool-proxy's own, generated in the pod, so root in the pod can reach
/// it. This is signed with the node's executor key, which the pod never sees, so
/// a pod that rewrites its log produces a different chain head and cannot forge
/// a signature over the new one. Every signed record names its signer inside the
/// chain, so the attested head pins the signer too.
///
/// # What it does NOT establish
///
/// It binds the HEAD, not the content: a pod that recorded nothing exports a
/// validly signed empty log, so completeness stays unverifiable from the
/// artifact. And it binds a MOMENT — signing happens at pod exit, after the host
/// has stopped the pod, so the head is one the pod can no longer move.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Art12Attestation {
    /// Schema tag, so a verifier refuses rather than guessing at field drift.
    pub kind: String,
    /// The session whose log this attests to.
    pub session_id: String,
    /// The log's chain head as the pod reported it at shutdown.
    pub chain_head: String,
    /// Records the log wrote.
    pub records: u64,
    /// Records the log could not write. Non-zero means it went degraded.
    pub dropped: u64,
    /// Executor identity, so a verifier knows which public key to check.
    pub executor_id: String,
    /// The head the POD reported, when it differs from the head the host
    /// observed.
    ///
    /// `None` means they agreed. `Some(_)` is a finding that must not be
    /// averaged away: the pod's own log and the stream the host received
    /// diverged. The direction matters — see `pod_records`.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub pod_reported_head: Option<String>,
    /// How many records the pod said it wrote.
    ///
    /// `records` is what the HOST received. The pod ships each record only
    /// after sealing and writing it locally (#3392), so the host holds a prefix
    /// of the pod's log: `records > pod_records` is something no honest pod
    /// produces, and `pod_records > records` means records the pod made and the
    /// host never saw.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub pod_records: Option<u64>,
    /// Ed25519 signature over [`art12_attestation_preimage`], hex-encoded.
    pub signature: String,
}

/// The tag every attestation carries, and the domain separator in its preimage.
pub const ART12_ATTESTATION_KIND: &str = "nucleus-art12-attestation-v1";

/// The signed preimage, field-ordered and delimited.
///
/// Deliberately not `serde_json::to_string`, for the reason
/// [`Art12Record::canonical_preimage`] gives: JSON key order and escaping are not
/// guaranteed stable across serde versions, and a verifier that re-serialises to
/// check a signature is checking its own serialiser.
#[must_use]
pub fn art12_attestation_preimage(
    session_id: &str,
    chain_head: &str,
    records: u64,
    dropped: u64,
    executor_id: &str,
) -> String {
    format!("{ART12_ATTESTATION_KIND}|{session_id}|{chain_head}|{records}|{dropped}|{executor_id}")
}

impl Art12Attestation {
    /// This attestation's own preimage, reconstructed from its own fields.
    #[must_use]
    pub fn preimage(&self) -> String {
        art12_attestation_preimage(
            &self.session_id,
            &self.chain_head,
            self.records,
            self.dropped,
            &self.executor_id,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn rec() -> Art12Record {
        Art12Record {
            schema_version: ART12_SCHEMA_VERSION,
            seq: 1,
            timestamp_unix: 1_700_000_000,
            session_id: "s".into(),
            transport: "http".into(),
            actor: Actor {
                kind: "stdio_guest".into(),
                spiffe_id: None,
            },
            operation: "read_files".into(),
            subject: "/work/x".into(),
            verdict: "deny".into(),
            gate_class: "admission".into(),
            deny_reason: Some(DenyInfo {
                code: "dlc_admission_denied".into(),
                detail: Some("no credential".into()),
            }),
            policy_checksum: "abc".into(),
            policy_rule: None,
            dlc_admission: "not_admitted".into(),
            lockdown_active: false,
            decision_sequence: Some(7),
            extensions: BTreeMap::new(),
            prev_hash: "p".into(),
            hash: String::new(),
            signature: String::new(),
            sig_alg: None,
            signer: None,
        }
    }

    fn signed_form(r: Art12Record) -> Art12Record {
        r.to_be_signed_by("ab".repeat(32))
    }

    /// Domain separation: an Article 12 preimage cannot collide with another
    /// artifact HMAC'd under the same audit secret.
    #[test]
    fn preimage_is_domain_separated() {
        assert!(rec().canonical_preimage().starts_with(PREIMAGE_DOMAIN));
    }

    /// ★ Every field an auditor would rely on must CHANGE the preimage. A field
    /// that does not is a field an attacker can edit without breaking the hash —
    /// which is the whole tamper-evidence claim.
    #[test]
    fn every_load_bearing_field_changes_the_preimage() {
        let base = rec().canonical_preimage();
        /// One named mutation of a record field, for the coverage sweep below.
        type Mutation = (&'static str, Box<dyn Fn(&mut Art12Record)>);

        let mutate: Vec<Mutation> = vec![
            ("seq", Box::new(|r: &mut Art12Record| r.seq = 2)),
            (
                "timestamp",
                Box::new(|r: &mut Art12Record| r.timestamp_unix += 1),
            ),
            (
                "session_id",
                Box::new(|r: &mut Art12Record| r.session_id = "other".into()),
            ),
            (
                "transport",
                Box::new(|r: &mut Art12Record| r.transport = "mcp".into()),
            ),
            (
                "actor.kind",
                Box::new(|r: &mut Art12Record| r.actor.kind = "authenticated".into()),
            ),
            (
                "actor.spiffe",
                Box::new(|r: &mut Art12Record| r.actor.spiffe_id = Some("spiffe://x".into())),
            ),
            (
                "operation",
                Box::new(|r: &mut Art12Record| r.operation = "run_bash".into()),
            ),
            (
                "subject",
                Box::new(|r: &mut Art12Record| r.subject = "/etc/shadow".into()),
            ),
            (
                "verdict",
                Box::new(|r: &mut Art12Record| r.verdict = "allow".into()),
            ),
            (
                "gate_class",
                Box::new(|r: &mut Art12Record| r.gate_class = "none".into()),
            ),
            (
                "deny_reason",
                Box::new(|r: &mut Art12Record| r.deny_reason = None),
            ),
            (
                "policy_checksum",
                Box::new(|r: &mut Art12Record| r.policy_checksum = "zzz".into()),
            ),
            (
                "policy_rule",
                Box::new(|r: &mut Art12Record| r.policy_rule = Some("rule".into())),
            ),
            (
                "dlc_admission",
                Box::new(|r: &mut Art12Record| r.dlc_admission = "admitted".into()),
            ),
            (
                "lockdown",
                Box::new(|r: &mut Art12Record| r.lockdown_active = true),
            ),
            (
                "decision_seq",
                Box::new(|r: &mut Art12Record| r.decision_sequence = Some(8)),
            ),
            (
                "prev_hash",
                Box::new(|r: &mut Art12Record| r.prev_hash = "q".into()),
            ),
            (
                "extensions",
                Box::new(|r: &mut Art12Record| {
                    r.extensions.insert("k".into(), "v".into());
                }),
            ),
        ];
        let signed_base = signed_form(rec()).signed_bytes().unwrap();
        for (name, f) in mutate {
            let mut r = rec();
            f(&mut r);
            assert_ne!(
                r.canonical_preimage(),
                base,
                "changing `{name}` left the preimage identical — it is not covered by the hash"
            );
            assert_ne!(
                signed_form(r).signed_bytes().unwrap(),
                signed_base,
                "changing `{name}` left the SIGNED preimage identical — it is not signed"
            );
        }
        let mut r = rec();
        r.schema_version += 1;
        assert_ne!(signed_form(r).signed_bytes().unwrap(), signed_base);
    }

    /// The signer is inside the signed bytes and the chain hash, so a pin on
    /// the chain head pins every record's signer.
    #[test]
    fn the_signer_is_inside_the_signed_bytes_and_the_hash() {
        let a = rec().to_be_signed_by("ab".repeat(32));
        let b = rec().to_be_signed_by("cd".repeat(32));
        assert_ne!(a.signed_bytes(), b.signed_bytes());
        let a = a.with_signature("00".into()).unwrap();
        let b = b.with_signature("00".into()).unwrap();
        assert_ne!(a.hash, b.hash);
        // And the signature is inside the hash.
        let c = rec()
            .to_be_signed_by("ab".repeat(32))
            .with_signature("01".into())
            .unwrap();
        assert_ne!(a.hash, c.hash);
    }

    /// The legacy `|`-joined preimage lets a `|` move a field boundary; the
    /// signed one does not.
    #[test]
    fn a_pipe_in_a_field_cannot_move_a_boundary_in_the_signed_form() {
        let (mut a, mut b) = (rec(), rec());
        a.subject = "x|y".into();
        a.verdict = "deny".into();
        b.subject = "x".into();
        b.verdict = "y|deny".into();
        assert_eq!(a.canonical_preimage(), b.canonical_preimage());
        assert_ne!(
            signed_form(a).signed_bytes().unwrap(),
            signed_form(b).signed_bytes().unwrap()
        );
    }

    /// A legacy record keeps the bytes the pre-#3309 writer MAC'd and hashed.
    #[test]
    fn a_legacy_record_keeps_its_preimage_and_hash() {
        let r = rec();
        assert_eq!(r.form(), Ok(RecordForm::LegacyMac));
        assert_eq!(
            r.signed_bytes().unwrap(),
            r.canonical_preimage().into_bytes()
        );
        assert_eq!(
            r.chain_hash().unwrap(),
            hex::encode(Sha256::digest(r.canonical_preimage().as_bytes()))
        );
    }

    /// A record round-trips through JSON in both forms, and an unknown
    /// algorithm or field is refused rather than read as legacy.
    #[test]
    fn both_forms_round_trip_and_unknown_shapes_are_refused() {
        let signed = signed_form(rec()).with_signature("00".into()).unwrap();
        for r in [rec(), signed.clone()] {
            let back: Art12Record =
                serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
            assert_eq!(back, r);
        }
        let mut v = serde_json::to_value(&signed).unwrap();
        v["sig_alg"] = serde_json::json!("hmac-sha256");
        assert!(serde_json::from_value::<Art12Record>(v).is_err());
        let mut half = signed;
        half.sig_alg = None;
        assert_eq!(half.form(), Err(FormError::AlgMissing));
    }
}

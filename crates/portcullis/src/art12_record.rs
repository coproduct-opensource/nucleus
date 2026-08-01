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

use serde::{Deserialize, Serialize};

/// Schema version for [`Art12Record`]. v1 is FROZEN: fields may be added with
/// `#[serde(default)]`, never removed or repurposed, and the canonical preimage
/// below must not change without a version bump.
pub const ART12_SCHEMA_VERSION: u32 = 1;

/// Domain separation tag for the record preimage, so an Article 12 record can
/// never be confused with another HMAC'd artifact signed by the same secret.
pub const PREIMAGE_DOMAIN: &str = "nucleus-art12-record-v1";

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
/// `verify-art12` can show no party LACKING the log's HMAC secret altered it. It
/// cannot show that a HOLDER of the secret did not rewrite history — and a pod
/// that derives its own secret is such a holder. This is signed with the node's
/// executor key, which the pod never sees, so a pod that rewrites its log
/// produces a different chain head and cannot forge a signature over the new one.
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
        }
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
        for (name, f) in mutate {
            let mut r = rec();
            f(&mut r);
            assert_ne!(
                r.canonical_preimage(),
                base,
                "changing `{name}` left the preimage identical — it is not covered by the hash"
            );
        }
    }
}

//! The refusal wire: every `Refusal` keeps the bytes a guest reads. Moved out
//! of `workload_api_vsock.rs` to keep that file under its line ceiling.

use super::*;
use crate::workload_api_protocol::CommandParseError;

/// **The typed refusals kept the protocol's bytes.** Each expected string is
/// the literal a handler returned before `Refusal` existed; `nucleus-guest-init`
/// reads these, and `fetch_audit_credentials` there matches on one. A reworded
/// `Display` arm fails here, not in a booted guest.
///
/// The match makes the list total: a new `Refusal` variant does not compile
/// until its wire text is pinned below.
#[test]
fn the_wire_text_of_every_refusal_is_unchanged() {
    let cases: Vec<(Refusal, &str)> = vec![
        (
            Refusal::NotProvisioned(Material::BrokerSecret),
            r#"{"error":"no broker secret provisioned for this pod"}"#,
        ),
        (
            Refusal::NotProvisioned(Material::MediationKey),
            r#"{"error":"no mediation key provisioned for this pod"}"#,
        ),
        (
            Refusal::NotProvisioned(Material::AuditCredentials),
            r#"{"error":"no audit credentials provisioned for this pod"}"#,
        ),
        (
            Refusal::NotProvisioned(Material::PodSpec),
            r#"{"error":"no pod spec provisioned for this pod"}"#,
        ),
        (
            Refusal::NotProvisioned(Material::DlcAdmission),
            r#"{"error":"no dlc admission provisioned for this pod"}"#,
        ),
        (
            Refusal::NotProvisioned(Material::PodCertificate),
            r#"{"error":"no certificate was issued for this pod"}"#,
        ),
        (
            Refusal::NotProvisioned(Material::TaskToken),
            r#"{"error":"no task token was minted for this pod"}"#,
        ),
        (
            Refusal::NotProvisioned(Material::CallerToken),
            r#"{"error":"no caller token minted for this pod"}"#,
        ),
        (
            Refusal::AlreadyServed(OneShot::BrokerSecret),
            r#"{"error":"broker secret already served"}"#,
        ),
        (
            Refusal::AlreadyServed(OneShot::MediationKey),
            r#"{"error":"mediation key already served"}"#,
        ),
        (
            Refusal::AlreadyServed(OneShot::AuditCredentials),
            r#"{"error":"audit credentials already served"}"#,
        ),
        // #2724. guest-init reads the shared " already served" ending as
        // "something in this guest asked before init did", so the ending is
        // protocol too (`identity::reply_error` on the guest side).
        (
            Refusal::AlreadyServed(OneShot::SvidKey),
            r#"{"error":"svid key already served"}"#,
        ),
        (
            Refusal::AlreadyServed(OneShot::PodCertificate),
            r#"{"error":"pod certificate already served"}"#,
        ),
        (
            Refusal::AlreadyServed(OneShot::TaskToken),
            r#"{"error":"task token already served"}"#,
        ),
        (
            Refusal::AlreadyServed(OneShot::CallerToken),
            r#"{"error":"caller token already served"}"#,
        ),
        (
            Refusal::AlreadyServed(OneShot::DlcAdmission),
            r#"{"error":"dlc admission already served"}"#,
        ),
        (
            Refusal::ReceiptCollectionNotConfigured,
            r#"{"error":"receipt collection not configured for this pod"}"#,
        ),
        (
            Refusal::NoReceiptBody,
            r#"{"error":"no receipt body after SHIP_RECEIPT"}"#,
        ),
        (
            Refusal::ReceiptBodyUnreadable,
            r#"{"error":"receipt body too long or unreadable"}"#,
        ),
        (
            Refusal::ReceiptStorageFailed,
            r#"{"error":"receipt storage failed"}"#,
        ),
        (
            Refusal::PodListEncodingFailed,
            r#"{"error":"failed to encode pod list"}"#,
        ),
        (
            Refusal::SerializationFailed("x".into()),
            r#"{"error":"serialization failed: x"}"#,
        ),
        (
            Refusal::NoSpendBody,
            r#"{"error":"no receipt body after SHIP_SPEND"}"#,
        ),
        (
            Refusal::SpendBodyUnreadable,
            r#"{"error":"spend receipt body too long or unreadable"}"#,
        ),
        (
            Refusal::SpendRejected(crate::spend_receipt_collector::SpendRejection::Malformed),
            r#"{"error":"spend receipt body is not a SpendReceipt"}"#,
        ),
        (
            Refusal::NoClearingBody,
            r#"{"error":"no receipt body after SHIP_CLEARING"}"#,
        ),
        (
            Refusal::ClearingBodyUnreadable,
            r#"{"error":"clearing receipt body too long or unreadable"}"#,
        ),
        (
            Refusal::ClearingRejected(
                crate::clearing_receipt_collector::ClearingRejection::Malformed,
            ),
            r#"{"error":"clearing receipt body is not a ClearingReceipt"}"#,
        ),
        (Refusal::Identity("no CA".into()), r#"{"error":"no CA"}"#),
        (
            Refusal::Parse(CommandParseError::Unknown("NOPE".into())),
            r#"{"error":"unknown command: NOPE"}"#,
        ),
    ];
    for (refusal, want) in &cases {
        match refusal {
            Refusal::NotProvisioned(_)
            | Refusal::AlreadyServed(_)
            | Refusal::ReceiptCollectionNotConfigured
            | Refusal::NoReceiptBody
            | Refusal::ReceiptBodyUnreadable
            | Refusal::ReceiptStorageFailed
            | Refusal::NoSpendBody
            | Refusal::SpendBodyUnreadable
            | Refusal::SpendRejected(_)
            | Refusal::NoClearingBody
            | Refusal::ClearingBodyUnreadable
            | Refusal::ClearingRejected(_)
            | Refusal::PodListEncodingFailed
            | Refusal::SerializationFailed(_)
            | Refusal::Identity(_)
            | Refusal::Parse(_) => {}
        }
        assert_eq!(&wire(&Err(refusal.clone())), want);
    }
    // Every one-shot's refusal is pinned, counted from `OneShot::ALL` rather
    // than restated (F-3).
    for o in OneShot::ALL {
        assert!(
            cases.iter().any(|(r, _)| *r == Refusal::AlreadyServed(o)),
            "{o:?} has no pinned wire text"
        );
    }
    // 8 materials + every one-shot + 14 others: nothing silently skipped.
    assert_eq!(cases.len(), 8 + OneShot::ALL.len() + 14);
}

/// The ledger's slots are `OneShot::ALL`, one each: spending one never
/// spends another, and every one can be spent exactly once.
#[test]
fn every_one_shot_has_its_own_slot() {
    for (i, o) in OneShot::ALL.into_iter().enumerate() {
        assert_eq!(o.slot(), i, "{o:?} is out of slot order");
        let ledger = ServedLedger::new();
        assert!(ledger.claim(o).is_ok(), "{o:?} not servable once");
        for other in OneShot::ALL {
            assert_eq!(ledger.is_served(other), other == o, "{o:?} spent {other:?}");
        }
        assert_eq!(
            ledger.claim(o).err(),
            Some(Refusal::AlreadyServed(o)),
            "{o:?} served twice"
        );
    }
}

/// The defect the old identity-error path had: its message was spliced into
/// a JSON string unescaped, so a quote in it broke the reply's framing.
#[test]
fn an_identity_error_with_a_quote_is_still_one_json_object() {
    let bytes = wire(&Err(Refusal::Identity(r#"bad "trust" domain"#.into())));
    let v: serde_json::Value = serde_json::from_str(&bytes).expect("valid JSON");
    assert_eq!(v["error"], r#"bad "trust" domain"#);
}

//! Wire format for multi-agent IFC label propagation.
//!
//! When Agent A's output is consumed by Agent B, the IFC labels must
//! propagate across the agent boundary. This module defines the wire
//! format for encoding labels in HTTP headers, gRPC metadata, or
//! MCP extension fields.
//!
//! ## Wire protocol
//!
//! Labels are encoded as a compact header string:
//!
//! ```text
//! X-Nucleus-Label: c=2;i=0;a=0;p=5;t=1711843200;ttl=3600
//! ```
//!
//! Where:
//! - `c` = confidentiality (0=Public, 1=Internal, 2=Secret)
//! - `i` = integrity (0=Adversarial, 1=Untrusted, 2=Trusted)
//! - `a` = authority (0=NoAuthority, 1=Informational, 2=Suggestive, 3=Directive)
//! - `p` = provenance bitmask (6 bits: USER|TOOL|WEB|MEMORY|MODEL|SYSTEM)
//! - `t` = observed_at (unix timestamp)
//! - `ttl` = time-to-live seconds (0 = no expiry)
//!
//! The receiving agent's kernel must `observe()` with this label as the
//! intrinsic label of the incoming data, ensuring taint propagates.

use crate::{AuthorityLevel, ConfLevel, Freshness, IFCLabel, IntegLevel, ProvenanceSet};

/// HTTP header name for IFC label propagation.
pub const LABEL_HEADER: &str = "x-nucleus-label";

/// Encode an IFC label to the wire format.
pub fn encode_label(label: &IFCLabel) -> String {
    format!(
        "c={};i={};a={};p={};t={};ttl={}",
        label.confidentiality as u8,
        label.integrity as u8,
        label.authority as u8,
        label.provenance.bits(),
        label.freshness.observed_at,
        label.freshness.ttl_secs,
    )
}

/// Decode an IFC label from the wire format.
///
/// Returns `None` if the format is invalid. Fail-closed: unknown fields
/// are ignored, missing fields use the most restrictive defaults.
pub fn decode_label(s: &str) -> Option<IFCLabel> {
    let mut conf: u8 = 2; // Secret (most restrictive)
    let mut integ: u8 = 0; // Adversarial (most restrictive)
    let mut auth: u8 = 0; // NoAuthority (most restrictive)
    let mut prov: u8 = 0;
    let mut observed_at: u64 = 0;
    let mut ttl: u64 = 0;

    for part in s.split(';') {
        let part = part.trim();
        if let Some((key, val)) = part.split_once('=') {
            match key {
                "c" => conf = val.parse().ok()?,
                "i" => integ = val.parse().ok()?,
                "a" => auth = val.parse().ok()?,
                "p" => prov = val.parse().ok()?,
                "t" => observed_at = val.parse().ok()?,
                "ttl" => ttl = val.parse().ok()?,
                _ => {} // ignore unknown fields
            }
        }
    }

    let confidentiality = match conf {
        0 => ConfLevel::Public,
        1 => ConfLevel::Internal,
        _ => ConfLevel::Secret, // fail-closed: unknown = Secret
    };

    let integrity = match integ {
        0 => IntegLevel::Adversarial,
        1 => IntegLevel::Untrusted,
        2 => IntegLevel::Trusted,
        _ => IntegLevel::Adversarial, // fail-closed
    };

    let authority = match auth {
        0 => AuthorityLevel::NoAuthority,
        1 => AuthorityLevel::Informational,
        2 => AuthorityLevel::Suggestive,
        3 => AuthorityLevel::Directive,
        _ => AuthorityLevel::NoAuthority, // fail-closed
    };

    Some(IFCLabel {
        confidentiality,
        integrity,
        provenance: ProvenanceSet::from_bits(prov & 0x3F),
        freshness: Freshness {
            observed_at,
            ttl_secs: ttl,
        },
        authority,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_public_trusted() {
        let label = IFCLabel {
            confidentiality: ConfLevel::Public,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::USER,
            freshness: Freshness {
                observed_at: 1711843200,
                ttl_secs: 3600,
            },
            authority: AuthorityLevel::Directive,
        };
        let encoded = encode_label(&label);
        let decoded = decode_label(&encoded).unwrap();
        assert_eq!(decoded.confidentiality, label.confidentiality);
        assert_eq!(decoded.integrity, label.integrity);
        assert_eq!(decoded.authority, label.authority);
        assert_eq!(decoded.freshness.observed_at, label.freshness.observed_at);
        assert_eq!(decoded.freshness.ttl_secs, label.freshness.ttl_secs);
    }

    #[test]
    fn roundtrip_adversarial_web() {
        let label = IFCLabel::web_content(1000);
        let encoded = encode_label(&label);
        let decoded = decode_label(&encoded).unwrap();
        assert_eq!(decoded.integrity, IntegLevel::Adversarial);
        assert_eq!(decoded.authority, AuthorityLevel::NoAuthority);
    }

    #[test]
    fn roundtrip_secret() {
        let label = IFCLabel::secret(2000);
        let encoded = encode_label(&label);
        let decoded = decode_label(&encoded).unwrap();
        assert_eq!(decoded.confidentiality, ConfLevel::Secret);
        assert_eq!(decoded.authority, AuthorityLevel::NoAuthority);
    }

    #[test]
    fn decode_unknown_values_fail_closed() {
        // Unknown conf=99 → Secret (most restrictive)
        let decoded = decode_label("c=99;i=0;a=0;p=0;t=0;ttl=0").unwrap();
        assert_eq!(decoded.confidentiality, ConfLevel::Secret);
    }

    #[test]
    fn decode_partial_uses_restrictive_defaults() {
        // Only integrity specified — everything else defaults to most restrictive
        let decoded = decode_label("i=2").unwrap();
        assert_eq!(decoded.integrity, IntegLevel::Trusted);
        assert_eq!(decoded.confidentiality, ConfLevel::Secret); // default
        assert_eq!(decoded.authority, AuthorityLevel::NoAuthority); // default
    }

    #[test]
    fn decode_empty_returns_restrictive() {
        let decoded = decode_label("").unwrap();
        assert_eq!(decoded.confidentiality, ConfLevel::Secret);
        assert_eq!(decoded.integrity, IntegLevel::Adversarial);
        assert_eq!(decoded.authority, AuthorityLevel::NoAuthority);
    }

    #[test]
    fn decode_invalid_returns_none() {
        // Non-numeric value
        assert!(decode_label("c=abc").is_none());
    }

    #[test]
    fn header_name_is_lowercase() {
        assert_eq!(LABEL_HEADER, "x-nucleus-label");
    }

    #[test]
    fn provenance_roundtrip() {
        let label = IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Untrusted,
            provenance: ProvenanceSet::WEB.union(ProvenanceSet::TOOL),
            freshness: Freshness {
                observed_at: 5000,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Informational,
        };
        let encoded = encode_label(&label);
        let decoded = decode_label(&encoded).unwrap();
        assert!(decoded.provenance.contains(ProvenanceSet::WEB));
        assert!(decoded.provenance.contains(ProvenanceSet::TOOL));
        assert!(!decoded.provenance.contains(ProvenanceSet::USER));
    }
}

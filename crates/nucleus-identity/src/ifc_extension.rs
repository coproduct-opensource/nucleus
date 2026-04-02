//! IFC label encoding for X.509 v3 extensions.
//!
//! Encodes [`IFCLabel`] and [`DelegationScope`] into a compact binary format
//! suitable for embedding in a custom X.509 v3 extension as an opaque
//! OCTET STRING. This avoids pulling in full ASN.1/DER encoding machinery
//! while remaining unambiguous and version-tagged for forward compatibility.
//!
//! # Wire format (v1)
//!
//! ```text
//! "nucleus-ifc-v1\n"          (15 bytes, version tag)
//! confidentiality: u8         (ConfLevel discriminant)
//! integrity: u8               (IntegLevel discriminant)
//! provenance: u8              (ProvenanceSet bitmask, 6 bits)
//! freshness_observed_at: u64  (big-endian)
//! freshness_ttl_secs: u64     (big-endian)
//! authority: u8               (AuthorityLevel discriminant)
//! derivation: u8              (DerivationClass discriminant)
//! num_paths: u16              (big-endian)
//!   for each path:
//!     len: u16 (big-endian) + UTF-8 bytes
//! num_sinks: u16              (big-endian)
//!   for each sink:
//!     discriminant: u8
//! num_repos: u16              (big-endian)
//!   for each repo:
//!     len: u16 (big-endian) + UTF-8 bytes
//! ```

use portcullis_core::{
    delegation::DelegationScope, AuthorityLevel, ConfLevel, DerivationClass, Freshness, IFCLabel,
    IntegLevel, ProvenanceSet, SinkClass,
};
use x509_parser::prelude::*;

/// Placeholder private OID under the nucleus PEN arc.
///
/// OID: 1.3.6.1.4.1.57212.1.3  (attestation.ifc_label)
///
/// Uses the same unregistered PEN (57212) as the attestation and
/// permission-fingerprint OIDs defined in [`crate::oid`].
pub const NUCLEUS_IFC_OID: &str = "1.3.6.1.4.1.57212.1.3";

/// BER-encoded OID bytes for the IFC extension.
pub const OID_NUCLEUS_IFC_BYTES: &[u8] = &[
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xbe, 0x7c, // 1.3.6.1.4.1.57212
    0x01, 0x03, // .1.3 (attestation.ifc_label)
];

/// Tuple representation for consistency with [`crate::oid`].
pub const OID_NUCLEUS_IFC_TUPLE: &[u64] = &[1, 3, 6, 1, 4, 1, 57212, 1, 3];

/// Version tag prefixed to every encoded payload.
const VERSION_TAG: &[u8] = b"nucleus-ifc-v1\n";

/// Errors from encoding or decoding IFC extensions.
#[derive(Debug, thiserror::Error)]
pub enum ExtensionError {
    /// The version tag is missing or does not match.
    #[error("unsupported or missing version tag")]
    UnsupportedVersion,

    /// The payload is truncated or structurally invalid.
    #[error("truncated or malformed payload at offset {0}")]
    Truncated(usize),

    /// A discriminant byte does not map to a known enum variant.
    #[error("invalid discriminant {value} for {type_name}")]
    InvalidDiscriminant { type_name: &'static str, value: u8 },

    /// A length-prefixed string contains invalid UTF-8.
    #[error("invalid UTF-8 in {field}: {source}")]
    InvalidUtf8 {
        field: &'static str,
        source: std::string::FromUtf8Error,
    },
}

/// Encode an [`IFCLabel`] and [`DelegationScope`] into the v1 binary format.
pub fn encode_ifc_extension(label: &IFCLabel, scope: &DelegationScope) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);

    // Version tag
    buf.extend_from_slice(VERSION_TAG);

    // IFCLabel dimensions
    buf.push(label.confidentiality as u8);
    buf.push(label.integrity as u8);
    buf.push(label.provenance.bits());
    buf.extend_from_slice(&label.freshness.observed_at.to_be_bytes());
    buf.extend_from_slice(&label.freshness.ttl_secs.to_be_bytes());
    buf.push(label.authority as u8);
    buf.push(label.derivation as u8);

    // DelegationScope: allowed_paths
    write_string_list(&mut buf, &scope.allowed_paths);

    // DelegationScope: allowed_sinks (as discriminant bytes)
    let num_sinks = scope.allowed_sinks.len().min(u16::MAX as usize) as u16;
    buf.extend_from_slice(&num_sinks.to_be_bytes());
    for sink in &scope.allowed_sinks[..num_sinks as usize] {
        buf.push(*sink as u8);
    }

    // DelegationScope: allowed_repos
    write_string_list(&mut buf, &scope.allowed_repos);

    buf
}

/// Decode the v1 binary format back into an [`IFCLabel`] and [`DelegationScope`].
pub fn decode_ifc_extension(bytes: &[u8]) -> Result<(IFCLabel, DelegationScope), ExtensionError> {
    let mut cursor = 0usize;

    // Check version tag
    if bytes.len() < VERSION_TAG.len() || &bytes[..VERSION_TAG.len()] != VERSION_TAG {
        return Err(ExtensionError::UnsupportedVersion);
    }
    cursor += VERSION_TAG.len();

    // IFCLabel dimensions
    let confidentiality = read_u8(bytes, &mut cursor)?;
    let integrity = read_u8(bytes, &mut cursor)?;
    let provenance_bits = read_u8(bytes, &mut cursor)?;
    let observed_at = read_u64(bytes, &mut cursor)?;
    let ttl_secs = read_u64(bytes, &mut cursor)?;
    let authority = read_u8(bytes, &mut cursor)?;
    let derivation = read_u8(bytes, &mut cursor)?;

    let label = IFCLabel {
        confidentiality: conf_from_u8(confidentiality)?,
        integrity: integ_from_u8(integrity)?,
        provenance: ProvenanceSet::from_bits(provenance_bits),
        freshness: Freshness {
            observed_at,
            ttl_secs,
        },
        authority: authority_from_u8(authority)?,
        derivation: derivation_from_u8(derivation)?,
    };

    // DelegationScope: allowed_paths
    let allowed_paths = read_string_list(bytes, &mut cursor, "allowed_paths")?;

    // DelegationScope: allowed_sinks
    let num_sinks = read_u16(bytes, &mut cursor)?;
    let mut allowed_sinks = Vec::with_capacity(num_sinks as usize);
    for _ in 0..num_sinks {
        let disc = read_u8(bytes, &mut cursor)?;
        allowed_sinks.push(sink_from_u8(disc)?);
    }

    // DelegationScope: allowed_repos
    let allowed_repos = read_string_list(bytes, &mut cursor, "allowed_repos")?;

    let scope = DelegationScope {
        allowed_paths,
        allowed_sinks,
        allowed_repos,
    };

    Ok((label, scope))
}

/// Extract the IFC label and delegation scope from a DER-encoded peer certificate.
///
/// Parses the X.509 certificate, searches for the custom extension identified
/// by [`NUCLEUS_IFC_OID`], and decodes it using [`decode_ifc_extension`].
///
/// Returns `None` if the certificate does not contain the IFC extension.
/// Returns `Some(Err(_))` if the extension is present but malformed.
pub fn extract_peer_ifc(
    cert_der: &[u8],
) -> Option<Result<(IFCLabel, DelegationScope), ExtensionError>> {
    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;

    let target_oid = x509_parser::oid_registry::asn1_rs::oid!(1.3.6 .1 .4 .1 .57212 .1 .3);

    for ext in cert.extensions() {
        if ext.oid == target_oid {
            return Some(decode_ifc_extension(ext.value));
        }
    }

    None
}

/// Returns the default (most restrictive) IFC label and delegation scope for
/// a peer that does not present an IFC extension in its certificate.
///
/// This follows the principle of least privilege: unknown peers are treated as
/// opaque external entities with adversarial integrity and no delegation authority.
pub fn default_peer_label() -> (IFCLabel, DelegationScope) {
    let label = IFCLabel {
        confidentiality: ConfLevel::Public,
        integrity: IntegLevel::Adversarial,
        provenance: ProvenanceSet::EMPTY,
        freshness: Freshness {
            observed_at: 0,
            ttl_secs: 0,
        },
        authority: AuthorityLevel::NoAuthority,
        derivation: DerivationClass::OpaqueExternal,
    };
    let scope = DelegationScope::empty();
    (label, scope)
}

// ---------------------------------------------------------------------------
// Helpers: reading
// ---------------------------------------------------------------------------

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, ExtensionError> {
    if *cursor >= bytes.len() {
        return Err(ExtensionError::Truncated(*cursor));
    }
    let v = bytes[*cursor];
    *cursor += 1;
    Ok(v)
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, ExtensionError> {
    if *cursor + 2 > bytes.len() {
        return Err(ExtensionError::Truncated(*cursor));
    }
    let v = u16::from_be_bytes([bytes[*cursor], bytes[*cursor + 1]]);
    *cursor += 2;
    Ok(v)
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, ExtensionError> {
    if *cursor + 8 > bytes.len() {
        return Err(ExtensionError::Truncated(*cursor));
    }
    let v = u64::from_be_bytes(bytes[*cursor..*cursor + 8].try_into().unwrap());
    *cursor += 8;
    Ok(v)
}

fn read_string_list(
    bytes: &[u8],
    cursor: &mut usize,
    field: &'static str,
) -> Result<Vec<String>, ExtensionError> {
    let count = read_u16(bytes, cursor)?;
    let mut out = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let len = read_u16(bytes, cursor)? as usize;
        if *cursor + len > bytes.len() {
            return Err(ExtensionError::Truncated(*cursor));
        }
        let s = String::from_utf8(bytes[*cursor..*cursor + len].to_vec())
            .map_err(|e| ExtensionError::InvalidUtf8 { field, source: e })?;
        *cursor += len;
        out.push(s);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Helpers: writing
// ---------------------------------------------------------------------------

fn write_string_list(buf: &mut Vec<u8>, strings: &[String]) {
    let count = strings.len().min(u16::MAX as usize) as u16;
    buf.extend_from_slice(&count.to_be_bytes());
    for s in &strings[..count as usize] {
        let len = s.len().min(u16::MAX as usize) as u16;
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&s.as_bytes()[..len as usize]);
    }
}

// ---------------------------------------------------------------------------
// Helpers: discriminant → enum
// ---------------------------------------------------------------------------

fn conf_from_u8(v: u8) -> Result<ConfLevel, ExtensionError> {
    match v {
        0 => Ok(ConfLevel::Public),
        1 => Ok(ConfLevel::Internal),
        2 => Ok(ConfLevel::Secret),
        _ => Err(ExtensionError::InvalidDiscriminant {
            type_name: "ConfLevel",
            value: v,
        }),
    }
}

fn integ_from_u8(v: u8) -> Result<IntegLevel, ExtensionError> {
    match v {
        0 => Ok(IntegLevel::Adversarial),
        1 => Ok(IntegLevel::Untrusted),
        2 => Ok(IntegLevel::Trusted),
        _ => Err(ExtensionError::InvalidDiscriminant {
            type_name: "IntegLevel",
            value: v,
        }),
    }
}

fn authority_from_u8(v: u8) -> Result<AuthorityLevel, ExtensionError> {
    match v {
        0 => Ok(AuthorityLevel::NoAuthority),
        1 => Ok(AuthorityLevel::Informational),
        2 => Ok(AuthorityLevel::Suggestive),
        3 => Ok(AuthorityLevel::Directive),
        _ => Err(ExtensionError::InvalidDiscriminant {
            type_name: "AuthorityLevel",
            value: v,
        }),
    }
}

fn derivation_from_u8(v: u8) -> Result<DerivationClass, ExtensionError> {
    match v {
        0 => Ok(DerivationClass::Deterministic),
        1 => Ok(DerivationClass::AIDerived),
        2 => Ok(DerivationClass::Mixed),
        3 => Ok(DerivationClass::HumanPromoted),
        4 => Ok(DerivationClass::OpaqueExternal),
        _ => Err(ExtensionError::InvalidDiscriminant {
            type_name: "DerivationClass",
            value: v,
        }),
    }
}

fn sink_from_u8(v: u8) -> Result<SinkClass, ExtensionError> {
    match v {
        0 => Ok(SinkClass::WorkspaceWrite),
        1 => Ok(SinkClass::SystemWrite),
        2 => Ok(SinkClass::BashExec),
        3 => Ok(SinkClass::HTTPEgress),
        4 => Ok(SinkClass::GitCommit),
        5 => Ok(SinkClass::GitPush),
        6 => Ok(SinkClass::PRCommentWrite),
        7 => Ok(SinkClass::EmailSend),
        8 => Ok(SinkClass::MemoryPersist),
        9 => Ok(SinkClass::AgentSpawn),
        10 => Ok(SinkClass::MCPWrite),
        11 => Ok(SinkClass::SecretRead),
        12 => Ok(SinkClass::CloudMutation),
        13 => Ok(SinkClass::ProposedTableWrite),
        14 => Ok(SinkClass::VerifiedTableWrite),
        15 => Ok(SinkClass::SearchIndexWrite),
        16 => Ok(SinkClass::CacheWrite),
        17 => Ok(SinkClass::TicketWrite),
        18 => Ok(SinkClass::AuditLogAppend),
        _ => Err(ExtensionError::InvalidDiscriminant {
            type_name: "SinkClass",
            value: v,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_label() -> IFCLabel {
        IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            provenance: ProvenanceSet::USER.union(ProvenanceSet::MODEL),
            freshness: Freshness {
                observed_at: 1711900000,
                ttl_secs: 3600,
            },
            authority: AuthorityLevel::Suggestive,
            derivation: DerivationClass::AIDerived,
        }
    }

    fn sample_scope() -> DelegationScope {
        DelegationScope {
            allowed_paths: vec!["src/**".to_string(), "tests/**".to_string()],
            allowed_sinks: vec![SinkClass::WorkspaceWrite, SinkClass::GitCommit],
            allowed_repos: vec!["org/repo".to_string()],
        }
    }

    #[test]
    fn roundtrip_encode_decode() {
        let label = sample_label();
        let scope = sample_scope();

        let bytes = encode_ifc_extension(&label, &scope);
        let (decoded_label, decoded_scope) =
            decode_ifc_extension(&bytes).expect("decode should succeed");

        assert_eq!(decoded_label.confidentiality, label.confidentiality);
        assert_eq!(decoded_label.integrity, label.integrity);
        assert_eq!(decoded_label.provenance, label.provenance);
        assert_eq!(
            decoded_label.freshness.observed_at,
            label.freshness.observed_at
        );
        assert_eq!(decoded_label.freshness.ttl_secs, label.freshness.ttl_secs);
        assert_eq!(decoded_label.authority, label.authority);
        assert_eq!(decoded_label.derivation, label.derivation);

        assert_eq!(decoded_scope.allowed_paths, scope.allowed_paths);
        assert_eq!(decoded_scope.allowed_sinks, scope.allowed_sinks);
        assert_eq!(decoded_scope.allowed_repos, scope.allowed_repos);
    }

    #[test]
    fn roundtrip_empty_scope() {
        let label = IFCLabel::default();
        let scope = DelegationScope::empty();

        let bytes = encode_ifc_extension(&label, &scope);
        let (decoded_label, decoded_scope) =
            decode_ifc_extension(&bytes).expect("decode should succeed");

        assert_eq!(decoded_label.confidentiality, ConfLevel::Public);
        assert_eq!(decoded_label.integrity, IntegLevel::Untrusted);
        assert_eq!(decoded_label.provenance, ProvenanceSet::EMPTY);
        assert_eq!(decoded_label.authority, AuthorityLevel::NoAuthority);
        assert_eq!(decoded_label.derivation, DerivationClass::Deterministic);

        assert!(decoded_scope.allowed_paths.is_empty());
        assert!(decoded_scope.allowed_sinks.is_empty());
        assert!(decoded_scope.allowed_repos.is_empty());
    }

    #[test]
    fn roundtrip_unrestricted_scope() {
        let label = IFCLabel {
            confidentiality: ConfLevel::Secret,
            integrity: IntegLevel::Adversarial,
            provenance: ProvenanceSet::USER
                .union(ProvenanceSet::TOOL)
                .union(ProvenanceSet::WEB)
                .union(ProvenanceSet::MEMORY)
                .union(ProvenanceSet::MODEL)
                .union(ProvenanceSet::SYSTEM),
            freshness: Freshness {
                observed_at: u64::MAX,
                ttl_secs: u64::MAX,
            },
            authority: AuthorityLevel::Directive,
            derivation: DerivationClass::OpaqueExternal,
        };
        let scope = DelegationScope::unrestricted();

        let bytes = encode_ifc_extension(&label, &scope);
        let (decoded_label, decoded_scope) =
            decode_ifc_extension(&bytes).expect("decode should succeed");

        assert_eq!(decoded_label.confidentiality, ConfLevel::Secret);
        assert_eq!(decoded_label.integrity, IntegLevel::Adversarial);
        assert_eq!(decoded_label.authority, AuthorityLevel::Directive);
        assert_eq!(decoded_label.derivation, DerivationClass::OpaqueExternal);
        assert_eq!(decoded_scope.allowed_sinks.len(), SinkClass::ALL.len());
    }

    #[test]
    fn invalid_version_tag_rejected() {
        let err = decode_ifc_extension(b"wrong-version\nstuff").unwrap_err();
        assert!(matches!(err, ExtensionError::UnsupportedVersion));
    }

    #[test]
    fn empty_bytes_rejected() {
        let err = decode_ifc_extension(b"").unwrap_err();
        assert!(matches!(err, ExtensionError::UnsupportedVersion));
    }

    #[test]
    fn truncated_payload_rejected() {
        // Valid version tag but truncated before all IFCLabel fields
        let mut bytes = VERSION_TAG.to_vec();
        bytes.push(0); // confidentiality only
        let err = decode_ifc_extension(&bytes).unwrap_err();
        assert!(matches!(err, ExtensionError::Truncated(_)));
    }

    #[test]
    fn invalid_discriminant_rejected() {
        let label = IFCLabel::default();
        let scope = DelegationScope::empty();
        let mut bytes = encode_ifc_extension(&label, &scope);

        // Corrupt the confidentiality byte (first byte after version tag)
        bytes[VERSION_TAG.len()] = 255;
        let err = decode_ifc_extension(&bytes).unwrap_err();
        assert!(matches!(
            err,
            ExtensionError::InvalidDiscriminant {
                type_name: "ConfLevel",
                value: 255
            }
        ));
    }

    #[test]
    fn different_labels_produce_different_bytes() {
        let scope = DelegationScope::empty();

        let label_a = IFCLabel {
            confidentiality: ConfLevel::Public,
            ..IFCLabel::default()
        };
        let label_b = IFCLabel {
            confidentiality: ConfLevel::Secret,
            ..IFCLabel::default()
        };

        let bytes_a = encode_ifc_extension(&label_a, &scope);
        let bytes_b = encode_ifc_extension(&label_b, &scope);
        assert_ne!(bytes_a, bytes_b);

        // Different scopes too
        let scope_c = DelegationScope {
            allowed_paths: vec!["foo".to_string()],
            allowed_sinks: vec![],
            allowed_repos: vec![],
        };
        let bytes_c = encode_ifc_extension(&label_a, &scope_c);
        assert_ne!(bytes_a, bytes_c);
    }

    #[test]
    fn oid_consistency() {
        // OID tuple matches the string representation
        assert_eq!(
            NUCLEUS_IFC_OID,
            OID_NUCLEUS_IFC_TUPLE
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(".")
        );

        // Same PEN prefix as attestation OID
        assert_eq!(
            &OID_NUCLEUS_IFC_BYTES[..8],
            &crate::oid::OID_NUCLEUS_ATTESTATION_BYTES[..8],
            "IFC OID must share the same PEN arc as attestation"
        );

        // Component .1.3 (distinct from .1.1 attestation and .1.2 fingerprint)
        assert_eq!(OID_NUCLEUS_IFC_BYTES[8], 0x01);
        assert_eq!(OID_NUCLEUS_IFC_BYTES[9], 0x03);
    }

    #[test]
    fn version_tag_is_prefix() {
        let label = IFCLabel::default();
        let scope = DelegationScope::empty();
        let bytes = encode_ifc_extension(&label, &scope);
        assert!(bytes.starts_with(VERSION_TAG));
    }

    // -----------------------------------------------------------------------
    // extract_peer_ifc / default_peer_label tests
    // -----------------------------------------------------------------------

    /// Helper: create a self-signed cert with an optional IFC custom extension.
    fn make_test_cert(ifc_payload: Option<Vec<u8>>) -> Vec<u8> {
        use rcgen::{CertificateParams, CustomExtension, KeyPair};

        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec!["test.local".to_string()]).unwrap();

        if let Some(payload) = ifc_payload {
            let mut ext = CustomExtension::from_oid_content(OID_NUCLEUS_IFC_TUPLE, payload);
            ext.set_criticality(false);
            params.custom_extensions = vec![ext];
        }

        let cert = params.self_signed(&key_pair).unwrap();
        cert.der().to_vec()
    }

    #[test]
    fn extract_peer_ifc_with_extension() {
        let label = sample_label();
        let scope = sample_scope();
        let payload = encode_ifc_extension(&label, &scope);
        let cert_der = make_test_cert(Some(payload));

        let result = extract_peer_ifc(&cert_der);
        assert!(result.is_some(), "should find IFC extension");

        let (decoded_label, decoded_scope) = result.unwrap().expect("decode should succeed");
        assert_eq!(decoded_label.confidentiality, label.confidentiality);
        assert_eq!(decoded_label.integrity, label.integrity);
        assert_eq!(decoded_label.provenance, label.provenance);
        assert_eq!(decoded_label.authority, label.authority);
        assert_eq!(decoded_label.derivation, label.derivation);
        assert_eq!(decoded_scope.allowed_paths, scope.allowed_paths);
        assert_eq!(decoded_scope.allowed_sinks, scope.allowed_sinks);
        assert_eq!(decoded_scope.allowed_repos, scope.allowed_repos);
    }

    #[test]
    fn extract_peer_ifc_missing_extension() {
        let cert_der = make_test_cert(None);
        let result = extract_peer_ifc(&cert_der);
        assert!(result.is_none(), "should return None when no IFC extension");
    }

    #[test]
    fn extract_peer_ifc_malformed_extension() {
        let cert_der = make_test_cert(Some(b"not-valid-ifc-payload".to_vec()));
        let result = extract_peer_ifc(&cert_der);
        assert!(result.is_some(), "should find the extension");
        assert!(
            result.unwrap().is_err(),
            "should fail to decode malformed payload"
        );
    }

    #[test]
    fn extract_peer_ifc_invalid_der() {
        let result = extract_peer_ifc(b"not a certificate");
        assert!(result.is_none(), "invalid DER should return None");
    }

    #[test]
    fn default_peer_label_is_restrictive() {
        let (label, scope) = default_peer_label();

        // Most restrictive IFC dimensions
        assert_eq!(label.confidentiality, ConfLevel::Public);
        assert_eq!(label.integrity, IntegLevel::Adversarial);
        assert_eq!(label.provenance, ProvenanceSet::EMPTY);
        assert_eq!(label.authority, AuthorityLevel::NoAuthority);
        assert_eq!(label.derivation, DerivationClass::OpaqueExternal);
        assert_eq!(label.freshness.observed_at, 0);
        assert_eq!(label.freshness.ttl_secs, 0);

        // Empty delegation scope
        assert!(scope.allowed_paths.is_empty());
        assert!(scope.allowed_sinks.is_empty());
        assert!(scope.allowed_repos.is_empty());
    }
}

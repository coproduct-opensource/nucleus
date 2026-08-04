//! W3C PROV-JSON export from flow graph (#957).
//!
//! Serializes the flow graph into the [W3C PROV-JSON](https://www.w3.org/submissions/prov-json/)
//! format for regulatory compliance and interoperability with provenance tooling.
//!
//! Mapping:
//! - `NodeKind` source observations → PROV `Entity`
//! - `NodeKind` action/model nodes → PROV `Activity`
//! - User/agent nodes → PROV `Agent`
//! - IFC labels → PROV attributes (derivation, authority, integrity)
//!
//! **Relations (`wasDerivedFrom`, `used`) are NOT emitted.** They would assert
//! that data actually flowed between two nodes, and nothing in the session
//! state this function receives records that. See `export_prov_json`.

use crate::flow::NodeKind;
use crate::{AuthorityLevel, DerivationClass, IntegLevel};
use std::collections::BTreeMap;

/// Convert a u8 discriminant to NodeKind (matching the hook adapter's encoding).
fn u8_to_node_kind(v: u8) -> NodeKind {
    match v {
        0 => NodeKind::UserPrompt,
        1 => NodeKind::ToolResponse,
        2 => NodeKind::WebContent,
        3 => NodeKind::MemoryRead,
        4 => NodeKind::MemoryWrite,
        5 => NodeKind::FileRead,
        6 => NodeKind::EnvVar,
        7 => NodeKind::ModelPlan,
        8 => NodeKind::Secret,
        9 => NodeKind::OutboundAction,
        10 => NodeKind::Summarization,
        11 => NodeKind::Retry,
        12 => NodeKind::HTTPResponse,
        13 => NodeKind::DatabaseRow,
        14 => NodeKind::GitBlob,
        15 => NodeKind::CachedDatum,
        16 => NodeKind::DeterministicBind,
        17 => NodeKind::ImageContent,
        18 => NodeKind::AudioContent,
        _ => NodeKind::PDFContent,
    }
}

/// A W3C PROV-JSON document.
///
/// Structure follows the [PROV-JSON specification](https://www.w3.org/submissions/prov-json/):
/// top-level keys are `entity`, `activity`, `agent`, `wasDerivedFrom`, `used`, etc.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProvDocument {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub entity: BTreeMap<String, ProvEntity>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub activity: BTreeMap<String, ProvActivity>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub agent: BTreeMap<String, ProvAgent>,
    #[serde(rename = "wasDerivedFrom", skip_serializing_if = "BTreeMap::is_empty")]
    pub was_derived_from: BTreeMap<String, ProvDerivation>,
    #[serde(rename = "used", skip_serializing_if = "BTreeMap::is_empty")]
    pub used: BTreeMap<String, ProvUsage>,
    #[serde(rename = "wasGeneratedBy", skip_serializing_if = "BTreeMap::is_empty")]
    pub was_generated_by: BTreeMap<String, ProvGeneration>,
    /// PROV-JSON prefix declarations.
    pub prefix: BTreeMap<String, String>,
}

/// A PROV Entity — a data item in the provenance graph.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProvEntity {
    #[serde(rename = "prov:type")]
    pub prov_type: String,
    #[serde(rename = "nucleus:derivation")]
    pub derivation: String,
    #[serde(rename = "nucleus:authority")]
    pub authority: String,
    #[serde(rename = "nucleus:integrity")]
    pub integrity: String,
    #[serde(rename = "nucleus:nodeKind")]
    pub node_kind: String,
}

/// A PROV Activity — an action or computation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProvActivity {
    #[serde(rename = "prov:type")]
    pub prov_type: String,
    #[serde(rename = "nucleus:nodeKind")]
    pub node_kind: String,
}

/// A PROV Agent — an actor (user, model, system).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProvAgent {
    #[serde(rename = "prov:type")]
    pub prov_type: String,
}

/// A PROV wasDerivedFrom relation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProvDerivation {
    #[serde(rename = "prov:generatedEntity")]
    pub generated_entity: String,
    #[serde(rename = "prov:usedEntity")]
    pub used_entity: String,
}

/// A PROV used relation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProvUsage {
    #[serde(rename = "prov:activity")]
    pub activity: String,
    #[serde(rename = "prov:entity")]
    pub entity: String,
}

/// A PROV wasGeneratedBy relation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProvGeneration {
    #[serde(rename = "prov:entity")]
    pub entity: String,
    #[serde(rename = "prov:activity")]
    pub activity: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// NodeKind classification for PROV mapping
// ═══════════════════════════════════════════════════════════════════════════

/// Classify a NodeKind into its PROV type.
fn prov_category(kind: NodeKind) -> ProvCategory {
    match kind {
        // Entities: data that exists
        NodeKind::FileRead
        | NodeKind::WebContent
        | NodeKind::McpToolResult
        | NodeKind::MemoryRead
        | NodeKind::EnvVar
        | NodeKind::Secret
        | NodeKind::HTTPResponse
        | NodeKind::DatabaseRow
        | NodeKind::GitBlob
        | NodeKind::CachedDatum
        | NodeKind::DeterministicBind
        | NodeKind::ImageContent
        | NodeKind::AudioContent
        | NodeKind::PDFContent => ProvCategory::Entity,
        // Activities: computations/actions
        NodeKind::OutboundAction
        | NodeKind::MemoryWrite
        | NodeKind::ModelPlan
        | NodeKind::ToolResponse
        | NodeKind::Summarization
        | NodeKind::Retry => ProvCategory::Activity,
        // Agents: principals
        NodeKind::UserPrompt => ProvCategory::Agent,
        // Custom kinds default to Entity (data that exists)
        NodeKind::Custom(_) => ProvCategory::Entity,
    }
}

enum ProvCategory {
    Entity,
    Activity,
    Agent,
}

fn derivation_str(d: DerivationClass) -> &'static str {
    match d {
        DerivationClass::Deterministic => "Deterministic",
        DerivationClass::AIDerived => "AIDerived",
        DerivationClass::Mixed => "Mixed",
        DerivationClass::HumanPromoted => "HumanPromoted",
        DerivationClass::OpaqueExternal => "OpaqueExternal",
    }
}

fn authority_str(a: AuthorityLevel) -> &'static str {
    match a {
        AuthorityLevel::NoAuthority => "NoAuthority",
        AuthorityLevel::Informational => "Informational",
        AuthorityLevel::Suggestive => "Suggestive",
        AuthorityLevel::Directive => "Directive",
    }
}

fn integrity_str(i: IntegLevel) -> &'static str {
    match i {
        IntegLevel::Adversarial => "Adversarial",
        IntegLevel::Untrusted => "Untrusted",
        IntegLevel::Trusted => "Trusted",
    }
}

fn node_kind_str(kind: NodeKind) -> &'static str {
    match kind {
        NodeKind::UserPrompt => "UserPrompt",
        NodeKind::ToolResponse => "ToolResponse",
        NodeKind::WebContent => "WebContent",
        NodeKind::McpToolResult => "McpToolResult",
        NodeKind::MemoryRead => "MemoryRead",
        NodeKind::MemoryWrite => "MemoryWrite",
        NodeKind::FileRead => "FileRead",
        NodeKind::EnvVar => "EnvVar",
        NodeKind::ModelPlan => "ModelPlan",
        NodeKind::Secret => "Secret",
        NodeKind::OutboundAction => "OutboundAction",
        NodeKind::Summarization => "Summarization",
        NodeKind::Retry => "Retry",
        NodeKind::HTTPResponse => "HTTPResponse",
        NodeKind::DatabaseRow => "DatabaseRow",
        NodeKind::GitBlob => "GitBlob",
        NodeKind::CachedDatum => "CachedDatum",
        NodeKind::DeterministicBind => "DeterministicBind",
        NodeKind::ImageContent => "ImageContent",
        NodeKind::AudioContent => "AudioContent",
        NodeKind::PDFContent => "PDFContent",
        NodeKind::Custom(name) => name,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Export function
// ═══════════════════════════════════════════════════════════════════════════

/// Export flow observations as a W3C PROV-JSON document.
///
/// Takes the raw flow observations `(node_kind_u8, label_str, subject)` from
/// session state and produces a standards-compliant PROV-JSON document of
/// **nodes only** — `entity`, `activity`, `agent`, each a direct rendering of
/// something actually observed, carrying its IFC label as attributes.
///
/// # No derivation relations are emitted, deliberately
///
/// This function used to emit `wasDerivedFrom` by linking each entity to the
/// *previous* one, and `used` by pointing each activity at the *preceding*
/// entity — both inferred from observation ORDER, commented as a "linear
/// approximation". They are removed.
///
/// PROV's `wasDerivedFrom` and `used` are assertions that data actually flowed.
/// Deriving them from sequence adjacency asserts flows that were never
/// computed: two unrelated reads become a derivation chain purely because one
/// happened after the other. In a document whose stated purpose is regulatory
/// evidence, a fabricated relation is worse than a missing one — a missing
/// relation is visibly absent, a fabricated one is indistinguishable from a
/// real finding.
///
/// The relation types are retained because the schema is right; only the data
/// is unavailable. Populating them needs genuine parent edges in the flow
/// graph. Note this signature cannot carry them: `(u8, String, String)` has no
/// field for a parent set, so restoring real relations is an input-type change
/// here, not a change to the body.
///
/// Until then, a consumer sees the nodes and their labels, and sees plainly
/// that no derivation was asserted.
pub fn export_prov_json(observations: &[(u8, String, String)], session_id: &str) -> ProvDocument {
    let mut doc = ProvDocument {
        entity: BTreeMap::new(),
        activity: BTreeMap::new(),
        agent: BTreeMap::new(),
        was_derived_from: BTreeMap::new(),
        used: BTreeMap::new(),
        was_generated_by: BTreeMap::new(),
        prefix: BTreeMap::new(),
    };

    // Standard PROV prefixes.
    doc.prefix
        .insert("prov".into(), "http://www.w3.org/ns/prov#".into());
    doc.prefix
        .insert("nucleus".into(), "https://nucleus.dev/ns/prov#".into());

    for (i, (kind_u8, label, _subject)) in observations.iter().enumerate() {
        let kind = u8_to_node_kind(*kind_u8);
        let node_id = format!("nucleus:{session_id}/obs/{i}");

        // Get the intrinsic label for IFC attributes.
        let ifc = crate::flow::intrinsic_label(kind, 0);

        match prov_category(kind) {
            ProvCategory::Entity => {
                doc.entity.insert(
                    node_id.clone(),
                    ProvEntity {
                        prov_type: format!("nucleus:{}", node_kind_str(kind)),
                        derivation: derivation_str(ifc.derivation).into(),
                        authority: authority_str(ifc.authority).into(),
                        integrity: integrity_str(ifc.integrity).into(),
                        node_kind: node_kind_str(kind).into(),
                    },
                );
            }
            ProvCategory::Activity => {
                doc.activity.insert(
                    node_id.clone(),
                    ProvActivity {
                        prov_type: format!("nucleus:{label}"),
                        node_kind: node_kind_str(kind).into(),
                    },
                );
            }
            ProvCategory::Agent => {
                doc.agent.insert(
                    node_id,
                    ProvAgent {
                        prov_type: "prov:Person".into(),
                    },
                );
            }
        }
    }

    doc
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_observations_produce_empty_doc() {
        let doc = export_prov_json(&[], "test-session");
        assert!(doc.entity.is_empty());
        assert!(doc.activity.is_empty());
        assert!(doc.agent.is_empty());
    }

    #[test]
    fn web_content_becomes_entity() {
        let obs = vec![(2u8, "WebFetch".into(), "https://example.com".into())];
        let doc = export_prov_json(&obs, "s1");
        assert_eq!(doc.entity.len(), 1);
        let entity = doc.entity.values().next().unwrap();
        assert_eq!(entity.integrity, "Adversarial");
        assert_eq!(entity.node_kind, "WebContent");
    }

    #[test]
    fn user_prompt_becomes_agent() {
        let obs = vec![(0u8, "user".into(), "hello".into())];
        let doc = export_prov_json(&obs, "s1");
        assert_eq!(doc.agent.len(), 1);
    }

    #[test]
    fn outbound_action_becomes_activity() {
        let obs = vec![(9u8, "WriteFiles".into(), "test.rs".into())];
        let doc = export_prov_json(&obs, "s1");
        assert_eq!(doc.activity.len(), 1);
    }

    #[test]
    fn adjacent_entities_are_not_asserted_to_derive_from_each_other() {
        // A local file read followed by an unrelated web fetch. Nothing flowed
        // between them; they are merely adjacent in time. The exporter used to
        // emit a `wasDerivedFrom` here, which claims the web content was
        // derived from the file.
        let obs = vec![
            (5u8, "Read".into(), "a.rs".into()),
            (2u8, "WebFetch".into(), "url".into()),
        ];
        let doc = export_prov_json(&obs, "s1");
        assert_eq!(doc.entity.len(), 2, "both observations are still exported");
        assert!(
            doc.was_derived_from.is_empty(),
            "sequence adjacency is not derivation: {:?}",
            doc.was_derived_from
        );
    }

    #[test]
    fn an_activity_is_not_asserted_to_have_used_the_preceding_entity() {
        // Reading `a.rs` then writing `b.rs` does not mean the write consumed
        // the read. PROV `used` is a claim about data flow, not about order.
        let obs = vec![
            (5u8, "Read".into(), "a.rs".into()),
            (9u8, "Write".into(), "b.rs".into()),
        ];
        let doc = export_prov_json(&obs, "s1");
        assert_eq!(doc.entity.len(), 1);
        assert_eq!(doc.activity.len(), 1);
        assert!(doc.used.is_empty(), "ordering is not usage: {:?}", doc.used);
    }

    /// The serialized document must not carry relation keys at all — a consumer
    /// reading the JSON should see plainly that no derivation was asserted,
    /// rather than an empty object that looks like a graph with no findings.
    #[test]
    fn serialized_document_omits_relation_keys_entirely() {
        let obs = vec![
            (5u8, "Read".into(), "a.rs".into()),
            (2u8, "WebFetch".into(), "url".into()),
            (9u8, "Write".into(), "b.rs".into()),
        ];
        let json = serde_json::to_string(&export_prov_json(&obs, "s1")).unwrap();
        assert!(json.contains("entity"), "nodes are still exported: {json}");
        for key in ["wasDerivedFrom", "used", "wasGeneratedBy"] {
            assert!(!json.contains(key), "{key} must be absent, got: {json}");
        }
    }

    #[test]
    fn deterministic_bind_is_entity() {
        let obs = vec![(16u8, "bind:jq:WebFetch".into(), String::new())];
        let doc = export_prov_json(&obs, "s1");
        assert_eq!(doc.entity.len(), 1);
        let entity = doc.entity.values().next().unwrap();
        assert_eq!(entity.node_kind, "DeterministicBind");
        assert_eq!(entity.derivation, "Deterministic");
    }

    #[cfg(feature = "artifact")]
    #[test]
    fn prov_json_serializes() {
        let obs = vec![
            (0u8, "user".into(), "prompt".into()),
            (5u8, "Read".into(), "file.rs".into()),
            (9u8, "Write".into(), "out.rs".into()),
        ];
        let doc = export_prov_json(&obs, "s1");
        let json = serde_json::to_string_pretty(&doc).unwrap();
        assert!(json.contains("wasDerivedFrom") || json.contains("entity"));
        assert!(json.contains("prov:type"));
    }

    #[test]
    fn prefixes_are_standard() {
        let doc = export_prov_json(&[], "s1");
        assert_eq!(
            doc.prefix.get("prov").unwrap(),
            "http://www.w3.org/ns/prov#"
        );
        assert!(doc.prefix.contains_key("nucleus"));
    }
}

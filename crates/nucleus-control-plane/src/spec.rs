//! [`JobSpec`] — the typed contract a customer submits to the control plane.
//!
//! Designed to be vendor-agnostic: no LLM provider names, no API key
//! formats. Agent-driver-specific configuration is stuffed into
//! `AgentDriverRef.config` as opaque JSON, interpreted only by the
//! concrete [`crate::runner::JobRunner`] for that driver.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// What the customer wants the agent to do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSpec {
    /// Where the input data lives.
    pub input_ref: InputRef,
    /// Free-form natural-language task description (e.g. "extract key
    /// stats and produce a one-paragraph summary"). The driver passes
    /// this to the LLM verbatim.
    pub task: String,
    /// Where to deliver the resulting [`crate::executor::ExecutedJob`].
    pub destination: Destination,
    /// Policy profile name — interpreted by `portcullis`. Vendor-neutral
    /// (e.g. "codegen", "review", "report-extraction").
    pub policy_profile: String,
    /// Which agent driver to run. Indirected to keep nucleus
    /// vendor-neutral; the actual LLM-vendor adapters live
    /// outside this crate.
    pub agent_driver: AgentDriverRef,
}

/// Source of the input the agent should process.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InputRef {
    /// JSON content embedded directly in the spec.
    Inline { content: serde_json::Value },
    /// HTTP(S) URL the agent will fetch.
    Url { url: String },
    /// Local filesystem path readable by the agent process.
    LocalPath { path: PathBuf },
}

/// Where the assembled provenance bundle is shipped.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Destination {
    /// Return the bundle in the API response (no remote shipping). The
    /// default for synchronous library use.
    InResponse,
    /// Write the bundle JSON to a local file path.
    LocalPath { path: PathBuf },
    /// HTTP POST the bundle JSON to a URL. The destination is
    /// responsible for authenticating the request (e.g. by pre-signed
    /// URL or by including credentials in `headers`).
    HttpPost {
        url: String,
        #[serde(default)]
        headers: std::collections::BTreeMap<String, String>,
    },
}

/// Reference to an agent-driver implementation. Concrete drivers live
/// in their own crates and register themselves with the executor; this
/// type carries enough information to dispatch but does not embed any
/// vendor SDKs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDriverRef {
    /// Driver identifier (e.g. "mock", "agent-cli", "openhands"). The
    /// orchestrator looks this up against a registry of available
    /// [`crate::runner::JobRunner`] implementations.
    pub name: String,
    /// Optional driver version pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Driver-specific configuration (LLM endpoint, model selection,
    /// credential reference, …). Opaque to the orchestrator core.
    #[serde(default)]
    pub config: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_spec_round_trips_through_json() {
        let spec = JobSpec {
            input_ref: InputRef::Inline {
                content: serde_json::json!({"text": "hello"}),
            },
            task: "summarize".to_string(),
            destination: Destination::InResponse,
            policy_profile: "report-extraction".to_string(),
            agent_driver: AgentDriverRef {
                name: "mock".to_string(),
                version: None,
                config: serde_json::json!({}),
            },
        };
        let json = serde_json::to_string(&spec).unwrap();
        let back: JobSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back.task, "summarize");
        matches!(back.input_ref, InputRef::Inline { .. });
    }

    #[test]
    fn destination_variants_round_trip() {
        let url_dest = Destination::HttpPost {
            url: "https://customer.example.com/ingest".to_string(),
            headers: std::collections::BTreeMap::from([(
                "Authorization".to_string(),
                "Bearer x".to_string(),
            )]),
        };
        let json = serde_json::to_string(&url_dest).unwrap();
        let back: Destination = serde_json::from_str(&json).unwrap();
        if let Destination::HttpPost { url, headers } = back {
            assert_eq!(url, "https://customer.example.com/ingest");
            assert_eq!(
                headers.get("Authorization").map(String::as_str),
                Some("Bearer x")
            );
        } else {
            panic!("destination variant changed");
        }
    }
}

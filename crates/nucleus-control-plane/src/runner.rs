//! [`JobRunner`] — the trait every concrete agent-driver implements.
//!
//! A runner takes a [`JobSpec`] plus a [`SessionWriter`] (for emitting
//! lineage edges) and returns the agent's payload JSON. Anything the
//! agent does that should appear in the provenance envelope MUST be
//! emitted as a [`LineageEdge`] through the writer.
//!
//! Concrete drivers (CLI-agent adapters, openhands, …) live OUTSIDE this
//! crate to keep nucleus vendor-neutral. The mock driver lives here because
//! it's part of the orchestrator's test surface, not a vendor adapter.

use nucleus_lineage::{CallSpiffeId, EdgeKind, LineageEdge};
use thiserror::Error;

use crate::session_writer::{SessionWriter, SessionWriterError};
use crate::spec::{InputRef, JobSpec};

/// Errors a [`JobRunner`] may surface.
#[derive(Debug, Error)]
pub enum JobRunnerError {
    /// The agent driver failed for a driver-specific reason.
    #[error("driver error: {0}")]
    Driver(String),
    /// Emitting a lineage edge failed.
    #[error("session writer: {0}")]
    Writer(#[from] SessionWriterError),
    /// The driver was given a spec it doesn't support.
    #[error("unsupported job spec: {0}")]
    Unsupported(String),
}

/// What every agent driver must implement.
///
/// `run` is called by [`crate::executor::execute_job`] *after* the
/// session pod-admit edge has been emitted, so `session_root` is the
/// already-admitted pod identity. The runner emits its own subsequent
/// edges via `writer`. On return, the orchestrator builds a bundle from
/// every edge in the sink under `session_root`.
pub trait JobRunner: Send + Sync {
    /// Execute the agent's work for `spec`. Returns the structured
    /// payload JSON to package into the bundle alongside the envelope.
    fn run(
        &self,
        spec: &JobSpec,
        session_root: &CallSpiffeId,
        writer: &SessionWriter<'_>,
    ) -> Result<serde_json::Value, JobRunnerError>;
}

/// Deterministic runner used by tests and as an executable reference
/// for what the trait expects. Implements a fixed three-step pipeline:
///
/// 1. ToolCall("Read") — emits a tool-call edge with the input's hash.
/// 2. LlmCall("mock", prompt + response) — emits two LLM edges.
/// 3. ArtifactProduced — emits a final artifact edge whose content
///    hash is the SHA-256 of the produced payload bytes.
///
/// The payload is `{ "task": spec.task, "summary": "..." }`. Not a real
/// summarization — the value of this runner is that the *shape* of the
/// resulting envelope matches what real drivers produce.
pub struct MockJobRunner;

impl JobRunner for MockJobRunner {
    fn run(
        &self,
        spec: &JobSpec,
        session_root: &CallSpiffeId,
        writer: &SessionWriter<'_>,
    ) -> Result<serde_json::Value, JobRunnerError> {
        // 1. Read step.
        let input_bytes = match &spec.input_ref {
            InputRef::Inline { content } => serde_json::to_vec(content)
                .map_err(|e| JobRunnerError::Driver(format!("serialize inline input: {e}")))?,
            InputRef::LocalPath { path } => std::fs::read(path)
                .map_err(|e| JobRunnerError::Driver(format!("reading {}: {e}", path.display())))?,
            InputRef::Url { .. } => {
                return Err(JobRunnerError::Unsupported(
                    "MockJobRunner does not fetch URLs; use Inline or LocalPath".into(),
                ));
            }
        };

        let read_id = session_root
            .derive_tool("Read", Some(&input_bytes))
            .map_err(|e| JobRunnerError::Driver(format!("derive_tool Read: {e}")))?;
        writer.emit_signed(
            LineageEdge::from_parent(
                read_id.clone(),
                session_root.clone(),
                EdgeKind::ToolCall {
                    tool: "Read".to_string(),
                },
            )
            .with_attr("driver", "mock")
            .with_attr("input_bytes", input_bytes.len().to_string()),
        )?;

        // 2. LLM call (prompt + response).
        let prompt_bytes = spec.task.as_bytes();
        let prompt_id = read_id
            .derive_llm("mock", "prompt", prompt_bytes)
            .map_err(|e| JobRunnerError::Driver(format!("derive_llm prompt: {e}")))?;
        writer.emit_signed(LineageEdge::from_parent(
            prompt_id.clone(),
            read_id,
            EdgeKind::LlmCall {
                provider: "mock".to_string(),
                direction: "prompt".to_string(),
            },
        ))?;

        let response_text = format!(
            "[mock] processed {} input bytes for task {:?}",
            input_bytes.len(),
            spec.task
        );
        let response_bytes = response_text.as_bytes();
        let response_id = prompt_id
            .derive_llm("mock", "response", response_bytes)
            .map_err(|e| JobRunnerError::Driver(format!("derive_llm response: {e}")))?;
        writer.emit_signed(LineageEdge::from_parent(
            response_id.clone(),
            prompt_id,
            EdgeKind::LlmCall {
                provider: "mock".to_string(),
                direction: "response".to_string(),
            },
        ))?;

        // 3. Final artifact derived from the response.
        let payload = serde_json::json!({
            "task": spec.task,
            "summary": response_text,
            "stats": {
                "input_bytes": input_bytes.len(),
                "response_bytes": response_bytes.len(),
            }
        });
        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| JobRunnerError::Driver(format!("serialize payload: {e}")))?;
        let artifact_id = response_id
            .derive_artifact(&payload_bytes)
            .map_err(|e| JobRunnerError::Driver(format!("derive_artifact: {e}")))?;
        writer.emit_signed(
            LineageEdge::from_parent(artifact_id, response_id, EdgeKind::ArtifactProduced)
                .with_attr("payload_bytes", payload_bytes.len().to_string()),
        )?;

        Ok(payload)
    }
}

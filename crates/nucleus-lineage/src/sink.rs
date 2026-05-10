//! Sinks for [`LineageEdge`] persistence.
//!
//! Two impls ship in this crate: an [`InMemorySink`] for tests and process-
//! local lookup, and a [`JsonlSink`] that appends to a file (one JSON object
//! per line, no rewrites). Larger deployments will plug in a remote sink
//! (S3, Tigris, etc.) — the trait is the integration point.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};

use thiserror::Error;

use crate::edge::LineageEdge;
use crate::id::CallSpiffeId;

/// Errors a sink may surface.
#[derive(Debug, Error)]
pub enum SinkError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("sink lock poisoned")]
    Poisoned,
}

/// Append-only lineage record store.
///
/// Implementations must be safe to call concurrently from multiple
/// threads: `emit` is `&self`, not `&mut self`.
pub trait LineageSink: Send + Sync {
    /// Append a single edge.
    fn emit(&self, edge: LineageEdge) -> Result<(), SinkError>;

    /// Iterate every edge ever emitted, oldest first. Used by the
    /// `nucleus lineage` walk; not expected to be hot-path.
    fn iter(&self) -> Result<Vec<LineageEdge>, SinkError>;

    /// Iterate all edges whose `child` matches `id`. Default impl walks
    /// `iter()`; sinks that index by child can override.
    fn edges_for_child(&self, id: &CallSpiffeId) -> Result<Vec<LineageEdge>, SinkError> {
        Ok(self
            .iter()?
            .into_iter()
            .filter(|e| &e.child == id)
            .collect())
    }
}

// ────────────────────────────────────────────────────────────────────────
// InMemorySink

/// Process-local sink. Edges are kept in insertion order in an `RwLock`.
#[derive(Default, Debug)]
pub struct InMemorySink {
    edges: RwLock<Vec<LineageEdge>>,
}

impl InMemorySink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> Result<usize, SinkError> {
        Ok(self.edges.read().map_err(|_| SinkError::Poisoned)?.len())
    }

    pub fn is_empty(&self) -> Result<bool, SinkError> {
        Ok(self.len()? == 0)
    }
}

impl LineageSink for InMemorySink {
    fn emit(&self, edge: LineageEdge) -> Result<(), SinkError> {
        self.edges
            .write()
            .map_err(|_| SinkError::Poisoned)?
            .push(edge);
        Ok(())
    }

    fn iter(&self) -> Result<Vec<LineageEdge>, SinkError> {
        Ok(self.edges.read().map_err(|_| SinkError::Poisoned)?.clone())
    }
}

// ────────────────────────────────────────────────────────────────────────
// JsonlSink

/// Append-only sink writing one JSON object per line to a file.
///
/// Open with `JsonlSink::open(path)`; the file is created if missing.
/// Writes are serialized by an internal mutex; reads (`iter`) re-open the
/// file fresh so they always see the latest contents.
pub struct JsonlSink {
    path: PathBuf,
    writer: Mutex<BufWriter<File>>,
}

impl JsonlSink {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, SinkError> {
        let path = path.into();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            writer: Mutex::new(BufWriter::new(file)),
        })
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl LineageSink for JsonlSink {
    fn emit(&self, edge: LineageEdge) -> Result<(), SinkError> {
        let line = serde_json::to_string(&edge)?;
        let mut w = self.writer.lock().map_err(|_| SinkError::Poisoned)?;
        w.write_all(line.as_bytes())?;
        w.write_all(b"\n")?;
        w.flush()?;
        Ok(())
    }

    fn iter(&self) -> Result<Vec<LineageEdge>, SinkError> {
        // Re-open so we see writes from this process even after our writer's
        // buffer has been flushed.
        let f = File::open(&self.path)?;
        let reader = BufReader::new(f);
        let mut out = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            out.push(serde_json::from_str(&line)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::EdgeKind;
    use std::sync::Arc;

    fn pod() -> CallSpiffeId {
        CallSpiffeId::pod("prod.example.com", "agents", "coder").unwrap()
    }

    #[test]
    fn in_memory_sink_round_trips() {
        let sink = InMemorySink::new();
        let p = pod();
        sink.emit(LineageEdge::pod_admit(p.clone())).unwrap();
        let child = p.derive_tool("Bash", Some(b"x")).unwrap();
        sink.emit(LineageEdge::from_parent(
            child.clone(),
            p.clone(),
            EdgeKind::ToolCall {
                tool: "Bash".to_string(),
            },
        ))
        .unwrap();
        let all = sink.iter().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(sink.edges_for_child(&child).unwrap().len(), 1);
        assert_eq!(sink.edges_for_child(&p).unwrap().len(), 1);
    }

    #[test]
    fn in_memory_sink_concurrent_emit() {
        let sink = Arc::new(InMemorySink::new());
        let p = pod();
        let mut handles = Vec::new();
        for i in 0..32 {
            let s = sink.clone();
            let parent = p.clone();
            handles.push(std::thread::spawn(move || {
                let child = parent
                    .derive_artifact(format!("payload {i}").as_bytes())
                    .unwrap();
                s.emit(LineageEdge::from_parent(
                    child,
                    parent,
                    EdgeKind::ArtifactProduced,
                ))
                .unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(sink.len().unwrap(), 32);
    }

    #[test]
    fn jsonl_sink_appends_and_reads_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lineage.jsonl");
        let sink = JsonlSink::open(&path).unwrap();
        let p = pod();
        sink.emit(LineageEdge::pod_admit(p.clone())).unwrap();
        let derived = p.derive_artifact(b"hi").unwrap();
        sink.emit(LineageEdge::from_parent(
            derived.clone(),
            p,
            EdgeKind::ArtifactProduced,
        ))
        .unwrap();

        let read_back = sink.iter().unwrap();
        assert_eq!(read_back.len(), 2);
        assert_eq!(read_back[1].child, derived);
    }

    #[test]
    fn jsonl_sink_re_open_sees_prior_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lineage.jsonl");
        let p = pod();
        {
            let s = JsonlSink::open(&path).unwrap();
            s.emit(LineageEdge::pod_admit(p.clone())).unwrap();
        }
        let s2 = JsonlSink::open(&path).unwrap();
        let edges = s2.iter().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].child, p);
    }

    #[test]
    fn jsonl_sink_skips_blank_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lineage.jsonl");
        let sink = JsonlSink::open(&path).unwrap();
        sink.emit(LineageEdge::pod_admit(pod())).unwrap();
        // Append a blank line directly.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"\n\n")
            .unwrap();
        sink.emit(LineageEdge::pod_admit(pod())).unwrap();
        assert_eq!(sink.iter().unwrap().len(), 2);
    }
}

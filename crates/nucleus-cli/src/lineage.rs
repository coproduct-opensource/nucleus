//! `nucleus lineage` — walk the lineage DAG for a given SPIFFE ID.
//!
//! Reads an append-only JSONL log produced by [`nucleus_lineage::JsonlSink`]
//! and renders the parent-chain (or full subtree) of a target call ID in
//! one of three formats: indented text (default), JSON, or Graphviz DOT.

use anyhow::{anyhow, Context, Result};
use clap::{Args, ValueEnum};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use nucleus_lineage::{CallSpiffeId, JsonlSink, LineageEdge, LineageSink};

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum LineageFormat {
    /// Indented text tree, one node per line.
    Tree,
    /// JSON object with `root`, `nodes`, `edges`.
    Json,
    /// Graphviz DOT (paste into https://dreampuf.github.io/GraphvizOnline/).
    Dot,
}

#[derive(Args, Debug)]
pub struct LineageArgs {
    /// Target CallSpiffeId — the leaf you want the lineage of.
    pub id: String,

    /// Path to the JSONL lineage log emitted by nucleus-tool-proxy.
    /// Defaults to ./nucleus-lineage.jsonl.
    #[arg(long, default_value = "./nucleus-lineage.jsonl")]
    pub log: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value_t = LineageFormat::Tree)]
    pub format: LineageFormat,

    /// Walk descendants instead of ancestors. Default is ancestors
    /// ("where did this come from?"); --descendants answers "what was
    /// derived from this?".
    #[arg(long)]
    pub descendants: bool,

    /// Maximum depth to walk. 0 means unlimited.
    #[arg(long, default_value_t = 0)]
    pub max_depth: usize,
}

pub fn execute(args: LineageArgs) -> Result<()> {
    let target = args
        .id
        .parse::<CallSpiffeId>()
        .with_context(|| format!("invalid SPIFFE ID: {}", args.id))?;

    let sink = JsonlSink::open(&args.log)
        .with_context(|| format!("opening lineage log {}", args.log.display()))?;
    let edges = sink.iter().context("reading lineage log")?;

    if edges.is_empty() {
        return Err(anyhow!(
            "no lineage edges in {} (is the log path correct?)",
            args.log.display()
        ));
    }

    let graph = LineageGraph::build(&edges);

    let collected = if args.descendants {
        graph.walk_descendants(&target, args.max_depth)
    } else {
        graph.walk_ancestors(&target, args.max_depth)
    };

    if collected.is_empty() {
        return Err(anyhow!(
            "no edges reference {} in {}",
            target,
            args.log.display()
        ));
    }

    match args.format {
        LineageFormat::Tree => render_tree(&target, &collected, args.descendants),
        LineageFormat::Json => render_json(&target, &collected)?,
        LineageFormat::Dot => render_dot(&target, &collected),
    }

    Ok(())
}

// ────────────────────────────────────────────────────────────────────────
// Graph

struct LineageGraph<'a> {
    /// child id → edges that produced it
    edges_by_child: BTreeMap<String, Vec<&'a LineageEdge>>,
    /// parent id → edges where this is one of the parents
    edges_by_parent: BTreeMap<String, Vec<&'a LineageEdge>>,
}

impl<'a> LineageGraph<'a> {
    fn build(edges: &'a [LineageEdge]) -> Self {
        let mut by_child: BTreeMap<String, Vec<&LineageEdge>> = BTreeMap::new();
        let mut by_parent: BTreeMap<String, Vec<&LineageEdge>> = BTreeMap::new();
        for e in edges {
            by_child.entry(e.child.to_string()).or_default().push(e);
            for p in &e.parents {
                by_parent.entry(p.to_string()).or_default().push(e);
            }
        }
        Self {
            edges_by_child: by_child,
            edges_by_parent: by_parent,
        }
    }

    /// BFS from `target` following parent pointers. Returns the subset of
    /// edges visited, deduplicated by edge identity.
    fn walk_ancestors(&self, target: &CallSpiffeId, max_depth: usize) -> Vec<LineageEdge> {
        let mut seen_ids: BTreeSet<String> = BTreeSet::new();
        let mut out: Vec<LineageEdge> = Vec::new();
        let mut frontier: Vec<(String, usize)> = vec![(target.to_string(), 0)];
        seen_ids.insert(target.to_string());

        while let Some((id, depth)) = frontier.pop() {
            if max_depth != 0 && depth > max_depth {
                continue;
            }
            if let Some(edges) = self.edges_by_child.get(&id) {
                for e in edges {
                    out.push((*e).clone());
                    for p in &e.parents {
                        if seen_ids.insert(p.to_string()) {
                            frontier.push((p.to_string(), depth + 1));
                        }
                    }
                }
            }
        }
        out
    }

    /// BFS from `target` following child pointers (descendants).
    fn walk_descendants(&self, target: &CallSpiffeId, max_depth: usize) -> Vec<LineageEdge> {
        let mut seen_ids: BTreeSet<String> = BTreeSet::new();
        let mut out: Vec<LineageEdge> = Vec::new();
        let mut frontier: Vec<(String, usize)> = vec![(target.to_string(), 0)];
        seen_ids.insert(target.to_string());

        while let Some((id, depth)) = frontier.pop() {
            if max_depth != 0 && depth > max_depth {
                continue;
            }
            if let Some(edges) = self.edges_by_parent.get(&id) {
                for e in edges {
                    out.push((*e).clone());
                    if seen_ids.insert(e.child.to_string()) {
                        frontier.push((e.child.to_string(), depth + 1));
                    }
                }
            }
        }
        out
    }
}

// ────────────────────────────────────────────────────────────────────────
// Renderers

fn render_tree(target: &CallSpiffeId, edges: &[LineageEdge], descendants: bool) {
    println!(
        "lineage {} {}",
        if descendants { "↓ from" } else { "↑ to" },
        target
    );
    for e in edges {
        let kind = format_kind(e);
        let hash = e
            .content_hash_hex
            .as_deref()
            .or_else(|| e.child.content_hash_hex())
            .map(|h| format!(" sha256={}…", &h[..h.len().min(12)]))
            .unwrap_or_default();
        println!("  {} {}{}", kind, e.child, hash);
        for p in &e.parents {
            println!("    ← {}", p);
        }
    }
}

fn render_json(target: &CallSpiffeId, edges: &[LineageEdge]) -> Result<()> {
    let payload = serde_json::json!({
        "target": target.to_string(),
        "edges": edges,
    });
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

fn render_dot(target: &CallSpiffeId, edges: &[LineageEdge]) {
    println!("digraph lineage {{");
    println!("  rankdir=BT;");
    println!("  node [shape=box, fontname=\"monospace\", fontsize=10];");
    let mut nodes: BTreeSet<String> = BTreeSet::new();
    for e in edges {
        nodes.insert(e.child.to_string());
        for p in &e.parents {
            nodes.insert(p.to_string());
        }
    }
    for n in &nodes {
        let label = short_label(n);
        let style = if n == &target.to_string() {
            ", style=filled, fillcolor=\"#cde7ff\""
        } else {
            ""
        };
        println!("  \"{n}\" [label=\"{label}\"{style}];");
    }
    for e in edges {
        for p in &e.parents {
            println!(
                "  \"{p}\" -> \"{}\" [label=\"{}\"];",
                e.child,
                format_kind(e)
            );
        }
    }
    println!("}}");
}

fn format_kind(edge: &LineageEdge) -> String {
    match &edge.kind {
        nucleus_lineage::EdgeKind::PodAdmit => "[pod_admit]".to_string(),
        nucleus_lineage::EdgeKind::ToolCall { tool } => format!("[tool/{}]", tool),
        nucleus_lineage::EdgeKind::LlmCall {
            provider,
            direction,
        } => format!("[llm/{}/{}]", provider, direction),
        nucleus_lineage::EdgeKind::ArtifactProduced => "[artifact]".to_string(),
        nucleus_lineage::EdgeKind::Merge => "[merge]".to_string(),
        nucleus_lineage::EdgeKind::Other { name } => format!("[{}]", name),
    }
}

fn short_label(id: &str) -> String {
    // Strip `spiffe://...` prefix and shorten the call uuid for readability.
    let stripped = id.strip_prefix("spiffe://").unwrap_or(id);
    let mut out = String::new();
    for seg in stripped.split('/') {
        if seg.len() > 16 && (seg.contains('-') || seg.starts_with("sha256:")) {
            out.push('/');
            out.push_str(&seg[..8]);
            out.push('…');
        } else {
            out.push('/');
            out.push_str(seg);
        }
    }
    // Drop the leading `/` we added unconditionally.
    out.strip_prefix('/').unwrap_or(&out).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_lineage::{EdgeKind, InMemorySink};

    fn pod() -> CallSpiffeId {
        CallSpiffeId::pod("prod.example.com", "agents", "coder").unwrap()
    }

    fn three_step_chain() -> (CallSpiffeId, Vec<LineageEdge>) {
        let p = pod();
        let bash = p.derive_tool("Bash", Some(b"ls")).unwrap();
        let derived = bash.derive_artifact(b"output bytes").unwrap();
        let edges = vec![
            LineageEdge::pod_admit(p.clone()),
            LineageEdge::from_parent(
                bash.clone(),
                p,
                EdgeKind::ToolCall {
                    tool: "Bash".to_string(),
                },
            ),
            LineageEdge::from_parent(derived.clone(), bash, EdgeKind::ArtifactProduced),
        ];
        (derived, edges)
    }

    #[test]
    fn walk_ancestors_finds_full_chain() {
        let (leaf, edges) = three_step_chain();
        let g = LineageGraph::build(&edges);
        let walk = g.walk_ancestors(&leaf, 0);
        // 3 edges visited: leaf, bash call, pod admit (no parents → terminates).
        assert_eq!(walk.len(), 3);
    }

    #[test]
    fn walk_ancestors_respects_max_depth() {
        let (leaf, edges) = three_step_chain();
        let g = LineageGraph::build(&edges);
        let walk = g.walk_ancestors(&leaf, 1);
        // Depth 0: leaf's edge. Depth 1: bash's edge. depth 2 (pod_admit) clipped.
        assert!(walk.len() < 3);
    }

    #[test]
    fn walk_descendants_finds_subtree() {
        let (_leaf, edges) = three_step_chain();
        let pod_id = pod();
        let g = LineageGraph::build(&edges);
        let walk = g.walk_descendants(&pod_id, 0);
        // From the pod we should reach the bash call (and through it, the artifact).
        assert!(!walk.is_empty(), "descendants walk must not be empty");
        let kinds: Vec<_> = walk
            .iter()
            .map(|e| {
                matches!(
                    e.kind,
                    EdgeKind::ToolCall { .. } | EdgeKind::ArtifactProduced
                )
            })
            .collect();
        assert!(
            kinds.iter().all(|x| *x),
            "walked edges should be tool/artifact, got {:?}",
            walk.iter().map(|e| &e.kind).collect::<Vec<_>>()
        );
    }

    #[test]
    fn unknown_id_returns_empty_walk() {
        let (_leaf, edges) = three_step_chain();
        let g = LineageGraph::build(&edges);
        let unknown = pod().derive_tool("NotInGraph", Some(b"x")).unwrap();
        assert!(g.walk_ancestors(&unknown, 0).is_empty());
    }

    #[test]
    fn graph_handles_multi_parent_merge() {
        let p = pod();
        let a = p.derive_tool("Read", Some(b"a")).unwrap();
        let b = p.derive_tool("Read", Some(b"b")).unwrap();
        let merged = p.derive_artifact(b"a+b").unwrap();
        let merge_edge = LineageEdge {
            child: merged.clone(),
            parents: vec![a.clone(), b.clone()],
            kind: EdgeKind::Merge,
            content_hash_hex: None,
            ts: chrono::Utc::now(),
            attrs: Default::default(),
        };
        let edges = vec![
            LineageEdge::pod_admit(p.clone()),
            LineageEdge::from_parent(
                a.clone(),
                p.clone(),
                EdgeKind::ToolCall {
                    tool: "Read".to_string(),
                },
            ),
            LineageEdge::from_parent(
                b.clone(),
                p.clone(),
                EdgeKind::ToolCall {
                    tool: "Read".to_string(),
                },
            ),
            merge_edge,
        ];
        let g = LineageGraph::build(&edges);
        let walk = g.walk_ancestors(&merged, 0);
        // Should reach both a and b.
        let parent_ids: BTreeSet<_> = walk
            .iter()
            .flat_map(|e| e.parents.iter().map(|p| p.to_string()))
            .collect();
        assert!(parent_ids.contains(a.as_str()));
        assert!(parent_ids.contains(b.as_str()));
    }

    #[test]
    fn cycle_does_not_loop_forever() {
        // Construct a synthetic cycle: x → y → x. (Not constructible via the
        // normal derivation API because uuids differ; we hand-build the edges.)
        let p = pod();
        let x = p.derive_artifact(b"x").unwrap();
        let y = p.derive_artifact(b"y").unwrap();
        let edges = vec![
            LineageEdge {
                child: x.clone(),
                parents: vec![y.clone()],
                kind: EdgeKind::ArtifactProduced,
                content_hash_hex: None,
                ts: chrono::Utc::now(),
                attrs: Default::default(),
            },
            LineageEdge {
                child: y.clone(),
                parents: vec![x.clone()],
                kind: EdgeKind::ArtifactProduced,
                content_hash_hex: None,
                ts: chrono::Utc::now(),
                attrs: Default::default(),
            },
        ];
        let g = LineageGraph::build(&edges);
        let walk = g.walk_ancestors(&x, 0);
        // 2 edges visited; no infinite loop. Both should appear.
        assert_eq!(walk.len(), 2);
    }

    #[test]
    fn end_to_end_via_jsonl_sink() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lineage.jsonl");
        let sink = JsonlSink::open(&path).unwrap();
        let (leaf, edges) = three_step_chain();
        for e in edges {
            sink.emit(e).unwrap();
        }
        // Reload via the same code path the CLI uses.
        let reloaded = JsonlSink::open(&path).unwrap();
        let all = reloaded.iter().unwrap();
        let g = LineageGraph::build(&all);
        let walk = g.walk_ancestors(&leaf, 0);
        assert_eq!(walk.len(), 3);
        // sanity-check rendering doesn't panic
        render_tree(&leaf, &walk, false);
    }

    #[test]
    fn dot_output_is_well_formed() {
        let (leaf, edges) = three_step_chain();
        let g = LineageGraph::build(&edges);
        let walk = g.walk_ancestors(&leaf, 0);
        // Capture stdout by routing render_dot through a Vec<u8> would require
        // refactoring; here we just verify no panic and a nontrivial graph.
        assert!(!walk.is_empty());
        render_dot(&leaf, &walk);
    }

    // Suppress unused-import lint for InMemorySink which is referenced in
    // future test additions.
    #[allow(dead_code)]
    fn _keep_in_memory_sink_in_scope() -> InMemorySink {
        InMemorySink::new()
    }
}

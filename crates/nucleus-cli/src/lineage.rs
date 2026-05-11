//! `nucleus lineage` — walk the lineage DAG for a given SPIFFE ID.
//!
//! Reads an append-only JSONL log produced by [`nucleus_lineage::JsonlSink`]
//! and renders the parent-chain (or full subtree) of a target call ID in
//! one of three formats: indented text (default), JSON, or Graphviz DOT.

use anyhow::{anyhow, Context, Result};
use clap::{Args, ValueEnum};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use nucleus_lineage::{
    edge_content_hash, verify_proof, CallSpiffeId, JsonlSink, Jwks, LineageEdge, LineageSink,
    VerifyError,
};

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

    /// Skip the structural-parent integrity check. By default, edges whose
    /// claimed `parents` are not a SPIFFE-prefix of the `child` are dropped
    /// from the walk (with a stderr warning) — this catches forged log
    /// entries that try to claim an unrelated SPIFFE ID as a parent. Pass
    /// `--allow-forged` to walk them anyway.
    #[arg(long)]
    pub allow_forged: bool,

    /// Path to a JWKS (JSON Web Key Set) file with verifying keys for the
    /// issuers that signed edges in this log. When provided, every edge's
    /// cryptographic `proof` is verified before the edge is included in the
    /// walk; failures are dropped with a stderr warning.
    #[arg(long)]
    pub jwks: Option<PathBuf>,

    /// Reject edges that lack a cryptographic `proof`. Requires `--jwks`.
    /// Without this flag, unsigned edges still walk normally (structural
    /// check only); with it, only signed edges that verify against the JWKS
    /// are kept.
    #[arg(long)]
    pub require_signed: bool,
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

    if args.require_signed && args.jwks.is_none() {
        return Err(anyhow!(
            "--require-signed needs --jwks <path> to know which keys to trust"
        ));
    }

    let jwks: Option<Jwks> = match &args.jwks {
        Some(path) => {
            let bytes = std::fs::read(path)
                .with_context(|| format!("reading JWKS file {}", path.display()))?;
            Some(Jwks::parse(&bytes).with_context(|| {
                format!(
                    "parsing JWKS at {} (must be a JSON Web Key Set)",
                    path.display()
                )
            })?)
        }
        None => None,
    };

    // Verify signatures BEFORE building the graph so the walker never sees
    // rejected edges. Hash-chain order is sink-iteration order (oldest first).
    let edges = if let Some(ref jwks) = jwks {
        filter_verified(edges, jwks, args.require_signed)
    } else {
        edges
    };

    if edges.is_empty() {
        return Err(anyhow!(
            "no edges survived verification (check --jwks, or pass --allow-forged / drop --require-signed)"
        ));
    }

    let graph = LineageGraph::build(&edges);

    let collected = if args.descendants {
        graph.walk_descendants(&target, args.max_depth, args.allow_forged)
    } else {
        graph.walk_ancestors(&target, args.max_depth, args.allow_forged)
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
    ///
    /// Skips edges that fail [`is_structurally_consistent`] unless
    /// `allow_forged` is true; an `eprintln!` warning is emitted for each
    /// dropped edge so operators see why an expected ancestor is missing.
    fn walk_ancestors(
        &self,
        target: &CallSpiffeId,
        max_depth: usize,
        allow_forged: bool,
    ) -> Vec<LineageEdge> {
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
                    if !allow_forged && !is_structurally_consistent(e) {
                        eprintln!(
                            "warning: dropping structurally-inconsistent edge \
                             (child={}, parents={:?}, kind={:?}) — pass --allow-forged to keep",
                            e.child,
                            e.parents.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
                            e.kind,
                        );
                        continue;
                    }
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

    /// BFS from `target` following child pointers (descendants). Same
    /// structural-consistency filter as `walk_ancestors`.
    fn walk_descendants(
        &self,
        target: &CallSpiffeId,
        max_depth: usize,
        allow_forged: bool,
    ) -> Vec<LineageEdge> {
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
                    if !allow_forged && !is_structurally_consistent(e) {
                        eprintln!(
                            "warning: dropping structurally-inconsistent edge \
                             (child={}, parents={:?}, kind={:?})",
                            e.child,
                            e.parents.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
                            e.kind,
                        );
                        continue;
                    }
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

/// Return true if the edge's `parents` are a structural prefix of `child`
/// in the SPIFFE path scheme (or, for `Merge` edges, share the trust-domain
/// prefix with the child).
///
/// The audit (CRIT-5) demonstrated that a forged JSONL line could claim an
/// arbitrary SPIFFE ID as a parent, and the walker would happily render it
/// as part of the lineage. This check is the cheap structural defense:
///
/// - `PodAdmit` edges must have empty `parents`.
/// - For most kinds, every parent must be a string-prefix of the child
///   followed by `/call/` — i.e., the child's path is the parent's path
///   extended by one or more `/call/<uuid>/...` segments.
/// - For `Merge` edges, parents may be siblings (not direct ancestors), so
///   we only require trust-domain agreement: the SPIFFE authority of every
///   parent must equal the authority of the child.
///
/// Cryptographic verification of an attached [`Proof`](nucleus_lineage::Proof)
/// is the stronger defense; it lands in PR-D once edges are signed.
pub fn is_structurally_consistent(edge: &LineageEdge) -> bool {
    use nucleus_lineage::EdgeKind;
    match &edge.kind {
        EdgeKind::PodAdmit => edge.parents.is_empty(),
        EdgeKind::Merge => {
            let child_authority = spiffe_authority(edge.child.as_str());
            !edge.parents.is_empty()
                && edge
                    .parents
                    .iter()
                    .all(|p| spiffe_authority(p.as_str()) == child_authority)
        }
        _ => {
            !edge.parents.is_empty()
                && edge.parents.iter().all(|parent| {
                    let parent_str = parent.as_str();
                    let child_str = edge.child.as_str();
                    child_str.starts_with(parent_str)
                        && child_str[parent_str.len()..].starts_with("/call/")
                })
        }
    }
}

/// Extract the SPIFFE authority (trust domain) from a SPIFFE URI string.
/// Caller is responsible for the `spiffe://` prefix being present (the
/// hardened parser ensures this for any [`CallSpiffeId`]).
fn spiffe_authority(s: &str) -> &str {
    s.strip_prefix("spiffe://")
        .and_then(|rest| rest.split_once('/').map(|(auth, _)| auth))
        .unwrap_or("")
}

/// Verify each edge's `proof` against `jwks` in chain order. Edges that
/// fail verification (or, when `require_signed`, edges with no `proof` at
/// all) are dropped with a `stderr` warning.
///
/// Hash chain: each edge is verified with `prev_hash` set to the SHA-256
/// of the previous **kept** edge's canonical bytes. Dropped edges break
/// the chain — anything downstream of a dropped edge will fail with
/// `BrokenChain` and is also dropped, which is the correct semantic for
/// a tamper-evident log.
fn filter_verified(edges: Vec<LineageEdge>, jwks: &Jwks, require_signed: bool) -> Vec<LineageEdge> {
    let mut prev_hash: Option<[u8; 32]> = None;
    let mut out = Vec::with_capacity(edges.len());
    for edge in edges {
        match verify_proof(&edge, prev_hash.as_ref(), jwks) {
            Ok(()) => {
                prev_hash = Some(edge_content_hash(&edge, prev_hash.as_ref()));
                out.push(edge);
            }
            Err(VerifyError::Unsigned) if !require_signed => {
                // Pass through unsigned edges in non-strict mode but DON'T
                // advance the hash chain — an unsigned edge can't anchor the
                // chain for subsequent signed edges.
                out.push(edge);
            }
            Err(e) => {
                eprintln!(
                    "warning: dropping edge with proof error ({}): child={}",
                    e, edge.child
                );
            }
        }
    }
    out
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
        let walk = g.walk_ancestors(&leaf, 0, true);
        // 3 edges visited: leaf, bash call, pod admit (no parents → terminates).
        assert_eq!(walk.len(), 3);
    }

    #[test]
    fn walk_ancestors_respects_max_depth() {
        let (leaf, edges) = three_step_chain();
        let g = LineageGraph::build(&edges);
        let walk = g.walk_ancestors(&leaf, 1, true);
        // Depth 0: leaf's edge. Depth 1: bash's edge. depth 2 (pod_admit) clipped.
        assert!(walk.len() < 3);
    }

    #[test]
    fn walk_descendants_finds_subtree() {
        let (_leaf, edges) = three_step_chain();
        let pod_id = pod();
        let g = LineageGraph::build(&edges);
        let walk = g.walk_descendants(&pod_id, 0, true);
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
        assert!(g.walk_ancestors(&unknown, 0, true).is_empty());
    }

    /// CRIT-5 from the audit: a forged JSONL line could claim an unrelated
    /// SPIFFE ID as the parent of an attacker artifact. Default-strict mode
    /// drops such edges; --allow-forged passes them through.
    #[test]
    fn walk_drops_forged_edges_by_default() {
        let attacker_pod = CallSpiffeId::pod("attacker.example.com", "evil", "evil-sa").unwrap();
        let victim_pod = CallSpiffeId::pod("victim.example.com", "secret", "secret-sa").unwrap();
        let attacker_artifact = attacker_pod.derive_artifact(b"forged claim").unwrap();
        // Hand-build a forged edge: attacker's child claims victim's pod
        // ID as a parent. Under no normal derivation would this happen.
        let forged = LineageEdge {
            child: attacker_artifact.clone(),
            parents: vec![victim_pod.clone()],
            kind: EdgeKind::ArtifactProduced,
            content_hash_hex: None,
            ts: chrono::Utc::now(),
            attrs: Default::default(),
            proof: None,
        };
        let edges = vec![LineageEdge::pod_admit(victim_pod), forged];
        let g = LineageGraph::build(&edges);

        // Strict (default) — dropped.
        let strict_walk = g.walk_ancestors(&attacker_artifact, 0, false);
        assert!(
            strict_walk.is_empty(),
            "forged edge should be dropped in strict mode, got {:?}",
            strict_walk.iter().map(|e| &e.child).collect::<Vec<_>>()
        );

        // --allow-forged — passes through. The walker reaches the forged
        // edge (1), and via its claimed parent reaches victim_pod's
        // pod_admit (2). The defense-in-depth point of this test is that
        // strict mode prevents this two-step poisoning.
        let permissive_walk = g.walk_ancestors(&attacker_artifact, 0, true);
        assert_eq!(permissive_walk.len(), 2);
    }

    #[test]
    fn is_structurally_consistent_accepts_real_derivation() {
        let p = pod();
        let bash = p.derive_tool("Bash", Some(b"x")).unwrap();
        let edge = LineageEdge::from_parent(
            bash,
            p,
            EdgeKind::ToolCall {
                tool: "Bash".to_string(),
            },
        );
        assert!(is_structurally_consistent(&edge));
    }

    #[test]
    fn is_structurally_consistent_rejects_unrelated_parent() {
        let attacker_pod = CallSpiffeId::pod("attacker.example.com", "evil", "evil-sa").unwrap();
        let victim_pod = CallSpiffeId::pod("victim.example.com", "ok", "ok-sa").unwrap();
        let attacker_artifact = attacker_pod.derive_artifact(b"x").unwrap();
        let edge = LineageEdge {
            child: attacker_artifact,
            parents: vec![victim_pod],
            kind: EdgeKind::ArtifactProduced,
            content_hash_hex: None,
            ts: chrono::Utc::now(),
            attrs: Default::default(),
            proof: None,
        };
        assert!(!is_structurally_consistent(&edge));
    }

    #[test]
    fn is_structurally_consistent_pod_admit_must_have_no_parents() {
        let edge_ok = LineageEdge::pod_admit(pod());
        assert!(is_structurally_consistent(&edge_ok));

        let edge_bad = LineageEdge {
            child: pod(),
            parents: vec![pod()],
            kind: EdgeKind::PodAdmit,
            content_hash_hex: None,
            ts: chrono::Utc::now(),
            attrs: Default::default(),
            proof: None,
        };
        assert!(!is_structurally_consistent(&edge_bad));
    }

    #[test]
    fn merge_edge_requires_trust_domain_agreement() {
        let p = pod();
        let a = p.derive_tool("Read", Some(b"a")).unwrap();
        let b = p.derive_tool("Read", Some(b"b")).unwrap();
        let merged = p.derive_artifact(b"merged").unwrap();

        // Same trust domain → ok.
        let ok = LineageEdge {
            child: merged.clone(),
            parents: vec![a.clone(), b.clone()],
            kind: EdgeKind::Merge,
            content_hash_hex: None,
            ts: chrono::Utc::now(),
            attrs: Default::default(),
            proof: None,
        };
        assert!(is_structurally_consistent(&ok));

        // Cross-trust-domain Merge → rejected.
        let attacker = CallSpiffeId::pod("attacker.example.com", "evil", "evil-sa").unwrap();
        let bad = LineageEdge {
            child: merged,
            parents: vec![a, attacker],
            kind: EdgeKind::Merge,
            content_hash_hex: None,
            ts: chrono::Utc::now(),
            attrs: Default::default(),
            proof: None,
        };
        assert!(!is_structurally_consistent(&bad));
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
            proof: None,
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
        let walk = g.walk_ancestors(&merged, 0, true);
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
                proof: None,
            },
            LineageEdge {
                child: y.clone(),
                parents: vec![x.clone()],
                kind: EdgeKind::ArtifactProduced,
                content_hash_hex: None,
                ts: chrono::Utc::now(),
                attrs: Default::default(),
                proof: None,
            },
        ];
        let g = LineageGraph::build(&edges);
        let walk = g.walk_ancestors(&x, 0, true);
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
        let walk = g.walk_ancestors(&leaf, 0, true);
        assert_eq!(walk.len(), 3);
        // sanity-check rendering doesn't panic
        render_tree(&leaf, &walk, false);
    }

    #[test]
    fn dot_output_is_well_formed() {
        let (leaf, edges) = three_step_chain();
        let g = LineageGraph::build(&edges);
        let walk = g.walk_ancestors(&leaf, 0, true);
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

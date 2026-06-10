//! `ExternalityCube` — OLAP-style rollup over signed externality
//! claims.
//!
//! **Pigouvian Q1-Q4.** The cube is the substrate's "marginal rate"
//! oracle: it ingests every `EdgeKind::Externality` edge into
//! `(ResourceDim, WindowId)` buckets and surfaces the slice-derivative
//! that the Pigouvian rate-setter uses to update `λ_k`.
//!
//! Borrows the tomato sibling repo's `Aggregate.fs` pattern: nested
//! map `windowKey -> dimensionKey -> accumulated values`, tumbling
//! (non-overlapping) windows of size `window_micros`. State is in-
//! memory + append-only per window — eviction past
//! `retention_windows` keeps the cube bounded.
//!
//! ## Slice semantics
//!
//! ```text
//! cube.slice(GpuSeconds, w)         — sum / count / mean for this bucket
//! cube.marginal_rate(GpuSeconds, w) — finite-difference slope vs prior window
//! ```
//!
//! Marginal-rate computation matches the Pigouvian principle: the
//! rate `λ_k` for resource `k` in window `w` is the discrete slope of
//! (welfare loss imposed) vs (consumption units), proxied here by
//! `(Δ consumption) / (Δ time)` — a first-order Pigouvian rate-setter.
//! Higher-order rate-setters (using cube-slice derivatives over
//! multiple windows) are a follow-on.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::dim::ResourceDim;

/// Errors from cube operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PullbackError {
    /// Pull-back requires matching `window_micros`. Federations
    /// using different window sizes need to re-bucket first.
    #[error("window_micros mismatch: lhs={lhs}, rhs={rhs}")]
    WindowMicrosMismatch { lhs: u64, rhs: u64 },
}

/// Tumbling-window identifier — units of `window_micros` since
/// unix epoch. `WindowId(0)` is the first window after epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WindowId(pub u64);

impl WindowId {
    /// Compute the window id containing a given timestamp.
    pub fn from_unix_micros(ts_unix_micros: u64, window_micros: u64) -> Self {
        WindowId(ts_unix_micros / window_micros.max(1))
    }

    /// The starting timestamp (inclusive) of this window.
    pub fn start_unix_micros(self, window_micros: u64) -> u64 {
        self.0.saturating_mul(window_micros.max(1))
    }
}

/// Aggregated bucket for one `(ResourceDim, WindowId)` cell.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateBucket {
    /// Sum of `units_micro` over all claims in this bucket. `u128`
    /// so a 32-bit-overflow doesn't wreck the rollup.
    pub total_units_micro: u128,
    /// Count of claims that landed in this bucket.
    pub count: u64,
}

impl AggregateBucket {
    /// Mean units per claim in this bucket, integer (saturating to
    /// `u64`). Returns 0 if no claims.
    pub fn mean_units_micro(&self) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let m = self.total_units_micro / u128::from(self.count);
        u64::try_from(m).unwrap_or(u64::MAX)
    }
}

/// The cube itself — OLAP rollup over signed externality claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalityCube {
    /// Window size in micros. 1_000_000 = 1 s; 60_000_000 = 1 min;
    /// 3_600_000_000 = 1 h.
    pub window_micros: u64,
    /// Keep this many trailing windows. Older buckets evict on
    /// `ingest_at`. Set to `u64::MAX` for unbounded retention.
    pub retention_windows: u64,
    /// `(ResourceDim, WindowId) -> AggregateBucket`. BTreeMap keeps
    /// iteration order deterministic.
    buckets: BTreeMap<(ResourceDim, WindowId), AggregateBucket>,
    /// Most recent window observed; used for retention eviction.
    latest_window: Option<WindowId>,
}

impl ExternalityCube {
    /// Construct a cube with the given window size + retention.
    pub fn new(window_micros: u64, retention_windows: u64) -> Self {
        Self {
            window_micros: window_micros.max(1),
            retention_windows,
            buckets: BTreeMap::new(),
            latest_window: None,
        }
    }

    /// Number of `(dim, window)` cells currently in the cube.
    pub fn cell_count(&self) -> usize {
        self.buckets.len()
    }

    /// Ingest a raw `(dim, units_micro, ts_unix_micros)` triple. Used
    /// when the caller has already extracted the claim from the
    /// signed envelope. The Q2 wrapper `ingest_edge` walks an
    /// `EdgeKind::Externality` edge into this.
    pub fn ingest_at(&mut self, dim: ResourceDim, units_micro: u64, ts_unix_micros: u64) {
        let w = WindowId::from_unix_micros(ts_unix_micros, self.window_micros);
        let entry = self.buckets.entry((dim, w)).or_default();
        entry.total_units_micro = entry
            .total_units_micro
            .saturating_add(u128::from(units_micro));
        entry.count = entry.count.saturating_add(1);
        self.latest_window = Some(match self.latest_window {
            Some(prev) => prev.max(w),
            None => w,
        });
        self.evict_stale();
    }

    /// Bucket for one `(dim, window)` cell, if present.
    pub fn slice(&self, dim: ResourceDim, window: WindowId) -> Option<&AggregateBucket> {
        self.buckets.get(&(dim, window))
    }

    /// First-order marginal rate for `dim` at `window`: integer
    /// finite difference `Δ_total_units / Δ_window_count` against
    /// the *immediately previous* window. Returns 0 if either
    /// window is empty (no consumption ⇒ no marginal rate).
    pub fn marginal_rate(&self, dim: ResourceDim, window: WindowId) -> u64 {
        let curr = self
            .slice(dim, window)
            .map(|b| b.total_units_micro)
            .unwrap_or(0);
        // No prior window exists at window 0 — the marginal rate is
        // just the current consumption (rate-setter sees the cold-
        // start signal directly). For window N>0, use the
        // finite-difference against window N-1.
        let prev = if window.0 == 0 {
            0
        } else {
            self.slice(dim, WindowId(window.0 - 1))
                .map(|b| b.total_units_micro)
                .unwrap_or(0)
        };
        // First-order Pigouvian rate: change in consumption per
        // window. Higher-order rate-setters (cube-slice derivatives
        // across multiple windows + welfare-loss model) follow on.
        let delta = curr.abs_diff(prev);
        u64::try_from(delta).unwrap_or(u64::MAX)
    }

    /// **Pigouvian Q2.** Ingest an `EdgeKind::Externality`
    /// `LineageEdge` into the cube. Expects:
    ///   - `edge.kind = EdgeKind::Externality { resource, .. }`
    ///   - `edge.attrs["units_micro"]` carries the unsigned integer
    ///     consumption as a base-10 string (the runner emits this
    ///     when constructing the edge)
    ///   - `edge.ts` is the claim timestamp (already chrono-typed
    ///     on the edge)
    ///
    /// Returns `true` if the edge was ingested, `false` if it was
    /// skipped because it didn't match the contract above (wrong
    /// kind, missing/malformed attr, unknown resource tag). The
    /// caller may also feed `SignedExternalityClaim` records
    /// directly via [`Self::ingest_at`].
    pub fn ingest_edge(&mut self, edge: &nucleus_lineage::LineageEdge) -> bool {
        let resource_tag = match &edge.kind {
            nucleus_lineage::EdgeKind::Externality { resource, .. } => resource.as_str(),
            _ => return false,
        };
        let dim = match ResourceDim::all()
            .iter()
            .find(|d| d.as_canonical_tag() == resource_tag.as_bytes())
        {
            Some(d) => *d,
            None => return false,
        };
        let units_str = match edge.attrs.get("units_micro") {
            Some(s) => s,
            None => return false,
        };
        let units: u64 = match units_str.parse() {
            Ok(u) => u,
            Err(_) => return false,
        };
        // Convert chrono UTC timestamp → unix micros (signed → u64
        // saturating for pre-epoch defensive case).
        let ts_micros = edge.ts.timestamp_micros();
        let ts_unsigned = u64::try_from(ts_micros).unwrap_or(0);
        self.ingest_at(dim, units, ts_unsigned);
        true
    }

    /// **Pigouvian Q4 — federation pullback.** Compose two cubes
    /// into a single cube whose buckets are the *sum* over
    /// overlapping `(dim, window)` cells and the *union* of cells
    /// present in either.
    ///
    /// This is the categorical pullback of the externality functor
    /// along a federation map (interpreted as the identity here —
    /// non-identity federation maps that rewrite SPIFFE id namespaces
    /// would compose with this pullback at the edge-ingestion layer).
    /// Two federation members aggregating their externalities yield
    /// the same total cube as one federation member with both
    /// streams ingested.
    ///
    /// `window_micros` MUST match; mismatched windowing produces an
    /// `Err`. `retention_windows` of `self` is preserved; the
    /// result is evicted to that horizon.
    pub fn pull_back(&self, other: &ExternalityCube) -> Result<ExternalityCube, PullbackError> {
        if self.window_micros != other.window_micros {
            return Err(PullbackError::WindowMicrosMismatch {
                lhs: self.window_micros,
                rhs: other.window_micros,
            });
        }
        let mut out = ExternalityCube::new(self.window_micros, self.retention_windows);
        // Sum overlapping cells; union the rest.
        for (key, b) in self.buckets.iter().chain(other.buckets.iter()) {
            let entry = out.buckets.entry(*key).or_default();
            entry.total_units_micro = entry.total_units_micro.saturating_add(b.total_units_micro);
            entry.count = entry.count.saturating_add(b.count);
        }
        out.latest_window = match (self.latest_window, other.latest_window) {
            (Some(a), Some(b)) => Some(WindowId(a.0.max(b.0))),
            (a, None) => a,
            (None, b) => b,
        };
        out.evict_stale();
        Ok(out)
    }

    /// Sum across all windows for a single dimension. Useful for
    /// release-notes "total carbon this quarter" surfacing.
    pub fn total(&self, dim: ResourceDim) -> u128 {
        self.buckets
            .iter()
            .filter(|((d, _), _)| *d == dim)
            .map(|(_, b)| b.total_units_micro)
            .sum()
    }

    /// Evict buckets older than `retention_windows` behind
    /// `latest_window`.
    fn evict_stale(&mut self) {
        if self.retention_windows == u64::MAX {
            return;
        }
        let Some(latest) = self.latest_window else {
            return;
        };
        if latest.0 < self.retention_windows {
            return;
        }
        let cutoff = WindowId(latest.0 - self.retention_windows + 1);
        self.buckets.retain(|(_, w), _| *w >= cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_id_buckets_correctly() {
        let w = WindowId::from_unix_micros(150, 100);
        assert_eq!(w, WindowId(1));
        assert_eq!(w.start_unix_micros(100), 100);
        // Boundary: ts == window_start belongs to that window.
        assert_eq!(WindowId::from_unix_micros(100, 100), WindowId(1));
        assert_eq!(WindowId::from_unix_micros(99, 100), WindowId(0));
    }

    #[test]
    fn aggregate_bucket_mean_handles_empty() {
        let b = AggregateBucket::default();
        assert_eq!(b.mean_units_micro(), 0);
    }

    #[test]
    fn ingest_aggregates_three_claims_correctly() {
        let mut c = ExternalityCube::new(100, u64::MAX);
        c.ingest_at(ResourceDim::GpuSeconds, 1_000, 50);
        c.ingest_at(ResourceDim::GpuSeconds, 2_000, 75);
        c.ingest_at(ResourceDim::GpuSeconds, 4_000, 95);
        let bucket = c
            .slice(ResourceDim::GpuSeconds, WindowId(0))
            .expect("bucket exists");
        assert_eq!(bucket.count, 3);
        assert_eq!(bucket.total_units_micro, 7_000);
        assert_eq!(bucket.mean_units_micro(), 2_333);
        assert_eq!(c.cell_count(), 1);
    }

    #[test]
    fn ingest_distributes_across_windows() {
        let mut c = ExternalityCube::new(100, u64::MAX);
        c.ingest_at(ResourceDim::GpuSeconds, 1_000, 50);
        c.ingest_at(ResourceDim::GpuSeconds, 2_000, 150);
        c.ingest_at(ResourceDim::GpuSeconds, 4_000, 250);
        assert_eq!(c.cell_count(), 3);
        assert_eq!(
            c.slice(ResourceDim::GpuSeconds, WindowId(0)).unwrap().count,
            1
        );
        assert_eq!(
            c.slice(ResourceDim::GpuSeconds, WindowId(1)).unwrap().count,
            1
        );
        assert_eq!(
            c.slice(ResourceDim::GpuSeconds, WindowId(2)).unwrap().count,
            1
        );
    }

    #[test]
    fn distinct_dims_dont_collide() {
        let mut c = ExternalityCube::new(100, u64::MAX);
        c.ingest_at(ResourceDim::GpuSeconds, 1_000, 50);
        c.ingest_at(ResourceDim::GridCarbonGramsCo2, 500, 50);
        assert_eq!(c.cell_count(), 2);
        assert_eq!(
            c.slice(ResourceDim::GpuSeconds, WindowId(0))
                .unwrap()
                .total_units_micro,
            1_000
        );
        assert_eq!(
            c.slice(ResourceDim::GridCarbonGramsCo2, WindowId(0))
                .unwrap()
                .total_units_micro,
            500
        );
    }

    #[test]
    fn marginal_rate_finite_difference() {
        let mut c = ExternalityCube::new(100, u64::MAX);
        // Window 0: total 1000
        c.ingest_at(ResourceDim::GpuSeconds, 1_000, 50);
        // Window 1: total 3500
        c.ingest_at(ResourceDim::GpuSeconds, 1_500, 150);
        c.ingest_at(ResourceDim::GpuSeconds, 2_000, 175);
        // Marginal rate at window 1 = |3500 - 1000| = 2500.
        assert_eq!(c.marginal_rate(ResourceDim::GpuSeconds, WindowId(1)), 2_500);
        // Window 0 has no prior window → rate = curr - 0 = 1000.
        assert_eq!(c.marginal_rate(ResourceDim::GpuSeconds, WindowId(0)), 1_000);
    }

    #[test]
    fn marginal_rate_handles_consumption_decrease() {
        let mut c = ExternalityCube::new(100, u64::MAX);
        c.ingest_at(ResourceDim::GpuSeconds, 5_000, 50);
        c.ingest_at(ResourceDim::GpuSeconds, 1_000, 150);
        // |1000 - 5000| = 4000 — magnitude of change. Sign would
        // matter in a real rate-setter (negative rate = subsidy);
        // for now we surface magnitude and let the rate-setter
        // assign sign based on resource direction.
        assert_eq!(c.marginal_rate(ResourceDim::GpuSeconds, WindowId(1)), 4_000);
    }

    #[test]
    fn total_sums_across_windows() {
        let mut c = ExternalityCube::new(100, u64::MAX);
        c.ingest_at(ResourceDim::GpuSeconds, 1_000, 50);
        c.ingest_at(ResourceDim::GpuSeconds, 2_000, 150);
        c.ingest_at(ResourceDim::GpuSeconds, 4_000, 250);
        c.ingest_at(ResourceDim::GridCarbonGramsCo2, 500, 50);
        assert_eq!(c.total(ResourceDim::GpuSeconds), 7_000);
        assert_eq!(c.total(ResourceDim::GridCarbonGramsCo2), 500);
        assert_eq!(c.total(ResourceDim::PeerVerifierMillis), 0);
    }

    #[test]
    fn retention_evicts_old_windows() {
        let mut c = ExternalityCube::new(100, 2);
        c.ingest_at(ResourceDim::GpuSeconds, 1_000, 50); // window 0
        c.ingest_at(ResourceDim::GpuSeconds, 2_000, 150); // window 1
        c.ingest_at(ResourceDim::GpuSeconds, 3_000, 250); // window 2 — evicts 0
        assert!(
            c.slice(ResourceDim::GpuSeconds, WindowId(0)).is_none(),
            "window 0 should be evicted"
        );
        assert!(c.slice(ResourceDim::GpuSeconds, WindowId(1)).is_some());
        assert!(c.slice(ResourceDim::GpuSeconds, WindowId(2)).is_some());
    }

    #[test]
    fn unbounded_retention_keeps_everything() {
        let mut c = ExternalityCube::new(100, u64::MAX);
        for i in 0..50 {
            c.ingest_at(ResourceDim::GpuSeconds, 1_000, i * 100 + 50);
        }
        assert_eq!(c.cell_count(), 50);
    }

    #[test]
    fn empty_cube_marginal_is_zero() {
        let c = ExternalityCube::new(100, u64::MAX);
        assert_eq!(c.marginal_rate(ResourceDim::GpuSeconds, WindowId(42)), 0);
    }

    // ── Q2 — ingest_edge from LineageEdge ──────────────────────────────

    fn mk_externality_edge(
        resource_tag: &str,
        units_micro: u64,
        ts_unix_micros: u64,
    ) -> nucleus_lineage::LineageEdge {
        use chrono::TimeZone as _;
        let pod = nucleus_lineage::CallSpiffeId::pod("test.example.com", "agents", "a1").unwrap();
        let child = pod
            .derive_artifact(format!("{resource_tag}-{units_micro}").as_bytes())
            .unwrap();
        let mut edge = nucleus_lineage::LineageEdge::from_parent(
            child,
            pod,
            nucleus_lineage::EdgeKind::Externality {
                resource: resource_tag.to_string(),
                oracle_kid: "test-oracle".to_string(),
            },
        )
        .with_attr("units_micro", units_micro.to_string());
        // Override ts so the cube buckets the edge into a known
        // window.
        edge.ts = chrono::Utc.timestamp_micros(ts_unix_micros as i64).unwrap();
        edge
    }

    #[test]
    fn ingest_edge_walks_externality_into_cube() {
        let mut c = ExternalityCube::new(100, u64::MAX);
        let edge = mk_externality_edge("gpu_s", 4_242_000, 50);
        assert!(c.ingest_edge(&edge));
        let bucket = c
            .slice(ResourceDim::GpuSeconds, WindowId(0))
            .expect("ingested bucket exists");
        assert_eq!(bucket.count, 1);
        assert_eq!(bucket.total_units_micro, 4_242_000);
    }

    #[test]
    fn ingest_edge_rejects_non_externality() {
        let mut c = ExternalityCube::new(100, u64::MAX);
        let pod = nucleus_lineage::CallSpiffeId::pod("test.example.com", "agents", "a1").unwrap();
        let edge = nucleus_lineage::LineageEdge::pod_admit(pod);
        assert!(!c.ingest_edge(&edge));
        assert_eq!(c.cell_count(), 0);
    }

    #[test]
    fn ingest_edge_rejects_unknown_resource_tag() {
        let mut c = ExternalityCube::new(100, u64::MAX);
        let edge = mk_externality_edge("unknown_dim", 1_000, 50);
        assert!(!c.ingest_edge(&edge));
        assert_eq!(c.cell_count(), 0);
    }

    #[test]
    fn ingest_edge_rejects_missing_units_attr() {
        let mut c = ExternalityCube::new(100, u64::MAX);
        let mut edge = mk_externality_edge("gpu_s", 1_000, 50);
        edge.attrs.clear();
        assert!(!c.ingest_edge(&edge));
        assert_eq!(c.cell_count(), 0);
    }

    // ── Q4 — federation pullback ──────────────────────────────────────

    #[test]
    fn pullback_sums_overlapping_cells_and_unions_others() {
        let mut a = ExternalityCube::new(100, u64::MAX);
        a.ingest_at(ResourceDim::GpuSeconds, 1_000, 50); // (gpu, 0)
        a.ingest_at(ResourceDim::GpuSeconds, 500, 150); // (gpu, 1)
        let mut b = ExternalityCube::new(100, u64::MAX);
        b.ingest_at(ResourceDim::GpuSeconds, 2_000, 75); // (gpu, 0) — overlap
        b.ingest_at(ResourceDim::GridCarbonGramsCo2, 300, 50); // (co2, 0) — new
        let pulled = a.pull_back(&b).unwrap();
        // Overlap: (gpu, 0) summed.
        let gpu0 = pulled.slice(ResourceDim::GpuSeconds, WindowId(0)).unwrap();
        assert_eq!(gpu0.total_units_micro, 3_000);
        assert_eq!(gpu0.count, 2);
        // (gpu, 1) carried from a only.
        let gpu1 = pulled.slice(ResourceDim::GpuSeconds, WindowId(1)).unwrap();
        assert_eq!(gpu1.total_units_micro, 500);
        // (co2, 0) carried from b only.
        let co2 = pulled
            .slice(ResourceDim::GridCarbonGramsCo2, WindowId(0))
            .unwrap();
        assert_eq!(co2.total_units_micro, 300);
    }

    #[test]
    fn pullback_associative_with_three_cubes() {
        // (a ⊕ b) ⊕ c = a ⊕ (b ⊕ c) — the categorical pullback is
        // associative when window_micros matches across all three.
        let mut a = ExternalityCube::new(100, u64::MAX);
        let mut b = ExternalityCube::new(100, u64::MAX);
        let mut c = ExternalityCube::new(100, u64::MAX);
        a.ingest_at(ResourceDim::GpuSeconds, 1_000, 50);
        b.ingest_at(ResourceDim::GpuSeconds, 2_000, 50);
        c.ingest_at(ResourceDim::GpuSeconds, 3_000, 50);

        let lhs = a.pull_back(&b).unwrap().pull_back(&c).unwrap();
        let rhs = a.pull_back(&b.pull_back(&c).unwrap()).unwrap();

        assert_eq!(
            lhs.slice(ResourceDim::GpuSeconds, WindowId(0))
                .unwrap()
                .total_units_micro,
            6_000
        );
        assert_eq!(
            rhs.slice(ResourceDim::GpuSeconds, WindowId(0))
                .unwrap()
                .total_units_micro,
            6_000
        );
    }

    #[test]
    fn pullback_rejects_window_micros_mismatch() {
        let a = ExternalityCube::new(100, u64::MAX);
        let b = ExternalityCube::new(1_000, u64::MAX);
        let err = a.pull_back(&b).unwrap_err();
        assert!(matches!(err, PullbackError::WindowMicrosMismatch { .. }));
    }

    #[test]
    fn pullback_with_empty_cube_is_identity() {
        // Categorical identity element of pullback: empty cube.
        let mut a = ExternalityCube::new(100, u64::MAX);
        a.ingest_at(ResourceDim::GpuSeconds, 1_500, 50);
        let empty = ExternalityCube::new(100, u64::MAX);
        let pulled = a.pull_back(&empty).unwrap();
        let original = a.slice(ResourceDim::GpuSeconds, WindowId(0)).unwrap();
        let after = pulled.slice(ResourceDim::GpuSeconds, WindowId(0)).unwrap();
        assert_eq!(original, after);
    }
}

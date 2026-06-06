//! The `Gov` functor contract — admitted witness → olog fact.
//!
//! `Gov : 𝓦 → 𝓞` maps an admitted witness (source category 𝓦: objects =
//! content-addressed witness digests, morphisms = admitted lineage edges) to a
//! **fact** in the olog (target category 𝓞). See
//! `docs/rfcs/witness-olog-functor.md`.
//!
//! **P2.1 scope:** this is the *contract* — the types, the functor trait, and the
//! load-bearing **no-upgrade invariant** (Gov carries the witness's assurance
//! rung through unchanged; it never manufactures or upgrades trust). Wiring to the
//! real `merge-gate` archive and the live `olog` instance store is **P2.2**;
//! [`WitnessDigest`]/[`OlogFact::instance_digest`] are 32-byte stand-ins that
//! P2.2 unifies with `ck-types::ArtifactDigest` and a real olog instance digest.
//!
//! ## Why a functor (the property the type system can't state but the law does)
//!
//! A functor preserves identity and composition: `Gov(g ∘ f) = Gov(g) ∘ Gov(f)`.
//! Concretely, a *pipeline* of admitted tasks (a chain of lineage edges) maps to a
//! *composed* fact — proven work composes, instead of piling up as unrelated
//! receipts. The functor laws are **PROVED sorry-free** (over the assurance
//! composition) in `nucleus-econ-kernels/lean/Nucleus/WitnessOlog.lean`
//! (`gov_is_functor`, axioms `[propext, Quot.sound]`); here we encode the
//! per-object behaviour and the no-upgrade invariant as tests. (Functoriality
//! over the full lineage DAG + real olog instance digests remains future work,
//! tracked with the olog Lean `sorry` budget.)

use nucleus_externality::AssuranceRung;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Content-addressed identifier of a witness (the source-category object id).
/// 32 bytes — a BLAKE3/SHA-256-class digest. P2.2 unifies this with
/// `ck-types::ArtifactDigest`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WitnessDigest(pub [u8; 32]);

impl WitnessDigest {
    /// Lowercase-hex rendering for receipts / logs.
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

/// An admitted lineage edge (a morphism in 𝓦): the child's admission points at
/// its already-admitted parent. The kernel's dual-DAG already enforces this; here
/// it is the composable arrow `Gov` is functorial over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LineageEdge {
    pub parent: WitnessDigest,
    pub child: WitnessDigest,
}

/// How well-proven an accumulated fact is — the honesty tier from
/// `CATEGORICAL-LANDSCAPE.md`. Mandatory: the olog's Lean core is theorem-
/// incomplete (~1000 tracked `sorry`s), so a fact must never *read* as more proven
/// than it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Backed by a discharged, axiom-audited proof (sorry-free).
    Proven,
    /// Structurally modelled; the proof is an obligation, not discharged.
    Modeled,
    /// An analogy / informal argument only.
    Analogy,
}

/// The kernel's admission decision for the witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionVerdict {
    Admitted,
    Rejected,
}

/// A source-category object: an admitted witness plus the attributes it *proved*.
/// These attributes are the witness's own — `Gov` may carry them through but must
/// never strengthen them (the no-upgrade invariant).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessNode {
    pub digest: WitnessDigest,
    /// The olog spec this witness claims to satisfy.
    pub task_spec_hash: [u8; 32],
    /// The assurance rung the witness's evidence actually reached.
    pub rung: AssuranceRung,
    /// How well-proven the witness's claim is.
    pub tier: Tier,
    /// The kernel's verdict on this witness.
    pub verdict: AdmissionVerdict,
    /// The admitted parent, if any (root nodes have none).
    pub parent: Option<WitnessDigest>,
}

/// A target-category object: a categorical **fact** in the olog. The accumulated,
/// queryable record of one piece of proven work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OlogFact {
    /// The olog spec this fact is an instance of.
    pub task_spec_hash: [u8; 32],
    /// Digest of the olog instance Gov produced (P2.2: the real instance digest).
    pub instance_digest: [u8; 32],
    /// Carried through from the witness — NEVER upgraded.
    pub rung: AssuranceRung,
    /// Carried through from the witness — NEVER upgraded.
    pub tier: Tier,
}

/// The functor `Gov : 𝓦 → 𝓞`.
///
/// Implementors MUST satisfy:
/// 1. **No-upgrade:** `gov.map_witness(n).rung == n.rung` and
///    `gov.map_witness(n).tier == n.tier` — Gov carries assurance through, never
///    strengthens it (trust in, trust out).
/// 2. **Determinism:** equal inputs map to equal facts (so anyone can recompute
///    the accumulation from the witness archive).
/// 3. **Functoriality (PROVED):** identity and composition preserved over
///    [`LineageEdge`]s, so proven pipelines compose. Proved sorry-free over the
///    assurance composition in `lean/Nucleus/WitnessOlog.lean` (`gov_is_functor`).
pub trait Gov {
    fn map_witness(&self, node: &WitnessNode) -> OlogFact;
}

/// The reference functor: carries every attribute through faithfully and derives a
/// deterministic stand-in instance digest. It is the canonical witness of the
/// no-upgrade invariant; P2.2 replaces the stand-in digest with the real olog
/// instance digest while keeping this behaviour.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoUpgradeGov;

/// Domain prefix for the stand-in instance digest. Versioned so P2.2's real
/// digest can't be confused with a P2.1 stand-in.
const INSTANCE_STANDIN_DOMAIN: &[u8] = b"nucleus/witness-olog/instance-standin/v1\0";

impl Gov for NoUpgradeGov {
    fn map_witness(&self, node: &WitnessNode) -> OlogFact {
        // Deterministic stand-in: SHA-256(domain || witness_digest || spec_hash).
        let mut h = Sha256::new();
        h.update(INSTANCE_STANDIN_DOMAIN);
        h.update(node.digest.0);
        h.update(node.task_spec_hash);
        let instance_digest: [u8; 32] = h.finalize().into();
        OlogFact {
            task_spec_hash: node.task_spec_hash,
            instance_digest,
            rung: node.rung, // carried through — NOT upgraded
            tier: node.tier, // carried through — NOT upgraded
        }
    }
}

// ── P2.2: reading admitted witnesses (the source `Gov` folds over) ───────────

/// A read-only source of admitted witnesses + their lineage — the contract
/// [`Gov`] folds over to accumulate facts. Defined in OSS so the witness→olog
/// mapping stays independently **recomputable**: an archive (e.g. merge-gate's
/// content-addressed store) implements this trait, and any relying party can
/// re-derive the same facts from the same source. (P2.2.)
///
/// Returns owned `Vec`s for the scaffold; a streaming variant for very large
/// archives is a later refinement.
pub trait WitnessSource {
    /// The admitted witness nodes, in a deterministic order.
    fn admitted(&self) -> Vec<WitnessNode>;
    /// The admitted lineage edges (parent → child) among those nodes.
    fn lineage(&self) -> Vec<LineageEdge>;
}

/// Fold `gov` over every admitted witness, producing one [`OlogFact`] per node
/// (in source order) — the accumulation step where proof-of-work becomes a
/// categorical fact. By the no-upgrade invariant, every produced fact carries its
/// witness's rung/tier unchanged.
pub fn accumulate<G: Gov, S: WitnessSource>(gov: &G, source: &S) -> Vec<OlogFact> {
    source
        .admitted()
        .iter()
        .map(|n| gov.map_witness(n))
        .collect()
}

/// An in-memory [`WitnessSource`] for tests and the Fake-backed demo path (no
/// real archive). Mirrors the `FakeFacilitator` honesty pattern — clearly not the
/// production store; the real one is merge-gate's archive (P2.2 step 4).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FakeWitnessSource {
    pub nodes: Vec<WitnessNode>,
    pub edges: Vec<LineageEdge>,
}

impl FakeWitnessSource {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an admitted node (builder style).
    pub fn with_node(mut self, n: WitnessNode) -> Self {
        self.nodes.push(n);
        self
    }

    /// Add a lineage edge (builder style).
    pub fn with_edge(mut self, e: LineageEdge) -> Self {
        self.edges.push(e);
        self
    }
}

impl WitnessSource for FakeWitnessSource {
    fn admitted(&self) -> Vec<WitnessNode> {
        self.nodes.clone()
    }
    fn lineage(&self) -> Vec<LineageEdge> {
        self.edges.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(rung: AssuranceRung, tier: Tier) -> WitnessNode {
        WitnessNode {
            digest: WitnessDigest([7u8; 32]),
            task_spec_hash: [9u8; 32],
            rung,
            tier,
            verdict: AdmissionVerdict::Admitted,
            parent: None,
        }
    }

    #[test]
    fn gov_never_upgrades_the_rung_or_tier() {
        // The load-bearing honesty invariant: trust in, trust out.
        let g = NoUpgradeGov;
        for &rung in &[
            AssuranceRung::SelfReported,
            AssuranceRung::OracleSigned,
            AssuranceRung::TeeAttested,
            AssuranceRung::MultiSourceDisputed,
            AssuranceRung::ZkUpperEnvelope,
        ] {
            for &tier in &[Tier::Proven, Tier::Modeled, Tier::Analogy] {
                let fact = g.map_witness(&node(rung, tier));
                assert_eq!(fact.rung, rung, "Gov must carry the rung through");
                assert_eq!(fact.tier, tier, "Gov must carry the tier through");
                assert!(fact.rung <= rung, "Gov must never UPGRADE the rung");
            }
        }
    }

    #[test]
    fn gov_is_deterministic() {
        let g = NoUpgradeGov;
        let n = node(AssuranceRung::TeeAttested, Tier::Modeled);
        assert_eq!(g.map_witness(&n), g.map_witness(&n));
    }

    #[test]
    fn distinct_witnesses_map_to_distinct_facts() {
        let g = NoUpgradeGov;
        let mut a = node(AssuranceRung::OracleSigned, Tier::Proven);
        let mut b = a.clone();
        a.digest = WitnessDigest([1u8; 32]);
        b.digest = WitnessDigest([2u8; 32]);
        assert_ne!(
            g.map_witness(&a).instance_digest,
            g.map_witness(&b).instance_digest
        );
    }

    #[test]
    fn fact_is_an_instance_of_the_claimed_spec() {
        let g = NoUpgradeGov;
        let n = node(AssuranceRung::ZkUpperEnvelope, Tier::Proven);
        assert_eq!(g.map_witness(&n).task_spec_hash, n.task_spec_hash);
    }

    #[test]
    fn accumulate_folds_gov_over_the_source_preserving_rung() {
        let mut a = node(AssuranceRung::OracleSigned, Tier::Modeled);
        let mut b = node(AssuranceRung::ZkUpperEnvelope, Tier::Proven);
        a.digest = WitnessDigest([1u8; 32]);
        b.digest = WitnessDigest([2u8; 32]);
        let src = FakeWitnessSource::new()
            .with_node(a.clone())
            .with_node(b.clone());
        let facts = accumulate(&NoUpgradeGov, &src);
        assert_eq!(facts.len(), 2, "one fact per admitted witness, in order");
        // No-upgrade carries through the accumulation, per node.
        assert_eq!(facts[0].rung, a.rung);
        assert_eq!(facts[1].rung, b.rung);
        assert_eq!(facts[0].tier, a.tier);
        // Distinct witnesses → distinct accumulated facts.
        assert_ne!(facts[0].instance_digest, facts[1].instance_digest);
    }

    #[test]
    fn empty_source_accumulates_to_nothing() {
        assert!(accumulate(&NoUpgradeGov, &FakeWitnessSource::new()).is_empty());
    }
}

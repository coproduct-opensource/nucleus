//! Fixture models for the recon ground truth checked in under `fixtures/recon/`.

use serde::Deserialize;
use std::fmt;
use std::path::Path;

/// Maturity lattice ranks. Trust of a composition is the MEET (weakest link);
/// the egglog `maturity` function uses `:merge (min old new)` to enforce it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Maturity {
    /// 0: absent edge, advisory-only gate.
    Unenforced = 0,
    /// 1: claimed in prose / unmerged PR.
    Stated = 1,
    /// 2: cited file:line evidence; no machine check on the claim itself.
    Attested = 2,
    /// 3: proptest parity.
    PropertyTested = 3,
    /// 4: golden-bytes pin, exhaustive parity, extraction-freshness gate.
    ParityPinned = 4,
    /// 5: Lean sorry-free in CI / Kani BMC.
    KernelChecked = 5,
}

impl Maturity {
    pub fn rank(self) -> i64 {
        self as i64
    }

    pub fn from_rank(rank: i64) -> Option<Self> {
        match rank {
            0 => Some(Self::Unenforced),
            1 => Some(Self::Stated),
            2 => Some(Self::Attested),
            3 => Some(Self::PropertyTested),
            4 => Some(Self::ParityPinned),
            5 => Some(Self::KernelChecked),
            _ => None,
        }
    }

    /// Rank assigned to a recon equivalence by its evidence kind.
    pub fn for_equivalence_kind(kind: &str) -> Self {
        match kind {
            "golden-bytes" | "exhaustive-parity" | "extraction-freshness" => Self::ParityPinned,
            "proptest-parity" => Self::PropertyTested,
            // A claimed identity that is not on main is only a statement.
            "reexport-identity" => Self::Stated,
            _ => Self::Stated,
        }
    }
}

impl fmt::Display for Maturity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Unenforced => "Unenforced",
            Self::Stated => "Stated",
            Self::Attested => "Attested",
            Self::PropertyTested => "PropertyTested",
            Self::ParityPinned => "ParityPinned",
            Self::KernelChecked => "KernelChecked",
        };
        write!(f, "{} {}", self.rank(), label)
    }
}

// ---------------------------------------------------------------------------
// fixtures/recon/gates.json
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct GatesFixture {
    #[serde(rename = "_provenance")]
    pub provenance: String,
    pub repos: Vec<RepoGates>,
}

#[derive(Deserialize)]
pub struct RepoGates {
    pub repo: String,
    pub workflows: Vec<Workflow>,
    pub required_checks: Vec<String>,
    pub notes: String,
}

#[derive(Deserialize)]
pub struct Workflow {
    pub file: String,
    pub name: String,
    pub jobs: Vec<String>,
}

// ---------------------------------------------------------------------------
// fixtures/recon/verification.json
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct VerificationFixture {
    #[serde(rename = "_provenance")]
    pub provenance: String,
    pub kani_harnesses: Vec<KaniHarness>,
    pub lean_libs: Vec<LeanLib>,
    pub sorry_files: Vec<SorryFile>,
    pub notes: String,
}

#[derive(Deserialize)]
pub struct KaniHarness {
    pub name: String,
    pub file: String,
    pub line: u64,
}

#[derive(Deserialize)]
pub struct LeanLib {
    pub lib: String,
    pub built_by_ci: String,
    pub sorry_free: bool,
}

#[derive(Deserialize)]
pub struct SorryFile {
    pub file: String,
    pub count: u64,
}

// ---------------------------------------------------------------------------
// fixtures/recon/equivalences.json
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct EquivalencesFixture {
    #[serde(rename = "_provenance")]
    pub provenance: String,
    pub equivalences: Vec<Equivalence>,
    pub notes: String,
}

#[derive(Deserialize)]
pub struct Equivalence {
    pub name: String,
    pub kind: String,
    pub lhs: String,
    pub rhs: String,
    pub fragment_condition: String,
    pub evidence: String,
}

// ---------------------------------------------------------------------------
// fixtures/recon/trust_path.json
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TrustPathFixture {
    #[serde(rename = "_provenance")]
    pub provenance: String,
    pub nodes: Vec<TrustNode>,
    pub edges: Vec<TrustEdge>,
    pub notes: String,
}

#[derive(Deserialize)]
pub struct TrustNode {
    pub id: String,
    pub repo: String,
    pub kind: String,
}

#[derive(Deserialize)]
pub struct TrustEdge {
    pub from: String,
    pub to: String,
    pub kind: String,
    pub evidence: String,
}

impl TrustEdge {
    /// An edge whose recon evidence starts with an ABSENT marker is a path
    /// discontinuity: the cited relationship does not exist in the source.
    pub fn is_absent(&self) -> bool {
        self.evidence.starts_with("ABSENT") || self.evidence.starts_with("CLAIMED-BUT-ABSENT")
    }

    pub fn maturity(&self) -> Maturity {
        if self.is_absent() {
            Maturity::Unenforced
        } else {
            Maturity::Attested
        }
    }
}

// ---------------------------------------------------------------------------
// loading
// ---------------------------------------------------------------------------

fn load<T: serde::de::DeserializeOwned>(dir: &Path, name: &str) -> anyhow::Result<T> {
    let path = dir.join(name);
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| anyhow::anyhow!("parsing {}: {e}", path.display()))
}

pub struct Fixtures {
    pub gates: GatesFixture,
    pub verification: VerificationFixture,
    pub equivalences: EquivalencesFixture,
    pub trust_path: TrustPathFixture,
    pub dir: std::path::PathBuf,
}

impl Fixtures {
    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        Ok(Self {
            gates: load(dir, "gates.json")?,
            verification: load(dir, "verification.json")?,
            equivalences: load(dir, "equivalences.json")?,
            trust_path: load(dir, "trust_path.json")?,
            dir: dir.to_path_buf(),
        })
    }

    /// Default fixture directory: `fixtures/recon` next to this crate.
    pub fn default_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/recon")
    }
}

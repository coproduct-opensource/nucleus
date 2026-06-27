//! The capability lattice — the product Heyting algebra of per-operation
//! permission levels. The PRIMARY Aeneas verification target (the Lean 4 proof
//! shows it is a distributive Heyting algebra). Moved into the kernel crate
//! (MVK M3 whole-core) so the entire Aeneas-verified surface lives in one crate
//! and the proof extraction stays single-crate. Re-exported at portcullis-core's
//! root for backward compat.

use crate::CapabilityLevel;

/// Capability lattice for tool permissions.
///
/// Product of 12 capability dimensions, each a [`CapabilityLevel`].
/// Meet, join, and leq are computed pointwise.
///
/// This is the primary verification target for the Aeneas pipeline.
/// The Lean 4 proof shows this forms a distributive Heyting algebra
/// (as a product of Heyting algebras).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub struct CapabilityLattice {
    #[cfg_attr(feature = "serde", serde(default))]
    pub read_files: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub write_files: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub edit_files: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub run_bash: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub glob_search: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub grep_search: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub web_search: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub web_fetch: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub git_commit: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub git_push: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub create_pr: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub manage_pods: CapabilityLevel,
    #[cfg_attr(feature = "serde", serde(default))]
    pub spawn_agent: CapabilityLevel,
}

impl Default for CapabilityLattice {
    fn default() -> Self {
        Self {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::LowRisk,
            edit_files: CapabilityLevel::LowRisk,
            run_bash: CapabilityLevel::Never,
            glob_search: CapabilityLevel::Always,
            grep_search: CapabilityLevel::Always,
            web_search: CapabilityLevel::LowRisk,
            web_fetch: CapabilityLevel::LowRisk,
            git_commit: CapabilityLevel::LowRisk,
            git_push: CapabilityLevel::Never,
            create_pr: CapabilityLevel::LowRisk,
            manage_pods: CapabilityLevel::Never,
            spawn_agent: CapabilityLevel::LowRisk,
        }
    }
}

impl CapabilityLattice {
    /// Bottom element — all dimensions Never.
    pub fn bottom() -> Self {
        Self {
            read_files: CapabilityLevel::Never,
            write_files: CapabilityLevel::Never,
            edit_files: CapabilityLevel::Never,
            run_bash: CapabilityLevel::Never,
            glob_search: CapabilityLevel::Never,
            grep_search: CapabilityLevel::Never,
            web_search: CapabilityLevel::Never,
            web_fetch: CapabilityLevel::Never,
            git_commit: CapabilityLevel::Never,
            git_push: CapabilityLevel::Never,
            create_pr: CapabilityLevel::Never,
            manage_pods: CapabilityLevel::Never,
            spawn_agent: CapabilityLevel::Never,
        }
    }

    /// Top element — all dimensions Always.
    pub fn top() -> Self {
        Self {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::Always,
            edit_files: CapabilityLevel::Always,
            run_bash: CapabilityLevel::Always,
            glob_search: CapabilityLevel::Always,
            grep_search: CapabilityLevel::Always,
            web_search: CapabilityLevel::Always,
            web_fetch: CapabilityLevel::Always,
            git_commit: CapabilityLevel::Always,
            git_push: CapabilityLevel::Always,
            create_pr: CapabilityLevel::Always,
            manage_pods: CapabilityLevel::Always,
            spawn_agent: CapabilityLevel::Always,
        }
    }

    /// Meet operation (greatest lower bound): pointwise min.
    pub fn meet(&self, other: &Self) -> Self {
        Self {
            read_files: self.read_files.meet(other.read_files),
            write_files: self.write_files.meet(other.write_files),
            edit_files: self.edit_files.meet(other.edit_files),
            run_bash: self.run_bash.meet(other.run_bash),
            glob_search: self.glob_search.meet(other.glob_search),
            grep_search: self.grep_search.meet(other.grep_search),
            web_search: self.web_search.meet(other.web_search),
            web_fetch: self.web_fetch.meet(other.web_fetch),
            git_commit: self.git_commit.meet(other.git_commit),
            git_push: self.git_push.meet(other.git_push),
            create_pr: self.create_pr.meet(other.create_pr),
            manage_pods: self.manage_pods.meet(other.manage_pods),
            spawn_agent: self.spawn_agent.meet(other.spawn_agent),
        }
    }

    /// Join operation (least upper bound): pointwise max.
    pub fn join(&self, other: &Self) -> Self {
        Self {
            read_files: self.read_files.join(other.read_files),
            write_files: self.write_files.join(other.write_files),
            edit_files: self.edit_files.join(other.edit_files),
            run_bash: self.run_bash.join(other.run_bash),
            glob_search: self.glob_search.join(other.glob_search),
            grep_search: self.grep_search.join(other.grep_search),
            web_search: self.web_search.join(other.web_search),
            web_fetch: self.web_fetch.join(other.web_fetch),
            git_commit: self.git_commit.join(other.git_commit),
            git_push: self.git_push.join(other.git_push),
            create_pr: self.create_pr.join(other.create_pr),
            manage_pods: self.manage_pods.join(other.manage_pods),
            spawn_agent: self.spawn_agent.join(other.spawn_agent),
        }
    }

    /// Partial order check: pointwise ≤.
    pub fn leq(&self, other: &Self) -> bool {
        self.read_files.leq(other.read_files)
            && self.write_files.leq(other.write_files)
            && self.edit_files.leq(other.edit_files)
            && self.run_bash.leq(other.run_bash)
            && self.glob_search.leq(other.glob_search)
            && self.grep_search.leq(other.grep_search)
            && self.web_search.leq(other.web_search)
            && self.web_fetch.leq(other.web_fetch)
            && self.git_commit.leq(other.git_commit)
            && self.git_push.leq(other.git_push)
            && self.create_pr.leq(other.create_pr)
            && self.manage_pods.leq(other.manage_pods)
            && self.spawn_agent.leq(other.spawn_agent)
    }

    /// Read-only projection: meet with the read-only ceiling.
    ///
    /// Preserves read capabilities (read_files, glob_search, grep_search,
    /// web_search, web_fetch) at their current level while dropping all
    /// write/execute/exfil capabilities to Never.
    ///
    /// This is the lockdown lattice: `current ⊓ read_only_ceiling`.
    /// By the HeytingAlgebra deflationary property, the result ≤ current.
    pub fn read_only(&self) -> Self {
        self.meet(&Self {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::Never,
            edit_files: CapabilityLevel::Never,
            run_bash: CapabilityLevel::Never,
            glob_search: CapabilityLevel::Always,
            grep_search: CapabilityLevel::Always,
            web_search: CapabilityLevel::Always,
            web_fetch: CapabilityLevel::Always,
            git_commit: CapabilityLevel::Never,
            git_push: CapabilityLevel::Never,
            create_pr: CapabilityLevel::Never,
            manage_pods: CapabilityLevel::Never,
            spawn_agent: CapabilityLevel::Never,
        })
    }

    /// Heyting implication: pointwise →.
    pub fn implies(&self, other: &Self) -> Self {
        Self {
            read_files: self.read_files.implies(other.read_files),
            write_files: self.write_files.implies(other.write_files),
            edit_files: self.edit_files.implies(other.edit_files),
            run_bash: self.run_bash.implies(other.run_bash),
            glob_search: self.glob_search.implies(other.glob_search),
            grep_search: self.grep_search.implies(other.grep_search),
            web_search: self.web_search.implies(other.web_search),
            web_fetch: self.web_fetch.implies(other.web_fetch),
            git_commit: self.git_commit.implies(other.git_commit),
            git_push: self.git_push.implies(other.git_push),
            create_pr: self.create_pr.implies(other.create_pr),
            manage_pods: self.manage_pods.implies(other.manage_pods),
            spawn_agent: self.spawn_agent.implies(other.spawn_agent),
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Named capability profiles (#1214)
    // ═══════════════════════════════════════════════════════════════════

    /// Read-only profile: read + glob + grep. No writes, no network, no shell.
    ///
    /// Runtime equivalent of the compile-time `capability_traits::ReadOnly`
    /// marker set. Use with `production_effects()` for agents that should only
    /// read and search the workspace.
    pub fn for_read_only() -> Self {
        Self {
            read_files: CapabilityLevel::Always,
            glob_search: CapabilityLevel::Always,
            grep_search: CapabilityLevel::Always,
            ..Self::bottom()
        }
    }

    /// Research profile: read + glob + grep + web fetch + web search.
    /// No writes, no shell, no git.
    ///
    /// For agents that need to search the codebase and fetch external
    /// documentation but must not modify any state.
    pub fn for_research() -> Self {
        Self {
            read_files: CapabilityLevel::Always,
            glob_search: CapabilityLevel::Always,
            grep_search: CapabilityLevel::Always,
            web_search: CapabilityLevel::Always,
            web_fetch: CapabilityLevel::Always,
            ..Self::bottom()
        }
    }

    /// Codegen profile: read + write + edit + bash + glob + grep + git commit.
    /// No network, no push.
    ///
    /// Runtime equivalent of `capability_traits::Codegen`. For agents
    /// that generate, edit, and test code locally but cannot publish or
    /// communicate externally.
    pub fn for_codegen() -> Self {
        Self {
            read_files: CapabilityLevel::Always,
            write_files: CapabilityLevel::Always,
            edit_files: CapabilityLevel::Always,
            run_bash: CapabilityLevel::Always,
            glob_search: CapabilityLevel::Always,
            grep_search: CapabilityLevel::Always,
            git_commit: CapabilityLevel::Always,
            ..Self::bottom()
        }
    }

    /// Review profile: read + glob + grep + web + git commit + push + create_pr.
    ///
    /// Runtime equivalent of `capability_traits::CodeReview` plus git
    /// publish capabilities. For agents that review code, fetch references,
    /// and submit PRs but do not write workspace files or run shell commands.
    pub fn for_review() -> Self {
        Self {
            read_files: CapabilityLevel::Always,
            glob_search: CapabilityLevel::Always,
            grep_search: CapabilityLevel::Always,
            web_search: CapabilityLevel::Always,
            web_fetch: CapabilityLevel::Always,
            git_commit: CapabilityLevel::Always,
            git_push: CapabilityLevel::Always,
            create_pr: CapabilityLevel::Always,
            ..Self::bottom()
        }
    }

    /// Returns a builder for composing a least-privilege lattice.
    ///
    /// Unset fields default to `Never` — the secure default. Callers
    /// explicitly grant only the capabilities they need.
    ///
    /// ```rust
    /// use nucleus_ifc_kernel::{CapabilityLattice, CapabilityLevel};
    ///
    /// let policy = CapabilityLattice::builder()
    ///     .read_files(CapabilityLevel::Always)
    ///     .web_fetch(CapabilityLevel::LowRisk)
    ///     .build();
    ///
    /// assert_eq!(policy.read_files, CapabilityLevel::Always);
    /// assert_eq!(policy.web_fetch, CapabilityLevel::LowRisk);
    /// assert_eq!(policy.run_bash, CapabilityLevel::Never); // unset → Never
    /// ```
    pub fn builder() -> CapabilityLatticeBuilder {
        CapabilityLatticeBuilder(Self::bottom())
    }
}

/// Builder for [`CapabilityLattice`] with secure defaults (#1214).
///
/// All fields start at `Never`. Each setter raises a single capability
/// dimension, enforcing least-privilege by construction.
pub struct CapabilityLatticeBuilder(CapabilityLattice);

impl CapabilityLatticeBuilder {
    /// Set the `read_files` capability level.
    pub fn read_files(mut self, level: CapabilityLevel) -> Self {
        self.0.read_files = level;
        self
    }
    /// Set the `write_files` capability level.
    pub fn write_files(mut self, level: CapabilityLevel) -> Self {
        self.0.write_files = level;
        self
    }
    /// Set the `edit_files` capability level.
    pub fn edit_files(mut self, level: CapabilityLevel) -> Self {
        self.0.edit_files = level;
        self
    }
    /// Set the `run_bash` capability level.
    pub fn run_bash(mut self, level: CapabilityLevel) -> Self {
        self.0.run_bash = level;
        self
    }
    /// Set the `glob_search` capability level.
    pub fn glob_search(mut self, level: CapabilityLevel) -> Self {
        self.0.glob_search = level;
        self
    }
    /// Set the `grep_search` capability level.
    pub fn grep_search(mut self, level: CapabilityLevel) -> Self {
        self.0.grep_search = level;
        self
    }
    /// Set the `web_search` capability level.
    pub fn web_search(mut self, level: CapabilityLevel) -> Self {
        self.0.web_search = level;
        self
    }
    /// Set the `web_fetch` capability level.
    pub fn web_fetch(mut self, level: CapabilityLevel) -> Self {
        self.0.web_fetch = level;
        self
    }
    /// Set the `git_commit` capability level.
    pub fn git_commit(mut self, level: CapabilityLevel) -> Self {
        self.0.git_commit = level;
        self
    }
    /// Set the `git_push` capability level.
    pub fn git_push(mut self, level: CapabilityLevel) -> Self {
        self.0.git_push = level;
        self
    }
    /// Set the `create_pr` capability level.
    pub fn create_pr(mut self, level: CapabilityLevel) -> Self {
        self.0.create_pr = level;
        self
    }
    /// Set the `manage_pods` capability level.
    pub fn manage_pods(mut self, level: CapabilityLevel) -> Self {
        self.0.manage_pods = level;
        self
    }
    /// Set the `spawn_agent` capability level.
    pub fn spawn_agent(mut self, level: CapabilityLevel) -> Self {
        self.0.spawn_agent = level;
        self
    }
    /// Consume the builder and return the lattice.
    pub fn build(self) -> CapabilityLattice {
        self.0
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// BTreeMap bridge — generic capability access (#1286)
// ═══════════════════════════════════════════════════════════════════════════

impl CapabilityLattice {
    /// All 13 capability dimension names.
    pub const DIMENSION_NAMES: [&'static str; 13] = [
        "read_files",
        "write_files",
        "edit_files",
        "run_bash",
        "glob_search",
        "grep_search",
        "web_search",
        "web_fetch",
        "git_commit",
        "git_push",
        "create_pr",
        "manage_pods",
        "spawn_agent",
    ];

    /// Get a capability level by string key.
    ///
    /// Returns `None` for unrecognized keys. Integrators who need custom
    /// dimensions should use the `BTreeMap` bridge.
    pub fn get(&self, key: &str) -> Option<CapabilityLevel> {
        match key {
            "read_files" => Some(self.read_files),
            "write_files" => Some(self.write_files),
            "edit_files" => Some(self.edit_files),
            "run_bash" => Some(self.run_bash),
            "glob_search" => Some(self.glob_search),
            "grep_search" => Some(self.grep_search),
            "web_search" => Some(self.web_search),
            "web_fetch" => Some(self.web_fetch),
            "git_commit" => Some(self.git_commit),
            "git_push" => Some(self.git_push),
            "create_pr" => Some(self.create_pr),
            "manage_pods" => Some(self.manage_pods),
            "spawn_agent" => Some(self.spawn_agent),
            _ => None,
        }
    }

    /// Set a capability level by string key. Returns `false` for unknown keys.
    pub fn set(&mut self, key: &str, level: CapabilityLevel) -> bool {
        match key {
            "read_files" => self.read_files = level,
            "write_files" => self.write_files = level,
            "edit_files" => self.edit_files = level,
            "run_bash" => self.run_bash = level,
            "glob_search" => self.glob_search = level,
            "grep_search" => self.grep_search = level,
            "web_search" => self.web_search = level,
            "web_fetch" => self.web_fetch = level,
            "git_commit" => self.git_commit = level,
            "git_push" => self.git_push = level,
            "create_pr" => self.create_pr = level,
            "manage_pods" => self.manage_pods = level,
            "spawn_agent" => self.spawn_agent = level,
            _ => return false,
        }
        true
    }

    /// Convert to a BTreeMap for generic/dynamic access.
    pub fn to_map(&self) -> std::collections::BTreeMap<&'static str, CapabilityLevel> {
        let mut m = std::collections::BTreeMap::new();
        for &name in &Self::DIMENSION_NAMES {
            if let Some(level) = self.get(name) {
                m.insert(name, level);
            }
        }
        m
    }

    /// Construct from a BTreeMap. Missing keys default to `Never`.
    pub fn from_map(map: &std::collections::BTreeMap<&str, CapabilityLevel>) -> Self {
        let mut lattice = Self::bottom();
        for (&key, &level) in map {
            lattice.set(key, level);
        }
        lattice
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Capability lens projections (#1149)
// ═══════════════════════════════════════════════════════════════════════════

/// A named group of capability dimensions for projection/injection.
///
/// Use with [`CapabilityLattice::project`] and [`CapabilityLattice::inject`]
/// to compose partial policies from different sources.
///
/// ```rust
/// use nucleus_ifc_kernel::{CapabilityLattice, DimGroup};
///
/// let reads_from_a = CapabilityLattice::for_research();
/// let writes_from_b = CapabilityLattice::for_codegen();
///
/// // Take reads from A, writes from B
/// let merged = CapabilityLattice::bottom()
///     .inject(&reads_from_a, &DimGroup::READS)
///     .inject(&writes_from_b, &DimGroup::WRITES);
///
/// assert_eq!(merged.read_files, reads_from_a.read_files);
/// assert_eq!(merged.write_files, writes_from_b.write_files);
/// ```
pub struct DimGroup {
    dims: &'static [&'static str],
}

impl DimGroup {
    /// Read-oriented dimensions.
    pub const READS: DimGroup = DimGroup {
        dims: &["read_files", "glob_search", "grep_search"],
    };

    /// Write-oriented dimensions.
    pub const WRITES: DimGroup = DimGroup {
        dims: &["write_files", "edit_files"],
    };

    /// Network-oriented dimensions.
    pub const NETWORK: DimGroup = DimGroup {
        dims: &["web_search", "web_fetch"],
    };

    /// Execution dimensions.
    pub const EXECUTION: DimGroup = DimGroup {
        dims: &["run_bash"],
    };

    /// Git/publish dimensions.
    pub const GIT: DimGroup = DimGroup {
        dims: &["git_commit", "git_push", "create_pr"],
    };

    /// Infrastructure/agent dimensions.
    pub const INFRA: DimGroup = DimGroup {
        dims: &["manage_pods", "spawn_agent"],
    };

    /// All dimensions.
    pub const ALL: DimGroup = DimGroup {
        dims: &CapabilityLattice::DIMENSION_NAMES,
    };

    /// The dimension names in this group.
    pub fn dims(&self) -> &[&'static str] {
        self.dims
    }
}

impl CapabilityLattice {
    /// Project this lattice onto a dimension group, zeroing all other dimensions.
    ///
    /// Returns a new lattice where only the dimensions in `group` retain
    /// their values; all others are `Never`.
    pub fn project(&self, group: &DimGroup) -> Self {
        let mut result = Self::bottom();
        for &dim in group.dims {
            if let Some(level) = self.get(dim) {
                result.set(dim, level);
            }
        }
        result
    }

    /// Inject dimensions from `source` into this lattice for the given group.
    ///
    /// Returns a new lattice where dimensions in `group` are taken from
    /// `source` and all other dimensions retain their current values.
    pub fn inject(mut self, source: &Self, group: &DimGroup) -> Self {
        for &dim in group.dims {
            if let Some(level) = source.get(dim) {
                self.set(dim, level);
            }
        }
        self
    }

    /// Merge dimensions from another lattice using lattice join (max per dimension).
    ///
    /// Only the dimensions in `group` are merged; others are unchanged.
    pub fn merge_from(mut self, other: &Self, group: &DimGroup) -> Self {
        for &dim in group.dims {
            if let (Some(mine), Some(theirs)) = (self.get(dim), other.get(dim)) {
                self.set(dim, mine.join(theirs));
            }
        }
        self
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Operation enum — the 12 core operations (Aeneas-translatable)
// ═══════════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════════
// Exposure types — the uninhabitable state detector (Aeneas-translatable)
// ═══════════════════════════════════════════════════════════════════════════

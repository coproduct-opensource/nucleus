//! Semantic effect catalog: the authority vocabulary a person reads.
//!
//! The 13-dimension [`CapabilityLattice`] is the verified core and the unit
//! the kernel enforces. It is not the unit a person should have to reason
//! about: "web_fetch: low_risk" says nothing about *what* is fetched, while
//! "read CI logs" does. An **effect** is that human-sized unit — a named,
//! titled, risk-graded authority (`github/read-ci-logs`) that *lowers* to
//! core dimensions, sink classes and hosts, and carries reverse indexes
//! (`matches`) so an observed tool call, command or HTTP request can be
//! attributed back to the effect that authorised it.
//!
//! Effects are **data**: TOML files with a `[plugin]` header and `[[effect]]`
//! entries. The built-in catalog (`crates/portcullis/effects/*.toml`) is
//! embedded at compile time; a repository adds its own under
//! `.nucleus/effects/`. Adding `github/merge-pr` is a TOML edit, not Rust.
//!
//! Lowering is *monotone and fail-closed*: it starts from every dimension at
//! `Never` and raises only the operations the named effects list, so a set of
//! effects can never lower to more authority than the union of its members,
//! and an unknown effect is an error rather than a silent no-op.
//!
//! This module does not change the verified core. It is the vocabulary layer
//! the task compiler (`nucleus-task-compiler`) and the grant renderer
//! (`task_grant`) speak; the kernel keeps enforcing the lattice it lowers to.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{
    classify_operation, CapabilityLattice, CapabilityLevel, ExposureSet, Operation, SinkClass,
};

/// The built-in catalog, one `(plugin name, TOML source)` per file under
/// `crates/portcullis/effects/`. Embedded so a binary never depends on a
/// checkout to know what "read CI logs" means.
pub const BUILTIN_CATALOG: &[(&str, &str)] = &[
    ("fs", include_str!("../effects/fs.toml")),
    ("shell", include_str!("../effects/shell.toml")),
    ("git", include_str!("../effects/git.toml")),
    ("web", include_str!("../effects/web.toml")),
    ("github", include_str!("../effects/github.toml")),
    ("aws", include_str!("../effects/aws.toml")),
    ("kubernetes", include_str!("../effects/kubernetes.toml")),
    ("database", include_str!("../effects/database.toml")),
    ("slack", include_str!("../effects/slack.toml")),
];

/// A fully-qualified effect name: `<plugin>/<id>`, both segments
/// `[a-z0-9-]+`. This is the key a grant carries and a person sees.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EffectId {
    /// The plugin (catalog file) that declares the effect.
    pub plugin: String,
    /// The effect's id within its plugin.
    pub id: String,
}

impl EffectId {
    /// Build an id from validated segments.
    pub fn new(plugin: &str, id: &str) -> Result<Self, EffectCatalogError> {
        if !is_segment(plugin) || !is_segment(id) {
            return Err(EffectCatalogError::InvalidId(format!("{plugin}/{id}")));
        }
        Ok(Self {
            plugin: plugin.to_string(),
            id: id.to_string(),
        })
    }
}

fn is_segment(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

impl fmt::Display for EffectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.plugin, self.id)
    }
}

impl FromStr for EffectId {
    type Err = EffectCatalogError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (plugin, id) = s
            .split_once('/')
            .ok_or_else(|| EffectCatalogError::InvalidId(s.to_string()))?;
        Self::new(plugin, id)
    }
}

impl TryFrom<String> for EffectId {
    type Error = EffectCatalogError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<EffectId> for String {
    fn from(id: EffectId) -> Self {
        id.to_string()
    }
}

/// How much an effect can change the world, ordered from least to most.
///
/// The order is what the renderer sorts by and what a later milestone's
/// escalation proposal compares against; it is not a lattice level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectRisk {
    /// Observes only (files, history, logs, registries).
    Read,
    /// Changes the workspace or local repository state.
    WriteLocal,
    /// Runs the project's own toolchain.
    Execute,
    /// Publishes something others can see (a branch, a comment, a PR).
    Publish,
    /// Changes remote state that is not simply undone (a merge).
    MutateRemote,
    /// Destroys data.
    Destructive,
}

impl EffectRisk {
    /// Stable lowercase name, matching the TOML spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::WriteLocal => "write_local",
            Self::Execute => "execute",
            Self::Publish => "publish",
            Self::MutateRemote => "mutate_remote",
            Self::Destructive => "destructive",
        }
    }
}

/// One HTTP shape an effect covers: the host→meaning table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpMatch {
    /// HTTP method, upper case.
    pub method: String,
    /// Exact host or `*.example` wildcard, as in the egress policy.
    pub host: String,
    /// Path glob: `*` matches any run of characters.
    pub path: String,
}

/// A declared effect after validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectSpec {
    /// Fully-qualified name.
    pub id: EffectId,
    /// The line a person reads ("Read CI logs and workflow runs").
    pub title: String,
    /// Risk grade, for ordering and for escalation proposals.
    pub risk: EffectRisk,
    /// The level the listed operations are raised to when lowered.
    pub level: CapabilityLevel,
    /// Core operations the effect needs.
    pub operations: Vec<Operation>,
    /// Sink classes the effect writes to.
    pub sinks: Vec<SinkClass>,
    /// Hosts the effect needs egress to.
    pub hosts: Vec<String>,
    /// MCP tool names that exercise this effect.
    pub mcp_tools: Vec<String>,
    /// Shell command prefixes that exercise this effect.
    pub commands: Vec<String>,
    /// HTTP shapes that exercise this effect.
    pub http: Vec<HttpMatch>,
}

/// What a set of effects lowers to: the raw material for a
/// [`crate::PermissionLattice`] plus the egress and command vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweredAuthority {
    /// Core dimensions, every unlisted operation at `Never`.
    pub capabilities: CapabilityLattice,
    /// Union of the effects' sink classes (deduplicated, catalog order).
    pub sinks: Vec<SinkClass>,
    /// Union of the effects' hosts.
    pub hosts: BTreeSet<String>,
    /// Union of the effects' command prefixes.
    pub commands: BTreeSet<String>,
    /// Union of the effects' MCP tool names.
    pub mcp_tools: BTreeSet<String>,
    /// The exposure legs the lowered operations contribute.
    pub exposure: ExposureSet,
}

/// Errors from loading, validating or lowering a catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectCatalogError {
    /// Malformed `<plugin>/<id>`.
    InvalidId(String),
    /// TOML did not parse.
    Parse {
        /// Where the TOML came from.
        source: String,
        /// The parser's message.
        detail: String,
    },
    /// An effect named an unknown operation, sink or host pattern.
    UnknownVocabulary {
        /// The effect.
        effect: String,
        /// What was unknown.
        detail: String,
    },
    /// The same id was declared twice.
    Duplicate(String),
    /// An effect is not in the catalog.
    Unknown(String),
    /// A declared effect failed a consistency check.
    Invalid {
        /// The effect.
        effect: String,
        /// Which check.
        detail: String,
    },
    /// Reading a catalog directory failed.
    Io(String),
}

impl fmt::Display for EffectCatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidId(s) => write!(
                f,
                "invalid effect id '{s}': expected <plugin>/<id>, each [a-z0-9-]+"
            ),
            Self::Parse { source, detail } => write!(f, "effect catalog {source}: {detail}"),
            Self::UnknownVocabulary { effect, detail } => {
                write!(f, "effect {effect}: {detail}")
            }
            Self::Duplicate(id) => write!(f, "effect {id} declared twice"),
            Self::Unknown(id) => write!(f, "unknown effect {id}"),
            Self::Invalid { effect, detail } => write!(f, "effect {effect} is invalid: {detail}"),
            Self::Io(s) => write!(f, "effect catalog: {s}"),
        }
    }
}

impl std::error::Error for EffectCatalogError {}

// ── TOML shape ────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogFile {
    plugin: PluginHeader,
    #[serde(default, rename = "effect")]
    effects: Vec<EffectEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginHeader {
    name: String,
    #[allow(dead_code)]
    version: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EffectEntry {
    id: String,
    title: String,
    risk: EffectRisk,
    #[serde(default = "default_level")]
    level: CapabilityLevel,
    #[serde(default)]
    lowers: Lowers,
    #[serde(default)]
    matches: Matches,
}

fn default_level() -> CapabilityLevel {
    CapabilityLevel::LowRisk
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lowers {
    #[serde(default)]
    operations: Vec<String>,
    #[serde(default)]
    sinks: Vec<SinkClass>,
    #[serde(default)]
    hosts: Vec<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Matches {
    #[serde(default)]
    mcp_tools: Vec<String>,
    #[serde(default)]
    commands: Vec<String>,
    #[serde(default)]
    http: Vec<HttpMatch>,
}

// ── Catalog ───────────────────────────────────────────────────────────

/// The loaded, validated set of effects with reverse indexes.
#[derive(Debug, Clone, Default)]
pub struct EffectCatalog {
    effects: BTreeMap<EffectId, EffectSpec>,
}

impl EffectCatalog {
    /// An empty catalog.
    pub fn empty() -> Self {
        Self::default()
    }

    /// The built-in catalog. Validated on every construction so a broken
    /// built-in file is a test failure, never a silently narrower catalog.
    pub fn builtin() -> Result<Self, EffectCatalogError> {
        let mut catalog = Self::empty();
        for (name, content) in BUILTIN_CATALOG {
            catalog.load_toml(content, &format!("builtin:{name}"))?;
        }
        catalog.validate()?;
        Ok(catalog)
    }

    /// Merge one TOML catalog. `source` names it in errors.
    pub fn load_toml(&mut self, content: &str, source: &str) -> Result<(), EffectCatalogError> {
        let file: CatalogFile = toml::from_str(content).map_err(|e| EffectCatalogError::Parse {
            source: source.to_string(),
            detail: e.to_string(),
        })?;
        if !is_segment(&file.plugin.name) {
            return Err(EffectCatalogError::InvalidId(format!(
                "{}/ (plugin name in {source})",
                file.plugin.name
            )));
        }
        for entry in file.effects {
            let id = EffectId::new(&file.plugin.name, &entry.id)?;
            let mut operations = Vec::with_capacity(entry.lowers.operations.len());
            for op in &entry.lowers.operations {
                let parsed = Operation::try_from(op.as_str()).map_err(|_| {
                    EffectCatalogError::UnknownVocabulary {
                        effect: id.to_string(),
                        detail: format!("unknown operation '{op}'"),
                    }
                })?;
                operations.push(parsed);
            }
            for host in &entry.lowers.hosts {
                if !is_host_pattern(host) {
                    return Err(EffectCatalogError::UnknownVocabulary {
                        effect: id.to_string(),
                        detail: format!("'{host}' is not a host pattern"),
                    });
                }
            }
            let spec = EffectSpec {
                id: id.clone(),
                title: entry.title,
                risk: entry.risk,
                level: entry.level,
                operations,
                sinks: entry.lowers.sinks,
                hosts: entry.lowers.hosts,
                mcp_tools: entry.matches.mcp_tools,
                commands: entry.matches.commands,
                http: entry.matches.http,
            };
            if self.effects.insert(id.clone(), spec).is_some() {
                return Err(EffectCatalogError::Duplicate(id.to_string()));
            }
        }
        Ok(())
    }

    /// Merge every `*.toml` in `dir`, in name order. A missing directory
    /// is not an error: most repositories declare no effects of their own.
    pub fn load_from_dir(&mut self, dir: &Path) -> Result<(), EffectCatalogError> {
        if !dir.is_dir() {
            return Ok(());
        }
        let mut paths: Vec<_> = std::fs::read_dir(dir)
            .map_err(|e| EffectCatalogError::Io(format!("{}: {e}", dir.display())))?
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .collect();
        paths.sort();
        for path in paths {
            let content = std::fs::read_to_string(&path)
                .map_err(|e| EffectCatalogError::Io(format!("{}: {e}", path.display())))?;
            self.load_toml(&content, &path.display().to_string())?;
        }
        self.validate()
    }

    /// Every consistency rule an effect must satisfy:
    /// - it lowers to at least one operation (an effect that grants nothing
    ///   would be a phantom line in a grant);
    /// - every `http` host is also a lowered host (the table cannot describe
    ///   traffic the effect does not allow);
    /// - every listed sink is one some listed operation can produce.
    pub fn validate(&self) -> Result<(), EffectCatalogError> {
        for (id, spec) in &self.effects {
            if spec.operations.is_empty() {
                return Err(EffectCatalogError::Invalid {
                    effect: id.to_string(),
                    detail: "lowers to no operation".into(),
                });
            }
            for h in &spec.http {
                if !spec
                    .hosts
                    .iter()
                    .any(|allowed| host_matches(allowed, &h.host))
                {
                    return Err(EffectCatalogError::Invalid {
                        effect: id.to_string(),
                        detail: format!("http host '{}' is not among lowers.hosts", h.host),
                    });
                }
            }
            if !spec.hosts.is_empty()
                && !spec.operations.iter().any(|op| {
                    matches!(
                        op,
                        Operation::WebFetch
                            | Operation::GitPush
                            | Operation::CreatePr
                            | Operation::RunBash
                    )
                })
            {
                return Err(EffectCatalogError::Invalid {
                    effect: id.to_string(),
                    detail: "names hosts but lowers to no network-capable operation".into(),
                });
            }
        }
        Ok(())
    }

    /// Look up one effect.
    pub fn get(&self, id: &EffectId) -> Option<&EffectSpec> {
        self.effects.get(id)
    }

    /// Every effect, in id order.
    pub fn iter(&self) -> impl Iterator<Item = &EffectSpec> {
        self.effects.values()
    }

    /// Number of effects.
    pub fn len(&self) -> usize {
        self.effects.len()
    }

    /// Whether the catalog is empty.
    pub fn is_empty(&self) -> bool {
        self.effects.is_empty()
    }

    /// Effects whose lowered hosts admit `host`.
    pub fn effects_for_host(&self, host: &str) -> Vec<&EffectSpec> {
        self.iter()
            .filter(|e| e.hosts.iter().any(|p| host_matches(p, host)))
            .collect()
    }

    /// Effects whose command prefixes cover `command` (first-word aware:
    /// `cargo test` matches `cargo test -p x`, not `cargo testing`).
    pub fn effects_for_command(&self, command: &str) -> Vec<&EffectSpec> {
        let cmd = command.trim();
        self.iter()
            .filter(|e| e.commands.iter().any(|p| command_matches(p, cmd)))
            .collect()
    }

    /// Effects that name `tool`, or whose name `tool` ends with after an
    /// `mcp__<server>__` prefix.
    pub fn effects_for_tool(&self, tool: &str) -> Vec<&EffectSpec> {
        let bare = tool.rsplit("__").next().unwrap_or(tool);
        self.iter()
            .filter(|e| e.mcp_tools.iter().any(|t| t == tool || t == bare))
            .collect()
    }

    /// Effects that lower to `op`.
    pub fn effects_for_operation(&self, op: Operation) -> Vec<&EffectSpec> {
        self.iter().filter(|e| e.operations.contains(&op)).collect()
    }

    /// Lower a set of effects. Starts from every dimension at `Never` and
    /// raises only what the effects list, so the result is exactly the union
    /// of the members and nothing else. Unknown ids are errors.
    pub fn lower(&self, ids: &BTreeSet<EffectId>) -> Result<LoweredAuthority, EffectCatalogError> {
        let mut capabilities = all_never();
        let mut sinks: Vec<SinkClass> = Vec::new();
        let mut hosts = BTreeSet::new();
        let mut commands = BTreeSet::new();
        let mut mcp_tools = BTreeSet::new();
        let mut exposure = ExposureSet::empty();

        for id in ids {
            let spec = self
                .get(id)
                .ok_or_else(|| EffectCatalogError::Unknown(id.to_string()))?;
            for &op in &spec.operations {
                raise(&mut capabilities, op, spec.level);
                if let Some(label) = classify_operation(op) {
                    exposure = exposure.union(&ExposureSet::singleton(label));
                }
            }
            for sink in &spec.sinks {
                if !sinks.contains(sink) {
                    sinks.push(*sink);
                }
            }
            hosts.extend(spec.hosts.iter().cloned());
            commands.extend(spec.commands.iter().cloned());
            mcp_tools.extend(spec.mcp_tools.iter().cloned());
        }

        Ok(LoweredAuthority {
            capabilities,
            sinks,
            hosts,
            commands,
            mcp_tools,
            exposure,
        })
    }
}

/// Every core dimension at `Never`; the lowering's starting point.
///
/// Built from [`CapabilityLattice::restrictive`] so this module adds no
/// `cfg(kani)` site of its own: `restrictive` leaves the three read
/// dimensions at `Always`, which the lowering must earn like any other.
fn all_never() -> CapabilityLattice {
    let mut caps = CapabilityLattice::restrictive();
    caps.read_files = CapabilityLevel::Never;
    caps.glob_search = CapabilityLevel::Never;
    caps.grep_search = CapabilityLevel::Never;
    caps
}

/// Raise one dimension to at least `level` (never lowers).
pub fn raise(caps: &mut CapabilityLattice, op: Operation, level: CapabilityLevel) {
    let slot = match op {
        Operation::ReadFiles => &mut caps.read_files,
        Operation::WriteFiles => &mut caps.write_files,
        Operation::EditFiles => &mut caps.edit_files,
        Operation::RunBash => &mut caps.run_bash,
        Operation::GlobSearch => &mut caps.glob_search,
        Operation::GrepSearch => &mut caps.grep_search,
        Operation::WebSearch => &mut caps.web_search,
        Operation::WebFetch => &mut caps.web_fetch,
        Operation::GitCommit => &mut caps.git_commit,
        Operation::GitPush => &mut caps.git_push,
        Operation::CreatePr => &mut caps.create_pr,
        Operation::ManagePods => &mut caps.manage_pods,
        Operation::SpawnAgent => &mut caps.spawn_agent,
    };
    if *slot < level {
        *slot = level;
    }
}

/// A host pattern is a dot-separated sequence of labels in which a label may
/// be the single character `*`.
///
/// `api.github.com`, `*.amazonaws.com`, `logs.*.amazonaws.com`. A `*` is a
/// whole label or nothing: `*foo.example` and `fo*o.example` are rejected, so
/// a pattern can never match a fragment of a name.
fn is_host_pattern(s: &str) -> bool {
    if s.is_empty() || s.starts_with('.') || s.ends_with('.') {
        return false;
    }
    s.split('.').all(|label| {
        !label.is_empty()
            && (label == "*"
                || label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'))
    })
}

/// Does `pattern` match `host`?
///
/// A `*` label matches **one or more** whole labels, which is what
/// `*.amazonaws.com` has always meant here (it matches
/// `bucket.s3.amazonaws.com`, not only `s3.amazonaws.com`). Allowing that same
/// `*` in the middle — `logs.*.amazonaws.com` — is what lets a cloud pack name
/// one regional service apart from another.
///
/// It is worth saying why that mattered enough to generalise a matcher the
/// egress gate also uses. With leading-`*.` only, every AWS effect had to
/// claim `*.amazonaws.com`, and an effect with a host list and no
/// discriminating HTTP shape vouches for its hosts — so a grant of "list cloud
/// resources" admitted a POST to `iam.amazonaws.com`, which is the one call
/// that can rewrite the boundary itself. The pack's own conformance test
/// caught it. A basis vector you cannot state precisely is not a basis vector.
///
/// The anchors are the safety property, and they are what the tests pin:
/// matching is over whole labels from both ends, so `*.amazonaws.com` admits
/// neither `evil-amazonaws.com` (no label boundary before `amazonaws`) nor
/// `amazonaws.com.evil.example` (the pattern must reach the end), and a `*`
/// never matches zero labels, so `*.amazonaws.com` does not admit the bare
/// `amazonaws.com`.
#[must_use]
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();
    let pattern = pattern.trim().to_ascii_lowercase();
    let h: Vec<&str> = host.split('.').collect();
    let p: Vec<&str> = pattern.split('.').collect();
    labels_match(&p, &h)
}

/// Anchored label match with `*` standing for one or more labels.
fn labels_match(pattern: &[&str], host: &[&str]) -> bool {
    match pattern.split_first() {
        // Both exhausted together, or neither: the match is anchored at the end.
        None => host.is_empty(),
        Some((&"*", rest)) => {
            // One or more: consume at least one label, then try every split.
            // Host lists are a handful of labels, so the search is trivial.
            (1..=host.len()).any(|take| labels_match(rest, &host[take..]))
        }
        Some((&literal, rest)) => match host.split_first() {
            Some((&first, host_rest)) if first == literal => labels_match(rest, host_rest),
            _ => false,
        },
    }
}

/// Does a path glob match `path`? `*` matches any run of characters, and
/// the pattern is anchored at both ends: `/repos/*/pulls` admits
/// `/repos/o/r/pulls` and not `/repos/o/r/pulls/7/merge`.
#[must_use]
pub fn path_matches(pattern: &str, path: &str) -> bool {
    let path = path.split(['?', '#']).next().unwrap_or(path);
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut rest = path;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        let Some(pos) = rest.find(part) else {
            return false;
        };
        if i == 0 && pos != 0 {
            return false;
        }
        rest = &rest[pos + part.len()..];
    }
    parts.last().is_some_and(|l| l.is_empty()) || rest.is_empty()
}

/// What the granted effect set says about one attempt (ADR 0004, milestone 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectAdmission {
    /// The certificate carries no effect dimension: nothing to check against.
    Unconstrained,
    /// A granted effect vouches for the attempt.
    Admitted(EffectId),
    /// The dimension is in use and no granted effect vouches for the attempt;
    /// `would_admit` names the catalog effects that would, for the proposal.
    NotAdmitted {
        /// Effects (granted or not) whose vocabulary covers the attempt.
        would_admit: Vec<EffectId>,
    },
}

impl EffectSpec {
    /// Does this effect vouch for an HTTP request? A declared `http` shape
    /// must match method, host and path; an effect with no `http` shapes but
    /// a host list vouches for any request to one of its hosts (a host-level
    /// effect such as `git/push-branch`).
    #[must_use]
    pub fn admits_http(&self, method: &str, host: &str, path: &str) -> bool {
        if self.http.is_empty() {
            return self.hosts.iter().any(|p| host_matches(p, host));
        }
        self.http.iter().any(|m| {
            m.method.eq_ignore_ascii_case(method.trim())
                && host_matches(&m.host, host)
                && path_matches(&m.path, path)
        })
    }

    /// Does this effect vouch for an MCP tool by name (`server__tool` or bare)?
    #[must_use]
    pub fn admits_tool(&self, tool: &str) -> bool {
        let bare = tool.rsplit("__").next().unwrap_or(tool);
        self.mcp_tools.iter().any(|t| t == tool || t == bare)
    }
}

impl EffectCatalog {
    /// Is an HTTP request admitted under `granted` (the certificate's effect
    /// set, `None` when the dimension is unset)?
    #[must_use]
    pub fn admits_http(
        &self,
        granted: Option<&BTreeSet<String>>,
        method: &str,
        host: &str,
        path: &str,
    ) -> EffectAdmission {
        let Some(granted) = granted else {
            return EffectAdmission::Unconstrained;
        };
        let host = host.trim().to_ascii_lowercase();
        let mut would_admit = Vec::new();
        for e in self.iter() {
            if !e.admits_http(method, &host, path) {
                continue;
            }
            if granted.contains(&e.id.to_string()) {
                return EffectAdmission::Admitted(e.id.clone());
            }
            would_admit.push(e.id.clone());
        }
        would_admit.sort();
        EffectAdmission::NotAdmitted { would_admit }
    }

    /// Is an MCP tool call admitted under `granted`?
    #[must_use]
    pub fn admits_tool(&self, granted: Option<&BTreeSet<String>>, tool: &str) -> EffectAdmission {
        let Some(granted) = granted else {
            return EffectAdmission::Unconstrained;
        };
        let mut would_admit = Vec::new();
        for e in self.iter() {
            if !e.admits_tool(tool) {
                continue;
            }
            if granted.contains(&e.id.to_string()) {
                return EffectAdmission::Admitted(e.id.clone());
            }
            would_admit.push(e.id.clone());
        }
        would_admit.sort();
        EffectAdmission::NotAdmitted { would_admit }
    }
}

/// A prefix match on whole words: `git push` matches `git push origin x` and
/// `git push`, not `git pushx`. A `*` inside a word matches any run of
/// characters, and because the pattern is a prefix its last literal may end
/// the word or a path segment: `gh api repos/*/actions` matches
/// `gh api repos/o/r/actions/runs`.
pub fn command_matches(prefix: &str, command: &str) -> bool {
    let p: Vec<&str> = prefix.split_whitespace().collect();
    let c: Vec<&str> = command.split_whitespace().collect();
    if p.is_empty() || c.len() < p.len() {
        return false;
    }
    p.iter().zip(c.iter()).all(|(pw, cw)| word_matches(pw, cw))
}

fn word_matches(pattern: &str, word: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == word;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut rest = word;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        let Some(pos) = rest.find(part) else {
            return false;
        };
        if i == 0 && pos != 0 {
            return false;
        }
        rest = &rest[pos + part.len()..];
    }
    // A command pattern is a prefix of the command, so the last literal
    // may end the word or end a path segment: `repos/*/actions` admits
    // `repos/o/r/actions/runs` but not `repos/o/r/actionsx`.
    let last = parts.last().copied().unwrap_or_default();
    last.is_empty() || rest.is_empty() || rest.starts_with('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(s: &str) -> EffectId {
        s.parse().expect("valid id")
    }

    #[test]
    fn builtin_catalog_is_sound() {
        let catalog = EffectCatalog::builtin().expect("built-in catalog loads and validates");
        assert!(catalog.len() >= 14, "expected the five built-in plugins");
        assert!(catalog.get(&id("github/read-ci-logs")).is_some());
        assert!(catalog.get(&id("fs/read-workspace")).is_some());
    }

    #[test]
    fn lowering_is_exactly_the_union_of_members() {
        let catalog = EffectCatalog::builtin().unwrap();
        let ids: BTreeSet<EffectId> = [id("github/read-ci-logs")].into_iter().collect();
        let lowered = catalog.lower(&ids).unwrap();
        assert_eq!(lowered.capabilities.web_fetch, CapabilityLevel::LowRisk);
        for op in Operation::ALL {
            if op != Operation::WebFetch {
                assert_eq!(
                    lowered.capabilities.level_for(op),
                    CapabilityLevel::Never,
                    "{op} must stay Never"
                );
            }
        }
        assert!(lowered.hosts.contains("api.github.com"));
        assert_eq!(lowered.hosts.len(), 1);
        assert!(lowered.sinks.contains(&SinkClass::HTTPEgress));
    }

    #[test]
    fn read_workspace_lowers_to_always() {
        let catalog = EffectCatalog::builtin().unwrap();
        let ids: BTreeSet<EffectId> = [id("fs/read-workspace")].into_iter().collect();
        let lowered = catalog.lower(&ids).unwrap();
        assert_eq!(lowered.capabilities.read_files, CapabilityLevel::Always);
        assert_eq!(lowered.capabilities.write_files, CapabilityLevel::Never);
    }

    #[test]
    fn unknown_effect_is_an_error_not_a_noop() {
        let catalog = EffectCatalog::builtin().unwrap();
        let ids: BTreeSet<EffectId> = [id("github/delete-repo")].into_iter().collect();
        assert!(matches!(
            catalog.lower(&ids),
            Err(EffectCatalogError::Unknown(_))
        ));
    }

    #[test]
    fn reverse_lookups() {
        let catalog = EffectCatalog::builtin().unwrap();
        let by_host: Vec<_> = catalog
            .effects_for_host("api.github.com")
            .into_iter()
            .map(|e| e.id.to_string())
            .collect();
        assert!(by_host.contains(&"github/read-ci-logs".to_string()));
        let by_cmd: Vec<_> = catalog
            .effects_for_command("gh pr merge 42 --squash")
            .into_iter()
            .map(|e| e.id.to_string())
            .collect();
        assert_eq!(by_cmd, vec!["github/merge-pr".to_string()]);
        assert!(catalog.effects_for_command("gh prmerge").is_empty());
        let by_tool: Vec<_> = catalog
            .effects_for_tool("mcp__github__get_job_logs")
            .into_iter()
            .map(|e| e.id.to_string())
            .collect();
        assert_eq!(by_tool, vec!["github/read-ci-logs".to_string()]);
        assert!(!catalog.effects_for_operation(Operation::GitPush).is_empty());
    }

    #[test]
    fn invalid_ids_and_vocabulary_are_rejected() {
        assert!("GitHub/read".parse::<EffectId>().is_err());
        assert!("github".parse::<EffectId>().is_err());
        assert!("github/-x".parse::<EffectId>().is_err());
        let mut catalog = EffectCatalog::empty();
        let bad_op = r#"
[plugin]
name = "x"
version = 1
[[effect]]
id = "a"
title = "A"
risk = "read"
[effect.lowers]
operations = ["teleport"]
"#;
        assert!(matches!(
            catalog.load_toml(bad_op, "test"),
            Err(EffectCatalogError::UnknownVocabulary { .. })
        ));
        let no_ops = r#"
[plugin]
name = "x"
version = 1
[[effect]]
id = "a"
title = "A"
risk = "read"
"#;
        let mut catalog = EffectCatalog::empty();
        catalog.load_toml(no_ops, "test").unwrap();
        assert!(matches!(
            catalog.validate(),
            Err(EffectCatalogError::Invalid { .. })
        ));
        let foreign_http = r#"
[plugin]
name = "x"
version = 1
[[effect]]
id = "a"
title = "A"
risk = "read"
[effect.lowers]
operations = ["web_fetch"]
hosts = ["a.example"]
[effect.matches]
http = [{ method = "GET", host = "b.example", path = "/*" }]
"#;
        let mut catalog = EffectCatalog::empty();
        catalog.load_toml(foreign_http, "test").unwrap();
        assert!(matches!(
            catalog.validate(),
            Err(EffectCatalogError::Invalid { .. })
        ));
    }

    #[test]
    fn duplicate_ids_are_rejected() {
        let mut catalog = EffectCatalog::builtin().unwrap();
        let dup = r#"
[plugin]
name = "github"
version = 1
[[effect]]
id = "read-issue"
title = "again"
risk = "read"
[effect.lowers]
operations = ["web_fetch"]
"#;
        assert!(matches!(
            catalog.load_toml(dup, "test"),
            Err(EffectCatalogError::Duplicate(_))
        ));
    }

    #[test]
    fn http_and_tool_admission_follow_the_granted_effects() {
        let catalog = EffectCatalog::builtin().unwrap();
        let granted: BTreeSet<String> = ["github/read-ci-logs", "fs/read-workspace"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let g = Some(&granted);
        assert!(matches!(
            catalog.admits_http(g, "GET", "api.github.com", "/repos/o/r/actions/runs/1/logs"),
            EffectAdmission::Admitted(ref id) if id.to_string() == "github/read-ci-logs"
        ));
        // Same host, a method and path only github/open-pr covers.
        match catalog.admits_http(g, "POST", "api.github.com", "/repos/o/r/pulls") {
            EffectAdmission::NotAdmitted { would_admit } => {
                assert!(would_admit
                    .iter()
                    .any(|e| e.to_string() == "github/open-pr"));
            }
            other => panic!("{other:?}"),
        }
        // Query strings do not defeat the path glob.
        assert!(matches!(
            catalog.admits_http(
                g,
                "get",
                "API.github.com",
                "/repos/o/r/actions/runs?per_page=5"
            ),
            EffectAdmission::Admitted(_)
        ));
        // A host no effect names at all.
        match catalog.admits_http(g, "GET", "evil.example", "/") {
            EffectAdmission::NotAdmitted { would_admit } => assert!(would_admit.is_empty()),
            other => panic!("{other:?}"),
        }
        // No effect dimension: unconstrained.
        assert_eq!(
            catalog.admits_http(None, "POST", "anywhere.example", "/"),
            EffectAdmission::Unconstrained
        );
        // Tools.
        assert!(matches!(
            catalog.admits_tool(g, "github__get_job_logs"),
            EffectAdmission::Admitted(_)
        ));
        assert!(matches!(
            catalog.admits_tool(g, "read_file"),
            EffectAdmission::Admitted(ref id) if id.to_string() == "fs/read-workspace"
        ));
        match catalog.admits_tool(g, "create_pull_request") {
            EffectAdmission::NotAdmitted { would_admit } => {
                assert_eq!(would_admit.len(), 1);
                assert_eq!(would_admit[0].to_string(), "github/open-pr");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn path_globs_are_anchored_and_star_spans_segments() {
        assert!(path_matches("/repos/*/pulls", "/repos/o/r/pulls"));
        assert!(!path_matches("/repos/*/pulls", "/repos/o/r/pulls/7/merge"));
        assert!(path_matches("/repos/*/pulls*", "/repos/o/r/pulls/7/merge"));
        assert!(path_matches("/*", "/anything/at/all"));
        assert!(!path_matches("/repos/*/pulls", "/other/o/r/pulls"));
        assert!(path_matches(
            "/repos/*/actions/*",
            "/repos/o/r/actions/runs?x=1"
        ));
    }

    #[test]
    fn host_and_command_matching() {
        assert!(host_matches("*.github.com", "api.github.com"));
        assert!(!host_matches("*.github.com", "github.com"));
        assert!(host_matches("github.com", "GitHub.com"));
        assert!(command_matches(
            "gh api repos/*/actions",
            "gh api repos/o/r/actions/runs"
        ));
        assert!(!command_matches(
            "gh api repos/*/actions",
            "gh api repos/o/r/actionsx"
        ));
        assert!(command_matches(
            "gh api repos/*/actions",
            "gh api repos/o/r/actions"
        ));
        assert!(!command_matches("cargo test", "cargo testing"));
        assert!(command_matches("cargo test", "cargo test"));
    }

    #[test]
    fn effect_id_serde_roundtrip() {
        let e = id("github/open-pr");
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(json, "\"github/open-pr\"");
        let back: EffectId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
        assert!(serde_json::from_str::<EffectId>("\"nope\"").is_err());
    }
}

// ── Pack conformance ────────────────────────────────────────────────────────
//
// Every pack states, as a table, requests it admits and requests it does not.
// A pack is a claim about what a grant MEANS, and a claim with no counterexample
// beside it is a claim nobody checked: it is trivially easy to write an effect
// whose `matches` index is so broad it vouches for the next effect along, and
// the symptom is not a test failure but a grant that quietly means more than
// the person who approved it thought.
//
// So each row here is a pair. `aws/read-object` admits a GET to the object
// store and must NOT admit the PUT that `aws/write-object` covers; the denial
// must NAME the effect that would have admitted it, because that name is what
// an escalation proposal is built from.
// ── The host matcher ────────────────────────────────────────────────────────
//
// `host_matches` is the effect catalog's matcher AND the egress gate's, so a
// pattern that matched one label too many would widen every grant that used it.
// The anchors are the property; these are the ways an attacker would try to
// slip past them.
#[cfg(test)]
mod host_matching {
    use super::host_matches;

    #[test]
    fn a_star_label_spans_one_or_more_whole_labels() {
        assert!(host_matches("*.amazonaws.com", "s3.amazonaws.com"));
        assert!(host_matches("*.amazonaws.com", "bucket.s3.amazonaws.com"));
        assert!(host_matches(
            "logs.*.amazonaws.com",
            "logs.eu-west-1.amazonaws.com"
        ));
        assert!(host_matches(
            "ec2.*.amazonaws.com",
            "ec2.us-east-1.amazonaws.com"
        ));
        assert!(host_matches("api.github.com", "api.github.com"));
        assert!(
            host_matches("API.GitHub.com", "api.github.com"),
            "case-insensitive"
        );
    }

    /// A `*` never matches zero labels, so a pattern is always strictly more
    /// specific than the bare suffix it is built from.
    #[test]
    fn a_star_does_not_match_nothing() {
        assert!(!host_matches("*.amazonaws.com", "amazonaws.com"));
        assert!(!host_matches("logs.*.amazonaws.com", "logs.amazonaws.com"));
    }

    /// The anchors, from both ends. Each of these is a real shape an attacker
    /// registers: a name that CONTAINS the target, and a name that is PREFIXED
    /// by it.
    #[test]
    fn matching_is_anchored_at_both_ends_and_at_label_boundaries() {
        assert!(!host_matches("*.amazonaws.com", "evil-amazonaws.com"));
        assert!(!host_matches("*.amazonaws.com", "notamazonaws.com"));
        assert!(!host_matches(
            "*.amazonaws.com",
            "s3.amazonaws.com.evil.example"
        ));
        assert!(!host_matches(
            "api.github.com",
            "api.github.com.evil.example"
        ));
        assert!(!host_matches("api.github.com", "evil.api.github.com"));
        assert!(!host_matches(
            "logs.*.amazonaws.com",
            "logs.eu-west-1.amazonaws.com.evil"
        ));
        assert!(!host_matches(
            "logs.*.amazonaws.com",
            "evil.logs.eu-west-1.amazonaws.com"
        ));
    }

    /// The pins the AWS pack leans on: one service host must not admit
    /// another's, or "read the logs" would carry "rewrite IAM".
    #[test]
    fn one_service_host_does_not_admit_another() {
        assert!(!host_matches("logs.*.amazonaws.com", "iam.amazonaws.com"));
        assert!(!host_matches(
            "ec2.*.amazonaws.com",
            "logs.eu-west-1.amazonaws.com"
        ));
        assert!(!host_matches(
            "iam.amazonaws.com",
            "iam.us-east-1.amazonaws.com"
        ));
        assert!(!host_matches(
            "*.s3.amazonaws.com",
            "ec2.us-east-1.amazonaws.com"
        ));
    }

    /// Grammar: a `*` is a whole label or it is not a wildcard at all, so no
    /// pattern can match a fragment of a name.
    #[test]
    fn a_star_must_be_a_whole_label() {
        assert!(super::is_host_pattern("*.amazonaws.com"));
        assert!(super::is_host_pattern("logs.*.amazonaws.com"));
        assert!(super::is_host_pattern("api.github.com"));
        assert!(!super::is_host_pattern("*foo.example"));
        assert!(!super::is_host_pattern("fo*o.example"));
        assert!(!super::is_host_pattern(".example.com"));
        assert!(!super::is_host_pattern("example.com."));
        assert!(!super::is_host_pattern(""));
        assert!(!super::is_host_pattern("a..b"));
    }
}

#[cfg(test)]
mod pack_conformance {
    use super::*;

    fn granted(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| (*s).to_string()).collect()
    }

    /// Admitted, and by the effect we meant.
    fn admits(catalog: &EffectCatalog, g: &BTreeSet<String>, m: &str, h: &str, p: &str, by: &str) {
        match catalog.admits_http(Some(g), m, h, p) {
            EffectAdmission::Admitted(id) => assert_eq!(
                id.to_string(),
                by,
                "{m} {h}{p} was admitted by {id}, expected {by}"
            ),
            other => panic!("{m} {h}{p} should be admitted by {by}, got {other:?}"),
        }
    }

    /// Refused, and the refusal names what a person would have to grant.
    fn refuses(
        catalog: &EffectCatalog,
        g: &BTreeSet<String>,
        m: &str,
        h: &str,
        p: &str,
        would: &str,
    ) {
        match catalog.admits_http(Some(g), m, h, p) {
            EffectAdmission::NotAdmitted { would_admit } => assert!(
                would_admit.iter().any(|e| e.to_string() == would),
                "{m} {h}{p} was refused, but the refusal did not name {would}: {would_admit:?}"
            ),
            other => panic!("{m} {h}{p} should be refused, got {other:?}"),
        }
    }

    #[test]
    fn aws_object_reads_do_not_carry_object_writes() {
        let catalog = EffectCatalog::builtin().unwrap();
        let g = granted(&["aws/read-object"]);
        admits(
            &catalog,
            &g,
            "GET",
            "bucket.s3.amazonaws.com",
            "/reports/q3.csv",
            "aws/read-object",
        );
        refuses(
            &catalog,
            &g,
            "PUT",
            "bucket.s3.amazonaws.com",
            "/reports/q3.csv",
            "aws/write-object",
        );
        refuses(
            &catalog,
            &g,
            "DELETE",
            "bucket.s3.amazonaws.com",
            "/reports/q3.csv",
            "aws/delete-object",
        );
    }

    /// The effect a grant of everything-but-IAM must still refuse. `mutate-iam`
    /// is the one that can rewrite the boundary itself, so it is pinned to its
    /// own host and graded `destructive`.
    #[test]
    fn iam_is_reachable_only_by_the_effect_that_names_it() {
        let catalog = EffectCatalog::builtin().unwrap();
        let g = granted(&["aws/read-inventory", "aws/read-object", "aws/start-compute"]);
        refuses(
            &catalog,
            &g,
            "POST",
            "iam.amazonaws.com",
            "/",
            "aws/mutate-iam",
        );
        let with_iam = granted(&["aws/mutate-iam"]);
        admits(
            &catalog,
            &with_iam,
            "POST",
            "iam.amazonaws.com",
            "/",
            "aws/mutate-iam",
        );
    }

    #[test]
    fn slack_reading_does_not_carry_posting() {
        let catalog = EffectCatalog::builtin().unwrap();
        let g = granted(&["slack/read-channel"]);
        admits(
            &catalog,
            &g,
            "GET",
            "slack.com",
            "/api/conversations.history",
            "slack/read-channel",
        );
        refuses(
            &catalog,
            &g,
            "POST",
            "slack.com",
            "/api/chat.postMessage",
            "slack/post-message",
        );
    }

    /// The command-recognised packs. Kubernetes and the database have no
    /// discriminating `http` index (see the header of each file), so their
    /// claim is about tool names and command prefixes, and that is what gets
    /// checked.
    #[test]
    fn kubernetes_reading_does_not_carry_mutating() {
        let catalog = EffectCatalog::builtin().unwrap();
        let g = granted(&["kubernetes/read-workloads", "kubernetes/read-logs"]);
        assert_eq!(
            catalog.admits_tool(Some(&g), "k8s_logs"),
            EffectAdmission::Admitted("kubernetes/read-logs".parse().unwrap())
        );
        for blocked in ["k8s_apply", "k8s_exec", "k8s_delete"] {
            assert!(
                matches!(
                    catalog.admits_tool(Some(&g), blocked),
                    EffectAdmission::NotAdmitted { .. }
                ),
                "{blocked} must not be admitted by a read-only kubernetes grant"
            );
        }
    }

    #[test]
    fn a_query_grant_does_not_carry_a_migration_or_a_drop() {
        let catalog = EffectCatalog::builtin().unwrap();
        let g = granted(&["database/read-rows", "database/read-schema"]);
        assert_eq!(
            catalog.admits_tool(Some(&g), "db_query"),
            EffectAdmission::Admitted("database/read-rows".parse().unwrap())
        );
        for blocked in ["db_migrate", "db_drop", "db_execute"] {
            assert!(
                matches!(
                    catalog.admits_tool(Some(&g), blocked),
                    EffectAdmission::NotAdmitted { .. }
                ),
                "{blocked} must not be admitted by a read-only database grant"
            );
        }
    }

    /// Non-vacuity for every pack at once. If an effect's recognition index
    /// were empty, each "refuses" above would pass for the wrong reason — the
    /// request would be refused because NOTHING names it, not because the
    /// granted effect does not. So: every effect in every built-in pack is
    /// named by at least one tool, command or HTTP shape.
    #[test]
    fn no_builtin_effect_is_unrecognisable() {
        let catalog = EffectCatalog::builtin().unwrap();
        for spec in catalog.iter() {
            assert!(
                !spec.mcp_tools.is_empty() || !spec.commands.is_empty() || !spec.http.is_empty(),
                "{} has an empty recognition index: nothing can ever be attributed \
                 to it, so granting it grants nothing and denying it denies nothing",
                spec.id
            );
        }
    }

    /// Two effects in the same pack must not be named by the same tool, or a
    /// grant of the narrower one silently admits the wider one's work.
    #[test]
    fn no_tool_name_is_claimed_by_two_effects_of_different_risk() {
        let catalog = EffectCatalog::builtin().unwrap();
        let mut by_tool: BTreeMap<&str, Vec<&EffectSpec>> = BTreeMap::new();
        for spec in catalog.iter() {
            for tool in &spec.mcp_tools {
                by_tool.entry(tool.as_str()).or_default().push(spec);
            }
        }
        for (tool, specs) in by_tool {
            let risks: BTreeSet<&str> = specs.iter().map(|s| s.risk.as_str()).collect();
            assert!(
                risks.len() <= 1,
                "tool '{tool}' is claimed by effects of differing risk ({risks:?}); a grant \
                 of the lower one would admit the higher one's work: {:?}",
                specs.iter().map(|s| s.id.to_string()).collect::<Vec<_>>()
            );
        }
    }
}

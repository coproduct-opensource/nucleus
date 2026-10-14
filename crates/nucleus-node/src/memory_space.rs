//! Memory spaces, binding policies and per-run bindings: the node's registry (Program B, M3).
//!
//! # Three graphs, kept apart
//!
//! Who spawned whom (execution), who delegated what to whom (authority), and what state was
//! derived from what (memory versions) are three graphs. #3451 keyed a store by the pod's
//! lineage root, which made execution ancestry decide memory visibility. Here a memory space is
//! an **object** with a stable identity ([`MemorySpace`]: tenant, space id, schema) and a linear,
//! hash-chained history (the v2 journal, `nucleus_provenance_memory::journal`). A run never
//! inherits a dead process's powers over it: at pod creation the node mints a fresh
//! [`Binding`] from the [`BindingPolicy`] that admits the pod, and a binding is never copied from
//! a parent.
//!
//! # Audiences
//!
//! A policy names who it admits ([`Audience`]):
//!
//! * `Lineage(root)` — the default. A pod that asks for a space name the tenant has not declared
//!   is bound to its lineage's own space for that name, created on first use with one
//!   `Lineage(root)` policy. Every run of the lineage reads the same **base** (the space's head
//!   when its binding is minted) and writes a **private** branch of its own; nothing one run
//!   writes reaches another until it is published. That is #3451's isolation, stated precisely:
//!   siblings share the base, never each other's writes.
//! * `Workspace(selector)` — normal cross-run continuity: every pod of the tenant whose
//!   tenant-authenticated labels carry the selector. Labels are tenant-authenticated only on a
//!   pod the tenant's own identity created; a pod-created child's labels were written by a pod,
//!   so they match no selector (a child does not acquire a workspace binding by naming itself
//!   into it).
//! * `TenantAll` — every pod of the tenant, and only when a policy names it.
//! * `TenantAllLegacy` — the declared form of what the owner-keyed layout did implicitly; only
//!   migration records one.
//!
//! A policy is created by the tenant's root identity (`memory_space_api`), or by citing a
//! standing signed owner decision whose scope covers `memory.bind:<space>` (and
//! `memory.publish:<space>` for a policy that may publish), re-cited at every bind and publish.
//!
//! # Revocation
//!
//! Revoking a space moves it to the next epoch: every policy and binding minted at an earlier
//! epoch is refused for new mediated operations (`ForeignEpoch`, decided by
//! `nucleus_memory_context`'s admission slice). Revoking a policy refuses its bindings by name.
//! Neither erases what was already disclosed: a snapshot delivered to a run stays delivered.
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use nucleus_memory_context::{LabelRank, Scope, ScopeAtom, View};
use nucleus_provenance_memory::{ConfLevel, MAX_JOURNAL_BYTES, MemoryRecord, Pin, SchemaType};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ApiError;
use crate::memory_flow::{FlowClaim, FlowEvent, Recorder};

const REGISTRY_FILE: &str = "spaces.json";
const REGISTRY_SCHEMA: &str = "nucleus.memory-spaces.v1";
/// The registry of the held #3451 branch, which this registry supersedes. Its grants have no
/// faithful translation (a grant named lineages, a policy names an audience), so a node that
/// finds one refuses to start rather than guess.
const HELD_SHARE_REGISTRY: &str = "shares.json";
/// What a publishing binding is allocated when its policy is the lineage default or a migration.
pub(crate) const DEFAULT_ALLOCATION_BYTES: u64 = 4 * 1024 * 1024;
/// The most labels a workspace selector may name.
const MAX_SELECTOR: usize = 16;

/// A space name: 1 to 64 ASCII letters, digits, underscores or hyphens. The one spelling check
/// for every name that becomes a path segment.
pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A tenant, as the hex SHA-256 of its root identity: the key the store layout has always used.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(crate) struct TenantKey(String);

impl TenantKey {
    /// The tenant whose root identity is `root_identity`.
    pub(crate) fn of(root_identity: &str) -> Self {
        Self(hex::encode(Sha256::digest(root_identity.as_bytes())))
    }
    /// A directory name in the legacy owner-keyed layout, if it is one.
    pub(crate) fn from_hex(name: &str) -> Option<Self> {
        (name.len() == 64 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
            .then(|| Self(name.to_owned()))
    }
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TenantKey {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        Self::from_hex(&s).ok_or_else(|| "not a tenant key".to_owned())
    }
}

impl From<TenantKey> for String {
    fn from(t: TenantKey) -> String {
        t.0
    }
}

/// A space name that passed [`valid_name`]. Deserialization checks it too, so no registry entry
/// carries a name that is not a safe path segment.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(crate) struct SpaceName(String);

impl SpaceName {
    pub(crate) fn new(name: &str) -> Result<Self, MemoryRefusal> {
        if valid_name(name) {
            Ok(Self(name.to_owned()))
        } else {
            Err(MemoryRefusal::BadName)
        }
    }
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SpaceName {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        Self::new(&s).map_err(|e| e.to_string())
    }
}

impl From<SpaceName> for String {
    fn from(n: SpaceName) -> String {
        n.0
    }
}

/// Which space, within a tenant. A lineage's own space for a name is a different space from the
/// tenant's declared space of that name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum SpaceId {
    /// A space the tenant declared, or a migrated owner-keyed store.
    Named { name: SpaceName },
    /// A lineage's own space for `name`.
    Lineage { root: Uuid, name: SpaceName },
}

impl SpaceId {
    /// The space's spelling in a URL and a capability: `name`, or `lineage.<root>.<name>`. A
    /// name cannot contain `.`, so the two never collide.
    pub(crate) fn reference(&self) -> String {
        match self {
            SpaceId::Named { name } => name.as_str().to_owned(),
            SpaceId::Lineage { root, name } => format!("lineage.{root}.{}", name.as_str()),
        }
    }

    /// Parse [`Self::reference`].
    pub(crate) fn parse(reference: &str) -> Result<Self, MemoryRefusal> {
        match reference.strip_prefix("lineage.") {
            None => Ok(SpaceId::Named {
                name: SpaceName::new(reference)?,
            }),
            Some(rest) => {
                let (root, name) = rest.split_once('.').ok_or(MemoryRefusal::BadName)?;
                Ok(SpaceId::Lineage {
                    root: Uuid::parse_str(root).map_err(|_| MemoryRefusal::BadName)?,
                    name: SpaceName::new(name)?,
                })
            }
        }
    }
}

/// A record schema class: one scope atom of the memory-context kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SchemaAtom {
    String,
    Json,
    Binary,
}

impl SchemaAtom {
    pub(crate) const ALL: [SchemaAtom; 3] =
        [SchemaAtom::String, SchemaAtom::Json, SchemaAtom::Binary];

    const fn kernel(self) -> ScopeAtom {
        match self {
            SchemaAtom::String => ScopeAtom::Ns0,
            SchemaAtom::Json => ScopeAtom::Ns1,
            SchemaAtom::Binary => ScopeAtom::Ns2,
        }
    }

    /// The atom a record's schema lives in. Exhaustive: a new schema type is a compile error
    /// here, never a record that falls outside every view by accident or inside one by default.
    pub(crate) const fn of(schema: SchemaType) -> Self {
        match schema {
            SchemaType::String => SchemaAtom::String,
            SchemaType::Json => SchemaAtom::Json,
            SchemaType::Binary => SchemaAtom::Binary,
        }
    }
}

/// The highest confidentiality a view sees.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Ceiling {
    Public,
    Internal,
    Secret,
}

impl Ceiling {
    const fn kernel(self) -> LabelRank {
        match self {
            Ceiling::Public => LabelRank::Public,
            Ceiling::Internal => LabelRank::Internal,
            Ceiling::Secret => LabelRank::Secret,
        }
    }
}

/// A confidentiality level as the kernel's rank. Exhaustive, for the reason [`SchemaAtom::of`]
/// gives.
const fn rank_of(level: ConfLevel) -> LabelRank {
    match level {
        ConfLevel::Public => LabelRank::Public,
        ConfLevel::Internal => LabelRank::Internal,
        ConfLevel::Secret => LabelRank::Secret,
    }
}

fn scope_of(atoms: &BTreeSet<SchemaAtom>) -> Scope {
    atoms
        .iter()
        .fold(Scope::EMPTY, |scope, atom| scope.with(atom.kernel()))
}

/// What a binding sees: which schema classes, up to which confidentiality. The wire form of the
/// kernel's `View`, which decides; the real record domain (three schema types, three
/// confidentiality levels) is exactly the kernel's finite one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ViewSpec {
    pub(crate) schema: BTreeSet<SchemaAtom>,
    pub(crate) ceiling: Ceiling,
}

impl ViewSpec {
    /// Every schema class, every label: what a migrated store and a lineage default see.
    pub(crate) fn everything() -> Self {
        Self {
            schema: SchemaAtom::ALL.into_iter().collect(),
            ceiling: Ceiling::Secret,
        }
    }

    pub(crate) fn kernel(&self) -> View {
        View {
            scope: scope_of(&self.schema),
            ceiling: self.ceiling.kernel(),
        }
    }

    /// Does this view see `record`? The kernel's one visibility decision.
    pub(crate) fn sees(&self, record: &MemoryRecord) -> bool {
        self.kernel().admits(
            SchemaAtom::of(record.schema).kernel(),
            rank_of(record.label.conf_level()),
        )
    }

    /// May a binding with this view write `record`? Its schema class must be in scope; its
    /// label may be above the ceiling (writing up), and label monotonicity is the store's.
    pub(crate) fn may_write(&self, record: &MemoryRecord) -> bool {
        self.kernel()
            .scope
            .contains(SchemaAtom::of(record.schema).kernel())
    }

    /// `SHA-256` over a domain tag, the scope bits and the ceiling rank: the view a delivery
    /// receipt names.
    pub(crate) fn digest(&self) -> String {
        let view = self.kernel();
        let mut h = Sha256::new();
        h.update(b"nucleus/memory-view/v1\0");
        h.update([view.scope.bits(), view.ceiling.rank()]);
        hex::encode(h.finalize())
    }
}

/// Where a space's journal lives under the memory root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Location {
    /// `<root>/<tenant>/<name>`: a store from the owner-keyed layout, kept in place so its
    /// journal header still matches.
    Legacy,
    /// `<root>/lineage/<tenant>/<root>/<name>`: a store from the held #3451 layout, in place.
    HeldLineage,
    /// `<root>/spaces/<tenant>/...`.
    Spaces,
}

/// How a space came to exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SpaceOrigin {
    /// Declared by the tenant root.
    Declared,
    /// A lineage's own space, created on first use.
    LineageDefault,
    /// An owner-keyed store, migrated.
    MigratedLegacy,
    /// A #3451 lineage store, migrated.
    MigratedHeldLineage,
}

/// A space: a stable identity and the epoch that revokes.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MemorySpace {
    pub(crate) tenant: TenantKey,
    pub(crate) id: SpaceId,
    /// The record schema classes the space holds. Every policy's view is within it.
    pub(crate) schema: BTreeSet<SchemaAtom>,
    /// Policies and bindings minted at an earlier epoch are revoked.
    pub(crate) epoch: u32,
    pub(crate) location: Location,
    /// The most bytes the journal may hold. Split into per-binding allocations, so no publish's
    /// verdict depends on another binding's spend.
    pub(crate) quota_bytes: u64,
    /// The highest position any binding of this space was pinned to or published, so a journal
    /// later found shorter (rolled back) or rewritten below it is refused by name.
    pub(crate) high_water: Option<Pin>,
    pub(crate) origin: SpaceOrigin,
    pub(crate) created_unix: u64,
}

impl MemorySpace {
    /// The journal's directory segments under the memory root, and the namespace its header
    /// carries. `None` for a location that cannot hold this id (refused when loaded).
    pub(crate) fn store(&self) -> Option<(Vec<String>, String)> {
        let tenant = self.tenant.as_str();
        match (self.location, &self.id) {
            (Location::Legacy, SpaceId::Named { name }) => Some((
                vec![tenant.to_owned(), name.as_str().to_owned()],
                format!("{tenant}/{}", name.as_str()),
            )),
            (Location::HeldLineage, SpaceId::Lineage { root, name }) => Some((
                vec![
                    "lineage".into(),
                    tenant.to_owned(),
                    root.to_string(),
                    name.as_str().to_owned(),
                ],
                format!("lineage/{tenant}/{root}/{}", name.as_str()),
            )),
            (Location::Spaces, SpaceId::Named { name }) => Some((
                vec![
                    "spaces".into(),
                    tenant.to_owned(),
                    "named".into(),
                    name.as_str().to_owned(),
                ],
                format!("space/{tenant}/{}", name.as_str()),
            )),
            (Location::Spaces, SpaceId::Lineage { root, name }) => Some((
                vec![
                    "spaces".into(),
                    tenant.to_owned(),
                    "lineage".into(),
                    root.to_string(),
                    name.as_str().to_owned(),
                ],
                format!("space/{tenant}/lineage/{root}/{}", name.as_str()),
            )),
            (Location::Legacy, SpaceId::Lineage { .. })
            | (Location::HeldLineage, SpaceId::Named { .. }) => None,
        }
    }

    pub(crate) fn kernel_scope(&self) -> Scope {
        scope_of(&self.schema)
    }
}

/// Who a policy admits. There is no variant for another tenant, so a cross-tenant binding is
/// not representable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Audience {
    /// The runs of one lineage.
    Lineage { root: Uuid },
    /// The pods whose tenant-authenticated labels carry every pair of `selector`.
    Workspace { selector: BTreeMap<String, String> },
    /// Every pod of the tenant: named, never a default.
    TenantAll,
    /// Every pod of the tenant, because the owner-keyed layout already gave them this store.
    TenantAllLegacy,
}

impl Audience {
    /// Which audience wins when several of a space's policies admit a pod: the narrowest.
    const fn precedence(&self) -> u8 {
        match self {
            Audience::Lineage { .. } => 0,
            Audience::Workspace { .. } => 1,
            Audience::TenantAll => 2,
            Audience::TenantAllLegacy => 3,
        }
    }

    fn admits(&self, pod: &PodMatch<'_>) -> bool {
        match self {
            Audience::Lineage { root } => *root == pod.lineage,
            Audience::Workspace { selector } => match pod.labels {
                PodLabels::TenantAuthenticated(labels) => selector
                    .iter()
                    .all(|(key, value)| labels.get(key) == Some(value)),
                PodLabels::PodAuthored => false,
            },
            Audience::TenantAll | Audience::TenantAllLegacy => true,
        }
    }
}

/// Whether a pod's labels speak for the tenant.
#[derive(Clone, Copy, Debug)]
pub(crate) enum PodLabels<'a> {
    /// The tenant's own identity created the pod: its labels are the tenant's.
    TenantAuthenticated(&'a BTreeMap<String, String>),
    /// Another pod created it, so a pod wrote its labels.
    PodAuthored,
}

/// The facts about a pod a policy is decided over.
pub(crate) struct PodMatch<'a> {
    pub(crate) lineage: Uuid,
    pub(crate) labels: PodLabels<'a>,
}

/// What a binding may do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Mode {
    /// Read the pinned base through the view.
    Read,
    /// Read, and write a private branch over the pinned base.
    ReadPropose,
}

/// When a policy stops admitting. Explicit: there is no "absent means forever" (ADR 0007 B-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "unix", rename_all = "snake_case")]
pub(crate) enum Expiry {
    At(u64),
    UntilRevoked,
}

impl Expiry {
    pub(crate) fn passed(self, now: u64) -> bool {
        match self {
            Expiry::At(at) => now >= at,
            Expiry::UntilRevoked => false,
        }
    }
}

/// What made a policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum PolicyAuthority {
    /// The tenant's root identity, over the API.
    TenantRoot,
    /// A standing signed owner decision, cited by id and re-cited at every bind and publish.
    Decision { id: String },
    /// The default policy of a lineage's own space.
    LineageDefault,
    /// The declared form of an earlier layout's reach.
    Migration,
}

/// Whether a policy still admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum PolicyState {
    Live,
    Revoked { at_unix: u64 },
}

/// Who may bind a space, how, and what they see. Minted only by this registry (ADR 0007 C-1);
/// not `Clone` and no `Default` (C-5, B-1).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BindingPolicy {
    pub(crate) id: Uuid,
    pub(crate) tenant: TenantKey,
    pub(crate) space: SpaceId,
    pub(crate) audience: Audience,
    pub(crate) mode: Mode,
    pub(crate) view: ViewSpec,
    pub(crate) may_publish: bool,
    /// Bytes each binding of this policy may add to the journal over its life.
    pub(crate) allocation_bytes: u64,
    pub(crate) expiry: Expiry,
    /// The space's epoch when the policy was made: a later space epoch revokes it.
    pub(crate) epoch: u32,
    pub(crate) state: PolicyState,
    pub(crate) authority: PolicyAuthority,
    pub(crate) issued_unix: u64,
}

/// Who holds a binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Principal {
    pub(crate) pod: Uuid,
    pub(crate) lineage: Uuid,
}

/// One run's binding to one space. Minted by the node when the pod is created
/// (`Registry::bind`), never inherited, never `Clone`. Bounded twice: by the space epoch it was
/// minted at and by `not_after`. It holds its pinned base, so a journal later rolled back below
/// the pin is refused by name rather than read as a shorter history.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Binding {
    pub(crate) binding_id: Uuid,
    pub(crate) tenant: TenantKey,
    pub(crate) space: SpaceId,
    pub(crate) policy: Uuid,
    pub(crate) principal: Principal,
    pub(crate) view: ViewSpec,
    pub(crate) base: Pin,
    pub(crate) mode: Mode,
    pub(crate) may_publish: bool,
    pub(crate) epoch: u32,
    pub(crate) not_after: u64,
    /// What this binding may add to the journal, reserved when it was minted.
    pub(crate) allocation_bytes: u64,
    /// What it has added so far.
    pub(crate) spent_bytes: u64,
    /// SHA-256 of the snapshot delivered to the run.
    pub(crate) delivered_sha256: String,
}

impl Binding {
    /// The binding's delivered directory under the memory root, and its journal's namespace.
    pub(crate) fn store(&self) -> (Vec<String>, String) {
        (
            vec!["bindings".into(), self.binding_id.to_string()],
            format!("binding/{}", self.binding_id),
        )
    }

    /// The publisher identity its commits carry: a domain-tagged hash of the binding id.
    pub(crate) fn publisher(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"nucleus/memory-binding/v1\0");
        h.update(self.binding_id.as_bytes());
        h.finalize().into()
    }

    /// Its reservation still counts against the space: same epoch, not past `not_after`.
    pub(crate) fn reserves(&self, space_epoch: u32, now: u64) -> u64 {
        if self.epoch == space_epoch && now <= self.not_after {
            self.allocation_bytes.saturating_sub(self.spent_bytes)
        } else {
            0
        }
    }
}

/// Why a memory operation was refused, by name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum MemoryRefusal {
    #[error("space names must be 1 to 64 ASCII letters, digits, underscores or hyphens")]
    BadName,
    /// Absent, or another tenant's: the same answer, so an id is no oracle across tenants.
    #[error("memory space {0} is not held by this tenant")]
    UnknownSpace(String),
    #[error("memory space {0} already exists")]
    SpaceExists(String),
    #[error("binding policy {0} is not held by this tenant")]
    UnknownPolicy(Uuid),
    #[error("binding {0} is not held by this caller")]
    UnknownBinding(Uuid),
    #[error("a space must hold at least one schema class")]
    EmptySchema,
    #[error("a space's quota must be 1 to {MAX_JOURNAL_BYTES} bytes")]
    BadQuota,
    #[error("the policy's view is wider than space {0}'s schema")]
    ViewWiderThanSpace(String),
    #[error("a workspace selector must name 1 to 16 non-empty labels")]
    BadSelector,
    #[error("a Read policy cannot publish, and a publishing policy must allocate bytes")]
    BadPublish,
    #[error("a policy's expiry must be in the future")]
    AlreadyExpired,
    #[error("only migration records a TenantAll-legacy audience")]
    LegacyAudience,
    #[error("no binding policy of memory space {space} admits this pod")]
    NoPolicyAdmits { space: String },
    #[error("binding policies {first} and {second} of memory space {space} both admit this pod")]
    Ambiguous {
        space: String,
        first: Uuid,
        second: Uuid,
    },
    #[error("binding policy {policy} is revoked")]
    PolicyRevoked { policy: Uuid },
    #[error("binding policy {policy} expired")]
    PolicyExpired { policy: Uuid },
    #[error(
        "binding {binding} was minted at epoch {binding_epoch}; memory space {space} is at epoch {current} (revoked). Revocation refuses new operations; it does not erase what was already delivered"
    )]
    ForeignEpoch {
        binding: Uuid,
        space: String,
        binding_epoch: u32,
        current: u32,
    },
    #[error("binding {binding} expired at {not_after}")]
    Expired { binding: Uuid, not_after: u64 },
    #[error("binding {0} may not publish")]
    MayNotPublish(Uuid),
    #[error(
        "memory space {space}'s journal holds version {found}, below version {held} a binding was pinned to: it was truncated, and is not read as a shorter history"
    )]
    Truncated {
        space: String,
        held: u64,
        found: u64,
    },
    #[error(
        "memory space {space}'s journal has a different head at version {version} than a binding was pinned to: it was rewritten"
    )]
    Rewritten { space: String, version: u64 },
    #[error(
        "memory space {space} has {free} bytes unreserved; a binding of this policy reserves {allocation}"
    )]
    QuotaFullyAllocated {
        space: String,
        free: u64,
        allocation: u64,
    },
    #[error("memory space {0} cannot be revoked again: its epoch is at its limit")]
    EpochExhausted(String),
    #[error("binding policy {policy}'s owner decision {decision} no longer covers it: {why}")]
    DecisionRefused {
        policy: Uuid,
        decision: String,
        why: String,
    },
}

impl From<MemoryRefusal> for ApiError {
    fn from(refusal: MemoryRefusal) -> Self {
        match refusal {
            MemoryRefusal::BadName
            | MemoryRefusal::SpaceExists(_)
            | MemoryRefusal::EmptySchema
            | MemoryRefusal::BadQuota
            | MemoryRefusal::ViewWiderThanSpace(_)
            | MemoryRefusal::BadSelector
            | MemoryRefusal::BadPublish
            | MemoryRefusal::AlreadyExpired
            | MemoryRefusal::LegacyAudience
            | MemoryRefusal::Truncated { .. }
            | MemoryRefusal::Rewritten { .. } => ApiError::InvalidSpec(refusal.to_string()),
            MemoryRefusal::UnknownSpace(_)
            | MemoryRefusal::UnknownPolicy(_)
            | MemoryRefusal::UnknownBinding(_)
            | MemoryRefusal::NoPolicyAdmits { .. }
            | MemoryRefusal::Ambiguous { .. }
            | MemoryRefusal::PolicyRevoked { .. }
            | MemoryRefusal::PolicyExpired { .. }
            | MemoryRefusal::ForeignEpoch { .. }
            | MemoryRefusal::Expired { .. }
            | MemoryRefusal::MayNotPublish(_)
            | MemoryRefusal::DecisionRefused { .. } => ApiError::Authority(refusal.to_string()),
            MemoryRefusal::QuotaFullyAllocated { .. } | MemoryRefusal::EpochExhausted(_) => {
                ApiError::CapacityExhausted(refusal.to_string())
            }
        }
    }
}

/// Re-cites a standing owner decision for one capability at `now`, returning the decision's
/// `not_after`. The node's implementation verifies the bundle against its trust roots
/// (`decision_provisioning`); `Err` names why it does not cover the capability.
pub(crate) trait DecisionCiter {
    fn cite(&self, decision: &str, capability: &str, now: u64) -> Result<u64, String>;
}

/// The capability a decision must cover to make a policy over `space`.
pub(crate) fn bind_capability(space: &SpaceId) -> String {
    format!("memory.bind:{}", space.reference())
}

/// The capability a decision must cover for that policy's bindings to publish.
pub(crate) fn publish_capability(space: &SpaceId) -> String {
    format!("memory.publish:{}", space.reference())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFile {
    schema: String,
    spaces: Vec<MemorySpace>,
    policies: Vec<BindingPolicy>,
    bindings: Vec<Binding>,
}

/// The node's record of every space, policy and live binding, persisted under the memory root.
#[derive(Debug)]
pub(crate) struct Registry {
    pub(crate) root: PathBuf,
    path: PathBuf,
    pub(crate) spaces: BTreeMap<(TenantKey, SpaceId), MemorySpace>,
    pub(crate) policies: BTreeMap<Uuid, BindingPolicy>,
    pub(crate) bindings: BTreeMap<Uuid, Binding>,
}

/// One store an earlier layout left, as migration declares it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Migrated {
    pub(crate) tenant: TenantKey,
    pub(crate) space: SpaceId,
    pub(crate) layout: &'static str,
    /// `None` when it collided with a space the tenant already has and was not migrated.
    pub(crate) policy: Option<Uuid>,
}

/// A space a tenant asks the API to declare.
pub(crate) struct SpaceRequest {
    pub(crate) name: SpaceName,
    pub(crate) schema: BTreeSet<SchemaAtom>,
    pub(crate) quota_bytes: u64,
}

/// A policy a tenant (or a decision) asks for.
pub(crate) struct PolicyRequest {
    pub(crate) audience: Audience,
    pub(crate) mode: Mode,
    pub(crate) view: ViewSpec,
    pub(crate) may_publish: bool,
    pub(crate) allocation_bytes: u64,
    pub(crate) expiry: Expiry,
    pub(crate) authority: PolicyAuthority,
}

impl Registry {
    /// Read the registry under `root`. Absent is empty; unreadable or malformed refuses the
    /// start (a space the node cannot read cannot be decided, and dropping it would be silent).
    pub(crate) fn load(root: &Path) -> Result<Self, ApiError> {
        if root.join(HELD_SHARE_REGISTRY).exists() {
            return Err(ApiError::Driver(format!(
                "memory root holds {HELD_SHARE_REGISTRY}, the SharedMemory registry of the held \
                 lineage-scoped branch; its grants are not migrated, so the node refuses to \
                 start rather than guess who may reach them"
            )));
        }
        let path = root.join(REGISTRY_FILE);
        let mut registry = Self {
            root: root.to_path_buf(),
            path,
            spaces: BTreeMap::new(),
            policies: BTreeMap::new(),
            bindings: BTreeMap::new(),
        };
        let bytes = match std::fs::read(&registry.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(registry),
            Err(e) => return Err(e.into()),
        };
        let unreadable =
            |why: &str| ApiError::Driver(format!("memory space registry is unreadable: {why}"));
        let file: RegistryFile =
            serde_json::from_slice(&bytes).map_err(|_| unreadable("not a registry"))?;
        if file.schema != REGISTRY_SCHEMA {
            return Err(unreadable("unknown schema"));
        }
        for space in file.spaces {
            if space.store().is_none() || space.schema.is_empty() {
                return Err(unreadable("malformed space"));
            }
            let key = (space.tenant.clone(), space.id.clone());
            if registry.spaces.insert(key, space).is_some() {
                return Err(unreadable("duplicate space"));
            }
        }
        for policy in file.policies {
            let Some(space) = registry
                .spaces
                .get(&(policy.tenant.clone(), policy.space.clone()))
            else {
                return Err(unreadable("policy for an unknown space"));
            };
            if policy.epoch > space.epoch {
                return Err(unreadable("policy disagrees with its space"));
            }
            if registry.policies.insert(policy.id, policy).is_some() {
                return Err(unreadable("duplicate policy"));
            }
        }
        for binding in file.bindings {
            if !registry.policies.contains_key(&binding.policy)
                || !registry
                    .spaces
                    .contains_key(&(binding.tenant.clone(), binding.space.clone()))
            {
                return Err(unreadable("binding for an unknown policy or space"));
            }
            if registry
                .bindings
                .insert(binding.binding_id, binding)
                .is_some()
            {
                return Err(unreadable("duplicate binding"));
            }
        }
        Ok(registry)
    }

    /// Replace the registry file whole: staged, synced, renamed into place, directory synced.
    pub(crate) fn persist(&self) -> Result<(), ApiError> {
        // Serialized by reference, so the registry's own maps are neither moved nor cloned.
        #[derive(Serialize)]
        struct Out<'a> {
            schema: &'a str,
            spaces: Vec<&'a MemorySpace>,
            policies: Vec<&'a BindingPolicy>,
            bindings: Vec<&'a Binding>,
        }
        let out = Out {
            schema: REGISTRY_SCHEMA,
            spaces: self.spaces.values().collect(),
            policies: self.policies.values().collect(),
            bindings: self.bindings.values().collect(),
        };
        let bytes = serde_json::to_vec_pretty(&out).map_err(|e| {
            ApiError::Driver(format!("cannot encode the memory space registry: {e}"))
        })?;
        let staged = self.root.join(format!("{REGISTRY_FILE}.staged"));
        {
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&staged)?;
            out.write_all(&bytes)?;
            out.sync_all()?;
        }
        std::fs::rename(&staged, &self.path)?;
        std::fs::File::open(&self.root)?.sync_all()?;
        Ok(())
    }

    /// Make an in-memory change durable: its receipt first, then the registry file. Either
    /// failing undoes the change and refuses it, so nothing takes effect without a kept
    /// receipt. A receipt kept for a change whose registry write then failed names a decision
    /// nothing will honour: the at-least-once side of the trade, never the silent one.
    ///
    /// Borrows the registry: a claim names what it decides by reference into it, so the caller
    /// undoes its own change once the claims are dropped.
    pub(crate) fn keep(
        &self,
        claims: &[FlowClaim<'_>],
        record: Recorder<'_>,
    ) -> Result<(), ApiError> {
        claims
            .iter()
            .try_for_each(record)
            .and_then(|()| self.persist())
    }

    /// The tenant's space `id`, or the refusal that does not say whether another tenant has one.
    pub(crate) fn space(
        &self,
        tenant: &TenantKey,
        id: &SpaceId,
    ) -> Result<&MemorySpace, MemoryRefusal> {
        self.spaces
            .get(&(tenant.clone(), id.clone()))
            .ok_or_else(|| MemoryRefusal::UnknownSpace(id.reference()))
    }

    /// The memory root's owner: every journal and directory under it must be the same uid.
    pub(crate) fn owner_uid(&self) -> Result<u32, ApiError> {
        Ok(std::fs::metadata(&self.root)?.uid())
    }

    /// Declare a named space. Only the tenant root reaches this (`memory_space_api`).
    pub(crate) fn create_space(
        &mut self,
        tenant: &TenantKey,
        request: SpaceRequest,
        now: u64,
        record: Recorder<'_>,
    ) -> Result<SpaceId, ApiError> {
        if request.schema.is_empty() {
            return Err(MemoryRefusal::EmptySchema.into());
        }
        if request.quota_bytes == 0 || request.quota_bytes > MAX_JOURNAL_BYTES {
            return Err(MemoryRefusal::BadQuota.into());
        }
        let id = SpaceId::Named { name: request.name };
        let key = (tenant.clone(), id.clone());
        if self.spaces.contains_key(&key) {
            return Err(MemoryRefusal::SpaceExists(id.reference()).into());
        }
        self.spaces.insert(
            key.clone(),
            MemorySpace {
                tenant: tenant.clone(),
                id: id.clone(),
                schema: request.schema,
                epoch: 0,
                location: Location::Spaces,
                quota_bytes: request.quota_bytes,
                high_water: None,
                origin: SpaceOrigin::Declared,
                created_unix: now,
            },
        );
        let space = &self.spaces[&key];
        let claim = FlowClaim::new(
            tenant,
            &key.1,
            now,
            FlowEvent::SpaceCreated {
                origin: space.origin,
                schema: &space.schema,
                quota_bytes: space.quota_bytes,
                epoch: space.epoch,
            },
        );
        let kept = claim_and_persist(self, claim, record);
        if let Err(e) = kept {
            self.spaces.remove(&key);
            return Err(e);
        }
        Ok(id)
    }

    /// Record a policy over the tenant's space `id`. The caller has decided the authority:
    /// the tenant root, or a decision it cited for the policy's capabilities.
    pub(crate) fn create_policy(
        &mut self,
        tenant: &TenantKey,
        id: &SpaceId,
        request: PolicyRequest,
        now: u64,
        record: Recorder<'_>,
    ) -> Result<Uuid, ApiError> {
        let space = self.space(tenant, id)?;
        check_policy(space, &request, now)?;
        let epoch = space.epoch;
        let policy = Uuid::new_v4();
        self.policies.insert(
            policy,
            BindingPolicy {
                id: policy,
                tenant: tenant.clone(),
                space: id.clone(),
                audience: request.audience,
                mode: request.mode,
                view: request.view,
                may_publish: request.may_publish,
                allocation_bytes: request.allocation_bytes,
                expiry: request.expiry,
                epoch,
                state: PolicyState::Live,
                authority: request.authority,
                issued_unix: now,
            },
        );
        let kept = {
            let made = &self.policies[&policy];
            let claim = FlowClaim::new(tenant, id, now, policy_created(made));
            claim_and_persist(self, claim, record)
        };
        if let Err(e) = kept {
            self.policies.remove(&policy);
            return Err(e);
        }
        Ok(policy)
    }

    /// Revoke one policy: no new binding from it, and its bindings are refused for new
    /// mediated operations.
    pub(crate) fn revoke_policy(
        &mut self,
        tenant: &TenantKey,
        id: &SpaceId,
        policy: Uuid,
        now: u64,
        record: Recorder<'_>,
    ) -> Result<(), ApiError> {
        let held = self
            .policies
            .get_mut(&policy)
            .filter(|p| &p.tenant == tenant && &p.space == id)
            .ok_or(MemoryRefusal::UnknownPolicy(policy))?;
        let before = held.state;
        held.state = PolicyState::Revoked { at_unix: now };
        let claim = FlowClaim::new(tenant, id, now, FlowEvent::PolicyRevoked { policy });
        let kept = claim_and_persist(self, claim, record);
        if let Err(e) = kept {
            if let Some(p) = self.policies.get_mut(&policy) {
                p.state = before;
            }
            return Err(e);
        }
        Ok(())
    }

    /// Revoke every policy and binding of space `id` issued so far, by moving it to the next
    /// epoch.
    pub(crate) fn revoke_space(
        &mut self,
        tenant: &TenantKey,
        id: &SpaceId,
        now: u64,
        record: Recorder<'_>,
    ) -> Result<u32, ApiError> {
        let key = (tenant.clone(), id.clone());
        let space = self
            .spaces
            .get_mut(&key)
            .ok_or_else(|| MemoryRefusal::UnknownSpace(id.reference()))?;
        let epoch = space
            .epoch
            .checked_add(1)
            .ok_or_else(|| MemoryRefusal::EpochExhausted(id.reference()))?;
        space.epoch = epoch;
        let claim = FlowClaim::new(tenant, id, now, FlowEvent::SpaceRevoked { epoch });
        let kept = claim_and_persist(self, claim, record);
        if let Err(e) = kept {
            if let Some(space) = self.spaces.get_mut(&key) {
                space.epoch = epoch.saturating_sub(1);
            }
            return Err(e);
        }
        Ok(epoch)
    }

    /// The tenant's spaces with their policies, for the API.
    pub(crate) fn spaces_of(&self, tenant: &TenantKey) -> serde_json::Value {
        let spaces: Vec<serde_json::Value> = self
            .spaces
            .values()
            .filter(|s| &s.tenant == tenant)
            .map(|s| {
                let policies: Vec<&BindingPolicy> = self
                    .policies
                    .values()
                    .filter(|p| &p.tenant == tenant && p.space == s.id)
                    .collect();
                serde_json::json!({
                    "space": s.id.reference(),
                    "schema": s.schema,
                    "epoch": s.epoch,
                    "quota_bytes": s.quota_bytes,
                    "high_water": s.high_water,
                    "origin": s.origin,
                    "policies": policies,
                })
            })
            .collect();
        serde_json::Value::Array(spaces)
    }

    /// The space a pod asking for `name` is bound to, and the policy that admits it.
    ///
    /// The tenant's declared (or migrated) space of that name if there is one: its policies
    /// decide, and none admitting the pod is a refusal by name, never a silent swap for an
    /// empty lineage store the pod did not ask for. Otherwise the lineage's own space for the
    /// name, created on first use with its `Lineage(root)` policy (receipted).
    pub(crate) fn resolve(
        &mut self,
        tenant: &TenantKey,
        name: &SpaceName,
        pod: &PodMatch<'_>,
        now: u64,
        record: Recorder<'_>,
    ) -> Result<(SpaceId, Uuid), ApiError> {
        let named = SpaceId::Named { name: name.clone() };
        let id = if self.spaces.contains_key(&(tenant.clone(), named.clone())) {
            named
        } else {
            let lineage = SpaceId::Lineage {
                root: pod.lineage,
                name: name.clone(),
            };
            if !self.spaces.contains_key(&(tenant.clone(), lineage.clone())) {
                self.create_lineage_space(tenant, &lineage, pod.lineage, now, record)?;
            }
            lineage
        };
        let policy = self.choose(tenant, &id, pod, now)?;
        Ok((id, policy))
    }

    /// The live policy of space `id` that admits `pod`, by audience precedence.
    fn choose(
        &self,
        tenant: &TenantKey,
        id: &SpaceId,
        pod: &PodMatch<'_>,
        now: u64,
    ) -> Result<Uuid, MemoryRefusal> {
        let space = self.space(tenant, id)?;
        let mut live: Vec<&BindingPolicy> = Vec::new();
        let mut dead: Option<MemoryRefusal> = None;
        for policy in self
            .policies
            .values()
            .filter(|p| &p.tenant == tenant && &p.space == id && p.audience.admits(pod))
        {
            match policy_liveness(policy, space, now) {
                Ok(()) => live.push(policy),
                Err(refusal) => {
                    dead.get_or_insert(refusal);
                }
            }
        }
        let Some(best) = live.iter().map(|p| p.audience.precedence()).min() else {
            return Err(dead.unwrap_or_else(|| MemoryRefusal::NoPolicyAdmits {
                space: id.reference(),
            }));
        };
        let mut tier = live.into_iter().filter(|p| p.audience.precedence() == best);
        let first = tier
            .next()
            .map(|p| p.id)
            .ok_or_else(|| MemoryRefusal::NoPolicyAdmits {
                space: id.reference(),
            })?;
        if let Some(second) = tier.next() {
            return Err(MemoryRefusal::Ambiguous {
                space: id.reference(),
                first,
                second: second.id,
            });
        }
        Ok(first)
    }

    fn create_lineage_space(
        &mut self,
        tenant: &TenantKey,
        id: &SpaceId,
        root: Uuid,
        now: u64,
        record: Recorder<'_>,
    ) -> Result<(), ApiError> {
        let key = (tenant.clone(), id.clone());
        let policy = Uuid::new_v4();
        self.spaces.insert(
            key.clone(),
            MemorySpace {
                tenant: tenant.clone(),
                id: id.clone(),
                schema: SchemaAtom::ALL.into_iter().collect(),
                epoch: 0,
                location: Location::Spaces,
                quota_bytes: MAX_JOURNAL_BYTES,
                high_water: None,
                origin: SpaceOrigin::LineageDefault,
                created_unix: now,
            },
        );
        self.policies.insert(
            policy,
            default_policy(
                policy,
                tenant,
                id,
                Audience::Lineage { root },
                PolicyAuthority::LineageDefault,
                now,
            ),
        );
        let kept = {
            let space = &self.spaces[&key];
            let made = &self.policies[&policy];
            let claims = [
                FlowClaim::new(
                    tenant,
                    id,
                    now,
                    FlowEvent::SpaceCreated {
                        origin: space.origin,
                        schema: &space.schema,
                        quota_bytes: space.quota_bytes,
                        epoch: space.epoch,
                    },
                ),
                FlowClaim::new(tenant, id, now, policy_created(made)),
            ];
            self.keep(&claims, record)
        };
        if let Err(e) = kept {
            self.spaces.remove(&key);
            self.policies.remove(&policy);
            return Err(e);
        }
        Ok(())
    }

    /// Declare every store an earlier layout left under the root, once, in memory:
    /// [`Self::commit_migration`] writes it after the receipts are kept.
    ///
    /// * `<root>/<tenant>/<name>` (owner-keyed: every lineage of the tenant reached it) becomes
    ///   the tenant's named space, in place, with one `TenantAllLegacy` policy. Its reach is
    ///   kept and declared; its writes now go to each run's private branch until published,
    ///   which narrows and never widens.
    /// * `<root>/lineage/<tenant>/<root>/<name>` (the held #3451 layout: one lineage reached it)
    ///   becomes that lineage's space, in place, with its default `Lineage(root)` policy.
    ///
    /// A store the registry already records is left exactly as recorded (revoked, narrowed or
    /// not), so running this twice changes nothing and never re-widens. A store whose space id
    /// the tenant already holds elsewhere is not migrated (that would merge two stores); it is
    /// reported and stays unreachable, which narrows rather than widens.
    pub(crate) fn migrate(&mut self, now: u64) -> Result<Vec<Migrated>, ApiError> {
        let mut found: Vec<(TenantKey, SpaceId, Location)> = Vec::new();
        for (tenant, dir) in tenant_dirs(&self.root)? {
            for name in subdirectories(&dir)? {
                if let Ok(name) = SpaceName::new(&name) {
                    found.push((tenant.clone(), SpaceId::Named { name }, Location::Legacy));
                }
            }
        }
        let held = self.root.join("lineage");
        if held.is_dir() {
            for (tenant, dir) in tenant_dirs(&held)? {
                for root in subdirectories(&dir)? {
                    let Ok(root) = Uuid::parse_str(&root) else {
                        continue;
                    };
                    for name in subdirectories(&dir.join(root.to_string()))? {
                        if let Ok(name) = SpaceName::new(&name) {
                            found.push((
                                tenant.clone(),
                                SpaceId::Lineage { root, name },
                                Location::HeldLineage,
                            ));
                        }
                    }
                }
            }
        }
        let mut migrated = Vec::new();
        for (tenant, id, location) in found {
            let layout = match location {
                Location::Legacy => "owner-keyed",
                Location::HeldLineage => "lineage-scoped",
                Location::Spaces => "spaces",
            };
            let key = (tenant.clone(), id.clone());
            match self.spaces.get(&key) {
                Some(space) if space.location == location => continue,
                Some(_) => {
                    migrated.push(Migrated {
                        tenant,
                        space: id,
                        layout,
                        policy: None,
                    });
                    continue;
                }
                None => {}
            }
            let (origin, audience) = match (&id, location) {
                (SpaceId::Lineage { root, .. }, _) => (
                    SpaceOrigin::MigratedHeldLineage,
                    Audience::Lineage { root: *root },
                ),
                (SpaceId::Named { .. }, _) => {
                    (SpaceOrigin::MigratedLegacy, Audience::TenantAllLegacy)
                }
            };
            let policy = migration_policy_id(&tenant, &id);
            self.spaces.insert(
                key,
                MemorySpace {
                    tenant: tenant.clone(),
                    id: id.clone(),
                    schema: SchemaAtom::ALL.into_iter().collect(),
                    epoch: 0,
                    location,
                    quota_bytes: MAX_JOURNAL_BYTES,
                    high_water: None,
                    origin,
                    created_unix: now,
                },
            );
            self.policies.insert(
                policy,
                default_policy(
                    policy,
                    &tenant,
                    &id,
                    audience,
                    PolicyAuthority::Migration,
                    now,
                ),
            );
            migrated.push(Migrated {
                tenant,
                space: id,
                layout,
                policy: Some(policy),
            });
        }
        Ok(migrated)
    }

    /// The receipt of one migration decision.
    pub(crate) fn migration_claim<'a>(&'a self, event: &'a Migrated, now: u64) -> FlowClaim<'a> {
        let flow = match event.policy.and_then(|id| self.policies.get(&id)) {
            Some(policy) => FlowEvent::Migrated {
                layout: event.layout,
                policy: policy.id,
                audience: &policy.audience,
            },
            None => FlowEvent::MigrationSkipped {
                layout: event.layout,
            },
        };
        FlowClaim::new(&event.tenant, &event.space, now, flow)
    }

    /// Write what [`Self::migrate`] recorded, once its receipts are kept. Until then the
    /// migration is in memory only, so a start that fails between the two re-migrates the same
    /// stores under the same policy ids.
    pub(crate) fn commit_migration(&self, migrated: &[Migrated]) -> Result<(), ApiError> {
        if migrated.iter().all(|m| m.policy.is_none()) {
            return Ok(());
        }
        self.persist()
    }
}

/// Receipt, then registry; the caller undoes on `Err`.
fn claim_and_persist(
    registry: &Registry,
    claim: FlowClaim<'_>,
    record: Recorder<'_>,
) -> Result<(), ApiError> {
    registry.keep(&[claim], record)
}

fn policy_created(policy: &BindingPolicy) -> FlowEvent<'_> {
    FlowEvent::PolicyCreated {
        policy: policy.id,
        audience: &policy.audience,
        mode: policy.mode,
        view: &policy.view,
        may_publish: policy.may_publish,
        allocation_bytes: policy.allocation_bytes,
        expiry: policy.expiry,
        authority: &policy.authority,
        epoch: policy.epoch,
    }
}

/// The policy a lineage default or a migration records: read and propose, everything visible,
/// may publish with the default allocation, until revoked.
fn default_policy(
    id: Uuid,
    tenant: &TenantKey,
    space: &SpaceId,
    audience: Audience,
    authority: PolicyAuthority,
    now: u64,
) -> BindingPolicy {
    BindingPolicy {
        id,
        tenant: tenant.clone(),
        space: space.clone(),
        audience,
        mode: Mode::ReadPropose,
        view: ViewSpec::everything(),
        may_publish: true,
        allocation_bytes: DEFAULT_ALLOCATION_BYTES,
        expiry: Expiry::UntilRevoked,
        epoch: 0,
        state: PolicyState::Live,
        authority,
        issued_unix: now,
    }
}

/// Whether `policy` admits anything now, or the refusal naming why not.
pub(crate) fn policy_liveness(
    policy: &BindingPolicy,
    space: &MemorySpace,
    now: u64,
) -> Result<(), MemoryRefusal> {
    match policy.state {
        PolicyState::Live => {}
        PolicyState::Revoked { .. } => {
            return Err(MemoryRefusal::PolicyRevoked { policy: policy.id });
        }
    }
    if policy.epoch != space.epoch {
        return Err(MemoryRefusal::PolicyRevoked { policy: policy.id });
    }
    if policy.expiry.passed(now) {
        return Err(MemoryRefusal::PolicyExpired { policy: policy.id });
    }
    Ok(())
}

fn check_policy(
    space: &MemorySpace,
    request: &PolicyRequest,
    now: u64,
) -> Result<(), MemoryRefusal> {
    match &request.audience {
        Audience::Workspace { selector } => {
            if selector.is_empty()
                || selector.len() > MAX_SELECTOR
                || selector.iter().any(|(k, v)| k.is_empty() || v.is_empty())
            {
                return Err(MemoryRefusal::BadSelector);
            }
        }
        Audience::TenantAllLegacy => return Err(MemoryRefusal::LegacyAudience),
        Audience::Lineage { .. } | Audience::TenantAll => {}
    }
    let space_view = View {
        scope: space.kernel_scope(),
        ceiling: LabelRank::Secret,
    };
    if nucleus_memory_context::restrict(space_view, request.view.kernel()).is_none() {
        return Err(MemoryRefusal::ViewWiderThanSpace(space.id.reference()));
    }
    let publishes = match request.mode {
        Mode::Read => false,
        Mode::ReadPropose => request.may_publish,
    };
    if request.may_publish != publishes || publishes != (request.allocation_bytes > 0) {
        return Err(MemoryRefusal::BadPublish);
    }
    if request.allocation_bytes > space.quota_bytes {
        return Err(MemoryRefusal::BadQuota);
    }
    if request.expiry.passed(now) {
        return Err(MemoryRefusal::AlreadyExpired);
    }
    Ok(())
}

/// The 64-hex tenant directories directly under `dir`, sorted.
fn tenant_dirs(dir: &Path) -> Result<Vec<(TenantKey, PathBuf)>, ApiError> {
    let mut tenants = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let Some(tenant) = entry.file_name().to_str().and_then(TenantKey::from_hex) else {
            continue;
        };
        if entry.file_type()?.is_dir() {
            tenants.push((tenant, entry.path()));
        }
    }
    tenants.sort();
    Ok(tenants)
}

/// The UTF-8 names of the directories directly under `dir`, sorted.
fn subdirectories(dir: &Path) -> Result<Vec<String>, ApiError> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str()
            && entry.file_type()?.is_dir()
        {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

/// A migrated policy's id is derived from what it migrates, so a migration interrupted between
/// its receipt and its registry write re-issues the SAME decision, not a second one.
fn migration_policy_id(tenant: &TenantKey, space: &SpaceId) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(b"nucleus/memory-migration/v2\0");
    hasher.update(tenant.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(space.reference().as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_custom_bytes(bytes).into_uuid()
}

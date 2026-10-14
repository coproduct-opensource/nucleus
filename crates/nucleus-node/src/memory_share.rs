//! Cross-lineage persistent memory: the `SharedMemory` grant (C2).
//!
//! # The flow this closes
//!
//! A persistent memory store used to be keyed by `sha256(owner)/namespace`, where the owner is the
//! root identity of the pod's certificate (its tenant, ADR 0001). Every pod of a tenant that asked
//! for namespace `N` was handed the same directory, so two pods in unrelated lineages — siblings
//! that cannot list, read or cancel each other through the pod API (`pod_api::caller_may_manage`)
//! — could still pass data through memory. That is a cross-pod flow outside lineage, which is
//! exactly what C2 ("nor those of any other pod") excludes.
//!
//! # The design (owner decision 2026-10-13)
//!
//! * **Lineage-scoped by default.** A store is keyed `(tenant, lineage root, namespace)`
//!   (`memory_provisioning`). The lineage root is a fold of the parent edge the node records at
//!   creation (`pod_api::parent_for_create`, the fact `caller_may_manage` and the pod view read),
//!   so there is one decider for "which lineage", not two.
//! * **Cross-lineage sharing only through a declared channel.** A [`SharedMemoryGrant`] is minted
//!   by the tenant's root identity and names a share, the namespace it serves, its readers and
//!   writers (lineages, or the tenant root meaning every lineage of that tenant) and an explicit
//!   expiry. It can be attenuated — narrowed, never widened — and revoked by bumping its share's
//!   epoch. A pod reaches a share only by presenting the grant by id ([`GRANT_LABEL`]).
//! * **Every exercise is receipted.** Attaching a pod to a share, and every mint, attenuation,
//!   revocation and migration, is a node-signed [`FlowClaim`] appended to the node's own
//!   `lifecycle.log` — outside every pod's reach — under the node's root key with its own domain
//!   tag (`PodAuthority::sign_memory_flow`).
//! * **Migration is declared, not silent.** At start, every store left in the old owner-keyed
//!   layout was by construction shared across lineages. Each becomes an explicit migrated grant
//!   (writers = the tenant root, until revoked) recorded once and receipted. Migration never
//!   re-creates a grant it already recorded, so a revoked migrated grant stays revoked.
//!
//! # What a grant does NOT change
//!
//! The journal's records are untouched: every record keeps the IFC label the proxy persisted
//! with it, and a reader's snapshot is a byte prefix of the share's journal, so taint survives
//! the crossing. A grant decides who may attach; what the attached pod may do with a labelled
//! record is still the proxy's flow decision.
use crate::ApiError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
use uuid::Uuid;

/// Records a decision's signed receipt before the decision takes effect (`record`, bound to the
/// node's state dir and authority by its caller).
pub(crate) type Recorder<'r> = &'r mut dyn FnMut(&FlowClaim<'_>) -> Result<(), ApiError>;

/// The label a pod presents a grant by: the grant's id.
pub(crate) const GRANT_LABEL: &str = "nucleus.io/memory-grant";
const REGISTRY_FILE: &str = "shares.json";
const REGISTRY_SCHEMA: &str = "nucleus.memory-shares.v1";
const FLOW_SCHEMA: &str = "nucleus.memory-flow.v1";

/// A namespace or share name: 1 to 64 ASCII letters, digits, underscores or hyphens. The one
/// spelling check for every name that becomes a path segment.
pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// A tenant, as the hex SHA-256 of its root identity: the key the store layout has always used.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct TenantKey(String);

impl TenantKey {
    /// The tenant whose root identity is `root_identity`.
    pub(crate) fn of(root_identity: &str) -> Self {
        Self(hex::encode(Sha256::digest(root_identity.as_bytes())))
    }
    /// A directory name in the legacy owner-keyed layout, if it is one.
    fn from_hex(name: &str) -> Option<Self> {
        (name.len() == 64 && name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
            .then(|| Self(name.to_owned()))
    }
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Who a grant names. `TenantRoot` is every lineage of the grant's tenant; there is no variant
/// for another tenant, so a cross-tenant share is not representable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", content = "root", rename_all = "snake_case")]
pub(crate) enum Holder {
    TenantRoot,
    Lineage(Uuid),
}

/// When a grant stops being honoured. Explicit in both cases: there is no "absent means
/// forever" (ADR 0007 B-2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "unix", rename_all = "snake_case")]
pub(crate) enum Expiry {
    At(u64),
    UntilRevoked,
}

impl Expiry {
    fn passed(self, now: u64) -> bool {
        match self {
            Expiry::At(at) => now >= at,
            Expiry::UntilRevoked => false,
        }
    }
    /// Whether `self` ends no later than `parent`.
    fn within(self, parent: Expiry) -> bool {
        match (self, parent) {
            (_, Expiry::UntilRevoked) => true,
            (Expiry::At(child), Expiry::At(parent)) => child <= parent,
            (Expiry::UntilRevoked, Expiry::At(_)) => false,
        }
    }
}

/// How a grant came to exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "from", rename_all = "snake_case")]
pub(crate) enum Origin {
    /// Minted by the tenant root through the issuing API.
    Minted,
    /// Recorded at node start for a store the owner-keyed layout already shared.
    Migrated,
    /// Narrowed from the named grant.
    Attenuated(Uuid),
}

/// What attaching under a grant lets a pod do to the share.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Access {
    /// A snapshot of the share's journal: nothing the pod writes reaches the share.
    Read,
    /// The share's journal itself.
    ReadWrite,
}

/// Where a share's journal lives under the memory root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Location {
    /// `<root>/<tenant>/<namespace>`: a store from the owner-keyed layout, kept in place so its
    /// journal header still matches.
    Legacy,
    /// `<root>/shares/<tenant>/<share>`.
    Share,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Share {
    tenant: TenantKey,
    name: String,
    namespace: String,
    /// Grants issued at an earlier epoch are revoked.
    epoch: u64,
    location: Location,
}

/// A capability to attach to one share. Minted only by [`Registry`] — by the tenant root through
/// the issuing API, by attenuating another grant, or by migration — so its constructor is this
/// module's (ADR 0007 C-1). Not `Clone` and no `Default` (C-5, B-1).
///
/// `Deserialize` is a constructor too: it is reached only by [`Registry::load`], reading the
/// node-private registry file the node itself wrote.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SharedMemoryGrant {
    id: Uuid,
    tenant: TenantKey,
    share: String,
    namespace: String,
    readers: BTreeSet<Holder>,
    writers: BTreeSet<Holder>,
    expiry: Expiry,
    epoch: u64,
    origin: Origin,
    issued_unix: u64,
}

fn covers(set: &BTreeSet<Holder>, holder: Holder) -> bool {
    set.contains(&Holder::TenantRoot) || set.contains(&holder)
}

impl SharedMemoryGrant {
    /// What `lineage` may do under this grant, if it is named at all. A writer reads too.
    fn access_for(&self, lineage: Uuid) -> Option<Access> {
        let holder = Holder::Lineage(lineage);
        if covers(&self.writers, holder) {
            Some(Access::ReadWrite)
        } else if covers(&self.readers, holder) {
            Some(Access::Read)
        } else {
            None
        }
    }

    /// The narrowing check: every holder of `narrower` is a holder of `self` at the same or a
    /// stronger access, and `narrower` ends no later. The first widening found is named.
    fn admits_narrowing(&self, narrower: &Narrowing) -> Result<(), Widening> {
        for holder in &narrower.writers {
            if !(covers(&self.writers, *holder)) {
                return Err(Widening::Writer(*holder));
            }
        }
        for holder in &narrower.readers {
            if !(covers(&self.writers, *holder) || covers(&self.readers, *holder)) {
                return Err(Widening::Reader(*holder));
            }
        }
        if !narrower.expiry.within(self.expiry) {
            return Err(Widening::Expiry);
        }
        Ok(())
    }

    fn view(&self) -> GrantView<'_> {
        GrantView {
            id: self.id,
            share: &self.share,
            namespace: &self.namespace,
            readers: &self.readers,
            writers: &self.writers,
            expiry: self.expiry,
            epoch: self.epoch,
            origin: self.origin,
            issued_unix: self.issued_unix,
        }
    }
}

/// A grant as the issuing API reports it.
#[derive(Debug, Serialize)]
pub(crate) struct GrantView<'a> {
    id: Uuid,
    share: &'a str,
    namespace: &'a str,
    readers: &'a BTreeSet<Holder>,
    writers: &'a BTreeSet<Holder>,
    expiry: Expiry,
    epoch: u64,
    origin: Origin,
    issued_unix: u64,
}

/// The holders and expiry of a grant being minted or narrowed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Narrowing {
    pub(crate) readers: BTreeSet<Holder>,
    pub(crate) writers: BTreeSet<Holder>,
    pub(crate) expiry: Expiry,
}

/// An attenuation that would have widened its parent, by what it widened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Widening {
    #[error("names {0:?} as a writer, which the parent grant does not")]
    Writer(Holder),
    #[error("names {0:?} as a reader, which the parent grant does not")]
    Reader(Holder),
    #[error("outlives the parent grant")]
    Expiry,
}

/// Why a presented grant was not honoured, by name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Refusal {
    /// Absent, or another tenant's: the same answer, so a grant id is no oracle across tenants.
    #[error("SharedMemory grant {0} is not held by this tenant")]
    Unknown(Uuid),
    #[error(
        "SharedMemory grant {grant} is revoked: share {share} is at epoch {current}, the grant was issued at {issued}"
    )]
    Revoked {
        grant: Uuid,
        share: String,
        issued: u64,
        current: u64,
    },
    #[error("SharedMemory grant {grant} expired at {at}")]
    Expired { grant: Uuid, at: u64 },
    #[error("SharedMemory grant {grant} is for namespace {granted}, not {requested}")]
    Namespace {
        grant: Uuid,
        granted: String,
        requested: String,
    },
    #[error("SharedMemory grant {grant} does not name lineage {lineage}")]
    NotNamed { grant: Uuid, lineage: Uuid },
    #[error("SharedMemory grant {grant} cannot be narrowed: the attenuation {widening}")]
    Widens { grant: Uuid, widening: Widening },
    #[error("a SharedMemory grant must name at least one reader or writer")]
    NamesNobody,
    #[error("a SharedMemory grant's expiry must be in the future")]
    AlreadyExpired,
    #[error("share {share} serves namespace {serves}, not {requested}")]
    ShareNamespace {
        share: String,
        serves: String,
        requested: String,
    },
    #[error(
        "share and namespace names must be 1 to 64 ASCII letters, digits, underscores or hyphens"
    )]
    BadName,
    #[error("share {0} is not held by this tenant")]
    UnknownShare(String),
}

impl From<Refusal> for ApiError {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::NamesNobody
            | Refusal::AlreadyExpired
            | Refusal::BadName
            | Refusal::ShareNamespace { .. } => ApiError::InvalidSpec(refusal.to_string()),
            Refusal::Unknown(_)
            | Refusal::UnknownShare(_)
            | Refusal::Revoked { .. }
            | Refusal::Expired { .. }
            | Refusal::Namespace { .. }
            | Refusal::NotNamed { .. }
            | Refusal::Widens { .. } => ApiError::Authority(refusal.to_string()),
        }
    }
}

/// A grant that was honoured, carrying exactly what provisioning needs. Minted only by
/// [`Registry::exercise`] and [`Registry::legacy`], so a share directory is reachable only from a
/// decided grant.
#[derive(Debug)]
#[must_use = "an exercised grant names the share a pod attaches to"]
pub(crate) struct Exercised {
    pub(crate) grant: Uuid,
    pub(crate) share: String,
    pub(crate) namespace: String,
    pub(crate) access: Access,
    pub(crate) epoch: u64,
    pub(crate) origin: Origin,
    location: Location,
}

impl Exercised {
    /// The share's journal directory, and the namespace its journal header carries.
    pub(crate) fn store(&self, tenant: &TenantKey) -> (Vec<String>, String) {
        match self.location {
            Location::Legacy => (
                vec![tenant.as_str().to_owned(), self.share.clone()],
                format!("{}/{}", tenant.as_str(), self.share),
            ),
            Location::Share => (
                vec![
                    "shares".into(),
                    tenant.as_str().to_owned(),
                    self.share.clone(),
                ],
                format!("share/{}/{}", tenant.as_str(), self.share),
            ),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFile {
    schema: String,
    shares: Vec<Share>,
    grants: Vec<SharedMemoryGrant>,
}

/// The node's record of every share and grant, persisted under the memory root.
#[derive(Debug)]
pub(crate) struct Registry {
    path: PathBuf,
    shares: BTreeMap<(TenantKey, String), Share>,
    grants: BTreeMap<Uuid, SharedMemoryGrant>,
}

/// One migrated store, as the receipt names it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Migrated {
    pub(crate) tenant: TenantKey,
    pub(crate) namespace: String,
    pub(crate) grant: Uuid,
}

impl Registry {
    /// Read the registry under `root`. Absent is empty; unreadable or malformed refuses the start
    /// (a share the node cannot read cannot be decided, and dropping it would be silent).
    pub(crate) fn load(root: &Path) -> Result<Self, ApiError> {
        let path = root.join(REGISTRY_FILE);
        let mut registry = Self {
            path,
            shares: BTreeMap::new(),
            grants: BTreeMap::new(),
        };
        let bytes = match std::fs::read(&registry.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(registry),
            Err(e) => return Err(e.into()),
        };
        let unreadable =
            |why: &str| ApiError::Driver(format!("memory share registry is unreadable: {why}"));
        let file: RegistryFile =
            serde_json::from_slice(&bytes).map_err(|_| unreadable("not a registry"))?;
        if file.schema != REGISTRY_SCHEMA {
            return Err(unreadable("unknown schema"));
        }
        for share in file.shares {
            if TenantKey::from_hex(share.tenant.as_str()).is_none()
                || !valid_name(&share.name)
                || !valid_name(&share.namespace)
            {
                return Err(unreadable("malformed share"));
            }
            let key = (share.tenant.clone(), share.name.clone());
            if registry.shares.insert(key, share).is_some() {
                return Err(unreadable("duplicate share"));
            }
        }
        for grant in file.grants {
            let Some(share) = registry
                .shares
                .get(&(grant.tenant.clone(), grant.share.clone()))
            else {
                return Err(unreadable("grant for an unknown share"));
            };
            if share.namespace != grant.namespace || grant.epoch > share.epoch {
                return Err(unreadable("grant disagrees with its share"));
            }
            if registry.grants.insert(grant.id, grant).is_some() {
                return Err(unreadable("duplicate grant"));
            }
        }
        Ok(registry)
    }

    /// Replace the registry file whole: staged, synced, renamed into place, directory synced.
    fn persist(&self) -> Result<(), ApiError> {
        // Serialized by reference, so the registry's own maps are neither moved nor cloned.
        #[derive(Serialize)]
        struct Out<'a> {
            schema: &'a str,
            shares: Vec<&'a Share>,
            grants: Vec<&'a SharedMemoryGrant>,
        }
        let out = Out {
            schema: REGISTRY_SCHEMA,
            shares: self.shares.values().collect(),
            grants: self.grants.values().collect(),
        };
        let bytes = serde_json::to_vec_pretty(&out).map_err(|e| {
            ApiError::Driver(format!("cannot encode the memory share registry: {e}"))
        })?;
        let parent = self
            .path
            .parent()
            .ok_or_else(|| ApiError::Driver("memory share registry has no parent".into()))?;
        let staged = parent.join(format!("{REGISTRY_FILE}.staged"));
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
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    fn live(&self, grant: &SharedMemoryGrant, now: u64) -> Result<&Share, Refusal> {
        let share = self
            .shares
            .get(&(grant.tenant.clone(), grant.share.clone()))
            .ok_or(Refusal::Unknown(grant.id))?;
        if grant.epoch < share.epoch {
            return Err(Refusal::Revoked {
                grant: grant.id,
                share: grant.share.clone(),
                issued: grant.epoch,
                current: share.epoch,
            });
        }
        if let Expiry::At(at) = grant.expiry
            && now >= at
        {
            return Err(Refusal::Expired {
                grant: grant.id,
                at,
            });
        }
        Ok(share)
    }

    /// Decide a grant a pod presented: held by its tenant, live, for the namespace it asked for,
    /// and naming its lineage.
    pub(crate) fn exercise(
        &self,
        presented: Uuid,
        tenant: &TenantKey,
        lineage: Uuid,
        namespace: &str,
        now: u64,
    ) -> Result<Exercised, Refusal> {
        let grant = self
            .grants
            .get(&presented)
            .filter(|g| &g.tenant == tenant)
            .ok_or(Refusal::Unknown(presented))?;
        let share = self.live(grant, now)?;
        if grant.namespace != namespace {
            return Err(Refusal::Namespace {
                grant: grant.id,
                granted: grant.namespace.clone(),
                requested: namespace.to_owned(),
            });
        }
        let access = grant.access_for(lineage).ok_or(Refusal::NotNamed {
            grant: grant.id,
            lineage,
        })?;
        Ok(Exercised {
            grant: grant.id,
            share: share.name.clone(),
            namespace: grant.namespace.clone(),
            access,
            epoch: grant.epoch,
            origin: grant.origin,
            location: share.location,
        })
    }

    /// The migrated grant a pod that presents none reaches for `namespace`, if migration recorded
    /// one for its tenant: the declared form of the sharing the owner-keyed layout did implicitly.
    /// A revoked or expired migrated grant is refused by name, never silently swapped for an
    /// empty lineage store the pod did not ask for.
    pub(crate) fn legacy(
        &self,
        tenant: &TenantKey,
        lineage: Uuid,
        namespace: &str,
        now: u64,
    ) -> Option<Result<Exercised, Refusal>> {
        let grant = self.grants.values().find(|g| {
            g.origin == Origin::Migrated && &g.tenant == tenant && g.namespace == namespace
        })?;
        Some(self.exercise(grant.id, tenant, lineage, namespace, now))
    }

    /// Make an in-memory change durable: its receipt first, then the registry file. Either
    /// failing undoes the change and refuses it, so no grant is honoured without a kept receipt.
    /// A receipt kept for a change whose registry write then failed names a grant nothing will
    /// ever honour: that is the at-least-once side of the trade, never the silent one.
    fn commit(
        &mut self,
        claim: &FlowClaim<'_>,
        record: Recorder<'_>,
        undo: impl FnOnce(&mut Self),
    ) -> Result<(), ApiError> {
        let kept = record(claim).and_then(|()| self.persist());
        if let Err(e) = kept {
            undo(self);
            return Err(e);
        }
        Ok(())
    }

    /// Mint a grant on `share` (creating it for `namespace` if the tenant has none of that name).
    /// Only the tenant root reaches this (`memory_share_api`).
    pub(crate) fn mint(
        &mut self,
        tenant: &TenantKey,
        share: &str,
        namespace: &str,
        holders: Narrowing,
        now: u64,
        record: Recorder<'_>,
    ) -> Result<Uuid, ApiError> {
        if !valid_name(share) || !valid_name(namespace) {
            return Err(Refusal::BadName.into());
        }
        check_holders(&holders, now)?;
        let key = (tenant.clone(), share.to_owned());
        let created = match self.shares.get(&key) {
            Some(existing) if existing.namespace != namespace => {
                return Err(Refusal::ShareNamespace {
                    share: share.to_owned(),
                    serves: existing.namespace.clone(),
                    requested: namespace.to_owned(),
                }
                .into());
            }
            Some(_) => false,
            None => {
                self.shares.insert(
                    key.clone(),
                    Share {
                        tenant: tenant.clone(),
                        name: share.to_owned(),
                        namespace: namespace.to_owned(),
                        epoch: 0,
                        location: Location::Share,
                    },
                );
                true
            }
        };
        let epoch = self.shares[&key].epoch;
        let id = Uuid::new_v4();
        self.grants.insert(
            id,
            SharedMemoryGrant {
                id,
                tenant: tenant.clone(),
                share: share.to_owned(),
                namespace: namespace.to_owned(),
                readers: holders.readers,
                writers: holders.writers,
                expiry: holders.expiry,
                epoch,
                origin: Origin::Minted,
                issued_unix: now,
            },
        );
        let claim = FlowClaim::new(
            FlowEvent::Mint,
            tenant,
            Some(id),
            share,
            namespace,
            epoch,
            now,
        );
        self.commit(&claim, record, |this| {
            this.grants.remove(&id);
            if created {
                this.shares.remove(&key);
            }
        })?;
        Ok(id)
    }

    /// Narrow `parent` into a new grant. The parent must be live and the narrowing must not widen
    /// it in any holder, access or expiry.
    pub(crate) fn attenuate(
        &mut self,
        tenant: &TenantKey,
        parent: Uuid,
        narrower: Narrowing,
        now: u64,
        record: Recorder<'_>,
    ) -> Result<Uuid, ApiError> {
        let grant = self
            .grants
            .get(&parent)
            .filter(|g| &g.tenant == tenant)
            .ok_or(Refusal::Unknown(parent))?;
        self.live(grant, now)?;
        check_holders(&narrower, now)?;
        grant
            .admits_narrowing(&narrower)
            .map_err(|widening| Refusal::Widens {
                grant: parent,
                widening,
            })?;
        let id = Uuid::new_v4();
        let (share, namespace, epoch) = (grant.share.clone(), grant.namespace.clone(), grant.epoch);
        self.grants.insert(
            id,
            SharedMemoryGrant {
                id,
                tenant: tenant.clone(),
                share: share.clone(),
                namespace: namespace.clone(),
                readers: narrower.readers,
                writers: narrower.writers,
                expiry: narrower.expiry,
                epoch,
                origin: Origin::Attenuated(parent),
                issued_unix: now,
            },
        );
        let claim = FlowClaim::new(
            FlowEvent::Attenuate,
            tenant,
            Some(id),
            &share,
            &namespace,
            epoch,
            now,
        );
        self.commit(&claim, record, |this| {
            this.grants.remove(&id);
        })?;
        Ok(id)
    }

    /// Revoke every grant on `share` issued so far, by moving the share to the next epoch. Its
    /// receipt names the share and the new epoch; no single grant is the subject.
    pub(crate) fn revoke(
        &mut self,
        tenant: &TenantKey,
        share: &str,
        now: u64,
        record: Recorder<'_>,
    ) -> Result<u64, ApiError> {
        let key = (tenant.clone(), share.to_owned());
        let current = self
            .shares
            .get_mut(&key)
            .ok_or_else(|| Refusal::UnknownShare(share.to_owned()))?;
        current.epoch += 1;
        let (epoch, namespace) = (current.epoch, current.namespace.clone());
        let claim = FlowClaim::new(
            FlowEvent::Revoke,
            tenant,
            None,
            share,
            &namespace,
            epoch,
            now,
        );
        self.commit(&claim, record, |this| {
            if let Some(current) = this.shares.get_mut(&key) {
                current.epoch -= 1;
            }
        })?;
        Ok(epoch)
    }

    /// The tenant's grants, for the issuing API.
    pub(crate) fn grants_of<'a>(&'a self, tenant: &'a TenantKey) -> Vec<GrantView<'a>> {
        self.grants
            .values()
            .filter(|g| &g.tenant == tenant)
            .map(SharedMemoryGrant::view)
            .collect()
    }

    /// Convert every store in the owner-keyed layout under `root` into a migrated grant, once,
    /// in memory: [`Self::commit_migration`] writes it after the receipts are kept.
    ///
    /// A store the registry already records a share for is left exactly as recorded — revoked,
    /// narrowed or not — so running this twice changes nothing and never re-widens. A legacy
    /// directory whose name collides with a share the tenant minted is not migrated (that would
    /// merge two stores); it is reported, and stays unreachable, which narrows rather than widens.
    pub(crate) fn migrate(
        &mut self,
        root: &Path,
        now: u64,
    ) -> Result<(Vec<Migrated>, Vec<Migrated>), ApiError> {
        let mut migrated = Vec::new();
        let mut skipped = Vec::new();
        let mut tenants: Vec<(TenantKey, PathBuf)> = Vec::new();
        for entry in std::fs::read_dir(root)? {
            let entry = entry?;
            let Some(tenant) = entry.file_name().to_str().and_then(TenantKey::from_hex) else {
                continue;
            };
            if entry.file_type()?.is_dir() {
                tenants.push((tenant, entry.path()));
            }
        }
        tenants.sort();
        for (tenant, dir) in tenants {
            let mut namespaces = Vec::new();
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                if valid_name(&name) && entry.file_type()?.is_dir() {
                    namespaces.push(name);
                }
            }
            namespaces.sort();
            for namespace in namespaces {
                let key = (tenant.clone(), namespace.clone());
                let grant = migration_grant_id(&tenant, &namespace);
                match self.shares.get(&key) {
                    Some(share) if share.location == Location::Legacy => continue,
                    Some(_) => {
                        skipped.push(Migrated {
                            tenant: tenant.clone(),
                            namespace,
                            grant,
                        });
                        continue;
                    }
                    None => {}
                }
                self.shares.insert(
                    key,
                    Share {
                        tenant: tenant.clone(),
                        name: namespace.clone(),
                        namespace: namespace.clone(),
                        epoch: 0,
                        location: Location::Legacy,
                    },
                );
                self.grants.insert(
                    grant,
                    SharedMemoryGrant {
                        id: grant,
                        tenant: tenant.clone(),
                        share: namespace.clone(),
                        namespace: namespace.clone(),
                        readers: BTreeSet::new(),
                        writers: BTreeSet::from([Holder::TenantRoot]),
                        expiry: Expiry::UntilRevoked,
                        epoch: 0,
                        origin: Origin::Migrated,
                        issued_unix: now,
                    },
                );
                migrated.push(Migrated {
                    tenant: tenant.clone(),
                    namespace,
                    grant,
                });
            }
        }
        Ok((migrated, skipped))
    }

    /// Write what [`Self::migrate`] recorded, once its receipts are kept. Until then the
    /// migration is in memory only, so a start that fails between the two re-migrates the same
    /// stores under the same grant ids.
    pub(crate) fn commit_migration(&self, migrated: &[Migrated]) -> Result<(), ApiError> {
        if migrated.is_empty() {
            return Ok(());
        }
        self.persist()
    }
}

fn check_holders(holders: &Narrowing, now: u64) -> Result<(), Refusal> {
    if holders.readers.is_empty() && holders.writers.is_empty() {
        return Err(Refusal::NamesNobody);
    }
    if holders.expiry.passed(now) {
        return Err(Refusal::AlreadyExpired);
    }
    Ok(())
}

/// A migrated grant's id is derived from what it migrates, so a migration that is interrupted
/// between its receipt and its registry write re-issues the SAME decision, not a second one.
fn migration_grant_id(tenant: &TenantKey, namespace: &str) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(b"nucleus/memory-migration/v1\0");
    hasher.update(tenant.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(namespace.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_custom_bytes(bytes).into_uuid()
}

/// One memory-flow decision, as the node signs it. Its derived serialization, canonicalized
/// (RFC 8785), is the preimage (F-1); nothing is formatted into it.
#[derive(Debug, Serialize)]
pub(crate) struct FlowClaim<'a> {
    pub(crate) schema: &'static str,
    pub(crate) event: FlowEvent,
    pub(crate) tenant: &'a str,
    /// The grant decided; absent only for a revocation, whose subject is the whole share.
    pub(crate) grant: Option<Uuid>,
    pub(crate) share: &'a str,
    pub(crate) namespace: &'a str,
    pub(crate) epoch: u64,
    /// The pod attached, for an `attach`.
    pub(crate) pod: Option<Uuid>,
    /// The attached pod's lineage root, for an `attach`.
    pub(crate) lineage: Option<Uuid>,
    pub(crate) access: Option<Access>,
    pub(crate) at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FlowEvent {
    Attach,
    Migrate,
    MigrationSkipped,
    Mint,
    Attenuate,
    Revoke,
}

impl FlowEvent {
    fn name(self) -> &'static str {
        match self {
            FlowEvent::Attach => "memory_share_attach",
            FlowEvent::Migrate => "memory_share_migrate",
            FlowEvent::MigrationSkipped => "memory_share_migration_skipped",
            FlowEvent::Mint => "memory_share_mint",
            FlowEvent::Attenuate => "memory_share_attenuate",
            FlowEvent::Revoke => "memory_share_revoke",
        }
    }
}

impl<'a> FlowClaim<'a> {
    pub(crate) fn new(
        event: FlowEvent,
        tenant: &'a TenantKey,
        grant: Option<Uuid>,
        share: &'a str,
        namespace: &'a str,
        epoch: u64,
        at_unix: u64,
    ) -> Self {
        Self {
            schema: FLOW_SCHEMA,
            event,
            tenant: tenant.as_str(),
            grant,
            share,
            namespace,
            epoch,
            pod: None,
            lineage: None,
            access: None,
            at_unix,
        }
    }
}

/// The node's own audit log: `<state_dir>/lifecycle.log`, the same sink every node-level
/// lifecycle event goes to, and outside every pod's reach (a container pod is bound only its pod
/// directory).
pub(crate) fn flow_log_path(state_dir: &Path) -> PathBuf {
    state_dir.join("lifecycle.log")
}

/// Sign and durably append one flow decision. A failure is returned, not logged and dropped: a
/// cross-lineage attach whose receipt was not kept does not happen.
pub(crate) fn record(
    state_dir: &Path,
    authority: &crate::pod_authority::PodAuthority,
    claim: &FlowClaim<'_>,
) -> Result<(), ApiError> {
    // RFC 8785 JSON: a relying party re-canonicalizes the `claim` it reads back and gets these
    // bytes, whatever its JSON library does with key order.
    let preimage = serde_json_canonicalizer::to_vec(claim)
        .map_err(|e| ApiError::Driver(format!("cannot encode a memory flow receipt: {e}")))?;
    let signature = authority.sign_memory_flow(&preimage);
    let subject = match claim.pod {
        Some(pod) => format!("pod:{pod}"),
        None => format!("tenant:{}", claim.tenant),
    };
    let entry = serde_json::json!({
        "timestamp_unix": claim.at_unix,
        "actor": "nucleus-node",
        "event": claim.event.name(),
        "subject": subject,
        "result": "recorded",
        "claim": claim,
        "signature": signature,
    });
    let line = serde_json::to_string(&entry)
        .map_err(|e| ApiError::Driver(format!("cannot encode a memory flow receipt: {e}")))?;
    let path = flow_log_path(state_dir);
    let kept = nucleus_jsonl::append_line_synced(&path, &line)?;
    if !kept.proves(&path, &line) {
        return Err(ApiError::Driver("memory flow receipt was not kept".into()));
    }
    Ok(())
}

#[cfg(test)]
#[path = "memory_share_tests.rs"]
mod tests;

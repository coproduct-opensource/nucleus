//! Persistent memory is selected by namespace, then bound to the pod's tenant AND lineage.
//!
//! A store is keyed `(tenant, lineage root, namespace)`: two pods of one tenant in unrelated
//! lineages are handed different stores, so memory carries nothing between pods the pod API
//! keeps apart. Crossing a lineage takes a declared, receipted `SharedMemory` grant
//! (`memory_share`), presented by id. Stores from the old owner-keyed layout, which every lineage
//! of a tenant reached, are converted into migrated grants at start (`MemoryArgs::load`).
use crate::{
    ApiError,
    container_mediation::ContainerMediation,
    driver::DriverKind,
    memory_share::{self, Access, FlowClaim, FlowEvent, Registry, TenantKey},
    pod_authority::PodAuthority,
};
use nucleus_spec::PodSpec;
use std::{
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};
use uuid::Uuid;

const LABEL: &str = "nucleus.io/memory-namespace";
const GUEST_DIRECTORY: &str = "/run/nucleus/memory";
const JOURNAL: &str = "memory.jsonl";
const ENV: [&str; 2] = ["NUCLEUS_MEMORY_STORE", "NUCLEUS_MEMORY_NAMESPACE"];
/// The proxy refuses a journal over 64 MiB; a reader's snapshot reads no more than that.
const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(clap::Args, Debug)]
pub(crate) struct MemoryArgs {
    /// Existing private directory for tenant- and lineage-bound persistent proxy memory.
    #[arg(long, env = "NUCLEUS_NODE_MEMORY_ROOT")]
    memory_root: Option<PathBuf>,
}

pub(crate) struct Stores {
    root: Option<Root>,
}
struct Root {
    path: PathBuf,
    shares: Mutex<Registry>,
}
pub(crate) struct Requested {
    namespace: String,
    presented: Option<Uuid>,
}
/// A store provisioned for one pod: the directory its proxy journals into, and the namespace
/// that journal's header carries.
pub(crate) struct Attachment {
    directory: PathBuf,
    namespace: String,
}

/// Which lineage a pod's memory belongs to: the root of the parent chain the node recorded at
/// creation (`pod_api::parent_for_create`, the same edge `caller_may_manage` reads), folded once
/// at creation so it never depends on an ancestor still being registered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LineageRoot {
    Known(Uuid),
    /// The recorded parent was not registered when the pod was created, so its lineage cannot be
    /// named. A pod in this state is refused persistent memory rather than given a guess.
    Unresolved {
        parent: Uuid,
    },
}

impl LineageRoot {
    /// The lineage of pod `id`, from its recorded parent and that parent's own lineage if the
    /// parent is registered (`Some(root)`) or not (`None`).
    pub(crate) fn of(id: Uuid, parent: Option<(Uuid, Option<LineageRoot>)>) -> Self {
        match parent {
            None => LineageRoot::Known(id),
            Some((_, Some(root))) => root,
            Some((parent, None)) => LineageRoot::Unresolved { parent },
        }
    }
}

/// Who a store is being provisioned for.
pub(crate) struct Subject<'a> {
    pub(crate) pod: Uuid,
    /// The issued root identity: the pod's tenant (ADR 0001).
    pub(crate) owner: &'a str,
    pub(crate) lineage: LineageRoot,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl MemoryArgs {
    /// The flags with `--memory-root` set, for fixtures that need a node with persistent memory.
    #[cfg(test)]
    pub(crate) fn rooted(memory_root: PathBuf) -> Self {
        Self {
            memory_root: Some(memory_root),
        }
    }

    /// Open the memory root, and migrate the owner-keyed layout into declared grants.
    ///
    /// Each migrated store is receipted in the node's `lifecycle.log` before the registry that
    /// records it is written, so an interrupted migration re-issues the same decision (its grant
    /// id is derived from the store) rather than losing its receipt.
    pub(crate) fn load(
        &self,
        roots: &crate::host_paths::Roots,
        state_dir: &Path,
        authority: &PodAuthority,
    ) -> Result<Stores, ApiError> {
        let Some(path) = self.memory_root.as_ref() else {
            return Ok(Stores { root: None });
        };
        let root = path.canonicalize()?;
        private_directory(&root)?;
        let workspace = roots.workspace_root().canonicalize()?;
        if root.starts_with(&workspace) || workspace.starts_with(&root) {
            return Err(ApiError::Driver(
                "memory root must be separate from the workspace root".into(),
            ));
        }
        let mut shares = Registry::load(&root)?;
        let now = now_unix();
        let (migrated, skipped) = shares.migrate(&root, now)?;
        for event in &skipped {
            tracing::warn!(
                tenant = event.tenant.as_str(),
                namespace = %event.namespace,
                "a legacy memory store collides with a minted share of the same name; it is not migrated and stays unreachable"
            );
            let claim = FlowClaim::new(
                FlowEvent::MigrationSkipped,
                &event.tenant,
                Some(event.grant),
                &event.namespace,
                &event.namespace,
                0,
                now,
            );
            memory_share::record(state_dir, authority, &claim)?;
        }
        for event in &migrated {
            tracing::info!(
                tenant = event.tenant.as_str(),
                namespace = %event.namespace,
                grant = %event.grant,
                "a memory store shared across lineages became a declared SharedMemory grant"
            );
            let claim = FlowClaim::new(
                FlowEvent::Migrate,
                &event.tenant,
                Some(event.grant),
                &event.namespace,
                &event.namespace,
                0,
                now,
            );
            memory_share::record(state_dir, authority, &claim)?;
        }
        shares.commit_migration(&migrated)?;
        Ok(Stores {
            root: Some(Root {
                path: root,
                shares: Mutex::new(shares),
            }),
        })
    }
}

impl Stores {
    pub(crate) fn request(
        &self,
        spec: &PodSpec,
        driver: &DriverKind,
        mediation: ContainerMediation,
    ) -> Result<Option<Requested>, ApiError> {
        let presented = spec.metadata.labels.get(memory_share::GRANT_LABEL);
        let Some(namespace) = spec.metadata.labels.get(LABEL) else {
            if presented.is_some() {
                return Err(ApiError::InvalidSpec(format!(
                    "{} presents a memory grant without a {LABEL}",
                    memory_share::GRANT_LABEL
                )));
            }
            return Ok(None);
        };
        if !memory_share::valid_name(namespace) {
            return Err(ApiError::InvalidSpec(format!(
                "{LABEL} must contain 1 to 64 ASCII letters, digits, underscores or hyphens"
            )));
        }
        let presented = presented
            .map(|id| {
                Uuid::parse_str(id).map_err(|_| {
                    ApiError::InvalidSpec(format!(
                        "{} must be a SharedMemory grant id",
                        memory_share::GRANT_LABEL
                    ))
                })
            })
            .transpose()?;
        let supported = match driver {
            #[cfg(feature = "local-driver")]
            DriverKind::Local => true,
            DriverKind::Container => mediation.runs_tool_proxy(),
            DriverKind::Firecracker | DriverKind::AppleVz => false,
        };
        if !supported {
            return Err(ApiError::InvalidSpec("persistent memory requires the local driver or a mediated container; VM memory transport is not provisioned".into()));
        }
        if self.root.is_none() {
            return Err(ApiError::InvalidSpec(
                "persistent memory requires an operator --memory-root".into(),
            ));
        }
        Ok(Some(Requested {
            namespace: namespace.clone(),
            presented,
        }))
    }

    /// Bind a requested store to the pod: its lineage's own store, or the share a grant it
    /// presents (or a migrated grant for its namespace) decides. A share is attached only after
    /// the node has durably recorded the signed receipt naming the grant.
    pub(crate) fn provision(
        &self,
        requested: Option<Requested>,
        subject: &Subject<'_>,
        state_dir: &Path,
        authority: &PodAuthority,
    ) -> Result<Option<Attachment>, ApiError> {
        let Some(Requested {
            namespace,
            presented,
        }) = requested
        else {
            return Ok(None);
        };
        let root = self
            .root
            .as_ref()
            .ok_or_else(|| ApiError::Driver("memory root unavailable".into()))?;
        let lineage = match subject.lineage {
            LineageRoot::Known(lineage) => lineage,
            LineageRoot::Unresolved { parent } => {
                return Err(ApiError::InvalidSpec(format!(
                    "persistent memory is bound to a lineage, and this pod's recorded parent {parent} is not registered"
                )));
            }
        };
        let tenant = TenantKey::of(subject.owner);
        let now = now_unix();
        let shares = root
            .shares
            .lock()
            .map_err(|_| ApiError::Driver("memory share registry unavailable".into()))?;
        let exercised = match presented {
            Some(grant) => Some(shares.exercise(grant, &tenant, lineage, &namespace, now)?),
            None => shares
                .legacy(&tenant, lineage, &namespace, now)
                .transpose()?,
        };
        let Some(exercised) = exercised else {
            let lineage = lineage.to_string();
            let directory = ensure_path(
                &root.path,
                &["lineage", tenant.as_str(), &lineage, &namespace],
            )?;
            return Ok(Some(Attachment {
                directory,
                namespace: format!("lineage/{}/{lineage}/{namespace}", tenant.as_str()),
            }));
        };
        let (segments, store_namespace) = exercised.store(&tenant);
        let segments: Vec<&str> = segments.iter().map(String::as_str).collect();
        let share_dir = ensure_path(&root.path, &segments)?;
        let directory = match exercised.access {
            Access::ReadWrite => share_dir,
            Access::Read => snapshot(&root.path, subject.pod, &share_dir)?,
        };
        let mut claim = FlowClaim::new(
            FlowEvent::Attach,
            &tenant,
            Some(exercised.grant),
            &exercised.share,
            &exercised.namespace,
            exercised.epoch,
            now,
        );
        claim.pod = Some(subject.pod);
        claim.lineage = Some(lineage);
        claim.access = Some(exercised.access);
        memory_share::record(state_dir, authority, &claim)?;
        tracing::info!(
            pod = %subject.pod,
            grant = %exercised.grant,
            share = %exercised.share,
            access = ?exercised.access,
            origin = ?exercised.origin,
            "a pod attached to a shared memory store under a SharedMemory grant"
        );
        Ok(Some(Attachment {
            directory,
            namespace: store_namespace,
        }))
    }

    /// The memory share registry, for the issuing API. `None` without a memory root.
    pub(crate) fn shares(&self) -> Option<&Mutex<Registry>> {
        self.root.as_ref().map(|root| &root.shares)
    }
}

/// A reader's copy of the share's journal: the complete records present at attach, in a private
/// directory of its own, so nothing the reader writes reaches the share. A byte prefix up to the
/// last newline, because the proxy appends each record as one write; every copied record keeps
/// its persisted label and is re-verified by the proxy's provenance replay on open.
fn snapshot(root: &Path, pod: Uuid, share_dir: &Path) -> Result<PathBuf, ApiError> {
    let directory = ensure_path(root, &["reads", &pod.to_string()])?;
    let mut bytes = Vec::new();
    match std::fs::File::open(share_dir.join(JOURNAL)) {
        Ok(file) => {
            file.take(MAX_SNAPSHOT_BYTES + 1).read_to_end(&mut bytes)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
        return Err(ApiError::Driver(
            "shared memory journal is too large to snapshot".into(),
        ));
    }
    let complete = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    if complete > 0 {
        let mut copy = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join(JOURNAL))?;
        copy.write_all(&bytes[..complete])?;
        copy.sync_all()?;
        std::fs::File::open(&directory)?.sync_all()?;
    }
    Ok(directory)
}

/// `root/<segments...>`, each level created private, and each checked private when it exists.
fn ensure_path(root: &Path, segments: &[&str]) -> Result<PathBuf, ApiError> {
    let mut path = root.to_path_buf();
    for segment in segments {
        path.push(segment);
        ensure_directory(&path)?;
    }
    Ok(path)
}

fn private_directory(path: &Path) -> Result<(), ApiError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(ApiError::Driver(
            "memory directories must be private real directories (mode 0700)".into(),
        ));
    }
    Ok(())
}
fn ensure_directory(path: &Path) -> Result<(), ApiError> {
    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                std::fs::File::open(parent)?.sync_all()?;
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    private_directory(path)
}

#[cfg(feature = "local-driver")]
pub(crate) fn local_command(command: &mut tokio::process::Command, memory: Option<&Attachment>) {
    for key in ENV {
        command.env_remove(key);
    }
    if let Some(memory) = memory {
        command
            .arg("--memory-store")
            .arg(memory.directory.join(JOURNAL))
            .arg("--memory-namespace")
            .arg(&memory.namespace);
    }
}
impl Attachment {
    pub(crate) fn container_env(&self) -> [String; 2] {
        [
            format!("{}={GUEST_DIRECTORY}/{JOURNAL}", ENV[0]),
            format!("{}={}", ENV[1], self.namespace),
        ]
    }
    pub(crate) fn container_bind(&self) -> String {
        format!("{}:{GUEST_DIRECTORY}:rw", self.directory.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_share::{Expiry, Holder, Narrowing};
    use std::collections::BTreeSet;

    const OWNER: &str = "spiffe://test.local/ns/system/sa/tenant-a";

    fn spec(namespace: &str) -> PodSpec {
        let mut spec: PodSpec =
            serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"policy":{"type":"profile","name":"default"}}}"#).unwrap();
        spec.metadata.labels.insert(LABEL.into(), namespace.into());
        spec
    }
    fn presenting(namespace: &str, grant: Uuid) -> PodSpec {
        let mut spec = spec(namespace);
        spec.metadata
            .labels
            .insert(memory_share::GRANT_LABEL.into(), grant.to_string());
        spec
    }
    fn authority(dir: &Path) -> PodAuthority {
        let args = crate::pod_authority::AuthorityArgs {
            root_minter_spiffe_id: None,
            cert_trust_anchors: Vec::new(),
            max_children_per_pod: 8,
            upstreams: None,
            federation_issuer: None,
            ingress: Default::default(),
            approvals: crate::host_decide::effects::ApprovalTimingArgs::HUMAN,
        };
        PodAuthority::new(&args, "test.local", dir, &crate::pod_authority::NO_TPM)
            .expect("authority builds")
    }
    fn roots(state: &Path) -> crate::host_paths::Roots {
        crate::host_paths::HostPathArgs {
            scratch_root: None,
            artifacts_root: state.join("artifacts"),
            data_root: None,
            workspace_root: None,
        }
        .ensure(state)
        .unwrap()
    }

    /// A node: its state dir, a private memory root, its authority, and the stores it loaded.
    struct Node {
        state: tempfile::TempDir,
        memory: tempfile::TempDir,
        authority: PodAuthority,
        stores: Stores,
    }
    impl Node {
        fn start() -> Self {
            let state = tempfile::tempdir().unwrap();
            let memory = tempfile::tempdir().unwrap();
            std::fs::set_permissions(memory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let authority = authority(state.path());
            let stores = Self::load(&state, &memory, &authority).unwrap();
            Self {
                state,
                memory,
                authority,
                stores,
            }
        }
        fn load(
            state: &tempfile::TempDir,
            memory: &tempfile::TempDir,
            authority: &PodAuthority,
        ) -> Result<Stores, ApiError> {
            MemoryArgs {
                memory_root: Some(memory.path().to_owned()),
            }
            .load(&roots(state.path()), state.path(), authority)
        }
        fn restart(self) -> Self {
            let stores = Self::load(&self.state, &self.memory, &self.authority).unwrap();
            Self { stores, ..self }
        }
        fn attach(&self, spec: &PodSpec, lineage: LineageRoot) -> Result<Attachment, ApiError> {
            self.attach_as(spec, lineage, Uuid::new_v4())
        }
        fn attach_as(
            &self,
            spec: &PodSpec,
            lineage: LineageRoot,
            pod: Uuid,
        ) -> Result<Attachment, ApiError> {
            let request = self
                .stores
                .request(spec, &DriverKind::Container, ContainerMediation::ToolProxy)
                .unwrap();
            let subject = Subject {
                pod,
                owner: OWNER,
                lineage,
            };
            self.stores
                .provision(request, &subject, self.state.path(), &self.authority)
                .map(|attached| attached.expect("a namespace was requested"))
        }
        fn mint(&self, namespace: &str, readers: &[Holder], writers: &[Holder]) -> Uuid {
            self.stores
                .shares()
                .unwrap()
                .lock()
                .unwrap()
                .mint(
                    &TenantKey::of(OWNER),
                    "team",
                    namespace,
                    Narrowing {
                        readers: readers.iter().copied().collect::<BTreeSet<_>>(),
                        writers: writers.iter().copied().collect::<BTreeSet<_>>(),
                        expiry: Expiry::UntilRevoked,
                    },
                    now_unix(),
                    &mut |claim: &FlowClaim<'_>| {
                        memory_share::record(self.state.path(), &self.authority, claim)
                    },
                )
                .unwrap()
        }
        fn revoke(&self, share: &str) {
            self.stores
                .shares()
                .unwrap()
                .lock()
                .unwrap()
                .revoke(
                    &TenantKey::of(OWNER),
                    share,
                    now_unix(),
                    &mut |claim: &FlowClaim<'_>| {
                        memory_share::record(self.state.path(), &self.authority, claim)
                    },
                )
                .unwrap();
        }
        fn receipts(&self) -> Vec<serde_json::Value> {
            std::fs::read_to_string(memory_share::flow_log_path(self.state.path()))
                .unwrap_or_default()
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .filter(|entry| {
                    entry["event"]
                        .as_str()
                        .is_some_and(|e| e.starts_with("memory_share_"))
                })
                .collect()
        }
    }

    fn root_lineage() -> LineageRoot {
        LineageRoot::Known(Uuid::new_v4())
    }

    /// C2: two pods of ONE tenant in unrelated lineages — siblings the pod API keeps apart — are
    /// handed different stores for the same namespace, so memory is no channel between them. On
    /// the owner-keyed layout both were handed `sha256(owner)/project-a`.
    #[test]
    fn non_lineage_siblings_of_one_tenant_are_handed_separate_stores() {
        let node = Node::start();
        let a = node.attach(&spec("project-a"), root_lineage()).unwrap();
        let b = node.attach(&spec("project-a"), root_lineage()).unwrap();
        assert_ne!(a.directory, b.directory, "siblings must not share a store");
        assert_ne!(a.namespace, b.namespace);
        private_directory(&a.directory).unwrap();
        private_directory(&b.directory).unwrap();
        assert!(
            node.receipts().is_empty(),
            "a lineage's own store crosses no lineage, so nothing is receipted"
        );
    }

    #[test]
    fn a_parent_its_child_and_grandchild_share_their_lineage_store() {
        let node = Node::start();
        let parent = Uuid::new_v4();
        let parent_root = LineageRoot::of(parent, None);
        let child = Uuid::new_v4();
        let child_root = LineageRoot::of(child, Some((parent, Some(parent_root))));
        let grandchild_root = LineageRoot::of(Uuid::new_v4(), Some((child, Some(child_root))));
        assert_eq!(child_root, LineageRoot::Known(parent));
        assert_eq!(grandchild_root, LineageRoot::Known(parent));
        let p = node.attach(&spec("project-a"), parent_root).unwrap();
        let c = node.attach(&spec("project-a"), child_root).unwrap();
        let g = node.attach(&spec("project-a"), grandchild_root).unwrap();
        assert_eq!(p.directory, c.directory);
        assert_eq!(p.directory, g.directory);
        assert_eq!(p.namespace, c.namespace);
        let other = node.attach(&spec("project-b"), parent_root).unwrap();
        assert_ne!(p.directory, other.directory, "namespaces stay separate");
        assert!(p.container_env()[0].ends_with("/run/nucleus/memory/memory.jsonl"));
        assert!(p.container_bind().ends_with(":/run/nucleus/memory:rw"));
    }

    #[test]
    fn a_pod_whose_lineage_cannot_be_named_is_refused_memory() {
        let node = Node::start();
        let orphan = LineageRoot::of(Uuid::new_v4(), Some((Uuid::new_v4(), None)));
        assert!(matches!(orphan, LineageRoot::Unresolved { .. }));
        let refused = node.attach(&spec("project-a"), orphan).err().unwrap();
        assert!(
            refused.to_string().contains("is not registered"),
            "{refused}"
        );
        // And a child of such a pod inherits the refusal, not a fresh lineage of its own.
        let child = LineageRoot::of(Uuid::new_v4(), Some((Uuid::new_v4(), Some(orphan))));
        assert_eq!(child, orphan);
    }

    /// A grant reaches exactly what it names: its writer attaches to the share, its reader to a
    /// snapshot that carries the share's complete records and returns nothing, and a lineage it
    /// does not name — or a namespace it is not for — is refused by name.
    #[test]
    fn a_grant_attaches_exactly_its_named_readers_and_writers() {
        let node = Node::start();
        let (writer, reader, stranger) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let grant = node.mint(
            "project-a",
            &[Holder::Lineage(reader)],
            &[Holder::Lineage(writer)],
        );
        let w = node
            .attach(&presenting("project-a", grant), LineageRoot::Known(writer))
            .unwrap();
        let again = node
            .attach(&presenting("project-a", grant), LineageRoot::Known(writer))
            .unwrap();
        assert_eq!(
            w.directory, again.directory,
            "a writer reaches the share itself"
        );
        assert_ne!(
            w.directory,
            node.attach(&spec("project-a"), LineageRoot::Known(writer))
                .unwrap()
                .directory,
            "without the grant, the writer's lineage has its own store"
        );
        // A complete record and a torn tail: the reader is given the record and not the tail.
        std::fs::write(w.directory.join(JOURNAL), b"{\"header\":1}\n{\"torn").unwrap();
        let r = node
            .attach(&presenting("project-a", grant), LineageRoot::Known(reader))
            .unwrap();
        assert_ne!(r.directory, w.directory, "a reader never holds the share");
        assert_eq!(
            std::fs::read(r.directory.join(JOURNAL)).unwrap(),
            b"{\"header\":1}\n"
        );
        assert_eq!(
            r.namespace, w.namespace,
            "the snapshot's header matches the share's"
        );
        private_directory(&r.directory).unwrap();
        let refused = node
            .attach(
                &presenting("project-a", grant),
                LineageRoot::Known(stranger),
            )
            .err()
            .unwrap();
        assert!(
            refused.to_string().contains(&grant.to_string())
                && refused.to_string().contains("does not name lineage"),
            "{refused}"
        );
        let refused = node
            .attach(&presenting("project-b", grant), LineageRoot::Known(writer))
            .err()
            .unwrap();
        assert!(
            refused.to_string().contains("is for namespace project-a"),
            "{refused}"
        );
    }

    #[test]
    fn a_revoked_grant_is_refused_by_name_at_attach() {
        let node = Node::start();
        let writer = Uuid::new_v4();
        let grant = node.mint("project-a", &[], &[Holder::Lineage(writer)]);
        node.attach(&presenting("project-a", grant), LineageRoot::Known(writer))
            .unwrap();
        node.revoke("team");
        let refused = node
            .attach(&presenting("project-a", grant), LineageRoot::Known(writer))
            .err()
            .unwrap();
        assert!(
            refused.to_string().contains(&grant.to_string())
                && refused.to_string().contains("is revoked"),
            "{refused}"
        );
    }

    /// Every cross-lineage attach is a node-signed receipt in the node's own log, naming the
    /// grant, the pod, its lineage and the access it was given, and it verifies under the node's
    /// advertised root key.
    #[test]
    fn a_cross_lineage_attach_is_receipted_naming_the_grant() {
        let node = Node::start();
        let (writer, pod) = (Uuid::new_v4(), Uuid::new_v4());
        let grant = node.mint("project-a", &[], &[Holder::TenantRoot]);
        node.attach_as(
            &presenting("project-a", grant),
            LineageRoot::Known(writer),
            pod,
        )
        .unwrap();
        let receipts = node.receipts();
        let [mint, attach] = receipts.as_slice() else {
            panic!("a mint and an attach, got {receipts:?}");
        };
        assert_eq!(mint["event"], "memory_share_mint");
        assert_eq!(mint["claim"]["grant"], grant.to_string());
        assert_eq!(attach["event"], "memory_share_attach");
        let claim = &attach["claim"];
        assert_eq!(claim["grant"], grant.to_string());
        assert_eq!(claim["pod"], pod.to_string());
        assert_eq!(claim["lineage"], writer.to_string());
        assert_eq!(claim["access"], "read_write");
        let preimage = serde_json_canonicalizer::to_vec(claim).unwrap();
        let signature = attach["signature"].as_str().unwrap();
        let key = node.authority.root_pubkey_hex();
        assert!(crate::pod_authority::verify_memory_flow(
            &key, &preimage, signature
        ));
        assert!(
            !crate::pod_authority::verify_pod_receipt(&key, &preimage, signature),
            "a flow receipt does not verify as a pod receipt"
        );
    }

    /// The owner-keyed layout shared every store across a tenant's lineages. At start each such
    /// store becomes a declared migrated grant, receipted once: a pod that presents no grant
    /// still reaches it (the same directory and journal header), a second start records nothing
    /// new, and a migrated grant the tenant revoked stays revoked across restarts.
    #[test]
    fn migration_declares_each_legacy_store_once_and_never_rewidens() {
        let node = Node::start();
        let tenant = TenantKey::of(OWNER);
        let legacy = node.memory.path().join(tenant.as_str()).join("project-a");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&legacy)
            .unwrap();
        let node = node.restart();
        let receipts = node.receipts();
        let [migrated] = receipts.as_slice() else {
            panic!("one migration receipt, got {receipts:?}");
        };
        assert_eq!(migrated["event"], "memory_share_migrate");
        assert_eq!(migrated["claim"]["namespace"], "project-a");
        let grant = migrated["claim"]["grant"].as_str().unwrap().to_owned();

        // Behaviour preserved, and declared: two unrelated lineages still reach the legacy store
        // — under the migrated grant, each attach receipted.
        let a = node.attach(&spec("project-a"), root_lineage()).unwrap();
        let b = node.attach(&spec("project-a"), root_lineage()).unwrap();
        assert_eq!(a.directory, legacy.canonicalize().unwrap());
        assert_eq!(a.directory, b.directory);
        assert_eq!(a.namespace, format!("{}/project-a", tenant.as_str()));
        // A namespace that had no legacy store is lineage-scoped.
        let fresh = node.attach(&spec("project-b"), root_lineage()).unwrap();
        assert!(fresh.namespace.starts_with("lineage/"));

        let node = node.restart();
        let attaches = node
            .receipts()
            .iter()
            .filter(|r| r["event"] == "memory_share_attach")
            .count();
        assert_eq!(attaches, 2);
        assert_eq!(
            node.receipts()
                .iter()
                .filter(|r| r["event"] == "memory_share_migrate")
                .count(),
            1,
            "a second start migrates nothing"
        );

        node.revoke("project-a");
        let node = node.restart();
        let refused = node
            .attach(&spec("project-a"), root_lineage())
            .err()
            .unwrap();
        assert!(
            refused.to_string().contains(&grant) && refused.to_string().contains("is revoked"),
            "a revoked migrated grant is refused by name, not re-migrated: {refused}"
        );
    }

    #[test]
    fn namespace_and_backend_are_checked_before_storage_is_created() {
        let node = Node::start();
        let stores = &node.stores;
        for name in ["", "../project", "project/a", "project.a"] {
            assert!(
                stores
                    .request(
                        &spec(name),
                        &DriverKind::Container,
                        ContainerMediation::ToolProxy
                    )
                    .is_err()
            );
        }
        assert!(
            stores
                .request(
                    &spec("project"),
                    &DriverKind::Firecracker,
                    ContainerMediation::ToolProxy
                )
                .is_err()
        );
        assert!(
            stores
                .request(
                    &spec("project"),
                    &DriverKind::Container,
                    ContainerMediation::Unmediated
                )
                .is_err()
        );
        assert!(
            Stores { root: None }
                .request(
                    &spec("project"),
                    &DriverKind::Container,
                    ContainerMediation::ToolProxy
                )
                .is_err()
        );
        let mut not_a_grant = spec("project");
        not_a_grant
            .metadata
            .labels
            .insert(memory_share::GRANT_LABEL.into(), "team".into());
        assert!(
            stores
                .request(
                    &not_a_grant,
                    &DriverKind::Container,
                    ContainerMediation::ToolProxy
                )
                .is_err()
        );
        let mut grant_alone = spec("project");
        grant_alone.metadata.labels.remove(LABEL);
        grant_alone
            .metadata
            .labels
            .insert(memory_share::GRANT_LABEL.into(), Uuid::new_v4().to_string());
        assert!(
            stores
                .request(
                    &grant_alone,
                    &DriverKind::Container,
                    ContainerMediation::ToolProxy
                )
                .is_err()
        );
        assert_eq!(std::fs::read_dir(node.memory.path()).unwrap().count(), 0);
    }

    #[test]
    fn configured_memory_root_must_be_private_and_separate_from_workspaces() {
        let state_dir = tempfile::tempdir().unwrap();
        let roots = roots(state_dir.path());
        let authority = authority(state_dir.path());
        let memory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(memory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let args = MemoryArgs {
            memory_root: Some(memory.path().to_owned()),
        };
        assert!(args.load(&roots, state_dir.path(), &authority).is_ok());
        std::fs::set_permissions(memory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(args.load(&roots, state_dir.path(), &authority).is_err());
        let workspace = roots.workspace_root();
        std::fs::set_permissions(workspace, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            MemoryArgs {
                memory_root: Some(workspace.to_owned())
            }
            .load(&roots, state_dir.path(), &authority)
            .is_err()
        );
    }

    #[cfg(feature = "local-driver")]
    #[tokio::test]
    async fn container_environment_uses_only_the_provisioned_grant() {
        let state_dir = tempfile::tempdir().unwrap();
        let state = crate::pod_api::handler_tests::state(&state_dir);
        let node = Node::start();
        let spec = spec("project-a");
        let grant = node.attach(&spec, root_lineage()).unwrap();
        let env =
            crate::container_env(&state, &spec, uuid::Uuid::new_v4(), "", None, Some(&grant)).await;
        for expected in grant.container_env() {
            assert!(env.contains(&expected));
        }
        let empty = crate::container_env(&state, &spec, uuid::Uuid::new_v4(), "", None, None).await;
        assert!(
            !empty
                .iter()
                .any(|value| value.starts_with("NUCLEUS_MEMORY_"))
        );
    }

    #[cfg(feature = "local-driver")]
    #[test]
    fn local_launch_does_not_inherit_an_ambient_memory_namespace() {
        let mut command = tokio::process::Command::new("proxy");
        command
            .env(ENV[0], "/operator/memory.jsonl")
            .env(ENV[1], "operator");
        local_command(&mut command, None);
        for name in ENV {
            assert!(
                command
                    .as_std()
                    .get_envs()
                    .any(|(key, value)| key == name && value.is_none())
            );
        }
    }
}

//! Persistent memory at pod creation: a pod names a space, and the node binds the run to it.
//!
//! The pod asks with `nucleus.io/memory-namespace: <name>`. The node resolves that name to a
//! memory space and the binding policy that admits the pod (`memory_space`), mints the run its
//! own binding, and hands its tool-proxy the binding's directory: a pinned snapshot for a `Read`
//! binding, the pinned base its private branch grows from for a `ReadPropose` one
//! (`memory_binding`). The proxy opens that journal exactly as it opened a store before, by the
//! same two variables or flags, so no guest behaviour changes.
//!
//! Stores left by the owner-keyed layout (every lineage of a tenant reached them) and by the
//! held lineage-scoped layout are declared as spaces at start (`MemoryArgs::load`), each
//! receipted once.
//!
//! Whether the pod's tool-proxy stamps what it writes (Program C, C1) is the node's judgment of
//! the guest ([`writer_of`]), from the same release table every guest capability is judged by;
//! the pod has no say in it.
use crate::{
    ApiError,
    container_mediation::ContainerMediation,
    driver::DriverKind,
    memory_binding::{BindRequest, JOURNAL, private_directory},
    memory_flow::{self, FlowClaim},
    memory_space::{
        DecisionCiter, MemoryWriter, PodLabels, PodMatch, Registry, SpaceName, TenantKey,
    },
    pod_authority::PodAuthority,
};
use nucleus_spec::PodSpec;
use nucleus_spec::tier2_artifacts::{self, GuestCapability, GuestSkew};
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
};
use uuid::Uuid;

const LABEL: &str = "nucleus.io/memory-namespace";
const GUEST_DIRECTORY: &str = "/run/nucleus/memory";
const ENV: [&str; 2] = ["NUCLEUS_MEMORY_STORE", "NUCLEUS_MEMORY_NAMESPACE"];
/// How long after a run's own deadline its binding may still publish its branch, so the
/// tenant can publish a finished run's work.
pub(crate) const PUBLISH_WINDOW_SECS: u64 = 15 * 60;

#[derive(clap::Args, Debug)]
pub(crate) struct MemoryArgs {
    /// Existing private directory for persistent memory spaces and their bindings.
    #[arg(long, env = "NUCLEUS_NODE_MEMORY_ROOT")]
    memory_root: Option<PathBuf>,
}

pub(crate) struct Stores {
    root: Option<Root>,
}
struct Root {
    registry: Mutex<Registry>,
}
pub(crate) struct Requested {
    name: SpaceName,
}
/// A binding provisioned for one pod: the directory its proxy journals into, and the namespace
/// that journal's header carries.
pub(crate) struct Attachment {
    pub(crate) directory: PathBuf,
    pub(crate) namespace: String,
}

/// Which lineage a pod belongs to: the root of the parent chain the node recorded at creation
/// (`pod_api::parent_for_create`, the same edge `caller_may_manage` reads), folded once at
/// creation so it never depends on an ancestor still being registered.
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

/// Who a binding is being minted for.
pub(crate) struct Subject<'a> {
    pub(crate) pod: Uuid,
    /// The issued root identity: the pod's tenant (ADR 0001).
    pub(crate) owner: &'a str,
    pub(crate) lineage: LineageRoot,
    pub(crate) labels: PodLabels<'a>,
    /// When the run's binding stops being honoured: its deadline plus the publish window.
    pub(crate) run_ends: u64,
    /// Whether its tool-proxy stamps what it writes ([`writer_of`]).
    pub(crate) writer: MemoryWriter,
}

/// Whether a pod's tool-proxy stamps every memory record with what its session had read
/// (`GuestCapability::MemoryDependencyStamp`), judged from what the node knows of it:
///
/// * the local driver runs this tree's tool-proxy, which stamps;
/// * a mediated container runs the node's tool-proxy image, judged by its OCI release label
///   (`image_release`) against the table. A release without the capability, a label the table
///   cannot order (a branch build) and an image with no readable label are all legacy: "could
///   not tell" is never "stamps" (ADR 0007 A-1);
/// * a VM driver provisions no memory (`Stores::request`), and is legacy.
pub(crate) fn writer_of(driver: &DriverKind, image_release: Option<&str>) -> MemoryWriter {
    match driver {
        #[cfg(feature = "local-driver")]
        DriverKind::Local => MemoryWriter::Stamping,
        DriverKind::Container => match image_release
            .map(|v| tier2_artifacts::capability_skew(v, GuestCapability::MemoryDependencyStamp))
        {
            Some(Ok(())) => MemoryWriter::Stamping,
            Some(Err(GuestSkew::Lacks { .. } | GuestSkew::Unorderable { .. })) | None => {
                MemoryWriter::Legacy
            }
        },
        DriverKind::Firecracker | DriverKind::AppleVz => MemoryWriter::Legacy,
    }
}

/// [`writer_of`] for a pod this node is creating: the container image's release label is read
/// only when the pod asks for memory on the container driver.
pub(crate) async fn writer_for(state: &crate::NodeState, requested: bool) -> MemoryWriter {
    let release = match (&state.driver, requested, state.docker.as_ref()) {
        (DriverKind::Container, true, Some(docker)) => {
            match docker.inspect_image(&state.container_image).await {
                Ok(inspected) => inspected.config.and_then(|c| c.labels).and_then(|labels| {
                    crate::container_transport::image_version(Some(&labels)).map(str::to_owned)
                }),
                Err(error) => {
                    tracing::info!(image = %state.container_image, %error,
                        "could not inspect the container image; its memory writes are judged unstamped");
                    None
                }
            }
        }
        _ => None,
    };
    writer_of(&state.driver, release.as_deref())
}

pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl MemoryArgs {
    /// The flags with `--memory-root` set, for fixtures that need a node with persistent memory.
    #[cfg(all(test, feature = "local-driver"))]
    pub(crate) fn rooted(memory_root: PathBuf) -> Self {
        Self {
            memory_root: Some(memory_root),
        }
    }

    /// Open the memory root, and declare every store an earlier layout left as a space.
    ///
    /// Each migration is receipted in the node's `lifecycle.log` before the registry that
    /// records it is written, so an interrupted migration re-issues the same decision (its
    /// policy id is derived from the store) rather than losing its receipt.
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
        let mut registry = Registry::load(&root)?;
        let now = now_unix();
        let migrated = registry.migrate(now)?;
        for event in &migrated {
            match event.policy {
                Some(policy) => tracing::info!(
                    tenant = event.tenant.as_str(),
                    space = %event.space.reference(),
                    layout = event.layout,
                    %policy,
                    "a memory store from an earlier layout became a declared memory space"
                ),
                None => tracing::warn!(
                    tenant = event.tenant.as_str(),
                    space = %event.space.reference(),
                    layout = event.layout,
                    "a memory store from an earlier layout collides with a space of the same id; it is not migrated and stays unreachable"
                ),
            }
            let claim: FlowClaim<'_> = registry.migration_claim(event, now);
            memory_flow::record(state_dir, authority, &claim)?;
        }
        registry.commit_migration(&migrated)?;
        Ok(Stores {
            root: Some(Root {
                registry: Mutex::new(registry),
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
        let Some(name) = spec.metadata.labels.get(LABEL) else {
            return Ok(None);
        };
        let name = SpaceName::new(name).map_err(|_| {
            ApiError::InvalidSpec(format!(
                "{LABEL} must contain 1 to 64 ASCII letters, digits, underscores or hyphens"
            ))
        })?;
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
        Ok(Some(Requested { name }))
    }

    /// Mint the run's binding to the space its request names, and return what the pod is
    /// handed. The binding's snapshot is written and its delivery receipt kept before this
    /// returns, so the pod never reaches bytes whose disclosure is unrecorded.
    pub(crate) fn provision(
        &self,
        requested: Option<Requested>,
        subject: &Subject<'_>,
        state_dir: &Path,
        authority: &PodAuthority,
        citer: Option<&dyn DecisionCiter>,
    ) -> Result<Option<Attachment>, ApiError> {
        let Some(Requested { name }) = requested else {
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
                    "persistent memory is bound per lineage, and this pod's recorded parent {parent} is not registered"
                )));
            }
        };
        let tenant = TenantKey::of(subject.owner);
        let mut registry = root
            .registry
            .lock()
            .map_err(|_| ApiError::Driver("memory space registry unavailable".into()))?;
        let delivered = registry.bind(
            BindRequest {
                tenant: &tenant,
                name: &name,
                pod: subject.pod,
                matched: PodMatch {
                    lineage,
                    labels: subject.labels,
                    writer: subject.writer,
                },
                run_ends: subject.run_ends,
                now: now_unix(),
            },
            citer,
            &mut |claim: &FlowClaim<'_>| memory_flow::record(state_dir, authority, claim),
        )?;
        tracing::debug!(pod = %subject.pod, binding = %delivered.binding, "memory binding delivered");
        Ok(Some(Attachment {
            directory: delivered.directory,
            namespace: delivered.namespace,
        }))
    }

    /// The memory space registry, for the API. `None` without a memory root.
    pub(crate) fn registry(&self) -> Option<&Mutex<Registry>> {
        self.root.as_ref().map(|root| &root.registry)
    }
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
    //! Provisioning through the node's own entry points: the request a spec makes, the binding
    //! `provision` mints with the node's real authority, the receipts it signs, and what reaches
    //! the pod's environment.
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[cfg(feature = "local-driver")]
    const OWNER: &str = "spiffe://test.local/ns/system/sa/tenant-a";

    fn spec(name: &str) -> PodSpec {
        let mut spec: PodSpec =
            serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"policy":{"type":"profile","name":"default"}}}"#).unwrap();
        spec.metadata.labels.insert(LABEL.into(), name.into());
        spec
    }

    #[test]
    fn namespace_and_backend_are_checked_before_storage_is_created() {
        let memory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(memory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let stores = Stores {
            root: Some(Root {
                registry: Mutex::new(Registry::load(memory.path()).unwrap()),
            }),
        };
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
        assert_eq!(std::fs::read_dir(memory.path()).unwrap().count(), 0);
    }

    #[cfg(feature = "local-driver")]
    use std::collections::BTreeMap;
    #[cfg(feature = "local-driver")]
    use std::os::unix::fs::DirBuilderExt;

    #[cfg(feature = "local-driver")]
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

    /// A node: its state, a private memory root, and the stores it loaded with its authority.
    #[cfg(feature = "local-driver")]
    struct Node {
        _state_dir: tempfile::TempDir,
        memory: tempfile::TempDir,
        state: crate::NodeState,
    }

    #[cfg(feature = "local-driver")]
    impl Node {
        fn start() -> Self {
            let state_dir = tempfile::tempdir().unwrap();
            let memory = tempfile::tempdir().unwrap();
            std::fs::set_permissions(memory.path(), std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let mut node = Self {
                state: crate::pod_api::handler_tests::state(&state_dir),
                _state_dir: state_dir,
                memory,
            };
            node.reload();
            node
        }

        /// The node restarted with the same state dir and memory root.
        fn reload(&mut self) {
            self.state.memory = std::sync::Arc::new(
                MemoryArgs::rooted(self.memory.path().to_owned())
                    .load(
                        &self.state.host_roots,
                        &self.state.state_dir,
                        &self.state.authority,
                    )
                    .unwrap(),
            );
        }

        fn provision(&self, lineage: LineageRoot, pod: Uuid) -> Result<Attachment, ApiError> {
            let request = self
                .state
                .memory
                .request(
                    &spec("project-a"),
                    &DriverKind::Container,
                    ContainerMediation::ToolProxy,
                )
                .unwrap();
            let labels = BTreeMap::new();
            self.state
                .memory
                .provision(
                    request,
                    &Subject {
                        pod,
                        owner: OWNER,
                        lineage,
                        labels: PodLabels::TenantAuthenticated(&labels),
                        run_ends: now_unix() + 3600,
                        writer: MemoryWriter::Stamping,
                    },
                    &self.state.state_dir,
                    &self.state.authority,
                    None,
                )
                .map(|a| a.expect("a space was requested"))
        }

        fn receipts(&self) -> Vec<serde_json::Value> {
            std::fs::read_to_string(memory_flow::flow_log_path(&self.state.state_dir))
                .unwrap_or_default()
                .lines()
                .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
                .filter(|entry| {
                    entry["event"]
                        .as_str()
                        .is_some_and(|e| e.starts_with("memory_"))
                })
                .collect()
        }
    }

    /// C2: two pods of ONE tenant in unrelated lineages — pods the pod API keeps apart — are
    /// bound to different spaces for the same name, so memory is no channel between them. On
    /// the owner-keyed layout both were handed `sha256(owner)/project-a`.
    #[cfg(feature = "local-driver")]
    #[test]
    fn non_lineage_pods_of_one_tenant_are_bound_to_separate_spaces() {
        let node = Node::start();
        let a = node
            .provision(LineageRoot::Known(Uuid::new_v4()), Uuid::new_v4())
            .unwrap();
        let b = node
            .provision(LineageRoot::Known(Uuid::new_v4()), Uuid::new_v4())
            .unwrap();
        assert_ne!(a.directory, b.directory);
        assert_ne!(a.namespace, b.namespace);
        private_directory(&a.directory).unwrap();
        let registry = node.state.memory.registry().unwrap().lock().unwrap();
        let spaces: std::collections::BTreeSet<_> = registry
            .bindings
            .values()
            .map(|b| b.space.clone())
            .collect();
        assert_eq!(spaces.len(), 2, "two lineages, two spaces");
    }

    #[cfg(feature = "local-driver")]
    #[test]
    fn a_pod_whose_lineage_cannot_be_named_is_refused_memory() {
        let node = Node::start();
        let orphan = LineageRoot::of(Uuid::new_v4(), Some((Uuid::new_v4(), None)));
        assert!(matches!(orphan, LineageRoot::Unresolved { .. }));
        let refused = node.provision(orphan, Uuid::new_v4()).err().unwrap();
        assert!(
            refused.to_string().contains("is not registered"),
            "{refused}"
        );
        // A child of such a pod inherits the refusal, not a fresh lineage of its own.
        let child = LineageRoot::of(Uuid::new_v4(), Some((Uuid::new_v4(), Some(orphan))));
        assert_eq!(child, orphan);
        // And a child of a known lineage is in its parent's.
        let parent = Uuid::new_v4();
        let root = LineageRoot::of(parent, None);
        assert_eq!(
            LineageRoot::of(Uuid::new_v4(), Some((parent, Some(root)))),
            LineageRoot::Known(parent)
        );
    }

    /// The snapshot's delivery is a node-signed receipt in the node's own log, kept before the
    /// pod is handed the directory: it names the binding, the pod, its lineage, the pinned base
    /// and the delivered bytes' digest, and verifies under the node's root key in the memory-flow
    /// signature space only.
    #[cfg(feature = "local-driver")]
    #[test]
    fn a_snapshot_delivery_is_signed_and_names_the_bytes_the_pod_is_handed() {
        let node = Node::start();
        let (lineage, pod) = (Uuid::new_v4(), Uuid::new_v4());
        let attached = node.provision(LineageRoot::Known(lineage), pod).unwrap();
        let receipts = node.receipts();
        let delivery = receipts
            .iter()
            .find(|r| r["event"] == "memory_snapshot_delivery")
            .expect("a delivery receipt");
        let claim = &delivery["claim"];
        assert_eq!(claim["event"]["pod"], pod.to_string());
        assert_eq!(claim["event"]["lineage"], lineage.to_string());
        assert_eq!(claim["event"]["base"]["version"], 0);
        assert_eq!(claim["event"]["writer"], "stamping");
        let bytes = std::fs::read(attached.directory.join(JOURNAL)).unwrap();
        assert_eq!(
            claim["event"]["bytes_sha256"],
            hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&bytes))
        );
        assert_eq!(
            attached.directory.parent().unwrap().file_name().unwrap(),
            "bindings"
        );
        assert_eq!(
            attached.directory.file_name().unwrap().to_str().unwrap(),
            claim["event"]["binding"].as_str().unwrap()
        );
        let preimage = serde_json_canonicalizer::to_vec(claim).unwrap();
        let signature = delivery["signature"].as_str().unwrap();
        let key = node.state.authority.root_pubkey_hex();
        assert!(crate::pod_authority::verify_record(
            crate::pod_authority::SignedRecord::MemoryFlow,
            &key,
            &preimage,
            signature
        ));
        assert!(
            !crate::pod_authority::verify_pod_receipt(&key, &preimage, signature),
            "a flow receipt does not verify as a pod receipt"
        );
    }

    /// Migration through the node's start: an owner-keyed store is declared once, and its
    /// receipt is in the node's log; a second start declares nothing new. Program C, C0: the
    /// store records no owning lineage, so a pod asking for it is refused by name, not bound.
    #[cfg(feature = "local-driver")]
    #[test]
    fn migration_is_receipted_once_across_restarts_and_the_store_is_bound_to_no_pod() {
        let mut node = Node::start();
        let tenant = TenantKey::of(OWNER);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(node.memory.path().join(tenant.as_str()).join("project-a"))
            .unwrap();
        node.reload();
        let migrated = || {
            node.receipts()
                .iter()
                .filter(|r| r["event"] == "memory_space_migrated")
                .count()
        };
        assert_eq!(migrated(), 1);
        let refused = node
            .provision(LineageRoot::Known(Uuid::new_v4()), Uuid::new_v4())
            .err()
            .unwrap();
        assert!(
            refused.to_string().contains("CrossRunMemoryUnavailable")
                && refused
                    .to_string()
                    .contains("records no lineage that owns it"),
            "{refused}"
        );
        node.reload();
        assert_eq!(
            node.receipts()
                .iter()
                .filter(|r| r["event"] == "memory_space_migrated")
                .count(),
            1,
            "a second start migrates nothing"
        );
    }

    #[cfg(feature = "local-driver")]
    #[test]
    fn configured_memory_root_must_be_private_and_separate_from_workspaces() {
        let state_dir = tempfile::tempdir().unwrap();
        let state = crate::pod_api::handler_tests::state(&state_dir);
        let roots = roots(state_dir.path());
        let memory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(memory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let args = MemoryArgs::rooted(memory.path().to_owned());
        assert!(
            args.load(&roots, state_dir.path(), &state.authority)
                .is_ok()
        );
        std::fs::set_permissions(memory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            args.load(&roots, state_dir.path(), &state.authority)
                .is_err()
        );
        let workspace = roots.workspace_root();
        std::fs::set_permissions(workspace, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            MemoryArgs::rooted(workspace.to_owned())
                .load(&roots, state_dir.path(), &state.authority)
                .is_err()
        );
    }

    #[cfg(feature = "local-driver")]
    #[tokio::test]
    async fn container_environment_uses_only_the_provisioned_grant() {
        let node = Node::start();
        let spec = spec("project-a");
        let grant = node
            .provision(LineageRoot::Known(Uuid::new_v4()), Uuid::new_v4())
            .unwrap();
        let env =
            crate::container_env(&node.state, &spec, Uuid::new_v4(), "", None, Some(&grant)).await;
        for expected in grant.container_env() {
            assert!(env.contains(&expected));
        }
        assert!(grant.container_bind().ends_with(":/run/nucleus/memory:rw"));
        assert!(grant.container_env()[0].ends_with("/run/nucleus/memory/memory.jsonl"));
        let empty = crate::container_env(&node.state, &spec, Uuid::new_v4(), "", None, None).await;
        assert!(
            !empty
                .iter()
                .any(|value| value.starts_with("NUCLEUS_MEMORY_"))
        );
    }

    /// Program C, C1: whether a run's proxy stamps is the node's judgment of its guest, from
    /// the release table. The pinned 2.7.0 tool-proxy image predates the stamp, and so does
    /// every published release until one ships it; a label the table cannot order and an image
    /// with no readable label are "could not tell", which is legacy, never stamping. The local
    /// driver runs this tree's proxy. A VM driver provisions no memory, and is legacy.
    #[test]
    fn a_guest_is_judged_stamping_only_when_the_node_knows_it_stamps() {
        use nucleus_spec::tier2_artifacts::{FirstShipped, GUEST_RELEASE};
        let container = DriverKind::Container;
        for release in [Some("2.7.0"), Some(GUEST_RELEASE), Some("main"), None] {
            assert_eq!(
                writer_of(&container, release),
                MemoryWriter::Legacy,
                "{release:?}"
            );
        }
        assert_eq!(
            GuestCapability::MemoryDependencyStamp.first_shipped(),
            FirstShipped::NotYet,
            "no release ships the stamp yet; the change that pins one moves this test"
        );
        assert_eq!(
            writer_of(&DriverKind::Firecracker, Some("99.0.0")),
            MemoryWriter::Legacy
        );
        #[cfg(feature = "local-driver")]
        assert_eq!(writer_of(&DriverKind::Local, None), MemoryWriter::Stamping);
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

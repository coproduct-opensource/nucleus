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
use crate::{
    ApiError,
    container_mediation::ContainerMediation,
    driver::DriverKind,
    memory_binding::{BindRequest, JOURNAL, private_directory},
    memory_flow::{self, FlowClaim},
    memory_space::{DecisionCiter, PodLabels, PodMatch, Registry, SpaceName, TenantKey},
    pod_authority::PodAuthority,
};
use nucleus_spec::PodSpec;
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
    directory: PathBuf,
    namespace: String,
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
#[path = "memory_provisioning_tests.rs"]
mod tests;

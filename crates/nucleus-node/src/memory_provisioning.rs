//! Persistent memory is selected by namespace, then bound to the issued owner.
use crate::{ApiError, container_mediation::ContainerMediation, driver::DriverKind};
use nucleus_spec::PodSpec;
use sha2::{Digest, Sha256};
use std::{
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
};

const LABEL: &str = "nucleus.io/memory-namespace";
const GUEST_DIRECTORY: &str = "/run/nucleus/memory";
const ENV: [&str; 2] = ["NUCLEUS_MEMORY_STORE", "NUCLEUS_MEMORY_NAMESPACE"];

#[derive(clap::Args, Debug)]
pub(crate) struct MemoryArgs {
    /// Existing private directory for owner-bound persistent proxy memory.
    #[arg(long, env = "NUCLEUS_NODE_MEMORY_ROOT")]
    memory_root: Option<PathBuf>,
}

pub(crate) struct Stores {
    root: Option<PathBuf>,
}
pub(crate) struct Requested {
    namespace: String,
}
pub(crate) struct Grant {
    directory: PathBuf,
    namespace: String,
}

impl MemoryArgs {
    pub(crate) fn load(&self, roots: &crate::host_paths::Roots) -> Result<Stores, ApiError> {
        let root = self
            .memory_root
            .as_ref()
            .map(|path| {
                let root = path.canonicalize()?;
                private_directory(&root)?;
                let workspace = roots.workspace_root().canonicalize()?;
                if root.starts_with(&workspace) || workspace.starts_with(&root) {
                    return Err(ApiError::Driver(
                        "memory root must be separate from the workspace root".into(),
                    ));
                }
                Ok(root)
            })
            .transpose()?;
        Ok(Stores { root })
    }
}

impl Stores {
    pub(crate) fn request(
        &self,
        spec: &PodSpec,
        driver: &DriverKind,
        mediation: ContainerMediation,
    ) -> Result<Option<Requested>, ApiError> {
        let Some(namespace) = spec.metadata.labels.get(LABEL) else {
            return Ok(None);
        };
        if namespace.is_empty()
            || namespace.len() > 64
            || !namespace
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(ApiError::InvalidSpec(format!(
                "{LABEL} must contain 1 to 64 ASCII letters, digits, underscores or hyphens"
            )));
        }
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
        }))
    }

    pub(crate) fn provision(
        &self,
        requested: Option<Requested>,
        owner: &str,
    ) -> Result<Option<Grant>, ApiError> {
        let Some(Requested { namespace }) = requested else {
            return Ok(None);
        };
        let root = self
            .root
            .as_ref()
            .ok_or_else(|| ApiError::Driver("memory root unavailable".into()))?;
        let owner_hash = hex::encode(Sha256::digest(owner.as_bytes()));
        let owner_dir = root.join(&owner_hash);
        ensure_directory(&owner_dir)?;
        let directory = owner_dir.join(&namespace);
        ensure_directory(&directory)?;
        Ok(Some(Grant {
            directory,
            namespace: format!("{owner_hash}/{namespace}"),
        }))
    }
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
pub(crate) fn local_command(command: &mut tokio::process::Command, grant: Option<&Grant>) {
    for key in ENV {
        command.env_remove(key);
    }
    if let Some(grant) = grant {
        command
            .arg("--memory-store")
            .arg(grant.directory.join("memory.jsonl"))
            .arg("--memory-namespace")
            .arg(&grant.namespace);
    }
}
impl Grant {
    pub(crate) fn container_env(&self) -> [String; 2] {
        [
            format!("{}={GUEST_DIRECTORY}/memory.jsonl", ENV[0]),
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
    fn spec(namespace: &str) -> PodSpec {
        let mut spec: PodSpec =
            serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{}}"#).unwrap();
        spec.metadata.labels.insert(LABEL.into(), namespace.into());
        spec
    }
    fn stores(dir: &Path) -> Stores {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        Stores {
            root: Some(dir.to_owned()),
        }
    }
    #[test]
    fn stable_owner_namespace_reuses_storage_and_other_owners_stay_separate() {
        let dir = tempfile::tempdir().unwrap();
        let stores = stores(dir.path());
        let request = || {
            stores
                .request(
                    &spec("project-a"),
                    &DriverKind::Container,
                    ContainerMediation::ToolProxy,
                )
                .unwrap()
        };
        let first = stores
            .provision(request(), "spiffe://test/owner-a")
            .unwrap()
            .unwrap();
        let second = stores
            .provision(request(), "spiffe://test/owner-a")
            .unwrap()
            .unwrap();
        let other = stores
            .provision(request(), "spiffe://test/owner-b")
            .unwrap()
            .unwrap();
        assert_eq!(first.directory, second.directory);
        assert_eq!(first.namespace, second.namespace);
        assert_ne!(first.directory, other.directory);
        assert_ne!(first.namespace, other.namespace);
        assert!(first.container_env()[0].ends_with("/run/nucleus/memory/memory.jsonl"));
        assert!(first.container_bind().ends_with(":/run/nucleus/memory:rw"));
        private_directory(&first.directory).unwrap();
    }
    #[test]
    fn namespace_and_backend_are_checked_before_storage_is_created() {
        let dir = tempfile::tempdir().unwrap();
        let stores = stores(dir.path());
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
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
    #[test]
    fn configured_memory_root_must_be_private_and_separate_from_workspaces() {
        let state_dir = tempfile::tempdir().unwrap();
        let state = crate::pod_api::handler_tests::state(&state_dir);
        let memory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(memory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let args = MemoryArgs {
            memory_root: Some(memory.path().to_owned()),
        };
        assert!(args.load(&state.host_roots).is_ok());
        std::fs::set_permissions(memory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(args.load(&state.host_roots).is_err());
        let workspace = state.host_roots.workspace_root();
        std::fs::set_permissions(workspace, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            MemoryArgs {
                memory_root: Some(workspace.to_owned())
            }
            .load(&state.host_roots)
            .is_err()
        );
    }
    #[tokio::test]
    async fn container_environment_uses_only_the_provisioned_grant() {
        let state_dir = tempfile::tempdir().unwrap();
        let state = crate::pod_api::handler_tests::state(&state_dir);
        let memory = tempfile::tempdir().unwrap();
        let stores = stores(memory.path());
        let spec = spec("project-a");
        let request = stores
            .request(&spec, &DriverKind::Container, ContainerMediation::ToolProxy)
            .unwrap();
        let grant = stores
            .provision(request, "spiffe://test/owner-a")
            .unwrap()
            .unwrap();
        let env = crate::container_env(
            &state,
            &spec,
            uuid::Uuid::new_v4(),
            "fixture-token",
            "",
            None,
            Some(&grant),
        )
        .await;
        for expected in grant.container_env() {
            assert!(env.contains(&expected));
        }
        let empty = crate::container_env(
            &state,
            &spec,
            uuid::Uuid::new_v4(),
            "fixture-token",
            "",
            None,
            None,
        )
        .await;
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

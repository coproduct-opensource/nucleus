//! Provisioning through the node's own entry points: the request a spec makes, the binding
//! `provision` mints with the node's real authority, the receipts it signs, and what reaches
//! the pod's environment.
use super::*;
use std::os::unix::fs::PermissionsExt;

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
mod with_authority {
    use super::*;
    use std::collections::BTreeMap;
    use std::os::unix::fs::DirBuilderExt;

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
    struct Node {
        _state_dir: tempfile::TempDir,
        memory: tempfile::TempDir,
        state: crate::NodeState,
    }

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
    /// receipt is in the node's log; a second start declares nothing new.
    #[test]
    fn migration_is_receipted_once_across_restarts() {
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
        let attached = node
            .provision(LineageRoot::Known(Uuid::new_v4()), Uuid::new_v4())
            .unwrap();
        assert_eq!(attached.namespace.split('/').next(), Some("binding"));
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

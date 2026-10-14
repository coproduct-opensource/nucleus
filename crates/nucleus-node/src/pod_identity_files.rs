//! Node-issued pod identities for file-based proxy bootstrap.
//!
//! An ordinary SVID identifies the pod; it makes no microVM attestation claim.
//!
//! # Which pods are handed the private key (#3471)
//!
//! The certificate and the trust bundle are public and every file-provisioned
//! pod gets them: they are its sandbox proof (tier 2), which reads no key. The
//! private key is read by a tool-proxy only when it calls this node as a
//! client, and on the local and container drivers only one thing makes it do
//! that: an orchestrator pod's pod management (`enable_pod_mgmt`). The lockdown
//! gRPC client (`--node-grpc-url`) and the mTLS listener (`--mtls`) are never
//! configured by either driver.
//!
//! | driver      | pod                       | key                                  |
//! |-------------|---------------------------|--------------------------------------|
//! | local       | `enable_pod_mgmt: "true"` | on the proxy's stdin, never a file   |
//! | local       | any other                 | none                                 |
//! | container   | any                       | none (the driver enables no client)  |
//! | Firecracker | any                       | not here: the guest fetches its SVID |
//!
//! [`NodeClient::of`] reads that from the admitted plan once, and the one value
//! both turns pod management on (`spawn_local_pod`) and delivers the key
//! ([`Issued::hand_to`]): there is no second reading of the label to disagree
//! with the first (ADR 0007 G-1).
//!
//! Why stdin rather than a file the proxy reads: a file is written at the
//! node's uid, which on the non-root local driver is the proxy's and so every
//! bare-tier child's. A pipe has no name to open. Its read end is
//! close-on-exec everywhere except as the proxy's fd 0, and the proxy drains
//! it before it spawns anything, after sealing itself non-dumpable, so the key
//! is then only in the memory of a process its children cannot read
//! (`nucleus::seal_runtime`).

use std::path::Path;
use uuid::Uuid;

use nucleus_identity::pod_files::PodKey;
#[cfg(feature = "local-driver")]
use nucleus_identity::pod_files::{KEY_ON_STDIN_ENV, RETIRED_KEY_FILE_ENV};
#[cfg(feature = "local-driver")]
use nucleus_spec::PodSpec;

use crate::{ApiError, NodeState};

/// The files' names, modes and variables are `nucleus_identity::pod_files`'s,
/// the one declaration the host-tier launchers write too (ADR 0007 G-1).
pub(crate) use nucleus_identity::pod_files::PodIdentityFiles as Files;

/// Whether a pod's tool-proxy calls this node as a client, read once from the
/// admitted plan. No `Default` (ADR 0007 B-1): each launch path asks.
#[cfg(feature = "local-driver")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NodeClient {
    /// The proxy calls no node, and is handed no key.
    Absent,
    /// An orchestrator pod: its proxy authenticates to the node's
    /// pod-management API with the pod's SVID, so it is handed the key.
    PodManagement,
}

#[cfg(feature = "local-driver")]
impl NodeClient {
    /// The local driver's decision, from the pod's `enable_pod_mgmt` label.
    pub(crate) fn of(spec: &PodSpec) -> Self {
        match spec
            .metadata
            .labels
            .get("enable_pod_mgmt")
            .map(String::as_str)
        {
            Some("true") => Self::PodManagement,
            Some(_) | None => Self::Absent,
        }
    }
}

/// A pod's identity, its public files written, its key not.
#[must_use = "an issued key is handed to the proxy or dropped by `hand_to`/`without_key`"]
pub(crate) struct Issued {
    files: Files,
    key: PodKey,
}

impl Issued {
    /// The written public files.
    #[cfg(all(test, feature = "local-driver"))]
    fn files(&self) -> &Files {
        &self.files
    }

    /// Configure the local proxy: the public files' variables always, and
    /// the key on its stdin exactly when `client` is a node client. Every
    /// key variable the node itself may carry is removed first, so none
    /// reaches the proxy by inheritance (`Command` does not `env_clear`).
    #[cfg(feature = "local-driver")]
    pub(crate) fn hand_to(
        self,
        command: &mut tokio::process::Command,
        client: NodeClient,
    ) -> Result<(), ApiError> {
        command
            .env_remove(RETIRED_KEY_FILE_ENV)
            .env_remove(KEY_ON_STDIN_ENV)
            .envs(self.files.env());
        match client {
            NodeClient::Absent => drop(self.key),
            NodeClient::PodManagement => {
                let pipe = self.key.into_pipe().map_err(|error| {
                    ApiError::Driver(format!("failed to hand the pod its key: {error}"))
                })?;
                command
                    .stdin(std::process::Stdio::from(pipe))
                    .env(KEY_ON_STDIN_ENV, "true");
            }
        }
        Ok(())
    }

    /// The public files alone, for a driver whose proxy calls no node (the
    /// container driver enables no node client). The key is dropped.
    pub(crate) fn without_key(self) -> Files {
        drop(self.key);
        self.files
    }
}

pub(crate) async fn provision(
    state: &NodeState,
    pod_dir: &Path,
    id: Uuid,
) -> Result<Issued, ApiError> {
    let manager = state
        .identity_manager
        .as_ref()
        .ok_or_else(|| ApiError::Driver("pod identity manager unavailable".into()))?;
    let tier = unmeasured_tier(&state.driver).ok_or_else(|| {
        ApiError::Driver(format!(
            "pod {id}: a Firecracker pod's identity is its measured launch, never a file-based \
             unmeasured one"
        ))
    })?;
    // The certificate says this tier did not measure the launch (ADR 0016 D5),
    // where it used to be a plain one that read like the absence of a check.
    let certificate = manager
        .issue_unmeasured_certificate(&manager.pod_identity(id), tier)
        .await
        .map_err(|error| ApiError::Driver(format!("failed to mint pod {id} identity: {error}")))?;
    let files = Files::at(pod_dir);
    let key = files
        .write(&certificate, manager.trust_bundle())
        .map_err(|error| ApiError::Driver(format!("failed to write pod {id} identity: {error}")))?;
    Ok(Issued { files, key })
}

/// The tier a driver launches on, when it cannot measure the launch. `None` for
/// Firecracker, whose launches are measured. Exhaustive, no `_` arm (E-2): a new
/// driver does not compile here until it says whether it measures.
fn unmeasured_tier(driver: &crate::driver::DriverKind) -> Option<nucleus_identity::UnmeasuredTier> {
    use crate::driver::DriverKind;
    use nucleus_identity::UnmeasuredTier;
    match driver {
        #[cfg(feature = "local-driver")]
        DriverKind::Local => Some(UnmeasuredTier::Local),
        DriverKind::Firecracker => None,
        DriverKind::Container => Some(UnmeasuredTier::Container),
        DriverKind::AppleVz => Some(UnmeasuredTier::AppleVz),
    }
}

#[cfg(all(test, feature = "local-driver"))]
mod client_tests {
    use super::*;

    fn spec(labels: &[(&str, &str)]) -> PodSpec {
        let labels: std::collections::BTreeMap<_, _> = labels
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        serde_json::from_value(serde_json::json!({
            "apiVersion": "nucleus/v1", "kind": "Pod",
            "metadata": {"name": "p", "labels": labels},
            "spec": {"policy": {"type": "profile", "name": "default"}}
        }))
        .unwrap()
    }

    /// #3471: only an orchestrator pod's proxy is a node client. Every other
    /// value of the label, and its absence, is not.
    #[test]
    fn only_an_orchestrator_pod_is_a_node_client() {
        assert_eq!(
            NodeClient::of(&spec(&[("enable_pod_mgmt", "true")])),
            NodeClient::PodManagement
        );
        for labels in [
            &[][..],
            &[("enable_pod_mgmt", "false")][..],
            &[("enable_pod_mgmt", "TRUE")][..],
            &[("enable_pod_mgmt", "")][..],
            &[("other", "true")][..],
        ] {
            assert_eq!(
                NodeClient::of(&spec(labels)),
                NodeClient::Absent,
                "{labels:?}"
            );
        }
    }
}

#[cfg(all(test, feature = "local-driver"))]
mod tests {
    use super::*;

    async fn issued(
        directory: &tempfile::TempDir,
    ) -> (Issued, Uuid, crate::identity::IdentityManager) {
        let mut state = crate::pod_api::handler_tests::state(directory);
        let manager = crate::identity::IdentityManager::new(
            "nucleus.local",
            std::time::Duration::from_secs(3600),
        )
        .unwrap();
        state.identity_manager = Some(manager.clone());
        let id = Uuid::new_v4();
        let issued = provision(&state, directory.path(), id).await.unwrap();
        (issued, id, manager)
    }

    /// The public files name the pod and chain to the node's root, and the
    /// identity directory holds no private key under any name (#3471). Red
    /// before: `key.pem` was written there for every local and container
    /// pod, at the node's uid.
    #[tokio::test]
    async fn issued_files_name_the_pod_and_hold_no_private_key() {
        let directory = tempfile::tempdir().unwrap();
        let (issued, id, manager) = issued(&directory).await;
        let files = issued.files();
        let cert = tokio::fs::read_to_string(files.directory().join("cert.pem"))
            .await
            .unwrap();
        let mut names: Vec<_> = std::fs::read_dir(files.directory())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["cert.pem", "trust-bundle.pem"], "no key file");
        for name in &names {
            let contents = std::fs::read_to_string(files.directory().join(name)).unwrap();
            assert!(!contents.contains("PRIVATE KEY"), "{name} holds a key");
        }
        let certificate =
            nucleus_identity::WorkloadCertificate::from_pem(&cert, issued.key.pem()).unwrap();
        assert_eq!(certificate.identity(), &manager.pod_identity(id));
        assert!(!certificate.is_expired());
        nucleus_identity::verify_svid_chain(certificate.leaf(), manager.trust_bundle()).unwrap();
        // ADR 0016 D5: the local tier cannot measure what it launches, and the
        // certificate says so by name, rather than being a plain one.
        assert_eq!(
            nucleus_identity::extract_unmeasured_launch(certificate.leaf().der()).unwrap(),
            Some(nucleus_identity::UnmeasuredTier::Local)
        );
        let refused = nucleus_identity::verify_attested_svid(
            &cert,
            manager.trust_bundle(),
            &nucleus_identity::AttestationRequirements::any(),
            true,
        )
        .expect_err("an unmeasured launch is not a measured one");
        assert!(refused.to_string().contains("`local` tier"), "{refused}");
        let bundle = tokio::fs::read_to_string(files.directory().join("trust-bundle.pem"))
            .await
            .unwrap();
        assert_eq!(
            bundle,
            manager
                .trust_bundle()
                .roots()
                .iter()
                .map(|root| root.to_pem().to_string())
                .collect::<Vec<_>>()
                .join("\n")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(files.directory()), 0o700);
            assert_eq!(mode(&files.directory().join("cert.pem")), 0o600);
        }
    }

    /// The env of a command, as `(name, Some(value) | None)` for removed.
    fn env(command: &tokio::process::Command) -> Vec<(String, Option<String>)> {
        command
            .as_std()
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect()
    }

    /// #3471, through a real child: a pod that is not a node client gets no
    /// key at all and its stdin is untouched; an orchestrator's proxy reads
    /// exactly the certificate's key on stdin, then end-of-file. Neither has
    /// a variable that names a key file.
    #[tokio::test]
    async fn the_key_reaches_only_a_node_clients_stdin() {
        for client in [NodeClient::Absent, NodeClient::PodManagement] {
            let directory = tempfile::tempdir().unwrap();
            let (issued, _, _) = issued(&directory).await;
            let expected = issued.key.pem().to_string();
            let cert_path = issued.files().directory().join("cert.pem");
            let mut command = tokio::process::Command::new("/bin/cat");
            command.stdin(std::process::Stdio::null());
            command.stdout(std::process::Stdio::piped());
            issued.hand_to(&mut command, client).unwrap();
            let vars = env(&command);
            assert!(
                vars.contains(&(RETIRED_KEY_FILE_ENV.into(), None)),
                "an inherited key path is removed: {vars:?}"
            );
            assert!(vars.contains(&(
                "NUCLEUS_IDENTITY_CERT".into(),
                Some(cert_path.to_string_lossy().into_owned())
            )));
            let out = command.output().await.unwrap();
            let stdin = String::from_utf8(out.stdout).unwrap();
            match client {
                NodeClient::Absent => {
                    assert_eq!(stdin, "", "no key on a non-client's stdin");
                    assert!(vars.contains(&(KEY_ON_STDIN_ENV.into(), None)), "{vars:?}");
                }
                NodeClient::PodManagement => {
                    assert_eq!(stdin, expected);
                    assert!(stdin.contains("PRIVATE KEY"));
                    assert!(
                        vars.contains(&(KEY_ON_STDIN_ENV.into(), Some("true".into()))),
                        "{vars:?}"
                    );
                }
            }
        }
    }
}

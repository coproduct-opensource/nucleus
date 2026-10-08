//! Node-issued pod identities for file-based proxy bootstrap.
//!
//! An ordinary SVID identifies the pod; it makes no microVM attestation claim.

use std::path::Path;
use uuid::Uuid;

use crate::{ApiError, NodeState};

/// The files' names, modes and variables are `nucleus_identity::pod_files`'s,
/// the one declaration the host-tier launchers write too (ADR 0007 G-1).
pub(crate) use nucleus_identity::pod_files::PodIdentityFiles as Files;

pub(crate) async fn provision(
    state: &NodeState,
    pod_dir: &Path,
    id: Uuid,
) -> Result<Files, ApiError> {
    let manager = state
        .identity_manager
        .as_ref()
        .ok_or_else(|| ApiError::Driver("pod identity manager unavailable".into()))?;
    let certificate = manager
        .fetch_certificate(&manager.pod_identity(id))
        .await
        .map_err(|error| ApiError::Driver(format!("failed to mint pod {id} identity: {error}")))?;
    let files = Files::at(pod_dir);
    files
        .write(&certificate, manager.trust_bundle())
        .map_err(|error| ApiError::Driver(format!("failed to write pod {id} identity: {error}")))?;
    Ok(files)
}

#[cfg(all(test, feature = "local-driver"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn issued_files_name_the_pod_and_keep_the_key_private() {
        let directory = tempfile::tempdir().unwrap();
        let mut state = crate::pod_api::handler_tests::state(&directory);
        let manager = crate::identity::IdentityManager::new(
            "nucleus.local",
            std::time::Duration::from_secs(3600),
        )
        .unwrap();
        state.identity_manager = Some(manager.clone());
        let id = Uuid::new_v4();
        let files = provision(&state, directory.path(), id).await.unwrap();
        let cert = tokio::fs::read_to_string(files.directory().join("cert.pem"))
            .await
            .unwrap();
        let key = tokio::fs::read_to_string(files.directory().join("key.pem"))
            .await
            .unwrap();
        let certificate = nucleus_identity::WorkloadCertificate::from_pem(&cert, &key).unwrap();
        assert_eq!(certificate.identity(), &manager.pod_identity(id));
        assert!(!certificate.is_expired());
        nucleus_identity::verify_svid_chain(certificate.leaf(), manager.trust_bundle()).unwrap();
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
            assert_eq!(
                std::fs::metadata(files.directory())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(files.directory().join("key.pem"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}

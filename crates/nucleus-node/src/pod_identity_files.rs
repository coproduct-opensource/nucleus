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
    files
        .write(&certificate, manager.trust_bundle())
        .map_err(|error| ApiError::Driver(format!("failed to write pod {id} identity: {error}")))?;
    Ok(files)
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

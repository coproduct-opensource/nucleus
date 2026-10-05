//! Node-issued pod identities for file-based proxy bootstrap.
//!
//! An ordinary SVID identifies the pod; it makes no microVM attestation claim.

use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use crate::{ApiError, NodeState};

pub(crate) struct Files {
    directory: PathBuf,
}

impl Files {
    pub(crate) fn at(pod_dir: &Path) -> Self {
        Self {
            directory: pod_dir.join("identity"),
        }
    }

    pub(crate) fn env(&self) -> impl Iterator<Item = (&'static str, PathBuf)> + '_ {
        [
            ("NUCLEUS_IDENTITY_CERT", "cert.pem"),
            ("NUCLEUS_IDENTITY_KEY", "key.pem"),
            ("NUCLEUS_IDENTITY_TRUST_BUNDLE", "trust-bundle.pem"),
        ]
        .into_iter()
        .map(|(key, name)| (key, self.directory.join(name)))
    }
}

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
    let mut directory = tokio::fs::DirBuilder::new();
    #[cfg(unix)]
    directory.mode(0o700);
    directory.create(&files.directory).await?;
    let bundle = manager
        .trust_bundle()
        .roots()
        .iter()
        .map(|root| root.to_pem().to_string())
        .collect::<Vec<_>>()
        .join("\n");
    for (name, contents) in [
        ("cert.pem", certificate.chain_pem()),
        ("key.pem", certificate.private_key_pem().to_string()),
        ("trust-bundle.pem", bundle),
    ] {
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(files.directory.join(name)).await?;
        file.write_all(contents.as_bytes()).await?;
        file.flush().await?;
    }
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
        let cert = tokio::fs::read_to_string(files.directory.join("cert.pem"))
            .await
            .unwrap();
        let key = tokio::fs::read_to_string(files.directory.join("key.pem"))
            .await
            .unwrap();
        let certificate = nucleus_identity::WorkloadCertificate::from_pem(&cert, &key).unwrap();
        assert_eq!(certificate.identity(), &manager.pod_identity(id));
        assert!(!certificate.is_expired());
        nucleus_identity::verify_svid_chain(certificate.leaf(), manager.trust_bundle()).unwrap();
        let bundle = tokio::fs::read_to_string(files.directory.join("trust-bundle.pem"))
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
                std::fs::metadata(&files.directory)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            assert_eq!(
                std::fs::metadata(files.directory.join("key.pem"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}

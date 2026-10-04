//! Own only the cgroup leaf this launch created. Never recursively remove a
//! hierarchy, and never claim ownership of an operator's existing directory.
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) struct Placement {
    owned: Option<PathBuf>,
}

impl Placement {
    #[cfg(any(test, target_os = "linux"))]
    pub(crate) async fn create(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let owned = match tokio::fs::create_dir(path).await {
            Ok(()) => Some(path.to_path_buf()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => None,
            Err(e) => return Err(e),
        };
        Ok(Self { owned })
    }

    /// Called after the VMM has stopped. Keep ownership on failure so teardown
    /// can be retried without releasing its capacity reservation prematurely.
    pub(crate) async fn cleanup(&mut self) -> std::io::Result<()> {
        if let Some(path) = &self.owned {
            remove_leaf(path).await?;
            self.owned = None;
        }
        Ok(())
    }
}

async fn remove_leaf(path: &Path) -> std::io::Result<()> {
    match tokio::fs::remove_dir(path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

impl Drop for Placement {
    fn drop(&mut self) {
        let Some(path) = self.owned.take() else {
            return;
        };
        // A cancelled launch drops its killing child too. Its process can take
        // a moment to exit, so give the now-empty leaf a bounded cleanup retry.
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move {
                    for _ in 0..40 {
                        match remove_leaf(&path).await {
                            Ok(()) => return,
                            Err(e) if matches!(e.kind(), std::io::ErrorKind::ResourceBusy | std::io::ErrorKind::DirectoryNotEmpty) => {
                                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                            }
                            Err(e) => {
                                tracing::warn!(path = %path.display(), error = %e, "cgroup leaf cleanup failed");
                                return;
                            }
                        }
                    }
                    tracing::warn!(path = %path.display(), "cgroup leaf remained busy after cleanup retries");
                });
            }
            Err(_) => {
                if let Err(e) = std::fs::remove_dir(&path) {
                    tracing::warn!(path = %path.display(), error = %e, "cgroup cleanup without runtime failed");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn completed_cleanup_removes_only_the_created_leaf() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("pod");
        let mut placed = Placement::create(&path).await.unwrap();
        assert!(path.is_dir());
        placed.cleanup().await.unwrap();
        placed.cleanup().await.unwrap();
        assert!(!path.exists());
        assert!(root.path().is_dir());
        let mut borrowed = Placement::create(root.path()).await.unwrap();
        borrowed.cleanup().await.unwrap();
        assert!(root.path().is_dir());
    }

    #[tokio::test]
    async fn cancelled_placement_retries_until_its_leaf_is_empty() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("pod");
        let placed = Placement::create(&path).await.unwrap();
        let busy = path.join("busy");
        tokio::fs::write(&busy, b"fixture").await.unwrap();
        drop(placed);
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        tokio::fs::remove_file(busy).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while path.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
}

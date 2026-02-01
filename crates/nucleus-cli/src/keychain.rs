//! Secure secret storage with macOS Keychain integration
//!
//! On macOS, secrets are stored in the system Keychain.
//! On Linux, secrets fall back to file-based storage with restricted permissions.
//!
//! Security features (per NIST SP 800-57):
//! - 32-byte cryptographically random secrets
//! - 90-day rotation tracking
//! - Audit logging for credential access

#[cfg_attr(target_os = "macos", allow(unused_imports))]
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const KEYCHAIN_SERVICE: &str = "com.nucleus.cli";
const SECRET_LENGTH: usize = 32;
const ROTATION_DAYS: i64 = 90;

/// Types of secrets stored in Keychain
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub enum SecretKind {
    /// HMAC secret for nucleus-node API authentication
    NodeAuthSecret,
    /// HMAC secret for tool-proxy request signing
    ProxyAuthSecret,
    /// HMAC secret for approval token signing
    ApprovalSecret,
}

impl SecretKind {
    /// Keychain account name for this secret type
    pub fn account_name(&self) -> &'static str {
        match self {
            Self::NodeAuthSecret => "node-auth-secret",
            Self::ProxyAuthSecret => "proxy-auth-secret",
            Self::ApprovalSecret => "approval-secret",
        }
    }

    /// Human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::NodeAuthSecret => "nucleus-node API authentication",
            Self::ProxyAuthSecret => "tool-proxy request signing",
            Self::ApprovalSecret => "approval token signing",
        }
    }

    /// All secret kinds
    pub fn all() -> &'static [SecretKind] {
        &[
            SecretKind::NodeAuthSecret,
            SecretKind::ProxyAuthSecret,
            SecretKind::ApprovalSecret,
        ]
    }
}

/// Metadata stored alongside secrets for rotation tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub created_at: DateTime<Utc>,
    pub rotation_due: DateTime<Utc>,
    pub version: u32,
}

impl SecretMetadata {
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            created_at: now,
            rotation_due: now + Duration::days(ROTATION_DAYS),
            version: 1,
        }
    }

    #[allow(dead_code)]
    pub fn needs_rotation(&self) -> bool {
        Utc::now() > self.rotation_due
    }

    pub fn days_until_rotation(&self) -> i64 {
        (self.rotation_due - Utc::now()).num_days()
    }

    pub fn increment_version(&mut self) {
        let now = Utc::now();
        self.created_at = now;
        self.rotation_due = now + Duration::days(ROTATION_DAYS);
        self.version += 1;
    }
}

impl Default for SecretMetadata {
    fn default() -> Self {
        Self::new()
    }
}

/// Secure secret storage abstraction
pub struct SecretStore;

impl SecretStore {
    /// Generate a cryptographically secure HMAC secret
    pub fn generate_secret() -> Vec<u8> {
        use rand::RngCore;
        let mut secret = vec![0u8; SECRET_LENGTH];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        secret
    }

    /// Get a secret from secure storage
    #[cfg(target_os = "macos")]
    pub fn get(kind: SecretKind) -> Result<Option<Vec<u8>>> {
        use security_framework::passwords::get_generic_password;

        match get_generic_password(KEYCHAIN_SERVICE, kind.account_name()) {
            Ok(password) => Ok(Some(password.to_vec())),
            Err(e) => {
                // errSecItemNotFound = -25300
                if e.code() == -25300 {
                    Ok(None)
                } else {
                    Err(anyhow!("Keychain error for {}: {}", kind.account_name(), e))
                }
            }
        }
    }

    /// Get a secret from file-based storage (Linux fallback)
    #[cfg(not(target_os = "macos"))]
    pub fn get(kind: SecretKind) -> Result<Option<Vec<u8>>> {
        let path = Self::secret_file_path(kind)?;
        if path.exists() {
            let content = std::fs::read(&path)
                .with_context(|| format!("Failed to read secret from {}", path.display()))?;
            Ok(Some(content))
        } else {
            Ok(None)
        }
    }

    /// Store a secret in secure storage
    #[cfg(target_os = "macos")]
    pub fn set(kind: SecretKind, secret: &[u8]) -> Result<()> {
        use security_framework::passwords::{delete_generic_password, set_generic_password};

        // Delete existing if present (ignore errors)
        let _ = delete_generic_password(KEYCHAIN_SERVICE, kind.account_name());

        set_generic_password(KEYCHAIN_SERVICE, kind.account_name(), secret)
            .map_err(|e| anyhow!("Failed to store {} in Keychain: {}", kind.account_name(), e))
    }

    /// Store a secret in file-based storage (Linux fallback)
    #[cfg(not(target_os = "macos"))]
    pub fn set(kind: SecretKind, secret: &[u8]) -> Result<()> {
        let path = Self::secret_file_path(kind)?;

        // Ensure directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Write secret
        std::fs::write(&path, secret)?;

        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }

        Ok(())
    }

    /// Delete a secret from secure storage
    #[cfg(target_os = "macos")]
    #[allow(dead_code)]
    pub fn delete(kind: SecretKind) -> Result<()> {
        use security_framework::passwords::delete_generic_password;

        match delete_generic_password(KEYCHAIN_SERVICE, kind.account_name()) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == -25300 => Ok(()), // Already doesn't exist
            Err(e) => Err(anyhow!(
                "Failed to delete {} from Keychain: {}",
                kind.account_name(),
                e
            )),
        }
    }

    /// Delete a secret from file-based storage (Linux fallback)
    #[cfg(not(target_os = "macos"))]
    #[allow(dead_code)]
    pub fn delete(kind: SecretKind) -> Result<()> {
        let path = Self::secret_file_path(kind)?;
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }

    /// Check if a secret exists
    pub fn exists(kind: SecretKind) -> Result<bool> {
        Ok(Self::get(kind)?.is_some())
    }

    /// Get the file path for a secret (Linux fallback)
    #[cfg(not(target_os = "macos"))]
    fn secret_file_path(kind: SecretKind) -> Result<PathBuf> {
        let config_dir =
            dirs::config_dir().ok_or_else(|| anyhow!("Could not determine config directory"))?;
        Ok(config_dir
            .join("nucleus")
            .join("secrets")
            .join(kind.account_name()))
    }

    /// Get or create a secret, returning whether it was newly created
    pub fn get_or_create(kind: SecretKind) -> Result<(Vec<u8>, bool)> {
        if let Some(secret) = Self::get(kind)? {
            Ok((secret, false))
        } else {
            let secret = Self::generate_secret();
            Self::set(kind, &secret)?;
            Ok((secret, true))
        }
    }
}

/// Metadata storage (separate from secrets, not sensitive)
pub struct MetadataStore;

impl MetadataStore {
    fn metadata_path() -> Result<PathBuf> {
        let config_dir =
            dirs::config_dir().ok_or_else(|| anyhow!("Could not determine config directory"))?;
        Ok(config_dir.join("nucleus").join("secrets-metadata.json"))
    }

    /// Load all secret metadata
    pub fn load() -> Result<std::collections::HashMap<String, SecretMetadata>> {
        let path = Self::metadata_path()?;
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            Ok(serde_json::from_str(&content)?)
        } else {
            Ok(std::collections::HashMap::new())
        }
    }

    /// Save all secret metadata
    pub fn save(metadata: &std::collections::HashMap<String, SecretMetadata>) -> Result<()> {
        let path = Self::metadata_path()?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(metadata)?;
        std::fs::write(&path, content)?;
        Ok(())
    }

    /// Get metadata for a specific secret
    pub fn get(kind: SecretKind) -> Result<Option<SecretMetadata>> {
        let all = Self::load()?;
        Ok(all.get(kind.account_name()).cloned())
    }

    /// Set metadata for a specific secret
    pub fn set(kind: SecretKind, metadata: SecretMetadata) -> Result<()> {
        let mut all = Self::load()?;
        all.insert(kind.account_name().to_string(), metadata);
        Self::save(&all)
    }
}

/// Initialize all secrets (generate if missing)
#[allow(dead_code)]
pub fn initialize_all_secrets() -> Result<()> {
    for kind in SecretKind::all() {
        let (_, created) = SecretStore::get_or_create(*kind)?;
        if created {
            MetadataStore::set(*kind, SecretMetadata::new())?;
            tracing::info!("Generated new secret: {}", kind.description());
        }
    }
    Ok(())
}

/// Check if any secrets need rotation
pub fn check_rotation_status() -> Result<Vec<(SecretKind, i64)>> {
    let mut warnings = Vec::new();
    for kind in SecretKind::all() {
        if let Some(metadata) = MetadataStore::get(*kind)? {
            let days = metadata.days_until_rotation();
            if days <= 14 {
                warnings.push((*kind, days));
            }
        }
    }
    Ok(warnings)
}

/// Rotate a secret
pub fn rotate_secret(kind: SecretKind) -> Result<()> {
    let new_secret = SecretStore::generate_secret();
    SecretStore::set(kind, &new_secret)?;

    let mut metadata = MetadataStore::get(kind)?.unwrap_or_default();
    metadata.increment_version();
    MetadataStore::set(kind, metadata)?;

    tracing::info!("Rotated secret: {}", kind.description());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_generation() {
        let secret = SecretStore::generate_secret();
        assert_eq!(secret.len(), SECRET_LENGTH);

        // Ensure randomness (two secrets should differ)
        let secret2 = SecretStore::generate_secret();
        assert_ne!(secret, secret2);
    }

    #[test]
    fn test_metadata_rotation_tracking() {
        let metadata = SecretMetadata::new();
        assert!(!metadata.needs_rotation());
        assert!(metadata.days_until_rotation() > 80);
    }

    #[test]
    fn test_secret_kind_names() {
        assert_eq!(
            SecretKind::NodeAuthSecret.account_name(),
            "node-auth-secret"
        );
        assert_eq!(
            SecretKind::ProxyAuthSecret.account_name(),
            "proxy-auth-secret"
        );
        assert_eq!(SecretKind::ApprovalSecret.account_name(), "approval-secret");
    }
}

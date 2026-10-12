//! Node-owned per-pod signing key. Only its public half enters the guest spec.
use crate::{ApiError, PodSpec};
use base64::Engine;
use std::{io::Write, path::Path};
pub(crate) const LABEL: &str = "nucleus.guest-proof";

pub(crate) fn provision(
    spec: &mut PodSpec,
    host_keys: &Path,
    id: uuid::Uuid,
) -> Result<(), ApiError> {
    if spec.metadata.labels.contains_key(LABEL) {
        return Err(ApiError::InvalidSpec(
            "guest proof identity is node-owned".into(),
        ));
    }
    let Some(raw) = spec.metadata.labels.get(crate::tool_proof_provision::LABEL) else {
        return Ok(());
    };
    let client: serde_json::Value = serde_json::from_str(raw).map_err(|_| invalid())?;
    let expires = client["expires"].as_u64().ok_or_else(invalid)?;
    let origin = format!("https://{id}.tools.nucleus.invalid");
    let csr = nucleus_identity::CsrOptions::new(format!("spiffe://nucleus.local/ns/pod/sa/{id}"))
        .generate()
        .map_err(|_| invalid())?;
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(csr.private_key().as_bytes()).map_err(|_| invalid())?;
    let sample =
        nucleus_identity::dpop::DpopProofBuilder::new("GET", &format!("{origin}/v1/health"))
            .build(&pem.contents)
            .map_err(|_| invalid())?;
    let header: nucleus_identity::dpop::DpopHeader = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(sample.split('.').next().ok_or_else(invalid)?)
            .map_err(|_| invalid())?,
    )
    .map_err(|_| invalid())?;
    let mut dirs = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        dirs.mode(0o700);
    }
    match dirs.create(host_keys) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    let metadata = std::fs::symlink_metadata(host_keys)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(invalid());
        }
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(host_keys.join(format!("{id}.der")))?;
    file.write_all(&pem.contents)?;
    file.sync_all()?;
    // The label is stamped only after durable key creation; no private material
    // is carried in launch specs, rootfs images, boot arguments or guest env.
    spec.metadata.labels.insert(
        LABEL.into(),
        serde_json::json!({
            "origin":origin,"key":{"kty":"EC","crv":"P-256","x":header.jwk.x,"y":header.jwk.y},
            "expires":expires
        })
        .to_string(),
    );
    Ok(())
}
fn invalid() -> ApiError {
    ApiError::InvalidSpec("guest proof provisioning failed".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn host_key_is_private_unique_and_never_overwritten() {
        let make = || {
            let mut spec: PodSpec = serde_json::from_value(serde_json::json!({
                "apiVersion":"nucleus/v1","kind":"Pod","metadata":{},"spec":{}
            }))
            .unwrap();
            spec.metadata.labels.insert(
                crate::tool_proof_provision::LABEL.into(),
                serde_json::json!({"expires":crate::now_unix()+300}).to_string(),
            );
            spec
        };
        let dir = tempfile::tempdir().unwrap();
        let mut spec = make();
        let id = uuid::Uuid::new_v4();
        provision(&mut spec, &dir.path().join("keys"), id).unwrap();
        let config: serde_json::Value = serde_json::from_str(&spec.metadata.labels[LABEL]).unwrap();
        assert_eq!(
            config["origin"],
            format!("https://{id}.tools.nucleus.invalid")
        );
        assert!(config["key"].get("d").is_none());
        let path = dir.path().join("keys").join(format!("{id}.der"));
        let original = std::fs::read(&path).unwrap();
        let signer = Signer::load(&spec, &dir.path().join("keys"), id)
            .unwrap()
            .unwrap();
        let body = b"exact tool body";
        let proof = signer.proof("POST", "/v1/read", body).unwrap();
        use sha2::{Digest, Sha256};
        let digest = hex::encode(Sha256::digest(body));
        let public = serde_json::from_value(config["key"].clone()).unwrap();
        let gate = nucleus_request_proof::ProofGate::open(
            config["origin"].as_str().unwrap(),
            &dir.path().join("replay"),
        )
        .unwrap();
        assert!(
            gate.verify(&proof, "POST", "/v1/read", Some("changed"), &public)
                .is_err()
        );
        gate.verify(&proof, "POST", "/v1/read", Some(&digest), &public)
            .unwrap()
            .into_thumbprint();
        assert!(
            gate.verify(&proof, "POST", "/v1/read", Some(&digest), &public)
                .is_err()
        );
        assert!(signer.proof("POST", "/v1/read?other", body).is_err());
        assert!(Signer::load(&spec, &dir.path().join("keys"), uuid::Uuid::new_v4()).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(provision(&mut spec, &dir.path().join("keys"), id).is_err());
        assert!(provision(&mut make(), &dir.path().join("keys"), id).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        let other = tempfile::tempdir().unwrap();
        let mut next = make();
        provision(&mut next, &other.path().join("keys"), uuid::Uuid::new_v4()).unwrap();
        assert_ne!(spec.metadata.labels[LABEL], next.metadata.labels[LABEL]);
    }
}

/// Private host capability, deliberately neither Debug nor Serialize.
#[derive(Clone)]
pub(crate) struct Signer {
    origin: String,
    key: std::sync::Arc<Vec<u8>>,
    expires: u64,
}
impl Signer {
    pub(crate) fn load(
        spec: &PodSpec,
        host_keys: &Path,
        id: uuid::Uuid,
    ) -> Result<Option<Self>, ApiError> {
        let Some(raw) = spec.metadata.labels.get(LABEL) else {
            if spec
                .metadata
                .labels
                .contains_key(crate::tool_proof_provision::LABEL)
            {
                return Err(invalid());
            }
            return Ok(None);
        };
        let value: serde_json::Value = serde_json::from_str(raw).map_err(|_| invalid())?;
        let origin = format!("https://{id}.tools.nucleus.invalid");
        if value["origin"].as_str() != Some(origin.as_str()) {
            return Err(invalid());
        }
        let expires = value["expires"].as_u64().ok_or_else(invalid)?;
        let public: nucleus_identity::did::JsonWebKey =
            serde_json::from_value(value["key"].clone()).map_err(|_| invalid())?;
        let path = host_keys.join(format!("{id}.der"));
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.len() > 4096 {
            return Err(invalid());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(invalid());
            }
        }
        let key = std::fs::read(path)?;
        let signer = Self {
            origin,
            key: std::sync::Arc::new(key),
            expires,
        };
        let proof = signer
            .proof("GET", "/v1/health", b"")
            .map_err(|_| invalid())?;
        let header: nucleus_identity::dpop::DpopHeader = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(proof.split('.').next().ok_or_else(invalid)?)
                .map_err(|_| invalid())?,
        )
        .map_err(|_| invalid())?;
        if nucleus_request_proof::thumbprint(&header.jwk).map_err(|_| invalid())?
            != nucleus_request_proof::thumbprint(&public).map_err(|_| invalid())?
        {
            return Err(invalid());
        }
        Ok(Some(signer))
    }
    pub(crate) fn proof(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<String, std::io::Error> {
        use sha2::{Digest, Sha256};
        if crate::now_unix().max(0) as u64 >= self.expires
            || !path.starts_with('/')
            || path.starts_with("//")
            || path.contains(['?', '#'])
        {
            return Err(std::io::Error::other("guest proof target or lease refused"));
        }
        let digest = hex::encode(Sha256::digest(body));
        nucleus_identity::dpop::DpopProofBuilder::new(method, &format!("{}{path}", self.origin))
            .with_access_token(&digest)
            .build(&self.key)
            .map_err(std::io::Error::other)
    }
}

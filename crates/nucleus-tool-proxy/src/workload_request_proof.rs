//! Per-pod workload proofs supplement the kernel-authenticated Unix door.
//! Key recovery is runtime-owned; workload-visible copies never establish trust.
use crate::{ApiError, PodSpec};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use nucleus_identity::did::JsonWebKey;
use p256::{ecdsa::SigningKey, pkcs8::DecodePrivateKey};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Provision {
    version: u32,
    origin: String,
    expires: u64,
    private_key: String,
}
pub(crate) struct Gate {
    inner: nucleus_request_proof::ProofGate,
    key: JsonWebKey,
    expires: u64,
}
fn refused() -> ApiError {
    ApiError::Auth(crate::auth::AuthError::InvalidHeader("dpop"))
}
fn now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}
fn key(config: &Provision) -> Result<SigningKey, ApiError> {
    let bytes = STANDARD
        .decode(&config.private_key)
        .map_err(|_| refused())?;
    SigningKey::from_slice(&bytes).map_err(|_| refused())
}
fn open(config: &Provision, path: &Path) -> Result<Gate, ApiError> {
    let secret = key(config)?;
    let point = secret.verifying_key().to_encoded_point(false);
    let public = JsonWebKey::ec_p256(
        URL_SAFE_NO_PAD.encode(point.x().ok_or_else(refused)?),
        URL_SAFE_NO_PAD.encode(point.y().ok_or_else(refused)?),
    );
    Ok(Gate {
        inner: nucleus_request_proof::ProofGate::open(&config.origin, path)
            .map_err(|_| refused())?,
        key: public,
        expires: config.expires,
    })
}
pub(crate) fn provision_runtime(
    spec: &PodSpec,
    directory: &Path,
) -> Result<Option<Gate>, ApiError> {
    use std::os::unix::fs::DirBuilderExt;
    if spec.spec.workload.is_none()
        || crate::guest_request_proof::Config::from_spec(spec)?.is_none()
    {
        return Ok(None);
    }
    if !nix::unistd::geteuid().is_root() || !directory.is_absolute() {
        return Err(refused());
    }
    // Create only one level under an existing trusted parent. Never follow a
    // workload-supplied symlink or repair unsafe permissions into acceptability.
    let parent = directory.parent().ok_or_else(refused)?;
    let parent_meta = parent.symlink_metadata().map_err(|_| refused())?;
    if !parent_meta.is_dir() || parent_meta.uid() != 0 || parent_meta.mode() & 0o022 != 0 {
        return Err(refused());
    }
    if parent
        .canonicalize()
        .map_err(|_| refused())?
        .starts_with(spec.spec.work_dir.canonicalize().map_err(|_| refused())?)
    {
        return Err(refused());
    }
    match std::fs::DirBuilder::new().mode(0o700).create(directory) {
        Ok(()) => std::fs::File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|_| refused())?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(refused()),
    }
    provision(spec, &directory.join("replay.olog"))
}

fn provision(spec: &PodSpec, replay: &Path) -> Result<Option<Gate>, ApiError> {
    let Some(workload) = spec.spec.workload.as_ref() else {
        return Ok(None);
    };
    if crate::guest_request_proof::Config::from_spec(spec)?.is_none() {
        return Ok(None);
    };
    if !nix::unistd::geteuid().is_root() {
        return Err(refused());
    }
    let uid = workload.uid.filter(|uid| *uid != 0).ok_or_else(refused)?;
    let label: serde_json::Value =
        serde_json::from_str(&spec.metadata.labels["nucleus.guest-proof"])
            .map_err(|_| refused())?;
    let origin = label["origin"]
        .as_str()
        .ok_or_else(refused)?
        .replace(".tools.nucleus.invalid", ".workload.nucleus.invalid");
    let expires = label["expires"].as_u64().ok_or_else(refused)?;
    let master = replay.with_extension("key.json");
    let parent = master.parent().ok_or_else(refused)?;
    // Work dir ownership is handed to the workload later in launch. Checking
    // its current root ownership alone would not protect durable authority.
    let work_root = spec.spec.work_dir.canonicalize().map_err(|_| refused())?;
    let authority_root = parent.canonicalize().map_err(|_| refused())?;
    if authority_root.starts_with(&work_root) {
        return Err(refused());
    }
    let meta = parent.symlink_metadata().map_err(|_| refused())?;
    if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err(refused());
    }
    let config = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(&master)
    {
        Ok(file) => {
            let meta = file.metadata().map_err(|_| refused())?;
            if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o077 != 0 || meta.len() > 4096 {
                return Err(refused());
            }
            let mut bytes = Vec::new();
            file.take(4097)
                .read_to_end(&mut bytes)
                .map_err(|_| refused())?;
            let config: Provision = serde_json::from_slice(&bytes).map_err(|_| refused())?;
            if config.version != 1 || config.origin != origin || config.expires != expires {
                return Err(refused());
            }
            config
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let csr =
                nucleus_identity::CsrOptions::new("spiffe://nucleus.local/ns/workload/sa/proof")
                    .generate()
                    .map_err(|_| refused())?;
            let (_, pem) = x509_parser::pem::parse_x509_pem(csr.private_key().as_bytes())
                .map_err(|_| refused())?;
            let secret = SigningKey::from_pkcs8_der(&pem.contents).map_err(|_| refused())?;
            let config = Provision {
                version: 1,
                origin,
                expires,
                private_key: STANDARD.encode(secret.to_bytes()),
            };
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&master)
                .map_err(|_| refused())?;
            file.write_all(&serde_json::to_vec(&config).map_err(|_| refused())?)
                .map_err(|_| refused())?;
            file.sync_all().map_err(|_| refused())?;
            std::fs::File::open(parent)
                .and_then(|f| f.sync_all())
                .map_err(|_| refused())?;
            config
        }
        Err(_) => return Err(refused()),
    };
    let gate = open(&config, replay)?;
    // Replace only the disposable workload copy, never recover authority from it.
    let stage = spec
        .spec
        .work_dir
        .join(format!(".workload-proof-{}", uuid::Uuid::new_v4()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&stage)
        .map_err(|_| refused())?;
    file.write_all(&serde_json::to_vec(&config).map_err(|_| refused())?)
        .map_err(|_| refused())?;
    nix::unistd::fchown(&file, Some(nix::unistd::Uid::from_raw(uid)), None)
        .map_err(|_| refused())?;
    file.set_permissions(std::fs::Permissions::from_mode(0o400))
        .map_err(|_| refused())?;
    file.sync_all().map_err(|_| refused())?;
    std::fs::rename(
        &stage,
        spec.spec.work_dir.join(".nucleus-workload-proof.json"),
    )
    .map_err(|_| refused())?;
    std::fs::File::open(&spec.spec.work_dir)
        .and_then(|f| f.sync_all())
        .map_err(|_| refused())?;
    Ok(Some(gate))
}
impl Gate {
    pub(crate) fn verify(
        &self,
        headers: &axum::http::HeaderMap,
        method: &str,
        uri: &axum::http::Uri,
        body: &[u8],
    ) -> Result<(), ApiError> {
        use sha2::{Digest, Sha256};
        if now() >= self.expires
            || uri.query().is_some()
            || headers.get_all("dpop").iter().count() != 1
        {
            return Err(refused());
        }
        let proof = headers
            .get("dpop")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(refused)?;
        self.inner
            .verify(
                proof,
                method,
                uri.path(),
                Some(&hex::encode(Sha256::digest(body))),
                &self.key,
            )
            .map_err(|_| refused())?
            .into_thumbprint();
        if now() >= self.expires {
            return Err(refused());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires root in an isolated Linux test container"]
    fn root_provisioning_preserves_authority_and_replay_on_restart() {
        use p256::pkcs8::EncodePrivateKey;
        assert!(nix::unistd::geteuid().is_root());
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let work = dir.path().join("work");
        std::fs::create_dir(&work).unwrap();
        let csr = nucleus_identity::CsrOptions::new("spiffe://test/ns/node/sa/proof")
            .generate()
            .unwrap();
        let (_, pem) = x509_parser::pem::parse_x509_pem(csr.private_key().as_bytes()).unwrap();
        let secret = SigningKey::from_pkcs8_der(&pem.contents).unwrap();
        let point = secret.verifying_key().to_encoded_point(false);
        let label = serde_json::json!({"origin":format!("https://{}.tools.nucleus.invalid",uuid::Uuid::new_v4()),"expires":now()+300,
            "key":{"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),"y":URL_SAFE_NO_PAD.encode(point.y().unwrap())}});
        let spec: PodSpec =
            serde_json::from_value(serde_json::json!({"apiVersion":"nucleus/v1","kind":"Pod",
            "metadata":{"labels":{"nucleus.guest-proof":label.to_string()}},
            "spec":{"work_dir":work,"workload":{"command":"/bin/true","uid":65534}}}))
            .unwrap();
        let replay = dir.path().join("workload-proofs.olog");
        assert!(provision(&spec, &work.join("forbidden.olog")).is_err());
        assert!(provision_runtime(&spec, &work.join("forbidden")).is_err());
        let runtime = dir.path().join("runtime");
        drop(provision_runtime(&spec, &runtime).unwrap().unwrap());
        assert_eq!(runtime.metadata().unwrap().mode() & 0o777, 0o700);
        drop(provision_runtime(&spec, &runtime).unwrap().unwrap());
        let link = dir.path().join("runtime-link");
        std::os::unix::fs::symlink(&runtime, &link).unwrap();
        assert!(provision_runtime(&spec, &link).is_err());
        let copy = work.join(".nucleus-workload-proof.json");
        let gate = provision(&spec, &replay).unwrap().unwrap();
        let master = replay.with_extension("key.json");
        let before = std::fs::read(&master).unwrap();
        let meta = copy.metadata().unwrap();
        assert_eq!(meta.uid(), 65534);
        assert_eq!(meta.mode() & 0o777, 0o400);
        assert_eq!(master.metadata().unwrap().uid(), 0);
        assert_eq!(master.metadata().unwrap().mode() & 0o777, 0o600);
        let config: Provision = serde_json::from_slice(&before).unwrap();
        let der = key(&config).unwrap().to_pkcs8_der().unwrap();
        let proof = nucleus_identity::dpop::DpopProofBuilder::new(
            "POST",
            &format!("{}/v1/read", config.origin),
        )
        .with_access_token(&hex::encode(Sha256::digest(b"body")))
        .build(der.as_bytes())
        .unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("dpop", proof.parse().unwrap());
        gate.verify(&headers, "POST", &"/v1/read".parse().unwrap(), b"body")
            .unwrap();
        drop(gate);
        std::fs::remove_file(&copy).unwrap();
        std::os::unix::fs::symlink(&master, &copy).unwrap();
        let gate = provision(&spec, &replay).unwrap().unwrap();
        assert!(copy.symlink_metadata().unwrap().is_file());
        assert_eq!(std::fs::read(&master).unwrap(), before);
        assert_eq!(std::fs::read(&copy).unwrap(), before);
        assert!(
            gate.verify(&headers, "POST", &"/v1/read".parse().unwrap(), b"body")
                .is_err()
        );
        drop(gate);
        std::fs::set_permissions(&master, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(provision(&spec, &replay).is_err());
    }
    #[test]
    fn workload_proof_is_key_body_target_bound_and_replay_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let csr = nucleus_identity::CsrOptions::new("spiffe://test/ns/workload/sa/proof")
            .generate()
            .unwrap();
        let (_, pem) = x509_parser::pem::parse_x509_pem(csr.private_key().as_bytes()).unwrap();
        let secret = SigningKey::from_pkcs8_der(&pem.contents).unwrap();
        let config = Provision {
            version: 1,
            origin: format!("https://{}.workload.nucleus.invalid", uuid::Uuid::new_v4()),
            expires: now() + 300,
            private_key: STANDARD.encode(secret.to_bytes()),
        };
        let replay = dir.path().join("replay.olog");
        let mut gate = open(&config, &replay).unwrap();
        let body = b"exact workload body";
        let digest = hex::encode(Sha256::digest(body));
        let proof = nucleus_identity::dpop::DpopProofBuilder::new(
            "POST",
            &format!("{}/v1/read", config.origin),
        )
        .with_access_token(&digest)
        .build(&pem.contents)
        .unwrap();
        let uri = "/v1/read".parse().unwrap();
        let mut headers = axum::http::HeaderMap::new();
        assert!(gate.verify(&headers, "POST", &uri, body).is_err());
        headers.insert("dpop", proof.parse().unwrap());
        assert!(gate.verify(&headers, "GET", &uri, body).is_err());
        assert!(gate.verify(&headers, "POST", &uri, b"altered").is_err());
        assert!(
            gate.verify(&headers, "POST", &"/v1/write".parse().unwrap(), body)
                .is_err()
        );
        assert!(
            gate.verify(
                &headers,
                "POST",
                &"/v1/read?q=unbound".parse().unwrap(),
                body
            )
            .is_err()
        );
        headers.append("dpop", proof.parse().unwrap());
        assert!(gate.verify(&headers, "POST", &uri, body).is_err());
        headers.remove("dpop");
        headers.insert("dpop", proof.parse().unwrap());
        let other = nucleus_identity::CsrOptions::new("spiffe://test/ns/other/sa/proof")
            .generate()
            .unwrap();
        let (_, wrong) = x509_parser::pem::parse_x509_pem(other.private_key().as_bytes()).unwrap();
        let wrong_proof = nucleus_identity::dpop::DpopProofBuilder::new(
            "POST",
            &format!("{}/v1/read", config.origin),
        )
        .with_access_token(&digest)
        .build(&wrong.contents)
        .unwrap();
        let mut wrong_headers = headers.clone();
        wrong_headers.insert("dpop", wrong_proof.parse().unwrap());
        assert!(gate.verify(&wrong_headers, "POST", &uri, body).is_err());
        gate.verify(&headers, "POST", &uri, body).unwrap();
        assert!(gate.verify(&headers, "POST", &uri, body).is_err());
        gate.expires = now();
        assert!(gate.verify(&headers, "POST", &uri, body).is_err());
        drop(gate);
        let gate = open(&config, &replay).unwrap();
        assert!(gate.verify(&headers, "POST", &uri, body).is_err());
    }
}

//! The files a tool-proxy proves its launch with.
//!
//! A pod's SVID, its private key and the root that issued it, at fixed names
//! under `<pod_dir>/identity`, handed to the proxy as
//! `NUCLEUS_IDENTITY_{CERT,KEY,TRUST_BUNDLE}`. The proxy reads a certificate
//! that names a SPIFFE ID and makes no launch claim as sandbox proof tier 2
//! (`SpiffeIdentity`), which needs no shared secret.
//!
//! One declaration for every launcher (ADR 0007 G-1). nucleus-node's local and
//! container drivers write these files from the node's CA. The host-tier
//! launchers (`nucleus run --local`, `nucleus shell` and nucleus-perf) write
//! them from a CA that exists only for the launch ([`issue_ephemeral`]).
//! Before #2446 step 3a those launchers proved the proxy with tier 3 instead:
//! an orchestrator token HMAC'd with a secret they passed on the proxy's
//! command line as `--auth-secret`, which only that check still read.
//!
//! What the proof is worth on the host tier: the same as the token it
//! replaces. The launcher vouches for its own child either way, and the proxy
//! attests `Unsandboxed` for tier 2 as it did for tier 3. What changes is that
//! no secret is minted, put on an argv any local user can read, or kept.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::ca::{CaClient, SelfSignedCa};
use crate::certificate::{TrustBundle, WorkloadCertificate};
use crate::{Identity, Result};

/// The trust domain of a certificate [`issue_ephemeral`] mints. Named for the
/// tier, so the proxy's boot line (`tier=2/spiffe-identity spiffe_id=…`) says
/// a host-tier launcher, not a node, issued it.
pub const HOST_TIER_TRUST_DOMAIN: &str = "host-tier.nucleus.local";

/// The SPIFFE namespace every pod identity is issued in, by a node or by a
/// host-tier launcher.
pub const POD_NAMESPACE: &str = "pods";

/// The env each file is exported as, and its name in the directory.
const FILES: [(&str, &str); 3] = [
    ("NUCLEUS_IDENTITY_CERT", "cert.pem"),
    ("NUCLEUS_IDENTITY_KEY", "key.pem"),
    ("NUCLEUS_IDENTITY_TRUST_BUNDLE", "trust-bundle.pem"),
];

/// Where a pod's identity files are, or will be.
#[derive(Debug)]
pub struct PodIdentityFiles {
    directory: PathBuf,
}

impl PodIdentityFiles {
    /// The identity directory of the pod whose directory is `pod_dir`. A
    /// container driver names the path the files have inside the container.
    pub fn at(pod_dir: &Path) -> Self {
        Self {
            directory: pod_dir.join("identity"),
        }
    }

    /// The directory holding the three files.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Each variable the proxy reads, and the path it names.
    pub fn env(&self) -> impl Iterator<Item = (&'static str, PathBuf)> + '_ {
        FILES
            .into_iter()
            .map(|(key, name)| (key, self.directory.join(name)))
    }

    /// Write `certificate` and the roots of `bundle`.
    ///
    /// The directory is created `0700` and must not exist; each file is
    /// created new, `0600`. A pod's key is written once, by its launcher, and
    /// never over something already there.
    pub fn write(&self, certificate: &WorkloadCertificate, bundle: &TrustBundle) -> Result<()> {
        use std::io::Write as _;

        let mut directory = std::fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut directory, 0o700);
        directory.create(&self.directory)?;
        let roots = bundle
            .roots()
            .iter()
            .map(|root| root.to_pem().to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let contents = [
            certificate.chain_pem(),
            certificate.private_key_pem().to_string(),
            roots,
        ];
        for ((_, name), contents) in FILES.into_iter().zip(contents) {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            let mut file = options.open(self.directory.join(name))?;
            file.write_all(contents.as_bytes())?;
            file.flush()?;
        }
        Ok(())
    }
}

/// Issue `pod_id` an identity from a CA made for this call, and write it under
/// `pod_dir`.
///
/// The CA's key is dropped on return, so nothing can issue another
/// certificate under the root written beside this one.
///
/// # Errors
///
/// When `pod_id` is not a valid SPIFFE path segment, when key generation or
/// signing fails, or when the files cannot be written (including when the
/// identity directory already exists).
pub fn issue_ephemeral(pod_dir: &Path, pod_id: &str, ttl: Duration) -> Result<PodIdentityFiles> {
    let ca = SelfSignedCa::new(HOST_TIER_TRUST_DOMAIN)?;
    let identity = Identity::try_new(HOST_TIER_TRUST_DOMAIN, POD_NAMESPACE, pod_id)?;
    let certificate = ca.issue_unmeasured(&identity, ttl, crate::UnmeasuredTier::Host)?;
    let files = PodIdentityFiles::at(pod_dir);
    files.write(&certificate, ca.trust_bundle())?;
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(files: &PodIdentityFiles, key: &str) -> String {
        let (_, path) = files.env().find(|(k, _)| *k == key).unwrap();
        std::fs::read_to_string(path).unwrap()
    }

    /// The minted identity names the pod, chains to the root written beside
    /// it, and makes no measured launch claim: it is tier 2, never a forged tier 1.
    /// It says so: the unmeasured-launch extension names the host tier.
    #[test]
    fn an_ephemeral_identity_names_the_pod_and_chains_to_its_root() {
        let dir = tempfile::tempdir().unwrap();
        let files = issue_ephemeral(dir.path(), "run-123", Duration::from_secs(600)).unwrap();
        let cert = read(&files, "NUCLEUS_IDENTITY_CERT");
        let key = read(&files, "NUCLEUS_IDENTITY_KEY");
        let certificate = WorkloadCertificate::from_pem(&cert, &key).unwrap();
        assert_eq!(
            certificate.identity().to_spiffe_uri(),
            "spiffe://host-tier.nucleus.local/ns/pods/sa/run-123"
        );
        assert!(!certificate.is_expired());
        let bundle = TrustBundle::from_pem(&read(&files, "NUCLEUS_IDENTITY_TRUST_BUNDLE")).unwrap();
        crate::verify_svid_chain(certificate.leaf(), &bundle).unwrap();
        assert!(crate::extract_launch_attestation(certificate.leaf().der()).is_none());
        // It states that the host tier did not measure the launch (ADR 0016 D5),
        // and a verifier that requires a measured launch refuses it by that name.
        assert_eq!(
            crate::extract_unmeasured_launch(certificate.leaf().der()).unwrap(),
            Some(crate::UnmeasuredTier::Host)
        );
        let err = crate::verify_attested_svid(
            &cert,
            &bundle,
            &crate::AttestationRequirements::any(),
            true,
        )
        .expect_err("an unmeasured launch is not a measured one");
        assert!(err.to_string().contains("`host` tier"), "{err}");
    }

    /// The key is private to its owner, and a second launch into the same
    /// directory is refused rather than overwriting the first.
    #[cfg(unix)]
    #[test]
    fn the_files_are_private_and_written_once() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let files = issue_ephemeral(dir.path(), "once", Duration::from_secs(600)).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(files.directory()), 0o700);
        for (_, path) in files.env() {
            assert_eq!(mode(&path), 0o600, "{}", path.display());
        }
        assert!(issue_ephemeral(dir.path(), "once", Duration::from_secs(600)).is_err());
    }

    /// The names are the ones the tool-proxy reads (`--identity-cert` and its
    /// siblings are bound to exactly these variables).
    #[test]
    fn the_env_names_are_the_proxys() {
        let files = PodIdentityFiles::at(Path::new("/data/pod"));
        let env: Vec<_> = files.env().collect();
        assert_eq!(
            env,
            vec![
                (
                    "NUCLEUS_IDENTITY_CERT",
                    PathBuf::from("/data/pod/identity/cert.pem")
                ),
                (
                    "NUCLEUS_IDENTITY_KEY",
                    PathBuf::from("/data/pod/identity/key.pem")
                ),
                (
                    "NUCLEUS_IDENTITY_TRUST_BUNDLE",
                    PathBuf::from("/data/pod/identity/trust-bundle.pem")
                ),
            ]
        );
    }
}

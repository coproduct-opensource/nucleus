//! The files a tool-proxy proves its launch with, and the key it may be handed.
//!
//! A pod's SVID and the root that issued it, at fixed names under
//! `<pod_dir>/identity`, handed to the proxy as
//! `NUCLEUS_IDENTITY_{CERT,TRUST_BUNDLE}`. The proxy reads a certificate
//! that names a SPIFFE ID and makes no launch claim as sandbox proof tier 2
//! (`SpiffeIdentity`), which needs no shared secret and no private key.
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
//!
//! # The private key is never a file (#3471)
//!
//! The certificate's private key is read only by a proxy that calls the node
//! as a client (pod management, lockdown). A launcher used to write it beside
//! the certificate for every pod, at its own uid: on the non-root local
//! driver and the host tier that is the proxy's uid, so every child of the
//! proxy could open it, whether or not the proxy ever read it. Now
//! [`PodIdentityFiles::write`] writes only the public files and hands the key
//! back as a [`PodKey`]. A launcher whose proxy needs it delivers it with
//! [`PodKey::into_pipe`], a pipe that becomes the proxy's stdin and is read
//! once at startup ([`KEY_ON_STDIN_ENV`]); every other launcher drops it, and
//! the key exists nowhere but briefly in the launcher's memory.

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

/// The env each file is exported as, and its name in the directory. Public
/// material only: there is no key file (#3471).
const FILES: [(&str, &str); 2] = [
    ("NUCLEUS_IDENTITY_CERT", "cert.pem"),
    ("NUCLEUS_IDENTITY_TRUST_BUNDLE", "trust-bundle.pem"),
];

/// The variable a launcher sets (to `true`) when it delivers the pod's key on
/// the proxy's stdin ([`PodKey::into_pipe`]). The proxy reads stdin to its end
/// once, at startup, before it spawns anything.
pub const KEY_ON_STDIN_ENV: &str = "NUCLEUS_IDENTITY_KEY_ON_STDIN";

/// The variable a key FILE used to be named by. A launcher removes it from
/// what its proxy inherits, so no stale path reaches a proxy by inheritance.
pub const RETIRED_KEY_FILE_ENV: &str = "NUCLEUS_IDENTITY_KEY";

/// The largest key a proxy accepts on stdin. A PEM private key is a few
/// hundred bytes; the bound keeps a misdirected stream from being buffered.
pub const KEY_ON_STDIN_MAX: u64 = 16 * 1024;

/// A pod's private key, which no launcher writes to a file (#3471).
///
/// Not `Clone`, and taken by value to deliver (ADR 0007 C-4): one key reaches
/// at most one proxy. Dropping it is the decision that the proxy reads no key.
#[must_use = "a pod key is delivered with `into_pipe` or dropped, never written"]
pub struct PodKey {
    pem: String,
}

impl std::fmt::Debug for PodKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PodKey(<redacted>)")
    }
}

impl PodKey {
    /// The key in a pipe, written whole and closed: the read end, for the
    /// proxy's stdin (`Stdio::from`), reads the PEM and then end-of-file.
    ///
    /// Both ends are close-on-exec (`std::io::pipe`), so no other process the
    /// launcher spawns inherits the read end; only the child whose stdin it
    /// becomes holds it. The write end is closed before this returns.
    ///
    /// # Errors
    /// When the pipe cannot be created or written (a PEM key is far below
    /// any pipe's capacity, so the write does not block).
    pub fn into_pipe(self) -> std::io::Result<std::io::PipeReader> {
        use std::io::Write as _;
        let (reader, mut writer) = std::io::pipe()?;
        writer.write_all(self.pem.as_bytes())?;
        drop(writer);
        Ok(reader)
    }

    /// The PEM, for a launcher's own test of what it delivers.
    pub fn pem(&self) -> &str {
        &self.pem
    }
}

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

    /// Write `certificate`'s chain and the roots of `bundle`, and return its
    /// private key unwritten.
    ///
    /// The directory is created `0700` and must not exist; each file is
    /// created new, `0600`, never over something already there. The key is
    /// not one of the files (#3471): see [`PodKey`].
    pub fn write(&self, certificate: &WorkloadCertificate, bundle: &TrustBundle) -> Result<PodKey> {
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
        let contents = [certificate.chain_pem(), roots];
        for ((_, name), contents) in FILES.into_iter().zip(contents) {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            let mut file = options.open(self.directory.join(name))?;
            file.write_all(contents.as_bytes())?;
            file.flush()?;
        }
        Ok(PodKey {
            pem: certificate.private_key_pem().to_string(),
        })
    }
}

/// Issue `pod_id` an identity from a CA made for this call, and write it under
/// `pod_dir`. The private key is dropped, never written: a host-tier proxy
/// calls no node, so nothing reads it (#3471). [`issue_ephemeral_keyed`]
/// returns it instead.
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
    let (files, unread) = issue_ephemeral_keyed(pod_dir, pod_id, ttl)?;
    drop(unread);
    Ok(files)
}

/// [`issue_ephemeral`], with the private key handed back for a launcher that
/// delivers it ([`PodKey::into_pipe`]).
///
/// # Errors
/// As [`issue_ephemeral`].
pub fn issue_ephemeral_keyed(
    pod_dir: &Path,
    pod_id: &str,
    ttl: Duration,
) -> Result<(PodIdentityFiles, PodKey)> {
    let ca = SelfSignedCa::new(HOST_TIER_TRUST_DOMAIN)?;
    let identity = Identity::try_new(HOST_TIER_TRUST_DOMAIN, POD_NAMESPACE, pod_id)?;
    let certificate = ca.issue_unmeasured(&identity, ttl, crate::UnmeasuredTier::Host)?;
    let files = PodIdentityFiles::at(pod_dir);
    let key = files.write(&certificate, ca.trust_bundle())?;
    Ok((files, key))
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
    /// It says so: the unmeasured-launch extension names the host tier. The
    /// key that comes back unwritten is the certificate's own.
    #[test]
    fn an_ephemeral_identity_names_the_pod_and_chains_to_its_root() {
        let dir = tempfile::tempdir().unwrap();
        let (files, key) =
            issue_ephemeral_keyed(dir.path(), "run-123", Duration::from_secs(600)).unwrap();
        let cert = read(&files, "NUCLEUS_IDENTITY_CERT");
        let certificate = WorkloadCertificate::from_pem(&cert, key.pem()).unwrap();
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

    /// #3471: the identity directory holds the public files and nothing else.
    /// No file in it, under any name, contains the private key. Red before:
    /// `key.pem` was written beside the certificate for every pod, at the
    /// launcher's uid, which is a bare-tier child's.
    #[test]
    fn no_launcher_writes_the_private_key_to_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let (files, key) =
            issue_ephemeral_keyed(dir.path(), "keyless", Duration::from_secs(600)).unwrap();
        let body = key
            .pem()
            .lines()
            .find(|l| !l.starts_with("-----") && !l.is_empty())
            .unwrap()
            .to_string();
        let mut names = Vec::new();
        for entry in std::fs::read_dir(files.directory()).unwrap() {
            let path = entry.unwrap().path();
            let contents = std::fs::read_to_string(&path).unwrap();
            assert!(
                !contents.contains("PRIVATE KEY") && !contents.contains(&body),
                "{} holds the private key",
                path.display()
            );
            names.push(path.file_name().unwrap().to_string_lossy().into_owned());
        }
        names.sort();
        assert_eq!(names, ["cert.pem", "trust-bundle.pem"]);
        assert!(
            !files.env().any(|(k, _)| k == RETIRED_KEY_FILE_ENV),
            "no variable names a key file"
        );
    }

    /// #3471: the delivered key is the whole PEM, then end-of-file, on a pipe
    /// whose write end is already closed.
    #[test]
    fn a_delivered_key_is_the_pem_then_end_of_file() {
        use std::io::Read as _;
        let dir = tempfile::tempdir().unwrap();
        let (_files, key) =
            issue_ephemeral_keyed(dir.path(), "piped", Duration::from_secs(600)).unwrap();
        let expected = key.pem().to_string();
        let mut reader = key.into_pipe().unwrap();
        let mut got = String::new();
        reader.read_to_string(&mut got).unwrap();
        assert_eq!(got, expected);
        assert!(got.contains("PRIVATE KEY"));
        assert!(u64::try_from(got.len()).unwrap() < KEY_ON_STDIN_MAX);
        assert_eq!(format!("{:?}", PodKey { pem: got }), "PodKey(<redacted>)");
    }

    /// The public files are private to their owner all the same, and a second
    /// launch into the same directory is refused rather than overwriting the
    /// first.
    #[cfg(unix)]
    #[test]
    fn the_public_files_are_private_and_written_once() {
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

    /// The names are the ones the tool-proxy reads (`--identity-cert` and
    /// `--identity-trust-bundle` are bound to exactly these variables), and
    /// no key file among them.
    #[test]
    fn the_env_names_are_the_proxys_public_ones() {
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
                    "NUCLEUS_IDENTITY_TRUST_BUNDLE",
                    PathBuf::from("/data/pod/identity/trust-bundle.pem")
                ),
            ]
        );
    }
}

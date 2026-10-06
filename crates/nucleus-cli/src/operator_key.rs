//! The operator's own federation identity: a P-256 key that signs short-lived
//! assertions as `spiffe://<td>/ns/system/sa/operator-automation`, for a
//! relying party that federates it (an OIDC workload-identity provider).
//!
//! Automation acting for the operator — agents reaching the operator's build
//! machines, for one — otherwise rides on an interactive human login that
//! expires into a browser prompt nobody is there to answer. With this, the
//! relying party runs `nucleus federation operator-assertion` whenever it
//! needs a credential, and nothing long-lived exists outside this key.
//!
//! # Why the subject is `ns/system/sa/operator-automation`
//!
//! `docs/spiffe-taxonomy.md` gives the operator the `system` namespace and
//! makes `ns/<ns>/sa/<sa>` the shortest ID that names a principal. The
//! operator's interactive identity is `ns/system/sa/cli`, which the node
//! grants node-wide authority by EXACT match. Automation gets a sibling
//! account rather than a child of `cli`, so the node grants it nothing at
//! all; its reach is only what the relying party binds to it.
//!
//! # Where the key lives, and why a rebuilt binary never blocks on it
//!
//! macOS authorises a Keychain item per calling binary. Every rebuilt `nucleus`
//! is a new binary, so reading an item through the Security framework from
//! this process raises a GUI dialog — and a credential helper invoked by
//! automation then waits on it forever, with no output.
//!
//! So the macOS store never touches the Keychain from this process. It runs
//! Apple's `/usr/bin/security`, which created the item and is therefore the
//! one application on its access list. That binary is signed by the OS and
//! does not change when `nucleus` is rebuilt, so no rebuild can trigger the
//! dialog. And every invocation has a deadline: a locked keychain, or a dialog
//! raised for any other reason, ends in [`OperatorKeyError::KeychainTimeout`]
//! after a few seconds — never a silent wait.
//!
//! The key goes into `security` on its stdin (`security -i`), never its argv,
//! which any local process can read.
//!
//! Elsewhere the key is an owner-only file under the user's config directory.
//!
//! # Rotation
//!
//! Two slots: `current` signs, `next` is published beside it. `rotate --stage`
//! creates `next` and prints the two-key JWKS to register; `rotate --promote`
//! makes it current and prints the one-key JWKS. There is no waiting period
//! enforced here, unlike the node's issuer key (`nucleus federation rotate`):
//! the relying party holds this JWKS inline, so it changes exactly when the
//! operator re-registers it, and each assertion is minted moments before the
//! exchange that spends it.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nucleus_federation::{AssertionSigner as _, EcdsaP256Signer, PublicJwk};
use zeroize::Zeroizing;

/// The operator automation's account in the `system` namespace.
pub const OPERATOR_ACCOUNT: &str = "operator-automation";

/// Apple's Keychain tool. Stable across `nucleus` rebuilds: see the module docs.
pub const SECURITY_PROGRAM: &str = "/usr/bin/security";

/// The Keychain service the operator key's items are filed under. Separate
/// from `com.nucleus.cli`, whose items the Security framework reads directly.
pub const KEYCHAIN_SERVICE: &str = "com.nucleus.cli.operator-key";

/// How long one `security` invocation may take before it is killed, in ms.
pub const DEFAULT_KEYCHAIN_TIMEOUT_MS: u64 = 5_000;

/// `security`'s exit status for "the specified item could not be found".
const SECURITY_NOT_FOUND: i32 = 44;

/// One of the two keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// Signs every assertion.
    Current,
    /// Staged by a rotation: published, never signing.
    Next,
}

impl Slot {
    fn name(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Next => "next",
        }
    }
}

/// Why an operator-key operation failed. Never carries key material.
#[derive(Debug, thiserror::Error)]
pub enum OperatorKeyError {
    /// `security` did not finish in time — the keychain is locked, or a dialog
    /// is waiting for a click. The process was killed.
    #[error(
        "{program} did not finish `{op}` within {} ms and was killed: the keychain is locked or \
         waiting on a dialog. Unlock it (`security unlock-keychain`) and retry.",
        after.as_millis()
    )]
    KeychainTimeout {
        program: PathBuf,
        op: &'static str,
        after: Duration,
    },
    /// `security` could not be started.
    #[error("could not run {program}: {what}")]
    KeychainSpawn { program: PathBuf, what: String },
    /// `security` exited with a failure.
    #[error("`{op}` failed (exit {code:?}): {detail}")]
    KeychainFailed {
        op: &'static str,
        code: Option<i32>,
        detail: String,
    },
    /// A write reported success but reading it back gave something else.
    #[error("the {slot} key written to the keychain did not read back")]
    WriteNotRead { slot: &'static str },
    /// A filesystem operation failed.
    #[error("{}: {what}", path.display())]
    Io { path: PathBuf, what: String },
    /// A key file or its directory is reachable by someone else.
    #[error("{} has mode {mode:o}; the operator key must be owner-only", path.display())]
    Permissions { path: PathBuf, mode: u32 },
    /// A key path is a symlink or not a regular file.
    #[error("{} is not a regular file", path.display())]
    NotAFile { path: PathBuf },
    /// Stored bytes are not a P-256 PKCS#8 key.
    #[error("the stored {slot} key is not a P-256 PKCS#8 key")]
    Key { slot: &'static str },
    /// No current key.
    #[error("no operator key in {0}; run `nucleus federation operator-key init`")]
    NoKey(String),
    /// `init` with a key already present.
    #[error("an operator key already exists in {0}; use `operator-key rotate` to replace it")]
    Exists(String),
    /// `--stage` with a key already staged.
    #[error("a key is already staged in {0}; promote it first")]
    AlreadyStaged(String),
    /// `--promote` with nothing staged.
    #[error("no key is staged; run `operator-key rotate --stage` first")]
    NotStaged,
    /// Key generation failed.
    #[error("key generation failed")]
    Generate,
}

/// Where the two slots are kept.
pub trait KeyStore {
    /// The slot's PKCS#8 DER, or `None` if empty.
    fn read(&self, slot: Slot) -> Result<Option<Zeroizing<Vec<u8>>>, OperatorKeyError>;
    /// Replace the slot's contents.
    fn write(&self, slot: Slot, der: &[u8]) -> Result<(), OperatorKeyError>;
    /// Empty the slot (already empty is fine).
    fn remove(&self, slot: Slot) -> Result<(), OperatorKeyError>;
    /// Where the keys are, for messages.
    fn location(&self) -> String;
}

/// The macOS store: Keychain items read and written only through `security`.
pub struct SecurityCli {
    program: PathBuf,
    service: String,
    timeout: Duration,
}

impl SecurityCli {
    /// The store through `program` (normally [`SECURITY_PROGRAM`]).
    pub fn new(program: impl Into<PathBuf>, service: impl Into<String>, timeout: Duration) -> Self {
        Self {
            program: program.into(),
            service: service.into(),
            timeout,
        }
    }

    /// Run `security` with `args`, feeding `stdin`, killed at the deadline.
    ///
    /// stdout and stderr are drained on their own threads so a chatty child
    /// cannot fill a pipe and stall into a false timeout.
    fn run_with_wait_timeout(
        &self,
        op: &'static str,
        args: &[&str],
        stdin: Option<&[u8]>,
    ) -> Result<(Option<i32>, Zeroizing<Vec<u8>>, Vec<u8>), OperatorKeyError> {
        let spawn_err = |e: std::io::Error| OperatorKeyError::KeychainSpawn {
            program: self.program.clone(),
            what: e.to_string(),
        };
        let mut child = Command::new(&self.program)
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(spawn_err)?;
        let deadline = Instant::now() + self.timeout;
        let mut out_pipe = child.stdout.take();
        let mut err_pipe = child.stderr.take();
        let out_reader = std::thread::spawn(move || {
            let mut buf = Zeroizing::new(Vec::new());
            if let Some(p) = out_pipe.as_mut() {
                let _ = p.read_to_end(&mut buf);
            }
            buf
        });
        let err_reader = std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(p) = err_pipe.as_mut() {
                let _ = p.read_to_end(&mut buf);
            }
            buf
        });
        if let (Some(bytes), Some(mut pipe)) = (stdin, child.stdin.take()) {
            // Small (one command line), so this cannot fill the pipe; a child
            // that exits without reading it is reported by its status below.
            let _ = pipe.write_all(bytes);
        }
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(OperatorKeyError::KeychainTimeout {
                        program: self.program.clone(),
                        op,
                        after: self.timeout,
                    });
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(spawn_err(e));
                }
            }
        };
        let stdout = out_reader.join().unwrap_or_default();
        let stderr = err_reader.join().unwrap_or_default();
        Ok((status.code(), stdout, stderr))
    }

    fn account(slot: Slot) -> &'static str {
        slot.name()
    }

    fn failed(op: &'static str, code: Option<i32>, stderr: &[u8]) -> OperatorKeyError {
        let detail = String::from_utf8_lossy(stderr)
            .lines()
            .next()
            .unwrap_or("")
            .chars()
            .take(200)
            .collect();
        OperatorKeyError::KeychainFailed { op, code, detail }
    }
}

impl KeyStore for SecurityCli {
    fn read(&self, slot: Slot) -> Result<Option<Zeroizing<Vec<u8>>>, OperatorKeyError> {
        let op = "find-generic-password";
        let (code, stdout, stderr) = self.run_with_wait_timeout(
            op,
            &[op, "-s", &self.service, "-a", Self::account(slot), "-w"],
            None,
        )?;
        match code {
            Some(0) => {
                let text = std::str::from_utf8(&stdout)
                    .map_err(|_| OperatorKeyError::Key { slot: slot.name() })?;
                URL_SAFE_NO_PAD
                    .decode(text.trim_end())
                    .map(|der| Some(Zeroizing::new(der)))
                    .map_err(|_| OperatorKeyError::Key { slot: slot.name() })
            }
            Some(SECURITY_NOT_FOUND) => Ok(None),
            _ => Err(Self::failed(op, code, &stderr)),
        }
    }

    fn write(&self, slot: Slot, der: &[u8]) -> Result<(), OperatorKeyError> {
        let op = "add-generic-password";
        let program = self.program.to_string_lossy();
        // `-U` replaces an existing item and keeps its access list; `-T` names
        // `security` itself, the only application that ever reads the item.
        let line = Zeroizing::new(format!(
            "{op} -U -s {} -a {} -T {program} -w {}\n",
            self.service,
            Self::account(slot),
            URL_SAFE_NO_PAD.encode(der)
        ));
        let (code, _, stderr) = self.run_with_wait_timeout(op, &["-i"], Some(line.as_bytes()))?;
        if code != Some(0) {
            return Err(Self::failed(op, code, &stderr));
        }
        // A success status is not the item: read it back.
        match self.read(slot)? {
            Some(back) if back.as_slice() == der => Ok(()),
            _ => Err(OperatorKeyError::WriteNotRead { slot: slot.name() }),
        }
    }

    fn remove(&self, slot: Slot) -> Result<(), OperatorKeyError> {
        let op = "delete-generic-password";
        let (code, _, stderr) = self.run_with_wait_timeout(
            op,
            &[op, "-s", &self.service, "-a", Self::account(slot)],
            None,
        )?;
        match code {
            Some(0 | SECURITY_NOT_FOUND) => Ok(()),
            _ => Err(Self::failed(op, code, &stderr)),
        }
    }

    fn location(&self) -> String {
        format!(
            "the keychain (service {}, via {})",
            self.service,
            self.program.display()
        )
    }
}

/// The store elsewhere: `<dir>/<slot>.p8`, owner-only.
pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    /// The store in `dir` (created `0700` on first write).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self, slot: Slot) -> PathBuf {
        self.dir.join(format!("{}.p8", slot.name()))
    }

    fn io(path: &Path, e: &std::io::Error) -> OperatorKeyError {
        OperatorKeyError::Io {
            path: path.to_path_buf(),
            what: e.to_string(),
        }
    }

    /// Refuse a directory or file that grants group or other any access.
    #[cfg(unix)]
    fn owner_only(path: &Path, meta: &std::fs::Metadata) -> Result<(), OperatorKeyError> {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = meta.permissions().mode() & 0o7777;
        if mode & 0o077 != 0 {
            return Err(OperatorKeyError::Permissions {
                path: path.to_path_buf(),
                mode,
            });
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn owner_only(_: &Path, _: &std::fs::Metadata) -> Result<(), OperatorKeyError> {
        Ok(())
    }

    fn check_dir(&self) -> Result<bool, OperatorKeyError> {
        match std::fs::symlink_metadata(&self.dir) {
            Ok(m) if m.is_dir() => Self::owner_only(&self.dir, &m).map(|()| true),
            Ok(_) => Err(OperatorKeyError::NotAFile {
                path: self.dir.clone(),
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Self::io(&self.dir, &e)),
        }
    }
}

impl KeyStore for FileStore {
    fn read(&self, slot: Slot) -> Result<Option<Zeroizing<Vec<u8>>>, OperatorKeyError> {
        if !self.check_dir()? {
            return Ok(None);
        }
        let path = self.path(slot);
        let link = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Self::io(&path, &e)),
        };
        if !link.file_type().is_file() {
            return Err(OperatorKeyError::NotAFile { path });
        }
        Self::owner_only(&path, &link)?;
        let mut file = std::fs::File::open(&path).map_err(|e| Self::io(&path, &e))?;
        let mut der = Zeroizing::new(Vec::new());
        file.read_to_end(&mut der)
            .map_err(|e| Self::io(&path, &e))?;
        Ok(Some(der))
    }

    fn write(&self, slot: Slot, der: &[u8]) -> Result<(), OperatorKeyError> {
        if !self.check_dir()? {
            let mut b = std::fs::DirBuilder::new();
            b.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
            b.create(&self.dir).map_err(|e| Self::io(&self.dir, &e))?;
            self.check_dir()?;
        }
        let target = self.path(slot);
        // An exclusive temporary created owner-only in the open itself, then
        // renamed over the slot: the key is never readable by anyone else,
        // and a reader never sees half of it.
        let mut builder = tempfile::Builder::new();
        builder.prefix(".operator-key-");
        #[cfg(unix)]
        builder.permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600));
        let mut tmp = builder
            .tempfile_in(&self.dir)
            .map_err(|e| Self::io(&self.dir, &e))?;
        tmp.write_all(der).map_err(|e| Self::io(&target, &e))?;
        tmp.as_file()
            .sync_all()
            .map_err(|e| Self::io(&target, &e))?;
        tmp.persist(&target)
            .map_err(|e| Self::io(&target, &e.error))?;
        Ok(())
    }

    fn remove(&self, slot: Slot) -> Result<(), OperatorKeyError> {
        let path = self.path(slot);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Self::io(&path, &e)),
        }
    }

    fn location(&self) -> String {
        self.dir.display().to_string()
    }
}

fn load(store: &dyn KeyStore, slot: Slot) -> Result<Option<EcdsaP256Signer>, OperatorKeyError> {
    let Some(der) = store.read(slot)? else {
        return Ok(None);
    };
    EcdsaP256Signer::from_pkcs8(&der)
        .map(Some)
        .map_err(|_| OperatorKeyError::Key { slot: slot.name() })
}

fn generate(store: &dyn KeyStore, slot: Slot) -> Result<PublicJwk, OperatorKeyError> {
    let der = EcdsaP256Signer::generate_pkcs8().map_err(|_| OperatorKeyError::Generate)?;
    let jwk = EcdsaP256Signer::from_pkcs8(&der)
        .map_err(|_| OperatorKeyError::Generate)?
        .public_jwk();
    store.write(slot, &der)?;
    Ok(jwk)
}

/// The signing key.
pub fn signer(store: &dyn KeyStore) -> Result<EcdsaP256Signer, OperatorKeyError> {
    load(store, Slot::Current)?.ok_or_else(|| OperatorKeyError::NoKey(store.location()))
}

/// The keys to publish: current, then next if staged (once, if a promote was
/// interrupted between its two writes).
pub fn published(store: &dyn KeyStore) -> Result<Vec<PublicJwk>, OperatorKeyError> {
    let mut keys = vec![signer(store)?.public_jwk()];
    if let Some(next) = load(store, Slot::Next)?.map(|s| s.public_jwk())
        && keys.iter().all(|k| k.kid != next.kid)
    {
        keys.push(next);
    }
    Ok(keys)
}

/// Create the first key. Refused if one exists: replacing a registered key
/// is a rotation, not an init.
pub fn init(store: &dyn KeyStore) -> Result<PublicJwk, OperatorKeyError> {
    if store.read(Slot::Current)?.is_some() {
        return Err(OperatorKeyError::Exists(store.location()));
    }
    generate(store, Slot::Current)
}

/// Generate the next key beside the current one.
pub fn stage(store: &dyn KeyStore) -> Result<PublicJwk, OperatorKeyError> {
    signer(store)?;
    if store.read(Slot::Next)?.is_some() {
        return Err(OperatorKeyError::AlreadyStaged(store.location()));
    }
    generate(store, Slot::Next)
}

/// Make the staged key current; the old one is gone.
///
/// Current is overwritten before next is removed, so an interruption leaves
/// both slots holding the new key, never neither.
pub fn promote(store: &dyn KeyStore) -> Result<PublicJwk, OperatorKeyError> {
    let der = store.read(Slot::Next)?.ok_or(OperatorKeyError::NotStaged)?;
    let jwk = EcdsaP256Signer::from_pkcs8(&der)
        .map_err(|_| OperatorKeyError::Key { slot: "next" })?
        .public_jwk();
    store.write(Slot::Current, &der)?;
    store.remove(Slot::Next)?;
    Ok(jwk)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn exercise(store: &dyn KeyStore) {
        assert!(matches!(signer(store), Err(OperatorKeyError::NoKey(_))));
        assert!(matches!(promote(store), Err(OperatorKeyError::NotStaged)));
        let first = init(store).unwrap();
        assert!(matches!(init(store), Err(OperatorKeyError::Exists(_))));
        assert_eq!(signer(store).unwrap().kid(), first.kid);
        assert_eq!(published(store).unwrap(), vec![first.clone()]);

        let next = stage(store).unwrap();
        assert_ne!(next.kid, first.kid);
        assert!(matches!(
            stage(store),
            Err(OperatorKeyError::AlreadyStaged(_))
        ));
        assert_eq!(
            published(store).unwrap(),
            vec![first.clone(), next.clone()],
            "staged key is published, current still signs"
        );
        assert_eq!(signer(store).unwrap().kid(), first.kid);

        assert_eq!(promote(store).unwrap(), next);
        assert_eq!(signer(store).unwrap().kid(), next.kid);
        assert_eq!(published(store).unwrap(), vec![next]);
        assert!(store.read(Slot::Next).unwrap().is_none());
    }

    #[test]
    fn file_store_rotates_and_keeps_keys_owner_only() {
        let root = tempfile::tempdir().unwrap();
        let store = FileStore::new(root.path().join("operator-key"));
        exercise(&store);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&root.path().join("operator-key")), 0o700);
            assert_eq!(mode(&store.path(Slot::Current)), 0o600);
        }
    }

    /// A key file someone else can read is refused, not used. A-19: the same
    /// read succeeds once the bits are put back.
    #[cfg(unix)]
    #[test]
    fn file_store_refuses_a_group_readable_key() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir().unwrap();
        let store = FileStore::new(root.path().join("k"));
        init(&store).unwrap();
        let p = store.path(Slot::Current);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            signer(&store),
            Err(OperatorKeyError::Permissions { mode: 0o640, .. })
        ));
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        signer(&store).unwrap();
    }

    /// A stand-in for `/usr/bin/security`: the item store is a directory, and
    /// the fixture speaks exactly the three commands `SecurityCli` sends
    /// (exit 44 on a missing item, like the real one). Test-only.
    #[cfg(unix)]
    pub(crate) fn fake_security(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let program = dir.join("security");
        std::fs::write(
            &program,
            format!("#!/bin/sh\nSTORE='{}'\n{body}\n", dir.display()),
        )
        .unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        program
    }

    #[cfg(unix)]
    const WORKING_SECURITY: &str = r#"
echo "$@" >> "$STORE/argv.log"
case "$1" in
  find-generic-password) [ -f "$STORE/$5" ] || exit 44; cat "$STORE/$5"; echo ;;
  delete-generic-password) [ -f "$STORE/$5" ] || exit 44; rm "$STORE/$5" ;;
  -i) read -r cmd u s svc a acct t prog w secret
      [ "$cmd" = add-generic-password ] || exit 1
      [ "$w" = -w ] || exit 1
      printf %s "$secret" > "$STORE/$acct" ;;
  *) exit 1 ;;
esac"#;

    /// The macOS store's own logic, through a fake `security`: the full
    /// rotation, and the key never on the child's argv.
    #[cfg(unix)]
    #[test]
    fn security_cli_store_rotates_through_the_tool() {
        let dir = tempfile::tempdir().unwrap();
        let program = fake_security(dir.path(), WORKING_SECURITY);
        let store = SecurityCli::new(
            &program,
            KEYCHAIN_SERVICE,
            Duration::from_millis(DEFAULT_KEYCHAIN_TIMEOUT_MS),
        );
        exercise(&store);
        let stored = std::fs::read_to_string(dir.path().join("current")).unwrap();
        assert!(stored.len() > 100, "the fixture stored the key");
        let argv = std::fs::read_to_string(dir.path().join("argv.log")).unwrap();
        assert!(argv.contains("find-generic-password"), "{argv}");
        assert!(
            !argv.contains(&stored),
            "the key appeared on security's argv"
        );
    }

    /// A tool that writes nothing while claiming success is caught by the
    /// read-back, not trusted.
    #[cfg(unix)]
    #[test]
    fn security_cli_store_verifies_a_write_by_reading_it_back() {
        let dir = tempfile::tempdir().unwrap();
        let body = WORKING_SECURITY.replace(r#"printf %s "$secret" > "$STORE/$acct""#, "true");
        let program = fake_security(dir.path(), &body);
        let store = SecurityCli::new(
            &program,
            KEYCHAIN_SERVICE,
            Duration::from_millis(DEFAULT_KEYCHAIN_TIMEOUT_MS),
        );
        assert!(matches!(
            init(&store),
            Err(OperatorKeyError::WriteNotRead { slot: "current" })
        ));
    }

    /// The hang the module exists to prevent: a `security` that never answers
    /// (a locked keychain, a dialog) ends in the named timeout error, promptly,
    /// on every path — read, write and delete. A-19: the same store with a
    /// working tool succeeds (`security_cli_store_rotates_through_the_tool`).
    #[cfg(unix)]
    #[test]
    fn a_hanging_security_is_a_named_timeout_never_a_wait() {
        let dir = tempfile::tempdir().unwrap();
        let program = fake_security(dir.path(), "exec sleep 30");
        let store = SecurityCli::new(&program, KEYCHAIN_SERVICE, Duration::from_millis(300));
        let started = Instant::now();
        for r in [
            store.read(Slot::Current).map(|_| ()),
            store.write(Slot::Current, b"x"),
            store.remove(Slot::Next),
        ] {
            match r {
                Err(OperatorKeyError::KeychainTimeout { after, .. }) => {
                    assert_eq!(after, Duration::from_millis(300));
                }
                other => panic!("expected KeychainTimeout, got {other:?}"),
            }
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "three timeouts took {:?}",
            started.elapsed()
        );
        let msg = signer(&store).unwrap_err().to_string();
        assert!(
            msg.contains("did not finish") && msg.contains("unlock-keychain"),
            "{msg}"
        );
    }

    /// A missing program is a named spawn error.
    #[test]
    fn a_missing_security_is_a_spawn_error() {
        let store = SecurityCli::new(
            "/nonexistent/security",
            KEYCHAIN_SERVICE,
            Duration::from_millis(DEFAULT_KEYCHAIN_TIMEOUT_MS),
        );
        assert!(matches!(
            store.read(Slot::Current),
            Err(OperatorKeyError::KeychainSpawn { .. })
        ));
    }
}

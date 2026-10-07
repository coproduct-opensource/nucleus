//! The federation keyring in TPM custody, against a real software TPM
//! (libtpms via swtpm): the issuer key, its rotation and its signatures all
//! stay in the TPM, and a moved boot state stops it (ADR 0012).
//!
//! Starts its own swtpm. Needs `swtpm` on `PATH` (or `NUCLEUS_SWTPM_BIN`).
//! Ignored by default; an ignored test is reported as ignored, never as a pass.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use nucleus_federation::keyring::{
    CURRENT_KEY_FILE, Held, KeyDir, KeyDirSigner, NEXT_KEY_FILE, RotationPolicy,
    TPM_CURRENT_KEY_FILE, TPM_NEXT_KEY_FILE, TPM_PREV_KEY_FILE,
};
use nucleus_federation::{
    CurrentSigner, CustodyKind, KeyCustody, PublicJwk, TpmCustody, TpmEndpoint,
};

const T0: u64 = 1_790_000_000;

struct Swtpm {
    child: Child,
    dir: PathBuf,
    addr: String,
}

impl Swtpm {
    fn start() -> Self {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let dir =
            std::env::temp_dir().join(format!("nucleus-fed-swtpm-{}-{port}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = std::env::var("NUCLEUS_SWTPM_BIN").unwrap_or_else(|_| "swtpm".into());
        let child = Command::new(bin)
            .args(["socket", "--tpm2", "--tpmstate"])
            .arg(format!("dir={}", dir.display()))
            .arg("--server")
            .arg(format!("type=tcp,port={port},bindaddr=127.0.0.1"))
            .arg("--ctrl")
            .arg(format!(
                "type=tcp,port={},bindaddr=127.0.0.1",
                port.checked_add(1).unwrap()
            ))
            .args(["--flags", "not-need-init,startup-clear"])
            .stdout(Stdio::null())
            .spawn()
            .expect("swtpm on PATH (or NUCLEUS_SWTPM_BIN)");
        let addr = format!("127.0.0.1:{port}");
        for _ in 0..100 {
            if std::net::TcpStream::connect(&addr).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        std::thread::sleep(Duration::from_millis(100));
        Self { child, dir, addr }
    }

    fn custody(&self) -> KeyCustody {
        KeyCustody::Tpm(TpmCustody::new(TpmEndpoint::Socket(self.addr.clone())))
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Whether `sig` is a valid ES256 signature over `msg` by `jwk`.
fn verifies(jwk: &PublicJwk, msg: &[u8], sig: &[u8; 64]) -> bool {
    let d = |s: &str| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .unwrap()
    };
    let mut point = vec![0x04];
    point.extend(d(&jwk.x));
    point.extend(d(&jwk.y));
    ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_FIXED, point)
        .verify(msg, sig)
        .is_ok()
}

fn sign_now(source: &Arc<KeyDirSigner>, msg: &[u8]) -> (String, Option<[u8; 64]>) {
    let signer = Arc::clone(source).current().unwrap();
    let sig = signer.sign_es256(msg).ok().map(|s| s.0);
    (signer.kid().to_string(), sig)
}

#[test]
#[ignore = "needs swtpm on PATH"]
fn the_issuer_key_and_its_rotation_stay_in_the_tpm() {
    let tpm = Swtpm::start();
    let custody = tpm.custody();
    let dir = tempfile::tempdir().unwrap();
    let keys = KeyDir::new(dir.path());

    let first = keys.create_current(&custody).unwrap();
    assert_eq!(keys.custody_on_disk().unwrap(), Some(CustodyKind::Tpm));
    assert!(dir.path().join(TPM_CURRENT_KEY_FILE).exists());
    assert!(
        !dir.path().join(CURRENT_KEY_FILE).exists(),
        "no PKCS#8 file"
    );

    let source = Arc::new(KeyDirSigner::open(keys.clone(), custody.clone()).unwrap());
    let msg = b"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJwb2QifQ";
    let (kid, sig) = sign_now(&source, msg);
    assert_eq!(kid, first.kid);
    assert!(verifies(&first, msg, &sig.expect("the TPM signs")));

    // Stage: the next key is made in the TPM too, published, never signing.
    let staged = keys.stage(T0, &custody).unwrap().after.next.unwrap().jwk;
    assert!(dir.path().join(TPM_NEXT_KEY_FILE).exists());
    assert!(!dir.path().join(NEXT_KEY_FILE).exists());
    assert_eq!(sign_now(&source, msg).0, first.kid);
    let held = keys.published_custody(T0).unwrap();
    assert_eq!(held.len(), 2);
    assert!(held.iter().all(|(_, h)| matches!(h, Held::Tpm(_))));

    // Promote: the running signer follows, and its signatures verify under
    // the staged key.
    let policy = RotationPolicy::default();
    keys.promote(T0 + policy.promote_overlap().as_secs(), &policy)
        .unwrap();
    assert!(dir.path().join(TPM_PREV_KEY_FILE).exists());
    let (kid, sig) = sign_now(&source, msg);
    assert_eq!(kid, staged.kid);
    assert!(verifies(&staged, msg, &sig.unwrap()));

    // The boot state moves under the running node (PCR 9: what the boot
    // loader read). From that moment the key signs nothing.
    let KeyCustody::Tpm(t) = &custody else {
        unreachable!()
    };
    t.endpoint()
        .connect()
        .unwrap()
        .pcr_extend(9, &[0x09; 32])
        .unwrap();
    let (kid, sig) = sign_now(&source, msg);
    assert_eq!(kid, staged.kid);
    assert_eq!(sig, None, "a moved boot state stops the signer");
    let Some(nucleus_federation::keyring::StoredKey::Tpm(current, _)) =
        keys.load_current().unwrap()
    else {
        panic!("a TPM key")
    };
    assert!(!t.usable_now(&current).unwrap());
}

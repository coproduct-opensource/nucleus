//! Exercise enrollment through the shipped host command, using the node's
//! Ed25519 PKCS#8 encoding rather than an OpenSSL-compatible substitute.
use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey as _};

#[test]
fn enrollment_exports_only_the_existing_public_key_and_never_creates_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("executor.der");
    let key = SigningKey::from_bytes(&[37; 32]);
    let der = key.to_pkcs8_der().unwrap();
    std::fs::write(&path, der.as_bytes()).unwrap();
    let run = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_nucleus-hostctl"))
            .arg("public-key")
            .arg(&path)
            .output()
            .unwrap()
    };
    let output = run();
    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        format!("{}\n", hex::encode(key.verifying_key().as_bytes())).as_bytes()
    );
    assert!(output.stderr.is_empty());
    assert_eq!(std::fs::read(&path).unwrap(), der.as_bytes());

    std::fs::remove_file(&path).unwrap();
    let missing = run();
    assert!(!missing.status.success());
    assert!(missing.stdout.is_empty());
    assert!(!path.exists());

    let invalid = b"an incomplete persisted key";
    std::fs::write(&path, invalid).unwrap();
    let unreadable = run();
    assert!(!unreadable.status.success());
    assert!(unreadable.stdout.is_empty());
    assert!(
        !unreadable
            .stderr
            .windows(invalid.len())
            .any(|s| s == invalid)
    );
    assert_eq!(std::fs::read(&path).unwrap(), invalid);
}

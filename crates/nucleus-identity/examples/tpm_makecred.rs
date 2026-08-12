//! Dev harness for C9 brick 2: runs `make_credential_ecc` and writes the
//! tpm2-tools credential file (`magic || version || TPM2B_ID_OBJECT ||
//! TPM2B_ENCRYPTED_SECRET`) that `tpm2_activatecredential -i` consumes. Used only
//! by the swtpm round-trip check (`scripts/tpm-credential-activation-check.sh`),
//! which proves nucleus's MakeCredential is byte-accepted by a real TPM.
//!
//! Usage: tpm_makecred <ek.pub> <ak_name_hex> <secret_hex> <out_file>
#[cfg(feature = "tpm-devid")]
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let ek_pub = std::fs::read(&a[1]).expect("read ek.pub");
    let ak_name = hex::decode(a[2].trim()).expect("ak_name hex");
    let secret = hex::decode(a[3].trim()).expect("secret hex");
    let c = nucleus_identity::tpm_devid::make_credential_ecc(&ek_pub, &ak_name, &secret)
        .expect("make_credential_ecc");
    let mut file = vec![0xba, 0xdc, 0xc0, 0xde, 0, 0, 0, 1];
    file.extend_from_slice(&c.credential_blob);
    file.extend_from_slice(&c.encrypted_secret);
    std::fs::write(&a[4], file).expect("write cred file");
}

#[cfg(not(feature = "tpm-devid"))]
fn main() {
    eprintln!("build with --features tpm-devid");
    std::process::exit(1);
}

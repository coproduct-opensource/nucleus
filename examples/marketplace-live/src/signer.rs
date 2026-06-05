//! Secure signing-key supply. Loads an `alloy` [`PrivateKeySigner`] from a
//! **foundry-format encrypted keystore** (`cast wallet import` →
//! `~/.foundry/keystores/<name>`, Web3 Secret Storage / scrypt). The plaintext
//! key lives only inside the in-process signer; the address is derived from the
//! key, never read from config.
//!
//! The decryption password is resolved WITHOUT ever touching argv or shell
//! history, in order of decreasing security:
//!
//! 1. **macOS Keychain** (via the `security` CLI) — `nucleus-x402 / marketplace-keystore`.
//! 2. **No-echo TTY prompt** (`rpassword`) — for human-driven runs.
//! 3. **File mount** (`NUCLEUS_X402_KEYSTORE_PASSWORD_FILE`) — k8s/Vault secret.
//! 4. **Env var** (`NUCLEUS_X402_KEYSTORE_PASSWORD`) — documented LAST resort.
//!
//! The raw key and the password are NEVER accepted on the command line.
//!
//! Mainnet: swap [`PrivateKeySigner`] for a non-extractable backend (AWS KMS via
//! `alloy-signer-aws`, or Ledger via `alloy-signer-ledger`) — both implement
//! alloy's `Signer`, so the x402 client path is unchanged. A local keystore is
//! acceptable for a **testnet faucet wallet only**.

use std::io::IsTerminal;
use std::path::Path;

use alloy_signer_local::{LocalSigner, PrivateKeySigner};
use anyhow::{anyhow, Context};
use zeroize::Zeroizing;

const KEYCHAIN_SERVICE: &str = "nucleus-x402";
const KEYCHAIN_ACCOUNT: &str = "marketplace-keystore";
const PASSWORD_FILE_ENV: &str = "NUCLEUS_X402_KEYSTORE_PASSWORD_FILE";
const PASSWORD_ENV: &str = "NUCLEUS_X402_KEYSTORE_PASSWORD";

/// Where the resolved password came from (for an honest startup log; the value
/// itself is never logged).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordSource {
    Keychain,
    Prompt,
    File,
    Env,
}

impl PasswordSource {
    pub fn label(self) -> &'static str {
        match self {
            PasswordSource::Keychain => "macOS Keychain",
            PasswordSource::Prompt => "interactive prompt",
            PasswordSource::File => "file mount",
            PasswordSource::Env => "env var (LAST RESORT)",
        }
    }
}

/// Resolve the keystore password from the most secure available source. The
/// password is wrapped in [`Zeroizing`] so it is wiped from memory on drop.
pub fn resolve_keystore_password() -> anyhow::Result<(Zeroizing<String>, PasswordSource)> {
    // 1) macOS Keychain via the `security` CLI (no extra crate; the `-w` flag
    //    prints ONLY the secret to stdout; absent/failing on non-macOS → fall
    //    through). The password was stored once with, e.g.:
    //      security add-generic-password -s nucleus-x402 -a marketplace-keystore -w
    if let Some(pw) = keychain_password() {
        return Ok((pw, PasswordSource::Keychain));
    }
    // 2) No-echo TTY prompt (only when attached to a terminal).
    if std::io::stdin().is_terminal() {
        let pw = rpassword::prompt_password("x402 keystore password: ")
            .context("reading keystore password from the terminal")?;
        return Ok((Zeroizing::new(pw), PasswordSource::Prompt));
    }
    // 3) File mount (k8s projected Secret / Vault agent).
    if let Ok(path) = std::env::var(PASSWORD_FILE_ENV) {
        let pw = std::fs::read_to_string(&path)
            .with_context(|| format!("reading keystore password file {path}"))?;
        return Ok((
            Zeroizing::new(pw.trim_end().to_string()),
            PasswordSource::File,
        ));
    }
    // 4) Env var — last resort.
    if let Ok(pw) = std::env::var(PASSWORD_ENV) {
        return Ok((Zeroizing::new(pw), PasswordSource::Env));
    }
    Err(anyhow!(
        "no keystore password source available — set the {KEYCHAIN_SERVICE} Keychain item \
         (`security add-generic-password -s {KEYCHAIN_SERVICE} -a {KEYCHAIN_ACCOUNT} -w`), \
         run attached to a TTY, set {PASSWORD_FILE_ENV}, or {PASSWORD_ENV} (last resort)"
    ))
}

/// Read the keystore password from the macOS Keychain via the `security` CLI.
/// Returns `None` if `security` is unavailable (non-macOS) or the item is unset.
fn keychain_password() -> Option<Zeroizing<String>> {
    let out = std::process::Command::new("security")
        .args([
            "find-generic-password",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            KEYCHAIN_ACCOUNT,
            "-w",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let pw = String::from_utf8(out.stdout).ok()?;
    Some(Zeroizing::new(pw.trim_end().to_string()))
}

/// Load a [`PrivateKeySigner`] from an encrypted keystore file at `path`,
/// resolving the password securely. Returns the signer (its address is derived
/// from the key via `signer.address()`).
pub fn load_keystore_signer(path: impl AsRef<Path>) -> anyhow::Result<PrivateKeySigner> {
    let path = path.as_ref();
    let (password, source) = resolve_keystore_password()?;
    eprintln!("  keystore password ← {}", source.label());
    let signer = LocalSigner::decrypt_keystore(path, password.as_bytes())
        .with_context(|| format!("decrypting keystore {}", path.display()))?;
    Ok(signer)
}

#[cfg(test)]
mod tests {
    use alloy_signer_local::LocalSigner;

    #[test]
    fn keystore_round_trips_to_the_expected_address() {
        // Generate a throwaway key, write an encrypted keystore, decrypt it, and
        // assert the recovered address matches — no network, no real funds.
        let dir = tempfile::tempdir().unwrap();
        let (signer, file_name) =
            LocalSigner::new_keystore(dir.path(), &mut rand::thread_rng(), "test-password", None)
                .unwrap();
        let expected = signer.address();

        let path = dir.path().join(file_name);
        let recovered = LocalSigner::decrypt_keystore(&path, b"test-password").unwrap();
        assert_eq!(recovered.address(), expected);

        // Wrong password must fail.
        assert!(LocalSigner::decrypt_keystore(&path, b"wrong").is_err());
    }
}

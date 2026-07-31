//! Host-side provisioning for DLC-D verified admission (portcullis feature `dlc`).
//!
//! Reads the pod's admission credentials from environment variables — the same
//! host-injection pattern as `NUCLEUS_DECLASSIFY_TRUSTED_KEYS` — and builds the
//! [`DlcAdmission`] both transports' kernels are provisioned with:
//!
//! - `NUCLEUS_DLC_TRUSTED_KEYS` — comma-separated 64-hex Ed25519 issuer public
//!   keys (the trust anchors). **Unset or empty ⇒ admission is inert** (the
//!   kernel gate never fires; behavior identical to before this feature).
//! - `NUCLEUS_DLC_ISSUER` — 64-hex public key of the issuer whose credentials
//!   this pod presents (its bytes are also its principal id, matching dlc-d's
//!   `Principal::Atom(PrincipalId(pk))` convention).
//! - `NUCLEUS_DLC_CREDENTIALS` — comma-separated `operation=hex_signature`
//!   pairs (canonical snake_case operation names, e.g.
//!   `read_files=ab12…,web_fetch=…`); each signature is the issuer's Ed25519
//!   credential over that operation's cap atom.
//!
//! **Fail-closed on partial configuration:** once `NUCLEUS_DLC_TRUSTED_KEYS` is
//! set, provisioning ALWAYS happens — a malformed issuer yields an
//! unsatisfiable admission state (empty keyring), and malformed or missing
//! credentials simply deny their operations. Misconfiguration can only narrow.

use portcullis::says_admission::{
    DlcAdmission, DlcKeyRecord, DlcKeyRing, DlcPrincipal, DlcPrincipalId, DlcSignature,
};

/// Decode a 64-char hex string into 32 bytes.
fn hex32(s: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(s.trim()).ok()?;
    bytes.try_into().ok()
}

/// Build the pod's [`DlcAdmission`] from the environment. `None` ⇔ the feature
/// is unprovisioned (inert). See the module docs for the variables and the
/// fail-closed semantics.
pub(crate) fn provision_from_env() -> Option<DlcAdmission> {
    let raw_keys = std::env::var("NUCLEUS_DLC_TRUSTED_KEYS").ok()?;
    if raw_keys.trim().is_empty() {
        return None;
    }

    let entries: Vec<DlcKeyRecord> = raw_keys
        .split(',')
        .filter_map(|k| {
            let pk = hex32(k).or_else(|| {
                tracing::warn!("NUCLEUS_DLC_TRUSTED_KEYS: skipping malformed key entry");
                None
            })?;
            Some(DlcKeyRecord {
                principal: DlcPrincipalId(pk),
                alg: 0,
                public_key: pk.to_vec(),
            })
        })
        .collect();

    let issuer = match std::env::var("NUCLEUS_DLC_ISSUER")
        .ok()
        .and_then(|s| hex32(&s))
    {
        Some(pk) => DlcPrincipal::Atom(DlcPrincipalId(pk)),
        None => {
            // Trusted keys were set but the issuer is absent/malformed: provision an
            // unsatisfiable state (zero principal + EMPTY keyring) so every operation
            // is denied — misconfiguration narrows, never widens.
            tracing::error!(
                "NUCLEUS_DLC_TRUSTED_KEYS is set but NUCLEUS_DLC_ISSUER is missing or \
                 malformed — provisioning DENY-ALL admission (fail-closed)"
            );
            return Some(DlcAdmission::new(
                DlcKeyRing { entries: vec![] },
                DlcPrincipal::Atom(DlcPrincipalId([0u8; 32])),
            ));
        }
    };

    let mut admission = DlcAdmission::new(DlcKeyRing { entries }, issuer);
    if let Ok(raw_creds) = std::env::var("NUCLEUS_DLC_CREDENTIALS") {
        for pair in raw_creds.split(',').filter(|p| !p.trim().is_empty()) {
            match pair.split_once('=') {
                Some((op, sig_hex)) => match hex::decode(sig_hex.trim()) {
                    Ok(bytes) => {
                        admission =
                            admission.with_credential(op.trim(), DlcSignature { alg: 0, bytes });
                    }
                    Err(_) => tracing::warn!(
                        operation = op.trim(),
                        "NUCLEUS_DLC_CREDENTIALS: malformed signature hex — operation \
                         will be denied"
                    ),
                },
                None => {
                    tracing::warn!("NUCLEUS_DLC_CREDENTIALS: entry without '=' — skipped (denied)")
                }
            }
        }
    }
    Some(admission)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Env-var tests mutate process state; serialize them.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_env(vars: &[(&str, Option<&str>)], f: impl FnOnce()) {
        let _guard = ENV_LOCK.lock().unwrap();
        for (k, v) in vars {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
        f();
        for (k, _) in vars {
            std::env::remove_var(k);
        }
    }

    /// Mint a real issuer keypair + credential for one operation, mirroring
    /// dlc-d's v1 cap-invoke layout (guarded by the rev-pinned dependency).
    fn mint(seed: &[u8; 32], operation: &str) -> (String, String) {
        let pk = dlc_crypto::ed25519::public_key(seed);
        let atom = dlc_d::admission::cap_atom(operation);
        let mut msg = b"dlc-d/cap-invoke:".to_vec();
        msg.extend_from_slice(&atom.to_le_bytes());
        let sig = dlc_crypto::ed25519::sign(seed, &msg);
        (hex::encode(pk), hex::encode(sig))
    }

    #[test]
    fn unset_is_inert() {
        with_env(
            &[
                ("NUCLEUS_DLC_TRUSTED_KEYS", None),
                ("NUCLEUS_DLC_ISSUER", None),
                ("NUCLEUS_DLC_CREDENTIALS", None),
            ],
            || assert!(provision_from_env().is_none()),
        );
    }

    #[test]
    fn happy_path_admits_credentialed_operation_only() {
        let seed = [9u8; 32];
        let (pk_hex, sig_hex) = mint(&seed, "read_files");
        with_env(
            &[
                ("NUCLEUS_DLC_TRUSTED_KEYS", Some(pk_hex.as_str())),
                ("NUCLEUS_DLC_ISSUER", Some(pk_hex.as_str())),
                (
                    "NUCLEUS_DLC_CREDENTIALS",
                    Some(&format!("read_files={sig_hex}")),
                ),
            ],
            || {
                let adm = provision_from_env().expect("provisioned");
                assert!(adm.decide_operation("read_files").is_admit());
                assert!(!adm.decide_operation("web_fetch").is_admit());
            },
        );
    }

    #[test]
    fn missing_issuer_is_deny_all() {
        let seed = [9u8; 32];
        let (pk_hex, sig_hex) = mint(&seed, "read_files");
        with_env(
            &[
                ("NUCLEUS_DLC_TRUSTED_KEYS", Some(pk_hex.as_str())),
                ("NUCLEUS_DLC_ISSUER", None),
                (
                    "NUCLEUS_DLC_CREDENTIALS",
                    Some(&format!("read_files={sig_hex}")),
                ),
            ],
            || {
                let adm = provision_from_env().expect("still provisioned — fail-closed");
                assert!(!adm.decide_operation("read_files").is_admit());
            },
        );
    }

    #[test]
    fn wrong_operation_credential_is_denied_by_signature() {
        // A credential minted for web_fetch, registered under read_files: the
        // registry lookup succeeds; the Ed25519 verify is what refuses.
        let seed = [9u8; 32];
        let (pk_hex, wrong_sig) = mint(&seed, "web_fetch");
        with_env(
            &[
                ("NUCLEUS_DLC_TRUSTED_KEYS", Some(pk_hex.as_str())),
                ("NUCLEUS_DLC_ISSUER", Some(pk_hex.as_str())),
                (
                    "NUCLEUS_DLC_CREDENTIALS",
                    Some(&format!("read_files={wrong_sig}")),
                ),
            ],
            || {
                let adm = provision_from_env().expect("provisioned");
                assert!(!adm.decide_operation("read_files").is_admit());
            },
        );
    }
}

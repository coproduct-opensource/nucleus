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

// The variable names are `nucleus_spec::dlc_admission`'s: the same declaration
// the node maps PodSpec labels through and guest-init exports with.
use nucleus_spec::dlc_admission::DlcField;
use portcullis::says_admission::DlcAdmission;

/// Build the pod's [`DlcAdmission`] from the environment. `None` ⇔ the feature
/// is unprovisioned (inert). The fields are read here and decided by
/// [`DlcAdmission::provision`], the one reading the host's decision service
/// applies to the same pod's labels (ADR 0007 G-1).
pub(crate) fn provision_from_env() -> Option<DlcAdmission> {
    let field = |f: DlcField| std::env::var(f.env()).unwrap_or_default();
    DlcAdmission::provision(
        &field(DlcField::TrustedKeys),
        &field(DlcField::Issuer),
        &field(DlcField::Credentials),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Env-var tests mutate process state; serialize them.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_env(vars: &[(&str, Option<&str>)], f: impl FnOnce()) {
        let _guard = ENV_LOCK.lock().unwrap();
        for (k, v) in vars {
            // SAFETY: env mutation is unsafe as of edition 2024 because it races
            // any concurrent reader. These tests hold ENV_LOCK for the whole
            // with_env call, so no other test in this binary touches the
            // environment concurrently.
            match v {
                #[expect(
                    clippy::disallowed_methods,
                    reason = "ADR 0007 H-1: test-only process-global mutation"
                )]
                Some(val) => unsafe { std::env::set_var(k, val) },
                #[expect(
                    clippy::disallowed_methods,
                    reason = "ADR 0007 H-1: test-only process-global mutation"
                )]
                None => unsafe { std::env::remove_var(k) },
            }
        }
        f();
        for (k, _) in vars {
            // SAFETY: edition 2024 makes env mutation unsafe -- it races any concurrent
            // reader. Sound here because this runs before any thread that reads the
            // environment is spawned.
            #[expect(
                clippy::disallowed_methods,
                reason = "ADR 0007 H-1: test-only process-global mutation"
            )]
            unsafe {
                std::env::remove_var(k)
            };
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

    /// The proxy holds these and the workload must not. The workload-env
    /// classifier keys on a prefix it spells for itself (it is an extracted,
    /// dependency-free crate), so this is where the two are held together: a
    /// provisioning variable named outside the prefix would be handed to the
    /// workload as ordinary data (ADR 0007 G-2).
    #[test]
    fn every_provisioning_variable_is_withheld_from_the_workload() {
        use nucleus_ifc_kernel::extracted::identity::MaterialKind;
        for f in DlcField::ALL {
            assert!(
                matches!(
                    crate::workload::env_key_material(f.env()),
                    MaterialKind::DlcCredentials
                ),
                "{} would reach the workload",
                f.env()
            );
        }
    }
}

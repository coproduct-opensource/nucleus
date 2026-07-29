//! Take credentials out of the spec before the spec enters the guest.
//!
//! # The exposure this closes
//!
//! The full `PodSpec` is written to `/etc/nucleus/pod.yaml` **inside the guest**
//! (`nucleus_guest_init::POD_SPEC_PATH`), and `CredentialsSpec.env` carries
//! user-supplied secrets in plaintext. So every credential a pod is given has
//! been landing in a file the agent can read.
//!
//! That is a larger exposure than the kernel command line the Phase 1 work
//! removed, and the same category: a secret placed inside the trust domain it
//! is meant to be protected from.
//!
//! # What replaces it
//!
//! [`split_credentials`] moves the values into a host-side
//! [`CredentialStore`](nucleus_cred_broker::CredentialStore) and leaves the spec
//! carrying only the credential **names**. The guest still learns which
//! credentials exist — it must, to reference them — but never their values. The
//! broker holds those and injects them host-side, which is CB4A Model A.
//!
//! # Why the names stay
//!
//! Stripping the keys as well would change the spec's shape and break any guest
//! code that enumerates them, for no gain: a name is not a secret, and the
//! `Debug` impl on `CredentialsSpec` already treats values as the sensitive part
//! by redacting them alone.

// Not yet reachable from the launch path: nothing calls into the credential split
// during pod spawn, because the guest still has no way to submit an
// envelope. CI denies warnings, and a bare dead_code warning here would
// read as an oversight rather than a stated gap. The tests exercise every
// item; `docs/production-delta.md` records the missing call site.
#![cfg_attr(not(test), allow(dead_code))]

use nucleus_cred_broker::{Credential, CredentialStore};
use nucleus_spec::PodSpec;

/// Move credential VALUES out of a spec, returning the store that now holds
/// them.
///
/// Mutates the spec in place: after this call the spec is safe to serialise into
/// the guest, and `the_guest_spec_carries_no_credential_values` is what holds
/// that claim.
///
/// Idempotent — calling it on an already-split spec yields an empty store and
/// changes nothing, so a second call cannot resurrect values.
pub fn split_credentials(spec: &mut PodSpec) -> CredentialStore {
    let mut store = CredentialStore::new();
    let Some(creds) = spec.spec.credentials.as_mut() else {
        return store;
    };
    for (name, value) in creds.env.iter_mut() {
        if value.is_empty() {
            continue;
        }
        store.insert(name.clone(), Credential::new(std::mem::take(value)));
    }
    store
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_with_credentials() -> PodSpec {
        serde_yaml::from_str(
            r#"
apiVersion: nucleus/v1
kind: Pod
metadata:
  name: test-pod
spec:
  work_dir: /work
  timeout_seconds: 60
  policy:
    type: profile
    name: codegen
  credentials:
    env:
      LLM_API_TOKEN: "super-secret-token-value"
      DB_PASSWORD: "hunter2"
"#,
        )
        .expect("spec parses")
    }

    /// **THE PROPERTY.** After splitting, serialising the spec — which is
    /// exactly what lands at /etc/nucleus/pod.yaml inside the guest — must not
    /// contain any credential value.
    #[test]
    fn the_guest_spec_carries_no_credential_values() {
        let mut spec = spec_with_credentials();
        let _store = split_credentials(&mut spec);

        let yaml = serde_yaml::to_string(&spec).expect("spec serialises");
        assert!(
            !yaml.contains("super-secret-token-value"),
            "the guest spec still carries a credential value:\n{yaml}"
        );
        assert!(
            !yaml.contains("hunter2"),
            "the guest spec still carries a credential value:\n{yaml}"
        );
    }

    /// The names survive — the guest may know WHICH credentials exist, because
    /// a name is not a secret and removing it would break enumeration for no
    /// gain.
    #[test]
    fn the_credential_names_survive_the_split() {
        let mut spec = spec_with_credentials();
        let _store = split_credentials(&mut spec);
        let yaml = serde_yaml::to_string(&spec).expect("spec serialises");
        assert!(
            yaml.contains("LLM_API_TOKEN"),
            "names must survive:\n{yaml}"
        );
        assert!(yaml.contains("DB_PASSWORD"), "names must survive:\n{yaml}");
    }

    /// The values are not destroyed, they are RELOCATED — the broker can still
    /// serve them. Without this the test above is satisfied by deleting them.
    #[test]
    fn the_values_move_to_the_broker_rather_than_vanishing() {
        use nucleus_cred_broker::{AuthorizedRequest, PodIdentity};
        let mut spec = spec_with_credentials();
        let store = split_credentials(&mut spec);

        let approved = AuthorizedRequest {
            pod_identity: PodIdentity::observed_by_host("spiffe://nucleus/pod/test"),
            operation: "WebFetch".to_string(),
            target: "LLM_API_TOKEN".to_string(),
        };
        let cred = store
            .for_request(&approved)
            .expect("the broker holds what the spec gave up");
        assert_eq!(cred.expose(), "super-secret-token-value");
    }

    /// Idempotent: a second split cannot resurrect values, and yields nothing.
    #[test]
    fn splitting_twice_is_harmless() {
        let mut spec = spec_with_credentials();
        let _first = split_credentials(&mut spec);
        let second = split_credentials(&mut spec);
        let yaml = serde_yaml::to_string(&spec).expect("spec serialises");
        assert!(!yaml.contains("super-secret-token-value"));
        // The second store is empty — every value was already taken.
        use nucleus_cred_broker::{AuthorizedRequest, PodIdentity};
        assert!(second
            .for_request(&AuthorizedRequest {
                pod_identity: PodIdentity::observed_by_host("p"),
                operation: "o".into(),
                target: "LLM_API_TOKEN".into(),
            })
            .is_err());
    }

    /// A spec with no credentials is handled without ceremony.
    #[test]
    fn a_spec_without_credentials_splits_to_nothing() {
        let mut spec: PodSpec = serde_yaml::from_str(
            r#"
apiVersion: nucleus/v1
kind: Pod
metadata:
  name: bare
spec:
  work_dir: /work
  timeout_seconds: 60
  policy:
    type: profile
    name: codegen
"#,
        )
        .expect("spec parses");
        let _store = split_credentials(&mut spec);
        assert!(spec.spec.credentials.is_none());
    }
}

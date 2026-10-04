//! Prepare the host-delivered spec without exporting broker credential values.
//!
//! Firecracker guest-init fetches its spec over the workload API. In enforcing
//! mode that response must omit every `credentials.env` value before the guest
//! can fetch the spec or start its workload. Legacy/listen delivery retains its
//! existing behavior. Container and local drivers use their own delivery paths.
//!
//! Broker credentials come from the operator's upstream registry and host
//! environment or federation. Values supplied in a pod spec are not allowed to
//! replace those credentials. The split store is therefore discarded for this
//! delivery path; only credential names cross into the enforced guest spec.
//! This does not scrub secrets a caller embeds in arbitrary workload arguments,
//! files, image layers, or environment fields outside `credentials.env`.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use nucleus_cred_broker::{Credential, CredentialStore};
use nucleus_spec::PodSpec;

/// Serialize only the copy prepared for this delivery mode. The admitted host
/// spec retains its original values for host-side admission and evidence.
/// Serialization failure refuses preparation; it is never an absent spec.
pub(crate) struct Withheld(());

pub(crate) fn guest_spec_yaml(
    spec: &PodSpec,
    withhold: bool,
) -> Result<(String, Option<Withheld>), serde_yaml::Error> {
    let mut guest = spec.clone();
    if withhold {
        // The operator registry remains the broker's credential authority.
        drop(split_credentials(&mut guest));
    }
    Ok((
        serde_yaml::to_string(&guest)?,
        withhold.then_some(Withheld(())),
    ))
}

/// Old guest-init binaries ignore the required-spec boot argument. Refuse them
/// even if their proxy is healthy. This acknowledges compatibility only: a
/// compromised guest's console is never independent execution evidence.
pub(crate) fn verify_guest_ack(console: &str) -> Result<(), crate::ApiError> {
    if console
        .lines()
        .any(|line| line.trim() == nucleus_spec::guest_layout::HOST_SPEC_READY)
    {
        Ok(())
    } else {
        Err(crate::ApiError::Driver(
            "guest did not acknowledge required host spec selection; rebuild guest-init for enforcing mode".into(),
        ))
    }
}

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

    #[test]
    fn healthy_old_guests_do_not_acknowledge_required_host_spec_selection() {
        assert!(verify_guest_ack("NUCLEUS_EGRESS_PROBE: PASS\n").is_err());
        assert!(verify_guest_ack("NUCLEUS_HOST_SPEC: NOT_READY\n").is_err());
        assert!(verify_guest_ack(nucleus_spec::guest_layout::HOST_SPEC_READY).is_ok());
    }

    const NOW: u64 = 1_700_000_000;

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
            expires_at_unix: NOW + nucleus_cred_broker::APPROVAL_TTL_SECS,
            pod_identity: PodIdentity::observed_by_host("spiffe://nucleus/pod/test"),
            operation: "WebFetch".to_string(),
            target: "LLM_API_TOKEN".to_string(),
        };
        let cred = store
            .for_request(&approved, NOW)
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
        assert!(
            second
                .for_request(
                    &AuthorizedRequest {
                        expires_at_unix: NOW + nucleus_cred_broker::APPROVAL_TTL_SECS,
                        pod_identity: PodIdentity::observed_by_host("p"),
                        operation: "o".into(),
                        target: "LLM_API_TOKEN".into(),
                    },
                    NOW
                )
                .is_err()
        );
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

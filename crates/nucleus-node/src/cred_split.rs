//! Take credentials out of the spec before the spec enters the guest.
//!
//! # Where the exposure actually is — corrected
//!
//! This module was written believing the exposure was uniform: *"the full
//! `PodSpec` is written to `/etc/nucleus/pod.yaml` inside the guest, so every
//! credential a pod is given lands in a file the agent can read."* Tracing each
//! driver shows that is **wrong per driver**, and the difference is what has kept
//! this module from having a call site:
//!
//! | Driver | Does the node write a guest spec? | How do `credentials.env` values reach the guest? |
//! |---|---|---|
//! | Firecracker | **No** — `scripts/firecracker/build-rootfs.sh` copies the spec into the rootfs at IMAGE BUILD time | They do not. Nothing on this path injects them. |
//! | Container | Yes, `pod.yaml` in the pod dir | **Directly as container environment variables** (`spawn_container_pod`), *and* in the spec file |
//! | Local | Yes, `pod.yaml` in the pod dir | Via the spec file |
//!
//! Two consequences, both load-bearing:
//!
//! * **The driver this work was built for has nothing to strip.** Firecracker
//!   never receives `credentials.env`, so `split_credentials` would be a no-op
//!   there. `broker_launch::check_enforcement_is_honest` refuses
//!   `--broker-enforcing` on that path for exactly this reason.
//! * **The driver that carries the exposure has no transport.** The container
//!   driver puts credential values into environment variables — readable via
//!   `docker inspect`, via `/proc/PID/environ`, and inherited by every child the
//!   agent spawns, which is strictly worse than a file — but it has no per-pod
//!   vsock, so `broker_rollout::decide_rollout` returns `Disabled` and there is
//!   no broker to ask instead.
//!
//! That is the deadlock, stated plainly rather than left as a missing call site:
//! stripping credentials on the container driver today would leave pods with no
//! credentials and nothing to ask. Closing it needs the container driver to gain
//! a broker socket (a bind-mounted Unix socket would do — it has no vsock, but it
//! does have a filesystem), which is real work and not a wiring oversight.
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

    /// **The exposure map, pinned.** The module docs claim each driver handles
    /// `credentials.env` differently, and that claim is why this module has no
    /// call site. A doc table drifts silently from the code; this does not.
    ///
    /// Checked against `main.rs` rather than by running a driver, because the
    /// property is about which code EXISTS on each path — a behavioural test
    /// would need Docker, a kernel and a rootfs to say the same thing, and would
    /// still only cover the paths it happened to exercise.
    #[test]
    fn only_the_container_driver_injects_credential_values() {
        let src = include_str!("main.rs");

        // The container driver reads `spec.spec.credentials` and pushes the
        // values into the process environment. This is the exposure.
        // Bounded at the next `async fn`, and matching the injection pattern
        // itself rather than the word "credentials" — an unbounded span running
        // to end-of-file, matched against a word that appears in a dozen
        // comments, passed with the injection deleted. Caught by perturbation.
        let container_fn = src
            .split("async fn spawn_container_pod")
            .nth(1)
            .and_then(|s| s.split("\nasync fn ").next())
            .expect("the container driver exists");
        assert!(
            container_fn.contains("creds.env"),
            "the container driver no longer injects credentials — if that is real \
             progress, update the exposure map in this module's docs; if it moved \
             elsewhere, this test has stopped looking where the code is"
        );

        // The Firecracker driver does not. If it starts to, `split_credentials`
        // gains a call site AND `check_enforcement_is_honest` must stop refusing
        // enforcement there — the two must move together.
        let firecracker_fn = src
            .split("async fn spawn_firecracker_pod")
            .nth(1)
            .and_then(|s| s.split("\nasync fn ").next())
            .expect("the firecracker driver exists");
        assert!(
            !firecracker_fn.contains("creds.env"),
            "the Firecracker driver has started injecting credential values. That is \
             the exposure this module exists to close, and it now has a call site: \
             call `split_credentials` before the spec reaches the guest, and revisit \
             `broker_launch::check_enforcement_is_honest`, which refuses \
             --broker-enforcing on the grounds that there is nothing to strip"
        );
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
        assert!(second
            .for_request(
                &AuthorizedRequest {
                    expires_at_unix: NOW + nucleus_cred_broker::APPROVAL_TTL_SECS,
                    pod_identity: PodIdentity::observed_by_host("p"),
                    operation: "o".into(),
                    target: "LLM_API_TOKEN".into(),
                },
                NOW
            )
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

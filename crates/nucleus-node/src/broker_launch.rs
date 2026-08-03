//! The decisions the pod launch path must make about the credential broker.
//!
//! Kept as pure functions rather than inlined into the spawn path, because the
//! spawn path needs a real VM to exercise and these are the parts that must be
//! right on a machine that has none.
//!
//! # Two forks, and why each is resolved the strict way
//!
//! **A pod with no workload identity gets no broker socket.** The broker binds
//! an identity to a listener, and that identity is supposed to be a fact the
//! host established. A pod that was never registered has no such fact, and
//! serving it anyway would mean inventing one — which is precisely the
//! sloppiness removed when `pod_identity` stopped coming off the wire. So the
//! answer is to not serve.
//!
//! ## A correction to what this module previously claimed
//!
//! It said the refusal "composes with a gate already in place: identity is only
//! registered when the pod's egress is confined enough to hold one, so a pod
//! with unconfined egress cannot obtain brokered credentials at all."
//!
//! **That overstated the gate.** `net::decide_identity_grant` returns `Granted`
//! for `None` — a pod with *no* network policy is registered. What it refuses is
//! a policy whose `allow` list names a broad public range. So the composition
//! holds where a driver applies default-deny to a pod that declared no policy
//! (the Firecracker netns path), and does **not** hold in general.
//!
//! The distinction is not academic. The container driver rejects any structured
//! network policy outright — `container_driver_reject_unsupported_network_policy`
//! — so a container pod always has `None`, would always be `Granted`, and has no
//! default-deny behind it. "Unconfined egress cannot get credentials" would be
//! false there in exactly the case that matters.
//!
//! **Under `Enforcing`, a listener that fails to start fails the launch.** This
//! is the one place the two rollout halves come apart at *runtime* rather than
//! at configuration time. `decide_rollout` already refuses to enforce without a
//! vsock, but a socket can also fail to bind for reasons no configuration check
//! can see: a stale path, a full filesystem, a permissions change. Enforcing
//! means credential values were withheld from the guest spec, so continuing
//! would launch a pod that has neither its credentials nor any way to ask for
//! them — and the failure would surface later as a confusing application error
//! rather than a launch refusal. Under `ListenOnly` nothing depends on the
//! socket yet, so a failure there is a warning.

// The blanket allow this replaced said "not yet reachable from the spawn path
// itself". That is false: with the allow removed, Linux clippy at `-D warnings`
// names ZERO dead items in this file. Every function here is on the live path —
// `start_broker_for_pod` is called from `spawn_firecracker_pod`, and it reaches
// all of them.
//
// NON-LINUX ONLY, because `start_broker_for_pod` is `cfg(target_os = "linux")`
// and it is the only caller, so a macOS build compiles none of this. On Linux
// the detector stays live and will report the next thing that stops being wired.
#![cfg_attr(all(not(test), not(target_os = "linux")), allow(dead_code))]

use crate::broker_rollout::BrokerRollout;
use nucleus_cred_broker::PodIdentity;

/// Why a launch refused to enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EnforcementRefused {
    /// The node does not write this pod's guest spec, so it cannot take
    /// anything out of it.
    #[error(
        "--broker-enforcing was requested, but this driver bakes the pod spec into the image at \
         build time, so the node has no guest spec to strip credentials from. Enforcing here \
         would serve a broker socket while the image still carried the credentials — a claim of \
         withholding that is not true. Use --broker-listen, or supply the spec at launch."
    )]
    NodeDoesNotWriteTheGuestSpec,
}

/// Refuse to *claim* enforcement the wiring cannot deliver.
///
/// # The failure mode this closes
///
/// `Enforcing` means two things: serve the socket, and withhold credential
/// values from the guest spec. On the Firecracker path the second is currently
/// impossible — `scripts/firecracker/build-rootfs.sh` copies the pod spec into
/// the rootfs at **image build time**, so the node never writes a guest spec and
/// [`crate::cred_split::split_credentials`] has nothing to run on.
///
/// An operator who passed `--broker-enforcing` there would get a broker socket
/// and a reasonable belief that credentials had been withheld, while the image
/// still carried them. That is worse than the feature being absent: it is a
/// security claim that outruns its wiring.
///
/// The available responses are to downgrade silently, to warn, or to refuse.
/// This refuses. A silent downgrade IS the failure mode — the operator asked for
/// enforcement, did not get it, and has no way to tell. A warning is a downgrade
/// that assumes someone is reading logs.
pub fn check_enforcement_is_honest(
    rollout: BrokerRollout,
    node_writes_the_guest_spec: bool,
) -> Result<BrokerRollout, EnforcementRefused> {
    if rollout.withholds_credentials() && !node_writes_the_guest_spec {
        return Err(EnforcementRefused::NodeDoesNotWriteTheGuestSpec);
    }
    Ok(rollout)
}

/// What the launch path should do when the broker socket cannot be created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartFailure {
    /// Fail the pod launch. The guest has been denied its credentials and has
    /// no way to ask for them, so it cannot do its job.
    AbortLaunch,
    /// Log and carry on. Nothing depends on the socket yet.
    ContinueDegraded,
}

/// Decide the identity to bind to a pod's broker listener.
///
/// `None` means **do not serve**, for either of two reasons that are one reason:
/// the rollout did not ask for a socket, or the pod has no established identity
/// to bind to one. Returning an `Option<PodIdentity>` rather than a bool and a
/// string keeps those inseparable — a caller cannot obtain a socket decision
/// without also obtaining the identity that socket will speak for.
pub fn broker_identity(
    rollout: BrokerRollout,
    registered: Option<&nucleus_identity::Identity>,
) -> Option<PodIdentity> {
    if !rollout.serves_socket() {
        return None;
    }
    // `observed_by_host` is accurate here: this identity was minted and
    // registered by the node, from pod metadata, before the guest ran.
    registered.map(|id| PodIdentity::observed_by_host(id.to_spiffe_uri()))
}

/// What to do when [`crate::broker_transport::prepare_socket`] fails.
///
/// Keyed on whether credentials were withheld, not on whether a socket was
/// wanted: the damage from a missing listener is entirely a function of whether
/// anything was taken away in exchange for it.
pub fn on_start_failure(rollout: BrokerRollout) -> StartFailure {
    if rollout.withholds_credentials() {
        StartFailure::AbortLaunch
    } else {
        StartFailure::ContinueDegraded
    }
}

/// One pod's broker capability, minted once and consumed by exactly two places.
///
/// # The defect this type exists to make impossible
///
/// The capability was minted at the workload API bridge
/// (`main.rs`, `PodMaterial { broker_secret: Some(Uuid::new_v4()…) }`) while
/// `BrokerListener::start` passed `broker_secret: None` to the thing that
/// VERIFIES it. So the guest fetched a secret the broker had never heard of, and
/// every signed frame was refused.
///
/// Nothing caught it, and nothing could have: both halves were individually
/// correct and individually tested. The serving side served, the verifying side
/// verified, and the failure lived in the gap between two files. It fails
/// CLOSED — a broker that refuses everything is safe — which is exactly why it
/// could sit there indefinitely looking like a working capability.
///
/// A single value with two projections is the smallest fix that makes the two
/// consumers provably the same secret rather than coincidentally the same
/// secret. `mint_appears_exactly_once_on_the_spawn_path` covers the one hole
/// this shape leaves: calling [`Self::mint`] twice.
///
/// # Affine, not linear — and the difference is worth stating
///
/// This derived `Clone` and handed out copies through `&self`, so it was freely
/// duplicable: "one value with two projections" described the intent, not the
/// type. It is now a PAIR of move-only tokens, neither `Clone` nor `Copy`, each
/// consumed by value. Duplication is a compile error.
///
/// What Rust gives is AFFINE — used at most once. Linear — used *exactly* once,
/// with the two tokens provably from the same mint — needs either an
/// invariant-lifetime brand (which requires a closure-shaped scope the async pod
/// spawn path does not naturally take) or a runtime check, which is not a proof.
/// So the residual hole is calling [`Self::mint`] twice and handing one consumer
/// a token from each; `mint_appears_exactly_once_on_the_spawn_path` covers it by
/// counting, and that test survives precisely because the type cannot.
///
/// True linearity lives in the model, not here. That asymmetry is the reason a
/// proved model↔code correspondence matters rather than being a nicety: it is
/// what would let the Lean side's linearity say anything about this side's
/// affineness.
pub struct BrokerCapability;

/// The token the workload API serves to the guest. Move-only, consumed once.
#[must_use = "a ServeToken that is never served is a capability the guest never gets"]
pub struct ServeToken {
    secret: String,
}

/// The token the broker listener verifies against. Move-only, consumed once.
#[must_use = "a VerifyToken that is never installed leaves the verifier with nothing, \
              which is exactly the defect BrokerCapability exists to prevent"]
pub struct VerifyToken {
    secret: String,
}

impl std::fmt::Debug for ServeToken {
    /// Never the value, and never its length.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ServeToken(<redacted>)")
    }
}

impl std::fmt::Debug for VerifyToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifyToken(<redacted>)")
    }
}

impl ServeToken {
    /// Consume the token, yielding the value served to the guest exactly once.
    #[must_use]
    pub fn into_served(self) -> String {
        self.secret
    }
}

impl VerifyToken {
    /// Consume the token, yielding the key the listener authenticates with.
    #[must_use]
    pub fn into_verifier(self) -> std::sync::Arc<Vec<u8>> {
        std::sync::Arc::new(self.secret.into_bytes())
    }
}

impl BrokerCapability {
    /// Mint a fresh capability for one pod, as a linked pair.
    ///
    /// Returns BOTH tokens because there is no use for one without the other:
    /// a served capability no verifier holds is what made this inert, and a
    /// verifier with a capability nobody was served refuses every frame.
    ///
    /// Per-pod and never reused: two pods sharing one would let either sign for
    /// the other, and the listener's identity binding — one socket per VM —
    /// would stop meaning anything.
    pub fn mint() -> (ServeToken, VerifyToken) {
        let secret = uuid::Uuid::new_v4().simple().to_string();
        (
            ServeToken {
                secret: secret.clone(),
            },
            VerifyToken { secret },
        )
    }
}

/// Build this pod's credential store from **the node's own environment**.
///
/// # The signature is the security property
///
/// This takes a slice of upstream specs and NOT a `PodSpec`, deliberately, and
/// that is the whole design rather than a style choice.
///
/// On Firecracker, `scripts/firecracker/build-rootfs.sh` copies the pod spec
/// into the rootfs **at image build time**. A credential sourced from
/// `spec.spec.credentials.env` would therefore be written into the guest image —
/// the precise opposite of the property this broker exists to provide, and
/// invisible at runtime because the file was baked days earlier.
///
/// A function that cannot name `PodSpec` cannot read `credentials.env` from it.
/// That beats a test asserting it does not: the test would pass for as long as
/// nobody added the field, and the compiler enforces this for as long as the
/// signature stands. `the_store_is_built_without_naming_the_pod_spec` pins the
/// signature so the guarantee cannot be widened without the widening being seen.
///
/// # What comes from where
///
/// The operator writes the upstream's `name` and `credential_env` in the pod
/// spec — those are configuration, not secrets. The VALUE comes from the node's
/// environment, where an operator put it and where no guest can reach.
///
/// An upstream whose variable is unset (or empty) registers nothing, so the
/// broker refuses it by absence — the same refusal a policy denial gives, which
/// is what stops a guest probing which credentials the host holds.
pub fn store_from_node_environment(
    upstreams: &[nucleus_spec::CredentialedEgressSpec],
) -> nucleus_cred_broker::CredentialStore {
    let mut store = nucleus_cred_broker::CredentialStore::new();
    for spec in upstreams {
        // Keyed by NAME, because that is what `PerformRequest.target` carries and
        // what `cdp_fetch` looks up. Keying by host would let two upstreams on
        // one host share a credential without anyone saying so.
        match std::env::var(&spec.credential_env) {
            Ok(value) if !value.is_empty() => {
                store.insert(&spec.name, nucleus_cred_broker::Credential::new(value));
            }
            _ => {
                // Logged by variable NAME, never by value, and at info because an
                // operator who configured an upstream and forgot its credential
                // otherwise sees only a coarse refusal from inside the guest.
                tracing::info!(
                    upstream = %spec.name,
                    variable = %spec.credential_env,
                    "no credential in the node's environment for this upstream; the broker \
                     will refuse requests for it"
                );
            }
        }
    }
    store
}

/// Start the credential broker for a pod, if the rollout and the pod's identity
/// both permit it.
///
/// Returns `Ok(None)` when no socket should exist — which is the default. The
/// error case is deliberately narrow: a launch fails only when enforcement was
/// requested dishonestly, or when the socket could not be created *and*
/// credentials had already been withheld in exchange for it.
#[cfg(target_os = "linux")]
pub fn start_broker_for_pod(
    state: &crate::NodeState,
    spec: &nucleus_spec::PodSpec,
    vsock_path: &std::path::Path,
    registered: Option<&nucleus_identity::Identity>,
    id: uuid::Uuid,
    capability: VerifyToken,
    jail_owner: Option<(u32, u32)>,
) -> Result<Option<crate::broker_transport::BrokerListener>, crate::ApiError> {
    let transport = if spec.spec.vsock.is_some() {
        crate::broker_rollout::BrokerTransport::Vsock
    } else {
        crate::broker_rollout::BrokerTransport::None
    };
    let rollout = crate::broker_rollout::decide_rollout(
        state.broker_enforcing,
        state.broker_listen,
        transport,
    );
    // The Firecracker rootfs carries the pod spec from image build time, so the
    // node writes no guest spec and can withhold nothing from it. Passing `false`
    // here is what turns `--broker-enforcing` into a refusal rather than a false
    // claim; it becomes `true` when the split gains a call site.
    let rollout = check_enforcement_is_honest(rollout, false)
        .map_err(|e| crate::ApiError::Driver(e.to_string()))?;

    let Some(identity) = broker_identity(rollout, registered) else {
        return Ok(None);
    };

    // The policy the PDP will decide against is the pod's own resolved lattice.
    // A pod whose policy will not resolve gets no broker: deciding against a
    // default lattice would silently substitute a policy nobody wrote.
    let policy = match spec.spec.resolve_policy() {
        Ok(p) => std::sync::Arc::new(p),
        Err(e) => {
            tracing::warn!(
                pod = %id,
                error = %e,
                "credential broker not started: the pod's policy did not resolve, and deciding \
                 against a default lattice would substitute a policy nobody wrote"
            );
            return Ok(None);
        }
    };

    // The upstreams the HOST may be asked to call, straight from the pod spec.
    //
    // This is the only source: a `PerformRequest` names an upstream, it does not
    // describe one, so the base URL, the header and its prefix are all facts the
    // operator wrote and the guest can only select among. An empty list — the
    // ordinary case today — means every perform request is refused by name,
    // which is the right answer for a pod whose operator configured none.
    let upstreams = std::sync::Arc::new(spec.spec.credentialed_egress.clone());

    // The comment here used to read "Empty until `cred_split` has a call site on
    // this driver", and a `CredentialStore::new()` sat under it refusing
    // everything. It is populated now — from the NODE's environment, never from
    // the pod spec, for the reason `store_from_node_environment` gives at
    // length: on Firecracker the pod spec is baked into the guest rootfs, so a
    // credential taken from it would ship inside the image.
    let store = std::sync::Arc::new(store_from_node_environment(&upstreams));

    match crate::broker_transport::BrokerListener::start(
        vsock_path,
        state.broker_vsock_port,
        crate::broker_transport::PodBrokerConfig {
            identity,
            policy,
            store,
            upstreams,
            // The SAME value the workload API serves the guest. Passing `None`
            // here is what made the capability inert; see `BrokerCapability`.
            broker_secret: capability.into_verifier(),
        },
        jail_owner,
    ) {
        Ok(listener) => {
            tracing::info!(
                "started credential broker at {} for pod {}",
                listener.socket_path().display(),
                id
            );
            Ok(Some(listener))
        }
        Err(e) => match on_start_failure(rollout) {
            StartFailure::AbortLaunch => Err(crate::ApiError::Driver(format!(
                "credential broker socket could not be created ({e}), and this pod's credentials \
                 were withheld in exchange for it — refusing to launch a pod that has neither its \
                 credentials nor a way to ask for them"
            ))),
            StartFailure::ContinueDegraded => {
                tracing::warn!(pod = %id, error = %e, "credential broker socket not created");
                Ok(None)
            }
        },
    }
}

#[cfg(test)]
mod broker_capability {
    use super::*;

    /// **The property, stated directly.** The value served to the guest and the
    /// value the broker verifies against must be the same bytes. They were not:
    /// the bridge minted its own and the listener got `None`.
    #[test]
    fn what_is_served_is_what_is_verified() {
        let (serve, verify) = BrokerCapability::mint();
        let served = serve.into_served();
        let verifier = verify.into_verifier();
        assert_eq!(
            served.as_bytes(),
            verifier.as_slice(),
            "the guest would hold a capability the verifier cannot recognise"
        );
    }

    /// Per-pod, never shared. Two pods on one capability could sign for each
    /// other, and the listener's one-socket-per-VM identity binding would stop
    /// meaning anything.
    #[test]
    fn two_pods_do_not_share_a_capability() {
        assert_ne!(
            BrokerCapability::mint().0.into_served(),
            BrokerCapability::mint().0.into_served()
        );
    }

    /// **The tokens cannot be duplicated, and the COMPILER says so.**
    ///
    /// This type derived `Clone` and served copies through `&self`, so "one value
    /// with two projections" described the intent and not the property: any
    /// holder could make as many capabilities as it liked.
    ///
    /// # This was a source scan, and it did not need to be
    ///
    /// The first version grepped the declarations for `Clone`/`Copy`, on the
    /// belief that "does not implement a trait" is not assertable in Rust. That
    /// is false. The `static_assertions` crate's `assert_not_impl_any!` does it
    /// on stable via deliberate inference ambiguity, and the trick is ten lines,
    /// so it is inlined here rather than adding a dependency to a crate that
    /// links credential material.
    ///
    /// How it works: two blanket impls that overlap ONLY when `T: Clone`. If the
    /// token is `Clone`, both apply, the type parameter cannot be inferred, and
    /// the build fails. If it is not, exactly one applies and this resolves.
    ///
    /// The failure therefore moves from a test to the compiler — a grep enforcing
    /// a type-level property was a confession, and this retires it.
    ///
    /// # What this does NOT establish
    ///
    /// Affine, not linear. Rust enforces at-most-once; it does not enforce that
    /// the two tokens came from the SAME mint. That needs an invariant-lifetime
    /// brand — reachable with `generativity`'s Drop-guard macro, which needs no
    /// closure — so `mint_appears_exactly_once_on_the_spawn_path` below is
    /// deletable debt rather than a permanent limit.
    #[test]
    fn the_tokens_are_move_only() {
        trait AmbiguousIfClone<A> {
            fn some_item() {}
        }
        impl<T: ?Sized> AmbiguousIfClone<()> for T {}
        impl<T: Clone> AmbiguousIfClone<u8> for T {}

        // Each line fails to COMPILE if that token becomes duplicable.
        let _ = <ServeToken as AmbiguousIfClone<_>>::some_item;
        let _ = <VerifyToken as AmbiguousIfClone<_>>::some_item;

        // NON-VACUITY, and it was run rather than assumed. A test cannot contain
        // its own compile error, so the control is a perturbation: uncommenting
        // the line below — `String` IS `Clone` — must fail to build. Measured:
        // `error[E0283]: type annotations needed`, the same error that
        // re-deriving `Clone` on a token produces. So the two assertions above
        // are not passing by failing to work.
        //   let _ = <String as AmbiguousIfClone<_>>::some_item;
    }

    /// **The hole this type's shape leaves, closed by counting.**
    ///
    /// `BrokerCapability` guarantees that the two PROJECTIONS agree. It cannot
    /// stop someone calling `mint()` twice on the spawn path and handing one to
    /// each consumer — which reproduces the original defect exactly, with a type
    /// that looks like it prevents it.
    ///
    /// So the call site is counted. One mint per spawn path. A second one is a
    /// compile-green, test-green, silently-refusing broker, and this is the only
    /// thing standing between that and a reviewer noticing.
    #[test]
    fn mint_appears_exactly_once_on_the_spawn_path() {
        let src = include_str!("main.rs");
        let mints = src.matches("BrokerCapability::mint()").count();
        assert_eq!(
            mints, 1,
            "found {mints} calls to BrokerCapability::mint() in main.rs. Two mints means the \
             workload API and the broker listener can each get their own, which is the exact \
             defect this type was introduced to remove."
        );
    }
}

#[cfg(test)]
mod store_population {
    use super::*;
    use nucleus_cred_broker::{PodIdentity, TaskRequestEnvelope};
    use nucleus_spec::CredentialedEgressSpec;
    use portcullis::PermissionLattice;

    const NOW: u64 = 1_700_000_000;

    /// Each env-touching test uses its OWN variable name. Tests share a process
    /// and run in parallel, so two of them on one name is a race that surfaces
    /// as an unrelated flake — which teaches people to re-run rather than look.
    fn upstream(name: &str, credential_env: &str) -> CredentialedEgressSpec {
        CredentialedEgressSpec {
            name: name.into(),
            upstream: "https://upstream.invalid/v1".into(),
            credential_env: credential_env.into(),
            header: "authorization".into(),
            value_prefix: "Bearer ".into(),
        }
    }

    /// Look a credential up exactly as the broker does.
    ///
    /// Through `authorize_and_fetch` rather than a test-only accessor on
    /// `CredentialStore`, deliberately: the risk this whole module carries is a
    /// KEYING mismatch — the store writing under one key while `cdp_fetch` reads
    /// another — and an accessor that read the map directly would agree with the
    /// store by construction and never notice. This fails if they disagree.
    fn brokered(store: &nucleus_cred_broker::CredentialStore, target: &str) -> Option<String> {
        let envelope = TaskRequestEnvelope {
            operation: "WebFetch".into(),
            target: target.into(),
            justification: "test".into(),
        };
        crate::broker::authorize_and_fetch(
            &envelope,
            &PodIdentity::observed_by_host("spiffe://nucleus/pod/abc"),
            &PermissionLattice::permissive(),
            store,
            NOW,
        )
        .ok()
        .map(|c| c.expose().to_string())
    }

    /// **The non-vacuity control, first.** Everything else here asserts that
    /// something is ABSENT from the store, and a function returning an empty
    /// store would satisfy all of it while being useless.
    ///
    /// This also pins the keying: the target is the upstream NAME, which is what
    /// `PerformRequest.target` carries.
    #[test]
    fn a_configured_upstream_with_a_set_variable_is_reachable_by_name() {
        let var = "NUCLEUS_TEST_STORE_POP_HAPPY";
        std::env::set_var(var, "node-side-token");
        let store = store_from_node_environment(&[upstream("model-api", var)]);
        std::env::remove_var(var);

        assert_eq!(
            brokered(&store, "model-api").as_deref(),
            Some("node-side-token"),
            "the store must key by the upstream NAME — the key PerformRequest.target \
             carries and cdp_fetch looks up"
        );
    }

    /// An unset variable registers nothing, so the broker refuses by absence.
    /// Registering an empty credential instead would send a bare `Bearer `
    /// upstream — authenticating as nobody, which some upstreams accept.
    #[test]
    fn an_unset_variable_registers_nothing() {
        let store =
            store_from_node_environment(&[upstream("model-api", "NUCLEUS_TEST_STORE_POP_UNSET")]);
        assert_eq!(brokered(&store, "model-api"), None);
    }

    /// Same for a variable that is set but empty — the more common operator
    /// mistake, and the one that looks configured.
    #[test]
    fn an_empty_variable_registers_nothing() {
        let var = "NUCLEUS_TEST_STORE_POP_EMPTY";
        std::env::set_var(var, "");
        let store = store_from_node_environment(&[upstream("model-api", var)]);
        std::env::remove_var(var);
        assert_eq!(
            brokered(&store, "model-api"),
            None,
            "an empty credential would authenticate as nobody"
        );
    }

    /// One upstream missing its credential must not take out the others. An
    /// operator adding a second upstream should not silently lose the first.
    #[test]
    fn one_missing_credential_does_not_discard_the_rest() {
        let var = "NUCLEUS_TEST_STORE_POP_PARTIAL";
        std::env::set_var(var, "present");
        let store = store_from_node_environment(&[
            upstream("has-one", var),
            upstream("has-none", "NUCLEUS_TEST_STORE_POP_PARTIAL_MISSING"),
        ]);
        std::env::remove_var(var);

        assert_eq!(brokered(&store, "has-one").as_deref(), Some("present"));
        assert_eq!(brokered(&store, "has-none"), None);
    }

    /// **The structural guarantee, checked against the signature.**
    ///
    /// `store_from_node_environment` takes upstream specs and NOT a `PodSpec`,
    /// so it CANNOT read `spec.spec.credentials.env`. That matters because on
    /// Firecracker the pod spec is baked into the guest rootfs at image build
    /// time — a credential sourced from it would ship inside the image, which is
    /// the exact property the broker exists to provide, inverted.
    ///
    /// Scanning the signature rather than the behaviour is deliberate: a
    /// behavioural test ("it did not read the spec") passes for as long as
    /// nobody adds the parameter, and says nothing the moment somebody does.
    /// This one fails at the widening, which is when it matters.
    #[test]
    fn the_store_is_built_without_naming_the_pod_spec() {
        let src = include_str!("broker_launch.rs");
        let sig = src
            .split("pub fn store_from_node_environment(")
            .nth(1)
            .and_then(|s| s.split(") -> ").next())
            .expect("store_from_node_environment signature");
        assert!(
            !sig.contains("PodSpec") && !sig.contains("credentials"),
            "the store builder can now reach the pod spec, and on Firecracker the pod \
             spec is baked into the guest rootfs — a credential read from it would ship \
             inside the image. Signature was: {sig}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn an_identity() -> nucleus_identity::Identity {
        nucleus_identity::Identity::new("nucleus.local", "default", "pod-abc")
    }

    /// Disabled serves nothing, identity or not.
    #[test]
    fn a_disabled_rollout_serves_no_socket() {
        assert!(broker_identity(BrokerRollout::Disabled, Some(&an_identity())).is_none());
    }

    /// **The gate.** A pod the node never registered has no host-established
    /// identity, so there is nothing truthful to bind the listener to and it is
    /// not served.
    ///
    /// This is the whole of the gate, deliberately stated without the egress
    /// claim this module used to make — see the module docs for why that claim
    /// was too strong.
    #[test]
    fn a_pod_without_an_identity_is_not_served_even_when_asked_for() {
        for rollout in [BrokerRollout::ListenOnly, BrokerRollout::Enforcing] {
            assert!(
                broker_identity(rollout, None).is_none(),
                "{rollout:?} served a socket for a pod with no established identity"
            );
        }
    }

    /// A registered pod is served, under the identity the node minted for it —
    /// not one derived from anything the guest supplied.
    #[test]
    fn a_registered_pod_is_served_under_the_identity_the_node_minted() {
        let id = an_identity();
        let bound = broker_identity(BrokerRollout::ListenOnly, Some(&id))
            .expect("a registered pod should be served");
        assert_eq!(bound.as_str(), id.to_spiffe_uri());
    }

    /// **Failing to bind is fatal exactly when credentials were withheld.**
    /// Enforcing means the guest spec was stripped, so a pod launched without a
    /// listener has neither its credentials nor a way to ask — a failure that
    /// would otherwise surface much later as an application error.
    #[test]
    fn a_failed_socket_aborts_the_launch_only_when_credentials_were_withheld() {
        assert_eq!(
            on_start_failure(BrokerRollout::Enforcing),
            StartFailure::AbortLaunch
        );
        assert_eq!(
            on_start_failure(BrokerRollout::ListenOnly),
            StartFailure::ContinueDegraded
        );
        assert_eq!(
            on_start_failure(BrokerRollout::Disabled),
            StartFailure::ContinueDegraded
        );
    }

    /// **What the identity gate actually does**, pinned so the prose above
    /// cannot drift back into overstating it. A pod with NO network policy is
    /// granted an identity; what gets refused is a policy naming a broad public
    /// range. Any claim of the form "unconfined egress cannot obtain X" has to
    /// rest on a driver's default-deny, not on this function.
    #[test]
    fn a_pod_with_no_network_policy_is_still_granted_an_identity() {
        assert!(matches!(
            crate::net::decide_identity_grant(None),
            crate::net::IdentityGrant::Granted
        ));
    }

    /// **A security claim may not outrun its wiring.** Asking to enforce where
    /// the node cannot strip the guest spec is refused, not quietly downgraded:
    /// the operator would otherwise believe credentials were withheld while the
    /// image still carried them.
    #[test]
    fn enforcement_is_refused_where_nothing_can_be_withheld() {
        assert_eq!(
            check_enforcement_is_honest(BrokerRollout::Enforcing, false),
            Err(EnforcementRefused::NodeDoesNotWriteTheGuestSpec)
        );
    }

    /// The refusal is specific to the claim, not to the broker. Serving a socket
    /// withholds nothing, so it is unaffected — otherwise this check would block
    /// the half that works in order to police the half that does not.
    #[test]
    fn listening_is_unaffected_by_the_enforcement_check() {
        for spec_written in [true, false] {
            assert_eq!(
                check_enforcement_is_honest(BrokerRollout::ListenOnly, spec_written),
                Ok(BrokerRollout::ListenOnly)
            );
            assert_eq!(
                check_enforcement_is_honest(BrokerRollout::Disabled, spec_written),
                Ok(BrokerRollout::Disabled)
            );
        }
        // And enforcing IS allowed where the node does write the spec.
        assert_eq!(
            check_enforcement_is_honest(BrokerRollout::Enforcing, true),
            Ok(BrokerRollout::Enforcing)
        );
    }

    /// Exactly the rollouts that withhold are the ones the check can refuse.
    /// Stated as a loop so a fourth variant cannot be added without deciding.
    #[test]
    fn only_withholding_rollouts_can_be_refused() {
        for rollout in [
            BrokerRollout::Disabled,
            BrokerRollout::ListenOnly,
            BrokerRollout::Enforcing,
        ] {
            assert_eq!(
                check_enforcement_is_honest(rollout, false).is_err(),
                rollout.withholds_credentials(),
                "{rollout:?} disagrees with its own withholding claim"
            );
        }
    }

    /// The two decisions must agree: anything that would abort on a start
    /// failure must have wanted a socket in the first place. A rollout that
    /// aborted the launch over a socket it never asked for would make the
    /// broker's failure mode worse than its absence.
    #[test]
    fn nothing_aborts_over_a_socket_it_never_wanted() {
        for rollout in [
            BrokerRollout::Disabled,
            BrokerRollout::ListenOnly,
            BrokerRollout::Enforcing,
        ] {
            if on_start_failure(rollout) == StartFailure::AbortLaunch {
                assert!(
                    broker_identity(rollout, Some(&an_identity())).is_some(),
                    "{rollout:?} aborts the launch over a socket it does not serve"
                );
            }
        }
    }
}

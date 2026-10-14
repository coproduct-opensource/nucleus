//! The C2 field census of [`NodeState`], as a compile error (M6 step 1 in
//! `docs/north-star.md`; ADR 0007 E-1).
//!
//! The cross-pod question for every field is the one `docs/cross-pod-view.md`
//! asks: **can pod B's actions change what pod A observes?** The census used to
//! be a hand list in that document, and it went stale (38 fields counted, 56 by
//! the time anyone looked again). Here one list generates two things: the
//! exhaustive pattern `NodeState { a: _, b: _, … }` with no `..`, and the
//! classification. So a field added to `NodeState` without an entry is E0027,
//! and an entry naming a field that no longer exists is E0026. Neither can be
//! merged by forgetting.
//!
//! The classes are what the code shows, not what the model needs.
//! `Unclassified` means the reading pass could not settle the field. It does
//! NOT mean the field is safe.

use crate::NodeState;

/// What a field is, for cross-pod confidentiality.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Surface {
    /// No pod's action writes it: operator configuration, or state only the
    /// node itself changes. A constant carries nothing between pods.
    Structural,
    /// Node-only key material or credential. Never served to any pod.
    Secret,
    /// Written for one pod and served only to that pod, keyed by an injective
    /// per-pod key.
    PerPod,
    /// Pods' actions write it, and what a pod is served is filtered to its own
    /// lineage.
    LineageScoped,
    /// Written by the operator, not by pods. Delivered per pod by a selector
    /// over the watcher's own lineage or its own labels.
    SelectorScoped,
    /// Scoped by the tenant root rather than by lineage, so pods of one tenant
    /// outside each other's lineage share it.
    TenantShared,
    /// Pods' actions write it, and another pod observes that only as
    /// availability, latency or a count. These channels are excluded by the
    /// North Star sentence ("availability and resource-contention channels").
    Contention,
    /// The reading pass could not settle it.
    Unclassified,
}

struct Entry {
    field: &'static str,
    surface: Surface,
    why: &'static str,
}

/// One list, two outputs. `$(#[$cfg])*` carries the field's own `#[cfg]`, so a
/// field that exists only under a feature or a target is classified exactly
/// where it exists.
macro_rules! census {
    ($( $(#[$cfg:meta])* $field:ident => $surface:ident, $why:literal; )*) => {
        // One `push` per entry is what lets each carry its field's `#[cfg]`: an
        // attribute may sit on a statement, not on an array element.
        #[expect(
            clippy::vec_init_then_push,
            reason = "each push carries its field's #[cfg]; vec![..] cannot"
        )]
        fn census() -> Vec<Entry> {
            // Exhaustive, no `..` (E-1): the compiler is the census. Never
            // called; the pattern alone is the check.
            let _exhaustive = |NodeState { $( $(#[$cfg])* $field: _, )* }: &NodeState| {};
            let mut entries = Vec::new();
            $(
                $(#[$cfg])*
                entries.push(Entry {
                    field: stringify!($field),
                    surface: Surface::$surface,
                    why: $why,
                });
            )*
            entries
        }
    };
}

census! {
    request_proofs => Unclassified,
        "replay caches behind the request-proof listeners; whether a pod-originated request can reach them, and so observe another caller's nonce, is not traced";
    pods => LineageScoped,
        "the pod registry; listing and management filtered by caller_may_manage, mechanized in PodCrossView.lean";
    intake => Structural,
        "the launch gate; only a node shutdown drain closes it";
    state_dir => Structural, "operator path, fixed at startup";
    host_roots => Structural, "operator host roots, fixed at startup; per-pod directories live beneath them";
    pod_ceilings => Structural, "operator per-pod resource ceilings";
    node_capacity => Contention,
        "aggregate memory/vCPU reservations; another pod's reservation shows only as a refused create";
    driver => Structural, "operator driver choice";
    #[cfg(feature = "local-driver")]
    tool_proxy_path => Structural, "operator path";
    #[cfg(feature = "local-driver")]
    local_driver_opt_in => Structural, "decided once at startup from operator flags";
    firecracker_path => Structural, "operator path";
    firecracker_pool => Contention,
        "bounded launch semaphore; blocks one pod's spawn on another's exit (cross-pod-view.md finding 2)";
    firecracker_api_boot => Structural, "operator flag";
    firecracker_netns => Structural, "operator flag";
    firecracker_netns_drift_check => Structural, "operator flag";
    firecracker_netns_drift_interval => Structural, "operator setting";
    firecracker_seccomp_verify => Structural, "operator flag";
    firecracker_jailer => Structural, "operator flag";
    jailer_path => Structural, "operator path";
    jailer_chroot_base => Structural, "operator path";
    jailer_uid => Structural, "operator setting";
    jailer_gid => Structural, "operator setting";
    egress_proxy => Structural, "operator egress-proxy configuration";
    jailer_limits => Structural, "operator jailer limits";
    sealed_rootfs => Contention,
        "LRU of sealed rootfs copies keyed by image digest; another pod's use shows only as a cache hit or miss";
    network_allocator => Contention,
        "dense index allocator; a pod's own IP reveals a high-water count of concurrent pods (co-tenancy cardinality)";
    #[cfg(feature = "local-driver")]
    listen_addr => Structural, "operator listen address";
    caller_secret => Secret, "node-only token-derivation secret, fresh per process";
    approval_signer => Secret, "approval signing key; only the public half, the same for every pod, is served";
    proxy_actor => Structural, "operator setting";
    trusted_postures => Structural, "operator posture registry, parsed once";
    audit_sinks => Structural, "operator audit sinks";
    decisions => Structural,
        "operator trust roots, tenant and bundle directory; read per pod, written by no pod (decision_provisioning)";
    memory => TenantShared,
        "memory spaces: by default one per (tenant, lineage root, name), so pods outside a lineage share nothing; a tenant-declared Workspace or TenantAll policy, or a migrated TenantAll-legacy one, shares a space across lineages as a declared channel. Each run gets its own binding with a pinned snapshot and a private branch, receipted at delivery (memory_space, memory_binding)";
    audit_minter => Secret, "holds the node's audit credential; each pod is minted only its own scoped one";
    drand_config => Structural, "operator setting";
    identity_manager => PerPod,
        "certificate cache keyed by the injective pod_identity; mechanized in PodCrossViewIdentity.lean";
    broker_listen => Structural, "operator flag";
    broker_enforcing => Structural, "resolved once at startup";
    workload_landlock => Structural, "operator waiver";
    egress_stream_limits => Structural, "operator per-call bounds";
    staging_budget => Contention,
        "one node-wide upload staging budget; another pod's reservation shows only as a refused upload";
    authz_policy => Structural, "operator authorization policy";
    container_image => Structural, "operator setting";
    container_mediation => Structural, "operator setting";
    container_network => Structural, "operator setting";
    container_pool => Contention, "bounded container semaphore, as firecracker_pool";
    docker => Contention, "shared client; connection-pool contention";
    trust_gate => Secret, "receipt-reporting configuration and role-separated signing keys; keys never served";
    node_platform => Structural, "the node's platform evidence, the same for every pod";
    guest_report => Structural,
        "which guest the default rootfs is, measured at startup from the operator's artifacts root; served alike to every caller on /v1/health";
    authority => Unclassified,
        "per-pod certificates, budgets charged up the lineage, per-chain external ledgers and a node-wide unreadable-record refusal; mixed scopes, not yet modelled";
    #[cfg(target_os = "linux")]
    decision_epochs => Contention,
        "one node-wide epoch counter; a channel's epoch reveals a count of channels created";
    http_client => Contention, "shared client; connection-pool contention";
    lockdown_tx => SelectorScoped,
        "operator lockdown commands; delivered per watcher by lockdown::reaches (lineage for pod:, own labels for label:); not mechanized";
    lockdowns => SelectorScoped, "the lockdowns in force; read through lockdown::reaches, as lockdown_tx";
    eval_cells => LineageScoped,
        "admitted eval-cell ids; read only at a child's admission, keyed by the parent the caller names (relies on the parent-ownership assumption)";
}

#[test]
fn every_node_state_field_has_a_cross_pod_class() {
    let entries = census();

    let mut names: Vec<&str> = entries.iter().map(|e| e.field).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), entries.len(), "a field is classified twice");
    for e in &entries {
        assert!(!e.why.is_empty(), "{} has no stated reason", e.field);
    }

    let count = |s: Surface| entries.iter().filter(|e| e.surface == s).count();
    // The cfg-gated fields are all `Structural` or `Contention`, so only those
    // two counts move with the build.
    let local = if cfg!(feature = "local-driver") { 3 } else { 0 };
    let linux = usize::from(cfg!(target_os = "linux"));
    // Pinned in both directions: a reclassification is an edit here, in the
    // open. `Unclassified` may only shrink.
    assert_eq!(count(Surface::Structural), 33 + local);
    assert_eq!(count(Surface::Secret), 4);
    assert_eq!(count(Surface::PerPod), 1);
    assert_eq!(count(Surface::LineageScoped), 2);
    assert_eq!(count(Surface::SelectorScoped), 2);
    assert_eq!(count(Surface::TenantShared), 1);
    assert_eq!(count(Surface::Contention), 8 + linux);
    assert_eq!(count(Surface::Unclassified), 2);
    assert_eq!(entries.len(), 53 + local + linux);
}

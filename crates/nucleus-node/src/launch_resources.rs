//! Everything a Firecracker launch holds before the pod is registered, owned by one linear handle
//! (#2579).
//!
//! # The defect this replaces
//!
//! The launch path used to keep its resources in loose locals — an `Option<NetPlan>`, an
//! `Option<String>` netns name, an `Option<DnsProxyState>`, the jail layout, the VMM `Child`, the
//! cgroup placement, the vsock bridge and the signed proxy — and release them by calling
//! `cleanup_net_resources` at each failure site. Its comment said every post-spawn failure
//! funnelled through it. Seven `?` sites did not (two log opens, the seccomp flags, the vsock
//! bridge, the signed proxy, and the two netns-name checks, which released the jail and nothing
//! else): each orphaned the allocator index (a `NetworkLease` has no `Drop`, so a dropped plan
//! never recycles it), the host veth and host-namespace iptables rules, the dnsmasq child (spawned
//! without `kill_on_drop`) and the jail directory. A `NetnsGuard` reaped only the namespace.
//! Before that guard, a host with zero live Firecracker processes was found holding the
//! namespaces of exactly the two pods whose guests had kernel-panicked.
//!
//! Enumerating failure sites is what failed, so this does not enumerate them.
//!
//! # The rule
//!
//! - Every resource is moved into [`LaunchResources`] the moment it exists (`hold_*`).
//! - The launch body runs inside [`LaunchResources::run`], which is the ONE place a launch ends:
//!   `Ok` commits (the parts move into the registered pod, by value — ADR 0007 C-4) and `Err`
//!   awaits [`LaunchResources::abort`], which releases everything held, in reverse dependency
//!   order. A `?` anywhere in the body reaches `abort`; there is no other exit to forget (D: the
//!   order is a type, not source-line adjacency).
//! - `Drop` cannot await. A handle dropped while it still holds something is a bug: under
//!   `cfg(test)` it panics, so the fault-injection matrix catches a bypass; otherwise it logs an
//!   error and releases in the background (or synchronously, best-effort, with no runtime).
//!
//! `#[must_use]` sits on this type and nowhere near it: it is the one-shot handle, and the
//! witnesses it hands out (`&NetPlan`, `&mut Child`) are borrows, not affine claims.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use tokio::process::Child;
use tokio::sync::OwnedSemaphorePermit;

use crate::{ApiError, cgroup, firecracker_config, net, signed_proxy, vsock_bridge};

/// How a held network is released. The host's implementation runs `ip`/`iptables` and confirms
/// absence before recycling the allocator index (`net/cleanup.rs`); the tests' confirms against a
/// fixture, so the matrix runs unprivileged.
#[tonic::async_trait]
pub(crate) trait NetRelease: Send + Sync {
    /// Release a whole allocation: host rules, host veth, namespace, then the index.
    async fn network(&self, plan: &mut net::NetPlan) -> Result<(), ApiError>;
    /// Release a namespace that never got an allocation.
    async fn namespace(&self, name: &str) -> Result<(), ApiError>;
}

/// The node's own network release.
pub(crate) struct HostNet;

#[tonic::async_trait]
impl NetRelease for HostNet {
    async fn network(&self, plan: &mut net::NetPlan) -> Result<(), ApiError> {
        net::cleanup_network(plan).await
    }
    async fn namespace(&self, name: &str) -> Result<(), ApiError> {
        net::cleanup_netns(name).await
    }
}

/// What a launch holds, until it either becomes a registered pod or is released.
#[must_use = "a launch's resources are released by `run`/`abort`, or handed on by commit"]
pub(crate) struct LaunchResources {
    net_release: &'static dyn NetRelease,
    /// Set on the copy a dropped handle hands to the runtime. If that copy is itself dropped
    /// unrun (the runtime is shutting down), it releases synchronously instead of spawning again.
    background: bool,
    /// The node's launch slot. Released LAST: capacity returns only after the VMM has exited.
    permit: Option<OwnedSemaphorePermit>,
    /// A namespace with no allocation yet. Once a plan is held the plan owns the namespace.
    netns: Option<String>,
    net_plan: Option<net::NetPlan>,
    dns: Option<net::DnsProxyState>,
    jail: Option<firecracker_config::JailLayout>,
    vmm: Option<Child>,
    cgroup: Option<cgroup::Placement>,
    bridge: Option<vsock_bridge::VsockBridge>,
    proxy: Option<signed_proxy::SignedProxy>,
}

/// What a committed launch hands the registered pod. Every field is named where it is taken
/// apart, so a resource added here cannot be silently dropped on the success path (E-1).
pub(crate) struct Committed {
    pub permit: Option<OwnedSemaphorePermit>,
    pub netns: Option<String>,
    pub net_plan: Option<net::NetPlan>,
    pub dns: Option<net::DnsProxyState>,
    pub jail: Option<firecracker_config::JailLayout>,
    pub vmm: Child,
    pub cgroup: Option<cgroup::Placement>,
    pub bridge: Option<vsock_bridge::VsockBridge>,
    pub proxy: Option<signed_proxy::SignedProxy>,
}

impl LaunchResources {
    pub(crate) fn new(
        permit: Option<OwnedSemaphorePermit>,
        net_release: &'static dyn NetRelease,
    ) -> Self {
        Self {
            net_release,
            background: false,
            permit,
            netns: None,
            net_plan: None,
            dns: None,
            jail: None,
            vmm: None,
            cgroup: None,
            bridge: None,
            proxy: None,
        }
    }

    /// Run a launch body. The only exit: `Ok` commits, `Err` releases everything held.
    ///
    /// A body that returns `Ok` without having spawned a VMM is a launch that registered nothing
    /// running; it is released and refused rather than committed.
    pub(crate) async fn run<T>(
        mut self,
        body: impl AsyncFnOnce(&mut Self) -> Result<T, ApiError>,
    ) -> Result<(T, Committed), ApiError> {
        match body(&mut self).await {
            Ok(value) => match self.vmm.take() {
                Some(vmm) => Ok((value, self.commit(vmm))),
                None => {
                    self.abort().await;
                    Err(ApiError::Driver(
                        "launch completed without a running VMM".to_string(),
                    ))
                }
            },
            Err(err) => {
                self.abort().await;
                Err(err)
            }
        }
    }

    fn commit(mut self, vmm: Child) -> Committed {
        Committed {
            permit: self.permit.take(),
            netns: self.netns.take(),
            net_plan: self.net_plan.take(),
            dns: self.dns.take(),
            jail: self.jail.take(),
            vmm,
            cgroup: self.cgroup.take(),
            bridge: self.bridge.take(),
            proxy: self.proxy.take(),
        }
    }

    pub(crate) fn hold_netns(&mut self, name: String) {
        self.netns = Some(name);
    }
    /// Held, then lent back: the launch still configures the plan it now owns.
    pub(crate) fn hold_network(&mut self, plan: net::NetPlan) -> &mut net::NetPlan {
        self.net_plan.insert(plan)
    }
    pub(crate) fn hold_dns(&mut self, dns: net::DnsProxyState) {
        self.dns = Some(dns);
    }
    pub(crate) fn hold_jail(&mut self, jail: firecracker_config::JailLayout) {
        self.jail = Some(jail);
    }
    pub(crate) fn hold_vmm(&mut self, vmm: Child) {
        self.vmm = Some(vmm);
    }
    pub(crate) fn hold_cgroup(&mut self, placement: cgroup::Placement) {
        self.cgroup = Some(placement);
    }
    pub(crate) fn hold_bridge(&mut self, bridge: vsock_bridge::VsockBridge) {
        self.bridge = Some(bridge);
    }
    pub(crate) fn hold_proxy(&mut self, proxy: signed_proxy::SignedProxy) {
        self.proxy = Some(proxy);
    }

    pub(crate) fn net_plan(&self) -> Option<&net::NetPlan> {
        self.net_plan.as_ref()
    }
    pub(crate) fn dns(&self) -> Option<&net::DnsProxyState> {
        self.dns.as_ref()
    }
    pub(crate) fn vmm_mut(&mut self) -> Result<&mut Child, ApiError> {
        self.vmm
            .as_mut()
            .ok_or_else(|| ApiError::Driver("no VMM has been spawned yet".to_string()))
    }

    fn holds_anything(&self) -> bool {
        let Self {
            net_release: _,
            background: _,
            permit,
            netns,
            net_plan,
            dns,
            jail,
            vmm,
            cgroup,
            bridge,
            proxy,
        } = self;
        permit.is_some()
            || netns.is_some()
            || net_plan.is_some()
            || dns.is_some()
            || jail.is_some()
            || vmm.is_some()
            || cgroup.is_some()
            || bridge.is_some()
            || proxy.is_some()
    }

    /// Release everything held, awaiting each step. The VMM is stopped and reaped first: nothing
    /// is removed out from under a live Firecracker. The launch slot goes last.
    ///
    /// Every field is destructured (E-1): a resource added to the handle does not compile until
    /// this says how it is released.
    pub(crate) async fn abort(mut self) {
        let Self {
            net_release,
            background: _,
            permit,
            netns,
            net_plan,
            dns,
            jail,
            vmm,
            cgroup,
            bridge,
            proxy,
        } = &mut self;
        let net_release = *net_release;
        if let Some(mut vmm) = vmm.take()
            && let Err(error) = vmm.kill().await
        {
            // `kill` fails on a process that has already exited; reap it either way.
            if !matches!(vmm.try_wait(), Ok(Some(_))) {
                tracing::error!(%error, "failed launch could not stop its VMM");
            }
        }
        if let Some(proxy) = proxy.take() {
            proxy.shutdown().await;
        }
        if let Some(bridge) = bridge.take() {
            bridge.shutdown().await;
        }
        if let Some(mut dns) = dns.take()
            && let Err(error) = dns.child.kill().await
            && !matches!(dns.child.try_wait(), Ok(Some(_)))
        {
            tracing::error!(%error, "failed launch could not stop its DNS proxy");
        }
        // The plan's cleanup removes its namespace too; a lone namespace is removed by name.
        let namespace = netns.take();
        if let Some(mut plan) = net_plan.take() {
            if let Err(error) = net_release.network(&mut plan).await {
                // The index is never recycled without a confirmed-absent inventory.
                tracing::error!(%error, "failed launch retains its network allocation");
            }
        } else if let Some(name) = namespace
            && let Err(error) = net_release.namespace(&name).await
        {
            tracing::error!(%error, netns = %name, "failed launch could not remove its namespace");
        }
        if let Some(mut placement) = cgroup.take()
            && let Err(error) = placement.cleanup().await
        {
            // `Placement`'s own drop retries the leaf in the background.
            tracing::error!(%error, "failed launch could not remove its cgroup leaf");
        }
        if let Some(layout) = jail.take() {
            firecracker_config::cleanup_jail(&layout);
        }
        permit.take();
    }

    /// The release a dropped, unconsumed handle still owes: on the runtime when there is one,
    /// otherwise synchronously and best-effort.
    fn release_in_background(&mut self) {
        let mut owed = Self {
            net_release: self.net_release,
            background: true,
            permit: self.permit.take(),
            netns: self.netns.take(),
            net_plan: self.net_plan.take(),
            dns: self.dns.take(),
            jail: self.jail.take(),
            vmm: self.vmm.take(),
            cgroup: self.cgroup.take(),
            bridge: self.bridge.take(),
            proxy: self.proxy.take(),
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(owed.abort());
            }
            Err(_) => owed.release_without_runtime(),
        }
    }

    /// Synchronous and best-effort: the kill-on-drop children are signalled, the namespace is
    /// deleted by name, the jail directory removed; the rest release through their own `Drop`.
    /// A network index is not recycled: that needs the confirmed-absent inventory.
    fn release_without_runtime(&mut self) {
        let Self {
            net_release: _,
            background: _,
            permit,
            netns,
            net_plan,
            dns,
            jail,
            vmm,
            cgroup,
            bridge,
            proxy,
        } = self;
        vmm.take();
        dns.take();
        let lone = netns.take();
        let name = net_plan.take().map(|plan| plan.netns.clone()).or(lone);
        #[cfg(target_os = "linux")]
        if let Some(name) = name {
            let _ = std::process::Command::new("ip")
                .args(["netns", "del", &name])
                .status();
        }
        #[cfg(not(target_os = "linux"))]
        drop(name);
        if let Some(layout) = jail.take() {
            firecracker_config::cleanup_jail(&layout);
        }
        cgroup.take();
        bridge.take();
        proxy.take();
        permit.take();
    }
}

impl Drop for LaunchResources {
    fn drop(&mut self) {
        if !self.holds_anything() {
            return;
        }
        if self.background {
            self.release_without_runtime();
            return;
        }
        if cfg!(test) && !std::thread::panicking() {
            // Release first so a panicking test does not leak the host resources it made.
            self.release_in_background();
            panic!("LaunchResources dropped while holding resources: route the exit through run");
        }
        tracing::error!(
            "a pod launch ended without releasing its resources; releasing in the background"
        );
        self.release_in_background();
    }
}

#[cfg(test)]
#[path = "launch_resources_tests.rs"]
mod tests;

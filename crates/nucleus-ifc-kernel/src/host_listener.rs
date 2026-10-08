//! The **closed inventory of host-side listeners a pod can reach**.
//!
//! # Why this exists
//!
//! A pod's guest can reach a handful of services the HOST runs for it: the
//! workload API, the standard SPIFFE Workload API, the credential broker and the
//! decision channel over vsock; the per-pod DNS forwarder on the namespace
//! gateway; and whatever the pod's network allowlist admits. Until this module
//! the ports were constants spread over four crates, and two of them disagreed
//! without anything noticing: the node's `--broker-vsock-port` defaulted to
//! `15013`, the SPIFFE Workload API's port, while the "documented" broker
//! constant said `1027` and was dead code. Both listeners bound
//! `vsock.sock_15013`; the broker, started second, unlinked the SPIFFE socket and
//! took the path, so on every broker-enabled pod the standard Workload API was
//! unreachable and nothing said so.
//!
//! [`HostListener`] is the one source of truth (ADR 0007 G-1). Every port is a
//! `match` arm here; the node binds a vsock listener only through a helper that
//! takes a [`VsockListener`], so a listener that is not a variant cannot be
//! bound, and two variants cannot share a port (`every_vsock_listener_has_its_own_port`).
//! The documented table in `docs/architecture/host-listeners.md` must equal the
//! enum (`documented_inventory_equals_the_enum`), the same categorical gate
//! [`crate::EgressChannel`] has for `mediated-set.md`.
//!
//! Each listener also carries what the WORKLOAD (the agent's uid, not the
//! mediating proxy) should get when it connects — [`WorkloadReach`]. The
//! in-guest adversary probe connects to every listener and holds the guest to
//! that column.

use crate::EgressChannel;

/// A host listener the guest reaches over vsock (guest-initiated, so the host
/// listens on Firecracker's `{uds_path}_{port}`).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VsockListener {
    /// The JSON workload API: SVIDs, the task token, the per-pod material,
    /// each served once to guest-init (`nucleus-node::workload_api_vsock`).
    WorkloadApi = 0,
    /// The standard SPIFFE Workload API (gRPC), beside the JSON one on its own
    /// port because nothing lets a server tell the two wire formats apart.
    SpiffeWorkloadApi = 1,
    /// The credential broker: the host performs credentialed egress for the
    /// mediating proxy (`nucleus-node::broker_transport`).
    CredentialBroker = 2,
    /// The per-pod decision channel (`nucleus-decision-protocol`, #2702).
    DecisionChannel = 3,
}

impl VsockListener {
    /// Every vsock listener, in discriminant order.
    pub const ALL: &'static [VsockListener] = &[
        VsockListener::WorkloadApi,
        VsockListener::SpiffeWorkloadApi,
        VsockListener::CredentialBroker,
        VsockListener::DecisionChannel,
    ];

    /// The vsock port the guest dials. The ONLY place these numbers are
    /// written; every other crate derives its constant from here.
    pub const fn port(self) -> u32 {
        match self {
            VsockListener::WorkloadApi => 15012,
            VsockListener::SpiffeWorkloadApi => 15013,
            VsockListener::CredentialBroker => 1027,
            VsockListener::DecisionChannel => 1028,
        }
    }
}

/// What the workload's uid should get when it connects to a listener.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WorkloadReach {
    /// The workload must not be able to connect at all. Today the fence is the
    /// workload's seccomp filter, which denies `AF_VSOCK`; guest root and the
    /// mediating proxy can still connect, and the host tells them apart by the
    /// once-served material, not by the connection.
    Refused = 0,
    /// The workload may connect, and the listener answers only what the pod's
    /// policy names (DNS answers only allowlisted names; the allowlist admits
    /// only its own address/port pairs). Anything outside must be refused.
    Filtered = 1,
}

impl WorkloadReach {
    /// The token in the doc table's `Workload` column.
    pub const fn doc_token(self) -> &'static str {
        match self {
            WorkloadReach::Refused => "refused",
            WorkloadReach::Filtered => "filtered",
        }
    }
}

/// How the guest reaches a listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// Guest-initiated vsock to the host CID on this port.
    Vsock {
        /// The port.
        port: u32,
    },
    /// UDP and TCP on the pod namespace's gateway address, on this port.
    Gateway {
        /// The port.
        port: u16,
    },
    /// The address/port pairs the pod's `network.allow` names — no fixed port.
    Allowlist,
}

/// One host-side service a pod's guest can reach. Closed on purpose: adding a
/// listener means adding a variant here, a row in `host-listeners.md`, and — for
/// vsock — binding it through the node's `VsockListener`-typed helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostListener {
    /// A vsock listener.
    Vsock(VsockListener),
    /// The per-pod `dnsmasq` on the namespace gateway, started only when the
    /// pod names a DNS allowlist. `no-resolv`, no upstream.
    PodDns,
    /// Whatever the pod's egress allowlist admits.
    AllowlistedEgress,
}

impl HostListener {
    /// Every host listener: the vsock ones in [`VsockListener::ALL`] order, then
    /// the network ones.
    pub const ALL: &'static [HostListener] = &[
        HostListener::Vsock(VsockListener::WorkloadApi),
        HostListener::Vsock(VsockListener::SpiffeWorkloadApi),
        HostListener::Vsock(VsockListener::CredentialBroker),
        HostListener::Vsock(VsockListener::DecisionChannel),
        HostListener::PodDns,
        HostListener::AllowlistedEgress,
    ];

    /// The DNS forwarder's port. Derived, so the node's `dnsmasq` config and the
    /// probe's query cannot disagree.
    pub const POD_DNS_PORT: u16 = 53;

    /// The stable machine key, the `Key` column of the doc table.
    pub const fn doc_key(self) -> &'static str {
        match self {
            HostListener::Vsock(VsockListener::WorkloadApi) => "workload_api",
            HostListener::Vsock(VsockListener::SpiffeWorkloadApi) => "spiffe_workload_api",
            HostListener::Vsock(VsockListener::CredentialBroker) => "credential_broker",
            HostListener::Vsock(VsockListener::DecisionChannel) => "decision_channel",
            HostListener::PodDns => "pod_dns",
            HostListener::AllowlistedEgress => "allowlisted_egress",
        }
    }

    /// How the guest reaches it.
    pub const fn transport(self) -> Transport {
        match self {
            HostListener::Vsock(v) => Transport::Vsock { port: v.port() },
            HostListener::PodDns => Transport::Gateway {
                port: Self::POD_DNS_PORT,
            },
            HostListener::AllowlistedEgress => Transport::Allowlist,
        }
    }

    /// What the workload's uid should get.
    pub const fn workload_reach(self) -> WorkloadReach {
        match self {
            HostListener::Vsock(
                VsockListener::WorkloadApi
                | VsockListener::SpiffeWorkloadApi
                | VsockListener::CredentialBroker
                | VsockListener::DecisionChannel,
            ) => WorkloadReach::Refused,
            HostListener::PodDns | HostListener::AllowlistedEgress => WorkloadReach::Filtered,
        }
    }

    /// The egress channel (`mediated-set.md`) this listener is an instance of.
    pub const fn egress_channel(self) -> EgressChannel {
        match self {
            HostListener::Vsock(
                VsockListener::WorkloadApi
                | VsockListener::SpiffeWorkloadApi
                | VsockListener::CredentialBroker
                | VsockListener::DecisionChannel,
            ) => EgressChannel::VsockTransport,
            HostListener::PodDns => EgressChannel::Dns,
            HostListener::AllowlistedEgress => EgressChannel::NetnsRawSocket,
        }
    }
}

/// The doc table's `Transport` cell: `vsock:15012`, `gateway:53`, `allowlist`.
impl core::fmt::Display for Transport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Transport::Vsock { port } => write!(f, "vsock:{port}"),
            Transport::Gateway { port } => write!(f, "gateway:{port}"),
            Transport::Allowlist => f.write_str("allowlist"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// `ALL` lists every vsock listener once, in discriminant order.
    #[test]
    fn vsock_all_is_dense_and_ordered() {
        for (i, v) in VsockListener::ALL.iter().enumerate() {
            assert_eq!(
                *v as usize, i,
                "VsockListener::ALL[{i}] = {v:?} out of order"
            );
        }
    }

    /// Every vsock listener is in the host inventory exactly once.
    #[test]
    fn every_vsock_listener_is_a_host_listener() {
        for v in VsockListener::ALL {
            let n = HostListener::ALL
                .iter()
                .filter(|h| **h == HostListener::Vsock(*v))
                .count();
            assert_eq!(n, 1, "{v:?} appears {n} times in HostListener::ALL");
        }
    }

    /// **The defect this module exists for.** Two listeners on one port bind one
    /// path, and the second unlinks the first. The broker's old default (15013)
    /// was the SPIFFE Workload API's port.
    #[test]
    fn every_vsock_listener_has_its_own_port() {
        let mut seen = BTreeMap::new();
        for v in VsockListener::ALL {
            if let Some(other) = seen.insert(v.port(), *v) {
                panic!(
                    "{other:?} and {v:?} both listen on vsock port {}: the second bind \
                     unlinks the first's socket and the guest reaches the wrong service",
                    v.port()
                );
            }
        }
    }

    /// Keys are unique — the parity contract needs the key to be an identity.
    #[test]
    fn doc_keys_are_unique() {
        let keys: BTreeSet<&str> = HostListener::ALL.iter().map(|h| h.doc_key()).collect();
        assert_eq!(keys.len(), HostListener::ALL.len(), "duplicate doc_key");
    }

    /// **THE GATE.** The table in `host-listeners.md` equals the enum: the same
    /// keys, and for each key the same transport, workload reach and egress
    /// channel. A new listener needs a variant AND a row; moving a port needs the
    /// enum AND the doc.
    #[test]
    fn documented_inventory_equals_the_enum() {
        let doc = crate::doc_table::read_doc("host-listeners.md");
        let table = crate::doc_table::DocTable::parse(&doc, "HOST-LISTENERS");
        let enum_keys: BTreeSet<&str> = HostListener::ALL.iter().map(|h| h.doc_key()).collect();
        for column in ["Transport", "Workload", "Egress channel"] {
            let documented = table.keyed("Key", column);
            let doc_keys: BTreeSet<&str> = documented.keys().map(String::as_str).collect();
            assert_eq!(
                doc_keys, enum_keys,
                "host-listeners.md keys != HostListener variants (add the row or the variant)"
            );
            for h in HostListener::ALL {
                assert_eq!(
                    documented[h.doc_key()],
                    cell(*h, column),
                    "listener {} documented {column} disagrees with the enum",
                    h.doc_key()
                );
            }
        }
    }

    /// What the enum says belongs in `column` for `h`.
    fn cell(h: HostListener, column: &str) -> String {
        match column {
            "Transport" => h.transport().to_string(),
            "Workload" => h.workload_reach().doc_token().to_string(),
            "Egress channel" => h.egress_channel().doc_key().to_string(),
            other => panic!("no such column {other}"),
        }
    }

    /// The egress channel each listener names is one the C6 inventory holds and
    /// does not call an open hole.
    #[test]
    fn every_listener_maps_to_a_fenced_channel() {
        for h in HostListener::ALL {
            let c = h.egress_channel();
            assert!(EgressChannel::ALL.contains(&c));
            assert_ne!(c.status(), crate::MediationStatus::OpenHole, "{h:?}");
        }
    }
}

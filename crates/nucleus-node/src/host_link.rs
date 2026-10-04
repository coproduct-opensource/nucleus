//! The rules the node installs in the HOST namespace for one pod's veth link, as a value.
//!
//! # The gap this closes (#3134)
//!
//! A pod's egress policy is enforced inside its own network namespace. The host end of its veth
//! link is in the host namespace, and the pod's default route points at it. A packet the pod's
//! chain admits and that is addressed to one of the HOST's own addresses — its LAN or public IP,
//! a docker bridge, another pod's link address — is then delivered to the host's `INPUT` chain,
//! which nucleus never configured. `allow: ["0.0.0.0/0"]` covers every one of those addresses,
//! so a spec author reached every service the host serves on them.
//!
//! [`crate::net::NODE_DENY_FLOOR`] cannot close this from inside the namespace: the node does not
//! know the host's addresses statically, and a list of them would go stale the moment the host
//! gained one. The rules here are scoped by INTERFACE instead, so a new host address is covered
//! the moment it exists:
//!
//! - [`HostRule::DropInput`] — nothing that arrives on the pod's link is delivered to the host.
//! - [`HostRule::DropToHostBeforeNat`] — nothing that arrives on the pod's link addressed to the
//!   host survives `PREROUTING`. Decided in the `raw` table, before `nat`, because a host port
//!   published with DNAT (a container's `-p 8080:80`) is rewritten to a non-local address in
//!   `nat PREROUTING` and then crosses `FORWARD`, never `INPUT`.
//!
//! # What a pod still needs from the host, and why that is nothing over IP
//!
//! Checked rather than assumed, so there is no accept carved out of either drop:
//!
//! - **DNS.** The pod's resolver is either `dnsmasq`, which listens on the gateway address of the
//!   bridge INSIDE the pod's namespace (`net::start_dns_proxy`), or a public resolver reached by
//!   forwarding. Neither is delivered to the host.
//! - **The default gateway.** The namespace routes via the host end of the link, but a routed
//!   packet is forwarded, not delivered: it crosses `FORWARD`, which [`HostRule::ForwardFrom`]
//!   accepts. Only a packet addressed to the host itself reaches `INPUT`.
//! - **The node.** Host and guest talk over vsock, which is not IP and never meets these chains.
//! - **ARP.** Not seen by `iptables` at all, so the link still resolves its neighbour.

use ipnet::IpNet;

/// Where in its chain a rule goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Placement {
    /// Inserted at position 1, ahead of anything the host's own firewall put there. A node-owned
    /// drop that a host `-A INPUT -j ACCEPT` could precede would be a drop in name only.
    Head,
    /// Appended.
    Tail,
}

/// One root-namespace rule for a pod's link. Closed: every variant is matched exhaustively by
/// the argv renderer and by the test model, so a new rule cannot be added to one and not the other.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HostRule {
    /// `raw PREROUTING`: drop a packet from the pod's link whose destination is any address of
    /// the host, decided before NAT can rewrite it.
    DropToHostBeforeNat { iface: String },
    /// `filter INPUT`: drop everything from the pod's link that would be delivered to the host.
    DropInput { iface: String },
    /// `nat POSTROUTING`: rewrite the link subnet to the host's outgoing address.
    Masquerade { source: IpNet },
    /// `filter FORWARD`: forward what the pod sends (its own namespace already filtered it).
    ForwardFrom { iface: String },
    /// `filter FORWARD`: forward replies back to the pod.
    ForwardRepliesTo { iface: String },
}

impl HostRule {
    pub(crate) fn table(&self) -> &'static str {
        match self {
            HostRule::DropToHostBeforeNat { iface: _ } => "raw",
            HostRule::Masquerade { source: _ } => "nat",
            HostRule::DropInput { iface: _ }
            | HostRule::ForwardFrom { iface: _ }
            | HostRule::ForwardRepliesTo { iface: _ } => "filter",
        }
    }

    pub(crate) fn chain(&self) -> &'static str {
        match self {
            HostRule::DropToHostBeforeNat { iface: _ } => "PREROUTING",
            HostRule::DropInput { iface: _ } => "INPUT",
            HostRule::Masquerade { source: _ } => "POSTROUTING",
            HostRule::ForwardFrom { iface: _ } | HostRule::ForwardRepliesTo { iface: _ } => {
                "FORWARD"
            }
        }
    }

    pub(crate) fn placement(&self) -> Placement {
        match self {
            HostRule::DropToHostBeforeNat { iface: _ } | HostRule::DropInput { iface: _ } => {
                Placement::Head
            }
            HostRule::Masquerade { source: _ }
            | HostRule::ForwardFrom { iface: _ }
            | HostRule::ForwardRepliesTo { iface: _ } => Placement::Tail,
        }
    }

    /// The match and target, shared by the add, check and delete forms so they cannot disagree
    /// about which rule they name.
    fn rule_spec(&self) -> Vec<String> {
        let words: Vec<&str> = match self {
            HostRule::DropToHostBeforeNat { iface } => vec![
                "-i",
                iface,
                "-m",
                "addrtype",
                "--dst-type",
                "LOCAL",
                "-j",
                "DROP",
            ],
            HostRule::DropInput { iface } => vec!["-i", iface, "-j", "DROP"],
            HostRule::Masquerade { source } => {
                return ["-s", &source.to_string(), "-j", "MASQUERADE"]
                    .map(String::from)
                    .to_vec();
            }
            HostRule::ForwardFrom { iface } => vec!["-i", iface, "-j", "ACCEPT"],
            HostRule::ForwardRepliesTo { iface } => vec![
                "-o",
                iface,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            ],
        };
        words.into_iter().map(String::from).collect()
    }

    fn argv(&self, op: &str, position: Option<&str>) -> Vec<String> {
        let mut argv: Vec<String> = ["-t", self.table(), op, self.chain()]
            .map(String::from)
            .to_vec();
        argv.extend(position.map(String::from));
        argv.extend(self.rule_spec());
        argv
    }

    /// `iptables` arguments that install the rule.
    pub(crate) fn add_argv(&self) -> Vec<String> {
        match self.placement() {
            Placement::Head => self.argv("-I", Some("1")),
            Placement::Tail => self.argv("-A", None),
        }
    }

    /// `iptables` arguments that succeed only when the rule is already installed.
    pub(crate) fn check_argv(&self) -> Vec<String> {
        self.argv("-C", None)
    }

    /// `iptables` arguments that remove the rule.
    pub(crate) fn delete_argv(&self) -> Vec<String> {
        self.argv("-D", None)
    }
}

/// Every root-namespace rule for one pod's link, in the order the node installs them.
///
/// The drops come first, so there is no moment in setup when the link's accepts are installed
/// and its drops are not. `cleanup_network` removes exactly this list, so teardown cannot forget
/// a rule setup added.
pub(crate) fn host_link_rules(host_veth: &str, link_subnet: IpNet) -> Vec<HostRule> {
    let iface = host_veth.to_string();
    vec![
        HostRule::DropToHostBeforeNat {
            iface: iface.clone(),
        },
        HostRule::DropInput {
            iface: iface.clone(),
        },
        HostRule::Masquerade {
            source: link_subnet,
        },
        HostRule::ForwardFrom {
            iface: iface.clone(),
        },
        HostRule::ForwardRepliesTo { iface },
    ]
}

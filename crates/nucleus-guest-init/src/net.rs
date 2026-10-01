//! The guest's network, configured over rtnetlink rather than by running `ip`.
//!
//! # Why not `ip`
//!
//! `configure_network` used to shell out to `ip link set eth0 up`, `ip addr add`
//! and `ip route add default via`. The rootfs this repository builds is Debian
//! slim, which ships no `iproute2`, so on every pod the first line it printed was
//! `ip not found; skipping network config` and the guest booted with `eth0` down
//! and unaddressed. A pod with a `network.allow` list had the host side of its
//! allowlist built correctly and a guest that could reach none of it.
//!
//! And the guest's correctness depended on what the *image* happened to contain,
//! which is the one thing an arbitrary workload image cannot be trusted to
//! provide. The three requests are sent here, from PID 1, on a netlink socket:
//! nothing from the image is executed.
//!
//! # Crates, and why the messages are encoded here
//!
//! `netlink-sys` (MIT, pure Rust, `rust-netlink`, already in the lockfile) is
//! the blocking socket. `rtnetlink`, the async wrapper, was not used: it needs
//! an executor, and PID 1 here is deliberately synchronous.
//!
//! The three requests themselves were first built with `netlink-packet-route`,
//! and PID 1 went from 616 KB to 1.97 MB — its emit and parse code covers every
//! attribute of every rtnetlink message, reachable through one runtime `match`
//! and so never dropped by the linker. Three fixed-shape messages do not justify
//! that, so they are written here, field by field, and the golden-byte tests
//! below pin every byte against the layout in `<linux/rtnetlink.h>` (and were
//! first cross-checked against the crate's own encoding of the same requests).
//!
//! The builders are split from the socket so the exact bytes are testable on any
//! host; only [`configure`] needs Linux.

use std::net::Ipv4Addr;

// <linux/netlink.h> and <linux/rtnetlink.h>.
const NLMSG_HDRLEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const RTM_SETLINK: u16 = 19;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWROUTE: u16 = 24;
const AF_INET: u8 = 2;
const IFF_UP: u32 = 0x1;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const RTA_GATEWAY: u16 = 5;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RTN_UNICAST: u8 = 1;

/// The one interface Firecracker gives the guest.
pub const GUEST_IFACE: &str = "eth0";

/// The network the node hands this guest on the kernel command line
/// (`nucleus.net=<addr>/<prefix>,gw=<gw>,dns=<dns>`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetConfig {
    /// The guest's own address.
    pub addr: Ipv4Addr,
    /// Its prefix length, 0..=32.
    pub prefix: u8,
    /// Default gateway, when the node gave one.
    pub gw: Option<Ipv4Addr>,
    /// Resolver, when the node gave one.
    pub dns: Option<Ipv4Addr>,
}

impl NetConfig {
    /// `<addr>/<prefix>`, as the boot report has always printed it.
    #[must_use]
    pub fn cidr(&self) -> String {
        format!("{}/{}", self.addr, self.prefix)
    }
}

/// Find `nucleus.net=` on a kernel command line and parse it.
///
/// `None` when absent — a pod with no network policy gets no network plan and
/// no argument — or when the address part is malformed. `gw=` / `dns=` values
/// that do not parse are dropped individually, as before.
#[must_use]
pub fn parse_cmdline(cmdline: &str) -> Option<NetConfig> {
    cmdline
        .split_whitespace()
        .find_map(|t| t.strip_prefix("nucleus.net="))
        .and_then(parse_value)
}

/// Parse the value of `nucleus.net=`.
#[must_use]
pub fn parse_value(value: &str) -> Option<NetConfig> {
    let mut parts = value.split(',');
    let (ip, prefix) = parts.next()?.trim().split_once('/')?;
    let addr = ip.parse::<Ipv4Addr>().ok()?;
    let prefix = prefix.parse::<u8>().ok().filter(|p| *p <= 32)?;
    let mut gw = None;
    let mut dns = None;
    for part in parts {
        if let Some(val) = part.strip_prefix("gw=") {
            gw = val.parse::<Ipv4Addr>().ok();
        } else if let Some(val) = part.strip_prefix("dns=") {
            dns = val.parse::<Ipv4Addr>().ok();
        }
    }
    Some(NetConfig {
        addr,
        prefix,
        gw,
        dns,
    })
}

/// The `/etc/resolv.conf` body for `dns`.
#[must_use]
pub fn resolv_conf(dns: Ipv4Addr) -> String {
    format!("nameserver {dns}\n")
}

/// One request: `nlmsghdr` (pid 0: addressed to the kernel) then `body`.
/// Every body here is a multiple of 4 bytes, so no padding is needed.
fn request(kind: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(NLMSG_HDRLEN + body.len()).unwrap_or(u32::MAX);
    let mut m = Vec::with_capacity(NLMSG_HDRLEN + body.len());
    m.extend_from_slice(&len.to_ne_bytes());
    m.extend_from_slice(&kind.to_ne_bytes());
    m.extend_from_slice(&flags.to_ne_bytes());
    m.extend_from_slice(&seq.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes());
    m.extend_from_slice(body);
    m
}

/// An `rtattr` carrying an IPv4 address: 4-byte header, 4-byte payload.
fn ipv4_attr(buf: &mut Vec<u8>, kind: u16, addr: Ipv4Addr) {
    buf.extend_from_slice(&8u16.to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(&addr.octets());
}

/// `ip link set <ifindex> up`, as RTM_SETLINK with IFF_UP in both flags and
/// mask. `ip` sends RTM_NEWLINK; SETLINK is the same change through the request
/// that can only modify an existing link and never create one.
#[must_use]
pub fn link_up(ifindex: u32, seq: u32) -> Vec<u8> {
    // struct ifinfomsg: family, pad, type, index, flags, change.
    let mut body = vec![0u8, 0u8];
    body.extend_from_slice(&0u16.to_ne_bytes());
    body.extend_from_slice(&ifindex.to_ne_bytes());
    body.extend_from_slice(&IFF_UP.to_ne_bytes());
    body.extend_from_slice(&IFF_UP.to_ne_bytes());
    request(RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK, seq, &body)
}

/// `ip addr add <addr>/<prefix> dev <ifindex>`: RTM_NEWADDR carrying both
/// IFA_LOCAL and IFA_ADDRESS, as `ip` sends for a non-point-to-point link.
#[must_use]
pub fn add_address(ifindex: u32, addr: Ipv4Addr, prefix: u8, seq: u32) -> Vec<u8> {
    // struct ifaddrmsg: family, prefixlen, flags, scope, index.
    let mut body = vec![AF_INET, prefix, 0, 0];
    body.extend_from_slice(&ifindex.to_ne_bytes());
    ipv4_attr(&mut body, IFA_LOCAL, addr);
    ipv4_attr(&mut body, IFA_ADDRESS, addr);
    request(
        RTM_NEWADDR,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        seq,
        &body,
    )
}

/// `ip route add default via <gw>`: RTM_NEWROUTE in the main table, protocol
/// `boot` and universe scope — the three values `ip` itself fills in.
#[must_use]
pub fn default_route(gw: Ipv4Addr, seq: u32) -> Vec<u8> {
    // struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope,
    // type, flags.
    let mut body = vec![
        AF_INET,
        0,
        0,
        0,
        RT_TABLE_MAIN,
        RTPROT_BOOT,
        RT_SCOPE_UNIVERSE,
        RTN_UNICAST,
    ];
    body.extend_from_slice(&0u32.to_ne_bytes());
    ipv4_attr(&mut body, RTA_GATEWAY, gw);
    request(
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        seq,
        &body,
    )
}

/// Which step of the configuration failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetStep {
    /// Looking up the interface index.
    Ifindex,
    /// Opening the netlink socket.
    Socket,
    /// Bringing the link up.
    LinkUp,
    /// Assigning the address.
    Address,
    /// Installing the default route.
    Route,
}

/// A step and why it failed.
#[derive(Debug)]
pub struct NetError {
    /// The step.
    pub step: NetStep,
    /// The kernel's (or the socket's) answer.
    pub source: std::io::Error,
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "network {:?} failed: {}", self.step, self.source)
    }
}

impl std::error::Error for NetError {}

/// What a kernel answer to one request means.
#[derive(Debug, PartialEq, Eq)]
pub enum Ack {
    /// NLMSG_ERROR with code 0.
    Done,
    /// NLMSG_ERROR with -EEXIST. The address or route is already there — a
    /// restored snapshot, or a second call — which is what was asked for.
    AlreadyThere,
    /// Any other error code, as a positive errno.
    Refused(i32),
    /// Not an acknowledgement at all.
    Unexpected,
}

/// Classify the kernel's reply to one request: an `nlmsghdr` of type
/// NLMSG_ERROR whose first payload word is the negated errno, 0 for success.
#[must_use]
pub fn classify_reply(reply: &[u8]) -> Ack {
    let word = |at: usize| -> Option<[u8; 4]> { reply.get(at..at + 4)?.try_into().ok() };
    let (Some(len), Some(kind), Some(code)) = (
        word(0).map(u32::from_ne_bytes),
        reply
            .get(4..6)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes),
        word(NLMSG_HDRLEN).map(i32::from_ne_bytes),
    ) else {
        return Ack::Unexpected;
    };
    if kind != NLMSG_ERROR || usize::try_from(len).map_or(true, |l| l > reply.len()) {
        return Ack::Unexpected;
    }
    match code {
        0 => Ack::Done,
        c if c == -EEXIST => Ack::AlreadyThere,
        c if c < 0 => Ack::Refused(-c),
        _ => Ack::Unexpected,
    }
}

/// Linux's EEXIST. Spelled out rather than taken from `libc` so the classifier
/// is the same on every host its tests run on.
const EEXIST: i32 = 17;

/// Bring up [`GUEST_IFACE`], address it, and route through the gateway.
///
/// Each step's failure is returned with the step named; the caller decides
/// whether a guest without a network is a boot failure (today it is not — a
/// pod still has vsock — so it is logged, loudly, rather than swallowed as the
/// `let _ = Command::new("ip")` calls did).
///
/// # Errors
/// The first step the kernel refused.
#[cfg(target_os = "linux")]
pub fn configure(cfg: &NetConfig) -> Result<(), NetError> {
    use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};

    let ifindex = nix::net::if_::if_nametoindex(GUEST_IFACE).map_err(|e| NetError {
        step: NetStep::Ifindex,
        source: e.into(),
    })?;
    let socket = Socket::new(NETLINK_ROUTE)
        .and_then(|mut s| s.bind_auto().map(|_| s))
        .map_err(|source| NetError {
            step: NetStep::Socket,
            source,
        })?;
    let kernel = SocketAddr::new(0, 0);

    let mut steps = vec![
        (NetStep::LinkUp, link_up(ifindex, 1)),
        (
            NetStep::Address,
            add_address(ifindex, cfg.addr, cfg.prefix, 2),
        ),
    ];
    if let Some(gw) = cfg.gw {
        steps.push((NetStep::Route, default_route(gw, 3)));
    }
    for (step, msg) in steps {
        let fail = |source| NetError { step, source };
        socket.send_to(&msg, &kernel, 0).map_err(fail)?;
        let mut reply = vec![0u8; 8192];
        let n = socket.recv(&mut &mut reply[..], 0).map_err(fail)?;
        match classify_reply(&reply[..n]) {
            Ack::Done | Ack::AlreadyThere => {}
            Ack::Refused(errno) => {
                return Err(NetError {
                    step,
                    source: std::io::Error::from_raw_os_error(errno),
                });
            }
            Ack::Unexpected => {
                return Err(NetError {
                    step,
                    source: std::io::Error::other("the kernel's reply was not an acknowledgement"),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_node_argument_parses() {
        let cfg = parse_cmdline(
            "console=ttyS0 nucleus.net=10.0.0.2/24,gw=10.0.0.1,dns=10.0.0.1 ipv6.disable=1",
        )
        .unwrap();
        assert_eq!(cfg.addr, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(cfg.prefix, 24);
        assert_eq!(cfg.gw, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(cfg.dns, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(cfg.cidr(), "10.0.0.2/24");
    }

    #[test]
    fn no_argument_means_no_network() {
        assert_eq!(parse_cmdline("console=ttyS0 init=/init"), None);
    }

    #[test]
    fn a_malformed_address_is_no_network_not_a_guess() {
        for bad in ["10.0.0.2", "10.0.0.2/33", "nope/24", "10.0.0.2/x"] {
            assert_eq!(parse_value(bad), None, "{bad}");
        }
        // A bad gateway is dropped on its own; the address still stands.
        let cfg = parse_value("10.0.0.2/24,gw=nope").unwrap();
        assert_eq!(cfg.gw, None);
    }

    /// Golden bytes: `ip link set eth0 up` for ifindex 2, as the kernel expects
    /// it. nlmsghdr (len 32, RTM_SETLINK=19, REQUEST|ACK, seq 1, pid 0) then
    /// ifinfomsg (family 0, type 0, index 2, flags IFF_UP, change IFF_UP).
    #[test]
    fn link_up_bytes() {
        let bytes = link_up(2, 1);
        let mut want = Vec::new();
        want.extend_from_slice(&32u32.to_ne_bytes());
        want.extend_from_slice(&19u16.to_ne_bytes());
        want.extend_from_slice(&(1u16 | 4).to_ne_bytes());
        want.extend_from_slice(&1u32.to_ne_bytes());
        want.extend_from_slice(&0u32.to_ne_bytes());
        want.extend_from_slice(&[0, 0]); // family, pad
        want.extend_from_slice(&0u16.to_ne_bytes()); // ifi_type
        want.extend_from_slice(&2i32.to_ne_bytes()); // index
        want.extend_from_slice(&1u32.to_ne_bytes()); // flags: IFF_UP
        want.extend_from_slice(&1u32.to_ne_bytes()); // change: IFF_UP
        assert_eq!(bytes, want);
    }

    /// Golden bytes: `ip addr add 10.0.0.2/24 dev <2>`. ifaddrmsg then
    /// IFA_LOCAL (2) and IFA_ADDRESS (1), each a 4-byte address in a 8-byte rta.
    #[test]
    fn add_address_bytes() {
        let bytes = add_address(2, Ipv4Addr::new(10, 0, 0, 2), 24, 2);
        let mut want = Vec::new();
        want.extend_from_slice(&40u32.to_ne_bytes());
        want.extend_from_slice(&20u16.to_ne_bytes()); // RTM_NEWADDR
        want.extend_from_slice(&(1u16 | 4 | 0x400 | 0x200).to_ne_bytes());
        want.extend_from_slice(&2u32.to_ne_bytes());
        want.extend_from_slice(&0u32.to_ne_bytes());
        want.extend_from_slice(&[2, 24, 0, 0]); // AF_INET, /24, flags, scope
        want.extend_from_slice(&2u32.to_ne_bytes()); // index
        for kind in [2u16, 1u16] {
            want.extend_from_slice(&8u16.to_ne_bytes());
            want.extend_from_slice(&kind.to_ne_bytes());
            want.extend_from_slice(&[10, 0, 0, 2]);
        }
        assert_eq!(bytes, want);
    }

    /// Golden bytes: `ip route add default via 10.0.0.1`. rtmsg (AF_INET, dst
    /// /0, main table 254, RTPROT_BOOT 3, universe scope 0, RTN_UNICAST 1) then
    /// RTA_GATEWAY (5).
    #[test]
    fn default_route_bytes() {
        let bytes = default_route(Ipv4Addr::new(10, 0, 0, 1), 3);
        let mut want = Vec::new();
        want.extend_from_slice(&36u32.to_ne_bytes());
        want.extend_from_slice(&24u16.to_ne_bytes()); // RTM_NEWROUTE
        want.extend_from_slice(&(1u16 | 4 | 0x400 | 0x200).to_ne_bytes());
        want.extend_from_slice(&3u32.to_ne_bytes());
        want.extend_from_slice(&0u32.to_ne_bytes());
        want.extend_from_slice(&[2, 0, 0, 0, 254, 3, 0, 1]);
        want.extend_from_slice(&0u32.to_ne_bytes()); // rtm_flags
        want.extend_from_slice(&8u16.to_ne_bytes());
        want.extend_from_slice(&5u16.to_ne_bytes());
        want.extend_from_slice(&[10, 0, 0, 1]);
        assert_eq!(bytes, want);
    }

    fn nlmsgerr(code: i32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&36u32.to_ne_bytes());
        b.extend_from_slice(&2u16.to_ne_bytes()); // NLMSG_ERROR
        b.extend_from_slice(&0u16.to_ne_bytes());
        b.extend_from_slice(&1u32.to_ne_bytes());
        b.extend_from_slice(&0u32.to_ne_bytes());
        b.extend_from_slice(&code.to_ne_bytes());
        b.extend_from_slice(&[0u8; 16]); // the echoed request header
        b
    }

    /// A-1: "the kernel said no" is never read as "done".
    #[test]
    fn replies_are_classified_not_assumed() {
        assert_eq!(classify_reply(&nlmsgerr(0)), Ack::Done);
        assert_eq!(classify_reply(&nlmsgerr(-17)), Ack::AlreadyThere);
        assert_eq!(classify_reply(&nlmsgerr(-1)), Ack::Refused(1));
        assert_eq!(classify_reply(&[0u8; 3]), Ack::Unexpected);
    }

    #[test]
    fn resolv_conf_names_the_resolver() {
        assert_eq!(
            resolv_conf(Ipv4Addr::new(10, 0, 0, 1)),
            "nameserver 10.0.0.1\n"
        );
    }
}

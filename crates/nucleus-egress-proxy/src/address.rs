//! Which resolved addresses an upstream may have (ADR 0015 §3).
//!
//! The node decides on the NAME the operator registered. Only the proxy
//! learns which address that name resolves to when it connects, so the
//! address rule is the proxy's, and it is about addresses only, never about
//! which upstream is allowed (ADR 0007 G-1):
//!
//! * [`AddressClass::Forbidden`] is never connected to, whoever named it:
//!   unspecified, link-local (where the cloud metadata service lives),
//!   multicast, broadcast, reserved and documentation ranges, and every
//!   network in the node's deny floor, which the node hands the proxy at
//!   spawn (the node's `NODE_DENY_FLOOR`, written once there).
//! * [`AddressClass::Private`] and [`AddressClass::Loopback`] are connected
//!   to only when the request named that exact address as a literal. The
//!   node allowed the request, so an operator registered that literal; a
//!   NAME that resolves to one is the DNS-rebinding shape and is refused.
//! * [`AddressClass::Public`] is connected to.
//!
//! Every resolved address must be admissible, not just the first: a resolver
//! answer that mixes a public and a metadata address is refused whole, so
//! the order of an answer cannot choose the outcome.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

use crate::Refusal;
use crate::request::Host;

/// What an address is, for an upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressClass {
    /// Globally routable.
    Public,
    /// RFC 1918, carrier-grade NAT, IPv6 unique-local and site-local.
    Private,
    /// The proxy's own host (its own network namespace's loopback).
    Loopback,
    /// Never an upstream.
    Forbidden(Forbidden),
}

/// Why an address is never an upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forbidden {
    /// `0.0.0.0/8`, `::`.
    Unspecified,
    /// `169.254.0.0/16`, `fe80::/10`: the cloud metadata service lives here.
    LinkLocal,
    /// `224.0.0.0/4`, `ff00::/8`.
    Multicast,
    /// `255.255.255.255`.
    Broadcast,
    /// IETF-reserved, benchmarking, documentation and `240.0.0.0/4`.
    Reserved,
    /// A network in the node's deny floor.
    NodeFloor,
}

/// Classify `ip`. The node's `floor` is checked first, so a floor network
/// is forbidden even where it overlaps a private range.
pub fn classify(ip: IpAddr, floor: &[IpNet]) -> AddressClass {
    if floor.iter().any(|net| net.contains(&ip)) {
        return AddressClass::Forbidden(Forbidden::NodeFloor);
    }
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => match embedded_v4(v6) {
            // An IPv4 address carried in IPv6 is that IPv4 address, floor
            // included.
            Some(v4) => classify(IpAddr::V4(v4), floor),
            None => classify_v6(v6),
        },
    }
}

fn classify_v4(ip: Ipv4Addr) -> AddressClass {
    let [a, b, c, _] = ip.octets();
    let forbidden = |why| AddressClass::Forbidden(why);
    if a == 0 {
        forbidden(Forbidden::Unspecified)
    } else if ip.is_loopback() {
        AddressClass::Loopback
    } else if ip.is_link_local() {
        forbidden(Forbidden::LinkLocal)
    } else if ip.is_broadcast() {
        forbidden(Forbidden::Broadcast)
    } else if ip.is_multicast() {
        forbidden(Forbidden::Multicast)
    } else if a >= 240
        || (a == 192 && b == 0 && c == 0)
        || ip.is_documentation()
        || (a == 198 && (b & 0xfe) == 18)
    {
        forbidden(Forbidden::Reserved)
    } else if ip.is_private() || (a == 100 && (b & 0xc0) == 64) {
        AddressClass::Private
    } else {
        AddressClass::Public
    }
}

fn classify_v6(ip: Ipv6Addr) -> AddressClass {
    let first = ip.segments()[0];
    let forbidden = |why| AddressClass::Forbidden(why);
    if ip.is_unspecified() {
        forbidden(Forbidden::Unspecified)
    } else if ip.is_loopback() {
        AddressClass::Loopback
    } else if (first & 0xffc0) == 0xfe80 {
        forbidden(Forbidden::LinkLocal)
    } else if ip.is_multicast() {
        forbidden(Forbidden::Multicast)
    } else if first == 0x2001 && ip.segments()[1] == 0x0db8 {
        forbidden(Forbidden::Reserved)
    } else if (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfec0 {
        AddressClass::Private
    } else {
        AddressClass::Public
    }
}

/// The IPv4 address an IPv6 address carries: v4-mapped (`::ffff:a.b.c.d`),
/// v4-compatible (`::a.b.c.d`, deprecated) and NAT64 (`64:ff9b::/96`).
fn embedded_v4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = ip.segments();
    let tail = Ipv4Addr::new(
        (s[6] >> 8) as u8,
        (s[6] & 0xff) as u8,
        (s[7] >> 8) as u8,
        (s[7] & 0xff) as u8,
    );
    let head = [s[0], s[1], s[2], s[3], s[4], s[5]];
    match head {
        [0, 0, 0, 0, 0, 0xffff] => Some(tail),
        // `::` and `::1` are themselves, not 0.0.0.0 and 0.0.0.1.
        [0, 0, 0, 0, 0, 0] if !ip.is_unspecified() && !ip.is_loopback() => Some(tail),
        [0x64, 0xff9b, 0, 0, 0, 0] => Some(tail),
        _ => None,
    }
}

/// The addresses the proxy may connect to for `host`, given what `host`
/// resolved to (a literal resolves to itself).
///
/// # Errors
/// * [`Refusal::NoAddress`] for an empty answer;
/// * [`Refusal::ForbiddenAddress`] if any address is forbidden;
/// * [`Refusal::PrivateAddress`] if any address is private or loopback and
///   `host` is not that exact literal.
pub fn admit(host: &Host, resolved: &[IpAddr], floor: &[IpNet]) -> Result<Vec<IpAddr>, Refusal> {
    if resolved.is_empty() {
        return Err(Refusal::NoAddress);
    }
    let literal = match host {
        Host::Name(_) => None,
        Host::Ipv4(a) => Some(IpAddr::V4(*a)),
        Host::Ipv6(a) => Some(IpAddr::V6(*a)),
    };
    for ip in resolved {
        match classify(*ip, floor) {
            AddressClass::Public => {}
            AddressClass::Private | AddressClass::Loopback => {
                if literal != Some(*ip) {
                    return Err(Refusal::PrivateAddress);
                }
            }
            AddressClass::Forbidden(_) => return Err(Refusal::ForbiddenAddress),
        }
    }
    Ok(resolved.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn name() -> Host {
        Host::Name("upstream.example".into())
    }

    fn floor() -> Vec<IpNet> {
        vec![
            "169.254.0.0/16".parse().unwrap(),
            "10.200.0.0/24".parse().unwrap(),
        ]
    }

    #[test]
    fn metadata_and_link_local_are_forbidden_however_written() {
        for a in [
            "169.254.169.254",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "fe80::1",
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "255.255.255.255",
            "240.0.0.1",
            "192.0.2.1",
        ] {
            assert!(
                matches!(classify(ip(a), &[]), AddressClass::Forbidden(_)),
                "{a}"
            );
            let literal = match ip(a) {
                IpAddr::V4(v) => Host::Ipv4(v),
                IpAddr::V6(v) => Host::Ipv6(v),
            };
            assert_eq!(
                admit(&literal, &[ip(a)], &[]),
                Err(Refusal::ForbiddenAddress),
                "a literal {a} is refused too"
            );
        }
    }

    #[test]
    fn the_node_floor_is_forbidden_even_inside_a_private_range() {
        let pool = ip("10.200.0.1");
        assert_eq!(
            classify(pool, &floor()),
            AddressClass::Forbidden(Forbidden::NodeFloor)
        );
        let IpAddr::V4(v4) = pool else { unreachable!() };
        assert_eq!(
            admit(&Host::Ipv4(v4), &[pool], &floor()),
            Err(Refusal::ForbiddenAddress)
        );
    }

    /// The DNS-rebinding defence: a name may not resolve to a private or
    /// loopback address; only a literal the operator registered may be one.
    #[test]
    fn a_name_that_resolves_private_is_refused() {
        for a in [
            "10.0.0.5",
            "192.168.1.1",
            "172.16.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "::1",
            "fd00::1",
        ] {
            assert_eq!(
                admit(&name(), &[ip(a)], &floor()),
                Err(Refusal::PrivateAddress),
                "{a}"
            );
        }
        assert_eq!(
            admit(
                &Host::Ipv4(Ipv4Addr::new(10, 0, 0, 5)),
                &[ip("10.0.0.5")],
                &floor()
            ),
            Ok(vec![ip("10.0.0.5")])
        );
    }

    #[test]
    fn one_bad_address_refuses_the_whole_answer() {
        assert_eq!(
            admit(
                &name(),
                &[ip("93.184.215.14"), ip("169.254.169.254")],
                &floor()
            ),
            Err(Refusal::ForbiddenAddress)
        );
        assert_eq!(admit(&name(), &[], &floor()), Err(Refusal::NoAddress));
        assert_eq!(
            admit(
                &name(),
                &[
                    ip("93.184.215.14"),
                    ip("2606:2800:21f:cb07:6820:80da:af6b:8b2c")
                ],
                &floor()
            ),
            Ok(vec![
                ip("93.184.215.14"),
                ip("2606:2800:21f:cb07:6820:80da:af6b:8b2c")
            ])
        );
    }
}

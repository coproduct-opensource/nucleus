//! Egress matching — the slice the **confinement** theorem is proven over after
//! Charon→Aeneas→Lean extraction.
//!
//! # Why this exists
//!
//! Complete mediation on the effect layer bounds what an agent may *ask* for. It
//! does not bound what a shell does once started: one `(RunBash, BashExec)`
//! authority buys arbitrary syscalls inside the guest, and
//! `bash -c 'curl … | sh'` never passes through `NetEffect::fetch`. For shell
//! effects the real enforcement boundary is the network policy, so that is where
//! a proof has to land if "a jailbreak cannot exceed its authority" is to mean
//! anything. The 2026 agent-jailbreak numbers make the point sharper — the
//! defence cannot be *preventing* the jailbreak.
//!
//! # What is extracted here, and what is not
//!
//! Extracted (real code, translated by Aeneas): the **per-packet matchers** —
//! [`in_cidr`] and [`rule_matches`]. These are the parts with arithmetic in
//! them, and they are where an off-by-one silently widens an allowlist.
//!
//! **Not** extracted: the fold over a rule list. Every function in
//! `extracted/` is scalar-only by design — Aeneas emits derived comparisons and
//! most collection operations as opaque axioms, which would put unspecified
//! assumptions on the proof's critical path. The list semantics (first match
//! wins, default DROP) is therefore stated in Lean over `List Rule`, using the
//! extracted matcher as its primitive. That is the same split the verified
//! iptables work uses: a formal semantics over rule lists in the prover, with
//! matchers underneath.
//!
//! The cost of the split is a correspondence obligation: the Lean fold must be
//! the order `nucleus_node::net` actually appends rules in. That is discharged
//! by construction — `net::egress_chain` returns the chain as an ordered VALUE
//! and `apply_host_policy` applies exactly that list in one pass — plus the
//! `deny_precedes_allow_in_the_chain` and `a_specific_deny_beats_a_broader_allow`
//! tests, which fail if the ordering is reversed. What is NOT discharged is that
//! iptables implements those semantics at all.
//!
//! # The ordering that carries the property
//!
//! `net.rs` appends every `Deny` rule before every `Allow` rule, into chains
//! whose policy is `DROP`. Under iptables' first-match-wins semantics that makes
//! deny strictly override allow, and makes an unmatched packet fall through to
//! the `DROP` policy. Both halves matter and both are proven.

/// A packet's destination, reduced to what the filter actually inspects.
///
/// IPv4 only, because `parse_entry` in `nucleus_node::net` yields IPv4 CIDRs and
/// the guest cmdline carries `ipv6.disable=1`. If IPv6 egress is ever enabled
/// this module is incomplete rather than wrong — and `verdict` would need a
/// second address family before any claim here covers it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Dest {
    /// Destination address, big-endian host order (as `u32::from(Ipv4Addr)`).
    pub addr: u32,
    /// Destination port.
    pub port: u16,
}

/// One filter rule, flattened so no field needs a derived comparison.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rule {
    /// Network base address.
    pub net: u32,
    /// Prefix length, 0..=32.
    pub prefix: u8,
    /// When false the rule matches any port and [`Rule::port`] is ignored.
    pub port_specific: bool,
    /// Port matched when [`Rule::port_specific`].
    pub port: u16,
    /// True for `ACCEPT`, false for `DROP`.
    pub allow: bool,
}

/// The netmask for `prefix`, as an explicit table.
///
/// # Why a table and not `u32::MAX << (32 - prefix)`
///
/// The shift formulation needs a subtraction, and in Aeneas's `Result` monad a
/// `u32` subtraction is *fallible* — every theorem downstream would carry an
/// underflow obligation, and [`in_cidr`] would no longer be total by
/// construction. Bitwise `&` and `==` have no failure mode, so with a table the
/// matcher cannot fail at all, which is the property a rule on the critical
/// path should have.
///
/// The table is not trusted by eye: `every_prefix_length_agrees_with_a_mask_formulation`
/// checks all 33 entries against the independent shift formulation.
///
/// A `prefix` above 32 cannot come from `parse_entry`, which rejects it. It maps
/// to the full mask — narrowing, never widening, for a matcher whose `true`
/// grants passage.
pub fn netmask(prefix: u8) -> u32 {
    match prefix {
        0 => 0x00000000,
        1 => 0x80000000,
        2 => 0xC0000000,
        3 => 0xE0000000,
        4 => 0xF0000000,
        5 => 0xF8000000,
        6 => 0xFC000000,
        7 => 0xFE000000,
        8 => 0xFF000000,
        9 => 0xFF800000,
        10 => 0xFFC00000,
        11 => 0xFFE00000,
        12 => 0xFFF00000,
        13 => 0xFFF80000,
        14 => 0xFFFC0000,
        15 => 0xFFFE0000,
        16 => 0xFFFF0000,
        17 => 0xFFFF8000,
        18 => 0xFFFFC000,
        19 => 0xFFFFE000,
        20 => 0xFFFFF000,
        21 => 0xFFFFF800,
        22 => 0xFFFFFC00,
        23 => 0xFFFFFE00,
        24 => 0xFFFFFF00,
        25 => 0xFFFFFF80,
        26 => 0xFFFFFFC0,
        27 => 0xFFFFFFE0,
        28 => 0xFFFFFFF0,
        29 => 0xFFFFFFF8,
        30 => 0xFFFFFFFC,
        31 => 0xFFFFFFFE,
        32 => 0xFFFFFFFF,
        _ => 0xFFFFFFFF,
    }
}

/// Whether `addr` lies in `net/prefix`.
///
/// Total: no arithmetic that can fail, so the extracted Lean definition needs no
/// side conditions. `prefix == 0` matches every address — that is what
/// `0.0.0.0/0` means, and [`the_zero_prefix_matches_everything`] pins it because
/// it is exactly the input that dissolves an allowlist.
pub fn in_cidr(net: u32, prefix: u8, addr: u32) -> bool {
    let m = netmask(prefix);
    (net & m) == (addr & m)
}

/// Whether `rule` matches `dest`, ignoring the rule's verdict.
pub fn rule_matches(rule: Rule, dest: Dest) -> bool {
    if !in_cidr(rule.net, rule.prefix, dest.addr) {
        return false;
    }
    if !rule.port_specific {
        return true;
    }
    rule.port == dest.port
}

/// A rule that grants passage to `dest`: it matches AND its verdict is accept.
///
/// Split out from [`rule_matches`] because the confinement theorem is about
/// *grants*, and folding the verdict into the matcher is the shape that makes an
/// accidental "matches ⇒ passes" reading possible.
pub fn rule_admits(rule: Rule, dest: Dest) -> bool {
    rule_matches(rule, dest) && rule.allow
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> u32 {
        ((a as u32) << 24) | ((b as u32) << 16) | ((c as u32) << 8) | (d as u32)
    }

    fn dest(a: u8, b: u8, c: u8, d: u8, port: u16) -> Dest {
        Dest {
            addr: v4(a, b, c, d),
            port,
        }
    }

    /// `0.0.0.0/0` matches every address. This is not a curiosity: `parse_rules`
    /// in `nucleus_node::net` accepts whatever CIDR a PodSpec supplies, so a
    /// policy of `allow: ["0.0.0.0/0"]` is a nominal network policy that permits
    /// unrestricted egress. Nothing rejects it today.
    #[test]
    fn the_zero_prefix_matches_everything() {
        for addr in [
            v4(0, 0, 0, 0),
            v4(127, 0, 0, 1),
            v4(10, 0, 0, 7),
            v4(255, 255, 255, 255),
            v4(93, 184, 216, 34),
        ] {
            assert!(in_cidr(0, 0, addr), "0.0.0.0/0 must match {addr:#010x}");
        }
    }

    /// /32 is exact.
    #[test]
    fn a_full_prefix_matches_only_itself() {
        let host = v4(10, 0, 0, 7);
        assert!(in_cidr(host, 32, host));
        assert!(!in_cidr(host, 32, v4(10, 0, 0, 8)));
        assert!(!in_cidr(host, 32, v4(10, 0, 0, 6)));
    }

    /// Boundaries, where an off-by-one silently widens the allowlist. A /24 must
    /// admit .0 through .255 of its own block and nothing on either side.
    #[test]
    fn prefix_boundaries_do_not_leak_into_the_neighbouring_block() {
        let net = v4(10, 0, 5, 0);
        assert!(in_cidr(net, 24, v4(10, 0, 5, 0)));
        assert!(in_cidr(net, 24, v4(10, 0, 5, 255)));
        assert!(!in_cidr(net, 24, v4(10, 0, 4, 255)));
        assert!(!in_cidr(net, 24, v4(10, 0, 6, 0)));
    }

    /// Exhaustive over every prefix length for a fixed pair — the shift is the
    /// part most likely to be wrong, so it is checked against an independent
    /// formulation rather than against itself.
    #[test]
    fn every_prefix_length_agrees_with_a_mask_formulation() {
        let net = v4(192, 168, 13, 37);
        for addr in [
            v4(192, 168, 13, 37),
            v4(192, 168, 13, 38),
            v4(192, 168, 12, 37),
            v4(192, 169, 13, 37),
            v4(193, 168, 13, 37),
            v4(0, 0, 0, 0),
            v4(255, 255, 255, 255),
        ] {
            for prefix in 0u8..=32 {
                let mask: u32 = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix as u32)
                };
                let expected = (net & mask) == (addr & mask);
                assert_eq!(
                    in_cidr(net, prefix, addr),
                    expected,
                    "prefix /{prefix} disagreed for {addr:#010x}"
                );
            }
        }
    }

    /// An out-of-range prefix narrows rather than widens, and does not panic.
    #[test]
    fn an_impossible_prefix_narrows_instead_of_widening() {
        let host = v4(10, 0, 0, 7);
        assert!(in_cidr(host, 33, host));
        assert!(!in_cidr(host, 200, v4(10, 0, 0, 8)));
    }

    /// A port-specific rule does not match another port; a port-agnostic one
    /// matches every port.
    #[test]
    fn port_matching_is_exact_when_specified_and_total_when_not() {
        let r = Rule {
            net: v4(10, 0, 0, 7),
            prefix: 32,
            port_specific: true,
            port: 443,
            allow: true,
        };
        assert!(rule_matches(r, dest(10, 0, 0, 7, 443)));
        assert!(!rule_matches(r, dest(10, 0, 0, 7, 444)));

        let any = Rule {
            port_specific: false,
            ..r
        };
        for p in [0u16, 53, 443, 8080, 65535] {
            assert!(rule_matches(any, dest(10, 0, 0, 7, p)), "port {p}");
        }
    }

    /// A DENY rule matches but never admits. Collapsing these two would turn
    /// every deny entry into an allow entry.
    #[test]
    fn a_matching_deny_rule_never_admits() {
        let deny = Rule {
            net: v4(10, 0, 0, 7),
            prefix: 32,
            port_specific: false,
            port: 0,
            allow: false,
        };
        let d = dest(10, 0, 0, 7, 443);
        assert!(rule_matches(deny, d), "it does match");
        assert!(!rule_admits(deny, d), "but it must not admit");
    }
}

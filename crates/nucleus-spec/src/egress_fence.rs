//! The packet counters on a pod's netns fence, as one shape for the node that
//! writes the chain and the reader that counts it (ADR 0015 E1, #2698).
//!
//! The node appends every rule of a pod's filter table with a `-m comment`
//! tag naming what the rule is ([`FenceRule::tag`]). A snapshot of that table
//! (`iptables-save -c` in the pod's network namespace, taken before teardown)
//! then says, per class, how many packets the guest sent that the fence
//! dropped, accepted or merely counted. [`read`] is the one reader.
//!
//! What the reader refuses rather than reads as zero (ADR 0007 A-2):
//!
//! * a snapshot with no `filter` table, or a filter chain with no policy line;
//! * a filter chain whose policy is not `DROP`: that is not a default-deny
//!   fence, and its counters do not mean what these names say;
//! * a rule in the filter table with no tag, or a tag this build does not know:
//!   a rule nobody can name is not one anybody counted (a snapshot from a node
//!   that predates the tags is refused, not read as a fence that dropped
//!   nothing);
//! * a counter that does not parse.
//!
//! The tags never change a verdict: `-m comment` matches every packet, and the
//! two DNS rules have no target, so they count and fall through. The decided
//! chain (`egress_chain` in `nucleus-node`, the list the confinement proof
//! folds) is applied in the same order as before.

use std::fmt;

/// What starts every tag the node writes.
pub const TAG_PREFIX: &str = "nucleus-fence:";

/// Every rule the node appends to a pod's filter table, by what it is.
///
/// No `_` arm anywhere this is matched (ADR 0007 E-2): a new kind of rule does
/// not compile until the reader says where its counter goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FenceRule {
    /// No target: counts UDP to port 53, whatever the verdict after it.
    DnsUdp,
    /// No target: counts TCP to port 53, whatever the verdict after it.
    DnsTcp,
    /// `-o lo` / `-i lo` ACCEPT.
    Loopback,
    /// `ESTABLISHED,RELATED` ACCEPT: replies to a flow already admitted.
    Established,
    /// A node-floor DROP (link-local and the node's own pod pool).
    Floor,
    /// A DROP the spec's `network.deny` listed.
    SpecDeny,
    /// An ACCEPT the spec listed (`network.allow`, or a `dns_allow` address).
    Allow,
    /// The INPUT ACCEPT of the pod's own resolver (`dns_allow`).
    Resolver,
}

impl FenceRule {
    /// Every rule, for the round-trip test and the reader's lookup.
    pub const ALL: [FenceRule; 8] = [
        FenceRule::DnsUdp,
        FenceRule::DnsTcp,
        FenceRule::Loopback,
        FenceRule::Established,
        FenceRule::Floor,
        FenceRule::SpecDeny,
        FenceRule::Allow,
        FenceRule::Resolver,
    ];

    /// The `--comment` the node writes on the rule. One function names it for
    /// the writer and the reader (ADR 0007 G-1).
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            FenceRule::DnsUdp => "nucleus-fence:dns-udp",
            FenceRule::DnsTcp => "nucleus-fence:dns-tcp",
            FenceRule::Loopback => "nucleus-fence:loopback",
            FenceRule::Established => "nucleus-fence:established",
            FenceRule::Floor => "nucleus-fence:floor",
            FenceRule::SpecDeny => "nucleus-fence:spec-deny",
            FenceRule::Allow => "nucleus-fence:allow",
            FenceRule::Resolver => "nucleus-fence:resolver",
        }
    }

    fn parse(tag: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.tag() == tag)
    }
}

/// Packets and bytes, as `iptables-save -c` prints them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counter {
    pub packets: u64,
    pub bytes: u64,
}

impl Counter {
    /// No packets. Named, not `Default` (ADR 0007 B-1).
    pub const ZERO: Counter = Counter {
        packets: 0,
        bytes: 0,
    };

    fn add(&mut self, other: Counter) {
        self.packets += other.packets;
        self.bytes += other.bytes;
    }
}

impl fmt::Display for Counter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}p/{}B", self.packets, self.bytes)
    }
}

/// DNS the guest sent, whatever became of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsQueries {
    pub udp: Counter,
    pub tcp: Counter,
}

/// What the fence dropped, by the class of destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dropped {
    /// The node floor: link-local (metadata services) and the pod pool.
    pub floor: Counter,
    /// A destination the spec denied.
    pub spec_deny: Counter,
    /// Leaving the namespace to a destination nothing listed (FORWARD policy).
    pub unlisted: Counter,
    /// Addressed to the namespace itself, the guest's gateway (INPUT policy).
    pub into_namespace: Counter,
}

/// What the fence accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accepted {
    /// The first packet of a flow to a listed destination.
    pub listed: Counter,
    /// To the pod's own resolver.
    pub resolver: Counter,
    /// Replies within flows already admitted.
    pub established: Counter,
}

/// One pod's fence, as the guest's traffic left it. Counted in the FORWARD
/// and INPUT chains, which carry what the guest sends; OUTPUT carries only the
/// namespace's own sockets (a resolver's upstream lookups), so its rules are
/// checked for a known tag but not attributed to the guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FenceCounters {
    pub dns: DnsQueries,
    pub dropped: Dropped,
    pub accepted: Accepted,
}

impl FenceCounters {
    const ZERO: FenceCounters = FenceCounters {
        dns: DnsQueries {
            udp: Counter::ZERO,
            tcp: Counter::ZERO,
        },
        dropped: Dropped {
            floor: Counter::ZERO,
            spec_deny: Counter::ZERO,
            unlisted: Counter::ZERO,
            into_namespace: Counter::ZERO,
        },
        accepted: Accepted {
            listed: Counter::ZERO,
            resolver: Counter::ZERO,
            established: Counter::ZERO,
        },
    };

    /// Every packet the fence dropped.
    #[must_use]
    pub fn dropped_total(&self) -> Counter {
        let mut total = Counter::ZERO;
        let Dropped {
            floor,
            spec_deny,
            unlisted,
            into_namespace,
        } = self.dropped;
        for c in [floor, spec_deny, unlisted, into_namespace] {
            total.add(c);
        }
        total
    }

    /// Sum another pod's (or run's) counters into this one.
    pub fn add(&mut self, other: &FenceCounters) {
        // Destructured whole, so a new field does not compile until it is summed (E-1).
        let FenceCounters {
            dns: DnsQueries { udp, tcp },
            dropped:
                Dropped {
                    floor,
                    spec_deny,
                    unlisted,
                    into_namespace,
                },
            accepted:
                Accepted {
                    listed,
                    resolver,
                    established,
                },
        } = *other;
        self.dns.udp.add(udp);
        self.dns.tcp.add(tcp);
        self.dropped.floor.add(floor);
        self.dropped.spec_deny.add(spec_deny);
        self.dropped.unlisted.add(unlisted);
        self.dropped.into_namespace.add(into_namespace);
        self.accepted.listed.add(listed);
        self.accepted.resolver.add(resolver);
        self.accepted.established.add(established);
    }

    /// No packets anywhere: the starting point of a sum.
    #[must_use]
    pub const fn none() -> Self {
        Self::ZERO
    }
}

/// Why a snapshot could not be read as a fence.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FenceUnreadable {
    #[error("the snapshot has no filter table")]
    NoFilterTable,
    #[error("the filter table has no policy line for {0}")]
    NoPolicy(&'static str),
    #[error(
        "the filter table's {chain} policy is {policy}, not DROP: this is not a default-deny fence"
    )]
    NotDefaultDeny { chain: &'static str, policy: String },
    #[error("a counter does not parse: {0:?}")]
    BadCounter(String),
    #[error("a filter rule carries no fence tag: {0:?}")]
    Untagged(String),
    #[error("a filter rule carries a fence tag this build does not know: {0:?}")]
    UnknownTag(String),
    #[error("a filter rule is in a chain the node never writes: {0:?}")]
    UnknownChain(String),
}

/// The chains a pod's filter table has, each with a DROP policy.
const CHAINS: [&str; 3] = ["INPUT", "FORWARD", "OUTPUT"];

fn counter(token: &str) -> Result<Counter, FenceUnreadable> {
    let bad = || FenceUnreadable::BadCounter(token.to_string());
    let (p, b) = token
        .strip_prefix('[')
        .and_then(|t| t.strip_suffix(']'))
        .and_then(|t| t.split_once(':'))
        .ok_or_else(bad)?;
    Ok(Counter {
        packets: p.parse().map_err(|_| bad())?,
        bytes: b.parse().map_err(|_| bad())?,
    })
}

/// Read `iptables-save -c` output from a pod's network namespace.
///
/// # Errors
///
/// [`FenceUnreadable`] for any shape listed in the module documentation.
pub fn read(snapshot: &str) -> Result<FenceCounters, FenceUnreadable> {
    let mut in_filter = false;
    let mut seen_filter = false;
    let mut policies: [Option<Counter>; 3] = [None; 3];
    let mut out = FenceCounters::ZERO;
    for line in snapshot.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(table) = line.strip_prefix('*') {
            in_filter = table == "filter";
            seen_filter |= in_filter;
            continue;
        }
        if line == "COMMIT" {
            in_filter = false;
            continue;
        }
        if !in_filter {
            continue;
        }
        if let Some(decl) = line.strip_prefix(':') {
            // `:FORWARD DROP [12:720]`
            let mut parts = decl.split_whitespace();
            let (Some(chain), Some(policy), Some(count), None) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                return Err(FenceUnreadable::BadCounter(line.to_string()));
            };
            let Some(i) = CHAINS.iter().position(|c| *c == chain) else {
                return Err(FenceUnreadable::UnknownChain(line.to_string()));
            };
            if policy != "DROP" {
                return Err(FenceUnreadable::NotDefaultDeny {
                    chain: CHAINS[i],
                    policy: policy.to_string(),
                });
            }
            policies[i] = Some(counter(count)?);
            continue;
        }
        // `[3:180] -A FORWARD … -m comment --comment "nucleus-fence:floor" -j DROP`
        let mut tokens = line.split_whitespace();
        let count = counter(tokens.next().unwrap_or_default())?;
        let (Some("-A"), Some(chain)) = (tokens.next(), tokens.next()) else {
            return Err(FenceUnreadable::BadCounter(line.to_string()));
        };
        let tag = tokens
            .skip_while(|t| *t != "--comment")
            .nth(1)
            .map(|t| t.trim_matches('"'))
            .ok_or_else(|| FenceUnreadable::Untagged(line.to_string()))?;
        if !tag.starts_with(TAG_PREFIX) {
            return Err(FenceUnreadable::Untagged(line.to_string()));
        }
        let rule = FenceRule::parse(tag).ok_or_else(|| FenceUnreadable::UnknownTag(tag.into()))?;
        let slot = match (chain, rule) {
            ("OUTPUT", _) => None,
            ("FORWARD" | "INPUT", FenceRule::DnsUdp) => Some(&mut out.dns.udp),
            ("FORWARD" | "INPUT", FenceRule::DnsTcp) => Some(&mut out.dns.tcp),
            ("FORWARD" | "INPUT", FenceRule::Loopback) => None,
            ("FORWARD" | "INPUT", FenceRule::Established) => Some(&mut out.accepted.established),
            ("FORWARD" | "INPUT", FenceRule::Floor) => Some(&mut out.dropped.floor),
            ("FORWARD" | "INPUT", FenceRule::SpecDeny) => Some(&mut out.dropped.spec_deny),
            ("FORWARD" | "INPUT", FenceRule::Allow) => Some(&mut out.accepted.listed),
            ("FORWARD" | "INPUT", FenceRule::Resolver) => Some(&mut out.accepted.resolver),
            (_, _) => return Err(FenceUnreadable::UnknownChain(line.to_string())),
        };
        if let Some(slot) = slot {
            slot.add(count);
        }
    }
    if !seen_filter {
        return Err(FenceUnreadable::NoFilterTable);
    }
    let [input, forward, output] = policies;
    let input = input.ok_or(FenceUnreadable::NoPolicy("INPUT"))?;
    let forward = forward.ok_or(FenceUnreadable::NoPolicy("FORWARD"))?;
    output.ok_or(FenceUnreadable::NoPolicy("OUTPUT"))?;
    out.dropped.unlisted = forward;
    out.dropped.into_namespace = input;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape the node writes, as `iptables-save -c` (nf_tables) prints it.
    const SNAPSHOT: &str = r#"# Generated by iptables-save v1.8.10 (nf_tables)
*nat
:POSTROUTING ACCEPT [4:240]
[4:240] -A POSTROUTING -s 192.168.241.0/30 -o veth1 -j MASQUERADE
COMMIT
*filter
:INPUT DROP [1:60]
:FORWARD DROP [9:540]
:OUTPUT DROP [0:0]
[0:0] -A INPUT -p udp -m udp --dport 53 -m comment --comment "nucleus-fence:dns-udp"
[0:0] -A INPUT -p tcp -m tcp --dport 53 -m comment --comment "nucleus-fence:dns-tcp"
[2:120] -A INPUT -i lo -m comment --comment "nucleus-fence:loopback" -j ACCEPT
[0:0] -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "nucleus-fence:established" -j ACCEPT
[4:256] -A FORWARD -p udp -m udp --dport 53 -m comment --comment "nucleus-fence:dns-udp"
[3:180] -A FORWARD -p tcp -m tcp --dport 53 -m comment --comment "nucleus-fence:dns-tcp"
[0:0] -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "nucleus-fence:established" -j ACCEPT
[1:60] -A FORWARD -d 169.254.0.0/16 -m comment --comment "nucleus-fence:floor" -j DROP
[0:0] -A FORWARD -d 10.0.0.0/8 -m comment --comment "nucleus-fence:floor" -j DROP
[0:0] -A OUTPUT -o lo -m comment --comment nucleus-fence:loopback -j ACCEPT
[7:420] -A OUTPUT -d 169.254.0.0/16 -m comment --comment "nucleus-fence:floor" -j DROP
COMMIT
"#;

    #[test]
    fn every_tag_round_trips_and_shares_the_prefix() {
        for rule in FenceRule::ALL {
            assert!(rule.tag().starts_with(TAG_PREFIX));
            assert_eq!(FenceRule::parse(rule.tag()), Some(rule));
        }
    }

    #[test]
    fn a_snapshot_is_read_by_class_and_output_is_not_the_guest() {
        let c = read(SNAPSHOT).unwrap();
        assert_eq!(
            c.dns.udp,
            Counter {
                packets: 4,
                bytes: 256
            }
        );
        assert_eq!(
            c.dns.tcp,
            Counter {
                packets: 3,
                bytes: 180
            }
        );
        assert_eq!(
            c.dropped.floor,
            Counter {
                packets: 1,
                bytes: 60
            }
        );
        assert_eq!(
            c.dropped.unlisted,
            Counter {
                packets: 9,
                bytes: 540
            }
        );
        assert_eq!(
            c.dropped.into_namespace,
            Counter {
                packets: 1,
                bytes: 60
            }
        );
        assert_eq!(
            c.dropped_total().packets,
            11,
            "OUTPUT's 7 are not the guest's"
        );
    }

    #[test]
    fn a_snapshot_without_tags_is_refused_not_read_as_zero() {
        // What a node from before the tags wrote: no rule names itself.
        let mut old = SNAPSHOT.to_string();
        for rule in FenceRule::ALL {
            for form in [format!("\"{}\"", rule.tag()), rule.tag().to_string()] {
                old = old.replace(&format!(" -m comment --comment {form}"), "");
            }
        }
        assert!(!old.contains("nucleus-fence"), "{old}");
        assert!(matches!(read(&old), Err(FenceUnreadable::Untagged(_))));
    }

    #[test]
    fn an_unknown_tag_a_missing_policy_or_an_open_policy_is_refused() {
        let unknown = SNAPSHOT.replace(
            "\"nucleus-fence:loopback\" -j ACCEPT",
            "\"nucleus-fence:mystery\" -j ACCEPT",
        );
        assert_eq!(
            read(&unknown),
            Err(FenceUnreadable::UnknownTag("nucleus-fence:mystery".into()))
        );
        let no_policy = SNAPSHOT.replace(":FORWARD DROP [9:540]\n", "");
        assert_eq!(read(&no_policy), Err(FenceUnreadable::NoPolicy("FORWARD")));
        let open = SNAPSHOT.replace(":FORWARD DROP", ":FORWARD ACCEPT");
        assert!(matches!(
            read(&open),
            Err(FenceUnreadable::NotDefaultDeny {
                chain: "FORWARD",
                ..
            })
        ));
        assert_eq!(read("*nat\nCOMMIT\n"), Err(FenceUnreadable::NoFilterTable));
        assert_eq!(read(""), Err(FenceUnreadable::NoFilterTable));
        let torn = SNAPSHOT.replace("[1:60] -A FORWARD", "[1:x] -A FORWARD");
        assert!(matches!(read(&torn), Err(FenceUnreadable::BadCounter(_))));
    }
}

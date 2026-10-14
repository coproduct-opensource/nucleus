//! The bypass detector: the kernel's own count of what left a pod's link,
//! checked against what this module's packet queue admitted (#2905).
//!
//! # What it is for
//!
//! Since #3184 every outbound IP packet on the pod's peer veth waits in NFQUEUE
//! until the egress ledger has reserved its length, so the ledger is the
//! meter. The kernel's interface counters are NOT a second meter: billing them
//! too would charge every admitted byte twice. They are a cross-check. If the
//! kernel says more left the link than the queue admitted, something sent
//! without asking — a removed or reordered rule, a path that skips the
//! `POSTROUTING` hook, a defect in this module — and the pod's egress is cut.
//!
//! # Which counter
//!
//! `rx_bytes` / `rx_packets` of the HOST end of the pod's veth pair, read from
//! the host namespace's sysfs. A veth's receive counters are its peer's
//! transmit counters, so this is exactly "frames that left the pod's namespace
//! toward the host", read without entering the namespace. Not the tap: the tap
//! also counts frames the fence or the ledger DROPPED (an off-allowlist connect,
//! the boot probe, a pace refusal), and those never left.
//!
//! # The tolerance, from header sizes
//!
//! The queue admits an IP packet's length (`NFQA_CAP_LEN`: the network header
//! onward). The kernel counts the frame that crossed the link. On a veth the
//! difference is exactly one Ethernet II header per frame — veth carries no
//! FCS, no preamble and no minimum-length padding — so an admitted packet
//! accounts for [`ETH_HLEN`] more bytes than the ledger charged. GSO cannot
//! inflate that: the queue is configured without `NFQA_CFG_F_GSO`, so the
//! kernel segments before admission and every admitted packet is one frame.
//!
//! The only frames on this link that are not IP, and so never pass the queue,
//! are ARP: [`ARP_FRAME_LEN`] bytes each (the Ethernet header plus the 28-byte
//! IPv4-over-Ethernet ARP body). IPv6 neighbour discovery is ICMPv6 and IS
//! queued. So the most the kernel may count is
//!
//! ```text
//! admitted_bytes + ETH_HLEN * admitted_packets
//!                + ARP_FRAME_LEN * max(0, kernel_packets - admitted_packets)
//! ```
//!
//! and one byte more is a bypass. Nothing in it is a slack chosen to make a
//! test pass; each term is a header someone can look up.
//!
//! # What this does not claim
//!
//! - A frame of at most [`ARP_FRAME_LEN`] bytes is indistinguishable from ARP by
//!   counters alone, so a bypass of such frames is invisible here. Each carries
//!   at most 28 bytes past its Ethernet header.
//! - It detects after the fact: up to one check period of bypassed bytes can
//!   leave before the cut. It is a tripwire on the meter, not the meter.
//! - An admitted packet the kernel then dropped (a failed neighbour lookup)
//!   leaves its length as headroom. The ledger already charged those bytes, so
//!   what the headroom can hide was paid for.

use std::path::{Path, PathBuf};

/// The Ethernet II header: destination MAC (6) + source MAC (6) + EtherType (2).
pub(crate) const ETH_HLEN: u64 = 6 + 6 + 2;

/// The body of an ARP packet for IPv4 over Ethernet (RFC 826): hardware type
/// (2), protocol type (2), hardware length (1), protocol length (1), operation
/// (2), sender MAC (6), sender IPv4 (4), target MAC (6), target IPv4 (4).
const ARP_IPV4_BODY: u64 = 2 + 2 + 1 + 1 + 2 + 6 + 4 + 6 + 4;

/// The largest frame on a pod's link that is not IP: an ARP frame.
pub(crate) const ARP_FRAME_LEN: u64 = ETH_HLEN + ARP_IPV4_BODY;

/// What the kernel says crossed a link: bytes and frames, since boot of the
/// interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LinkTotals {
    pub bytes: u64,
    pub packets: u64,
}

/// What the packet queue admitted onto the link since the detector's baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Admitted {
    pub bytes: u64,
    pub packets: u64,
}

/// Why the counters could not be checked. Every variant is a reason the
/// detector did not look, and none of them is "no bypass" (ADR 0007 A-1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum CouldNotCheck {
    /// A counter file could not be read.
    #[error("could not read {path}: {error}")]
    Unreadable { path: PathBuf, error: String },
    /// A counter file did not hold a decimal count.
    #[error("{path} does not hold a count: {content:?}")]
    NotACount { path: PathBuf, content: String },
    /// A counter went backwards: the interface was reset or replaced, and the
    /// baseline no longer describes it.
    #[error(
        "the link's counters went backwards ({before_bytes} -> {now_bytes} bytes, \
         {before_packets} -> {now_packets} frames): the interface was reset or replaced"
    )]
    Regressed {
        before_bytes: u64,
        now_bytes: u64,
        before_packets: u64,
        now_packets: u64,
    },
    /// The allowance does not fit in a `u64`. Unreachable for a real link; a
    /// saturated allowance would grant, so it is refused instead (ADR 0007 B).
    #[error("the egress allowance overflows")]
    Overflow,
}

/// The kernel counted more than the queue admitted, past the framing
/// tolerance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Bypass {
    /// Kernel-counted bytes since the baseline.
    pub kernel_bytes: u64,
    /// Kernel-counted frames since the baseline.
    pub kernel_packets: u64,
    /// What the queue admitted since the baseline.
    pub admitted: Admitted,
    /// The most the kernel may count for what was admitted.
    pub allowed_bytes: u64,
}

impl std::fmt::Display for Bypass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "egress bypass (egress.link): the kernel counted {} bytes in {} frames leaving the \
             pod's link; the egress ledger admitted {} bytes in {} packets, which allows at most \
             {} bytes with framing; {} bytes left without a reservation; egress is cut for the \
             rest of this pod's life",
            self.kernel_bytes,
            self.kernel_packets,
            self.admitted.bytes,
            self.admitted.packets,
            self.allowed_bytes,
            self.kernel_bytes.saturating_sub(self.allowed_bytes),
        )
    }
}

/// The outcome of one check. Three arms, because "could not look" is not
/// "looked and it was fine" (ADR 0007 A-1, A-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Assessment {
    /// The kernel counted no more than the ledger admitted, with framing.
    Consistent,
    /// The kernel counted more.
    Bypass(Bypass),
    /// The counters could not be read or compared.
    CouldNotCheck(CouldNotCheck),
}

/// A source of a link's kernel counters. Injectable, so tests can point the
/// detector at a fake sysfs.
pub(crate) trait LinkCounters: Send + Sync + 'static {
    /// The link's totals now.
    fn read(&self) -> Result<LinkTotals, CouldNotCheck>;
}

/// A link's receive counters in a sysfs tree: `<root>/<iface>/statistics/`.
#[derive(Debug, Clone)]
pub(crate) struct SysfsCounters {
    statistics: PathBuf,
}

impl SysfsCounters {
    /// The production root: the host namespace's `/sys/class/net`.
    pub(crate) const HOST_ROOT: &'static str = "/sys/class/net";

    /// The receive counters of `iface` under `root`. For the host end of a
    /// pod's veth these are what left the pod's namespace.
    pub(crate) fn receive(root: &Path, iface: &str) -> Self {
        Self {
            statistics: root.join(iface).join("statistics"),
        }
    }

    fn count(&self, name: &str) -> Result<u64, CouldNotCheck> {
        let path = self.statistics.join(name);
        let content = std::fs::read_to_string(&path).map_err(|e| CouldNotCheck::Unreadable {
            path: path.clone(),
            error: e.to_string(),
        })?;
        content
            .trim()
            .parse::<u64>()
            .map_err(|_| CouldNotCheck::NotACount { path, content })
    }
}

impl LinkCounters for SysfsCounters {
    fn read(&self) -> Result<LinkTotals, CouldNotCheck> {
        Ok(LinkTotals {
            bytes: self.count("rx_bytes")?,
            packets: self.count("rx_packets")?,
        })
    }
}

/// The most the kernel may count for what was admitted, given how many frames
/// it counted. See the module docs for each term.
pub(crate) fn allowance(admitted: Admitted, kernel_packets: u64) -> Option<u64> {
    let unqueued = kernel_packets.saturating_sub(admitted.packets);
    admitted
        .bytes
        .checked_add(ETH_HLEN.checked_mul(admitted.packets)?)?
        .checked_add(ARP_FRAME_LEN.checked_mul(unqueued)?)
}

/// Compare the kernel's count since `baseline` with what was admitted.
pub(crate) fn assess(baseline: LinkTotals, now: LinkTotals, admitted: Admitted) -> Assessment {
    let (Some(kernel_bytes), Some(kernel_packets)) = (
        now.bytes.checked_sub(baseline.bytes),
        now.packets.checked_sub(baseline.packets),
    ) else {
        return Assessment::CouldNotCheck(CouldNotCheck::Regressed {
            before_bytes: baseline.bytes,
            now_bytes: now.bytes,
            before_packets: baseline.packets,
            now_packets: now.packets,
        });
    };
    let Some(allowed_bytes) = allowance(admitted, kernel_packets) else {
        return Assessment::CouldNotCheck(CouldNotCheck::Overflow);
    };
    if kernel_bytes > allowed_bytes {
        Assessment::Bypass(Bypass {
            kernel_bytes,
            kernel_packets,
            admitted,
            allowed_bytes,
        })
    } else {
        Assessment::Consistent
    }
}

/// A link's counters and the baseline they are measured from.
pub(crate) struct Detector {
    counters: Box<dyn LinkCounters>,
    baseline: LinkTotals,
    /// How often the run loop checks.
    pub(crate) period: std::time::Duration,
}

/// How often a pod's link is checked.
pub(crate) const CHECK_PERIOD: std::time::Duration = std::time::Duration::from_secs(1);

impl Detector {
    /// Read the baseline now. Called once the queue rules are installed, so
    /// every IP frame after it passed the queue. A baseline that cannot be read
    /// is refused: a pod whose link cannot be checked does not get one.
    pub(crate) fn start(
        counters: impl LinkCounters,
        period: std::time::Duration,
    ) -> Result<Self, CouldNotCheck> {
        let baseline = counters.read()?;
        Ok(Self {
            counters: Box::new(counters),
            baseline,
            period,
        })
    }

    /// Check the link against what was admitted since the baseline.
    pub(crate) fn check(&self, admitted: Admitted) -> Assessment {
        match self.counters.read() {
            Ok(now) => assess(self.baseline, now, admitted),
            Err(why) => Assessment::CouldNotCheck(why),
        }
    }
}

impl std::fmt::Debug for Detector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Detector")
            .field("baseline", &self.baseline)
            .field("period", &self.period)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: LinkTotals = LinkTotals {
        bytes: 5_000,
        packets: 40,
    };

    fn after(bytes: u64, packets: u64) -> LinkTotals {
        LinkTotals {
            bytes: BASE.bytes + bytes,
            packets: BASE.packets + packets,
        }
    }

    fn admitted(bytes: u64, packets: u64) -> Admitted {
        Admitted { bytes, packets }
    }

    /// The constants are the header sizes, not tuned numbers.
    #[test]
    fn the_tolerance_is_the_ethernet_and_arp_headers() {
        assert_eq!(ETH_HLEN, 14);
        assert_eq!(ARP_FRAME_LEN, 42);
    }

    /// Exactly one Ethernet header per admitted packet is consistent, and one
    /// byte more is a bypass.
    #[test]
    fn one_byte_past_the_framing_of_what_was_admitted_is_a_bypass() {
        let a = admitted(1_000, 10);
        assert_eq!(assess(BASE, after(1_140, 10), a), Assessment::Consistent);
        assert_eq!(
            assess(BASE, after(1_141, 10), a),
            Assessment::Bypass(Bypass {
                kernel_bytes: 1_141,
                kernel_packets: 10,
                admitted: a,
                allowed_bytes: 1_140,
            })
        );
    }

    /// A frame the queue never saw is allowed only an ARP frame's length.
    #[test]
    fn an_unqueued_frame_is_allowed_an_arp_frame_and_no_more() {
        let a = admitted(1_000, 10);
        assert_eq!(
            assess(BASE, after(1_140 + 42, 11), a),
            Assessment::Consistent
        );
        assert!(matches!(
            assess(BASE, after(1_140 + 43, 11), a),
            Assessment::Bypass(_)
        ));
        // A full-size frame that skipped the queue is caught however much was
        // admitted before it.
        assert!(matches!(
            assess(BASE, after(1_140 + 1_514, 11), a),
            Assessment::Bypass(_)
        ));
    }

    /// Nothing admitted and nothing counted is consistent; anything past ARP
    /// with nothing admitted is a bypass.
    #[test]
    fn a_link_with_nothing_admitted_may_carry_only_arp() {
        let none = Admitted::default();
        assert_eq!(assess(BASE, BASE, none), Assessment::Consistent);
        assert_eq!(assess(BASE, after(84, 2), none), Assessment::Consistent);
        assert!(matches!(
            assess(BASE, after(100, 1), none),
            Assessment::Bypass(_)
        ));
    }

    /// A counter that went backwards is not a reading of zero.
    #[test]
    fn a_counter_that_went_backwards_could_not_be_checked() {
        let earlier = LinkTotals {
            bytes: BASE.bytes - 1,
            packets: BASE.packets,
        };
        assert!(matches!(
            assess(BASE, earlier, Admitted::default()),
            Assessment::CouldNotCheck(CouldNotCheck::Regressed { .. })
        ));
    }

    /// An allowance that would overflow is refused rather than saturated.
    #[test]
    fn an_overflowing_allowance_could_not_be_checked() {
        assert_eq!(allowance(admitted(u64::MAX, 1), 1), None);
        assert_eq!(
            assess(
                LinkTotals {
                    bytes: 0,
                    packets: 0
                },
                LinkTotals {
                    bytes: 0,
                    packets: 1
                },
                admitted(u64::MAX, 1)
            ),
            Assessment::CouldNotCheck(CouldNotCheck::Overflow)
        );
    }

    fn fake_sysfs(bytes: &str, packets: &str) -> (tempfile::TempDir, SysfsCounters) {
        let root = tempfile::tempdir().unwrap();
        let stats = root.path().join("vh-test").join("statistics");
        std::fs::create_dir_all(&stats).unwrap();
        std::fs::write(stats.join("rx_bytes"), bytes).unwrap();
        std::fs::write(stats.join("rx_packets"), packets).unwrap();
        let counters = SysfsCounters::receive(root.path(), "vh-test");
        (root, counters)
    }

    #[test]
    fn sysfs_counters_read_the_receive_statistics() {
        let (_root, counters) = fake_sysfs("1234\n", "7\n");
        assert_eq!(
            counters.read(),
            Ok(LinkTotals {
                bytes: 1_234,
                packets: 7
            })
        );
    }

    #[test]
    fn a_missing_or_garbled_counter_is_named() {
        let (root, counters) = fake_sysfs("12x\n", "7\n");
        assert!(matches!(
            counters.read(),
            Err(CouldNotCheck::NotACount { .. })
        ));
        std::fs::remove_file(root.path().join("vh-test/statistics/rx_bytes")).unwrap();
        let err = counters.read().unwrap_err();
        assert!(matches!(err, CouldNotCheck::Unreadable { .. }), "{err}");
        assert!(err.to_string().contains("rx_bytes"), "{err}");
    }

    /// A detector whose baseline cannot be read does not start.
    #[test]
    fn a_detector_without_a_baseline_does_not_start() {
        let (root, counters) = fake_sysfs("1\n", "1\n");
        std::fs::remove_file(root.path().join("vh-test/statistics/rx_packets")).unwrap();
        assert!(Detector::start(counters, CHECK_PERIOD).is_err());
    }
}

//! The guest's own egress fence, installed from PID 1 with no image contents.
//!
//! # What it replaces
//!
//! `scripts/firecracker/guest-net.sh`, which guest-init ran whenever
//! `/etc/nucleus/net.allow` or `net.deny` existed. The script needed `/bin/sh`
//! and `iptables` from the image; the rootfs this repository builds has no
//! `iptables`, so on every pod it reached `command -v iptables`, found nothing,
//! and exited 0 having installed no rules at all. The in-guest half of the
//! defence in depth was a no-op wherever it was deployed.
//!
//! # Why x_tables and not nftables
//!
//! The owner decision was "nftables over netlink". The guest kernel pinned when
//! this was written (Firecracker CI `vmlinux-6.1.141`) was measured first, by
//! booting it with a probe as `/init`:
//!
//! * `socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)` → `EPROTONOSUPPORT`.
//!   There is no nfnetlink, so there is no nf_tables to talk to, by any crate.
//! * `/proc/net/ip_tables_matches` → `conntrack` (three revisions), `tcp`,
//!   `udp`, `icmp`, `addrtype`, `udplite`; `/proc/net/ip_tables_targets` →
//!   `ERROR`, `REJECT`, NAT targets; `IPT_SO_GET_INFO` on `filter` succeeds.
//!
//! So the kernel's legacy x_tables interface is the one that exists, and this
//! module speaks it directly: one `setsockopt(IPT_SO_SET_REPLACE)` carrying the
//! whole `filter` table, exactly what `iptables-legacy-restore` sends. Every
//! crate that would have helped was ruled out on its own terms first —
//! `rustables` is GPL-3.0, `nftnl`/`mnl` link the C libraries, the `nftables`
//! crate runs the `nft` binary — and none of them would have reached this
//! kernel anyway.
//!
//! The pin has since moved to Firecracker CI `vmlinux-6.1.186`
//! ([`nucleus_spec::tier2_artifacts`], #2696 P3). Its config keeps every
//! x_tables option this module relies on (`IP_NF_IPTABLES`, `IP_NF_FILTER`,
//! `NETFILTER_XT_MATCH_CONNTRACK`) and adds `CONFIG_NF_TABLES=y`, so the
//! nftables route is now open. The rule set below ([`EgressPolicy`]) is the
//! input an nftables encoder would take; the policy parsing and the verdict
//! order do not change.
//!
//! # The rule set, reproduced
//!
//! Precisely `guest-net.sh`'s, verified by installing both into scratch network
//! namespaces and comparing `iptables-legacy-save` (see the `#[ignore]`d
//! `parity` test):
//!
//! * `INPUT`, `OUTPUT`, `FORWARD` policies `DROP`.
//! * `INPUT -i lo` and `OUTPUT -o lo` accept.
//! * `INPUT`/`OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED` accept.
//! * per allow entry, in file order: `host:port` → `-d host -p tcp --dport
//!   port` and the same for `udp`; bare `host` → `-d host` any protocol.
//! * per deny entry, after every allow: `-d host -j DROP` (the port, if any, is
//!   ignored, as `cut -d: -f1` ignored it).
//!
//! There is no DNS rule. The script's comment said "Allow DNS to resolver only
//! if allowlist present" and its code never did; the resolver is reachable
//! from the guest only if it is listed, and that is kept.
//!
//! # Where it differs, deliberately
//!
//! * Blank lines and `#` comments are skipped. The script handed a comment
//!   line to `iptables -d`, which failed, and `set -e` then abandoned every
//!   later rule: the example `net.allow` in this repository, which is all
//!   comments, installed the DROP policies and nothing else.
//! * A malformed entry is an error that names it, and guest-init refuses to
//!   boot on it — a policy file that cannot be enforced as written is not
//!   enforced as something else. The script's `iptables` failed on the same
//!   entry, `set -e` stopped, and guest-init discarded the exit status.
//! * Hostnames are refused. `iptables -d name` resolves at insertion time, and
//!   by then the script had already set `OUTPUT` to `DROP`, so only
//!   `/etc/hosts` could ever answer — an image-supplied file.

use std::net::Ipv4Addr;

/// A destination: an IPv4 address and prefix, as `-d a.b.c.d[/n]` takes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dest {
    /// The network address, already masked.
    pub addr: Ipv4Addr,
    /// Prefix length, 0..=32.
    pub prefix: u8,
}

impl Dest {
    fn mask(self) -> Ipv4Addr {
        let bits = u32::MAX
            .checked_shl(32 - u32::from(self.prefix))
            .unwrap_or(0);
        Ipv4Addr::from(bits)
    }

    fn parse(s: &str) -> Option<Self> {
        let (ip, prefix) = match s.split_once('/') {
            Some((ip, p)) => (ip, p.parse::<u8>().ok().filter(|p| *p <= 32)?),
            None => (s, 32),
        };
        let ip = ip.parse::<Ipv4Addr>().ok()?;
        let d = Self { addr: ip, prefix };
        Some(Self {
            addr: Ipv4Addr::from(u32::from(ip) & u32::from(d.mask())),
            prefix,
        })
    }
}

/// One `net.allow` line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allow {
    /// Where to.
    pub dest: Dest,
    /// TCP and UDP to this port only; every protocol when `None`.
    pub port: Option<u16>,
}

/// The whole in-guest egress policy: `net.allow` then `net.deny`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressPolicy {
    /// Accepted, in file order.
    pub allow: Vec<Allow>,
    /// Dropped, after every allow.
    pub deny: Vec<Dest>,
}

/// A policy line that could not be enforced as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    /// Which file.
    pub file: &'static str,
    /// 1-based line number.
    pub line: usize,
    /// The line itself.
    pub entry: String,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}: `{}` is not an IPv4 address or CIDR with an optional :port",
            self.file, self.line, self.entry
        )
    }
}

impl std::error::Error for PolicyError {}

fn entries<'a>(
    file: &'static str,
    text: &'a str,
) -> impl Iterator<Item = (usize, &'a str, PolicyError)> + 'a {
    text.lines().enumerate().filter_map(move |(i, raw)| {
        let entry = raw.trim();
        (!entry.is_empty() && !entry.starts_with('#')).then(|| {
            (
                i + 1,
                entry,
                PolicyError {
                    file,
                    line: i + 1,
                    entry: entry.to_string(),
                },
            )
        })
    })
}

impl EgressPolicy {
    /// Parse the two files. Either may be absent (`None`).
    ///
    /// # Errors
    /// The first line that is not `a.b.c.d[/n][:port]`.
    pub fn parse(allow: Option<&str>, deny: Option<&str>) -> Result<Self, PolicyError> {
        let mut policy = Self {
            allow: Vec::new(),
            deny: Vec::new(),
        };
        for (_, entry, err) in entries(nucleus_spec::guest_layout::NET_ALLOW, allow.unwrap_or("")) {
            let (host, port) = match entry.split_once(':') {
                Some((h, p)) => (
                    h,
                    Some(
                        p.parse::<u16>()
                            .ok()
                            .filter(|p| *p != 0)
                            .ok_or(err.clone())?,
                    ),
                ),
                None => (entry, None),
            };
            let dest = Dest::parse(host).ok_or(err)?;
            policy.allow.push(Allow { dest, port });
        }
        for (_, entry, err) in entries(nucleus_spec::guest_layout::NET_DENY, deny.unwrap_or("")) {
            let host = entry.split_once(':').map_or(entry, |(h, _)| h);
            policy.deny.push(Dest::parse(host).ok_or(err)?);
        }
        Ok(policy)
    }
}

// ---- the x_tables ABI -------------------------------------------------------
//
// Layouts from <linux/netfilter_ipv4/ip_tables.h> and <linux/netfilter/x_tables.h>
// on a 64-bit kernel (XT_ALIGN = 8), which both guest architectures are. Written
// field by field into a byte vector rather than through `#[repr(C)]` structs, so
// no `unsafe` is needed to build the table and the tests can pin every offset.

const XT_TABLE_MAXNAMELEN: usize = 32;
const XT_EXTENSION_MAXNAMELEN: usize = 29;
const IFNAMSIZ: usize = 16;
/// `sizeof(struct ipt_ip)`.
const IPT_IP_LEN: usize = 84;
/// `sizeof(struct ipt_entry)`.
pub const IPT_ENTRY_LEN: usize = 112;
/// `sizeof(struct xt_entry_match)` / `xt_entry_target`.
const XT_HDR_LEN: usize = 32;
/// `XT_ALIGN(sizeof(struct xt_standard_target))`.
const STANDARD_TARGET_LEN: usize = 40;
/// `XT_ALIGN(sizeof(struct xt_error_target))`.
const ERROR_TARGET_LEN: usize = 64;
/// `sizeof(struct ipt_replace)`, up to `entries`.
pub const IPT_REPLACE_LEN: usize = 96;
/// Offset of the `counters` pointer inside `ipt_replace`.
pub const IPT_REPLACE_COUNTERS_OFFSET: usize = 88;
/// `sizeof(struct xt_counters)`.
pub const XT_COUNTERS_LEN: usize = 16;

const NF_INET_LOCAL_IN: usize = 1;
const NF_INET_FORWARD: usize = 2;
const NF_INET_LOCAL_OUT: usize = 3;
const NF_INET_NUMHOOKS: usize = 5;
/// The `filter` table's hooks.
pub const FILTER_VALID_HOOKS: u32 =
    (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_FORWARD) | (1 << NF_INET_LOCAL_OUT);

const IPPROTO_TCP: u16 = 6;
const IPPROTO_UDP: u16 = 17;

/// `-NF_DROP - 1`: a standard target's verdict for DROP.
const VERDICT_DROP: i32 = -1;
/// `-NF_ACCEPT - 1`.
const VERDICT_ACCEPT: i32 = -2;

/// `XT_CONNTRACK_STATE`, and `ESTABLISHED | RELATED` as the conntrack match
/// encodes them (`1 << (IP_CT_ESTABLISHED + 1) | 1 << (IP_CT_RELATED + 1)`).
const XT_CONNTRACK_STATE: u16 = 1;
const CT_ESTABLISHED_RELATED: u16 = (1 << 1) | (1 << 2);
/// Revision 3, the one `iptables --ctstate` sends. The kernel accepts 1 as
/// well (measured), but iptables-legacy-save cannot print revision 1, and a
/// table the reference tool cannot read back is a table whose parity nobody
/// can check.
const CONNTRACK_REVISION: u8 = 3;
/// `XT_ALIGN(sizeof(struct xt_conntrack_mtinfo3))`: 164 bytes, padded to 168.
const CONNTRACK_MTINFO3_LEN: usize = 168;
/// Offsets inside `xt_conntrack_mtinfo3`, after eight 16-byte addresses, the
/// two `expires` words and five `__u16` protocol/port fields.
const CT_MATCH_FLAGS_AT: usize = 146;
const CT_STATE_MASK_AT: usize = 150;

/// A rule's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// `-j ACCEPT`.
    Accept,
    /// `-j DROP`.
    Drop,
}

impl Verdict {
    fn code(self) -> i32 {
        match self {
            Self::Accept => VERDICT_ACCEPT,
            Self::Drop => VERDICT_DROP,
        }
    }
}

/// The match a rule carries beyond `ipt_ip`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Extra {
    None,
    /// `-m conntrack --ctstate ESTABLISHED,RELATED`.
    CtEstablished,
    /// `-p tcp -m tcp --dport N`.
    TcpDport(u16),
    /// `-p udp -m udp --dport N`.
    UdpDport(u16),
}

/// One rule, before encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rule {
    in_iface: Option<&'static str>,
    out_iface: Option<&'static str>,
    dest: Option<Dest>,
    extra: Extra,
    verdict: Verdict,
}

impl Rule {
    const fn any(verdict: Verdict) -> Self {
        Self {
            in_iface: None,
            out_iface: None,
            dest: None,
            extra: Extra::None,
            verdict,
        }
    }
}

/// The three chains, in hook order, each ending in its policy.
fn chains(policy: &EgressPolicy) -> [(usize, Vec<Rule>, Verdict); 3] {
    let ct = Rule {
        extra: Extra::CtEstablished,
        ..Rule::any(Verdict::Accept)
    };
    let input = vec![
        Rule {
            in_iface: Some("lo"),
            ..Rule::any(Verdict::Accept)
        },
        ct,
    ];
    let mut output = vec![
        Rule {
            out_iface: Some("lo"),
            ..Rule::any(Verdict::Accept)
        },
        ct,
    ];
    for allow in &policy.allow {
        let dest = Some(allow.dest);
        match allow.port {
            Some(port) => {
                output.push(Rule {
                    dest,
                    extra: Extra::TcpDport(port),
                    ..Rule::any(Verdict::Accept)
                });
                output.push(Rule {
                    dest,
                    extra: Extra::UdpDport(port),
                    ..Rule::any(Verdict::Accept)
                });
            }
            None => output.push(Rule {
                dest,
                ..Rule::any(Verdict::Accept)
            }),
        }
    }
    for dest in &policy.deny {
        output.push(Rule {
            dest: Some(*dest),
            ..Rule::any(Verdict::Drop)
        });
    }
    [
        (NF_INET_LOCAL_IN, input, Verdict::Drop),
        (NF_INET_FORWARD, Vec::new(), Verdict::Drop),
        (NF_INET_LOCAL_OUT, output, Verdict::Drop),
    ]
}

fn put_name(buf: &mut Vec<u8>, name: &str, width: usize) {
    let mut field = vec![0u8; width];
    let bytes = name.as_bytes();
    let n = bytes.len().min(width.saturating_sub(1));
    field[..n].copy_from_slice(&bytes[..n]);
    buf.extend_from_slice(&field);
}

fn put_iface(name: Option<&str>) -> ([u8; IFNAMSIZ], [u8; IFNAMSIZ]) {
    let mut iface = [0u8; IFNAMSIZ];
    let mut mask = [0u8; IFNAMSIZ];
    if let Some(name) = name {
        let n = name.len().min(IFNAMSIZ - 1);
        iface[..n].copy_from_slice(&name.as_bytes()[..n]);
        // iptables masks the name and its NUL: an exact match, not a prefix.
        mask[..=n].fill(0xff);
    }
    (iface, mask)
}

fn match_header(buf: &mut Vec<u8>, size: usize, name: &str, revision: u8) {
    buf.extend_from_slice(&u16::try_from(size).unwrap_or(u16::MAX).to_ne_bytes());
    put_name(buf, name, XT_EXTENSION_MAXNAMELEN);
    buf.push(revision);
}

fn encode_extra(extra: Extra) -> Vec<u8> {
    let mut m = Vec::new();
    match extra {
        Extra::None => {}
        Extra::CtEstablished => {
            match_header(
                &mut m,
                XT_HDR_LEN + CONNTRACK_MTINFO3_LEN,
                "conntrack",
                CONNTRACK_REVISION,
            );
            let mut info = vec![0u8; CONNTRACK_MTINFO3_LEN];
            info[CT_MATCH_FLAGS_AT..CT_MATCH_FLAGS_AT + 2]
                .copy_from_slice(&XT_CONNTRACK_STATE.to_ne_bytes());
            info[CT_STATE_MASK_AT..CT_STATE_MASK_AT + 2]
                .copy_from_slice(&CT_ESTABLISHED_RELATED.to_ne_bytes());
            m.extend_from_slice(&info);
        }
        Extra::TcpDport(port) => {
            match_header(&mut m, XT_HDR_LEN + 16, "tcp", 0);
            // struct xt_tcp: spts[2], dpts[2], option, flg_mask, flg_cmp, invflags.
            m.extend_from_slice(&0u16.to_ne_bytes());
            m.extend_from_slice(&u16::MAX.to_ne_bytes());
            m.extend_from_slice(&port.to_ne_bytes());
            m.extend_from_slice(&port.to_ne_bytes());
            m.extend_from_slice(&[0u8; 4]);
            m.extend_from_slice(&[0u8; 4]); // XT_ALIGN(12) = 16
        }
        Extra::UdpDport(port) => {
            match_header(&mut m, XT_HDR_LEN + 16, "udp", 0);
            // struct xt_udp: spts[2], dpts[2], invflags (+1 pad).
            m.extend_from_slice(&0u16.to_ne_bytes());
            m.extend_from_slice(&u16::MAX.to_ne_bytes());
            m.extend_from_slice(&port.to_ne_bytes());
            m.extend_from_slice(&port.to_ne_bytes());
            m.extend_from_slice(&[0u8; 8]); // invflags, pad, XT_ALIGN(10) = 16
        }
    }
    m
}

fn proto(extra: Extra) -> u16 {
    match extra {
        Extra::TcpDport(_) => IPPROTO_TCP,
        Extra::UdpDport(_) => IPPROTO_UDP,
        Extra::None | Extra::CtEstablished => 0,
    }
}

/// `struct ipt_entry` + matches + target, for a rule ending in a standard verdict.
fn encode_rule(rule: &Rule) -> Vec<u8> {
    let matches = encode_extra(rule.extra);
    let target_offset = IPT_ENTRY_LEN + matches.len();
    let next_offset = target_offset + STANDARD_TARGET_LEN;

    let mut e = Vec::with_capacity(next_offset);
    // struct ipt_ip
    e.extend_from_slice(&[0u8; 4]); // src
    let (dst, dmsk) = rule.dest.map_or(([0u8; 4], [0u8; 4]), |d| {
        (d.addr.octets(), d.mask().octets())
    });
    e.extend_from_slice(&dst);
    e.extend_from_slice(&[0u8; 4]); // smsk
    e.extend_from_slice(&dmsk);
    let (iniface, iniface_mask) = put_iface(rule.in_iface);
    let (outiface, outiface_mask) = put_iface(rule.out_iface);
    e.extend_from_slice(&iniface);
    e.extend_from_slice(&outiface);
    e.extend_from_slice(&iniface_mask);
    e.extend_from_slice(&outiface_mask);
    e.extend_from_slice(&proto(rule.extra).to_ne_bytes());
    e.extend_from_slice(&[0u8, 0u8]); // flags, invflags
    debug_assert_eq!(e.len(), IPT_IP_LEN);
    e.extend_from_slice(&0u32.to_ne_bytes()); // nfcache
    e.extend_from_slice(
        &u16::try_from(target_offset)
            .unwrap_or(u16::MAX)
            .to_ne_bytes(),
    );
    e.extend_from_slice(&u16::try_from(next_offset).unwrap_or(u16::MAX).to_ne_bytes());
    e.extend_from_slice(&0u32.to_ne_bytes()); // comefrom
    e.extend_from_slice(&[0u8; XT_COUNTERS_LEN]);
    debug_assert_eq!(e.len(), IPT_ENTRY_LEN);
    e.extend_from_slice(&matches);
    // struct xt_standard_target: header with the empty name, then the verdict.
    match_header(&mut e, STANDARD_TARGET_LEN, "", 0);
    e.extend_from_slice(&rule.verdict.code().to_ne_bytes());
    e.extend_from_slice(&[0u8; 4]);
    e
}

/// The `ERROR` entry every table ends in.
fn encode_error_entry() -> Vec<u8> {
    let mut e = vec![0u8; IPT_IP_LEN];
    e.extend_from_slice(&0u32.to_ne_bytes());
    e.extend_from_slice(
        &u16::try_from(IPT_ENTRY_LEN)
            .unwrap_or(u16::MAX)
            .to_ne_bytes(),
    );
    e.extend_from_slice(
        &u16::try_from(IPT_ENTRY_LEN + ERROR_TARGET_LEN)
            .unwrap_or(u16::MAX)
            .to_ne_bytes(),
    );
    e.extend_from_slice(&0u32.to_ne_bytes());
    e.extend_from_slice(&[0u8; XT_COUNTERS_LEN]);
    match_header(&mut e, ERROR_TARGET_LEN, "ERROR", 0);
    put_name(&mut e, "ERROR", ERROR_TARGET_LEN - XT_HDR_LEN);
    e
}

/// The `filter` table, encoded: what follows the `ipt_replace` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterTable {
    /// The entries, back to back.
    pub entries: Vec<u8>,
    /// How many.
    pub num_entries: u32,
    /// Offset of each hook's first rule.
    pub hook_entry: [u32; NF_INET_NUMHOOKS],
    /// Offset of each hook's policy entry.
    pub underflow: [u32; NF_INET_NUMHOOKS],
}

impl FilterTable {
    /// Encode `policy` as the whole `filter` table.
    #[must_use]
    pub fn build(policy: &EgressPolicy) -> Self {
        let mut entries = Vec::new();
        let mut num_entries = 0u32;
        let mut hook_entry = [0u32; NF_INET_NUMHOOKS];
        let mut underflow = [0u32; NF_INET_NUMHOOKS];
        let offset = |v: &Vec<u8>| u32::try_from(v.len()).unwrap_or(u32::MAX);
        for (hook, rules, policy_verdict) in chains(policy) {
            hook_entry[hook] = offset(&entries);
            for rule in &rules {
                entries.extend_from_slice(&encode_rule(rule));
                num_entries += 1;
            }
            underflow[hook] = offset(&entries);
            entries.extend_from_slice(&encode_rule(&Rule::any(policy_verdict)));
            num_entries += 1;
        }
        entries.extend_from_slice(&encode_error_entry());
        num_entries += 1;
        Self {
            entries,
            num_entries,
            hook_entry,
            underflow,
        }
    }

    /// `struct ipt_replace` followed by the entries, with `num_counters` from
    /// `IPT_SO_GET_INFO` and the counters pointer left zero for the caller.
    #[must_use]
    pub fn replace_blob(&self, num_counters: u32) -> Vec<u8> {
        let mut b = Vec::with_capacity(IPT_REPLACE_LEN + self.entries.len());
        put_name(&mut b, "filter", XT_TABLE_MAXNAMELEN);
        b.extend_from_slice(&FILTER_VALID_HOOKS.to_ne_bytes());
        b.extend_from_slice(&self.num_entries.to_ne_bytes());
        b.extend_from_slice(
            &u32::try_from(self.entries.len())
                .unwrap_or(u32::MAX)
                .to_ne_bytes(),
        );
        for h in self.hook_entry {
            b.extend_from_slice(&h.to_ne_bytes());
        }
        for u in self.underflow {
            b.extend_from_slice(&u.to_ne_bytes());
        }
        b.extend_from_slice(&num_counters.to_ne_bytes());
        debug_assert_eq!(b.len(), IPT_REPLACE_COUNTERS_OFFSET);
        b.extend_from_slice(&0u64.to_ne_bytes()); // counters pointer
        b.extend_from_slice(&self.entries);
        b
    }
}

/// Why the fence could not be installed.
#[derive(Debug)]
pub enum FenceError {
    /// A policy line could not be enforced as written.
    Policy(PolicyError),
    /// A policy file exists and could not be read.
    Read(&'static str, std::io::Error),
    /// The kernel refused the table.
    Kernel(&'static str, std::io::Error),
}

impl std::fmt::Display for FenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy(e) => write!(f, "egress policy: {e}"),
            Self::Read(path, e) => write!(f, "egress policy: {path}: {e}"),
            Self::Kernel(step, e) => write!(f, "egress fence: {step}: {e}"),
        }
    }
}

impl std::error::Error for FenceError {}

/// What [`install_from_files`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum Fenced {
    /// Neither policy file exists: this guest layer carries no in-guest
    /// policy, and the host netns is the only fence — as it always was.
    NoPolicy,
    /// The table is in the kernel.
    Installed {
        /// `net.allow` entries.
        allow: usize,
        /// `net.deny` entries.
        deny: usize,
    },
}

/// Read [`NET_ALLOW`](nucleus_spec::guest_layout::NET_ALLOW) and
/// [`NET_DENY`](nucleus_spec::guest_layout::NET_DENY) and install the fence
/// they describe.
///
/// # Errors
/// A file that exists but cannot be read, a line that cannot be enforced, or a
/// kernel refusal. Each means a policy the image builder asked for is not in
/// force, and the caller refuses to boot.
pub fn install_from_files() -> Result<Fenced, FenceError> {
    use nucleus_spec::guest_layout::{NET_ALLOW, NET_DENY};
    let read = |path: &'static str| match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(FenceError::Read(path, e)),
    };
    let (allow, deny) = (read(NET_ALLOW)?, read(NET_DENY)?);
    if allow.is_none() && deny.is_none() {
        return Ok(Fenced::NoPolicy);
    }
    let policy =
        EgressPolicy::parse(allow.as_deref(), deny.as_deref()).map_err(FenceError::Policy)?;
    install(&policy)?;
    Ok(Fenced::Installed {
        allow: policy.allow.len(),
        deny: policy.deny.len(),
    })
}

/// Replace the kernel's `filter` table with `policy`'s.
///
/// # Errors
/// The step the kernel refused.
#[cfg(target_os = "linux")]
pub fn install(policy: &EgressPolicy) -> Result<(), FenceError> {
    use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType};
    use std::os::fd::AsRawFd;

    /// `IPT_BASE_CTL`: `IPT_SO_GET_INFO` and `IPT_SO_SET_REPLACE` share it.
    const IPT_SO_GET_INFO: libc::c_int = 64;
    const IPT_SO_SET_REPLACE: libc::c_int = 64;
    /// `sizeof(struct ipt_getinfo)`; `num_entries` is at offset 76.
    const IPT_GETINFO_LEN: usize = 84;

    let kernel = |step: &'static str| move |e: std::io::Error| FenceError::Kernel(step, e);

    // The socket needs no `unsafe` of ours: nix returns it already owned. The
    // two sockopt calls below do, because x_tables' ABI is a caller-sized
    // buffer the kernel both reads and writes (`IPT_SO_GET_INFO` takes the
    // table name *in* the buffer it fills), which no safe wrapper models.
    let sock = nix::sys::socket::socket(
        AddressFamily::Inet,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::Raw,
    )
    .map_err(|e| kernel("socket")(std::io::Error::from(e)))?;

    let mut info = [0u8; IPT_GETINFO_LEN];
    info[..6].copy_from_slice(b"filter");
    let mut len = libc::socklen_t::try_from(info.len()).unwrap_or(libc::socklen_t::MAX);
    // SAFETY: `info` is a live buffer of `len` bytes for the duration of the call.
    let rc = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IP,
            IPT_SO_GET_INFO,
            info.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(kernel("IPT_SO_GET_INFO")(std::io::Error::last_os_error()));
    }
    let num_counters = u32::from_ne_bytes([info[76], info[77], info[78], info[79]]);

    let table = FilterTable::build(policy);
    let mut blob = table.replace_blob(num_counters);
    // The kernel copies the old table's counters out through this pointer.
    let slots = usize::try_from(num_counters).unwrap_or(1).max(1);
    let mut counters = vec![0u8; slots.saturating_mul(XT_COUNTERS_LEN)];
    let ptr = u64::try_from(counters.as_mut_ptr().expose_provenance()).unwrap_or(0);
    blob[IPT_REPLACE_COUNTERS_OFFSET..IPT_REPLACE_COUNTERS_OFFSET + 8]
        .copy_from_slice(&ptr.to_ne_bytes());
    let blob_len = libc::socklen_t::try_from(blob.len()).unwrap_or(libc::socklen_t::MAX);
    // SAFETY: `blob` is live for `blob_len` bytes, and the pointer inside it
    // names `counters`, which outlives the call and is sized for
    // `num_counters` entries, as the kernel requires.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IP,
            IPT_SO_SET_REPLACE,
            blob.as_ptr().cast(),
            blob_len,
        )
    };
    if rc != 0 {
        return Err(kernel("IPT_SO_SET_REPLACE")(std::io::Error::last_os_error()));
    }
    drop(counters);
    Ok(())
}

/// Off Linux there is no kernel to install into; the encoder above is still
/// tested on every host.
///
/// # Errors
/// Always.
#[cfg(not(target_os = "linux"))]
pub fn install(_policy: &EgressPolicy) -> Result<(), FenceError> {
    Err(FenceError::Kernel(
        "install",
        std::io::Error::other("x_tables exists only on Linux"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(allow: &str, deny: &str) -> EgressPolicy {
        EgressPolicy::parse(Some(allow), Some(deny)).unwrap()
    }

    #[test]
    fn the_scripts_entry_shapes_parse() {
        let p = policy(
            "1.1.1.1:443\n10.0.0.0/8\n\n# a comment\n  9.9.9.9:53  \n",
            "169.254.169.254\n",
        );
        assert_eq!(
            p.allow,
            vec![
                Allow {
                    dest: Dest {
                        addr: Ipv4Addr::new(1, 1, 1, 1),
                        prefix: 32
                    },
                    port: Some(443)
                },
                Allow {
                    dest: Dest {
                        addr: Ipv4Addr::new(10, 0, 0, 0),
                        prefix: 8
                    },
                    port: None
                },
                Allow {
                    dest: Dest {
                        addr: Ipv4Addr::new(9, 9, 9, 9),
                        prefix: 32
                    },
                    port: Some(53)
                },
            ]
        );
        assert_eq!(
            p.deny,
            vec![Dest {
                addr: Ipv4Addr::new(169, 254, 169, 254),
                prefix: 32
            }]
        );
    }

    /// iptables masks the address it is given; so does this.
    #[test]
    fn a_cidr_is_masked() {
        assert_eq!(
            Dest::parse("10.1.2.3/8"),
            Some(Dest {
                addr: Ipv4Addr::new(10, 0, 0, 0),
                prefix: 8
            })
        );
        assert_eq!(
            Dest::parse("1.2.3.4/0").map(Dest::mask),
            Some(Ipv4Addr::UNSPECIFIED)
        );
    }

    /// A-1: a line that cannot be enforced as written is an error naming it,
    /// never a rule that means something else.
    #[test]
    fn an_unenforceable_line_is_named_not_skipped() {
        for bad in [
            "example.com:443",
            "1.2.3.4:http",
            "1.2.3.4:0",
            "1.2.3.4/33",
            "1.2.3.4:99999",
        ] {
            let err =
                EgressPolicy::parse(Some(&format!("1.1.1.1:443\n{bad}\n")), None).unwrap_err();
            assert_eq!(err.line, 2, "{bad}");
            assert_eq!(err.entry, bad);
        }
        // The deny list ignores a port, as `cut -d: -f1` did.
        assert!(EgressPolicy::parse(None, Some("1.2.3.4:whatever")).is_ok());
    }

    /// Entry sizes the kernel checks (`xt_check_entry_offsets`): every entry is
    /// 8-aligned, and each target sits exactly at its declared offset.
    #[test]
    fn every_entry_is_aligned_and_self_consistent() {
        let t = FilterTable::build(&policy("1.1.1.1:443\n10.0.0.0/8\n", "8.8.8.8\n"));
        let mut off = 0usize;
        let mut seen = 0u32;
        while off < t.entries.len() {
            let e = &t.entries[off..];
            let target_offset = usize::from(u16::from_ne_bytes([e[88], e[89]]));
            let next_offset = usize::from(u16::from_ne_bytes([e[90], e[91]]));
            assert_eq!(next_offset % 8, 0, "entry at {off} is not 8-aligned");
            let target_size =
                usize::from(u16::from_ne_bytes([e[target_offset], e[target_offset + 1]]));
            assert_eq!(target_offset + target_size, next_offset, "entry at {off}");
            off += next_offset;
            seen += 1;
        }
        assert_eq!(off, t.entries.len());
        assert_eq!(seen, t.num_entries);
    }

    /// The layout: INPUT(lo, ct, policy) FORWARD(policy) OUTPUT(lo, ct, tcp,
    /// udp, any, deny, policy) ERROR, with each hook entry and underflow at
    /// the offset the kernel will check, in ascending hook order.
    #[test]
    fn hooks_and_underflows_point_where_the_chains_are() {
        let t = FilterTable::build(&policy("1.1.1.1:443\n10.0.0.0/8\n", "8.8.8.8\n"));
        let plain = IPT_ENTRY_LEN + STANDARD_TARGET_LEN; // 152
        let ct = plain + XT_HDR_LEN + CONNTRACK_MTINFO3_LEN; // 352
        let port = plain + XT_HDR_LEN + 16; // 200
        assert_eq!((plain, ct, port), (152, 352, 200));
        let input = 0;
        let input_policy = input + plain + ct;
        let forward = input_policy + plain;
        let output = forward + plain;
        let output_policy = output + plain + ct + port + port + plain + plain;
        let expect = |v: [usize; 3]| v.map(|o| u32::try_from(o).unwrap());
        let expect = |v: [usize; 3]| {
            let [a, b, c] = expect(v);
            [0, a, b, c, 0]
        };
        assert_eq!(t.hook_entry, expect([input, forward, output]));
        assert_eq!(t.underflow, expect([input_policy, forward, output_policy]));
        assert_eq!(
            t.entries.len(),
            output_policy + plain + IPT_ENTRY_LEN + ERROR_TARGET_LEN
        );
        assert_eq!(t.num_entries, 3 + 1 + 7 + 1);
    }

    /// Golden bytes for the one rule shape with the most fields:
    /// `-A OUTPUT -d 1.1.1.1/32 -p tcp -m tcp --dport 443 -j ACCEPT`.
    #[test]
    fn a_tcp_allow_rule_encodes_exactly() {
        let rule = Rule {
            dest: Some(Dest {
                addr: Ipv4Addr::new(1, 1, 1, 1),
                prefix: 32,
            }),
            extra: Extra::TcpDport(443),
            ..Rule::any(Verdict::Accept)
        };
        let e = encode_rule(&rule);
        assert_eq!(e.len(), 200);
        assert_eq!(&e[4..8], &[1, 1, 1, 1], "dst");
        assert_eq!(&e[12..16], &[255, 255, 255, 255], "dmsk");
        assert_eq!(&e[16..80], &[0u8; 64][..], "no interfaces");
        assert_eq!(u16::from_ne_bytes([e[80], e[81]]), 6, "proto tcp");
        assert_eq!(u16::from_ne_bytes([e[88], e[89]]), 160, "target_offset");
        assert_eq!(u16::from_ne_bytes([e[90], e[91]]), 200, "next_offset");
        // the match
        assert_eq!(u16::from_ne_bytes([e[112], e[113]]), 48, "match_size");
        assert_eq!(&e[114..118], b"tcp\0");
        assert_eq!(e[143], 0, "revision");
        let ports: Vec<u16> = (0..4)
            .map(|i| u16::from_ne_bytes([e[144 + 2 * i], e[145 + 2 * i]]))
            .collect();
        assert_eq!(ports, vec![0, 65535, 443, 443]);
        // the target
        assert_eq!(u16::from_ne_bytes([e[160], e[161]]), 40, "target_size");
        assert_eq!(&e[162..191], &[0u8; 29][..], "standard target: empty name");
        assert_eq!(
            i32::from_ne_bytes([e[192], e[193], e[194], e[195]]),
            VERDICT_ACCEPT
        );
    }

    #[test]
    fn the_loopback_rule_matches_the_name_exactly() {
        let e = encode_rule(&Rule {
            out_iface: Some("lo"),
            ..Rule::any(Verdict::Accept)
        });
        assert_eq!(&e[32..35], b"lo\0", "outiface");
        assert_eq!(
            &e[64..67],
            &[0xff, 0xff, 0xff],
            "outiface_mask covers the NUL"
        );
        assert_eq!(e[67], 0);
        assert_eq!(&e[16..32], &[0u8; 16], "no iniface");
    }

    #[test]
    fn the_conntrack_match_asks_for_established_and_related() {
        let e = encode_rule(&Rule {
            extra: Extra::CtEstablished,
            ..Rule::any(Verdict::Accept)
        });
        let m = &e[IPT_ENTRY_LEN..];
        assert_eq!(u16::from_ne_bytes([m[0], m[1]]), 200);
        assert_eq!(&m[2..12], b"conntrack\0");
        assert_eq!(m[31], 3, "revision 3");
        let info = &m[XT_HDR_LEN..];
        assert_eq!(
            u16::from_ne_bytes([info[146], info[147]]),
            XT_CONNTRACK_STATE
        );
        assert_eq!(u16::from_ne_bytes([info[150], info[151]]), 0b110);
        assert_eq!(
            &info[152..CONNTRACK_MTINFO3_LEN],
            &[0u8; 16][..],
            "no status, no port ranges, padding"
        );
    }

    /// The policy entries are what `check_underflow` demands: unconditional,
    /// no matches, a standard DROP.
    #[test]
    fn every_policy_is_an_unconditional_drop() {
        let t = FilterTable::build(&policy("", ""));
        for hook in [NF_INET_LOCAL_IN, NF_INET_FORWARD, NF_INET_LOCAL_OUT] {
            let e = &t.entries[usize::try_from(t.underflow[hook]).unwrap()..];
            assert_eq!(&e[..IPT_IP_LEN], &[0u8; IPT_IP_LEN][..], "hook {hook}");
            assert_eq!(
                usize::from(u16::from_ne_bytes([e[88], e[89]])),
                IPT_ENTRY_LEN
            );
            assert_eq!(
                i32::from_ne_bytes([e[144], e[145], e[146], e[147]]),
                VERDICT_DROP,
                "hook {hook}"
            );
        }
    }

    #[test]
    fn the_replace_header_names_the_filter_table() {
        let t = FilterTable::build(&policy("", ""));
        let b = t.replace_blob(4);
        assert_eq!(&b[..7], b"filter\0");
        assert_eq!(u32::from_ne_bytes([b[32], b[33], b[34], b[35]]), 0b1110);
        assert_eq!(
            u32::from_ne_bytes([b[36], b[37], b[38], b[39]]),
            t.num_entries
        );
        assert_eq!(
            u32::from_ne_bytes([b[40], b[41], b[42], b[43]]),
            u32::try_from(t.entries.len()).unwrap()
        );
        assert_eq!(
            u32::from_ne_bytes([b[84], b[85], b[86], b[87]]),
            4,
            "num_counters"
        );
        assert_eq!(b.len(), IPT_REPLACE_LEN + t.entries.len());
    }

    /// PARITY with `guest-net.sh`, on a real kernel. Needs root and a scratch
    /// network namespace, so it is `#[ignore]`d; run it as
    /// `sudo unshare -n <test-binary> --ignored fence::tests::parity`.
    ///
    /// `EXPECTED` is `iptables-legacy-save -t filter` taken from a namespace in
    /// which `guest-net.sh` ran over this same `net.allow`/`net.deny` (counters
    /// and the header/trailer comments stripped). The encoder must produce a
    /// table the kernel accepts and that the reference tool reads back as the
    /// same rules, in the same order.
    #[test]
    #[ignore = "needs root in a scratch netns and iptables-legacy-save"]
    fn parity() {
        const EXPECTED: &str = include_str!("fence_parity.expected");
        let p = EgressPolicy::parse(Some(PARITY_ALLOW), Some(PARITY_DENY)).unwrap();
        install(&p).unwrap();
        let out = std::process::Command::new("iptables-legacy-save")
            .args(["-t", "filter"])
            .output()
            .unwrap();
        assert!(out.status.success());
        let got: Vec<String> = String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with('#'))
            .map(|l| l.split(" [").next().unwrap_or(l).to_string())
            .collect();
        let want: Vec<&str> = EXPECTED.lines().collect();
        assert_eq!(got, want);
    }

    /// The input `fence_parity.expected` was produced from with `guest-net.sh`.
    const PARITY_ALLOW: &str = "1.0.0.1:443\n10.20.0.0/16\n9.9.9.9:53\n";
    const PARITY_DENY: &str = "169.254.169.254\n8.8.8.8:53\n";
}

//! Is this process confined the way ADR 0015 §7 says? Read from the kernel,
//! never assumed.
//!
//! The node starts the proxy in a fresh network namespace, as the pod's
//! unprivileged uid, with no capabilities, `no_new_privs` and a syscall
//! filter. The proxy refuses to serve unless it can see each of those from
//! inside ([`check_status`], [`check_interfaces`]), and the node reads the
//! same `/proc/<pid>/status` through the same [`check_status`] from outside
//! (ADR 0007 G-1: one reader of "confined"). Landlock is the proxy's own last
//! step, after these reads, because it takes away `/proc` too.

/// Evidence that a `/proc/<pid>/status` showed a confined process. Minted
/// only by [`check_status`] (ADR 0007 C-1, C-2).
#[derive(Debug, PartialEq, Eq)]
pub struct Confined {
    uid: u32,
}

impl Confined {
    /// The uid it runs as (never 0).
    pub const fn uid(&self) -> u32 {
        self.uid
    }
}

/// What was missing. Each its own reason (ADR 0007 I-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unconfined {
    /// A line `check_status` reads was absent or unparseable: could not
    /// look, which is not "looked and it was fine" (ADR 0007 A-2).
    Unreadable(&'static str),
    /// Some uid (real, effective, saved or filesystem) is 0.
    Root,
    /// `CapEff`, `CapPrm` or `CapAmb` is not empty.
    Capabilities,
    /// `NoNewPrivs` is not 1.
    NoNewPrivs,
    /// `Seccomp` is not 2 (filter mode).
    NoSyscallFilter,
    /// A network interface other than `lo` exists: this is not the fresh,
    /// route-less namespace the node promised.
    Interface(String),
}

impl std::fmt::Display for Unconfined {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unconfined::Unreadable(field) => write!(f, "cannot read {field} from the status"),
            Unconfined::Root => f.write_str("runs with a uid of 0"),
            Unconfined::Capabilities => f.write_str("holds capabilities"),
            Unconfined::NoNewPrivs => f.write_str("no_new_privs is not set"),
            Unconfined::NoSyscallFilter => f.write_str("no seccomp filter is installed"),
            Unconfined::Interface(name) => write!(f, "has network interface {name}"),
        }
    }
}

fn field<'a>(status: &'a str, name: &'static str) -> Result<&'a str, Unconfined> {
    status
        .lines()
        .find_map(|l| l.strip_prefix(name)?.strip_prefix(':'))
        .map(str::trim)
        .ok_or(Unconfined::Unreadable(name))
}

/// Check a `/proc/<pid>/status` text.
///
/// # Errors
/// The first [`Unconfined`] reason found.
pub fn check_status(status: &str) -> Result<Confined, Unconfined> {
    let uids: Vec<u32> = field(status, "Uid")?
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .map_err(|_| Unconfined::Unreadable("Uid"))?;
    let [real, effective, saved, fs] = uids[..] else {
        return Err(Unconfined::Unreadable("Uid"));
    };
    if [real, effective, saved, fs].contains(&0) {
        return Err(Unconfined::Root);
    }
    for cap in ["CapEff", "CapPrm", "CapAmb"] {
        let mask = u64::from_str_radix(field(status, cap)?, 16)
            .map_err(|_| Unconfined::Unreadable(cap))?;
        if mask != 0 {
            return Err(Unconfined::Capabilities);
        }
    }
    if field(status, "NoNewPrivs")? != "1" {
        return Err(Unconfined::NoNewPrivs);
    }
    if field(status, "Seccomp")? != "2" {
        return Err(Unconfined::NoSyscallFilter);
    }
    Ok(Confined { uid: effective })
}

/// Check a `/proc/self/net/dev` text: only `lo` may exist.
///
/// # Errors
/// [`Unconfined::Interface`] naming the first other interface, or
/// [`Unconfined::Unreadable`] if the text has no interface table.
pub fn check_interfaces(net_dev: &str) -> Result<(), Unconfined> {
    let mut rows = 0usize;
    // Two header lines, then `  name: counters…`.
    for line in net_dev.lines().skip(2) {
        let name = line
            .split_once(':')
            .map(|(n, _)| n.trim())
            .ok_or(Unconfined::Unreadable("net/dev"))?;
        if name != "lo" {
            return Err(Unconfined::Interface(name.to_string()));
        }
        rows = rows.saturating_add(1);
    }
    if rows == 0 {
        return Err(Unconfined::Unreadable("net/dev"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(uid: &str, cap: &str, nnp: &str, seccomp: &str) -> String {
        format!(
            "Name:\tnucleus-egress-proxy\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n\
             CapPrm:\t{cap}\nCapEff:\t{cap}\nCapAmb:\t0000000000000000\n\
             NoNewPrivs:\t{nnp}\nSeccomp:\t{seccomp}\n"
        )
    }

    const NONE: &str = "0000000000000000";

    #[test]
    fn a_confined_status_is_evidence() {
        assert_eq!(
            check_status(&status("123", NONE, "1", "2")).map(|c| c.uid()),
            Ok(123)
        );
    }

    #[test]
    fn each_missing_layer_is_named() {
        assert_eq!(
            check_status(&status("0", NONE, "1", "2")),
            Err(Unconfined::Root)
        );
        assert_eq!(
            check_status(&status("123", "0000000000003000", "1", "2")),
            Err(Unconfined::Capabilities)
        );
        assert_eq!(
            check_status(&status("123", NONE, "0", "2")),
            Err(Unconfined::NoNewPrivs)
        );
        assert_eq!(
            check_status(&status("123", NONE, "1", "0")),
            Err(Unconfined::NoSyscallFilter)
        );
        assert_eq!(
            check_status("Name:\tx\n"),
            Err(Unconfined::Unreadable("Uid"))
        );
    }

    #[test]
    fn only_loopback_may_exist() {
        let head = "Inter-|   Receive\n face |bytes\n";
        assert_eq!(check_interfaces(&format!("{head}    lo: 0 0\n")), Ok(()));
        assert_eq!(
            check_interfaces(&format!("{head}    lo: 0 0\n  eth0: 1 2\n")),
            Err(Unconfined::Interface("eth0".into()))
        );
        assert_eq!(
            check_interfaces(head),
            Err(Unconfined::Unreadable("net/dev"))
        );
    }
}

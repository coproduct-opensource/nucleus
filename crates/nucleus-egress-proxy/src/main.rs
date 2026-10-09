//! `nucleus-egress-proxy`: one eval cell's host egress proxy (ADR 0015 §7).
//!
//! Started by the node, never by hand. The node hands it two descriptors and
//! nothing else:
//!
//! * **stdin** is the listening socket the guest reaches over vsock 1029
//!   (`HostListener::Vsock(VsockListener::EgressProxy)`), bound by the node
//!   through its one typed helper;
//! * **stdout** is the proxy's end of a socketpair whose other end is the
//!   node's decision service for this pod.
//!
//! The node has already put the process in a fresh network namespace, as an
//! unprivileged uid, with no capabilities, `no_new_privs` and its syscall
//! filter. This binary checks each of those from inside and refuses to serve
//! if any is missing, then gives up all filesystem access (Landlock) and
//! serves. It holds no node key and no policy: every request is decided by
//! the node.
//!
//! Exit status 2 is a refusal to start, with the reason on stderr.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic,
        clippy::unreachable,
        clippy::todo
    )
)]

use std::process::ExitCode;

use ipnet::IpNet;

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(reason) => {
            tracing::error!(%reason, "egress proxy refused to start");
            ExitCode::from(2)
        }
    }
}

/// `--deny-floor <cidr>`, repeated. At least one: the node always passes
/// its floor, so an empty one is a broken spawn, not an empty policy.
fn deny_floor() -> Result<Vec<IpNet>, String> {
    let mut floor = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--deny-floor" => {
                let net = args.next().ok_or("--deny-floor needs a CIDR")?;
                floor.push(
                    net.parse::<IpNet>()
                        .map_err(|e| format!("--deny-floor {net}: {e}"))?,
                );
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if floor.is_empty() {
        return Err("no --deny-floor given".into());
    }
    Ok(floor)
}

#[cfg(not(target_os = "linux"))]
fn run() -> Result<(), String> {
    deny_floor()?;
    Err(
        "the egress proxy's sandbox (network namespace, seccomp, Landlock) exists only on Linux"
            .into(),
    )
}

#[cfg(target_os = "linux")]
fn run() -> Result<(), String> {
    use std::os::fd::AsFd;
    use std::sync::Arc;

    use nucleus_egress_proxy::decision::{DECISION_DEADLINE, SharedDecider};
    use nucleus_egress_proxy::posture::{check_interfaces, check_status};
    use nucleus_egress_proxy::resolve::NoOutboundPath;
    use nucleus_egress_proxy::serve::Proxy;

    let floor = deny_floor()?;

    // What the node did, read from the kernel before Landlock takes /proc.
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|e| format!("cannot read /proc/self/status: {e}"))?;
    let confined = check_status(&status).map_err(|e| format!("not confined: {e}"))?;
    let net_dev = std::fs::read_to_string("/proc/self/net/dev")
        .map_err(|e| format!("cannot read /proc/self/net/dev: {e}"))?;
    check_interfaces(&net_dev).map_err(|e| format!("not network-isolated: {e}"))?;

    // The two descriptors, as owned sockets, before the filesystem goes.
    let listener = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map(std::os::unix::net::UnixListener::from)
        .map_err(|e| format!("stdin is not the guest listener: {e}"))?;
    let decisions = std::io::stdout()
        .as_fd()
        .try_clone_to_owned()
        .map(std::os::unix::net::UnixStream::from)
        .map_err(|e| format!("stdout is not the decision channel: {e}"))?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    decisions.set_nonblocking(true).map_err(|e| e.to_string())?;

    no_filesystem()?;
    tracing::info!(uid = confined.uid(), floor = ?floor, "egress proxy confined and serving");

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    runtime.block_on(async move {
        let listener = tokio::net::UnixListener::from_std(listener).map_err(|e| e.to_string())?;
        let decisions = tokio::net::UnixStream::from_std(decisions).map_err(|e| e.to_string())?;
        let proxy = Proxy::new(
            SharedDecider::new(decisions, DECISION_DEADLINE),
            NoOutboundPath,
            floor,
        );
        Arc::new(proxy).serve(listener).await;
        Ok(())
    })
}

/// Landlock with every filesystem right handled and none granted: no open,
/// no create, no exec, anywhere. Fully enforced or the proxy does not start.
#[cfg(target_os = "linux")]
fn no_filesystem() -> Result<(), String> {
    use landlock::{
        ABI, Access, AccessFs, CompatLevel, Compatible, Ruleset, RulesetAttr, RulesetStatus,
    };
    let status = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(ABI::V2))
        .and_then(|r| r.create())
        .and_then(|r| r.restrict_self())
        .map_err(|e| format!("Landlock: {e}"))?;
    match status.ruleset {
        RulesetStatus::FullyEnforced => Ok(()),
        RulesetStatus::PartiallyEnforced | RulesetStatus::NotEnforced => {
            Err(format!("Landlock not fully enforced: {:?}", status.ruleset))
        }
    }
}

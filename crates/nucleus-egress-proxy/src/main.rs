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
//! With `--mode link` (ADR 0017 L4b) stdin is the pod's link listener
//! (vsock 1030, `VsockListener::PodLink`) instead, `--link-control-socket PATH`
//! names the node's control socket for `LINK`/`SEVER` lines, and there
//! is no `--deny-floor`: a link proxy reaches only the pods the node routes.
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

/// `--deny-floor <cidr>`, repeated. At least one in egress mode: the node
/// always passes its floor, so an empty one is a broken spawn, not an empty
/// policy.
///
/// `--tls-ca-channel` (ADR 0015 E3): the pod CA bundle is the first thing on
/// the decision channel (`tls::read_bundle`), read once before serving.
/// Without it, `CONNECT` is refused as in E2. The key is never in argv, the
/// environment or a file. (An inherited descriptor cannot carry it: the
/// confinement hook closes every descriptor from 3 up on exec.)
///
/// `--mode link --link-control-socket <path>` (ADR 0017 L4b): the node binds
/// and owns a Unix socket at an absolute path it chooses; the proxy connects
/// once at start, before Landlock, and reads `LINK`/`SEVER` lines from it.
fn deny_floor() -> Result<Args, String> {
    let mut floor = Vec::new();
    let mut tls_ca_channel = false;
    let mut link = false;
    let mut link_control: Option<std::path::PathBuf> = None;
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
            "--tls-ca-channel" => {
                if std::mem::replace(&mut tls_ca_channel, true) {
                    return Err("--tls-ca-channel given twice".into());
                }
            }
            "--mode" => match args.next().as_deref() {
                Some("egress") => link = false,
                Some("link") => link = true,
                other => return Err(format!("--mode {other:?}: egress or link")),
            },
            "--link-control-socket" => {
                let p = std::path::PathBuf::from(
                    args.next().ok_or("--link-control-socket needs a path")?,
                );
                if !p.is_absolute() {
                    return Err(format!(
                        "--link-control-socket {}: not an absolute path",
                        p.display()
                    ));
                }
                if link_control.replace(p).is_some() {
                    return Err("--link-control-socket given twice".into());
                }
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if link {
        let control = link_control.ok_or("--mode link needs --link-control-socket")?;
        if !floor.is_empty() {
            return Err("--deny-floor is for egress mode; a link proxy has no address path".into());
        }
        return Ok(Args {
            floor,
            tls_ca_channel,
            link_control: Some(control),
        });
    }
    if link_control.is_some() {
        return Err("--link-control-socket is for --mode link".into());
    }
    if floor.is_empty() {
        return Err("no --deny-floor given".into());
    }
    Ok(Args {
        floor,
        tls_ca_channel,
        link_control: None,
    })
}

/// What the node passed.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct Args {
    floor: Vec<IpNet>,
    tls_ca_channel: bool,
    /// `Some` in link mode (ADR 0017 L4b): the node's control socket, which
    /// carries `LINK`/`SEVER` lines (`link::Links::follow`).
    link_control: Option<std::path::PathBuf>,
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
    use nucleus_egress_proxy::link::{self, Links};
    use nucleus_egress_proxy::posture::{check_interfaces, check_status};
    use nucleus_egress_proxy::resolve::NoOutboundPath;
    use nucleus_egress_proxy::serve::Proxy;
    use nucleus_egress_proxy::tls::{Termination, now_unix};

    let Args {
        floor,
        tls_ca_channel,
        link_control,
    } = deny_floor()?;

    // What the node did, read from the kernel before Landlock takes /proc.
    let status = std::fs::read_to_string("/proc/self/status")
        .map_err(|e| format!("cannot read /proc/self/status: {e}"))?;
    let confined = check_status(&status).map_err(|e| format!("not confined: {e}"))?;
    let net_dev = std::fs::read_to_string("/proc/self/net/dev")
        .map_err(|e| format!("cannot read /proc/self/net/dev: {e}"))?;
    check_interfaces(&net_dev).map_err(|e| format!("not network-isolated: {e}"))?;

    // The two descriptors, as owned sockets.
    let listener = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map(std::os::unix::net::UnixListener::from)
        .map_err(|e| format!("stdin is not the guest listener: {e}"))?;
    let mut decisions = std::io::stdout()
        .as_fd()
        .try_clone_to_owned()
        .map(std::os::unix::net::UnixStream::from)
        .map_err(|e| format!("stdout is not the decision channel: {e}"))?;

    // The pod CA (E3): the head of the decision channel, before any frame.
    let ca = if tls_ca_channel {
        Some(read_ca(&mut decisions)?)
    } else {
        None
    };

    // The link control socket (L4b), connected while the path is reachable.
    let control = match &link_control {
        None => None,
        Some(path) => Some(
            std::os::unix::net::UnixStream::connect(path)
                .map_err(|e| format!("--link-control-socket {}: {e}", path.display()))?,
        ),
    };
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
        let decider = SharedDecider::new(decisions, DECISION_DEADLINE);
        let proxy = match control {
            None => {
                let proxy = Proxy::new(decider, NoOutboundPath, floor);
                match ca {
                    Some(ca) => {
                        proxy.with_tls(Termination::new(ca, Termination::webpki(), now_unix)?)
                    }
                    None => proxy,
                }
            }
            Some(control) => {
                control.set_nonblocking(true).map_err(|e| e.to_string())?;
                let control =
                    tokio::net::UnixStream::from_std(control).map_err(|e| e.to_string())?;
                let links = Arc::new(Links::default());
                let follow = Arc::clone(&links);
                tokio::spawn(async move { follow.follow(control).await });
                let proxy = Proxy::link(decider, Arc::clone(&links));
                match ca {
                    Some(ca) => proxy.with_tls(link::termination(
                        ca,
                        Termination::webpki(),
                        now_unix,
                        &links,
                    )?),
                    None => proxy,
                }
            }
        };
        Arc::new(proxy).serve(listener).await;
        Ok(())
    })
}

/// Read the pod CA bundle off the head of the decision channel, bounded in
/// size and time. Not gated to Linux, so it is type-checked everywhere.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn read_ca(
    decisions: &mut std::os::unix::net::UnixStream,
) -> Result<nucleus_egress_proxy::tls::PodCa, String> {
    use nucleus_egress_proxy::tls::{PodCa, read_bundle};

    decisions
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .map_err(|e| format!("--tls-ca-channel: {e}"))?;
    let bundle = read_bundle(decisions).map_err(|e| format!("--tls-ca-channel: {e}"))?;
    decisions
        .set_read_timeout(None)
        .map_err(|e| format!("--tls-ca-channel: {e}"))?;
    PodCa::from_bundle(&bundle).map_err(|e| format!("--tls-ca-channel: {e}"))
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

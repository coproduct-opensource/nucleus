//! Recycle a network lease only after successful inventory proves its resources absent.
use std::process::Output;
use std::time::Duration;

use super::{NetPlan, host_link};
use crate::ApiError;
use ipnet::IpNet;

#[tonic::async_trait]
trait Runner {
    async fn run(&self, program: &str, args: &[String]) -> Result<Output, ApiError>;
}

struct System;
#[tonic::async_trait]
impl Runner for System {
    async fn run(&self, program: &str, args: &[String]) -> Result<Output, ApiError> {
        tokio::time::timeout(
            Duration::from_secs(10),
            tokio::process::Command::new(program)
                .args(args)
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(|_| ApiError::Driver(format!("network cleanup command {program} timed out")))?
        .map_err(ApiError::Io)
    }
}

fn words(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

async fn observed(runner: &impl Runner, program: &str, args: &[&str]) -> Result<String, ApiError> {
    let output = runner.run(program, &words(args)).await?;
    if !output.status.success() {
        return Err(ApiError::Driver(format!(
            "cannot confirm network cleanup: {program} exited {}",
            output.status
        )));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| ApiError::Driver(format!("invalid {program} inventory encoding")))
}

async fn namespace_with(runner: &impl Runner, name: &str) -> Result<(), ApiError> {
    // Deletion may report absence. Only a successful subsequent inventory can
    // distinguish that from a permission or command failure.
    let _ = runner.run("ip", &words(&["netns", "del", name])).await?;
    let namespaces = observed(runner, "ip", &["netns", "list"]).await?;
    if namespaces
        .lines()
        .any(|line| line.split_whitespace().next() == Some(name))
    {
        return Err(ApiError::Driver(format!(
            "network namespace {name} remains after cleanup"
        )));
    }
    Ok(())
}

async fn network_with(runner: &impl Runner, plan: &mut NetPlan) -> Result<(), ApiError> {
    if plan.lease.is_none() {
        return Ok(());
    }
    for rule in host_link::host_link_rules(&plan.host_veth, plan.subnet) {
        let mut args = words(&["-w", "5"]);
        args.extend(rule.delete_argv());
        let _ = runner.run("iptables", &args).await?;
    }
    let _ = runner
        .run("ip", &words(&["link", "del", &plan.host_veth]))
        .await?;
    namespace_with(runner, &plan.netns).await?;
    let subnet = plan.subnet.to_string();
    confirm_link_released(runner, &plan.host_veth, Some(&subnet)).await?;
    // Consuming this unique lease makes a second recycle impossible, even if
    // the retired plan is observed again after its index has been reassigned.
    if let Some(lease) = plan.lease.take()
        && let Err(lease) = lease.release()
    {
        plan.lease = Some(lease);
        return Err(ApiError::Driver("network allocator lock poisoned".into()));
    }
    Ok(())
}

/// Confirm, from inventory, that no host link named `host_veth` exists and that the host firewall
/// no longer names it (or `subnet`, when known). One check, shared by a live pod's release and the
/// startup reclaim of a stranded one, so the two cannot disagree about what "released" means.
async fn confirm_link_released(
    runner: &impl Runner,
    host_veth: &str,
    subnet: Option<&str>,
) -> Result<(), ApiError> {
    let links = observed(runner, "ip", &["-j", "link", "show"]).await?;
    #[derive(serde::Deserialize)]
    struct Link {
        ifname: String,
    }
    let links: Vec<Link> = serde_json::from_str(&links)
        .map_err(|e| ApiError::Driver(format!("invalid network link inventory: {e}")))?;
    if links.iter().any(|link| link.ifname == host_veth) {
        return Err(ApiError::Driver(format!(
            "network link {host_veth} remains after cleanup"
        )));
    }
    let rules = observed(runner, "iptables-save", &[]).await?;
    if rules
        .lines()
        .filter(|line| line.starts_with("-A "))
        .any(|line| {
            line.split_whitespace()
                .map(|word| word.trim_matches('"'))
                .any(|word| word == host_veth || Some(word) == subnet)
        })
    {
        return Err(ApiError::Driver(
            "host firewall still refers to the network allocation".into(),
        ));
    }
    Ok(())
}

/// The processes inside the network namespace `name`, or `None` when it does not exist.
///
/// Membership is the kernel's (`ip netns pids` compares namespace inodes), not a process name:
/// it finds a stranded pod's jailed VMM (the jailer joins the namespace with `--netns`) and its
/// dnsmasq (started under `ip netns exec`), and nothing that merely shares their name.
async fn netns_pids_with(runner: &impl Runner, name: &str) -> Result<Option<Vec<i32>>, ApiError> {
    let namespaces = observed(runner, "ip", &["netns", "list"]).await?;
    if !namespaces
        .lines()
        .any(|line| line.split_whitespace().next() == Some(name))
    {
        return Ok(None);
    }
    let pids = observed(runner, "ip", &["netns", "pids", name]).await?;
    pids.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.parse::<i32>().map_err(|_| {
                ApiError::Driver(format!("invalid pid {line:?} in network namespace {name}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

/// The link subnet of `host_veth`, read from the address the node gave it, or `None` when the
/// link does not exist. The allocator restarts at index 0 in a new life, so the stranded pod's
/// subnet is only recoverable from the kernel.
async fn link_subnet(runner: &impl Runner, host_veth: &str) -> Result<Option<IpNet>, ApiError> {
    let addrs = observed(runner, "ip", &["-j", "addr", "show"]).await?;
    #[derive(serde::Deserialize)]
    struct Addr {
        family: String,
        local: std::net::IpAddr,
        prefixlen: u8,
    }
    #[derive(serde::Deserialize)]
    struct Link {
        ifname: String,
        #[serde(default)]
        addr_info: Vec<Addr>,
    }
    let links: Vec<Link> = serde_json::from_str(&addrs)
        .map_err(|e| ApiError::Driver(format!("invalid network address inventory: {e}")))?;
    let Some(link) = links.into_iter().find(|link| link.ifname == host_veth) else {
        return Ok(None);
    };
    let Some(addr) = link.addr_info.into_iter().find(|a| a.family == "inet") else {
        return Ok(None);
    };
    IpNet::new(addr.local, addr.prefixlen)
        .map(|net| Some(net.trunc()))
        .map_err(|e| ApiError::Driver(format!("invalid address on {host_veth}: {e}")))
}

/// Release what a pod of a PREVIOUS node life left in the host namespace: its host-link firewall
/// rules, its host veth and its namespace, confirmed absent by the same inventory a live release
/// uses. Its processes must already be dead (`jail_reclaim`), or the namespace delete only
/// detaches a name from a namespace they still hold.
async fn stranded_with(runner: &impl Runner, netns: &str, host_veth: &str) -> Result<(), ApiError> {
    let subnet = link_subnet(runner, host_veth).await?;
    if let Some(subnet) = subnet {
        for rule in host_link::host_link_rules(host_veth, subnet) {
            let mut args = words(&["-w", "5"]);
            args.extend(rule.delete_argv());
            let _ = runner.run("iptables", &args).await?;
        }
        let _ = runner
            .run("ip", &words(&["link", "del", host_veth]))
            .await?;
    }
    namespace_with(runner, netns).await?;
    let subnet = subnet.map(|net| net.to_string());
    confirm_link_released(runner, host_veth, subnet.as_deref()).await
}

pub(super) async fn netns_pids(name: &str) -> Result<Option<Vec<i32>>, ApiError> {
    if !cfg!(target_os = "linux") {
        return Err(ApiError::Driver("network namespaces require Linux".into()));
    }
    netns_pids_with(&System, name).await
}

pub(super) async fn stranded(netns: &str, host_veth: &str) -> Result<(), ApiError> {
    if !cfg!(target_os = "linux") {
        return Err(ApiError::Driver("network cleanup requires Linux".into()));
    }
    stranded_with(&System, netns, host_veth).await
}

pub(super) async fn network(plan: &mut NetPlan) -> Result<(), ApiError> {
    if !cfg!(target_os = "linux") {
        return Err(ApiError::Driver("network cleanup requires Linux".into()));
    }
    network_with(&System, plan).await
}

pub(super) async fn namespace(name: &str) -> Result<(), ApiError> {
    if !cfg!(target_os = "linux") {
        return Err(ApiError::Driver("network cleanup requires Linux".into()));
    }
    namespace_with(&System, name).await
}

/// Recycle against an inventory reporting everything absent: the real lease logic, unprivileged.
#[cfg(test)]
pub(super) async fn network_confirmed_absent(plan: &mut NetPlan) -> Result<(), ApiError> {
    network_with(&tests::Fixture::absent(), plan).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::NetworkAllocator;
    use std::{os::unix::process::ExitStatusExt, sync::Mutex};

    pub(super) struct Fixture {
        namespaces: String,
        links: String,
        addrs: String,
        pids: String,
        rules: String,
        inventory_available: bool,
        commands: Mutex<Vec<String>>,
    }
    impl Fixture {
        pub(super) fn absent() -> Self {
            Self {
                namespaces: "unrelated (id: 4)\n".into(),
                links: r#"[{"ifname":"lo"}]"#.into(),
                addrs: r#"[{"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8}]}]"#.into(),
                pids: String::new(),
                rules: "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n".into(),
                inventory_available: true,
                commands: Mutex::new(Vec::new()),
            }
        }
    }
    #[tonic::async_trait]
    impl Runner for Fixture {
        async fn run(&self, program: &str, args: &[String]) -> Result<Output, ApiError> {
            self.commands
                .lock()
                .unwrap()
                .push(format!("{program} {}", args.join(" ")));
            let stdout = match (program, args.first().map(String::as_str)) {
                ("ip", Some("-j")) if args.get(1).map(String::as_str) == Some("addr") => {
                    &self.addrs
                }
                ("ip", Some("-j")) => &self.links,
                ("ip", Some("netns")) if args.get(1).map(String::as_str) == Some("pids") => {
                    &self.pids
                }
                ("ip", Some("netns")) if args.get(1).map(String::as_str) == Some("list") => {
                    &self.namespaces
                }
                ("iptables-save", None) => &self.rules,
                _ => {
                    return Ok(Output {
                        status: std::process::ExitStatus::from_raw(256),
                        stdout: Vec::new(),
                        stderr: b"already absent".to_vec(),
                    });
                }
            };
            Ok(Output {
                status: std::process::ExitStatus::from_raw(if self.inventory_available {
                    0
                } else {
                    256
                }),
                stdout: stdout.as_bytes().to_vec(),
                stderr: Vec::new(),
            })
        }
    }

    #[tokio::test]
    async fn confirmed_absence_recycles_once_and_retired_plan_does_not_delete_again() {
        let allocator = NetworkAllocator::new();
        let mut plan = allocator
            .allocate(uuid::Uuid::new_v4(), "ordinary".into())
            .unwrap();
        let index = plan.index();
        let fixture = Fixture::absent();
        network_with(&fixture, &mut plan).await.unwrap();
        let successor = allocator
            .allocate(uuid::Uuid::new_v4(), "successor".into())
            .unwrap();
        assert_eq!(successor.index(), index);
        let calls = fixture.commands.lock().unwrap().len();
        network_with(&fixture, &mut plan).await.unwrap();
        assert_eq!(fixture.commands.lock().unwrap().len(), calls);
        let next = allocator
            .allocate(uuid::Uuid::new_v4(), "next".into())
            .unwrap();
        assert_ne!(next.index(), successor.index());
    }

    #[tokio::test]
    async fn incomplete_cleanup_retains_ownership_and_can_retry() {
        for remaining in ["namespace", "link", "rule", "inventory"] {
            let allocator = NetworkAllocator::new();
            let mut plan = allocator
                .allocate(uuid::Uuid::new_v4(), "ordinary".into())
                .unwrap();
            let index = plan.index();
            let mut fixture = Fixture::absent();
            match remaining {
                "namespace" => fixture.namespaces = "ordinary (id: 1)\n".into(),
                "link" => {
                    fixture.links = serde_json::json!([{"ifname":plan.host_veth}]).to_string()
                }
                "rule" => {
                    fixture.rules = format!(
                        "*nat\n-A POSTROUTING -s {} -j MASQUERADE\nCOMMIT\n",
                        plan.subnet
                    )
                }
                "inventory" => fixture.inventory_available = false,
                _ => unreachable!(),
            }
            assert!(
                network_with(&fixture, &mut plan).await.is_err(),
                "{remaining}"
            );
            assert!(plan.lease.is_some());
            let other = allocator
                .allocate(uuid::Uuid::new_v4(), "other".into())
                .unwrap();
            assert_ne!(other.index(), index);
            network_with(&Fixture::absent(), &mut plan).await.unwrap();
            let reused = allocator
                .allocate(uuid::Uuid::new_v4(), "reused".into())
                .unwrap();
            assert_eq!(reused.index(), index);
        }
    }

    /// A stranded pod's link is released by the subnet READ FROM ITS VETH, not one the new
    /// node's allocator would assign: a restarted allocator starts again at index 0.
    #[tokio::test]
    async fn a_stranded_link_is_released_by_the_subnet_its_veth_carries() {
        let mut fixture = Fixture::absent();
        fixture.addrs = r#"[{"ifname":"veth0badc0de","addr_info":[
            {"family":"inet6","local":"fe80::1","prefixlen":64},
            {"family":"inet","local":"10.200.0.13","prefixlen":30}]}]"#
            .into();
        stranded_with(&fixture, "nuc-0badc0de", "veth0badc0de")
            .await
            .unwrap();
        let commands = fixture.commands.lock().unwrap().clone();
        let deletes: Vec<&String> = commands
            .iter()
            .filter(|c| c.starts_with("iptables -w 5 -t") && c.contains(" -D "))
            .collect();
        assert_eq!(
            deletes.len(),
            host_link::host_link_rules("veth0badc0de", "10.200.0.12/30".parse().unwrap()).len(),
            "every host-link rule is deleted: {commands:?}"
        );
        assert!(
            deletes.iter().any(|c| c.contains("-s 10.200.0.12/30")),
            "the MASQUERADE rule is named by the veth's own subnet: {commands:?}"
        );
        assert!(commands.iter().any(|c| c == "ip link del veth0badc0de"));
        assert!(commands.iter().any(|c| c == "ip netns del nuc-0badc0de"));
    }

    /// A leftover the inventory still shows is an error, never a quiet success (ADR 0007 A-2).
    #[tokio::test]
    async fn a_stranded_link_whose_rules_remain_is_not_reported_released() {
        let mut fixture = Fixture::absent();
        fixture.rules = "*filter\n-A INPUT -i veth0badc0de -j DROP\nCOMMIT\n".into();
        assert!(
            stranded_with(&fixture, "nuc-0badc0de", "veth0badc0de")
                .await
                .is_err()
        );
        let mut fixture = Fixture::absent();
        fixture.namespaces = "nuc-0badc0de (id: 3)\n".into();
        assert!(
            stranded_with(&fixture, "nuc-0badc0de", "veth0badc0de")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn namespace_members_are_read_only_from_an_existing_namespace() {
        let mut fixture = Fixture::absent();
        assert_eq!(
            netns_pids_with(&fixture, "nuc-0badc0de").await.unwrap(),
            None
        );
        fixture.namespaces = "nuc-0badc0de (id: 3)\nother\n".into();
        fixture.pids = "4242\n4343\n".into();
        assert_eq!(
            netns_pids_with(&fixture, "nuc-0badc0de").await.unwrap(),
            Some(vec![4242, 4343])
        );
        fixture.inventory_available = false;
        assert!(
            netns_pids_with(&fixture, "nuc-0badc0de").await.is_err(),
            "could not look is not 'no members'"
        );
    }
}

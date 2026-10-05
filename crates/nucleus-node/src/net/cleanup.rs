//! Recycle a network lease only after successful inventory proves its resources absent.
use std::process::Output;
use std::time::Duration;

use super::{NetPlan, host_link};
use crate::ApiError;

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
    let links = observed(runner, "ip", &["-j", "link", "show"]).await?;
    #[derive(serde::Deserialize)]
    struct Link {
        ifname: String,
    }
    let links: Vec<Link> = serde_json::from_str(&links)
        .map_err(|e| ApiError::Driver(format!("invalid network link inventory: {e}")))?;
    if links.iter().any(|link| link.ifname == plan.host_veth) {
        return Err(ApiError::Driver(format!(
            "network link {} remains after cleanup",
            plan.host_veth
        )));
    }
    let rules = observed(runner, "iptables-save", &[]).await?;
    let subnet = plan.subnet.to_string();
    if rules
        .lines()
        .filter(|line| line.starts_with("-A "))
        .any(|line| {
            line.split_whitespace()
                .map(|word| word.trim_matches('"'))
                .any(|word| word == plan.host_veth || word == subnet)
        })
    {
        return Err(ApiError::Driver(
            "host firewall still refers to the network allocation".into(),
        ));
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::NetworkAllocator;
    use std::{os::unix::process::ExitStatusExt, sync::Mutex};

    struct Fixture {
        namespaces: String,
        links: String,
        rules: String,
        inventory_available: bool,
        commands: Mutex<Vec<String>>,
    }
    impl Fixture {
        fn absent() -> Self {
            Self {
                namespaces: "unrelated (id: 4)\n".into(),
                links: r#"[{"ifname":"lo"}]"#.into(),
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
                ("ip", Some("-j")) => &self.links,
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
}

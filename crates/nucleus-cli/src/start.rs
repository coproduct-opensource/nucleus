//! Start command - start nucleus-node in Lima VM
//!
//! Ensures the Lima VM is running and starts nucleus-node service.

use anyhow::{bail, Context, Result};
use clap::Args;
use std::process::Command;
use std::thread;
use std::time::Duration;

/// Start nucleus-node in the Lima VM
#[derive(Args, Debug)]
pub struct StartArgs {
    /// Lima VM name
    #[arg(long, default_value = "nucleus")]
    pub vm_name: String,

    /// Skip health check after starting
    #[arg(long)]
    pub no_wait: bool,

    /// Health check timeout in seconds
    #[arg(long, default_value = "60")]
    pub timeout: u32,

    /// Start the Lima VM if it's not running
    #[arg(long, default_value = "true")]
    pub auto_start_vm: bool,
}

/// Execute the start command
pub async fn execute(args: StartArgs) -> Result<()> {
    println!("Starting Nucleus...\n");

    // Step 1: Ensure Lima VM is running
    ensure_lima_vm_running(&args)?;

    // Step 2: Check if nucleus-node binary exists in VM
    ensure_nucleus_node_available(&args.vm_name)?;

    // Step 3: Start nucleus-node service
    start_nucleus_node_service(&args.vm_name)?;

    // Step 4: Wait for health check
    if !args.no_wait {
        wait_for_health_check(&args)?;
    }

    // Step 5: Print success message
    print_success_message();

    Ok(())
}

fn ensure_lima_vm_running(args: &StartArgs) -> Result<()> {
    let status = get_lima_vm_status(&args.vm_name)?;

    match status.as_str() {
        "Running" => {
            println!("Lima VM '{}' is running", args.vm_name);
            Ok(())
        }
        "Stopped" => {
            if args.auto_start_vm {
                println!("Starting Lima VM '{}'...", args.vm_name);
                start_lima_vm(&args.vm_name)?;
                println!("Lima VM '{}' started", args.vm_name);
                Ok(())
            } else {
                bail!(
                    "Lima VM '{}' is stopped. Start it with: limactl start {}",
                    args.vm_name,
                    args.vm_name
                );
            }
        }
        "" => {
            bail!(
                "Lima VM '{}' does not exist. Run: nucleus setup",
                args.vm_name
            );
        }
        other => {
            bail!(
                "Lima VM '{}' is in unexpected state: {}. Check: limactl list",
                args.vm_name,
                other
            );
        }
    }
}

fn get_lima_vm_status(name: &str) -> Result<String> {
    let output = Command::new("limactl")
        .args(["list", "--format", "{{.Name}}\t{{.Status}}"])
        .output()
        .context("Failed to list Lima VMs")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.first() == Some(&name) {
            return Ok(parts.get(1).unwrap_or(&"").to_string());
        }
    }

    Ok(String::new()) // VM not found
}

fn start_lima_vm(name: &str) -> Result<()> {
    let status = Command::new("limactl")
        .args(["start", name])
        .status()
        .context("Failed to start Lima VM")?;

    if !status.success() {
        bail!("Failed to start Lima VM '{}'", name);
    }
    Ok(())
}

fn ensure_nucleus_node_available(vm_name: &str) -> Result<()> {
    // Check if nucleus-node binary exists
    let output = Command::new("limactl")
        .args([
            "shell",
            vm_name,
            "--",
            "test",
            "-f",
            "/usr/local/bin/nucleus-node",
        ])
        .output()
        .context("Failed to check for nucleus-node in VM")?;

    if !output.status.success() {
        println!();
        println!("WARNING: nucleus-node binary not found in Lima VM.");
        println!();
        println!("To install nucleus-node in the VM:");
        println!("  1. Build: cargo build --release -p nucleus-node");
        println!(
            "  2. Copy to VM: limactl copy nucleus target/release/nucleus-node :/usr/local/bin/"
        );
        println!();
        println!("Or use the cross-compiled binary:");
        println!("  1. Build: scripts/cross-build.sh");
        println!(
            "  2. Copy: limactl copy {} target/aarch64-unknown-linux-musl/release/nucleus-node :/usr/local/bin/",
            vm_name
        );
        println!();
        bail!("nucleus-node not available in VM");
    }

    Ok(())
}

fn start_nucleus_node_service(vm_name: &str) -> Result<()> {
    // Check if service is already running
    let output = Command::new("limactl")
        .args([
            "shell",
            vm_name,
            "--",
            "systemctl",
            "is-active",
            "nucleus-node",
        ])
        .output()
        .context("Failed to check nucleus-node service status")?;

    let status = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if status == "active" {
        println!("nucleus-node service is already running");
        return Ok(());
    }

    // Try to start the systemd service first
    println!("Starting nucleus-node service...");
    let result = Command::new("limactl")
        .args([
            "shell",
            vm_name,
            "--",
            "sudo",
            "systemctl",
            "start",
            "nucleus-node",
        ])
        .output()
        .context("Failed to start nucleus-node service")?;

    if result.status.success() {
        println!("nucleus-node service started via systemd");
        return Ok(());
    }

    // Fallback: start directly
    println!("systemd service failed, starting nucleus-node directly...");
    let result = Command::new("limactl")
        .args([
            "shell",
            vm_name,
            "--",
            "sudo",
            "nohup",
            "/usr/local/bin/nucleus-node",
            ">",
            "/var/log/nucleus-node.log",
            "2>&1",
            "&",
        ])
        .output()
        .context("Failed to start nucleus-node directly")?;

    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        bail!("Failed to start nucleus-node: {}", stderr);
    }

    Ok(())
}

fn wait_for_health_check(args: &StartArgs) -> Result<()> {
    println!("Waiting for nucleus-node to be ready...");

    let endpoint = "http://127.0.0.1:8080/health";
    let timeout = Duration::from_secs(args.timeout as u64);
    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(500);

    // Create agent with timeout
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(2)))
        .build();
    let agent: ureq::Agent = config.into();

    loop {
        if start.elapsed() > timeout {
            bail!(
                "Health check timed out after {} seconds. Check: limactl shell {} -- journalctl -u nucleus-node",
                args.timeout,
                args.vm_name
            );
        }

        match agent.get(endpoint).call() {
            Ok(response) if response.status().as_u16() == 200 => {
                println!("\nnucleus-node is ready!");
                return Ok(());
            }
            Ok(response) => {
                // Non-200 response, keep waiting
                eprintln!(
                    "  Health check returned status {}, retrying...",
                    response.status().as_u16()
                );
            }
            Err(_) => {
                // Connection failed, keep waiting
                print!(".");
                std::io::Write::flush(&mut std::io::stdout()).ok();
            }
        }

        thread::sleep(poll_interval);
    }
}

fn print_success_message() {
    println!();
    println!("Nucleus is running!");
    println!("===================");
    println!();
    println!("Endpoints:");
    println!("  HTTP API: http://127.0.0.1:8080");
    println!("  Metrics:  http://127.0.0.1:9080");
    println!("  gRPC:     http://127.0.0.1:9180");
    println!();
    println!("Commands:");
    println!("  nucleus run \"Your task here\"    # Run a task");
    println!("  nucleus stop                    # Stop nucleus");
    println!("  nucleus doctor                  # Check status");
    println!();
    println!("API Example:");
    println!("  curl http://127.0.0.1:8080/v1/pods");
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_args() {
        let args = StartArgs {
            vm_name: "nucleus".to_string(),
            no_wait: false,
            timeout: 60,
            auto_start_vm: true,
        };
        assert_eq!(args.vm_name, "nucleus");
        assert!(!args.no_wait);
        assert!(args.auto_start_vm);
    }
}

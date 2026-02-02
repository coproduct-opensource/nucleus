//! Stop command - stop nucleus-node and optionally the Lima VM
//!
//! Cleanly shuts down nucleus-node and related services.

use anyhow::{bail, Context, Result};
use clap::Args;
use std::process::Command;

/// Stop nucleus-node and optionally the Lima VM
#[derive(Args, Debug)]
pub struct StopArgs {
    /// Lima VM name
    #[arg(long, default_value = "nucleus")]
    pub vm_name: String,

    /// Also stop the Lima VM (to save resources)
    #[arg(long)]
    pub stop_vm: bool,

    /// Force stop without graceful shutdown
    #[arg(long)]
    pub force: bool,
}

/// Execute the stop command
pub async fn execute(args: StopArgs) -> Result<()> {
    println!("Stopping Nucleus...\n");

    // Check if VM exists and is running
    let vm_status = get_lima_vm_status(&args.vm_name)?;

    if vm_status.is_empty() {
        println!("Lima VM '{}' does not exist. Nothing to stop.", args.vm_name);
        return Ok(());
    }

    if vm_status != "Running" {
        println!(
            "Lima VM '{}' is not running (status: {}). Nothing to stop.",
            args.vm_name, vm_status
        );
        return Ok(());
    }

    // Step 1: Stop nucleus-node service
    stop_nucleus_node(&args)?;

    // Step 2: Optionally stop the Lima VM
    if args.stop_vm {
        stop_lima_vm(&args)?;
    }

    // Step 3: Print success message
    print_success_message(&args);

    Ok(())
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

fn stop_nucleus_node(args: &StopArgs) -> Result<()> {
    // Check if service is running
    let output = Command::new("limactl")
        .args([
            "shell",
            &args.vm_name,
            "--",
            "systemctl",
            "is-active",
            "nucleus-node",
        ])
        .output()
        .context("Failed to check nucleus-node service status")?;

    let status = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if status != "active" {
        println!("nucleus-node service is not running");

        // Also check for any running nucleus-node processes
        let output = Command::new("limactl")
            .args([
                "shell",
                &args.vm_name,
                "--",
                "pgrep",
                "-x",
                "nucleus-node",
            ])
            .output()
            .context("Failed to check for nucleus-node process")?;

        if output.status.success() {
            println!("Found nucleus-node process, stopping...");
            stop_nucleus_node_process(args)?;
        }

        return Ok(());
    }

    // Stop via systemd
    println!("Stopping nucleus-node service...");

    let stop_cmd = if args.force { "kill" } else { "stop" };

    let result = Command::new("limactl")
        .args([
            "shell",
            &args.vm_name,
            "--",
            "sudo",
            "systemctl",
            stop_cmd,
            "nucleus-node",
        ])
        .output()
        .context("Failed to stop nucleus-node service")?;

    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        if args.force {
            // Force kill the process directly
            println!("systemctl kill failed, trying pkill...");
            stop_nucleus_node_process(args)?;
        } else {
            bail!("Failed to stop nucleus-node service: {}", stderr);
        }
    } else {
        println!("nucleus-node service stopped");
    }

    Ok(())
}

fn stop_nucleus_node_process(args: &StopArgs) -> Result<()> {
    let signal = if args.force { "-9" } else { "-15" };

    let result = Command::new("limactl")
        .args([
            "shell",
            &args.vm_name,
            "--",
            "sudo",
            "pkill",
            signal,
            "-x",
            "nucleus-node",
        ])
        .output()
        .context("Failed to kill nucleus-node process")?;

    if result.status.success() {
        println!("nucleus-node process stopped");
    } else {
        // Process might not exist, which is fine
        let stderr = String::from_utf8_lossy(&result.stderr);
        if !stderr.is_empty() && !stderr.contains("no process found") {
            eprintln!("Warning: pkill returned error: {}", stderr);
        }
    }

    Ok(())
}

fn stop_lima_vm(args: &StopArgs) -> Result<()> {
    println!("Stopping Lima VM '{}'...", args.vm_name);

    let mut cmd_args = vec!["stop"];

    if args.force {
        cmd_args.push("--force");
    }

    cmd_args.push(&args.vm_name);

    let result = Command::new("limactl")
        .args(&cmd_args)
        .status()
        .context("Failed to stop Lima VM")?;

    if !result.success() {
        bail!("Failed to stop Lima VM '{}'", args.vm_name);
    }

    println!("Lima VM '{}' stopped", args.vm_name);
    Ok(())
}

fn print_success_message(args: &StopArgs) {
    println!();
    println!("Nucleus stopped!");
    println!();

    if args.stop_vm {
        println!("Lima VM '{}' has been stopped.", args.vm_name);
        println!("To restart: nucleus start");
    } else {
        println!("nucleus-node has been stopped, but Lima VM '{}' is still running.", args.vm_name);
        println!("To restart nucleus-node: nucleus start");
        println!("To stop the VM: nucleus stop --stop-vm");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_args() {
        let args = StopArgs {
            vm_name: "nucleus".to_string(),
            stop_vm: false,
            force: false,
        };
        assert_eq!(args.vm_name, "nucleus");
        assert!(!args.stop_vm);
        assert!(!args.force);
    }
}

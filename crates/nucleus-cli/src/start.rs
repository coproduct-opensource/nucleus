//! Start command - start nucleus-node in Lima VM
//!
//! Ensures the Lima VM is running and starts nucleus-node service.

use anyhow::{Context, Result, bail};
use clap::Args;
use std::net::{SocketAddr, TcpStream};
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
        // This used to hand out a four-step cross-compile recipe, for a binary
        // the project already publishes and `setup` now installs. Telling
        // someone to build from source because a provisioning step was never
        // written is not a workaround, it is the bug wearing instructions.
        bail!(
            "nucleus-node is not installed in Lima VM '{vm_name}'.\n\
             Install it (and the kernel, rootfs and node secrets) with:\n\
             \n    nucleus setup\n\n\
             To use this working tree's own build instead of the pinned release:\n\
             \n    nucleus setup --artifacts local\n"
        );
    }

    // A node binary with no environment file cannot start: the node requires
    // three secrets at startup and exits immediately without them. Checking here
    // turns a systemd restart loop into one sentence.
    let env_present = Command::new("limactl")
        .args([
            "shell",
            vm_name,
            "--",
            "sudo",
            "test",
            "-s",
            crate::provision::NODE_ENV_PATH,
        ])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !env_present {
        bail!(
            "nucleus-node is installed in '{vm_name}' but {} is missing.\n\
             The node requires three HMAC secrets at startup and will exit without them.\n\
             Write it with: nucleus setup",
            crate::provision::NODE_ENV_PATH
        );
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

    // Fallback: start directly using a shell to interpret redirection
    println!("systemd service failed, starting nucleus-node directly...");
    let result = Command::new("limactl")
        .args([
            "shell",
            vm_name,
            "--",
            "sudo",
            "sh",
            "-c",
            "nohup /usr/local/bin/nucleus-node > /var/log/nucleus-node.log 2>&1 &",
        ])
        .output()
        .context("Failed to start nucleus-node directly")?;

    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        bail!("Failed to start nucleus-node: {}", stderr);
    }

    Ok(())
}

/// The node's address, and the health route on it.
///
/// The node's HTTP listener requires mTLS unconditionally -- there is no
/// plaintext mode left to default to (`nucleus node --help`, `--url`). A plain
/// `GET /health` is therefore not a health check of it; it is a corrupt TLS
/// record. This probe used to send one every 500 ms for 60 s, the node logged
/// an `InvalidContentType` handshake failure for each, and the command then
/// reported the *node* unhealthy and pointed the user at those 120 lines
/// (#2788). The route is `/v1/health`, not `/health`.
const NODE_ADDR: &str = "127.0.0.1:8080";
const HEALTH_URL: &str = "https://127.0.0.1:8080/v1/health";

/// How the probe talks to the node.
enum Probe {
    /// A real `GET /v1/health` over mTLS, presenting the identity
    /// `nucleus setup` provisioned. Proves the node is *serving*.
    Mtls(Box<reqwest::blocking::Client>),
    /// No provisioned CLI identity to present, so the strongest honest signal
    /// left is that the listener accepts a connection. Weaker, but it can
    /// never report a healthy node unhealthy because of something on this
    /// side -- which is the failure this probe is being fixed for.
    Listening,
}

impl Probe {
    /// `Ok(true)` when the node answered, `Ok(false)` when it is not ready
    /// yet. Failures of the probe's own making are not the node's verdict.
    fn poll(&self) -> Result<bool, String> {
        match self {
            Probe::Mtls(client) => match client.get(HEALTH_URL).send() {
                Ok(response) if response.status().is_success() => Ok(true),
                Ok(response) => Err(format!("status {}", response.status().as_u16())),
                Err(_) => Ok(false),
            },
            Probe::Listening => {
                let addr: SocketAddr = NODE_ADDR
                    .parse()
                    .expect("NODE_ADDR is a literal socket address");
                Ok(TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok())
            }
        }
    }
}

fn wait_for_health_check(args: &StartArgs) -> Result<()> {
    println!("Waiting for nucleus-node to be ready...");

    let probe = match crate::provision::mtls_blocking_client_from_provisioned_identity() {
        Ok(client) => Probe::Mtls(Box::new(client)),
        Err(_) => {
            println!(
                "  (no provisioned CLI identity found -- checking that the node's\n   \
                 listener is accepting connections. For an authenticated check,\n   \
                 run `nucleus setup`, then `nucleus node health`.)"
            );
            Probe::Listening
        }
    };

    let timeout = Duration::from_secs(u64::from(args.timeout));
    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(500);

    loop {
        if start.elapsed() > timeout {
            bail!(
                "nucleus-node did not become ready within {} seconds.\n  \
                 Check the node: limactl shell {} -- journalctl -u nucleus-node\n  \
                 Check it directly: nucleus node health",
                args.timeout,
                args.vm_name
            );
        }

        match probe.poll() {
            Ok(true) => {
                println!("\nnucleus-node is ready!");
                return Ok(());
            }
            Ok(false) => {
                print!(".");
                std::io::Write::flush(&mut std::io::stdout()).ok();
            }
            Err(detail) => {
                eprintln!("  Health check returned {detail}, retrying...");
            }
        }

        thread::sleep(poll_interval);
    }
}

/// The banner printed on success.
///
/// Built as a string so it can be asserted on: every line here used to name
/// something a user could not reach -- `http://` on an mTLS-only listener, a
/// metrics port nothing in `nucleus-node` binds, and a `curl` that could only
/// ever produce the same handshake failure the health probe did (#2788).
fn success_message() -> String {
    let mut out = String::new();
    out.push_str("\nNucleus is running!\n");
    out.push_str("===================\n\n");
    out.push_str("Endpoints:\n");
    out.push_str(&format!(
        "  HTTP API: https://{NODE_ADDR}  (mTLS -- a client certificate is required)\n"
    ));
    out.push_str("  gRPC:     https://127.0.0.1:9180\n\n");
    out.push_str("Commands:\n");
    out.push_str("  nucleus run \"Your task here\"    # Run a task\n");
    out.push_str("  nucleus node health             # Ask the node how it is\n");
    out.push_str("  nucleus node pods               # List pods\n");
    out.push_str("  nucleus stop                    # Stop nucleus\n");
    out.push_str("  nucleus doctor                  # Check status\n\n");
    out.push_str("API Example:\n");
    out.push_str(
        "  nucleus node health             # a raw curl needs the provisioned client cert\n\n",
    );
    out
}

fn print_success_message() {
    print!("{}", success_message());
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

    /// The probe must speak the protocol the node speaks. It sent plaintext
    /// `GET /health` to an mTLS-only listener, so it timed out on every
    /// healthy node (#2788).
    #[test]
    fn the_health_probe_addresses_the_listener_the_node_actually_has() {
        assert!(
            HEALTH_URL.starts_with("https://"),
            "the node's listener requires mTLS; a plaintext probe is a corrupt \
             TLS record, not a health check: {HEALTH_URL}"
        );
        assert!(
            HEALTH_URL.ends_with("/v1/health"),
            "the health route is /v1/health, not /health: {HEALTH_URL}"
        );
        assert!(
            NODE_ADDR.parse::<SocketAddr>().is_ok(),
            "the listening probe parses this as a socket address: {NODE_ADDR}"
        );
    }

    /// Every endpoint the banner names must be one a user can reach.
    #[test]
    fn the_banner_advertises_nothing_unreachable() {
        let banner = success_message();
        assert!(
            !banner.contains("http://"),
            "no plaintext endpoint is served; banner was:\n{banner}"
        );
        assert!(
            !banner.contains("9080"),
            "nothing in nucleus-node binds 9080; banner was:\n{banner}"
        );
        assert!(
            !banner.contains("curl http"),
            "a bare curl cannot complete the mTLS handshake; banner was:\n{banner}"
        );
        assert!(
            banner.contains("nucleus node health"),
            "the banner should name a command that works; banner was:\n{banner}"
        );
    }
}

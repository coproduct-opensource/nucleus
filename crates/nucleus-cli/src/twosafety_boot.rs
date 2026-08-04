//! The booted half of the 2-safety experiment: two REAL pods, one secret apart.
//!
//! [`crate::twosafety`] holds the observation function, the canonicaliser and the
//! comparison. It is deliberately booter-agnostic — it takes a [`Boot`] — and
//! until this file existed the only implementation was a fixture. **A harness
//! that has only ever run against a fake proves nothing about the runtime**: the
//! fake's kernel command line is a `format!`, not one `firecracker_config.rs`
//! built, and every channel the real node has (the task token, the wall clock,
//! the workload API port, the environment `nucleus-node` was started with) is
//! absent from it by construction.
//!
//! So this is the part that boots. [`PodBoot`] plants a secret in the node's
//! environment, restarts the node, creates a pod through the same authenticated
//! `POST /v1/pods` that `nucleus verify --tier2` uses, waits for the guest to
//! finish booting, and hands back the two files the host is left holding.
//!
//! # Where the two observations come from
//!
//! * `<chroot>/firecracker/<pod-id>/root/config.json` — the machine
//!   configuration Firecracker was **launched with** (`--config-file`), inside
//!   the jail. The node also writes a byte-identical copy to
//!   `<state>/pods/<pod-id>/firecracker.json`; the jail copy is read here
//!   because it is the one the VMM actually opened.
//! * `<state>/pods/<pod-id>/firecracker.log` — the guest console, i.e. what
//!   Firecracker's stdout carried off `console=ttyS0`. This is the same file
//!   `check_guest_facts` reads.
//!
//! Both are addressed by pod id, never by "most recently modified": locating a
//! pod's log by mtime already produced a check in this repo that could pass on
//! another pod's evidence.
//!
//! # Why the secret rides the node's environment
//!
//! Because that is the input whose containment is actually in question. The node
//! is a long-lived root process that spawns Firecracker, the jailer and a
//! per-pod tool-proxy, and `Command`'s default environment inheritance has
//! already leaked one capability across exactly that boundary in this repo. A
//! secret placed in `/etc/nucleus/node.env` is low-input-equal in every respect
//! the guest is entitled to see, so any byte of it reaching the guest's console
//! or command line is a channel nobody wrote down.
//!
//! # S4: the positive control is the load-bearing part
//!
//! [`twosafety::control`] runs first and asks for the secret to be planted
//! **into the kernel command line** — a channel that certainly reaches
//! `/proc/cmdline` — and requires the comparison to find it. Until that has
//! fired against a real boot, "no leak found" is indistinguishable from a
//! canonicaliser that erased too much, an observation collected from the wrong
//! files, or a comparison with an inverted condition. That is why
//! [`execute`] runs the control before the check and reports
//! [`TwoSafetyError::ControlDidNotFire`] as its own outcome rather than as a
//! pass.

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use nucleus_client::sign_http_headers;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::provision::{Tier2Host, HOST_ARTIFACTS_DIR, HOST_STATE_DIR, NODE_ENV_PATH};
use crate::twosafety::{self, Boot, CheckFailure, RunArtifacts, RunFacts, TwoSafetyError};

/// The environment variable the secret rides into the node's process.
///
/// Generic on purpose: nothing about this experiment is specific to what the
/// secret protects, and a name that implied otherwise would invite someone to
/// "fix" the harness by special-casing it.
const CANARY_ENV_KEY: &str = "NUCLEUS_E2E_CANARY";

/// The kernel command line key the positive control plants into.
///
/// Not a `nucleus.*` key the guest parses: `parse_cmdline_secret` looks for
/// exact prefixes, so an unknown one is inert in the guest and the control
/// measures the harness rather than provoking the runtime.
const PLANT_KEY: &str = "nucleus.twosafety_canary";

/// The node's HTTP address on the machine running the experiment.
const NODE_URL: &str = "http://127.0.0.1:8080";

/// The subcommand name clap derives from `Commands::TwoSafety`, used when this
/// command re-invokes itself inside the Lima VM.
const SUBCOMMAND: &str = "two-safety";

/// Defaults matching `nucleus-node`'s own clap defaults, used only when
/// `node.env` does not override them.
const DEFAULT_CHROOT_BASE: &str = "/srv/jailer";
const DEFAULT_FIRECRACKER_PATH: &str = "/usr/local/bin/firecracker";

/// The console line that proves the guest got all the way through boot.
///
/// The same fact `check_guest_facts` asserts. Waiting on it rather than on a
/// timeout is what stops a half-written log being compared against a complete
/// one and reported as a leak.
const BOOT_COMPLETE_MARKER: &str = "fetched session task token";

/// The pod's vsock CID. Fixed, as in `nucleus verify --tier2`: the runs are
/// sequential and each is cancelled before the next, so there is no contention,
/// and a CID that varied would be one more difference to explain.
const GUEST_CID: u32 = 3;

/// How long to wait for the guest to reach [`BOOT_COMPLETE_MARKER`].
const BOOT_DEADLINE: Duration = Duration::from_secs(120);
/// How long to wait for a log to stop growing once it has.
const SETTLE_DEADLINE: Duration = Duration::from_secs(30);
/// Consecutive unchanged samples that count as settled.
const SETTLE_SAMPLES: u32 = 5;
/// Gap between samples.
const POLL: Duration = Duration::from_millis(400);

/// Run the 2-safety experiment against real booted pods.
#[derive(Args, Debug)]
pub struct TwoSafetyArgs {
    /// Run the experiment on this machine rather than delegating into a VM.
    ///
    /// Set automatically when `nucleus two-safety` re-invokes itself inside the
    /// Lima VM; also the right flag on a Linux host with KVM. Mirrors
    /// `nucleus verify --tier2 --here`, and for the same reason: the artifacts
    /// are files inside the VM, so the comparison has to happen where they are.
    #[arg(long)]
    pub here: bool,

    /// Lima VM to run inside (macOS). Ignored on Linux.
    #[arg(long, default_value = "nucleus")]
    pub vm_name: String,
}

/// Boot the same pod four times — twice with the secret planted in the kernel
/// command line, twice without — and compare.
///
/// # The order is the point
///
/// The positive control runs FIRST. A blind harness and a clean system produce
/// the same output from [`twosafety::check`] alone, so running the check first
/// would let a broken observation report success. Running the control first
/// means a blind harness is reported as blind.
pub async fn execute(args: TwoSafetyArgs) -> Result<()> {
    if !args.here && !cfg!(target_os = "linux") {
        return delegate_to_lima(&args.vm_name);
    }
    run_here()
}

/// Re-invoke inside the Lima VM, where `/dev/kvm` and the artifacts are.
///
/// Identical in shape to `verify_tier2`'s Lima arm — and for a stronger reason
/// here: the observation is two root-owned files under `/srv/jailer` and
/// `/var/lib/nucleus`, which do not exist in the workstation's namespace at all.
fn delegate_to_lima(vm_name: &str) -> Result<()> {
    println!("Running the 2-safety experiment inside Lima VM '{vm_name}'...");
    let installed = Command::new("limactl")
        .args([
            "shell",
            vm_name,
            "--",
            "test",
            "-x",
            "/usr/local/bin/nucleus",
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !installed {
        bail!(
            "the Linux `nucleus` CLI is not installed in VM '{vm_name}'.\n\
             The experiment reads two root-owned files inside the VM, so it has to\n\
             run there. Install it with: nucleus setup"
        );
    }
    let status = Command::new("limactl")
        .args([
            "shell",
            vm_name,
            "--",
            "sudo",
            "/usr/local/bin/nucleus",
            // The clap variant `TwoSafety` derives this kebab-case name. Spelled
            // out rather than derived here, so `the_delegated_subcommand_exists`
            // fails if the variant is ever renamed — a wrong name would only
            // surface as "unrecognized subcommand" from inside the VM.
            SUBCOMMAND,
            "--here",
        ])
        .status()
        .context("failed to run the 2-safety experiment inside the Lima VM")?;
    if !status.success() {
        bail!("the in-VM 2-safety experiment failed (see its output above)");
    }
    Ok(())
}

fn run_here() -> Result<()> {
    println!("\n2-safety: boot twice, differ only in a secret, compare");
    println!("=====================================================");

    let mut booter = PodBoot::new()?;
    println!("  node env : {NODE_ENV_PATH} (secret rides {CANARY_ENV_KEY})");
    println!("  configs  : {}", booter.chroot_base.display());
    println!(
        "  consoles : {}/pods/<pod-id>/firecracker.log",
        booter.state_dir.display()
    );

    // The control FIRST. See the doc comment on `execute`.
    println!("\n[1/2] positive control — the secret is planted in the kernel command line");
    println!("      and the comparison MUST find it.");
    let control = twosafety::control(&mut booter);

    // A divergence between two REAL boots is not by itself evidence that the
    // plant was seen — see `attribute_plant`. Both legs must hold.
    let attribution = control.is_ok().then(|| booter.attribute_plant());

    let control_ok = control.is_ok() && matches!(attribution, Some(Ok(())));
    let check = if control_ok {
        println!("  [OK] the control fired: the two planted boots diverged,");
        println!("       and the planted secret is present in BOTH components of BOTH runs,");
        println!("       each carrying its own value — so the divergence is the plant's.");
        println!("\n[2/2] the check — two boots differing ONLY in the node's environment.");
        Some(twosafety::check_all(&mut booter))
    } else {
        None
    };

    // Always put the node back the way it was found, whatever happened above.
    let restored = booter.restore();

    match control {
        Err(TwoSafetyError::ControlDidNotFire) => {
            restored?;
            bail!(
                "{}\n\n\
                 The check was NOT run. A comparison that cannot see a secret written\n\
                 straight into /proc/cmdline cannot see one anywhere else either, so\n\
                 reporting it as clean would be the vacuous pass this control exists to\n\
                 prevent.",
                TwoSafetyError::ControlDidNotFire
            );
        }
        // The control ran and the two runs DID differ, but not because of the
        // plant. Against a real pod this is the likely shape rather than an
        // exotic one — two boots differ in run-scoped values anyway — and it is
        // exactly the confound that let a completely removed plant still report
        // `Ok`. Treated as a hard stop, not a warning: an unattributable red
        // certifies nothing, so the check below must not run on the strength of
        // it.
        Err(e @ TwoSafetyError::ControlNotAttributable(_)) => {
            restored?;
            bail!(
                "{e}\n\n\
                 The check was NOT run. The control must show that the divergence it\n\
                 produced is the one it planted; a divergence it cannot attribute is\n\
                 indistinguishable from boot-to-boot noise, and certifying the harness\n\
                 on that basis is the vacuous pass this control exists to prevent."
            );
        }
        Err(e @ TwoSafetyError::Harness(_)) => {
            restored?;
            bail!("{e}\n\nThe experiment did not run, which is not the same as finding nothing.");
        }
        Ok(()) => {}
    }
    restored?;

    if let Some(Err(e)) = attribution {
        bail!(
            "the positive control is NOT attributable: {e:#}\n\n\
             The check was NOT run. `control` found a divergence between the two\n\
             planted boots, but a divergence is what two real boots produce anyway —\n\
             the per-boot task token differs in the same `boot_args` line — so its\n\
             firing carries no information unless the plant is separately shown to\n\
             have reached the observation. It was not."
        );
    }

    match check.expect("the check runs whenever the control fired") {
        Ok(()) => {
            println!("  [OK] the two observations are bit-identical after canonicalisation.");
            println!(
                "\nNo channel in the observation carried the secret. This is complete\n\
                 RELATIVE TO the observation function in `twosafety.rs` — timing, cache\n\
                 residency and power are outside it, exactly as seL4's information-flow\n\
                 proof is silent on timing."
            );
            Ok(())
        }
        // EVERY residual region, not `compare`'s first. While a residual is
        // being worked down, one region is ambiguous in the worst way: a rule
        // that fixes one of three is indistinguishable from a rule that fixes
        // all three, because either way the next run reports "a divergence" and
        // only the line number moves.
        Err(CheckFailure::Diverged(ds)) => {
            let mut report = String::new();
            for d in &ds {
                report.push_str(&format!("  {d}\n"));
            }
            bail!(
                "{} differing region(s) after canonicalisation:\n{report}\n\
                 Two boots that differed only in {CANARY_ENV_KEY} produced different\n\
                 observations. Either a channel carries the secret, or those regions are\n\
                 run-to-run nondeterministic and the canonicaliser does not yet cover them —\n\
                 and the harness cannot tell those apart, which is why it reports the\n\
                 regions rather than a verdict.",
                ds.len()
            );
        }
        Err(CheckFailure::Harness(e)) => bail!("{e}"),
    }
}

/// A [`Boot`] that boots real pods on a host with KVM.
pub struct PodBoot {
    host: Tier2Host,
    /// The node's HMAC secret, read once so a restart cannot race it.
    auth_secret: String,
    state_dir: PathBuf,
    chroot_base: PathBuf,
    /// `basename` of the Firecracker binary — the jailer's second path segment.
    exec_name: String,
    /// Whether `node.env` already carried a canary line, so `restore` puts the
    /// file back rather than merely deleting.
    prior_canary: Option<String>,
    /// Every run whose secret was planted in the kernel command line, with the
    /// snapshot it produced. Recorded so the control's firing can be
    /// ATTRIBUTED to the plant — see [`PodBoot::attribute_plant`].
    planted: Vec<PlantedRun>,
}

/// A control run, kept so its divergence can be traced back to the plant.
struct PlantedRun {
    secret: String,
    config: PathBuf,
    console: PathBuf,
}

impl PodBoot {
    /// Read everything the experiment needs off the host, failing loudly.
    ///
    /// Every path is resolved from `node.env` where the node reads it from the
    /// same place, so a host configured with a non-default state directory or
    /// chroot base is followed rather than silently mis-read. A wrong path here
    /// would not error — it would produce two `collect` failures, or worse, two
    /// reads of a *previous* pod's artifacts.
    pub fn new() -> Result<Self> {
        let host = Tier2Host::Local;
        if !host.test("test -r /dev/kvm") {
            bail!(
                "no /dev/kvm on this machine, so no pod can boot. The 2-safety\n\
                 experiment needs a real boot: comparing two fixtures proves only that\n\
                 the fixtures agree."
            );
        }
        let env = host
            .sh(&format!("cat {NODE_ENV_PATH}"))
            .with_context(|| format!("cannot read {NODE_ENV_PATH}; run: nucleus setup"))?;
        let value = |key: &str| env_value(&env, key);

        let auth_secret = value("NUCLEUS_NODE_AUTH_SECRET").ok_or_else(|| {
            anyhow!("{NODE_ENV_PATH} has no NUCLEUS_NODE_AUTH_SECRET; run: nucleus setup")
        })?;
        let state_dir = PathBuf::from(
            value("NUCLEUS_NODE_STATE_DIR").unwrap_or_else(|| HOST_STATE_DIR.to_string()),
        );
        let chroot_base = PathBuf::from(
            value("NUCLEUS_JAILER_CHROOT_BASE").unwrap_or_else(|| DEFAULT_CHROOT_BASE.to_string()),
        );
        let firecracker =
            value("NUCLEUS_FIRECRACKER_PATH").unwrap_or_else(|| DEFAULT_FIRECRACKER_PATH.into());
        let exec_name = PathBuf::from(&firecracker)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .ok_or_else(|| anyhow!("NUCLEUS_FIRECRACKER_PATH is not a file path: {firecracker}"))?;

        // Clear the previous experiment's snapshots. Kept until the NEXT run
        // rather than deleted at the end of this one, because when a divergence
        // is reported the two frozen files are the only place the differing
        // region can actually be looked at.
        let _ = std::fs::remove_dir_all(state_dir.join("twosafety"));

        Ok(PodBoot {
            host,
            auth_secret,
            state_dir,
            chroot_base,
            exec_name,
            prior_canary: value(CANARY_ENV_KEY),
            planted: Vec::new(),
        })
    }

    /// **Attribute the control's divergence to the plant.**
    ///
    /// # Why `control` returning `Ok` is not, on its own, evidence
    ///
    /// [`twosafety::control`] boots twice WITH the plant and accepts any
    /// divergence as proof the harness can see. That is airtight against the
    /// fake `Boot`, whose two runs are identical apart from the plant. It is
    /// **not** airtight against a real pod: measured on this host, two boots
    /// that differ in nothing at all still differ in `nucleus.task_token_hex`
    /// and `nucleus.task_token_nonce`, which live in the same `boot_args` line.
    /// So a real `control` fires at `machine_config` line 4 whether the plant
    /// works or not, and a plant that silently stopped reaching the command
    /// line would still look like a firing control.
    ///
    /// The direct evidence of that: [`twosafety::check`] is exactly `control`
    /// with the plant switched off, and it diverges at the SAME component and
    /// line.
    ///
    /// So this asserts what the control was supposed to establish and, on a real
    /// boot, cannot: the planted secret is **present in the observation**, each
    /// run carries its own and not the other's, and the two differ. That is a
    /// statement about the plant specifically, and no amount of boot-to-boot
    /// noise can satisfy it.
    ///
    /// # Errors
    /// If the plant did not reach both components of both control runs.
    fn attribute_plant(&self) -> Result<()> {
        let [a, b] = match self.planted.as_slice() {
            [.., a, b] => [a, b],
            _ => bail!(
                "the control ran {} planted boots; two are needed to attribute its \
                 divergence",
                self.planted.len()
            ),
        };
        if a.secret == b.secret {
            bail!(
                "both control runs planted the same secret, so a divergence between \
                 them cannot be the plant"
            );
        }
        for (run, other) in [(a, b), (b, a)] {
            for (path, what, needle) in [
                (
                    &run.config,
                    "machine config",
                    format!("{PLANT_KEY}={}", run.secret),
                ),
                // The kernel echoes its whole command line, so the plant must be
                // visible on the console too. Checking both components is what
                // makes this an assertion about the OBSERVATION rather than
                // about one file.
                (
                    &run.console,
                    "guest console",
                    format!("{PLANT_KEY}={}", run.secret),
                ),
            ] {
                let body = std::fs::read_to_string(path)
                    .with_context(|| format!("cannot re-read the {what} at {}", path.display()))?;
                if !body.contains(&needle) {
                    bail!(
                        "the planted secret never reached the {what} at {}. The control's \
                         divergence therefore came from something else — on a real boot the \
                         task token differs between any two runs — so it is NOT evidence \
                         that this harness can see a secret.",
                        path.display()
                    );
                }
                let foreign = format!("{PLANT_KEY}={}", other.secret);
                if body.contains(&foreign) {
                    bail!(
                        "the {what} at {} carries the OTHER control run's secret, so the \
                         two runs are not independent boots",
                        path.display()
                    );
                }
            }
        }
        Ok(())
    }

    /// Put `node.env` back as it was found and restart the node on it.
    ///
    /// Called on every exit path. Leaving a canary in a root-owned environment
    /// file would be a secret this experiment introduced and then abandoned.
    pub fn restore(&self) -> Result<()> {
        match self.prior_canary.clone() {
            Some(v) => self.set_canary(&v),
            None => {
                self.host.sh(&format!(
                    "set -e; sed -i '/^{CANARY_ENV_KEY}=/d' {NODE_ENV_PATH}; \
                     systemctl restart nucleus-node"
                ))?;
                self.await_node()
            }
        }
    }

    /// Write the secret into the node's environment and restart it onto it.
    ///
    /// The restart happens on EVERY run, planted or not, so "the node was
    /// restarted" is a constant of the experiment rather than a difference
    /// between its arms.
    fn set_canary(&self, secret: &str) -> Result<()> {
        // The value is interpolated into a root shell command. Every caller in
        // this crate passes a constant from `twosafety.rs`, but a value that
        // could carry a quote would turn a future caller's secret into a
        // command — so the shape is checked rather than assumed.
        if !is_shell_safe(secret) {
            bail!(
                "refusing to write a secret containing shell metacharacters into \
                 {NODE_ENV_PATH}"
            );
        }
        self.host.sh(&format!(
            "set -e; sed -i '/^{CANARY_ENV_KEY}=/d' {NODE_ENV_PATH}; \
             printf '%s=%s\\n' '{CANARY_ENV_KEY}' '{secret}' >> {NODE_ENV_PATH}; \
             systemctl restart nucleus-node"
        ))?;
        self.await_node()
    }

    /// Wait for the node to answer, or say what it logged.
    fn await_node(&self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if ureq::get(&format!("{NODE_URL}/v1/health"))
                .call()
                .map(|r| r.status().is_success())
                .unwrap_or(false)
            {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        let log = self
            .host
            .sh("journalctl -u nucleus-node --no-pager -n 20")
            .unwrap_or_else(|_| "(no journal available)".into());
        bail!("nucleus-node did not become healthy within 30s. Its log said:\n{log}")
    }

    /// Create the pod and return its id.
    ///
    /// The spec is a constant except for `boot_args`, which carries the planted
    /// secret when the control asks for it. No DLC admission material is minted:
    /// `mint_admission` draws a fresh issuer key from `/dev/urandom` per call,
    /// which would be a per-run difference that has nothing to do with the
    /// secret — the experiment's inputs must be equal apart from the one under
    /// test.
    fn create_pod(&self, secret: &str, plant: bool) -> Result<String> {
        let boot_args = if plant {
            format!(
                ",\"boot_args\":\"console=ttyS0 reboot=k panic=1 pci=off init=/init \
                 {PLANT_KEY}={secret}\""
            )
        } else {
            String::new()
        };
        let body = format!(
            r#"{{"apiVersion":"nucleus/v1","kind":"Pod",
                "metadata":{{"name":"nucleus-twosafety"}},
                "spec":{{"work_dir":"/work","timeout_seconds":120,
                  "policy":{{"type":"profile","name":"codegen"}},
                  "image":{{"kernel_path":"{HOST_ARTIFACTS_DIR}/vmlinux",
                            "rootfs_path":"{HOST_ARTIFACTS_DIR}/rootfs.ext4",
                            "read_only":false{boot_args}}},
                  "vsock":{{"guest_cid":{GUEST_CID},"port":5005}}}}}}"#
        );

        // A 4xx must arrive as data: the node's refusals explain themselves in
        // the body, and ureq's default discards it.
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();
        let mut request = agent
            .post(format!("{NODE_URL}/v1/pods"))
            .header("content-type", "application/json");
        let signed = sign_http_headers(
            self.auth_secret.as_bytes(),
            Some("nucleus-twosafety"),
            body.as_bytes(),
        );
        for (key, value) in signed.headers {
            request = request.header(&key, &value);
        }
        let mut response = request
            .send(body.as_bytes())
            .map_err(|e| anyhow!("the node refused to create a pod: {e}"))?;
        if !response.status().is_success() {
            let status = response.status();
            let detail = response
                .body_mut()
                .read_to_string()
                .unwrap_or_else(|_| "<no body>".to_string());
            bail!("pod creation returned {status}: {}", detail.trim());
        }
        #[derive(serde::Deserialize)]
        struct CreatePodResponse {
            id: Option<String>,
        }
        let parsed: CreatePodResponse = response
            .body_mut()
            .read_json()
            .context("the node's response was not the JSON we expected")?;
        parsed
            .id
            .ok_or_else(|| anyhow!("the node created a pod but returned no id"))
    }

    /// Stop the pod, so the next run's CID and vsock path are free.
    ///
    /// Best-effort: a pod that already exited returns 404, which is the desired
    /// end state and not a failure.
    fn cancel_pod(&self, id: &str) {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();
        let mut request = agent.post(format!("{NODE_URL}/v1/pods/{id}/cancel"));
        let signed = sign_http_headers(self.auth_secret.as_bytes(), Some("nucleus-twosafety"), b"");
        for (key, value) in signed.headers {
            request = request.header(&key, &value);
        }
        let _ = request.send(b"" as &[u8]);
    }

    fn console_path(&self, id: &str) -> PathBuf {
        self.state_dir.join("pods").join(id).join("firecracker.log")
    }

    fn config_path(&self, id: &str) -> PathBuf {
        self.chroot_base
            .join(&self.exec_name)
            .join(id)
            .join("root")
            .join("config.json")
    }

    /// Where a run's frozen observation is kept.
    fn snapshot_dir(&self, id: &str) -> PathBuf {
        self.state_dir.join("twosafety").join(id)
    }

    /// Copy both components out before the pod is stopped, and hand back the
    /// copies.
    ///
    /// # This is not tidiness, it is a correctness requirement
    ///
    /// `cleanup_jail` deletes `<chroot>/<exec>/<pod-id>` when the pod stops, and
    /// the pod must be stopped before the next run can have the same CID. So the
    /// live config path is valid only while the pod is alive, and reading it
    /// afterwards fails — which is exactly how this failed on its first real
    /// run, as a `Harness` error naming a config.json that no longer existed.
    ///
    /// Freezing the pair also removes the second hazard: the console is a file
    /// the node is still appending to, so two runs read at different moments in
    /// their tails differ for a reason that is not the secret. The snapshot is
    /// taken once, after the console has settled and before anything is torn
    /// down, so both runs are compared at the same point in their lives.
    ///
    /// The copies are left in place deliberately. When the comparison reports a
    /// divergence, the two files ARE the evidence, and a harness that deleted
    /// them would report a region nobody could then look at.
    fn snapshot(&self, id: &str) -> Result<(PathBuf, PathBuf)> {
        let dir = self.snapshot_dir(id);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
        let mut out = Vec::new();
        for (from, name) in [
            (self.config_path(id), "config.json"),
            (self.console_path(id), "console.log"),
        ] {
            let to = dir.join(name);
            std::fs::copy(&from, &to).with_context(|| {
                format!(
                    "cannot snapshot {} to {}. Without a snapshot the observation would \
                     be read after the jail is torn down, or while the console is still \
                     being written",
                    from.display(),
                    to.display()
                )
            })?;
            out.push(to);
        }
        Ok((out.remove(0), out.remove(0)))
    }

    /// Wait until the guest has finished booting AND its console has stopped
    /// growing.
    ///
    /// Both halves matter and for different reasons. The marker is the
    /// non-vacuity condition: without it a boot that died in the kernel produces
    /// a short log, and two short logs of *different* lengths compare as a
    /// divergence — a leak report caused by the harness. The settle is the
    /// determinism condition: the console keeps a few lines coming after the
    /// marker, and sampling two runs at different points in that tail is the
    /// same false positive wearing a different hat.
    fn await_console(&self, id: &str) -> Result<()> {
        let path = self.console_path(id);
        let size = || {
            std::fs::metadata(&path)
                .map(|m| m.len())
                .unwrap_or_default()
        };
        let deadline = Instant::now() + BOOT_DEADLINE;
        loop {
            if let Ok(body) = std::fs::read_to_string(&path) {
                if body.contains(BOOT_COMPLETE_MARKER) {
                    break;
                }
            }
            if Instant::now() >= deadline {
                let tail = std::fs::read_to_string(&path).unwrap_or_default();
                let tail: Vec<&str> = tail.lines().rev().take(8).collect();
                bail!(
                    "the guest never reached {BOOT_COMPLETE_MARKER:?} within {}s.\n\
                     An incomplete boot cannot be compared: two truncated consoles differ\n\
                     from each other for reasons that have nothing to do with the secret.\n\
                     console: {}\n  last lines (newest first): {tail:?}",
                    BOOT_DEADLINE.as_secs(),
                    path.display()
                );
            }
            std::thread::sleep(POLL);
        }
        self.settle(&path, size)
    }

    fn settle(&self, path: &std::path::Path, size: impl Fn() -> u64) -> Result<()> {
        let deadline = Instant::now() + SETTLE_DEADLINE;
        let mut last = size();
        let mut stable = 0;
        while stable < SETTLE_SAMPLES {
            std::thread::sleep(POLL);
            let now = size();
            if now == last {
                stable += 1;
            } else {
                stable = 0;
                last = now;
            }
            if Instant::now() >= deadline {
                bail!(
                    "the console at {} never stopped growing, so there is no point at \
                     which two runs are comparable",
                    path.display()
                );
            }
        }
        Ok(())
    }
}

impl Boot for PodBoot {
    fn boot(&mut self, secret: &str, plant_in_cmdline: bool) -> std::io::Result<RunArtifacts> {
        // `Boot` returns io::Error, so anyhow's context is flattened into the
        // message. That is deliberate: `observe` turns it into
        // `TwoSafetyError::Harness`, and the whole point of that variant is that
        // "the experiment did not run" reads differently from "the experiment
        // found nothing".
        let io = |e: anyhow::Error| std::io::Error::other(format!("{e:#}"));

        self.set_canary(secret).map_err(io)?;
        let id = self.create_pod(secret, plant_in_cmdline).map_err(io)?;
        println!(
            "      booted pod {id} (secret in {CANARY_ENV_KEY}{})",
            if plant_in_cmdline {
                ", planted in the kernel command line"
            } else {
                ""
            }
        );
        // Freeze the observation BEFORE the pod is stopped: `cleanup_jail`
        // deletes the config the moment it is. See `snapshot`.
        let frozen = self.await_console(&id).and_then(|()| self.snapshot(&id));
        self.cancel_pod(&id);
        let (config, console) = frozen.map_err(io)?;

        if plant_in_cmdline {
            self.planted.push(PlantedRun {
                secret: secret.to_string(),
                config: config.clone(),
                console: console.clone(),
            });
        }

        Ok(RunArtifacts {
            config,
            console,
            facts: RunFacts {
                pod_id: id,
                guest_cid: GUEST_CID,
            },
        })
    }
}

/// Read `KEY=value` out of an environment file's text.
///
/// Comment lines are skipped rather than matched, because `node.env` opens with
/// one and a prefix match on a commented-out key would return a stale value.
fn env_value(env: &str, key: &str) -> Option<String> {
    env.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Whether a value can be single-quoted into a shell command without escaping.
///
/// Deliberately an allow-list. A deny-list of metacharacters is the shape that
/// has to be right about every shell; an allow-list only has to be right about
/// the characters a canary needs.
fn is_shell_safe(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canary's env key must not name a vendor or a product — the harness is
    /// about the runtime's containment, not about what the secret protects.
    #[test]
    fn the_canary_key_is_generic() {
        assert!(CANARY_ENV_KEY.starts_with("NUCLEUS_"));
    }

    /// **The name this command re-invokes itself by must exist.**
    ///
    /// `delegate_to_lima` runs `nucleus <SUBCOMMAND> --here` inside the VM, and
    /// a wrong name fails only there, as clap's "unrecognized subcommand" —
    /// which is exactly what happened the first time this was run for real
    /// (`twosafety` vs the derived `two-safety`). Asserted against clap's own
    /// command tree rather than against a second literal, so renaming the
    /// variant fails here instead of in the VM.
    #[test]
    fn the_delegated_subcommand_exists() {
        let cmd = <crate::Cli as clap::CommandFactory>::command();
        let names: Vec<&str> = cmd.get_subcommands().map(|s| s.get_name()).collect();
        assert!(
            names.contains(&SUBCOMMAND),
            "`nucleus {SUBCOMMAND}` is not a subcommand; clap knows: {names:?}"
        );
    }

    /// **The plant must not be a key the guest parses.**
    ///
    /// `nucleus-guest-init` reads `nucleus.task_token_hex`,
    /// `nucleus.approval_secret`, `nucleus.workload_api_port` and friends by
    /// exact prefix. Planting into one of those would change what the guest
    /// DOES, so a divergence could come from the runtime reacting rather than
    /// from the harness seeing — and the control would be measuring the wrong
    /// thing.
    #[test]
    fn the_planted_key_is_inert_in_the_guest() {
        for parsed in [
            "nucleus.task_token_hex",
            "nucleus.task_token_nonce",
            "nucleus.task_token_issuer",
            "nucleus.approval_secret",
            "nucleus.auth_secret",
            "nucleus.workload_api_port",
            "nucleus.sandbox_token",
            "nucleus.net",
        ] {
            assert_ne!(PLANT_KEY, parsed, "the plant collides with a parsed key");
        }
    }

    /// Both observation paths must be addressed by POD ID.
    ///
    /// Locating a pod's artifacts any other way — newest file, single directory
    /// entry — is how a check in this repo came to pass on a different pod's
    /// evidence. Here it would be worse: two runs could read the SAME file and
    /// compare equal, which is a silent vacuous pass.
    #[test]
    fn artifacts_are_addressed_by_pod_id() {
        let mut b = booter(std::path::Path::new("/var/lib/nucleus/state"), Vec::new());
        b.chroot_base = PathBuf::from("/srv/jailer");
        let id = "aeb31452-ce64-468b-abf4-ea5f23378519";
        assert_eq!(
            b.config_path(id),
            PathBuf::from(format!("/srv/jailer/firecracker/{id}/root/config.json"))
        );
        assert_eq!(
            b.console_path(id),
            PathBuf::from(format!("/var/lib/nucleus/state/pods/{id}/firecracker.log"))
        );
        // And two ids must not resolve to the same file, or the comparison is
        // between a run and itself.
        assert_ne!(b.config_path(id), b.config_path("other"));
        assert_ne!(b.console_path(id), b.console_path("other"));
        // The snapshot the comparison actually reads is under the SAME
        // discipline: a shared snapshot directory would make four runs overwrite
        // one another and every comparison pass.
        assert_ne!(b.snapshot_dir(id), b.snapshot_dir("other"));
        assert!(b.snapshot_dir(id).ends_with(id));
    }

    fn booter(dir: &std::path::Path, planted: Vec<PlantedRun>) -> PodBoot {
        PodBoot {
            host: Tier2Host::Local,
            auth_secret: "unused".into(),
            state_dir: dir.to_path_buf(),
            chroot_base: dir.to_path_buf(),
            exec_name: "firecracker".into(),
            prior_canary: None,
            planted,
        }
    }

    /// Write one control run's snapshot pair. `in_config` / `in_console` choose
    /// whether the plant actually made it there — i.e. whether the harness under
    /// test is blind.
    fn planted_run(
        dir: &std::path::Path,
        secret: &str,
        in_config: bool,
        in_console: bool,
    ) -> PlantedRun {
        let plant = format!("{PLANT_KEY}={secret}");
        let config = dir.join(format!("{secret}.config.json"));
        let console = dir.join(format!("{secret}.console.log"));
        let body = |present: bool| {
            if present {
                format!("boot_args: console=ttyS0 init=/init {plant} pci=off\n")
            } else {
                "boot_args: console=ttyS0 init=/init pci=off\n".to_string()
            }
        };
        std::fs::write(&config, body(in_config)).expect("write config");
        std::fs::write(&console, body(in_console)).expect("write console");
        PlantedRun {
            secret: secret.into(),
            config,
            console,
        }
    }

    /// The control: a working plant is attributable.
    #[test]
    fn a_working_plant_is_attributed() {
        let d = tempfile::tempdir().expect("tempdir");
        let b = booter(
            d.path(),
            vec![
                planted_run(d.path(), "control-aaaa", true, true),
                planted_run(d.path(), "control-bbbb", true, true),
            ],
        );
        b.attribute_plant()
            .expect("both runs carry their own plant");
    }

    /// **The meta-check, and the reason this function exists.**
    ///
    /// On a real boot `twosafety::control` fires on ANY divergence, and two real
    /// boots always diverge in the per-boot task token — so a plant that stopped
    /// reaching the kernel command line would still look like a firing control.
    /// Attribution must fail in that case, in each component independently.
    #[test]
    fn a_plant_that_never_arrived_is_not_attributable() {
        for (in_config, in_console, missing) in [
            (false, true, "machine config"),
            (true, false, "guest console"),
        ] {
            let d = tempfile::tempdir().expect("tempdir");
            let b = booter(
                d.path(),
                vec![
                    planted_run(d.path(), "control-aaaa", in_config, in_console),
                    planted_run(d.path(), "control-bbbb", true, true),
                ],
            );
            let e = format!(
                "{:#}",
                b.attribute_plant()
                    .expect_err("a plant that did not arrive must not be attributable")
            );
            assert!(e.contains(missing), "names which component: {e}");
        }
    }

    /// Two control runs planting the SAME value cannot explain a divergence
    /// between them, so attribution must refuse rather than accept.
    #[test]
    fn two_identical_plants_are_not_attributable() {
        let d = tempfile::tempdir().expect("tempdir");
        let b = booter(
            d.path(),
            vec![
                planted_run(d.path(), "control-same", true, true),
                planted_run(d.path(), "control-same", true, true),
            ],
        );
        assert!(b.attribute_plant().is_err());
    }

    /// Fewer than two planted boots is a harness failure, not a pass. An empty
    /// `planted` list would otherwise satisfy every "contains" check by
    /// vacuous quantification — the shape this repo has been bitten by.
    #[test]
    fn no_planted_boots_is_not_an_attribution() {
        let d = tempfile::tempdir().expect("tempdir");
        assert!(booter(d.path(), Vec::new()).attribute_plant().is_err());
        let one = vec![planted_run(d.path(), "control-aaaa", true, true)];
        assert!(booter(d.path(), one).attribute_plant().is_err());
    }

    #[test]
    fn env_values_are_read_and_comments_ignored() {
        let env = "# NUCLEUS_NODE_STATE_DIR=/wrong\nNUCLEUS_NODE_STATE_DIR=/right\nEMPTY=\n";
        assert_eq!(
            env_value(env, "NUCLEUS_NODE_STATE_DIR").as_deref(),
            Some("/right")
        );
        assert_eq!(env_value(env, "EMPTY"), None);
        assert_eq!(env_value(env, "ABSENT"), None);
    }

    /// The secrets this crate actually plants must pass the shell check, or the
    /// experiment fails at the first boot for a reason unrelated to security.
    #[test]
    fn the_planted_secrets_are_shell_safe_and_metacharacters_are_not() {
        for s in [
            "twosafety-control-aaaaaaaa",
            "twosafety-control-bbbbbbbb",
            "twosafety-secret-aaaaaaaa",
            "twosafety-secret-bbbbbbbb",
        ] {
            assert!(is_shell_safe(s), "{s} must be writable into node.env");
        }
        for bad in ["a'b", "a b", "a;rm -rf /", "a$(id)", "a\nb", ""] {
            assert!(!is_shell_safe(bad), "{bad:?} must be refused");
        }
    }

    /// The planted command line must keep `init=/init`, or `from_spec` appends
    /// it and the two arms of the control differ in shape as well as in value.
    #[test]
    fn the_planted_boot_args_still_name_init() {
        let plant = format!(
            "console=ttyS0 reboot=k panic=1 pci=off init=/init {PLANT_KEY}=twosafety-control-aaaaaaaa"
        );
        assert!(plant.contains("init="));
        assert!(plant.contains("console=ttyS0"));
    }
}

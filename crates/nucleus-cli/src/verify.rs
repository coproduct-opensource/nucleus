//! Prove Tier 2 works by booting a real nucleus pod, not a stock rootfs.
//!
//! # Why this replaced the smoke test
//!
//! `scripts/firecracker/smoke-test.sh` boots an Ubuntu image from the
//! Firecracker CI bucket. It proves Firecracker can start a microVM on this
//! host, and it says nothing whatsoever about nucleus: it never runs
//! `guest-init` or the tool-proxy, so no defect in either can make it fail.
//!
//! That gap is not theoretical. On 2026-07-29 it reported "PASS — Tier 2 works
//! on this host" on a VM with no `nucleus-node` and no nucleus rootfs, in the
//! same run where `nucleus start` exited 1. In the week before, the same gap hid
//! five production-blocking defects behind a fully green 436-test suite: a PID-1
//! panic from a missing CA store, a rootfs built without a CA bundle, an
//! identity bridge started after the health check that needed it, an SVID
//! fetched and never handed to the proxy, and a health budget set before the
//! guest did host round-trips. Every one needed a pod that boots.
//!
//! # What is asserted, and why each one
//!
//! 1. The pod is created at all — `POST /v1/pods` returns 200 with a proxy.
//! 2. A permitted command runs **inside the microVM** and reports Linux.
//! 3. A forbidden command is **denied**. Without this, (2) passing is equally
//!    consistent with no enforcement at all — the non-vacuity leg.
//! 4. The guest fetched its SPIFFE SVID, fetched its task token over vsock, and
//!    Firecracker is running under a seccomp filter. These are the facts only a
//!    booted pod can show, and each one has been broken in the last week.
//!
//! # Why not `nucleus run`
//!
//! `run_enforced` spawns `constants::AGENT_CLI_BIN`, a specific vendor's
//! assistant CLI. Making the quickstart's proof depend on a vendor binary would
//! violate the neutrality rule this project holds itself to, and would fail on
//! any machine that has not installed it. The tool-proxy's `/v1/run` route is
//! the same enforcement path with no vendor in it.

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use nucleus_client::sign_http_headers;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::provision::{Tier2Host, HOST_ARTIFACTS_DIR, HOST_STATE_DIR};

/// Verify that Tier 2 actually works on this machine.
#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Boot a real nucleus pod and assert what the guest did.
    #[arg(long)]
    pub tier2: bool,

    /// Lima VM to verify through (macOS). Ignored on Linux.
    #[arg(long, default_value = "nucleus")]
    pub vm_name: String,

    /// Run the checks on this machine rather than delegating into a VM.
    ///
    /// Set automatically when `nucleus verify --tier2` re-invokes itself inside
    /// the Lima VM; also the right flag on a Linux host with KVM.
    #[arg(long)]
    pub here: bool,

    /// Print every pinned artifact URL and digest as JSON, and exit.
    ///
    /// Exists so CI can check the pins are still fetchable without duplicating
    /// them in a shell script — which is how the published Lima templates came
    /// to point at a kernel that returns 404 while the code pinned a different
    /// one entirely.
    #[arg(long)]
    pub pins: bool,
}

/// The node's HTTP address on the machine running the checks.
const NODE_URL: &str = "http://127.0.0.1:8080";

/// An operation the policy allows, used to show the proxy really serves the
/// guest's filesystem.
///
/// `glob_search` is `Always` in every non-restrictive profile, and it needs no
/// file to exist — so this does not depend on what the rootfs happens to contain.
const ALLOWED_GLOB: &str = "*";

/// A read every profile must refuse.
///
/// Matched by two independent rules in `PathLattice::block_sensitive` —
/// `**/.ssh/**` and `**/id_rsa*` — so the refusal does not rest on one rule.
/// Relative, because absolute paths are rejected earlier as a sandbox escape,
/// which is a *different* control and would prove something else.
const FORBIDDEN_READ: &str = ".ssh/id_rsa";

/// Ephemeral DLC-D admission material for the pod under test: issuer + one
/// credential per operation the OTHER checks exercise, and deliberately NONE
/// for `web_fetch` — the operation [`check_admission_gate`] proves is refused
/// by the verified-admission gate specifically.
struct AdmissionMaterial {
    issuer_hex: String,
    credentials: String,
}

/// Mint the pod's admission material with a throwaway issuer key.
///
/// Key from `/dev/urandom` (this path is Linux-only, like the whole Tier 2
/// harness); the key never outlives the run and its only power is over this
/// one ephemeral pod. Credentials cover exactly the operations the existing
/// checks exercise — `glob_search` (allowed-op check) and `read_files` (the
/// forbidden-read check, WHICH MUST KEEP FAILING FOR THE LATTICE'S REASON:
/// credentialing `read_files` means admission passes and the refusal that
/// check asserts remains the path lattice's, not a missing credential's).
fn mint_admission() -> Result<AdmissionMaterial> {
    let mut seed = [0u8; 32];
    {
        use std::io::Read as _;
        std::fs::File::open("/dev/urandom")
            .context("no /dev/urandom on this host")?
            .read_exact(&mut seed)
            .context("could not read 32 bytes of randomness")?;
    }
    let mut issuer_hex = String::new();
    let mut creds = Vec::new();
    for op in ["glob_search", "read_files"] {
        let (pk, sig) = portcullis::says_admission::mint_credential(&seed, op);
        issuer_hex = hex::encode(pk);
        creds.push(format!("{op}={}", hex::encode(&sig.bytes)));
    }
    Ok(AdmissionMaterial {
        issuer_hex,
        credentials: creds.join(","),
    })
}

pub async fn execute(args: VerifyArgs) -> Result<()> {
    if args.pins {
        return print_pins();
    }
    if !args.tier2 {
        bail!("nothing to verify; did you mean `nucleus verify --tier2`?");
    }
    if args.here || cfg!(target_os = "linux") {
        verify_here()
    } else {
        verify_tier2(&Tier2Host::Lima(args.vm_name.clone()), &args.vm_name)
    }
}

/// Emit the pin manifest, so CI checks the same constants the installer uses.
fn print_pins() -> Result<()> {
    use nucleus_spec::tier2_artifacts as pins;

    let mut entries = Vec::new();
    for arch in ["aarch64", "x86_64"] {
        let kernel = pins::kernel_for(arch).expect("both architectures are pinned");
        entries.push(serde_json::json!({
            "kind": "kernel",
            "arch": arch,
            "url": kernel.url,
            "sha256": kernel.sha256,
            // Immutable object with a baked digest, so this pin is checkable
            // offline and a substitution fails without any network trust.
            "digest_pinned": true,
        }));
        for artifact in pins::Tier2Artifact::all() {
            entries.push(serde_json::json!({
                "kind": format!("{artifact:?}").to_lowercase(),
                "arch": arch,
                "url": artifact.asset_url(pins::GUEST_RELEASE, arch),
                "release": pins::GUEST_RELEASE,
                // Release-asset digests cannot be baked in: the constant would
                // have to be written before the release it describes exists.
                "digest_pinned": false,
            }));
        }
    }
    entries.push(serde_json::json!({
        "kind": "firecracker",
        "url": format!(
            "https://github.com/firecracker-microvm/firecracker/releases/tag/v{}",
            nucleus_spec::vmm_version::PINNED_STR
        ),
        "version": nucleus_spec::vmm_version::PINNED_STR,
        "digest_pinned": false,
    }));

    println!("{}", serde_json::to_string_pretty(&entries)?);
    Ok(())
}

/// Run the Tier 2 verification against `host`, wherever that is.
pub fn verify_tier2(host: &Tier2Host, vm_name: &str) -> Result<()> {
    match host {
        Tier2Host::Local => verify_here(),
        // The per-pod tool-proxy binds 127.0.0.1:0 inside the VM, so there is no
        // address the workstation could reach even in principle. Re-invoke the
        // Linux CLI where the proxy is.
        Tier2Host::Lima(_) => {
            println!("\nVerifying Tier 2 by booting a real pod (inside Lima VM '{vm_name}')...");
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
                     The tool-proxy binds an ephemeral loopback port inside the VM, so the\n\
                     checks have to run there. Install it with: nucleus setup"
                );
            }
            let status = Command::new("limactl")
                .args([
                    "shell",
                    vm_name,
                    "--",
                    "sudo",
                    "/usr/local/bin/nucleus",
                    "verify",
                    "--tier2",
                    "--here",
                ])
                .status()
                .context("failed to run the verification inside the Lima VM")?;
            if !status.success() {
                bail!("the in-VM verification failed (see its output above)");
            }
            Ok(())
        }
    }
}

/// The verification proper, on a machine that has KVM.
fn verify_here() -> Result<()> {
    let host = Tier2Host::Local;
    println!("\nTier 2 verification: booting a real nucleus pod");
    println!("================================================");

    preflight(&host)?;
    start_node(&host)?;

    // The pod runs UNDER verified admission: every check below therefore also
    // exercises the DLC-D gate — the allowed-op check proves the credentialed
    // path serves, the forbidden-read check proves lattice denials still win
    // (its operation IS credentialed), and check_admission_gate proves an
    // uncredentialed operation is refused by the admission gate specifically.
    let admission = mint_admission()?;
    let started = Instant::now();
    let pod = create_pod(&host, &admission)?;
    println!(
        "  [OK] pod created in {} ms, tool-proxy at {} (verified admission provisioned)",
        started.elapsed().as_millis(),
        pod.proxy
    );

    check_sandbox_proof(&pod)?;
    check_allowed_operation(&pod)?;
    check_forbidden_operation(&pod)?;
    check_admission_gate(&pod)?;
    check_guest_facts(&host, &pod)?;

    println!();
    println!("Tier 2 works on this host. A real nucleus pod booted, proved its");
    println!("identity to its own tool-proxy, served an allowed operation from");
    println!("inside the sandbox under an issuer-signed admission credential,");
    println!("refused a forbidden one, refused an uncredentialed operation");
    println!("at the verified-admission gate.");
    println!("at the verified-admission gate.");
    Ok(())
}

/// Everything that must already be true, each reported separately.
///
/// Separately, because a single "not ready" would send someone to re-run setup
/// when the actual cause is one missing file they can see named here.
fn preflight(host: &Tier2Host) -> Result<()> {
    let checks: [(&str, String, &str); 6] = [
        (
            "/dev/kvm",
            "test -r /dev/kvm".to_string(),
            "no KVM: Tier 2 needs Apple M3+ on macOS 15+, or a Linux host with /dev/kvm",
        ),
        (
            // Firecracker's vsock device needs the host's vhost-vsock, and the
            // guest reaches the workload API — its SVID and task token — over
            // exactly that channel. Without it the pod fails at device setup,
            // far from anything that names vsock. Checked here because a missing
            // kernel module is a host precondition, not a nucleus defect.
            "/dev/vhost-vsock",
            "test -e /dev/vhost-vsock".to_string(),
            "no /dev/vhost-vsock — load it with: sudo modprobe vhost_vsock",
        ),
        (
            "firecracker",
            "command -v firecracker".to_string(),
            "Firecracker is not installed; run: nucleus setup",
        ),
        (
            "guest kernel",
            format!("test -s {HOST_ARTIFACTS_DIR}/vmlinux"),
            "no guest kernel; run: nucleus setup",
        ),
        (
            "nucleus rootfs",
            format!("test -s {HOST_ARTIFACTS_DIR}/rootfs.ext4"),
            "no nucleus rootfs; run: nucleus setup",
        ),
        (
            "nucleus-node + secrets",
            "test -x /usr/local/bin/nucleus-node && test -s /etc/nucleus/node.env".to_string(),
            "nucleus-node or its environment file is missing; run: nucleus setup",
        ),
    ];
    let mut missing = Vec::new();
    for (name, probe, hint) in &checks {
        if host.test(probe) {
            println!("  [OK] {name}");
        } else {
            println!("  [--] {name}: {hint}");
            missing.push(*name);
        }
    }
    if !missing.is_empty() {
        bail!("preconditions not met: {}", missing.join(", "));
    }
    Ok(())
}

/// Bring the node up and wait for it to answer, or say what it logged.
fn start_node(host: &Tier2Host) -> Result<()> {
    host.sh("systemctl restart nucleus-node")
        .context("could not start the nucleus-node service")?;

    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if ureq::get(&format!("{NODE_URL}/v1/health"))
            .call()
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            println!("  [OK] nucleus-node is answering on {NODE_URL}");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    // The node exits immediately when a required secret is absent, and its own
    // message says which one — far more useful than "timed out".
    let log = host
        .sh("journalctl -u nucleus-node --no-pager -n 20")
        .unwrap_or_else(|_| "(no journal available)".into());
    bail!("nucleus-node did not become healthy within 30s. Its log said:\n{log}");
}

/// A created pod and the proxy that speaks for it.
struct Pod {
    proxy: String,
    /// The node's id for this pod, which is also its state directory name.
    ///
    /// Carried rather than rediscovered: an earlier version of this command
    /// located the guest log with `find -newermt '-10 minutes' | head -1`, which
    /// silently reads a DIFFERENT pod's log as soon as two run in ten minutes.
    /// It did exactly that here — reporting a missing task token from a stale
    /// log while the pod under test was fine — so the check was non-deterministic
    /// in the direction that matters: it could pass on someone else's evidence.
    id: String,
}

#[derive(serde::Deserialize)]
struct CreatePodResponse {
    id: Option<String>,
    proxy_addr: Option<String>,
}

/// Create a pod on the real nucleus rootfs, signed the way the node requires.
///
/// The DLC-D labels provision verified admission for THIS pod only (the node
/// forwards them to the pod's tool-proxy as `NUCLEUS_DLC_*`); the issuer key
/// doubles as its own trust anchor, matching dlc-d's principal convention.
fn create_pod(host: &Tier2Host, admission: &AdmissionMaterial) -> Result<Pod> {
    let secret = node_auth_secret(host)?;
    let issuer = &admission.issuer_hex;
    let creds = &admission.credentials;
    let body = format!(
        r#"{{"apiVersion":"nucleus/v1","kind":"Pod",
            "metadata":{{"name":"nucleus-verify",
              "labels":{{"dlc_trusted_keys":"{issuer}",
                         "dlc_issuer":"{issuer}",
                         "dlc_credentials":"{creds}"}}}},
            "spec":{{"work_dir":"/work","timeout_seconds":120,
              "policy":{{"type":"profile","name":"codegen"}},
              "image":{{"kernel_path":"{HOST_ARTIFACTS_DIR}/vmlinux",
                        "rootfs_path":"{HOST_ARTIFACTS_DIR}/rootfs.ext4",
                        "read_only":false}},
              "vsock":{{"guest_cid":3,"port":5005}}}}}}"#
    );

    // Do NOT treat a 4xx as a transport error: ureq's default turns the response
    // into an `Err` and discards the body, which is exactly where the node
    // explains itself.
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let mut request = agent
        .post(format!("{NODE_URL}/v1/pods"))
        .header("content-type", "application/json");
    let signed = sign_http_headers(secret.as_bytes(), Some("nucleus-verify"), body.as_bytes());
    for (key, value) in signed.headers {
        request = request.header(&key, &value);
    }

    let mut response = request
        .send(body.as_bytes())
        .map_err(|e| anyhow!("the node refused to create a pod: {e}"))?;
    if !response.status().is_success() {
        // The body is the whole value here: the node's 400s name the actual
        // reason (a policy it cannot resolve, a rootfs it cannot open, a seccomp
        // mode it read from the wrong process). Reporting only "http status:
        // 400" turns a precise diagnosis into a guess.
        let status = response.status();
        let detail = response
            .body_mut()
            .read_to_string()
            .unwrap_or_else(|_| "<no body>".to_string());
        bail!("pod creation returned {status}: {}", detail.trim());
    }
    let parsed: CreatePodResponse = response
        .body_mut()
        .read_json()
        .context("the node's response was not the JSON we expected")?;
    let proxy = parsed
        .proxy_addr
        .ok_or_else(|| anyhow!("the node created a pod but returned no tool-proxy address"))?;
    let id = parsed
        .id
        .ok_or_else(|| anyhow!("the node created a pod but returned no id"))?;
    Ok(Pod {
        proxy: if proxy.starts_with("http") {
            proxy
        } else {
            format!("http://{proxy}")
        },
        id,
    })
}

/// The node's HMAC secret, read from the env file setup wrote.
///
/// Read from the host rather than from the Keychain because this runs *on* the
/// Tier 2 host, which has no Keychain — and because the value that matters is
/// the one the running node was actually started with.
fn node_auth_secret(host: &Tier2Host) -> Result<String> {
    let line = host.sh("grep '^NUCLEUS_NODE_AUTH_SECRET=' /etc/nucleus/node.env")?;
    line.split_once('=')
        .map(|(_, v)| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("/etc/nucleus/node.env has no NUCLEUS_NODE_AUTH_SECRET value"))
}

/// The tool-proxy's `/v1/run` reply. Mirrors `nucleus_tool_proxy::RunResponse`,
/// plus `error`, which is what a refusal returns instead.
/// An agent that treats a 4xx as data rather than as a transport failure.
///
/// ureq's default turns a 403 into an `Err` and discards the body — and a 403
/// with its body is precisely the outcome the enforcement check is looking for.
fn plain_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into()
}

/// POST JSON to one of the proxy's routes; return the status and raw body.
fn proxy_post(pod: &Pod, route: &str, body: serde_json::Value) -> Result<(u16, String)> {
    let payload = body.to_string();
    let mut response = plain_agent()
        .post(format!("{}/v1/{route}", pod.proxy))
        .header("content-type", "application/json")
        .send(payload.as_bytes())
        .map_err(|e| anyhow!("the tool-proxy did not answer /v1/{route}: {e}"))?;
    let status = response.status().as_u16();
    let text = response.body_mut().read_to_string().unwrap_or_default();
    Ok((status, text))
}

/// The guest proved its own identity to its own tool-proxy.
///
/// This is the strongest single assertion available, and it is machine-readable:
/// the proxy reports which sandbox-proof tier it established. Tier 2 is
/// `spiffe-identity`, which the guest can only reach by fetching an SVID from
/// the host over vsock. Tier 3 is the kernel-cmdline token — a pod that fell
/// back to it has NOT exercised the identity path, and reporting that as success
/// is exactly the kind of silent downgrade this command exists to catch.
fn check_sandbox_proof(pod: &Pod) -> Result<()> {
    let mut response = plain_agent()
        .get(format!("{}/v1/health", pod.proxy))
        .call()
        .map_err(|e| anyhow!("the tool-proxy did not answer /v1/health: {e}"))?;
    let body: serde_json::Value = response
        .body_mut()
        .read_json()
        .context("the tool-proxy's health response was not JSON")?;

    let proof = body
        .get("sandbox_proof")
        .ok_or_else(|| anyhow!("the tool-proxy reported no sandbox proof at all: {body}"))?;
    let tier = proof.get("tier").and_then(|t| t.as_u64());
    let label = proof.get("label").and_then(|l| l.as_str()).unwrap_or("");
    if tier != Some(2) {
        bail!(
            "the guest did not establish a SPIFFE identity: sandbox proof is \
             tier {tier:?} ({label:?}), expected tier 2 (spiffe-identity). \
             A lower tier means the identity path silently fell back."
        );
    }
    println!(
        "  [OK] guest proved itself to its proxy: tier {} ({label})",
        2
    );
    Ok(())
}

/// An allowed operation is served, from inside the guest's sandbox.
fn check_allowed_operation(pod: &Pod) -> Result<()> {
    let (status, body) = proxy_post(pod, "glob", serde_json::json!({ "pattern": ALLOWED_GLOB }))?;
    if status >= 400 {
        bail!(
            "glob `{ALLOWED_GLOB}` was refused ({status}): {}",
            body.trim()
        );
    }
    // Non-vacuity: a proxy that answered 200 to everything with an empty body
    // would pass a status-only check while serving nothing.
    if !body.contains("matches") {
        bail!("glob returned {status} but no match list: {}", body.trim());
    }
    println!("  [OK] allowed operation served from the guest sandbox");
    println!("       glob \"{ALLOWED_GLOB}\" -> {}", body.trim());
    Ok(())
}

/// A forbidden operation is refused BY POLICY. This is the non-vacuity leg.
///
/// # What this does and does not establish
///
/// It establishes that the proxy consults a policy and refuses on it — paired
/// with [`check_allowed_operation`], which must *succeed*, so a proxy that
/// denied everything fails this pair rather than passing it.
///
/// It does **not** establish that the enforced lattice equals the one the pod's
/// profile declares — that would need the check to know the image's baked
/// profile and compare it, which it does not do.
///
/// A note on the `kind` it accepts: a booted pod used to report this refusal as
/// `insufficient_capability` with a fabricated `Never`, for a policy that said
/// `Always`. That was the proxy flattening every kernel reason into a capability
/// claim, since fixed — the denial now arrives as `kernel_denied` naming the
/// delegation ceiling it exceeded. The check accepts both, because the point is
/// that a *policy* refused, not which spelling it used.
/// An operation with NO issuer credential is refused BY THE VERIFIED-ADMISSION
/// GATE — the active leg of the DLC-D scenario.
///
/// The operation is `run_bash`: granted by the codegen profile, inside the
/// pod's verified task scope, exercised by no other check, a DISTINCT
/// primitive at the ActionTerm layer, and deliberately absent from
/// [`mint_admission`]'s credential list. Each qualifier was earned by a live
/// failure of this check refusing to accept a counterfeit denial:
/// - `web_fetch` (out of task scope) was refused by `InScopeWithTask` before
///   the request ever reached the kernel;
/// - `grep_search` was ADMITTED by the glob credential — `from_operation`
///   collapses Grep and Glob into one `GlobSearch` primitive, so at the
///   kernel boundary they are the same operation identity and a glob
///   credential legitimately covers grep — then refused downstream by an
///   obligations check, i.e. the wrong reason again.
///
/// An in-scope, primitively-distinct, uncredentialed operation reaches the
/// kernel, where the admission gate runs before the capability lattice — so
/// the refusal must arrive as the gate's own reason (`DlcAdmissionDenied`);
/// anything else means a different control refused and this check proves
/// nothing about admission.
fn check_admission_gate(pod: &Pod) -> Result<()> {
    // First: was the gate ARMED at all? The proxy's health endpoint reports
    // whether NUCLEUS_DLC_* provisioning reached it — without this, a refusal
    // check cannot distinguish "gate refused" from "gate never armed" (and an
    // unarmed gate would let the uncredentialed operation THROUGH, failing
    // below with a misleading message about enforcement).
    let mut health = plain_agent()
        .get(format!("{}/v1/health", pod.proxy))
        .call()
        .map_err(|e| anyhow!("the tool-proxy did not answer /v1/health: {e}"))?;
    let health_body: serde_json::Value = health
        .body_mut()
        .read_json()
        .context("health response was not JSON")?;
    let armed = health_body.get("dlc_admission").and_then(|v| v.as_str());
    if armed != Some("provisioned") {
        bail!(
            "the pod's tool-proxy reports dlc_admission={armed:?}, expected \
             \"provisioned\" — the PodSpec labels did not arrive as NUCLEUS_DLC_* \
             env. The break is in the labels→node→spawn-env chain, not the gate."
        );
    }

    let (status, body) = proxy_post(
        pod,
        "run",
        // Never executes: the gate refuses before any discharge or spawn.
        serde_json::json!({ "args": ["true"] }),
    )?;
    if status < 400 {
        bail!(
            "run WITHOUT a credential was ALLOWED ({status}): {}\n\
             The pod is provisioned for verified admission, so an uncredentialed\n\
             operation passing means the admission gate is not on the live path.",
            body.trim()
        );
    }
    if !body.contains("DlcAdmissionDenied") {
        bail!(
            "run was refused ({status}) but NOT by the admission gate: {}\n\
             A refusal for another reason (lattice, scope, IFC) does not prove\n\
             the verified-admission gate fired.",
            body.trim()
        );
    }
    println!("  [OK] uncredentialed operation refused by the verified-admission gate");
    println!("       run without an issuer credential -> {status} (DlcAdmissionDenied)");
    Ok(())
}

fn check_forbidden_operation(pod: &Pod) -> Result<()> {
    let (status, body) = proxy_post(pod, "read", serde_json::json!({ "path": FORBIDDEN_READ }))?;
    if status < 400 {
        bail!(
            "reading {FORBIDDEN_READ} was ALLOWED. The pod booted and served\n\
             operations, but policy is not being enforced — which makes every\n\
             other check here meaningless. This is the failure it exists to catch."
        );
    }
    // A refusal for the wrong reason is not enforcement. "Not found" would deny
    // this on any machine lacking the file and is indistinguishable by status
    // code alone, so the REASON is checked, not just the rejection.
    let kind = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("kind").and_then(|k| k.as_str()).map(str::to_string))
        .unwrap_or_default();
    // `kernel_denied` carries the kernel's own reason (e.g. a delegation-ceiling
    // rejection naming the operation and the level it exceeded). It is included
    // because it is the ACCURATE kind: the proxy used to flatten most kernel
    // refusals into `insufficient_capability` with a hand-written `Never`.
    // `approval_required` is deliberately NOT here — "this needs an approval you
    // did not present" is not the same as "this is forbidden", and accepting it
    // would let an approvable operation pass as a denial.
    let policy_kinds = [
        "path_denied",
        "insufficient_capability",
        "sandbox_escape",
        "kernel_denied",
        "command_denied",
    ];
    if !policy_kinds.contains(&kind.as_str()) {
        bail!(
            "reading {FORBIDDEN_READ} was refused ({status}) but not by policy \
             (kind={kind:?}). A denial that is not a policy decision proves \
             nothing about enforcement. Body: {}",
            body.trim()
        );
    }
    println!("  [OK] forbidden operation denied by policy (kind={kind})");
    Ok(())
}

/// The HOST's own Article 12 record of what this pod did.
///
/// # NOT YET CALLED, deliberately and visibly
///
/// Tier 2 boots a FIRECRACKER pod, and the evidence channel is currently
/// provisioned only for the local driver — a guest in a microVM reaches the host
/// over vsock, not over the node's HTTP address. Calling this now would gate CI
/// on a channel no Firecracker pod has, i.e. a check that cannot pass.
///
/// It is written, and left uncalled behind an `allow(dead_code)` that names its
/// own removal condition, for the same reason `art12.rs` was landed unwired: the
/// assertion is ready before the plumbing, and the allow is the thing that has
/// to be deleted when the plumbing arrives. Do NOT delete this function to
/// silence the warning.
///
/// # Why this is read from the host, not the pod
///
/// A pod-side log proves only what the pod chose to keep. This reads the file
/// the NODE assembled from records streamed as each decision was made, so a pod
/// that suppressed or rewrote its own copy cannot make this check pass.
///
/// # Why it asserts a DENIAL specifically
///
/// `check_forbidden_operation` above already proved the operation was refused.
/// What that cannot show is that the refusal was RECORDED — and a record-keeping
/// log containing only allows is non-empty, plausible, and wrong in the most
/// dangerous direction. Every defect in this arc (an unwired sink, a producer
/// with no consumer, a signed attestation nobody sent) was invisible to unit
/// tests and would have been caught by this one check running once.
#[allow(dead_code)] // Reachable once Firecracker pods ship over vsock; see below.
fn check_art12_witnessed(host: &Tier2Host, pod: &Pod) -> Result<()> {
    let log = format!("{HOST_STATE_DIR}/art12/{}.jsonl", pod.id);
    if !host.test(&format!("test -s {log}")) {
        bail!(
            "the host collected no Article 12 records at {log}. The pod booted and\n             enforced policy, but nothing reached the host's evidence channel — so\n             the executor would attest a chain head the POD reported rather than one\n             the host observed."
        );
    }
    let contents = host.sh(&format!("cat {log}"))?;

    // Non-vacuity first, as in check_guest_facts: an empty file satisfies every
    // "contains no wrong thing" check below while proving nothing.
    let lines: Vec<&str> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.is_empty() {
        bail!("the host's Article 12 log at {log} exists but is empty");
    }

    let mut denials = 0usize;
    let mut allows = 0usize;
    for line in &lines {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            bail!("the host stored a malformed Article 12 record: {line}");
        };
        match v.get("verdict").and_then(|x| x.as_str()) {
            Some("deny") => denials += 1,
            Some("allow") => allows += 1,
            _ => {}
        }
    }

    if denials == 0 {
        bail!(
            "the host witnessed {} Article 12 records but NOT the refusal it just\n             observed. A log of allows only is exactly the failure this check\n             exists to catch: it is non-empty, it verifies, and it is wrong.",
            lines.len()
        );
    }
    // Both legs, for the same reason check_forbidden_operation pairs with
    // check_allowed_operation: a runtime that recorded a denial for everything
    // would satisfy the assertion above while proving nothing.
    if allows == 0 {
        bail!(
            "the host witnessed {denials} refusals and no allows, so the log does not\n             distinguish a working runtime from one that denies everything."
        );
    }

    println!("  [OK] host witnessed {allows} allowed and {denials} refused decisions in its own Article 12 log");
    Ok(())
}

/// What the guest did during boot, read from its own log.
///
/// Each line here corresponds to a defect found by booting in the last week; a
/// check that only asserted "the pod started" would have passed through all of
/// them.
fn check_guest_facts(host: &Tier2Host, pod: &Pod) -> Result<()> {
    // Addressed by pod id, not found by timestamp. See `Pod::id`.
    let log = format!("{HOST_STATE_DIR}/pods/{}/firecracker.log", pod.id);
    if !host.test(&format!("test -s {log}")) {
        bail!("no guest log at {log}, so nothing can be said about what the guest did");
    }
    let contents = host.sh(&format!("cat {log}"))?;

    // Assert non-vacuity FIRST: an empty log would satisfy every "does not
    // contain a panic" check below while proving nothing at all.
    if contents.trim().is_empty() {
        bail!("{log} is empty; the guest produced no output to check");
    }

    let facts: [(&str, &str, &str); 3] = [
        (
            "SPIFFE identity fetched",
            "spiffe://",
            "the guest never fetched an SVID — the workload API bridge or its ordering is wrong",
        ),
        (
            "task token fetched over vsock",
            "fetched session task token",
            "the guest fell back to the kernel cmdline or has no token at all",
        ),
        (
            "no PID-1 panic",
            "",
            "the guest panicked as PID 1 — check the rootfs has a CA bundle",
        ),
    ];

    let mut failures = Vec::new();
    for (name, needle, hint) in &facts {
        let ok = if needle.is_empty() {
            !contents.contains("panicked")
        } else {
            contents.contains(needle)
        };
        if ok {
            println!("  [OK] {name}");
        } else {
            println!("  [--] {name}: {hint}");
            failures.push(*name);
        }
    }

    // The in-guest workload probe (`nucleus-workload-probe`), when the pod runs
    // it as its workload, asserts the FM-5 posture on the REAL child —
    // no identity vars in its environment, no leaked fds, dropped groups, a
    // read-only root — and prints a PASS/FAIL sentinel that the tool-proxy
    // drains into this log. Conditional on the sentinel appearing: a pod with no
    // probe workload (the demo pod) says nothing here, so this cannot fail
    // vacuously. The boot job that bakes the probe as its workload separately
    // asserts the sentinel is PRESENT, so a probe that failed to exec is caught
    // too.
    if contents.contains("NUCLEUS_WORKLOAD_PROBE") {
        if contents.contains("NUCLEUS_WORKLOAD_PROBE: PASS")
            && !contents.contains("NUCLEUS_WORKLOAD_PROBE: FAIL")
        {
            println!("  [OK] in-guest workload probe passed (FM-5 posture on the real child)");
        } else {
            println!(
                "  [--] in-guest workload probe FAILED: the real workload child saw identity \
                 material, a leaked file descriptor, retained supplementary groups, or a \
                 writable root"
            );
            failures.push("workload probe");
        }
    }

    match host.sh("pgrep -x firecracker | head -1") {
        Ok(pid) if !pid.is_empty() => {
            let mode = host
                .sh(&format!("grep '^Seccomp:' /proc/{pid}/status"))
                .unwrap_or_default();
            if mode.contains("2") {
                println!("  [OK] Firecracker is running under a seccomp filter");
            } else {
                println!("  [--] seccomp: expected mode 2 (filter), saw {mode:?}");
                failures.push("seccomp filter");
            }
        }
        // Not a failure: the pod may simply have finished. Saying "seccomp is
        // off" here would be a true statement about the wrong process, which is
        // exactly the misreading that cost a day of debugging last week.
        _ => println!("  [--] seccomp: no live Firecracker process to read (pod already exited)"),
    }

    if !failures.is_empty() {
        bail!(
            "the pod booted but did not do everything it must: {}\n  guest log: {log}",
            failures.join(", ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The forbidden read must be denied by a PATH rule, and matched by more
    /// than one, so a single rule changing does not silently turn this check
    /// into a no-op. It must also be RELATIVE: an absolute path is rejected
    /// earlier as a sandbox escape, which is a different control.
    #[test]
    fn the_forbidden_read_is_matched_by_two_block_sensitive_rules() {
        assert!(FORBIDDEN_READ.contains(".ssh/"), "must match `**/.ssh/**`");
        assert!(
            FORBIDDEN_READ.contains("id_rsa"),
            "must also match `**/id_rsa*`"
        );
        assert!(
            !FORBIDDEN_READ.starts_with('/'),
            "must be relative, or the denial comes from the sandbox-root check instead"
        );
    }

    /// The allowed operation must need no file to exist, or the check would be
    /// asserting something about the rootfs contents rather than about policy.
    #[test]
    fn the_allowed_operation_does_not_depend_on_rootfs_contents() {
        assert_eq!(ALLOWED_GLOB, "*");
    }

    #[test]
    fn artifact_paths_are_absolute_on_the_tier2_host() {
        assert!(HOST_ARTIFACTS_DIR.starts_with('/'));
    }
}

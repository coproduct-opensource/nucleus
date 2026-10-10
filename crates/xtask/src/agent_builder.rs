//! `cargo xtask agent-builder up|status|down` — operator tooling for the build VM agents
//! compile on.
//!
//! **Operator tooling, not runtime.** Nothing in nucleus depends on this module; it is a thin
//! driver over the `gcloud` CLI for an operator who keeps a disposable build VM in a
//! compute project they own. Every site-specific value — project, zones, machine type, disk
//! type, service account — is a flag or an `AGENT_BUILDER_*` environment variable with no
//! default, so the repository names no account, region or instance shape. See
//! `crates/xtask/README.md` § "Operator tooling: agent build VM".
//!
//! What it fixes, rather than parameterises, is the lifetime policy: the VM is spot, is
//! deleted (not stopped) when it is preempted or reaches [`MAX_RUN`], and carries
//! `role=agent-builder`. A build VM that outlives its purpose costs money silently, and an
//! operator who wants a different lifetime should edit this file in review, not pass a flag.
//!
//! The label is also the authority to destroy: `down` acts only through an [`Owned`], which
//! is minted by [`owned`] after reading the label back from the instance itself, and is
//! consumed by the delete (ADR 0007 C-1, C-4). An instance whose labels could not be read,
//! or that carries none, is refused — absent labels never mean "ours" (B-2).

use std::collections::BTreeMap;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use serde::Deserialize;

/// The label every instance this tool creates carries, and the only ones it will delete.
pub const LABEL_KEY: &str = "role";
pub const LABEL_VALUE: &str = "agent-builder";
/// Spot capacity: the VM can be reclaimed at any time, and costs a fraction of on-demand.
const PROVISIONING_MODEL: &str = "SPOT";
/// The VM deletes itself after this long, whether or not anyone remembered it.
const MAX_RUN: &str = "12h";
/// Preemption and the max-run limit both DELETE the VM; a stopped VM still bills its disk.
const TERMINATION_ACTION: &str = "DELETE";
/// The VM reaches cloud storage (the compile cache) as its attached service account; what
/// it may touch is decided by that account's IAM bindings, not by the scope.
const SCOPES: &str = "cloud-platform";
/// Written by the startup script once the repo clone is refreshed. The image does not
/// contain it, so its presence means this boot provisioned.
const READY_MARKER: &str = "/var/tmp/provisioned";

/// Which instance, where.
#[derive(Args, Debug, Clone)]
pub struct Target {
    /// Compute project; the gcloud configuration's default when absent.
    #[arg(long, env = "AGENT_BUILDER_PROJECT")]
    pub project: Option<String>,
    /// Zones to try, in order (comma-separated). `up` moves to the next zone only when the
    /// current one has no capacity or quota; any other failure stops.
    #[arg(
        long = "zone",
        env = "AGENT_BUILDER_ZONES",
        value_delimiter = ',',
        required = true
    )]
    pub zones: Vec<String>,
    /// Instance name.
    #[arg(
        long,
        env = "AGENT_BUILDER_NAME",
        default_value = "nucleus-agent-build"
    )]
    pub name: String,
}

/// The shape of a new instance. Only `up` reads it.
#[derive(Args, Debug, Clone)]
pub struct Shape {
    #[arg(long, env = "AGENT_BUILDER_MACHINE_TYPE")]
    pub machine_type: String,
    #[arg(long, env = "AGENT_BUILDER_DISK_TYPE")]
    pub disk_type: String,
    #[arg(long, env = "AGENT_BUILDER_DISK_GB", default_value_t = 200)]
    pub disk_gb: u32,
    /// Image family the boot disk is created from (the newest image in it).
    #[arg(
        long,
        env = "AGENT_BUILDER_IMAGE_FAMILY",
        default_value = "nucleus-agent-builder"
    )]
    pub image_family: String,
    /// Project holding the image family; the instance's project when absent.
    #[arg(long, env = "AGENT_BUILDER_IMAGE_PROJECT")]
    pub image_project: Option<String>,
    /// Service account the VM runs as. Grant it only what builds need (the cache bucket).
    #[arg(long, env = "AGENT_BUILDER_SERVICE_ACCOUNT")]
    pub service_account: String,
    /// Login user whose `~/nucleus` clone the startup script refreshes; `$USER` when absent,
    /// which is also the account `gcloud compute ssh` logs in as.
    #[arg(long, env = "AGENT_BUILDER_USER")]
    pub user: Option<String>,
    /// How long `up` waits for the ready marker over IAP before giving up.
    #[arg(long, default_value_t = 900)]
    pub ready_timeout_secs: u64,
}

#[derive(Subcommand, Debug)]
pub enum Action {
    /// Create the VM from the image family (or adopt a running one) and wait until it is
    /// reachable over IAP and provisioned.
    Up {
        #[command(flatten)]
        target: Target,
        #[command(flatten)]
        shape: Shape,
    },
    /// List every instance labelled `role=agent-builder`.
    Status {
        /// Compute project; the gcloud configuration's default when absent.
        #[arg(long, env = "AGENT_BUILDER_PROJECT")]
        project: Option<String>,
    },
    /// Delete the named VM — only if it carries `role=agent-builder`.
    Down {
        #[command(flatten)]
        target: Target,
    },
}

pub fn run(action: Action) -> Result<()> {
    match action {
        Action::Up { target, shape } => up(&target, &shape),
        Action::Status { project } => status(project.as_deref()),
        Action::Down { target } => down(&target),
    }
}

/// One instance as `gcloud compute instances list --format json` reports it.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Instance {
    name: String,
    /// A URL; the zone is its last segment.
    zone: String,
    status: String,
    /// Absent when the instance has no labels at all.
    labels: Option<BTreeMap<String, String>>,
    creation_timestamp: Option<String>,
}

impl Instance {
    fn zone_name(&self) -> &str {
        self.zone.rsplit('/').next().unwrap_or(&self.zone)
    }
}

/// An instance this tool may act on. Private fields: minted only by [`owned`], after the
/// label was read back from the instance. Not `Clone`: [`delete`] consumes it.
#[must_use]
#[derive(Debug)]
pub struct Owned {
    name: String,
    zone: String,
    status: String,
}

/// Why an instance is not ours to touch.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    NoLabels,
    WrongLabel(Option<String>),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoLabels => write!(f, "it has no labels"),
            Self::WrongLabel(None) => write!(f, "it has no `{LABEL_KEY}` label"),
            Self::WrongLabel(Some(v)) => write!(f, "its `{LABEL_KEY}` label is `{v}`"),
        }
    }
}

fn owned(inst: Instance) -> Result<Owned, Refusal> {
    let Some(labels) = inst.labels.as_ref() else {
        return Err(Refusal::NoLabels);
    };
    match labels.get(LABEL_KEY) {
        Some(v) if v == LABEL_VALUE => Ok(Owned {
            zone: inst.zone_name().to_string(),
            name: inst.name,
            status: inst.status,
        }),
        other => Err(Refusal::WrongLabel(other.cloned())),
    }
}

/// Debug-info levels every agent build on the VM uses, appended to the user's cargo config.
/// Full debug info made each agent's `target/` 25-150 GiB, and several agents at once filled
/// the 200 GB disk (2026-10-08). Line tables keep panic and backtrace locations;
/// dependencies carry none. CI builds are unaffected: this lives only on the builder.
const BUILDER_PROFILE: &str = "[profile.dev]\n\
                               debug = \"line-tables-only\"\n\
                               [profile.dev.package.\"*\"]\n\
                               debug = false\n";

/// The boot-time script. Deliberately minimal: everything slow is in the image. It refreshes
/// the baked clone (a failed pull leaves the image's commit, which is still a usable clone),
/// appends [`BUILDER_PROFILE`] to the user's cargo config once, and then writes the ready
/// marker that `up` waits for.
pub fn startup_script(user: &str) -> String {
    format!(
        "#!/bin/bash\n\
         runuser -u {user} -- git -C /home/{user}/nucleus pull -q --ff-only\n\
         CFG=/home/{user}/.cargo/config.toml\n\
         grep -q 'line-tables-only' \"$CFG\" || runuser -u {user} -- tee -a \"$CFG\" >/dev/null <<'EOF'\n\
         {BUILDER_PROFILE}EOF\n\
         touch {READY_MARKER}\n"
    )
}

fn project_args(project: Option<&str>) -> Vec<String> {
    project
        .map(|p| vec!["--project".to_string(), p.to_string()])
        .unwrap_or_default()
}

/// `gcloud compute instances create …` for one zone.
pub fn create_args(target: &Target, shape: &Shape, zone: &str, user: &str) -> Vec<String> {
    let mut a: Vec<String> = [
        "compute",
        "instances",
        "create",
        &target.name,
        "--zone",
        zone,
        "--machine-type",
        &shape.machine_type,
        "--image-family",
        &shape.image_family,
        "--boot-disk-size",
        &format!("{}GB", shape.disk_gb),
        "--boot-disk-type",
        &shape.disk_type,
        "--provisioning-model",
        PROVISIONING_MODEL,
        "--max-run-duration",
        MAX_RUN,
        "--instance-termination-action",
        TERMINATION_ACTION,
        "--labels",
        &format!("{LABEL_KEY}={LABEL_VALUE}"),
        "--service-account",
        &shape.service_account,
        "--scopes",
        SCOPES,
        "--metadata",
        &format!("startup-script={}", startup_script(user)),
        "--format",
        "json",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if let Some(p) = shape.image_project.as_deref().or(target.project.as_deref()) {
        a.extend(["--image-project".to_string(), p.to_string()]);
    }
    a.extend(project_args(target.project.as_deref()));
    a
}

/// The lifetime policy, as `(flag, value)` pairs a create command must carry verbatim.
const POLICY: &[(&str, &str)] = &[
    ("--provisioning-model", PROVISIONING_MODEL),
    ("--max-run-duration", MAX_RUN),
    ("--instance-termination-action", TERMINATION_ACTION),
];

/// Policy flags a create command lacks. Checked before every create, not only in tests: an
/// edit to [`create_args`] that drops one must not reach the cloud.
pub fn missing_policy(args: &[String]) -> Vec<String> {
    let has = |flag: &str, value: &str| args.windows(2).any(|w| w[0] == flag && w[1] == value);
    let label = format!("{LABEL_KEY}={LABEL_VALUE}");
    POLICY
        .iter()
        .map(|&(f, v)| (f, v.to_string()))
        .chain(std::iter::once(("--labels", label)))
        .filter(|(f, v)| !has(f, v))
        .map(|(f, v)| format!("{f} {v}"))
        .collect()
}

/// Why a create in one zone failed.
#[derive(Debug, PartialEq, Eq)]
pub enum CreateFailure {
    /// No capacity or quota there; another zone may do.
    Exhausted,
    /// Anything else (bad image, permissions, a typo): another zone will not help.
    Other,
}

pub fn classify(stderr: &str) -> CreateFailure {
    let s = stderr.to_ascii_lowercase();
    let exhausted = s.contains("zone_resource_pool_exhausted")
        || s.contains("does not have enough resources")
        || s.contains("quota_exceeded")
        || (s.contains("quota") && s.contains("exceeded"));
    if exhausted {
        CreateFailure::Exhausted
    } else {
        CreateFailure::Other
    }
}

fn gcloud(args: &[String]) -> Result<Output> {
    Command::new("gcloud")
        .args(args)
        .output()
        .with_context(|| format!("could not run gcloud {}", args.join(" ")))
}

/// Instances with this exact name, in any zone. A gcloud failure is an error, never "none".
fn find(target: &Target) -> Result<Vec<Instance>> {
    let mut args: Vec<String> = [
        "compute",
        "instances",
        "list",
        "--filter",
        &format!("name=({})", target.name),
        "--format",
        "json",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    args.extend(project_args(target.project.as_deref()));
    let out = gcloud(&args)?;
    if !out.status.success() {
        bail!(
            "could not list instances: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    serde_json::from_slice(&out.stdout).context("gcloud instances list returned unparseable JSON")
}

/// The one instance with this name, if any, refused unless labelled ours.
fn lookup(target: &Target) -> Result<Option<Owned>> {
    let mut found = find(target)?;
    match found.len() {
        0 => Ok(None),
        1 => {
            let inst = found.remove(0);
            let (name, zone) = (inst.name.clone(), inst.zone_name().to_string());
            owned(inst).map(Some).map_err(|why| {
                anyhow::anyhow!(
                    "refusing to touch {name} in {zone}: {why}, not `{LABEL_KEY}={LABEL_VALUE}`"
                )
            })
        }
        n => bail!(
            "{n} instances are named {}; name one zone's instance explicitly",
            target.name
        ),
    }
}

fn up(target: &Target, shape: &Shape) -> Result<()> {
    let started = Instant::now();
    let zone = match lookup(target)? {
        Some(o) if o.status == "RUNNING" => {
            println!(
                "{} already RUNNING in {}; waiting for readiness",
                o.name, o.zone
            );
            o.zone
        }
        Some(o) => bail!(
            "{} exists in {} with status {}; `cargo xtask agent-builder down` it first",
            o.name,
            o.zone,
            o.status
        ),
        None => create(target, shape)?,
    };
    let created = started.elapsed();
    wait_ready(target, &zone, Duration::from_secs(shape.ready_timeout_secs))?;
    println!(
        "{} ready in {zone}: created after {:.0}s, provisioned after {:.0}s",
        target.name,
        created.as_secs_f64(),
        started.elapsed().as_secs_f64()
    );
    println!(
        "  gcloud compute ssh {} --zone {zone} --tunnel-through-iap{}",
        target.name,
        target
            .project
            .as_deref()
            .map(|p| format!(" --project {p}"))
            .unwrap_or_default()
    );
    Ok(())
}

/// Create in the first zone that has room. Returns the zone.
fn create(target: &Target, shape: &Shape) -> Result<String> {
    let user = match shape.user.clone() {
        Some(u) => u,
        None => std::env::var("USER").context("no --user and $USER is unset")?,
    };
    let mut exhausted = Vec::new();
    for zone in &target.zones {
        let args = create_args(target, shape, zone, &user);
        let missing = missing_policy(&args);
        if !missing.is_empty() {
            bail!("create command lacks policy flags: {}", missing.join(", "));
        }
        println!("creating {} in {zone}", target.name);
        let out = gcloud(&args)?;
        if out.status.success() {
            return Ok(zone.clone());
        }
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        match classify(&stderr) {
            CreateFailure::Exhausted => {
                eprintln!("  {zone}: no capacity or quota, trying the next zone\n  {stderr}");
                exhausted.push(zone.clone());
            }
            CreateFailure::Other => bail!("create in {zone} failed: {stderr}"),
        }
    }
    bail!(
        "no zone had capacity or quota: {} (a project-wide CPU quota is not fixed by another zone)",
        exhausted.join(", ")
    )
}

fn ssh_args(target: &Target, zone: &str, command: &str) -> Vec<String> {
    let mut a: Vec<String> = [
        "compute",
        "ssh",
        &target.name,
        "--zone",
        zone,
        "--tunnel-through-iap",
        "--quiet",
        "--ssh-flag=-o ConnectTimeout=15",
        "--command",
        command,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    a.extend(project_args(target.project.as_deref()));
    a
}

fn wait_ready(target: &Target, zone: &str, timeout: Duration) -> Result<()> {
    let started = Instant::now();
    let args = ssh_args(target, zone, &format!("test -f {READY_MARKER}"));
    loop {
        let out = gcloud(&args)?;
        if out.status.success() {
            return Ok(());
        }
        if started.elapsed() > timeout {
            bail!(
                "{} not ready after {}s: {}",
                target.name,
                timeout.as_secs(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

fn status(project: Option<&str>) -> Result<()> {
    let mut args: Vec<String> = [
        "compute",
        "instances",
        "list",
        "--filter",
        &format!("labels.{LABEL_KEY}={LABEL_VALUE}"),
        "--format",
        "json",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    args.extend(project_args(project));
    let out = gcloud(&args)?;
    if !out.status.success() {
        bail!(
            "could not list instances: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let found: Vec<Instance> =
        serde_json::from_slice(&out.stdout).context("unparseable instances list")?;
    if found.is_empty() {
        println!("no instance labelled {LABEL_KEY}={LABEL_VALUE}");
    }
    for i in &found {
        println!(
            "{}\t{}\t{}\t{}",
            i.name,
            i.zone_name(),
            i.status,
            i.creation_timestamp.as_deref().unwrap_or("?")
        );
    }
    Ok(())
}

fn down(target: &Target) -> Result<()> {
    match lookup(target)? {
        None => {
            println!("no instance named {}", target.name);
            Ok(())
        }
        Some(o) => delete(o, target.project.as_deref()),
    }
}

/// Consumes the witness: one check, one delete.
fn delete(o: Owned, project: Option<&str>) -> Result<()> {
    let mut args: Vec<String> = [
        "compute",
        "instances",
        "delete",
        &o.name,
        "--zone",
        &o.zone,
        "--quiet",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    args.extend(project_args(project));
    let out = gcloud(&args)?;
    if !out.status.success() {
        bail!(
            "delete {} failed: {}",
            o.name,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    println!("deleted {} in {}", o.name, o.zone);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> Target {
        Target {
            project: Some("example-project".into()),
            zones: vec!["zone-a".into(), "zone-b".into()],
            name: "nucleus-agent-build".into(),
        }
    }

    fn shape() -> Shape {
        Shape {
            machine_type: "arm64-16".into(),
            disk_type: "balanced".into(),
            disk_gb: 200,
            image_family: "nucleus-agent-builder".into(),
            image_project: None,
            service_account: "builder@example-project.example".into(),
            user: Some("dev".into()),
            ready_timeout_secs: 1,
        }
    }

    fn value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
        args.windows(2)
            .find(|w| w[0] == flag)
            .map(|w| w[1].as_str())
    }

    /// The lifetime policy, spelled out literally: a change to a constant reds this too.
    #[test]
    fn create_carries_the_lifetime_policy() {
        let a = create_args(&target(), &shape(), "zone-a", "dev");
        assert_eq!(value(&a, "--provisioning-model"), Some("SPOT"));
        assert_eq!(value(&a, "--max-run-duration"), Some("12h"));
        assert_eq!(value(&a, "--instance-termination-action"), Some("DELETE"));
        assert_eq!(value(&a, "--labels"), Some("role=agent-builder"));
        assert_eq!(
            value(&a, "--service-account"),
            Some("builder@example-project.example")
        );
        assert_eq!(value(&a, "--zone"), Some("zone-a"));
        assert_eq!(value(&a, "--image-family"), Some("nucleus-agent-builder"));
        assert_eq!(value(&a, "--image-project"), Some("example-project"));
        assert_eq!(value(&a, "--project"), Some("example-project"));
        assert_eq!(value(&a, "--boot-disk-size"), Some("200GB"));
        assert!(missing_policy(&a).is_empty(), "{:?}", missing_policy(&a));
    }

    /// A-19 for the runtime check: dropping or altering any one policy flag (or its value)
    /// must make `missing_policy` report it, so `create` refuses to run.
    #[test]
    fn dropping_any_policy_flag_is_caught() {
        let full = create_args(&target(), &shape(), "zone-a", "dev");
        for flag in [
            "--provisioning-model",
            "--max-run-duration",
            "--instance-termination-action",
            "--labels",
        ] {
            let i = full.iter().position(|a| a == flag).expect(flag);
            let mut dropped = full.clone();
            dropped.drain(i..i + 2);
            assert_eq!(missing_policy(&dropped).len(), 1, "drop {flag}");
            let mut altered = full.clone();
            altered[i + 1] = "STANDARD".into();
            assert_eq!(missing_policy(&altered).len(), 1, "alter {flag}");
        }
    }

    #[test]
    fn startup_script_refreshes_then_marks_ready() {
        let s = startup_script("dev");
        assert!(s.contains("runuser -u dev -- git -C /home/dev/nucleus pull"));
        assert!(s.contains(BUILDER_PROFILE));
        assert!(s.contains("debug = \"line-tables-only\""));
        assert!(s.trim_end().ends_with(&format!("touch {READY_MARKER}")));
        // gcloud splits `--metadata` on commas; a comma would truncate the script.
        assert!(!s.contains(','));
        let a = create_args(&target(), &shape(), "zone-a", "dev");
        assert_eq!(
            value(&a, "--metadata"),
            Some(format!("startup-script={s}").as_str())
        );
    }

    #[test]
    fn no_project_means_no_project_flags() {
        let t = Target {
            project: None,
            ..target()
        };
        let a = create_args(&t, &shape(), "zone-a", "dev");
        assert!(!a.iter().any(|x| x == "--project" || x == "--image-project"));
    }

    fn inst(labels: Option<&[(&str, &str)]>) -> Instance {
        Instance {
            name: "nucleus-agent-build".into(),
            zone: "https://compute.example/projects/p/zones/zone-a".into(),
            status: "RUNNING".into(),
            labels: labels.map(|l| {
                l.iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect()
            }),
            creation_timestamp: None,
        }
    }

    #[test]
    fn only_labelled_instances_are_owned() {
        let o = owned(inst(Some(&[("role", "agent-builder")]))).expect("ours");
        assert_eq!(
            (o.name.as_str(), o.zone.as_str()),
            ("nucleus-agent-build", "zone-a")
        );
        assert_eq!(owned(inst(None)).unwrap_err(), Refusal::NoLabels);
        assert_eq!(
            owned(inst(Some(&[("purpose", "ci")]))).unwrap_err(),
            Refusal::WrongLabel(None)
        );
        assert_eq!(
            owned(inst(Some(&[("role", "ci-runner")]))).unwrap_err(),
            Refusal::WrongLabel(Some("ci-runner".into()))
        );
    }

    #[test]
    fn gcloud_instance_json_parses() {
        let json = r#"[{"name":"b","zone":"https://x/zones/zone-b","status":"RUNNING",
            "creationTimestamp":"2026-10-06T00:00:00Z","labels":{"role":"agent-builder"}},
            {"name":"c","zone":"https://x/zones/zone-a","status":"TERMINATED"}]"#;
        let v: Vec<Instance> = serde_json::from_str(json).expect("parse");
        assert_eq!(v[0].zone_name(), "zone-b");
        assert!(v[1].labels.is_none());
        assert_eq!(
            owned(v.into_iter().nth(1).expect("c")).unwrap_err(),
            Refusal::NoLabels
        );
    }

    #[test]
    fn only_capacity_failures_fall_through_to_the_next_zone() {
        for s in [
            "ERROR: The zone 'z' does not have enough resources available to fulfill the request.",
            "code: ZONE_RESOURCE_POOL_EXHAUSTED",
            "Quota 'CPUS_ALL_REGIONS' exceeded.  Limit: 192.0 globally.",
            "QUOTA_EXCEEDED",
        ] {
            assert_eq!(classify(s), CreateFailure::Exhausted, "{s}");
        }
        for s in [
            "The resource 'projects/p/global/images/family/x' was not found",
            "Required 'iam.serviceAccounts.actAs' permission",
        ] {
            assert_eq!(classify(s), CreateFailure::Other, "{s}");
        }
    }
}

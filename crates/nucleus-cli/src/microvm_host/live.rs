//! End to end on a real Mac: build the L1 kernel and the image, bring the
//! host up with `ensure_ready`, kill it, and watch the supervisor restart it.
//!
//! ```text
//! NUCLEUS_MICROVM_HOST_LIVE=1 cargo test -p nucleus-cli -- --ignored --nocapture \
//!     microvm_host::live
//! ```
//!
//! Everything it creates uses [`HostNames::DEV`] (`nucleus-dev-*`) and a state
//! directory under the build's target dir, and it removes both at the end.
//! Set `NUCLEUS_MICROVM_HOST_KEEP=1` to leave them for inspection. Prebuilt
//! artifacts can be supplied with `NUCLEUS_MICROVM_HOST_L1_KERNEL` (an `Image`
//! with its `config` beside it) and `NUCLEUS_MICROVM_HOST_IMAGE`.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nucleus_spec::microvm_host::{
    self as pins, ArtifactSource, HostNames, IMAGE_OVERRIDE_ENV, L1_KERNEL_IMAGE_IN_OUTPUT,
};

use super::container_cli::ContainerCli;
use super::lifecycle::{self, HostConfig, HostState};
use super::supervisor::{HostEvent, Supervisor};

fn enabled() -> bool {
    let on = std::env::var("NUCLEUS_MICROVM_HOST_LIVE").as_deref() == Ok("1");
    if !on {
        eprintln!("skipped: set NUCLEUS_MICROVM_HOST_LIVE=1");
    }
    on
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("two levels below the root")
        .to_path_buf()
}

fn recipe(source: ArtifactSource) -> PathBuf {
    match source {
        ArtifactSource::LocalBuild { containerfile } => repo_root().join(containerfile),
        ArtifactSource::Pinned { digest } => panic!("no recipe for {digest}"),
    }
}

fn work() -> PathBuf {
    let d = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/microvm-host-live");
    std::fs::create_dir_all(&d).expect("work dir");
    d
}

/// The runtime's default kernel, whose config the L1 kernel inherits.
fn base_kernel(cli: &ContainerCli) -> PathBuf {
    let status = cli.system_status();
    let json: serde_json::Value =
        serde_json::from_str(status.stdout().expect("system status")).expect("json");
    let root = json
        .pointer("/paths/appRoot")
        .and_then(|v| v.as_str())
        .expect("appRoot");
    PathBuf::from(root).join(format!(
        "kernels/vmlinux-{}-197-debug",
        pins::L1_KERNEL.linux_version
    ))
}

fn l1_kernel(cli: &ContainerCli) -> PathBuf {
    if let Some(k) = std::env::var_os("NUCLEUS_MICROVM_HOST_L1_KERNEL") {
        return PathBuf::from(k);
    }
    let out = work().join("l1");
    let image = out.join(L1_KERNEL_IMAGE_IN_OUTPUT);
    if image.is_file() {
        return image;
    }
    let ctx = work().join("l1-ctx");
    std::fs::create_dir_all(&ctx).expect("ctx");
    std::fs::copy(base_kernel(cli), ctx.join("base-kernel")).expect("base kernel");
    std::fs::copy(
        repo_root().join("docker/l1-kernel.fragment"),
        ctx.join("l1-kernel.fragment"),
    )
    .expect("fragment");
    let started = Instant::now();
    let built = cli.build_to_dir(&recipe(pins::L1_KERNEL.source), &out, &ctx);
    assert!(built.succeeded(), "kernel build {}", built.describe());
    println!("L1 kernel built in {:.0?}", started.elapsed());
    image
}

fn image(cli: &ContainerCli, names: &HostNames) -> String {
    if let Ok(v) = std::env::var(IMAGE_OVERRIDE_ENV) {
        let pins::ImageOverride::Reference(r) = pins::parse_image_override(&v).expect("override");
        return r;
    }
    let started = Instant::now();
    // A node built from this tree: the mTLS listener `ensure_ready` checks.
    let built = cli.build_image(
        &recipe(pins::IMAGE_SOURCE),
        names.image_tag,
        &[("NODE_SOURCE", "source")],
        &repo_root(),
    );
    assert!(built.succeeded(), "image build {}", built.describe());
    println!("image built in {:.0?}", started.elapsed());
    names.image_tag.to_string()
}

fn cleanup(cli: &ContainerCli, cfg: &HostConfig) {
    if std::env::var("NUCLEUS_MICROVM_HOST_KEEP").as_deref() == Ok("1") {
        println!(
            "kept {} and {}",
            cfg.names.container, cfg.names.state_volume
        );
        return;
    }
    match lifecycle::observe_state(cli, cfg) {
        Ok(HostState::Running(o, _) | HostState::Stopped(o)) => {
            println!("delete: {}", cli.delete(&o).describe());
        }
        Ok(HostState::Stale {
            reason:
                lifecycle::StaleReason::Drifted { owned, .. }
                | lifecycle::StaleReason::Transitional { owned, .. },
        }) => println!("delete: {}", cli.delete(&owned).describe()),
        other => println!("nothing to delete: {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&cfg.state_dir);
    println!(
        "volume delete: {}",
        cli.volume_delete(cfg.names.state_volume).describe()
    );
}

#[test]
#[ignore = "live: builds and boots an Apple container with nested virtualization"]
fn ensure_ready_then_survive_a_kill() {
    if !enabled() {
        return;
    }
    let cli = ContainerCli::system();
    let names = HostNames::DEV;
    let cfg = HostConfig {
        names,
        image: image(&cli, &names),
        kernel: l1_kernel(&cli),
        state_dir: work().join("state"),
        cpus: 4,
        memory: "4g".into(),
        trust_domain: "nucleus.local".into(),
        ready_timeout: Duration::from_secs(120),
        connection: crate::microvm_host::lifecycle::Connection::PublishedLoopback,
    };
    let started = Instant::now();
    let ready = lifecycle::ensure_ready(&cli, &cfg);
    let host = match ready {
        Ok(h) => h,
        Err(e) => {
            cleanup(&cli, &cfg);
            panic!("ensure_ready refused: {e}");
        }
    };
    println!(
        "ensure_ready: {:.1?}, node {}, relays {:?}",
        started.elapsed(),
        host.node_url(),
        host.relay_ports()
    );
    let list = cli.list_all();
    std::fs::write(
        work().join("list-live.json"),
        list.stdout().unwrap_or_default(),
    )
    .expect("save list");

    let mut sup = Supervisor::new(cli.clone(), cfg.clone());
    // A kept run leaves its log behind; count only this run's events.
    let _ = std::fs::remove_file(sup.audit_log());
    let healthy = sup.tick();
    println!("tick: {healthy:?}");

    let owned = host.container().clone();
    let killed = cli.kill(&owned);
    println!("kill: {}", killed.describe());
    let died_at = Instant::now();
    let mut state = String::new();
    while died_at.elapsed() < Duration::from_secs(10) {
        match lifecycle::observe_state(&cli, &cfg) {
            Ok(HostState::Running(..)) => std::thread::sleep(Duration::from_millis(100)),
            other => {
                state = format!("{other:?}");
                break;
            }
        }
    }
    println!("death seen in {:.2?}: {state}", died_at.elapsed());
    let recovery = sup.tick();
    println!("tick after kill: {recovery:?} ({:.1?})", died_at.elapsed());
    let log = std::fs::read_to_string(sup.audit_log()).unwrap_or_default();
    println!("audit log:\n{log}");

    cleanup(&cli, &cfg);
    assert_eq!(healthy, vec![HostEvent::Healthy]);
    assert!(
        matches!(
            recovery.as_slice(),
            [HostEvent::Died { .. }, HostEvent::Restarted { .. }]
        ),
        "{recovery:?}"
    );
    assert_eq!(
        log.lines().count(),
        2,
        "died and restarted are both audited"
    );
}
